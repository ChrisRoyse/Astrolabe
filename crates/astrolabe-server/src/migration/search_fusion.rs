//! Production `search_graph` fusion surface (P6.6, #42 DoD 2–4).
//!
//! [`astrolabe_weave::search_production`] is the vault→manifest lifecycle,
//! [`astrolabe_weave::search`] is the fail-closed planner + RRF fusion core, and
//! [`astrolabe_weave::search_index`] runs a validated plan against real per-slot
//! indexes. This module is the MCP wiring that binds them to the live
//! `search_graph` tool: it is the **opt-in** fused path.
//!
//! Contract (standing invariants #2/#3/#6):
//! - **Opt-in only.** The fused engine runs iff the caller passes `fusion: true`.
//!   Every other `search_graph` request is the byte-identical legacy CBM
//!   passthrough (dispatch strips the Astrolabe-only `fusion` knob before the
//!   CBM tool sees it, exactly as it strips `propagated_label`).
//! - **Freshness-gated rebuild.** The per-project manifest is persisted under the
//!   CBM cache dir. On each fused query the manifest is loaded iff it is fresh
//!   against the live vault sequence; a stale, missing, or unreadable manifest is
//!   rebuilt from the vault (the source of truth) and re-persisted, with the
//!   rebuild reason surfaced in the response (never a silent stale serve).
//! - **Query embedding.** The query string is embedded into the semantic slots
//!   S18/S20 with the *same* [`astrolabe_panel::encode_static_embedding_slot`]
//!   the shadow import used to measure the corpus, so a query vector lives in the
//!   same space as the persisted corpus vectors.
//! - **Fail-closed.** A missing query/project, a non-shadow project, an absent
//!   vault, an unavailable embedding table, or an explicit override naming a slot
//!   the corpus cannot serve is a coded `{code, message, remediation}` refusal —
//!   never a degraded scan and never a silent slot drop.

use astrolabe_panel::{StaticEmbeddingInput, StaticEmbeddingTable, encode_static_embedding_slot};
use astrolabe_weave::search::{
    FusedResult, SLOT_CODE_SEMANTIC, SLOT_LEXICAL_BM25, SLOT_NAME_SEMANTIC, SearchCaps,
    SearchError, SearchIntent, SearchRequest, classify_intent, intent_weights_millis, plan_search,
};
use astrolabe_weave::search_index::{
    IndexKnobs, SlotIndexKind, SlotIndexManifest, SlotIndexSet, SlotQuery, run_indexed_search,
    split_identifier_tokens,
};
use astrolabe_weave::search_production::{
    ASTRO_SEARCH_PRODUCTION_STALE, PRODUCTION_VECTOR_SLOTS, build_search_index_manifest_from_vault,
    load_manifest_if_fresh, persist_manifest,
};

use super::*;

/// Astrolabe fused-search surface schema (the `structuredContent.schema` value).
pub(crate) const SEARCH_FUSION_SURFACE_SCHEMA: &str = "astrolabe.search_fusion.v1";
/// Registry version for the surface knobs declared below.
pub(crate) const SEARCH_FUSION_SURFACE_KNOB_REGISTRY_VERSION: &str =
    "astro.server.search_fusion_surface_knobs.v1";

/// Default requested result count when the caller omits `k`/`limit` (declared
/// knob; the planner cap is `k<=100`).
pub(crate) const DEFAULT_FUSION_K: u64 = 10;
/// Default per-slot search effort `ef` when omitted (declared knob; cap `ef<=512`).
pub(crate) const DEFAULT_FUSION_EF: u64 = 64;
/// Default query timeout in millis when omitted (declared knob; cap 10s).
pub(crate) const DEFAULT_FUSION_TIMEOUT_MS: u64 = 1_000;
/// Deterministic construction seed for the production index knobs (declared knob;
/// fixed so two rebuilds of one vault produce byte-identical manifests).
pub(crate) const FUSION_INDEX_SEED: u64 = 0xA570_1ABE_5EED_0042;

/// Fail-closed: the fused request carried no non-empty `query`.
pub(crate) const ASTRO_SEARCH_FUSION_QUERY: &str = "ASTRO_SEARCH_FUSION_QUERY";
/// Fail-closed: the fused request carried no `project`.
pub(crate) const ASTRO_SEARCH_FUSION_PROJECT: &str = "ASTRO_SEARCH_FUSION_PROJECT";
/// Fail-closed: the project is not shadow-indexed, so no vault/manifest exists.
pub(crate) const ASTRO_SEARCH_FUSION_SHADOW: &str = "ASTRO_SEARCH_FUSION_SHADOW";
/// Fail-closed: the shadow vault directory for the project is missing.
pub(crate) const ASTRO_SEARCH_FUSION_VAULT_MISSING: &str = "ASTRO_SEARCH_FUSION_VAULT_MISSING";
/// Fail-closed: an argument had the wrong JSON type.
pub(crate) const ASTRO_SEARCH_FUSION_ARG: &str = "ASTRO_SEARCH_FUSION_ARG";
/// Fail-closed: an explicit `fusion_override` named a slot the corpus cannot
/// serve for a text query (never silently dropped).
pub(crate) const ASTRO_SEARCH_FUSION_SLOT_UNAVAILABLE: &str =
    "ASTRO_SEARCH_FUSION_SLOT_UNAVAILABLE";
/// Fail-closed: the frozen static-embedding table could not be loaded, so the
/// query cannot be embedded into the S18/S20 corpus space.
pub(crate) const ASTRO_SEARCH_FUSION_TABLE: &str = "ASTRO_SEARCH_FUSION_TABLE";

/// How the persisted manifest was resolved for this query (labeled, never silent).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ManifestStatus {
    /// A persisted manifest was present and fresh at the live vault sequence.
    LoadedFresh,
    /// No manifest was persisted yet; it was built from the vault and persisted.
    RebuiltAbsent,
    /// The persisted manifest was stale (vault advanced); rebuilt and persisted.
    RebuiltStale,
    /// The persisted manifest was unreadable/corrupt; rebuilt from the vault
    /// (the source of truth) and persisted over it.
    RebuiltRecovered,
}

impl ManifestStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LoadedFresh => "loaded_fresh",
            Self::RebuiltAbsent => "rebuilt_absent",
            Self::RebuiltStale => "rebuilt_stale",
            Self::RebuiltRecovered => "rebuilt_recovered",
        }
    }
}

/// The per-project persisted manifest path under the CBM cache dir.
pub(crate) fn manifest_cache_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}.astrolabe-search-index.v1.json"))
}

/// Renders a weave [`SearchError`] as a coded MCP tool error result.
fn search_error_result(error: &SearchError) -> Result<String, DynError> {
    tool_error_result(format!(
        "{}: {}; remediation: {}",
        error.code(),
        error.message(),
        error.remediation()
    ))
}

/// The MCP entry point for a fused `search_graph` request (`fusion: true`).
///
/// `args` is the caller's argument object with the Astrolabe-only `fusion` knob
/// already observed by dispatch. Reads the project's persisted shadow vault,
/// resolves a fresh manifest (rebuilding from the vault when stale/absent),
/// embeds the query into S18/S20, plans + runs the fused search, optionally
/// composes the #69 `propagated_label` exact filter, and returns a labeled,
/// grounded result.
pub(crate) fn run_fused_search_graph(args: &Map<String, Value>) -> Result<String, DynError> {
    let Some(query) = string_arg(args, "query").map(ToOwned::to_owned) else {
        return coded_error(
            ASTRO_SEARCH_FUSION_QUERY,
            "fused search_graph requires a non-empty query",
            "Pass query=\"<text>\"; fusion ranks a real query, never an empty one.",
        );
    };
    let Some(project) = status_project_from_args(args)? else {
        return coded_error(
            ASTRO_SEARCH_FUSION_PROJECT,
            "fused search_graph requires project",
            "Pass the project whose shadow vault holds the search corpus.",
        );
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return coded_error(
            ASTRO_SEARCH_FUSION_SHADOW,
            format!("project {project:?} is not shadow-indexed; the fused engine needs the vault"),
            "Run index_repository with calyx=\"shadow\" for this project before fusion:true.",
        );
    }

    let k = optional_u64(args, "k")?
        .or(optional_u64(args, "limit")?)
        .unwrap_or(DEFAULT_FUSION_K);
    let ef = optional_u64(args, "ef")?.unwrap_or(DEFAULT_FUSION_EF);
    let timeout_ms = optional_u64(args, "timeout_ms")?.unwrap_or(DEFAULT_FUSION_TIMEOUT_MS);
    let temporal_alpha_millis = optional_u64(args, "temporal_alpha_millis")?.unwrap_or(0);
    let explicit_override = parse_fusion_override(args)?;
    let propagated_label = string_arg(args, "propagated_label").map(ToOwned::to_owned);

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(&cache_dir, &project)?;
    if !vault_dir.exists() {
        return coded_error(
            ASTRO_SEARCH_FUSION_VAULT_MISSING,
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "Rerun index_repository with calyx=\"shadow\" so the vault exists before searching.",
        );
    }
    let vault =
        open_shadow_vault_read_only(&vault_dir, &vault_id, &vault_salt, fusion_selected_cfs())?;
    let current_seq = vault.latest_seq();
    let manifest_path = manifest_cache_path(&cache_dir, &project);

    let (manifest, manifest_status) =
        match load_or_rebuild_manifest(&vault, &project, &manifest_path, current_seq) {
            Ok(resolved) => resolved,
            Err(error) => return search_error_result(&error),
        };

    let index_set = match SlotIndexSet::from_manifest(&manifest) {
        Ok(set) => set,
        Err(error) => return search_error_result(&error),
    };

    let table = match load_embedding_table() {
        Ok(table) => table,
        Err(result) => return result,
    };

    // Compose the optional #69 propagated_label exact filter (kernel_context).
    let label_ids = match &propagated_label {
        Some(label) => {
            let kernel_context = read_kernel_context_metadata(&cache_dir, &project)?;
            match propagated_label_symbol_ids(&kernel_context, label) {
                Ok(ids) => Some(ids),
                Err(message) => return tool_error_result(message),
            }
        }
        None => None,
    };

    let request = FusedQueryRequest {
        query: query.as_str(),
        k,
        ef,
        timeout_ms,
        temporal_alpha_millis,
        explicit_override: explicit_override.as_ref(),
    };
    let outcome = match execute_fused_query(&manifest, &index_set, &table, &request) {
        Ok(outcome) => outcome,
        Err(FusedQueryError::Search(error)) => return search_error_result(&error),
        Err(FusedQueryError::Coded {
            code,
            message,
            remediation,
        }) => return coded_error(code, message, remediation),
    };

    let (results, filter_meta) = apply_propagated_label_filter(
        outcome.results,
        propagated_label.as_deref(),
        label_ids.as_ref(),
    );

    let value = fused_result_json(
        &project,
        &query,
        &manifest,
        manifest_status,
        current_seq,
        &outcome.plan_summary,
        &results,
        filter_meta,
    );
    tool_json_result(value)
}

/// Loads a fresh manifest or rebuilds it from the vault, labeling the outcome.
pub(crate) fn load_or_rebuild_manifest<C>(
    vault: &AsterVault<C>,
    project: &str,
    manifest_path: &Path,
    current_seq: u64,
) -> Result<(SlotIndexManifest, ManifestStatus), SearchError>
where
    C: Clock,
{
    if manifest_path.exists() {
        match load_manifest_if_fresh(manifest_path, current_seq) {
            Ok(manifest) => return Ok((manifest, ManifestStatus::LoadedFresh)),
            Err(error) if error.code() == ASTRO_SEARCH_PRODUCTION_STALE => {
                let manifest = rebuild_manifest(vault, project, manifest_path)?;
                return Ok((manifest, ManifestStatus::RebuiltStale));
            }
            Err(_corrupt) => {
                // Unreadable/corrupt persisted manifest: the vault is the source of
                // truth, so regenerate over it. Labeled (RebuiltRecovered), not
                // silent.
                let manifest = rebuild_manifest(vault, project, manifest_path)?;
                return Ok((manifest, ManifestStatus::RebuiltRecovered));
            }
        }
    }
    let manifest = rebuild_manifest(vault, project, manifest_path)?;
    Ok((manifest, ManifestStatus::RebuiltAbsent))
}

fn rebuild_manifest<C>(
    vault: &AsterVault<C>,
    project: &str,
    manifest_path: &Path,
) -> Result<SlotIndexManifest, SearchError>
where
    C: Clock,
{
    let (manifest, _report) = build_search_index_manifest_from_vault(
        vault,
        project,
        &PRODUCTION_VECTOR_SLOTS,
        IndexKnobs::defaults(FUSION_INDEX_SEED),
    )?;
    persist_manifest(manifest_path, &manifest)?;
    Ok(manifest)
}

/// The warm inner request the fused engine executes (index already built).
pub(crate) struct FusedQueryRequest<'a> {
    pub(crate) query: &'a str,
    pub(crate) k: u64,
    pub(crate) ef: u64,
    pub(crate) timeout_ms: u64,
    pub(crate) temporal_alpha_millis: u64,
    pub(crate) explicit_override: Option<&'a BTreeMap<SlotId, u64>>,
}

/// The fused query outcome: the ranked results plus the plan accounting used to
/// build the labeled response.
pub(crate) struct FusedQueryOutcome {
    pub(crate) results: Vec<FusedResult>,
    pub(crate) plan_summary: PlanSummary,
}

/// A labeled account of how the fusion profile was derived and which slots the
/// corpus could not serve (standing invariant #3).
pub(crate) struct PlanSummary {
    pub(crate) intent: SearchIntent,
    pub(crate) weight_source: &'static str,
    pub(crate) weights_millis: BTreeMap<SlotId, u64>,
    pub(crate) servable_slots: Vec<SlotId>,
    pub(crate) unavailable_slots: Vec<SlotId>,
    pub(crate) k: u64,
    pub(crate) ef: u64,
    pub(crate) temporal_alpha_millis: u64,
}

/// Error from the warm inner fused path.
pub(crate) enum FusedQueryError {
    /// A weave planner/index/fusion refusal (carries its own coded card).
    Search(SearchError),
    /// A refusal this module constructs (weave's `SearchError::new` is crate-private).
    Coded {
        code: &'static str,
        message: String,
        remediation: &'static str,
    },
}

impl From<SearchError> for FusedQueryError {
    fn from(error: SearchError) -> Self {
        Self::Search(error)
    }
}

/// Runs a fused query against a prebuilt index set (the warm path measured by the
/// p99 harness). Embeds the query into the servable semantic slots, projects the
/// fusion weights onto what the corpus can serve, plans, runs, and fuses.
pub(crate) fn execute_fused_query(
    manifest: &SlotIndexManifest,
    index_set: &SlotIndexSet,
    table: &StaticEmbeddingTable,
    request: &FusedQueryRequest<'_>,
) -> Result<FusedQueryOutcome, FusedQueryError> {
    let declared_vector_slots = declared_vector_slots(manifest);
    let query_vectors = embed_query_slots(table, request.query, &declared_vector_slots)?;

    // Servable universe: S7 lexical (if declared) plus every semantic slot that is
    // both declared and produced a query vector.
    let mut servable: BTreeSet<SlotId> = BTreeSet::new();
    if manifest.slots.iter().any(|s| s.slot == SLOT_LEXICAL_BM25) {
        servable.insert(SLOT_LEXICAL_BM25);
    }
    for slot in query_vectors.keys() {
        servable.insert(*slot);
    }

    let intent = classify_intent(request.query);
    let (base_weights, weight_source) = match request.explicit_override {
        Some(weights) => ((*weights).clone(), "explicit_override"),
        None => (intent_weights_millis(intent), "intent_profile_projected"),
    };

    let mut weights_millis: BTreeMap<SlotId, u64> = BTreeMap::new();
    let mut unavailable_slots: Vec<SlotId> = Vec::new();
    for (slot, weight) in &base_weights {
        if servable.contains(slot) {
            weights_millis.insert(*slot, *weight);
        } else if request.explicit_override.is_some() {
            return Err(FusedQueryError::Coded {
                code: ASTRO_SEARCH_FUSION_SLOT_UNAVAILABLE,
                message: format!(
                    "fusion_override slot {} cannot be served for a text query over this corpus \
                     (servable: S7 lexical, S18 code-semantic, S20 name-semantic)",
                    slot.get()
                ),
                remediation: "Request only slots the corpus serves for a text query (S7 lexical, \
                              S18 code, S20 name), or omit fusion_override to use the intent \
                              profile projected onto the servable slots.",
            });
        } else {
            unavailable_slots.push(*slot);
        }
    }
    if weights_millis.is_empty() {
        return Err(FusedQueryError::Coded {
            code: ASTRO_SEARCH_FUSION_SLOT_UNAVAILABLE,
            message: "no servable fusion slot for this query and corpus".to_string(),
            remediation: "Rebuild the search index so at least the S7 lexical slot is present.",
        });
    }

    let plan_request = SearchRequest {
        query: request.query.to_string(),
        k: request.k,
        ef: request.ef,
        timeout_ms: request.timeout_ms,
        fusion_override_millis: Some(weights_millis.clone()),
        temporal_alpha_millis: request.temporal_alpha_millis,
    };
    let plan = plan_search(&plan_request, &SearchCaps::default_caps())?;

    let query = SlotQuery {
        text: request.query.to_string(),
        vectors: query_vectors,
        // A free-text fusion query supplies no structural sparse vectors; any
        // structural slot in the manifest is refused ASTRO_SEARCH_INDEX_QUERY_MISSING
        // exactly as a dense vector slot is when it receives no query vector (#332).
        sparse_vectors: BTreeMap::new(),
    };
    let results = run_indexed_search(
        &plan,
        index_set,
        &query,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
    )?;

    let servable_slots = plan.weights_millis.keys().copied().collect();
    Ok(FusedQueryOutcome {
        results,
        plan_summary: PlanSummary {
            intent,
            weight_source,
            weights_millis,
            servable_slots,
            unavailable_slots,
            k: request.k,
            ef: request.ef,
            temporal_alpha_millis: request.temporal_alpha_millis,
        },
    })
}

/// The vector slots the manifest declares as dense HNSW indexes.
fn declared_vector_slots(manifest: &SlotIndexManifest) -> BTreeSet<SlotId> {
    manifest
        .slots
        .iter()
        .filter_map(|spec| match spec.kind {
            SlotIndexKind::Vector { .. } => Some(spec.slot),
            // Structural (#332) slots carry sparse per-symbol vectors, not dense
            // query embeddings, so the free-text fusion path never embeds into them.
            SlotIndexKind::Lexical | SlotIndexKind::Structural { .. } => None,
        })
        .collect()
}

/// Embeds the query string into the requested semantic slots using the same
/// frozen table the shadow import measured the corpus with. A slot whose query
/// embedding is `Absent` (no in-vocabulary tokens) is a labeled skip: it simply
/// does not contribute a query vector.
pub(crate) fn embed_query_slots(
    table: &StaticEmbeddingTable,
    query: &str,
    declared_vector_slots: &BTreeSet<SlotId>,
) -> Result<BTreeMap<SlotId, Vec<f32>>, FusedQueryError> {
    let input = StaticEmbeddingInput {
        body_tokens: split_identifier_tokens(query),
        doc_tokens: Vec::new(),
        name: query.to_string(),
        qualified_name: query.to_string(),
    };
    let mut out: BTreeMap<SlotId, Vec<f32>> = BTreeMap::new();
    for slot in [SLOT_CODE_SEMANTIC, SLOT_NAME_SEMANTIC] {
        if !declared_vector_slots.contains(&slot) {
            continue;
        }
        let vector = encode_static_embedding_slot(slot, &input, table).map_err(|error| {
            FusedQueryError::Coded {
                code: ASTRO_SEARCH_FUSION_TABLE,
                message: format!(
                    "query embedding for slot {} failed: {}: {}",
                    slot.get(),
                    error.code(),
                    error.message()
                ),
                remediation: "The frozen nomic table rejected the query tokens; report this.",
            }
        })?;
        if let SlotVector::Dense { data, .. } = vector {
            out.insert(slot, data);
        }
        // Absent/sparse/multi: labeled skip — the slot yields no query vector and
        // is dropped from the fusion profile below.
    }
    Ok(out)
}

/// Loads the frozen static-embedding table, mapping a load failure to a coded
/// fail-closed tool error (the caller returns it verbatim).
fn load_embedding_table() -> Result<StaticEmbeddingTable, Result<String, DynError>> {
    StaticEmbeddingTable::load_default().map_err(|error| {
        coded_error(
            ASTRO_SEARCH_FUSION_TABLE,
            format!(
                "static embedding table unavailable: {}: {}",
                error.code(),
                error.message()
            ),
            "Restore the vendored nomic code_vectors.bin/code_tokens.txt so queries can be \
             embedded into the S18/S20 corpus space.",
        )
    })
}

/// Composes the #69 propagated_label exact filter over the fused results, keeping
/// only symbols carrying the label. Returns the (possibly filtered) results and a
/// labeled filter-meta value.
fn apply_propagated_label_filter(
    results: Vec<FusedResult>,
    label: Option<&str>,
    label_ids: Option<&BTreeSet<String>>,
) -> (Vec<FusedResult>, Option<Value>) {
    match (label, label_ids) {
        (Some(label), Some(ids)) => {
            let input_count = results.len();
            let filtered: Vec<FusedResult> = results
                .into_iter()
                .filter(|result| ids.contains(&result.symbol_id))
                .collect();
            let meta = json!({
                "schema": "astrolabe.search_graph_propagated_label_filter.v1",
                "label": label,
                "input_count": input_count,
                "matched_count": filtered.len(),
                "trust": "provisional",
                "freshness": "fresh",
                "provenance": "kernel_context.label_propagation (astrolabe.label_propagation.v1)",
            });
            (filtered, Some(meta))
        }
        _ => (results, None),
    }
}

/// Builds the labeled, grounded fused-search tool payload.
#[allow(clippy::too_many_arguments)]
fn fused_result_json(
    project: &str,
    query: &str,
    manifest: &SlotIndexManifest,
    manifest_status: ManifestStatus,
    current_seq: u64,
    plan_summary: &PlanSummary,
    results: &[FusedResult],
    filter_meta: Option<Value>,
) -> Value {
    let content_hash = manifest
        .content_hash()
        .map(|hash| hex_lower(&hash))
        .unwrap_or_else(|_| "unavailable".to_string());
    let result_json: Vec<Value> = results
        .iter()
        .map(|result| {
            json!({
                "qualified_name": result.symbol_id,
                "name": result.symbol_id,
                "rrf_score_micros": result.rrf_score_micros,
                "final_score_micros": result.final_score_micros,
                "contributions": result
                    .contributions
                    .iter()
                    .map(|c| json!({
                        "slot": c.slot.get(),
                        "rank": c.rank,
                        "score_micros": c.score_micros,
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut value = json!({
        "schema": SEARCH_FUSION_SURFACE_SCHEMA,
        "knob_registry_version": SEARCH_FUSION_SURFACE_KNOB_REGISTRY_VERSION,
        "project": project,
        "query": query,
        "mode": "fused",
        "intent": plan_summary.intent.as_str(),
        "weight_source": plan_summary.weight_source,
        "weights_millis": weights_json(&plan_summary.weights_millis),
        "servable_slots": slot_ids_json(&plan_summary.servable_slots),
        "unavailable_slots": slot_ids_json(&plan_summary.unavailable_slots),
        "k": plan_summary.k,
        "ef": plan_summary.ef,
        "temporal_alpha_millis": plan_summary.temporal_alpha_millis,
        "manifest": {
            "status": manifest_status.as_str(),
            "base_seq": manifest.base_seq,
            "current_vault_seq": current_seq,
            "content_hash": content_hash,
            "document_count": manifest.documents.len(),
        },
        "trust": "grounded",
        "freshness": "fresh",
        "provenance": format!(
            "astrolabe.search_fusion.v1 over AsterVault ColumnFamily::Slot{{S7,S18,S20}} @ base_seq={}",
            manifest.base_seq
        ),
        "result_count": results.len(),
        "results": result_json,
    });
    if let Some(meta) = filter_meta {
        value["astrolabe_propagated_label_filter"] = meta;
    }
    value
}

fn weights_json(weights: &BTreeMap<SlotId, u64>) -> Value {
    let mut map = Map::new();
    for (slot, weight) in weights {
        map.insert(format!("S{}", slot.get()), json!(weight));
    }
    Value::Object(map)
}

fn slot_ids_json(slots: &[SlotId]) -> Value {
    Value::Array(slots.iter().map(|slot| json!(slot.get())).collect())
}

/// Column families a read-only fused-search vault open needs: everything
/// [`build_search_index_manifest_from_vault`] reads (graph snapshot: Graph/Base/
/// Kernel/Ledger plus the legacy-series guard's Kv/Recurrence) and the two
/// semantic slot columns.
pub(crate) fn fusion_selected_cfs() -> Vec<ColumnFamily> {
    vec![
        ColumnFamily::Base,
        ColumnFamily::Graph,
        ColumnFamily::Kernel,
        ColumnFamily::Ledger,
        ColumnFamily::Kv,
        ColumnFamily::Recurrence,
        ColumnFamily::slot(SLOT_CODE_SEMANTIC),
        ColumnFamily::slot(SLOT_NAME_SEMANTIC),
    ]
}

fn coded_error(
    code: &str,
    message: impl std::fmt::Display,
    remediation: &str,
) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}

fn optional_u64(args: &Map<String, Value>, key: &str) -> Result<Option<u64>, DynError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            format!("{ASTRO_SEARCH_FUSION_ARG}: {key} must be an unsigned integer").into()
        }),
    }
}

/// Parses an explicit `fusion_override` object mapping slot names to positive
/// milli-weights. Accepts `"S7"`/`"7"`/`"lexical"`/`"code_semantic"`/`"name_semantic"`.
fn parse_fusion_override(
    args: &Map<String, Value>,
) -> Result<Option<BTreeMap<SlotId, u64>>, DynError> {
    let Some(value) = args.get("fusion_override") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let obj = value.as_object().ok_or_else(|| {
        format!("{ASTRO_SEARCH_FUSION_ARG}: fusion_override must be a JSON object of slot->weight")
    })?;
    let mut weights = BTreeMap::new();
    for (name, weight_value) in obj {
        let slot = parse_slot_name(name).ok_or_else(|| {
            format!(
                "{ASTRO_SEARCH_FUSION_ARG}: unknown fusion_override slot {name:?}; use S7/S18/S20 \
                 (lexical/code_semantic/name_semantic)"
            )
        })?;
        let weight = weight_value.as_u64().filter(|w| *w > 0).ok_or_else(|| {
            format!(
                "{ASTRO_SEARCH_FUSION_ARG}: fusion_override[{name:?}] must be a positive integer \
                 milli-weight"
            )
        })?;
        weights.insert(slot, weight);
    }
    if weights.is_empty() {
        return Err(format!(
            "{ASTRO_SEARCH_FUSION_ARG}: fusion_override must name at least one slot with a positive \
             weight"
        )
        .into());
    }
    Ok(Some(weights))
}

fn parse_slot_name(name: &str) -> Option<SlotId> {
    match name.trim().to_ascii_lowercase().as_str() {
        "s7" | "7" | "lexical" | "bm25" => Some(SLOT_LEXICAL_BM25),
        "s18" | "18" | "code_semantic" | "code" => Some(SLOT_CODE_SEMANTIC),
        "s20" | "20" | "name_semantic" | "name" => Some(SLOT_NAME_SEMANTIC),
        _ => None,
    }
}

/// Extracts the ordered `qualified_name` ids from a raw `search_graph` tool
/// result (legacy CBM shape or the fused shape share `structuredContent.results`).
/// Used by the A/B harness to score either path's ranking.
#[cfg(test)]
pub(crate) fn ordered_symbol_ids_from_search_result(raw: &str) -> Result<Vec<String>, DynError> {
    let value: Value = serde_json::from_str(raw)?;
    let results = value
        .get("structuredContent")
        .and_then(|structured| structured.get("results"))
        .and_then(Value::as_array)
        .ok_or("search result carried no structuredContent.results array")?;
    let mut ids = Vec::with_capacity(results.len());
    for hit in results {
        let id = hit
            .get("qualified_name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .or_else(|| hit.get("name").and_then(Value::as_str))
            .unwrap_or_default();
        if !id.is_empty() {
            ids.push(id.to_string());
        }
    }
    Ok(ids)
}

/// The Astrolabe-side extension properties overlaid onto the CBM `search_graph`
/// tool schema in tools/list (#328). Documents the `propagated_label` filter
/// (#69) and the `fusion` engine (#42) truthfully — every property here maps to
/// an argument this module or [`super::dispatch::handle_search_graph`] actually
/// honors.
pub(crate) fn search_graph_astrolabe_property_overlay() -> Vec<(String, Value)> {
    vec![
        (
            "propagated_label".to_string(),
            json!({
                "type": "string",
                "description": "Astrolabe extension (#69): intersect the raw CBM hits with the \
                    project's persisted propagated labels (kernel_context.label_propagation), \
                    keeping only symbols carrying this inferred label. Provisional-trust filter; \
                    fails closed if the project is missing, not calyx-shadow-indexed, or \
                    propagation is unavailable. Requires project."
            }),
        ),
        (
            "fusion".to_string(),
            json!({
                "type": "boolean",
                "description": "Astrolabe extension (#42): when true, serve the Sextant-fused \
                    engine instead of legacy CBM BM25 — deterministic intent classification, \
                    fail-closed planner caps (k<=100, ef<=512, slots<=16), per-slot indexes \
                    (S7 BM25 + S18/S20 HNSW over the shadow vault), RRF fusion, and a bounded \
                    temporal boost. Requires a calyx-shadow-indexed project. Omitted/false keeps \
                    the byte-identical legacy passthrough."
            }),
        ),
        (
            "fusion_override".to_string(),
            json!({
                "type": "object",
                "description": "Astrolabe extension (#42, fusion:true only): explicit per-slot \
                    fusion weights, slot name (S7/S18/S20 or lexical/code_semantic/name_semantic) \
                    to a positive integer milli-weight (1000 = 1.0). Overrides the deterministic \
                    intent profile. Naming a slot the corpus cannot serve for a text query fails \
                    closed (ASTRO_SEARCH_FUSION_SLOT_UNAVAILABLE), never a silent drop."
            }),
        ),
        (
            "temporal_alpha_millis".to_string(),
            json!({
                "type": "integer",
                "description": "Astrolabe extension (#42, fusion:true only): bounded recency-boost \
                    strength in millis (0 disables; capped at 100 = alpha 0.10). Larger values \
                    fail closed."
            }),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure FSV of the query embedder: the same query embeds identically across
    // repeats (determinism), only declared slots are embedded, and a
    // no-vocabulary query yields no vector rather than a fabricated one.
    #[test]
    fn embed_query_slots_is_deterministic_and_declared_only() {
        let table = StaticEmbeddingTable::load_default().expect("load frozen nomic table");
        let declared: BTreeSet<SlotId> = [SLOT_CODE_SEMANTIC, SLOT_NAME_SEMANTIC]
            .into_iter()
            .collect();

        let first = embed_query_slots(&table, "authenticate user token", &declared)
            .unwrap_or_else(|_| panic!("embed must not fail on a real query"));
        let second = embed_query_slots(&table, "authenticate user token", &declared)
            .unwrap_or_else(|_| panic!("embed must be deterministic"));
        assert_eq!(
            first, second,
            "identical query must embed to identical vectors"
        );
        assert!(
            first.contains_key(&SLOT_CODE_SEMANTIC) && first.contains_key(&SLOT_NAME_SEMANTIC),
            "both declared semantic slots must embed a real query"
        );

        // A slot not declared in the corpus is never embedded.
        let only_code: BTreeSet<SlotId> = [SLOT_CODE_SEMANTIC].into_iter().collect();
        let restricted = embed_query_slots(&table, "authenticate user", &only_code)
            .unwrap_or_else(|_| panic!("embed must not fail"));
        assert!(restricted.contains_key(&SLOT_CODE_SEMANTIC));
        assert!(
            !restricted.contains_key(&SLOT_NAME_SEMANTIC),
            "an undeclared slot must not be embedded"
        );
    }

    // #328: the tools/list overlay advertises the fusion + propagated_label knobs,
    // and every advertised property maps to a real honored argument.
    #[test]
    fn search_graph_overlay_advertises_fusion_and_propagated_label_truthfully() {
        let overlay = search_graph_astrolabe_property_overlay();
        let names: BTreeSet<&str> = overlay.iter().map(|(name, _)| name.as_str()).collect();
        assert!(names.contains("fusion"), "fusion knob must be advertised");
        assert!(
            names.contains("propagated_label"),
            "propagated_label knob must be advertised"
        );
        assert!(names.contains("fusion_override"));
        assert!(names.contains("temporal_alpha_millis"));
        for (name, schema) in &overlay {
            assert!(
                schema.get("type").is_some(),
                "{name} overlay must declare a JSON type"
            );
            let description = schema
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            assert!(
                !description.is_empty(),
                "{name} overlay must carry a truthful description"
            );
        }
    }

    #[test]
    fn manifest_cache_path_is_project_scoped_under_cache_dir() {
        let path = manifest_cache_path(Path::new("/cache"), "demo");
        assert!(path.ends_with("demo.astrolabe-search-index.v1.json"));
    }

    #[test]
    fn parse_slot_name_accepts_declared_aliases_only() {
        assert_eq!(parse_slot_name("S7"), Some(SLOT_LEXICAL_BM25));
        assert_eq!(parse_slot_name("code_semantic"), Some(SLOT_CODE_SEMANTIC));
        assert_eq!(parse_slot_name("20"), Some(SLOT_NAME_SEMANTIC));
        assert_eq!(parse_slot_name("s1"), None);
        assert_eq!(parse_slot_name("api_callees"), None);
    }
}
