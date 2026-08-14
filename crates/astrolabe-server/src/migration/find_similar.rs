//! Navigation tool `find_similar` (P6.7, #43) — symbol-anchored "more like this"
//! over a shadow-indexed project's persisted per-slot vectors.
//!
//! This is the MCP surface for the weave symbol-anchored query APIs:
//! [`structural_more_like_this`] (sparse S1/S4, the #332 structural surface) and
//! [`semantic_more_like_this`] (dense S18/S20). It builds ONE combined manifest
//! (S1 struct-trigrams, S4 API-callees, S18 code-semantic, S20 name-semantic) from
//! the live vault — the source of truth — and anchors the requested mode on an
//! already-indexed symbol's own persisted vectors.
//!
//! Modes served from persisted state (never a fabricated or degraded answer):
//! - `structural` — sparse S1+S4 cosine neighbors (copy-paste / near-textual).
//! - `api` — sparse S4 (API-callee) cosine neighbors only.
//! - `semantic` — dense S18+S20 cosine neighbors (reimplementation-sensitive).
//! - `clone` / `agree` / `disagree` — clone taxonomy fusing the structural and
//!   semantic neighbor lists: present in both => true clone; structural-only =>
//!   copy-paste; semantic-only => reimplementation. `agree` filters to true
//!   clones; `disagree` filters to the copy-paste ∪ reimplementation set.
//!
//! Fail-closed contract (standing invariants #2/#3/#6): a missing project/anchor,
//! a non-shadow project, an absent vault, a bad argument type, or a mode not
//! backed by the persisted slot vectors is a coded `{code, message, remediation}`
//! refusal — never a silent empty or a degraded guess.

use astrolabe_weave::search::{
    FusedResult, SLOT_API_CALLEES, SLOT_CODE_SEMANTIC, SLOT_NAME_SEMANTIC, SLOT_STRUCT_TRIGRAMS,
    SearchCaps, SearchError,
};
use astrolabe_weave::search_index::{IndexKnobs, SlotIndexSet};
use astrolabe_weave::search_production::{
    CloneCandidate, CloneClass, SEMANTIC_QUERY_SLOTS, STRUCTURAL_QUERY_SLOTS,
    build_search_index_manifest_from_vault, classify_clone_taxonomy, semantic_more_like_this,
    structural_more_like_this,
};

use super::*;

/// Surface schema tag for the `find_similar` response envelope.
pub(crate) const FIND_SIMILAR_SURFACE_SCHEMA: &str = "astrolabe.find_similar.v2";
/// Registry version for the find_similar surface knobs declared below.
pub(crate) const FIND_SIMILAR_KNOB_REGISTRY_VERSION: &str =
    "astro.server.find_similar_surface_knobs.v1";

/// Default requested neighbor count when the caller omits `k` (declared knob; the
/// planner cap is `k<=100`).
pub(crate) const DEFAULT_FIND_SIMILAR_K: u64 = 10;
/// Default per-slot search effort `ef` when omitted (declared knob; cap `ef<=512`).
pub(crate) const DEFAULT_FIND_SIMILAR_EF: u64 = 64;
/// Deterministic construction seed for the combined index knobs (declared knob;
/// fixed so two rebuilds of one vault produce byte-identical manifests).
pub(crate) const FIND_SIMILAR_INDEX_SEED: u64 = 0xF1D5_1A1B_5EED_0043;

/// Fail-closed: the request carried no `project`.
pub(crate) const ASTRO_FIND_SIMILAR_PROJECT: &str = "ASTRO_FIND_SIMILAR_PROJECT";
/// Fail-closed: the request carried no anchor `symbol`.
pub(crate) const ASTRO_FIND_SIMILAR_ANCHOR: &str = "ASTRO_FIND_SIMILAR_ANCHOR";
/// Fail-closed: a qualified-name anchor resolves to multiple stable atoms.
pub(crate) const ASTRO_FIND_SIMILAR_ANCHOR_AMBIGUOUS: &str = "ASTRO_FIND_SIMILAR_ANCHOR_AMBIGUOUS";
/// Fail-closed: the project is not shadow-indexed, so no vault/manifest exists.
pub(crate) const ASTRO_FIND_SIMILAR_SHADOW: &str = "ASTRO_FIND_SIMILAR_SHADOW";
/// Fail-closed: the shadow vault directory for the project is missing.
pub(crate) const ASTRO_FIND_SIMILAR_VAULT_MISSING: &str = "ASTRO_FIND_SIMILAR_VAULT_MISSING";
/// Fail-closed: an argument had the wrong JSON type.
pub(crate) const ASTRO_FIND_SIMILAR_ARG: &str = "ASTRO_FIND_SIMILAR_ARG";
/// Fail-closed: an unknown or not-yet-served `mode`.
pub(crate) const ASTRO_FIND_SIMILAR_MODE: &str = "ASTRO_FIND_SIMILAR_MODE";

/// The four combined per-slot vectors the find_similar manifest indexes: the two
/// sparse structural slots (S1/S4) and the two dense semantic slots (S18/S20).
pub(crate) const FIND_SIMILAR_SLOTS: [SlotId; 4] = [
    SLOT_STRUCT_TRIGRAMS,
    SLOT_API_CALLEES,
    SLOT_CODE_SEMANTIC,
    SLOT_NAME_SEMANTIC,
];

/// Column families a read-only find_similar vault open needs: the graph-snapshot
/// families (Base/Graph/Kernel/Ledger plus the legacy-series guard's Kv/Recurrence)
/// and the four per-slot vector columns (S1/S4/S18/S20).
fn find_similar_selected_cfs() -> Vec<ColumnFamily> {
    vec![
        ColumnFamily::Base,
        ColumnFamily::Graph,
        ColumnFamily::Kernel,
        ColumnFamily::Ledger,
        ColumnFamily::Kv,
        ColumnFamily::Recurrence,
        ColumnFamily::slot(SLOT_STRUCT_TRIGRAMS),
        ColumnFamily::slot(SLOT_API_CALLEES),
        ColumnFamily::slot(SLOT_CODE_SEMANTIC),
        ColumnFamily::slot(SLOT_NAME_SEMANTIC),
    ]
}

fn fs_coded_error(
    code: &str,
    message: impl std::fmt::Display,
    remediation: &str,
) -> Result<String, DynError> {
    ToolFault::new(code, message.to_string(), remediation).into_result()
}

fn fs_search_error(error: &SearchError) -> Result<String, DynError> {
    ToolFault::new(error.code(), error.message(), error.remediation()).into_result()
}

/// Reads an optional unsigned argument, refusing a wrong JSON type as a
/// caller-correctable fault rather than a bare error string (#919).
fn fs_optional_u64(args: &Map<String, Value>, key: &str) -> Result<Option<u64>, ToolFault> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            argument_type_fault(
                ASTRO_FIND_SIMILAR_ARG,
                "find_similar",
                key,
                "a JSON unsigned integer",
                value,
            )
        }),
    }
}

/// Every purely syntactic check on `find_similar` arguments, resolved before any
/// persisted state is read.
///
/// #919 requires argument validation to precede the freshness/vault read, but the
/// handler used to consult the project's persisted dial *before* type-checking
/// `k`/`ef` — so `k: "bad"` on a non-shadow project reported "not shadow-indexed"
/// and the caller never learned the real fault. Resolving the argument shape here
/// keeps the refusal honest and means a malformed request touches no store.
struct FindSimilarArgs {
    project: String,
    anchor: String,
    mode: String,
    k: u64,
    ef: u64,
}

fn parse_find_similar_args(args: &Map<String, Value>) -> Result<FindSimilarArgs, ToolFault> {
    let project = status_project_from_args(args)
        .map_err(|error| {
            ToolFault::new(
                ASTRO_FIND_SIMILAR_PROJECT,
                format!("find_similar could not resolve the project argument: {error}"),
                "Pass project=\"<name>\" or a repo_path that resolves to an indexed project.",
            )
        })?
        .ok_or_else(|| {
            ToolFault::new(
                ASTRO_FIND_SIMILAR_PROJECT,
                "find_similar requires project",
                "Pass the project whose shadow vault holds the search corpus.",
            )
        })?;
    let anchor = string_arg(args, "symbol").map(ToOwned::to_owned).ok_or_else(|| {
        ToolFault::new(
            ASTRO_FIND_SIMILAR_ANCHOR,
            "find_similar requires an anchor symbol",
            "Pass symbol=\"<qualified_name>\" — the already-indexed symbol to find neighbors of.",
        )
    })?;
    if let Some(value) = args.get("mode")
        && !value.is_null()
        && !value.is_string()
    {
        return Err(argument_type_fault(
            ASTRO_FIND_SIMILAR_ARG,
            "find_similar",
            "mode",
            "a JSON string",
            value,
        ));
    }
    let mode = string_arg(args, "mode").unwrap_or("structural").to_string();
    if !matches!(
        mode.as_str(),
        "structural" | "api" | "semantic" | "clone" | "agree" | "disagree"
    ) {
        return Err(ToolFault::new(
            ASTRO_FIND_SIMILAR_MODE,
            format!(
                "find_similar mode {mode:?} is not served by the persisted slot-vector surface"
            ),
            "Use mode structural, api, semantic, clone, agree, or disagree. profile/co_change/\
             define are tracked separately and refuse rather than fabricate a neighbor list.",
        )
        .with_detail("argument", "mode")
        .with_detail("observed_mode", mode.clone()));
    }
    let k = fs_optional_u64(args, "k")?.unwrap_or(DEFAULT_FIND_SIMILAR_K);
    let ef = fs_optional_u64(args, "ef")?.unwrap_or(DEFAULT_FIND_SIMILAR_EF);
    Ok(FindSimilarArgs {
        project,
        anchor,
        mode,
        k,
        ef,
    })
}

/// MCP entry point for `find_similar`.
pub(crate) fn handle_find_similar(args_json: &str) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return fs_coded_error(
            ASTRO_FIND_SIMILAR_ARG,
            "find_similar arguments must be a JSON object",
            "Pass a JSON object with project, symbol, and optional mode/k/ef.",
        );
    };
    let Some(args) = args.as_object() else {
        return fs_coded_error(
            ASTRO_FIND_SIMILAR_ARG,
            "find_similar arguments must be a JSON object",
            "Pass a JSON object with project, symbol, and optional mode/k/ef.",
        );
    };

    // #919: resolve the complete argument shape before touching any persisted
    // state, so a malformed request is refused on its own terms and reads nothing.
    let FindSimilarArgs {
        project,
        anchor,
        mode,
        k,
        ef,
    } = match parse_find_similar_args(args) {
        Ok(parsed) => parsed,
        Err(fault) => return fault.into_result(),
    };

    if read_dial(&project)? != MigrationDial::Shadow {
        return fs_coded_error(
            ASTRO_FIND_SIMILAR_SHADOW,
            format!("project {project:?} is not shadow-indexed; find_similar needs the vault"),
            "Run index_repository with calyx=\"shadow\" for this project before find_similar.",
        );
    }

    let caps = SearchCaps::default_caps();

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if let Some(refusal) = shadow_graph_freshness_refusal(&cache_dir, &project, "find_similar")? {
        return Ok(refusal);
    }
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(&cache_dir, &project)?;
    if !vault_dir.exists() {
        return fs_coded_error(
            ASTRO_FIND_SIMILAR_VAULT_MISSING,
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "Rerun index_repository with calyx=\"shadow\" so the vault exists before find_similar.",
        );
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        find_similar_selected_cfs(),
    )?;
    let current_seq = vault.latest_seq();

    // Build the combined manifest fresh from the vault (the source of truth) so the
    // anchor is always ranked against the current graph — never a stale index.
    let (manifest, report) = match build_search_index_manifest_from_vault(
        &vault,
        &project,
        &FIND_SIMILAR_SLOTS,
        IndexKnobs::defaults(FIND_SIMILAR_INDEX_SEED),
    ) {
        Ok(resolved) => resolved,
        Err(error) => return fs_search_error(&error),
    };
    let index_set = match SlotIndexSet::from_manifest(&manifest) {
        Ok(set) => set,
        Err(error) => return fs_search_error(&error),
    };
    let base_seq = report.base_seq;
    let mut identity_by_atom = BTreeMap::new();
    for symbol in &report.symbols {
        if identity_by_atom
            .insert(
                symbol.symbol_id.clone(),
                (symbol.qualified_name.clone(), symbol.name.clone()),
            )
            .is_some()
        {
            return fs_coded_error(
                ASTRO_FIND_SIMILAR_ANCHOR,
                format!(
                    "duplicate stable atom id {:?} in search corpus",
                    symbol.symbol_id
                ),
                "Rebuild the project store from source; stable atom ids must be unique.",
            );
        }
    }
    let anchor_id = if identity_by_atom.contains_key(&anchor) {
        anchor.clone()
    } else {
        let candidates = report
            .symbols
            .iter()
            .filter(|symbol| symbol.qualified_name == anchor)
            .map(|symbol| symbol.symbol_id.clone())
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [only] => only.clone(),
            [] => {
                return fs_coded_error(
                    ASTRO_FIND_SIMILAR_ANCHOR,
                    format!(
                        "anchor {anchor:?} is neither a stable atom id nor a live qualified name"
                    ),
                    "Pass a stable atom id from search/index output, or an unambiguous live qualified name.",
                );
            }
            _ => {
                return fs_coded_error(
                    ASTRO_FIND_SIMILAR_ANCHOR_AMBIGUOUS,
                    format!(
                        "qualified-name anchor {anchor:?} resolves to {} stable atoms: {}",
                        candidates.len(),
                        candidates.join(", ")
                    ),
                    "Pass the exact stable atom id for the intended overload or same-name definition.",
                );
            }
        }
    };

    match mode.as_str() {
        "structural" => serve_structural(
            &index_set,
            &project,
            &anchor_id,
            &STRUCTURAL_QUERY_SLOTS,
            k,
            ef,
            &caps,
            base_seq,
            current_seq,
            &mode,
            &identity_by_atom,
        ),
        "api" => serve_structural(
            &index_set,
            &project,
            &anchor_id,
            &[SLOT_API_CALLEES],
            k,
            ef,
            &caps,
            base_seq,
            current_seq,
            &mode,
            &identity_by_atom,
        ),
        "semantic" => serve_semantic(
            &index_set,
            &project,
            &anchor_id,
            k,
            ef,
            &caps,
            base_seq,
            current_seq,
            &mode,
            &identity_by_atom,
        ),
        "clone" | "agree" | "disagree" => serve_clone_taxonomy(
            &index_set,
            &project,
            &anchor_id,
            k,
            ef,
            &caps,
            base_seq,
            current_seq,
            &mode,
            &identity_by_atom,
        ),
        other => fs_coded_error(
            ASTRO_FIND_SIMILAR_MODE,
            format!(
                "find_similar mode {other:?} is not served by the persisted slot-vector surface"
            ),
            "Use mode structural, api, semantic, clone, agree, or disagree. profile/co_change/\
             define are tracked separately and refuse rather than fabricate a neighbor list.",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_structural(
    index_set: &SlotIndexSet,
    project: &str,
    anchor: &str,
    slots: &[SlotId],
    k: u64,
    ef: u64,
    caps: &SearchCaps,
    base_seq: u64,
    current_seq: u64,
    mode: &str,
    identity_by_atom: &BTreeMap<String, (String, String)>,
) -> Result<String, DynError> {
    let result = match structural_more_like_this(index_set, anchor, slots, k, ef, caps) {
        Ok(result) => result,
        Err(error) => return fs_search_error(&error),
    };
    let value = json!({
        "schema": FIND_SIMILAR_SURFACE_SCHEMA,
        "knob_registry_version": FIND_SIMILAR_KNOB_REGISTRY_VERSION,
        "project": project,
        "mode": mode,
        "anchor_symbol": result.anchor_symbol_id,
        "anchor_qualified_name": identity_by_atom.get(&result.anchor_symbol_id).map(|identity| &identity.0),
        "anchored_slots": slot_ids_json(&result.anchored_slots),
        "k": k,
        "ef": ef,
        "neighbor_count": result.neighbors.len(),
        "neighbors": neighbors_json(&result.neighbors, identity_by_atom),
        "trust": "grounded",
        "freshness": freshness_label(base_seq, current_seq),
        "provenance": provenance_label(mode, base_seq, &result.anchored_slots),
    });
    tool_json_result(value)
}

#[allow(clippy::too_many_arguments)]
fn serve_semantic(
    index_set: &SlotIndexSet,
    project: &str,
    anchor: &str,
    k: u64,
    ef: u64,
    caps: &SearchCaps,
    base_seq: u64,
    current_seq: u64,
    mode: &str,
    identity_by_atom: &BTreeMap<String, (String, String)>,
) -> Result<String, DynError> {
    let result =
        match semantic_more_like_this(index_set, anchor, &SEMANTIC_QUERY_SLOTS, k, ef, caps) {
            Ok(result) => result,
            Err(error) => return fs_search_error(&error),
        };
    let value = json!({
        "schema": FIND_SIMILAR_SURFACE_SCHEMA,
        "knob_registry_version": FIND_SIMILAR_KNOB_REGISTRY_VERSION,
        "project": project,
        "mode": mode,
        "anchor_symbol": result.anchor_symbol_id,
        "anchor_qualified_name": identity_by_atom.get(&result.anchor_symbol_id).map(|identity| &identity.0),
        "anchored_slots": slot_ids_json(&result.anchored_slots),
        "k": k,
        "ef": ef,
        "neighbor_count": result.neighbors.len(),
        "neighbors": neighbors_json(&result.neighbors, identity_by_atom),
        "trust": "grounded",
        "freshness": freshness_label(base_seq, current_seq),
        "provenance": provenance_label(mode, base_seq, &result.anchored_slots),
    });
    tool_json_result(value)
}

/// Serves the clone taxonomy: runs both the structural and semantic anchored
/// queries and classifies the union of their neighbor lists. `agree` keeps only
/// true clones; `disagree` keeps copy-paste ∪ reimplementation; `clone` returns
/// the full taxonomy.
#[allow(clippy::too_many_arguments)]
fn serve_clone_taxonomy(
    index_set: &SlotIndexSet,
    project: &str,
    anchor: &str,
    k: u64,
    ef: u64,
    caps: &SearchCaps,
    base_seq: u64,
    current_seq: u64,
    mode: &str,
    identity_by_atom: &BTreeMap<String, (String, String)>,
) -> Result<String, DynError> {
    let structural =
        match structural_more_like_this(index_set, anchor, &STRUCTURAL_QUERY_SLOTS, k, ef, caps) {
            Ok(result) => result,
            Err(error) => return fs_search_error(&error),
        };
    let semantic =
        match semantic_more_like_this(index_set, anchor, &SEMANTIC_QUERY_SLOTS, k, ef, caps) {
            Ok(result) => result,
            Err(error) => return fs_search_error(&error),
        };
    let structural_ids: Vec<String> = structural
        .neighbors
        .iter()
        .map(|n| n.symbol_id.clone())
        .collect();
    let semantic_ids: Vec<String> = semantic
        .neighbors
        .iter()
        .map(|n| n.symbol_id.clone())
        .collect();
    let taxonomy = classify_clone_taxonomy(&structural_ids, &semantic_ids);

    // Mode-specific filter over the classified union.
    let filtered: Vec<&CloneCandidate> = taxonomy
        .iter()
        .filter(|candidate| match mode {
            "agree" => candidate.class == CloneClass::TrueClone,
            "disagree" => candidate.class != CloneClass::TrueClone,
            // "clone": the full taxonomy.
            _ => true,
        })
        .collect();

    let candidates_json: Vec<Value> = filtered
        .iter()
        .map(|candidate| {
            let identity = identity_by_atom
                .get(&candidate.symbol_id)
                .expect("taxonomy candidates originate in the current corpus");
            json!({
                "symbol_id": candidate.symbol_id,
                "qualified_name": identity.0,
                "name": identity.1,
                "class": candidate.class.as_str(),
                "structural_rank": candidate.structural_rank,
                "semantic_rank": candidate.semantic_rank,
            })
        })
        .collect();

    let anchored_slots: Vec<SlotId> = STRUCTURAL_QUERY_SLOTS
        .iter()
        .chain(SEMANTIC_QUERY_SLOTS.iter())
        .copied()
        .collect();
    let value = json!({
        "schema": FIND_SIMILAR_SURFACE_SCHEMA,
        "knob_registry_version": FIND_SIMILAR_KNOB_REGISTRY_VERSION,
        "project": project,
        "mode": mode,
        "anchor_symbol": anchor,
        "anchor_qualified_name": identity_by_atom.get(anchor).map(|identity| &identity.0),
        "taxonomy": {
            "structural_only": "copy_paste",
            "semantic_only": "reimplementation",
            "both": "true_clone",
        },
        "structural_slots": slot_ids_json(&structural.anchored_slots),
        "semantic_slots": slot_ids_json(&semantic.anchored_slots),
        "k": k,
        "ef": ef,
        "structural_neighbor_count": structural_ids.len(),
        "semantic_neighbor_count": semantic_ids.len(),
        "candidate_count": candidates_json.len(),
        "candidates": candidates_json,
        "trust": "grounded",
        "freshness": freshness_label(base_seq, current_seq),
        "provenance": provenance_label(mode, base_seq, &anchored_slots),
    });
    tool_json_result(value)
}

fn neighbors_json(
    neighbors: &[FusedResult],
    identity_by_atom: &BTreeMap<String, (String, String)>,
) -> Vec<Value> {
    neighbors
        .iter()
        .map(|result| {
            let identity = identity_by_atom
                .get(&result.symbol_id)
                .expect("neighbors originate in the current corpus");
            json!({
                "symbol_id": result.symbol_id,
                "qualified_name": identity.0,
                "name": identity.1,
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
        .collect()
}

fn slot_ids_json(slots: &[SlotId]) -> Value {
    Value::Array(slots.iter().map(|slot| json!(slot.get())).collect())
}

/// Fresh iff the manifest was built at exactly the current vault sequence (it
/// always is here — the manifest is rebuilt from the live vault on every call).
fn freshness_label(base_seq: u64, current_seq: u64) -> &'static str {
    if base_seq == current_seq {
        "fresh"
    } else {
        "stale"
    }
}

fn provenance_label(mode: &str, base_seq: u64, slots: &[SlotId]) -> String {
    let slot_list = slots
        .iter()
        .map(|slot| format!("S{}", slot.get()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "astrolabe.find_similar.v1 mode={mode} over AsterVault ColumnFamily::Slot{{{slot_list}}} @ base_seq={base_seq}"
    )
}

/// The `find_similar` tool definition advertised in tools/list.
pub(crate) fn find_similar_tool_definition() -> Value {
    json!({
        "name": "find_similar",
        "title": "Find Similar",
        "description": "Symbol-anchored \"more like this\" navigation for a calyx-shadow-indexed project, ranked over the persisted per-slot vectors an anchor symbol already carries — never a free-text query. Modes: structural (sparse S1 struct-trigram + S4 API-callee cosine — copy-paste / near-textual neighbors), api (S4 API-callee cosine only), semantic (dense S18 code-semantic + S20 name-semantic cosine — reimplementation-sensitive), and the clone taxonomy clone/agree/disagree that fuses the structural and semantic neighbor lists: present in both => true clone, structural-only => copy-paste, semantic-only => reimplementation (agree keeps true clones, disagree keeps copy-paste ∪ reimplementation). Every response carries trust/freshness/provenance and the anchored slots. Fails closed with {code,message,remediation} on a missing project/anchor, a non-shadow project, an absent vault, or an anchor/slot with no persisted vector (never a partial score or a silent empty). profile/co_change/define modes are not backed by this surface and refuse rather than fabricate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "symbol": {
                    "type": "string",
                    "description": "Anchor symbol qualified_name — the already-indexed symbol to find neighbors of. An anchor absent from the index refuses fail-closed."
                },
                "mode": {
                    "type": "string",
                    "enum": ["structural", "api", "semantic", "clone", "agree", "disagree"],
                    "description": "Which similarity signal to anchor on. Default structural."
                },
                "k": {
                    "type": "integer",
                    "description": "Requested neighbor count (default 10; planner cap 100)."
                },
                "ef": {
                    "type": "integer",
                    "description": "Per-slot search effort (default 64; planner cap 512)."
                }
            },
            "required": ["project", "symbol"],
            "additionalProperties": false
        }
    })
}
