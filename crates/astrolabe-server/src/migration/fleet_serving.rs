//! Atomic fleet-scope serving for `get_kernel` and `kernel_answer` (#1151).
//!
//! A `fleet:` scope is selected from the fleet catalog's content-addressed
//! current pointer. Cold loads independently rebuild every repository source
//! binding and the complete fleet projection before caching the immutable
//! generation. Warm loads point-read the fleet manifest/Ledger plus each
//! repository's current pointer/manifest/Ledger and durable Base+Blob content
//! generations, then reuse only the matching immutable fleet projection/HNSW.
//! Historical fixed three-row names are exact-presence-classified only; the
//! production path never decodes or returns a legacy artifact.

use super::*;

use std::sync::Arc;

use astrolabe_fleet::{
    CurrentFleetKernelGeneration, FleetCatalog, FleetKernelSourceVerificationReport,
    read_current_fleet_kernel_generation_header, read_verified_fleet_kernel_generation,
    verify_fleet_kernel_generation_sources,
};
use calyx_core::CalyxError;

pub(crate) const ASTRO_FLEET_SCOPE_INVALID: &str = "ASTRO_FLEET_SCOPE_INVALID";
pub(crate) const ASTRO_FLEET_CATALOG_MISSING: &str = "ASTRO_FLEET_CATALOG_MISSING";
pub(crate) const ASTRO_FLEET_SCOPE_UNKNOWN: &str = "ASTRO_FLEET_SCOPE_UNKNOWN";
pub(crate) const ASTRO_FLEET_QUERY_REQUIRED: &str = "ASTRO_FLEET_QUERY_REQUIRED";
pub(crate) const ASTRO_FLEET_QUERY_ENCODER_DRIFT: &str = "ASTRO_FLEET_QUERY_ENCODER_DRIFT";
pub(crate) const ASTRO_FLEET_KERNEL_MODE_UNSUPPORTED: &str = "ASTRO_FLEET_KERNEL_MODE_UNSUPPORTED";
pub(crate) const ASTRO_FLEET_GENERATION_CACHE_CLOCK_OVERFLOW: &str =
    "ASTRO_FLEET_GENERATION_CACHE_CLOCK_OVERFLOW";

pub(crate) fn is_fleet_scope(scope: &str) -> bool {
    scope.starts_with("fleet:")
}

#[derive(Default)]
struct FleetGenerationCache {
    entries: BTreeMap<
        String,
        (
            Arc<OnceLock<Result<Arc<CurrentFleetKernelGeneration>, CalyxError>>>,
            u64,
        ),
    >,
    clock: u64,
}

impl FleetGenerationCache {
    fn load_cell(
        &mut self,
        key: String,
    ) -> Result<Arc<OnceLock<Result<Arc<CurrentFleetKernelGeneration>, CalyxError>>>, CalyxError>
    {
        self.clock = next_fleet_generation_cache_clock(self.clock)?;
        if let Some((cell, touched)) = self.entries.get_mut(&key) {
            *touched = self.clock;
            return Ok(Arc::clone(cell));
        }
        let capacity = fleet_generation_cache_entries();
        while self.entries.len() >= capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, touched))| *touched)
                .map(|(key, _)| key.clone())
                .expect("nonempty fleet generation cache");
            self.entries.remove(&oldest);
        }
        let cell = Arc::new(OnceLock::new());
        self.entries.insert(key, (Arc::clone(&cell), self.clock));
        Ok(cell)
    }
}

fn next_fleet_generation_cache_clock(current: u64) -> Result<u64, CalyxError> {
    current.checked_add(1).ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_GENERATION_CACHE_CLOCK_OVERFLOW,
        message: "fleet generation cache LRU clock exhausted u64; ordering can no longer advance exactly"
            .to_string(),
        remediation: "restart the Astrolabe server to establish a fresh empty generation cache before serving another fleet request",
    })
}

/// Manual-FSV entrypoint for the production checked LRU-order edge. It mutates
/// no cache or persisted state.
#[cfg(feature = "manual-fsv")]
pub fn manual_fsv_cache_clock_overflow() -> Result<Value, CalyxError> {
    match next_fleet_generation_cache_clock(u64::MAX) {
        Err(error) if error.code == ASTRO_FLEET_GENERATION_CACHE_CLOCK_OVERFLOW => Ok(json!({
            "schema": "astrolabe.issue_1151.cache_clock_edge.v1",
            "input": u64::MAX.to_string(),
            "code": error.code,
            "saturation_used": false,
        })),
        Err(error) => Err(CalyxError {
            code: error.code,
            message: format!(
                "manual fleet cache-clock edge returned the wrong refusal: {}",
                error.message,
            ),
            remediation: error.remediation,
        }),
        Ok(value) => Err(CalyxError {
            code: ASTRO_FLEET_GENERATION_CACHE_CLOCK_OVERFLOW,
            message: format!(
                "manual fleet cache-clock edge unexpectedly advanced u64::MAX to {value}"
            ),
            remediation: "restore checked LRU clock advancement before serving fleet cache entries",
        }),
    }
}

static FLEET_GENERATION_CACHE: OnceLock<Mutex<FleetGenerationCache>> = OnceLock::new();

fn fleet_generation_cache_entries() -> usize {
    KERNEL_ANSWER_KNOBS
        .iter()
        .find(|knob| knob.name == KNOB_ANSWER_INDEX_CACHE_ENTRIES)
        .expect("kernel generation cache knob is declared")
        .default as usize
}

fn refusal(
    schema: &str,
    code: &str,
    scope: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": schema,
        "status": "refused",
        "fleet": true,
        "scope": scope,
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "trust": "provisional",
        "freshness": "not_evaluated",
    })
}

fn calyx_refusal(schema: &str, scope: &str, error: &CalyxError) -> Value {
    refusal(
        schema,
        error.code,
        scope,
        error.message.clone(),
        error.remediation,
    )
}

fn open_fleet_catalog(
    args_obj: &Map<String, Value>,
) -> Result<(FleetCatalog, PathBuf), CalyxError> {
    let root =
        string_arg(args_obj, "fleet_catalog_root").unwrap_or(astrolabe_fleet::DEFAULT_CATALOG_ROOT);
    let store_root = PathBuf::from(
        string_arg(args_obj, "fleet_store_root").unwrap_or(astrolabe_fleet::DEFAULT_STORE_ROOT),
    );
    let catalog = FleetCatalog::open_read_only(
        Path::new(root),
        vec![
            ColumnFamily::Base,
            ColumnFamily::Blob,
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
        ],
    )
    .map_err(|error| CalyxError {
        code: if error.code == "ASTRO_FLEET_ROOT_UNAVAILABLE" {
            ASTRO_FLEET_CATALOG_MISSING
        } else {
            error.code
        },
        message: format!(
            "fleet catalog at {root:?} failed to open: [{}] {}",
            error.code, error.message
        ),
        remediation: "repair or re-create the exact fleet catalog vault, then retry",
    })?;
    Ok((catalog, store_root))
}

/// Selects one exact generation without a mixed cache/source read.
///
/// At measured per-repository production `N=192,873/E=328,899` (2026-08-20),
/// a cold cache fill pays the persisted full-rebuild verification contract;
/// fleet totals remain unknown. A warm hit performs two
/// `O(C log C + sum(open_i) + R)` passes: one canonical latest-row inventory
/// over `C` catalog rows plus one latest-state vault open and exact repository
/// pointer/manifest/physical-Ledger and Base+Blob content-generation checks for
/// each of `R` selected repositories. It also performs two `O(1)` fleet header
/// reads and zero repository graph, Base/Blob-row, S20-vector, fleet projection,
/// or HNSW rebuilds.
/// Current pointer, generation id, repository roster, and encoder identity stay
/// invariant across the request
/// (PC-02/03/04/07/14/15/28/32/35/37/38/41/43; #1064).
fn load_fleet_generation(
    args_obj: &Map<String, Value>,
    scope: &str,
) -> Result<
    (
        Arc<CurrentFleetKernelGeneration>,
        bool,
        usize,
        Option<FleetKernelSourceVerificationReport>,
    ),
    CalyxError,
> {
    if scope["fleet:".len()..].trim().is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_SCOPE_INVALID,
            message: format!("fleet scope {scope:?} names no scope id after the fleet: prefix"),
            remediation: "pass a complete fleet scope such as fleet:rust:v1",
        });
    }
    let (catalog, store_root) = open_fleet_catalog(args_obj)?;
    let Some(header_before) = read_current_fleet_kernel_generation_header(catalog.vault(), scope)?
    else {
        return read_verified_fleet_kernel_generation(&catalog, &store_root, scope)
            .map(|generation| (Arc::new(generation), false, 0, None));
    };
    let catalog_root =
        string_arg(args_obj, "fleet_catalog_root").unwrap_or(astrolabe_fleet::DEFAULT_CATALOG_ROOT);
    let cache_key = format!(
        "{}\u{0}{}\u{0}{}\u{0}{}",
        catalog_root,
        store_root.display(),
        scope,
        header_before.manifest.generation_id,
    );
    let cache = FLEET_GENERATION_CACHE.get_or_init(|| Mutex::new(FleetGenerationCache::default()));
    let (cell, cache_entries) = {
        let mut cache = cache.lock().map_err(|_| CalyxError {
            code: "ASTRO_FLEET_GENERATION_CACHE_POISONED",
            message: "fleet generation cache mutex is poisoned".to_string(),
            remediation: "restart the Astrolabe server and inspect the preceding panic before serving another fleet request",
        })?;
        let cell = cache.load_cell(cache_key.clone())?;
        (cell, cache.entries.len())
    };
    let mut loaded_this_request = false;
    let generation_result = cell
        .get_or_init(|| {
            loaded_this_request = true;
            let generation =
                read_verified_fleet_kernel_generation(&catalog, &store_root, scope)?;
            if generation.manifest != header_before.manifest
                || generation.pointer != header_before.pointer
            {
                return Err(CalyxError {
                    code: astrolabe_fleet::ASTRO_FLEET_GENERATION_SOURCE_DRIFT,
                    message: format!(
                        "fleet generation moved between header selection and cold verification for scope {scope:?}"
                    ),
                    remediation: "discard the mixed cold load and retry against one stable atomic fleet generation",
                });
            }
            Ok(Arc::new(generation))
        })
        .clone();
    let generation = match generation_result {
        Ok(generation) => generation,
        Err(error) => {
            // A single-flight cell owns only one attempt, not permanent
            // refusal state. Evict the exact failed cell so a repaired source
            // or a transient stable-read race can be retried without waiting
            // for unrelated LRU pressure (PC-23/35; #1064).
            let mut cache = cache.lock().map_err(|_| CalyxError {
                code: "ASTRO_FLEET_GENERATION_CACHE_POISONED",
                message: "fleet generation cache mutex is poisoned".to_string(),
                remediation: "restart the Astrolabe server and inspect the preceding panic before serving another fleet request",
            })?;
            if cache
                .entries
                .get(&cache_key)
                .is_some_and(|(resident, _)| Arc::ptr_eq(resident, &cell))
            {
                cache.entries.remove(&cache_key);
            }
            return Err(error);
        }
    };
    let warm_source_verification = (!loaded_this_request)
        .then(|| verify_fleet_kernel_generation_sources(&catalog, &store_root, &generation))
        .transpose()?;
    let header_after = read_current_fleet_kernel_generation_header(catalog.vault(), scope)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_SCOPE_UNKNOWN,
            message: format!("fleet current pointer disappeared during request for {scope:?}"),
            remediation: "retry only after one complete atomic fleet generation is current",
        })?;
    if header_before.manifest != header_after.manifest
        || header_before.pointer != header_after.pointer
        || generation.manifest != header_after.manifest
        || generation.pointer != header_after.pointer
    {
        return Err(CalyxError {
            code: astrolabe_fleet::ASTRO_FLEET_GENERATION_SOURCE_DRIFT,
            message: format!(
                "fleet current generation moved during request: before={} cached={} after={}",
                header_before.manifest.generation_id,
                generation.manifest.generation_id,
                header_after.manifest.generation_id,
            ),
            remediation: "discard the mixed request and retry against one stable current fleet generation",
        });
    }
    Ok((
        generation,
        !loaded_this_request,
        cache_entries,
        warm_source_verification,
    ))
}

fn generation_evidence(
    generation: &CurrentFleetKernelGeneration,
    cache_hit: bool,
    cache_entries: usize,
    warm_source_verification: Option<&FleetKernelSourceVerificationReport>,
) -> Value {
    let nodes = generation.manifest.graph_node_count as u128;
    let similarity_pairs = if nodes < 2 {
        0
    } else {
        nodes * (nodes - 1) / 2
    };
    json!({
        "generation_id": generation.manifest.generation_id,
        "source_generation_identity": generation.manifest.source_generation_identity,
        "compose_input_hash": generation.manifest.compose_input_hash,
        "source_roster_hash": generation.manifest.source_roster_hash,
        "repository_generation_count": generation.source_roster.repositories.len(),
        "graph_hash": generation.manifest.graph_hash,
        "vector_roster_hash": generation.manifest.vector_roster_hash,
        "members_hash": generation.manifest.members_hash,
        "provenance_hash": generation.manifest.provenance_hash,
        "admission_input_blake3": generation.manifest.admission_input_blake3,
        "query_encoder_identity_hash": generation.manifest.query_encoder_identity_hash,
        "query_corpus_hash": generation.manifest.query_corpus_hash,
        "graph_routed_report_hash": generation.manifest.graph_routed_report_hash,
        "ledger_ref": generation.manifest.ledger_ref,
        "base_seq": generation.manifest.base_seq,
        "ledger_physical_tiers": generation.ledger_physical_tiers,
        "current_pointer": generation.pointer.current,
        "previous_pointer": generation.pointer.previous,
        "rows_readback_verified": generation.rows_verified,
        "source_recomputed_for_request": !cache_hit,
        "warm_source_header_bindings_rechecked": cache_hit,
        "warm_source_verification": warm_source_verification,
        "warm_source_check_cost": if cache_hit { "two O(C log C + sum(open_i) + R) passes: one canonical catalog latest-row merge plus R repository latest-state opens and header/content-generation checks" } else { "cold full source/projection verification" },
        "fleet_projection_recomputed_this_request": !cache_hit,
        "cached_generation_was_cold_verified": true,
        "production_cost_contract": {
            "measurement_date": "2026-08-20",
            "measured_repository_n": 192_873,
            "measured_repository_e": 328_899,
            "global_fleet_production_totals": "unknown; selected-generation values are persisted observations, not an extrapolation",
            "selected_generation": {
                "repositories": generation.source_roster.repositories.len(),
                "fleet_nodes": generation.manifest.graph_node_count,
                "fleet_edges": generation.manifest.graph_edge_count,
                "kernel_members": generation.manifest.member_count,
                "semantic_dimension": generation.manifest.semantic_dim,
                "external_queries": generation.query_corpus.queries.len(),
                "similarity_pair_evaluations": similarity_pairs.to_string(),
            },
            "pc_classes": ["PC-02", "PC-03", "PC-04", "PC-07", "PC-14", "PC-15", "PC-28", "PC-32", "PC-35", "PC-37", "PC-38", "PC-41", "PC-43"],
        },
        "cache": {
            "generation_cache_hit": cache_hit,
            "resident_generation_cells": cache_entries,
            "capacity_entries": fleet_generation_cache_entries(),
            "keyed_by_immutable_generation_id": true,
        },
    })
}

fn member_rows(generation: &CurrentFleetKernelGeneration) -> Vec<Value> {
    let provenance = generation
        .provenance
        .members
        .iter()
        .map(|member| (member.fleet_cx, member))
        .collect::<BTreeMap<_, _>>();
    generation
        .artifact
        .members
        .iter()
        .map(|member| {
            let source = provenance
                .get(&member.id)
                .expect("atomic fleet reader joined artifact/provenance ids");
            json!({
                "symbol_id": member.id.to_string(),
                "score_permille": member.score_permille,
                "degree": member.degree,
                "betweenness_permille": member.betweenness_permille,
                "groundedness_permille": member.groundedness_permille,
                "frequency": member.frequency,
                "in_fvs": member.in_fvs,
                "grounded": member.grounded,
                "content_key_hex": source.content_key_hex,
                "occurrences": source.occurrences,
            })
        })
        .collect()
}

pub(crate) fn handle_get_kernel_fleet(
    args_obj: &Map<String, Value>,
    scope: &str,
) -> Result<String, DynError> {
    let mode = string_arg(args_obj, "mode").unwrap_or("read");
    if !matches!(mode, "read" | "gaps" | "quadrant") {
        return tool_json_error_result(refusal(
            "astrolabe.get_kernel.v1",
            ASTRO_FLEET_KERNEL_MODE_UNSUPPORTED,
            scope,
            format!("fleet get_kernel mode {mode:?} is not a read-only production mode"),
            "use mode=read, mode=gaps, or mode=quadrant; publish through fleet compose/grow with an explicit genuine-query admission file",
        ));
    }
    let (generation, cache_hit, cache_entries, warm_source_verification) =
        match load_fleet_generation(args_obj, scope) {
            Ok(value) => value,
            Err(error) => {
                return tool_json_error_result(calyx_refusal(
                    "astrolabe.get_kernel.v1",
                    scope,
                    &error,
                ));
            }
        };
    let evidence = generation_evidence(
        &generation,
        cache_hit,
        cache_entries,
        warm_source_verification.as_ref(),
    );
    let mut response = match mode {
        "gaps" => artifact_gap_report_value("fleet", &generation.artifact),
        "quadrant" => artifact_quadrant_value("fleet", &generation.artifact),
        _ => json!({
            "schema": "astrolabe.get_kernel.v1",
            "status": "served",
            "fleet": true,
            "scope": scope,
            "mode": "read",
            "member_count": generation.artifact.member_count,
            "node_count": generation.artifact.node_count,
            "graph_edge_count": generation.manifest.graph_edge_count,
            "members": member_rows(&generation),
            "artifact": generation.artifact,
            "admission": generation.admission,
            "query_corpus": generation.query_corpus,
            "graph_routed_report": generation.graph_routed_report,
            "trust": generation.artifact.trust,
            "freshness": "fresh",
        }),
    };
    let object = response
        .as_object_mut()
        .expect("fleet get-kernel response is an object");
    object.insert("fleet".to_string(), Value::Bool(true));
    object.insert("scope".to_string(), Value::String(scope.to_string()));
    object.insert("generation".to_string(), evidence);
    tool_json_result(response)
}

fn fleet_answer_nodes(
    generation: &CurrentFleetKernelGeneration,
) -> (
    Vec<astrolabe_kernel::AnswerNode>,
    Vec<astrolabe_kernel::AnswerEdge>,
) {
    let artifact_members = generation
        .artifact
        .members
        .iter()
        .map(|member| (member.id, member))
        .collect::<BTreeMap<_, _>>();
    let member_ids = artifact_members.keys().copied().collect::<BTreeSet<_>>();
    let ledger_ref = format!(
        "{}:{}",
        generation.manifest.ledger_ref.seq,
        hex_lower(&generation.manifest.ledger_ref.hash),
    );
    let nodes = generation
        .provenance
        .members
        .iter()
        .map(|provenance| {
            let member = artifact_members[&provenance.fleet_cx];
            let qualified_name = provenance
                .occurrences
                .first()
                .map(|row| row.qualified_name.clone())
                .unwrap_or_else(|| provenance.fleet_cx.to_string());
            astrolabe_kernel::AnswerNode::new(
                member.id,
                qualified_name,
                member.grounded && provenance.grounded,
                Some(format!(
                    "fleet-generation:{}:provenance:{}:member:{}",
                    generation.manifest.generation_id,
                    generation.provenance.provenance_hash,
                    member.id,
                )),
                member.score_permille,
            )
        })
        .collect();
    let edges = generation
        .graph_record
        .edges
        .iter()
        .filter(|edge| member_ids.contains(&edge.src) && member_ids.contains(&edge.dst))
        .map(|edge| {
            astrolabe_kernel::AnswerEdge::new(
                edge.src,
                edge.dst,
                astrolabe_kernel::weight_to_permille(f32::from_bits(edge.weight_bits)),
                Some(ledger_ref.clone()),
            )
        })
        .collect();
    (nodes, edges)
}

pub(crate) fn handle_kernel_answer_fleet(
    args_obj: &Map<String, Value>,
    scope: &str,
) -> Result<String, DynError> {
    let Some(query) = string_arg(args_obj, "query").filter(|query| !query.trim().is_empty()) else {
        return tool_json_error_result(refusal(
            KERNEL_ANSWER_SCHEMA,
            ASTRO_FLEET_QUERY_REQUIRED,
            scope,
            "fleet kernel_answer requires a nonempty external query",
            "pass the actual operator question; no query is synthesized from fleet graph state",
        ));
    };
    let (generation, cache_hit, cache_entries, warm_source_verification) =
        match load_fleet_generation(args_obj, scope) {
            Ok(value) => value,
            Err(error) => {
                return tool_json_error_result(calyx_refusal(KERNEL_ANSWER_SCHEMA, scope, &error));
            }
        };
    let encoded =
        match astrolabe_weave::encode_kernel_recall_query(generation.manifest.panel_version, query)
        {
            Ok(encoded) => encoded,
            Err(error) => {
                return tool_json_error_result(refusal(
                    KERNEL_ANSWER_SCHEMA,
                    error.code(),
                    scope,
                    error.message().to_string(),
                    error.remediation(),
                ));
            }
        };
    if encoded.encoder != generation.query_corpus.encoder {
        return tool_json_error_result(refusal(
            KERNEL_ANSWER_SCHEMA,
            ASTRO_FLEET_QUERY_ENCODER_DRIFT,
            scope,
            format!(
                "live S20 query encoder differs from fleet generation {}",
                generation.manifest.generation_id
            ),
            "restore the exact frozen S20 encoder or explicitly publish a new fleet generation admitted by genuine external queries under that encoder",
        ));
    }
    let top_k = generation.admission.params.top_k;
    let ef = match usize::try_from(generation.admission.index_knobs.hnsw_ef_search) {
        Ok(value) => value,
        Err(_) => {
            return tool_json_error_result(refusal(
                KERNEL_ANSWER_SCHEMA,
                astrolabe_fleet::ASTRO_FLEET_GENERATION_CORRUPT,
                scope,
                "persisted fleet HNSW ef_search cannot be represented on this host",
                "preserve and explicitly recompose the fleet generation with representable controls",
            ));
        }
    };
    let hits = match generation.index.query(&encoded.vector, top_k, ef) {
        Ok(hits) => hits,
        Err(error) => {
            return tool_json_error_result(calyx_refusal(KERNEL_ANSWER_SCHEMA, scope, &error));
        }
    };
    let matched_ids = hits.iter().map(|hit| hit.cx_id).collect::<Vec<_>>();
    let ranked = hits
        .iter()
        .map(|hit| {
            json!({
                "rank": hit.rank,
                "cx_id": hit.cx_id.to_string(),
                "score_bits": hit.score.to_bits(),
            })
        })
        .collect::<Vec<_>>();
    let (nodes, edges) = fleet_answer_nodes(&generation);
    let answer = match astrolabe_kernel::answer_query(
        &nodes,
        &edges,
        &matched_ids,
        query,
        &astrolabe_kernel::AnswerConfig::with_registry_defaults(),
    ) {
        Ok(answer) => answer,
        Err(error) => {
            return tool_json_error_result(refusal(
                KERNEL_ANSWER_SCHEMA,
                error.code(),
                scope,
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };
    let query_resolution = json!({
        "schema": "astrolabe.fleet_kernel_answer_query_resolution.v1",
        "entry_selection": "generation_bound_s20_hnsw",
        "query": query,
        "encoder": encoded.encoder,
        "query_vector_dimension": encoded.vector.len(),
        "top_k": top_k,
        "hnsw_ef_search": ef,
        "ranked_member_count": ranked.len(),
        "ranked_members": ranked,
        "answer_graph": "induced_atomic_kernel_member_graph",
        "no_fallback": true,
    });
    let evidence = generation_evidence(
        &generation,
        cache_hit,
        cache_entries,
        warm_source_verification.as_ref(),
    );
    match answer {
        astrolabe_kernel::AnswerResolution::Refused(answer) => tool_json_error_result(json!({
            "schema": answer.schema,
            "status": "refused",
            "fleet": true,
            "scope": scope,
            "query": answer.query,
            "code": answer.code,
            "deficits": answer.deficits.iter().map(|deficit| json!({
                "lens": deficit.lens,
                "satisfied": deficit.satisfied,
                "detail": deficit.detail,
            })).collect::<Vec<_>>(),
            "message": answer.message,
            "remediation": answer.remediation,
            "query_resolution": query_resolution,
            "generation": evidence,
            "trust": answer.trust,
            "freshness": answer.freshness,
        })),
        astrolabe_kernel::AnswerResolution::Answered(answer) => tool_json_result(json!({
            "schema": answer.schema,
            "status": "served",
            "fleet": true,
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
            "entry_selection": "generation_bound_s20_hnsw",
            "query_resolution": query_resolution,
            "generation": evidence,
            "trust": answer.trust,
            "freshness": answer.freshness,
        })),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
