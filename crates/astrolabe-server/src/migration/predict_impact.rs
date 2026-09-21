use super::*;

use astrolabe_domain::EdgeKind;
use astrolabe_oracle::{
    ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED, ASTRO_ORACLE_BACKTEST_NOT_BEATEN, ConsequenceEdge,
    ConsequenceEdgeKind, ConsequenceGraph, ImpactOutcome, OracleError, OracleEvidence,
    PredictConfig, PredictRequest, predict_impact,
};
use calyx_core::CxId;

/// Envelope schema for the `predict_impact` MCP tool.
pub(crate) const PREDICT_IMPACT_SCHEMA: &str = "astrolabe.predict_impact.v1";
/// Stable failure code: the tool was called without a shadow-indexed project.
const ASTRO_PREDICT_SHADOW_REQUIRED: &str = "ASTRO_PREDICT_SHADOW_REQUIRED";
/// Stable failure code: the shadow vault directory is missing.
const ASTRO_PREDICT_VAULT_MISSING: &str = "ASTRO_PREDICT_VAULT_MISSING";
/// Stable failure code: no seed symbols were supplied.
const ASTRO_PREDICT_SEEDS_REQUIRED: &str = "ASTRO_PREDICT_SEEDS_REQUIRED";
/// Stable failure code: one or more seed symbols did not resolve to a constellation.
const ASTRO_PREDICT_SEED_UNRESOLVED: &str = "ASTRO_PREDICT_SEED_UNRESOLVED";
/// Stable failure code: an unsupported `mode` was requested.
const ASTRO_PREDICT_MODE_UNSUPPORTED: &str = "ASTRO_PREDICT_MODE_UNSUPPORTED";

// ---------------------------------------------------------------------------
// CBM edge_type -> oracle impact edge mapping
// ---------------------------------------------------------------------------

/// True for the service-call family (mirrors the graph projection's
/// `is_service_edge` classification): direct + cross-project HTTP/async/gRPC/
/// GraphQL/tRPC calls plus channel and handler edges.
fn is_service_kind(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::HttpCalls
            | EdgeKind::AsyncCalls
            | EdgeKind::GrpcCalls
            | EdgeKind::GraphqlCalls
            | EdgeKind::TrpcCalls
            | EdgeKind::Emits
            | EdgeKind::ListensOn
            | EdgeKind::Handles
            | EdgeKind::InfraMaps
            | EdgeKind::CrossHttpCalls
            | EdgeKind::CrossAsyncCalls
            | EdgeKind::CrossChannel
            | EdgeKind::CrossGrpcCalls
            | EdgeKind::CrossGraphqlCalls
            | EdgeKind::CrossTrpcCalls
    )
}

/// Maps one persisted CBM structural edge (`edge_type`, resolved `src`→`dst`
/// constellation ids) to a directed oracle *impact* edge, or `None` when the
/// edge type is not one the oracle propagates over.
///
/// The oracle's consequence walk flows from the **changed** symbol to the
/// symbols a change in it can break, so the impact direction is not always the
/// CBM edge direction:
///
/// * `CALLS`/`RESOLVED_CALLS` (CBM caller→callee): changing the callee breaks
///   its callers, so impact flows callee→caller — the CBM edge is **reversed**.
/// * service calls (`HTTP_CALLS`/`ASYNC_CALLS`/`GRPC_CALLS`/`GRAPHQL_CALLS`/
///   `TRPC_CALLS`, their cross-project variants, `EMITS`/`LISTENS_ON`/`HANDLES`/
///   `INFRA_MAPS`; CBM consumer→provider): changing the provider breaks the
///   consumer, so impact flows provider→consumer — **reversed**.
/// * `DATA_FLOWS` (CBM producer→consumer): changing the producer breaks the
///   downstream consumer, so impact flows producer→consumer — **kept**.
/// * `TESTS`/`TESTS_FILE` (CBM test→covered): a change to the covered symbol
///   selects its covering test, so the oracle edge points covered→test —
///   **reversed**. `predict_impact` reads exactly this direction to build its
///   test-selection set (`covering_tests(covered)` yields the test).
///
/// `DRIVES` (`ConsequenceEdgeKind::Drives`, the lead/lag causal edge) has no CBM
/// edge type today, so the CBM graph never emits one; the variant stays wired so
/// a future persisted `DRIVES` edge lands without another migration.
fn impact_edge(edge_type: &str, src: CxId, dst: CxId) -> Option<ConsequenceEdge> {
    let kind = EdgeKind::from_cbm_type(edge_type)?;
    let edge = match kind {
        EdgeKind::Calls | EdgeKind::ResolvedCalls => ConsequenceEdge {
            from: dst,
            to: src,
            kind: ConsequenceEdgeKind::Calls,
        },
        EdgeKind::DataFlows => ConsequenceEdge {
            from: src,
            to: dst,
            kind: ConsequenceEdgeKind::DataFlow,
        },
        EdgeKind::Tests | EdgeKind::TestsFile => ConsequenceEdge {
            from: dst,
            to: src,
            kind: ConsequenceEdgeKind::Tests,
        },
        k if is_service_kind(k) => ConsequenceEdge {
            from: dst,
            to: src,
            kind: ConsequenceEdgeKind::Service,
        },
        _ => return None,
    };
    Some(edge)
}

/// Accounting for how the persisted CBM graph slice was assembled into the
/// composite consequence graph. Every edge that could not be used is counted,
/// never silently dropped (HONEST invariant 3).
#[derive(Debug, Default, Clone)]
pub(crate) struct GraphBuild {
    edges_used: usize,
    calls: usize,
    dataflow: usize,
    service: usize,
    tests: usize,
    /// Endpoints that did not resolve to a constellation id (structural / dangling).
    edges_unresolved: usize,
    /// Edge types the oracle does not propagate over (imports, containment, …).
    edges_untyped: usize,
    /// Self-loops (recursion) — carry no cross-symbol impact.
    edges_self_loop: usize,
}

/// Assembles a validated [`ConsequenceGraph`] plus a covered→tests index (used to
/// derive backtest cases) from a persisted CBM graph snapshot. Endpoints are
/// resolved through the node→constellation map exactly as the coverage-ingest and
/// invalidation lanes do (raw-edge snapshot rows carry only SQLite node ids).
/// The covered-symbol -> covering-tests index derived alongside the consequence
/// graph (each covered `CxId` maps to the set of TESTS `CxId`s that exercise it).
pub(crate) type CoveredTestsIndex = BTreeMap<CxId, BTreeSet<CxId>>;

/// Derives the raw directed [`ConsequenceEdge`] set (plus the covered→tests index
/// and the build accounting) from a persisted CBM graph snapshot. Endpoints are
/// resolved through the node→constellation map exactly as the coverage-ingest and
/// invalidation lanes do; every edge that could not be used is counted, never
/// silently dropped (HONEST invariant 3). Shared by [`build_consequence_graph`]
/// (which validates the edges into a [`ConsequenceGraph`]) and by the
/// `abduce_cause` surface, which reverse-walks the same edge set.
pub(crate) fn consequence_edges_from_snapshot(
    snapshot: &CbmGraphSnapshot,
) -> (Vec<ConsequenceEdge>, CoveredTestsIndex, GraphBuild) {
    let mut cx_by_node_id: BTreeMap<i64, CxId> = BTreeMap::new();
    for node in &snapshot.nodes {
        if let Some(cx_id) = node.cx_id {
            cx_by_node_id.insert(node.source_node_id, cx_id);
        }
    }

    let mut edges: Vec<ConsequenceEdge> = Vec::new();
    let mut tests_by_covered: BTreeMap<CxId, BTreeSet<CxId>> = BTreeMap::new();
    let mut build = GraphBuild::default();

    for edge in &snapshot.edges {
        let (Some(&src), Some(&dst)) = (
            cx_by_node_id.get(&edge.source_node_id),
            cx_by_node_id.get(&edge.target_node_id),
        ) else {
            build.edges_unresolved += 1;
            continue;
        };
        let Some(impact) = impact_edge(&edge.edge_type, src, dst) else {
            build.edges_untyped += 1;
            continue;
        };
        if impact.from == impact.to {
            build.edges_self_loop += 1;
            continue;
        }
        match impact.kind {
            ConsequenceEdgeKind::Calls => build.calls += 1,
            ConsequenceEdgeKind::DataFlow => build.dataflow += 1,
            ConsequenceEdgeKind::Service => build.service += 1,
            ConsequenceEdgeKind::Drives => {}
            ConsequenceEdgeKind::Tests => {
                build.tests += 1;
                tests_by_covered
                    .entry(impact.from)
                    .or_default()
                    .insert(impact.to);
            }
        }
        build.edges_used += 1;
        edges.push(impact);
    }

    (edges, tests_by_covered, build)
}

pub(crate) fn graph_build_json(build: &GraphBuild) -> Value {
    json!({
        "edges_used": build.edges_used,
        "calls": build.calls,
        "dataflow": build.dataflow,
        "service": build.service,
        "tests": build.tests,
        "edges_unresolved_endpoints": build.edges_unresolved,
        "edges_non_propagation": build.edges_untyped,
        "edges_self_loop": build.edges_self_loop,
    })
}

// ---------------------------------------------------------------------------
// Response rendering
// ---------------------------------------------------------------------------

pub(crate) fn cx_label(cx: CxId, cx_to_qn: &BTreeMap<CxId, String>) -> Value {
    json!({
        "cx": hex_lower(cx.as_bytes()),
        "qualified_name": cx_to_qn.get(&cx),
    })
}

pub(crate) fn cx_path(path: &[CxId], cx_to_qn: &BTreeMap<CxId, String>) -> Value {
    Value::Array(path.iter().map(|cx| cx_label(*cx, cx_to_qn)).collect())
}

fn predict_refused(
    project: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": PREDICT_IMPACT_SCHEMA,
        "project": project,
        "status": "refused",
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:pre-prediction:no-result-emitted"],
    })
}

fn oracle_error_refused(project: &str, error: &OracleError) -> Value {
    predict_refused(
        project,
        error.code,
        error.message.clone(),
        error.remediation,
    )
}

fn gate_error_refused(project: &str, error: &dyn std::fmt::Display) -> Value {
    let message = error.to_string();
    let code = if message.contains(ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED) {
        ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED
    } else if message.contains(ASTRO_ORACLE_BACKTEST_NOT_BEATEN) {
        ASTRO_ORACLE_BACKTEST_NOT_BEATEN
    } else if message.contains(ASTRO_ORACLE_GATE_ABSENT) {
        ASTRO_ORACLE_GATE_ABSENT
    } else if message.contains(ASTRO_ORACLE_GATE_CORRUPT) {
        ASTRO_ORACLE_GATE_CORRUPT
    } else {
        ASTRO_ORACLE_GATE_STALE
    };
    predict_refused(
        project,
        code,
        message,
        "publish one new shadow generation from real Git archaeology and source-backed CI outcome anchors; grounded serving never falls back to a manual or stale gate",
    )
}

// ---------------------------------------------------------------------------
// Core: predict_impact_json_at
// ---------------------------------------------------------------------------

/// Shared core for the `predict_impact` MCP tool. One retained generation binds
/// the compact CBM graph, source-backed Oracle corpus, current complete kernel,
/// and automatically-persisted chronological gate attestation.
///
/// * `"predict"` (default): ranked consequences + test-selection, or an honest
///   `Insufficient` deficit card when the seeds carry no grounded history.
/// * `"backtest"`: reads the exact generation-owned attestation. Serving never
///   creates, replaces, or manually approves a gate.
///
/// At production `N=192,873`, `E=328,899`, this path performs one compact
/// `O(N+E)` graph read/build and, only for `predict`, one `O(R)` Oracle-owned
/// occurrence scan. Kernel and gate identities are point-read from the same
/// retained generation; the obsolete second occurrence scan is absent
/// (PC-04/PC-16/PC-38/PC-43).
pub(crate) fn predict_impact_json_at(
    cache_dir: &Path,
    project: &str,
    seeds: &[String],
    mode: &str,
) -> Result<Value, DynError> {
    if !matches!(mode, "predict" | "backtest") {
        return Ok(predict_refused(
            project,
            ASTRO_PREDICT_MODE_UNSUPPORTED,
            format!("predict_impact mode {mode:?} is not available"),
            "use mode=\"predict\" (default) or mode=\"backtest\"",
        ));
    }
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(predict_refused(
            project,
            ASTRO_PREDICT_SHADOW_REQUIRED,
            format!("predict_impact requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before predicting impact",
        ));
    }

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(predict_refused(
            project,
            ASTRO_PREDICT_VAULT_MISSING,
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before predicting impact",
        ));
    }

    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Base,
            ColumnFamily::Graph,
            ColumnFamily::Kv,
            ColumnFamily::Recurrence,
            ColumnFamily::Kernel,
            ColumnFamily::Anchors,
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
            ColumnFamily::Slot(astrolabe_weave::search::SLOT_NAME_SEMANTIC),
        ],
    )?;
    let read_lease = vault.retain_latest_snapshot();
    let read_seq = read_lease.seq();
    let compact = astrolabe_ingest::read_cbm_compact_graph_snapshot(&vault, project)?;
    if compact.receipt.snapshot_seq != read_seq {
        return Ok(predict_refused(
            project,
            ASTRO_ORACLE_GATE_STALE,
            format!(
                "compact graph sequence {} differs from retained Oracle serving sequence {read_seq}",
                compact.receipt.snapshot_seq
            ),
            "retry against one stable retained shadow generation",
        ));
    }
    let mut node_map: BTreeMap<String, CxId> = BTreeMap::new();
    let mut cx_to_qn: BTreeMap<CxId, String> = BTreeMap::new();
    for node in &compact.nodes {
        if let Some(previous) = node_map.insert(node.qualified_name.clone(), node.cx_id)
            && previous != node.cx_id
        {
            return Ok(predict_refused(
                project,
                ASTRO_PREDICT_SEED_UNRESOLVED,
                format!(
                    "qualified name {:?} resolves to multiple constellations",
                    node.qualified_name
                ),
                "reindex the project so each qualified seed name has one exact constellation identity",
            ));
        }
        cx_to_qn
            .entry(node.cx_id)
            .or_insert_with(|| node.qualified_name.clone());
    }
    let (graph, _, projection) = match consequence_graph_from_compact(&compact) {
        Ok(parts) => parts,
        Err(error) => return Ok(oracle_error_refused(project, &error)),
    };
    let scope_id = kernel_artifact_scope_id(project);
    let Some(generation) =
        astrolabe_weave::read_current_kernel_generation_header(&vault, project, &scope_id)?
    else {
        return Ok(predict_refused(
            project,
            ASTRO_ORACLE_GATE_STALE,
            "the retained shadow generation has no complete current kernel artifact",
            "publish one complete shadow/kernel/Oracle generation before predicting impact",
        ));
    };
    let attestation = match validate_current_oracle_gate_at(
        &vault,
        read_seq,
        project,
        &generation.manifest,
        &generation.pointer,
    ) {
        Ok(attestation) => attestation,
        Err(error) => return Ok(gate_error_refused(project, error.as_ref())),
    };
    if !oracle_gate_projection_matches(&attestation, &projection) {
        return Ok(predict_refused(
            project,
            ASTRO_ORACLE_GATE_STALE,
            "the serving consequence projection differs from the exact gate-attested projection accounting",
            "publish one new shadow generation; do not serve across graph-projection drift",
        ));
    }
    let gate = oracle_gate_summary(&attestation);
    if mode == "backtest" {
        let admitted = gate
            .get("admitted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        return Ok(json!({
            "schema": PREDICT_IMPACT_SCHEMA,
            "project": project,
            "status": "backtest_attested",
            "advertise_grounded": admitted,
            "gate": gate,
            "graph": projection,
            "trust": if admitted { "trusted" } else { "provisional" },
            "freshness": "fresh",
            "provenance": [
                "backtest:generation-transaction:strict-chronological-held-out",
                "gate:Kernel+Ledger:exact-attestation-readback",
            ],
        }));
    }
    let attestation = match require_current_oracle_gate_at(
        &vault,
        read_seq,
        project,
        &generation.manifest,
        &generation.pointer,
    ) {
        Ok(attestation) => attestation,
        Err(error) => return Ok(gate_error_refused(project, error.as_ref())),
    };
    let evidence = OracleEvidence::from_vault_at(&vault, read_seq)?;
    if vault.latest_seq() != read_seq {
        return Ok(predict_refused(
            project,
            ASTRO_ORACLE_GATE_STALE,
            format!(
                "vault advanced from retained sequence {read_seq} to {} during prediction preparation",
                vault.latest_seq()
            ),
            "retry against one stable retained shadow generation",
        ));
    }
    read_lease.record_progress();
    predict_mode(
        project,
        seeds,
        &node_map,
        &cx_to_qn,
        &graph,
        &evidence,
        &projection,
        oracle_gate_summary(&attestation),
    )
}

#[allow(clippy::too_many_arguments)]
fn predict_mode(
    project: &str,
    seeds: &[String],
    node_map: &BTreeMap<String, CxId>,
    cx_to_qn: &BTreeMap<CxId, String>,
    graph: &ConsequenceGraph,
    evidence: &OracleEvidence,
    projection: &OracleProjectionBuild,
    gate: Value,
) -> Result<Value, DynError> {
    if seeds.is_empty() {
        return Ok(predict_refused(
            project,
            ASTRO_PREDICT_SEEDS_REQUIRED,
            "predict_impact requires at least one seed symbol",
            "pass seeds: the qualified name(s) of the symbol(s) you intend to change",
        ));
    }

    // Resolve seed qualified names to constellation ids. Any unresolved seed
    // fails closed (never a silent partial prediction, HONEST invariant 3).
    let mut seed_cx: Vec<CxId> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    for seed in seeds {
        match node_map.get(seed) {
            Some(cx) => seed_cx.push(*cx),
            None => unresolved.push(seed.clone()),
        }
    }
    if !unresolved.is_empty() {
        return Ok(predict_refused(
            project,
            ASTRO_PREDICT_SEED_UNRESOLVED,
            format!(
                "these seed symbols did not resolve to an indexed constellation: {}",
                unresolved.join(", ")
            ),
            "pass qualified names present in this project's indexed graph (see search_graph); re-index if the symbols are new",
        ));
    }

    let config = PredictConfig {
        advertise_grounded: true,
        ..PredictConfig::default()
    };
    let request = PredictRequest {
        seeds: seed_cx.clone(),
        cohort_peers: BTreeMap::new(),
    };

    let seed_labels = cx_path(&seed_cx, cx_to_qn);
    match predict_impact(graph, evidence, &request, &config) {
        Ok(ImpactOutcome::Grounded(prediction)) => {
            let consequences: Vec<Value> = prediction
                .consequences
                .iter()
                .map(|c| {
                    json!({
                        "target": cx_label(c.target, cx_to_qn),
                        "p": c.p,
                        "hop_path": cx_path(&c.hop_path, cx_to_qn),
                        "evidence_n": c.evidence_n,
                        "trust": c.trust.as_str(),
                        "grounded": c.grounded,
                        "cohort": c.cohort,
                    })
                })
                .collect();
            let test_selection: Vec<Value> = prediction
                .test_selection
                .iter()
                .map(|t| {
                    json!({
                        "test": cx_label(t.test, cx_to_qn),
                        "p": t.p,
                        "via": cx_label(t.via, cx_to_qn),
                    })
                })
                .collect();
            Ok(json!({
                "schema": PREDICT_IMPACT_SCHEMA,
                "project": project,
                "status": "grounded",
                "grounded_mode": prediction.grounded_mode,
                "seeds": seed_labels,
                "consequences": consequences,
                "consequence_count": prediction.consequences.len(),
                "test_selection": test_selection,
                "gate": gate,
                "graph": projection,
                "trust": "trusted",
                "freshness": "fresh",
                "provenance": [
                    "graph:read_cbm_compact_graph_snapshot:one-retained-generation",
                    "evidence:OracleEvidence::from_vault_at:one-owned-prefix-scan",
                    "gate:exact-generation-attestation:admitted=true",
                ],
            }))
        }
        Ok(ImpactOutcome::Insufficient(report)) => {
            let deficits: Vec<Value> = report
                .deficits
                .iter()
                .map(|d| {
                    json!({
                        "sensor": d.sensor,
                        "have": d.have,
                        "need": d.need,
                        "bits_short": d.bits_short,
                    })
                })
                .collect();
            Ok(json!({
                "schema": PREDICT_IMPACT_SCHEMA,
                "project": project,
                "status": "insufficient",
                "seeds": seed_labels,
                "deficits": deficits,
                "remediation": report.remediation,
                "gate": gate,
                "graph": projection,
                "trust": "provisional",
                "freshness": "fresh",
                "provenance": ["refusal:insufficient-grounded-history:deficit-card"],
            }))
        }
        Err(error) => Ok(oracle_error_refused(project, &error)),
    }
}

// ---------------------------------------------------------------------------
// MCP dispatch entry point
// ---------------------------------------------------------------------------

/// MCP dispatch entry point for `predict_impact` (routed from the JSON-RPC surface
/// via `migration::handle_tool_raw`). Fails closed with a stable
/// `{code, message, remediation}` refusal on any structural error; an honest
/// `Insufficient` deficit card is returned as a non-error result.
pub(crate) fn handle_predict_impact(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("predict_impact arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("predict_impact requires project");
    };
    let mode = string_arg(args_obj, "mode").unwrap_or("predict");
    let seeds = string_array_field(&args, "seeds");

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = predict_impact_json_at(&cache_dir, &project, &seeds, mode)?;
    match value.get("status").and_then(Value::as_str) {
        Some("refused") => tool_json_error_result(value),
        _ => tool_json_result(value),
    }
}
