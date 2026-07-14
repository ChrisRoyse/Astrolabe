use super::*;

use astrolabe_domain::EdgeKind;
use astrolabe_oracle::{
    BacktestCase, ConsequenceEdge, ConsequenceEdgeKind, ConsequenceGraph, ImpactOutcome,
    OracleError, OracleEvidence, PredictConfig, PredictRequest, predict_impact, run_backtest,
};
use calyx_core::CxId;

/// Envelope schema for the `predict_impact` MCP tool.
pub(crate) const PREDICT_IMPACT_SCHEMA: &str = "astrolabe.predict_impact.v1";
/// Config-store metadata key holding the per-repo backtest gate state.
pub(crate) const PREDICT_GATE_KEY: &str = "oracle_predict_gate";
/// Ledger/actor-style provenance tag for the backtest gate record.
const PREDICT_BACKTEST_ACTOR: &str = "astrolabe-predict-backtest";

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
/// Stable failure code: the persisted backtest gate row is corrupt.
const ASTRO_PREDICT_GATE_CORRUPT: &str = "ASTRO_PREDICT_GATE_CORRUPT";
/// Stable failure code: the gate write did not read back byte-identically.
const ASTRO_PREDICT_GATE_FSV: &str = "ASTRO_PREDICT_GATE_FSV";
/// Stable failure code: a backtest was requested but no held-out cases exist.
const ASTRO_PREDICT_BACKTEST_NO_CASES: &str = "ASTRO_PREDICT_BACKTEST_NO_CASES";

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
struct GraphBuild {
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
fn build_consequence_graph(
    snapshot: &CbmGraphSnapshot,
) -> Result<(ConsequenceGraph, BTreeMap<CxId, BTreeSet<CxId>>, GraphBuild), OracleError> {
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

    let graph = ConsequenceGraph::from_edges(&edges)?;
    Ok((graph, tests_by_covered, build))
}

fn graph_build_json(build: &GraphBuild) -> Value {
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
// Per-repo backtest gate state (persist + FSV readback)
// ---------------------------------------------------------------------------

/// The persisted per-repo backtest gate. Grounded confidence is advertised only
/// when a gate row exists AND records `advertise_grounded: true`; every other
/// case (absent row, gate not passed) resolves to provisional labeling — never a
/// silent grounded default.
#[derive(Debug, Clone)]
struct PredictGate {
    advertise_grounded: bool,
    record: Value,
}

/// Reads the persisted backtest gate for `project`. An absent row is the honest
/// default: provisional (grounded confidence withheld), clearly labeled.
fn read_predict_gate(cache_dir: &Path, project: &str) -> Result<PredictGate, DynError> {
    let Some(text) = read_config_value(cache_dir, &metadata_key(project, PREDICT_GATE_KEY))? else {
        return Ok(PredictGate {
            advertise_grounded: false,
            record: json!({
                "advertise_grounded": false,
                "source": "absent",
                "note": "no persisted backtest gate for this repo; grounded confidence is withheld and every consequence is labeled provisional",
            }),
        });
    };
    let record: Value = serde_json::from_str(&text).map_err(|error| -> DynError {
        format!(
            "{ASTRO_PREDICT_GATE_CORRUPT}: persisted backtest gate for project {project:?} is not valid JSON: {error}; remediation: re-run predict_impact mode=\"backtest\" to rewrite the gate"
        )
        .into()
    })?;
    let advertise_grounded = record
        .get("advertise_grounded")
        .and_then(Value::as_bool)
        .ok_or_else(|| -> DynError {
            format!(
                "{ASTRO_PREDICT_GATE_CORRUPT}: persisted backtest gate for project {project:?} has no boolean advertise_grounded; remediation: re-run predict_impact mode=\"backtest\""
            )
            .into()
        })?;
    let mut record = record;
    if let Some(obj) = record.as_object_mut() {
        obj.insert("source".to_string(), json!("persisted"));
    }
    Ok(PredictGate {
        advertise_grounded,
        record,
    })
}

/// Persists the backtest gate `record` for `project` and independently reads it
/// back, failing closed if the readback is not byte-identical (FSV, #122 pattern).
fn persist_predict_gate(cache_dir: &Path, project: &str, record: &Value) -> Result<(), DynError> {
    let text = serde_json::to_string(record)?;
    let key = metadata_key(project, PREDICT_GATE_KEY);
    write_config_value(cache_dir, &key, &text)?;
    let readback = read_config_value(cache_dir, &key)?;
    if readback.as_deref() != Some(text.as_str()) {
        return Err(format!(
            "{ASTRO_PREDICT_GATE_FSV}: backtest gate for project {project:?} did not read back byte-identically after write; remediation: retry, and if it persists inspect {cache}/_config.db for a conflicting writer",
            cache = cache_dir.display(),
        )
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response rendering
// ---------------------------------------------------------------------------

fn cx_label(cx: CxId, cx_to_qn: &BTreeMap<CxId, String>) -> Value {
    json!({
        "cx": hex_lower(cx.as_bytes()),
        "qualified_name": cx_to_qn.get(&cx),
    })
}

fn cx_path(path: &[CxId], cx_to_qn: &BTreeMap<CxId, String>) -> Value {
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

// ---------------------------------------------------------------------------
// Core: predict_impact_json_at
// ---------------------------------------------------------------------------

/// Shared core for the `predict_impact` MCP tool. Reads the persisted CBM graph
/// and oracle change→outcome corpus for a shadow-indexed project, builds the
/// composite consequence graph and grounded evidence from persisted state, honors
/// the persisted per-repo backtest gate, and answers `mode`:
///
/// * `"predict"` (default): ranked consequences + test-selection, or an honest
///   `Insufficient` deficit card when the seeds carry no grounded history.
/// * `"backtest"`: derives held-out cases from the corpus + graph, runs the
///   grounded-vs-topology backtest, and persists (+ FSV reads back) the gate.
pub(crate) fn predict_impact_json_at(
    cache_dir: &Path,
    project: &str,
    seeds: &[String],
    mode: &str,
) -> Result<Value, DynError> {
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
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Kv,
            ColumnFamily::Ledger,
            ColumnFamily::Recurrence,
        ],
    )?;

    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project)?;
    let node_map = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;
    let evidence = OracleEvidence::from_vault(&vault)?;
    // Subjects with at least one grounded *failing* occurrence, read back from the
    // persisted oracle `Kv` rows — used to derive held-out backtest cases without
    // reaching into OracleEvidence's private index.
    let mut failing_subjects: BTreeSet<CxId> = BTreeSet::new();
    for persisted in astrolabe_oracle::read_occurrence_rows(&vault)? {
        if !persisted.row.passed {
            failing_subjects.insert(persisted.row.subject);
        }
    }
    drop(vault);

    let mut cx_to_qn: BTreeMap<CxId, String> = BTreeMap::new();
    for (qn, cx) in &node_map {
        cx_to_qn.insert(*cx, qn.clone());
    }

    let (graph, tests_by_covered, build) = match build_consequence_graph(&snapshot) {
        Ok(parts) => parts,
        Err(error) => return Ok(oracle_error_refused(project, &error)),
    };

    match mode {
        "predict" => predict_mode(
            cache_dir, project, seeds, &node_map, &cx_to_qn, &graph, &evidence, &build,
        ),
        "backtest" => backtest_mode(
            cache_dir,
            project,
            &graph,
            &tests_by_covered,
            &failing_subjects,
            &evidence,
            &build,
        ),
        other => Ok(predict_refused(
            project,
            ASTRO_PREDICT_MODE_UNSUPPORTED,
            format!("predict_impact mode {other:?} is not available"),
            "use mode=\"predict\" (default) or mode=\"backtest\"",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn predict_mode(
    cache_dir: &Path,
    project: &str,
    seeds: &[String],
    node_map: &BTreeMap<String, CxId>,
    cx_to_qn: &BTreeMap<CxId, String>,
    graph: &ConsequenceGraph,
    evidence: &OracleEvidence,
    build: &GraphBuild,
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

    let gate = read_predict_gate(cache_dir, project)?;
    let config = PredictConfig {
        advertise_grounded: gate.advertise_grounded,
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
                "gate": gate.record,
                "graph": graph_build_json(build),
                // grounded_mode gates whether a Trusted consequence may ride as
                // Trusted; when the repo's backtest gate has not passed every
                // consequence is provisional (labeled, never silent). Per-consequence
                // trust tags refine this envelope-level operating-mode label.
                "trust": if prediction.grounded_mode { "trusted" } else { "provisional" },
                "freshness": "fresh",
                "provenance": [
                    "graph:read_cbm_graph_snapshot",
                    "evidence:OracleEvidence::from_vault",
                    format!("gate:advertise_grounded={}", gate.advertise_grounded),
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
                "gate": gate.record,
                "graph": graph_build_json(build),
                "trust": "provisional",
                "freshness": "fresh",
                "provenance": ["refusal:insufficient-grounded-history:deficit-card"],
            }))
        }
        Err(error) => Ok(oracle_error_refused(project, &error)),
    }
}

#[allow(clippy::too_many_arguments)]
fn backtest_mode(
    cache_dir: &Path,
    project: &str,
    graph: &ConsequenceGraph,
    tests_by_covered: &BTreeMap<CxId, BTreeSet<CxId>>,
    failing_subjects: &BTreeSet<CxId>,
    evidence: &OracleEvidence,
    build: &GraphBuild,
) -> Result<Value, DynError> {
    // Derive held-out cases from persisted state: each subject that carries a
    // grounded failing outcome and is covered by a test yields the case
    // (seed = subject, actually_failing_test = covering test). This exercises the
    // real oracle backtest against the same corpus the predictor grounds on; it is
    // an in-corpus self-backtest, not the crate-level held-out multi-corpus gate
    // (#50), and is labeled as such so grounded mode is never over-advertised.
    let mut cases: Vec<BacktestCase> = Vec::new();
    let mut seen: BTreeSet<(CxId, CxId)> = BTreeSet::new();
    for (&covered, tests) in tests_by_covered {
        if !failing_subjects.contains(&covered) {
            continue;
        }
        for &test in tests {
            if seen.insert((covered, test)) {
                cases.push(BacktestCase {
                    seed: covered,
                    actually_failing_test: test,
                });
            }
        }
    }

    if cases.is_empty() {
        return Ok(predict_refused(
            project,
            ASTRO_PREDICT_BACKTEST_NO_CASES,
            "no held-out backtest cases: no indexed symbol carries both a grounded failing outcome and a covering test edge",
            "ground failing outcomes via anchor_outcome and ensure the graph carries TESTS edges, then re-run mode=\"backtest\"",
        ));
    }

    let config = PredictConfig::default();
    let report = match run_backtest(graph, evidence, &cases, &config) {
        Ok(report) => report,
        Err(error) => return Ok(oracle_error_refused(project, &error)),
    };

    // Grounded confidence is advertised only when the grounded predictor strictly
    // beat the topology baseline on this corpus (the phase-gate criterion).
    let advertise_grounded = report.beats_baseline;
    let record = json!({
        "advertise_grounded": advertise_grounded,
        "recorded_by": PREDICT_BACKTEST_ACTOR,
        "backtest_kind": "in_corpus_self_backtest",
        "cases": report.cases,
        "grounded_top_k_hits": report.grounded_top_k_hits,
        "baseline_top_k_hits": report.baseline_top_k_hits,
        "grounded_top_k_rate": report.grounded_top_k_rate,
        "baseline_top_k_rate": report.baseline_top_k_rate,
        "beats_baseline": report.beats_baseline,
        "meets_top_k_target": report.meets_top_k_target,
        "top_k": report.top_k,
    });
    persist_predict_gate(cache_dir, project, &record)?;

    // Independent readback: prove the persisted gate resolves to the verdict.
    let gate = read_predict_gate(cache_dir, project)?;

    Ok(json!({
        "schema": PREDICT_IMPACT_SCHEMA,
        "project": project,
        "status": "backtest_recorded",
        "advertise_grounded": gate.advertise_grounded,
        "gate": gate.record,
        "graph": graph_build_json(build),
        // An in-corpus self-backtest, not the crate-level held-out gate (#50), so
        // the report envelope is labeled provisional even though the persisted
        // advertise_grounded verdict is a real run_backtest result.
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": [
            "backtest:run_backtest",
            "gate:persist+fsv-readback",
            format!("gate:advertise_grounded={}", gate.advertise_grounded),
        ],
    }))
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
