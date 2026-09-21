use super::*;

use astrolabe_anchors::{
    CoverageFormat, PropagationInputs, PropagationReport, SymbolNode, TestReportFormat, TestsEdge,
    TestsFileEdge, ingest_outcome_anchors, parse_coverage, parse_test_report, plan_propagation,
};
use astrolabe_domain::EdgeKind;
use calyx_core::CxId;

/// Envelope schema for the `coverage_ingest` MCP tool.
pub(crate) const COVERAGE_INGEST_SCHEMA: &str = "astrolabe.coverage_ingest.v1";
/// Ledger actor recorded for every anchor ingest driven by this surface.
pub(crate) const COVERAGE_INGEST_ACTOR: &str = "astrolabe-coverage-ingest";

/// Stable failure code when the live graph has no anchorable symbols to plan on.
pub(crate) const ASTRO_COVERAGE_NO_GRAPH: &str = "ASTRO_COVERAGE_NO_GRAPH";
/// Canonical CBM edge_type string for a direct test→symbol edge.
const TESTS_EDGE_TYPE: &str = "TESTS";
/// Canonical CBM edge_type string for a test→file edge.
const TESTS_FILE_EDGE_TYPE: &str = "TESTS_FILE";

/// Maps a wire coverage-format token to a [`CoverageFormat`], fail-closed.
fn coverage_format_from_wire(name: &str) -> Result<CoverageFormat, (&'static str, String)> {
    match name {
        "lcov" => Ok(CoverageFormat::Lcov),
        "coverage_py_json" => Ok(CoverageFormat::CoveragePyJson),
        "cobertura_xml" => Ok(CoverageFormat::CoberturaXml),
        other => Err((
            "ASTRO_COVERAGE_FORMAT_UNSUPPORTED",
            format!(
                "coverage_format {other:?} is not supported; expected lcov, coverage_py_json, or \
                 cobertura_xml"
            ),
        )),
    }
}

/// Accounting for how the live graph slice was assembled into propagation inputs.
/// Every node/edge the assembly could not use is counted, never silently dropped.
#[derive(Debug, Default, Clone)]
struct GraphAssembly {
    symbols: Vec<SymbolNode>,
    tests_edges: Vec<TestsEdge>,
    tests_file_edges: Vec<TestsFileEdge>,
    /// Nodes with no resolved CxId (never anchorable).
    nodes_unresolved: usize,
    /// Nodes excluded because they carry no one-based line range (file/package
    /// scaffolding, not code symbols).
    nodes_without_range: usize,
    /// TESTS / TESTS_FILE edges dropped because an endpoint did not resolve.
    tests_edges_unresolved: usize,
}

/// Assembles [`PropagationInputs`] source data from a persisted CBM graph
/// snapshot. A symbol is a *test* iff it is the source of a `TESTS`/`TESTS_FILE`
/// edge (the graph's own signal of a test definition); test symbols are matched
/// by qualified name to run cases and never anchored as targets.
fn assemble_graph(snapshot: &CbmGraphSnapshot) -> GraphAssembly {
    // Raw-edge snapshot rows carry only the SQLite node ids (src/dst CxIds are
    // left None by read_cbm_graph_snapshot), so resolve every endpoint through
    // the node→constellation map ourselves, exactly as the invalidation lane
    // does. Only non-structural nodes carry a CxId.
    let mut cx_by_node_id: BTreeMap<i64, CxId> = BTreeMap::new();
    let mut file_by_node_id: BTreeMap<i64, String> = BTreeMap::new();
    for node in &snapshot.nodes {
        if let Some(cx_id) = node.cx_id {
            cx_by_node_id.insert(node.source_node_id, cx_id);
        }
        let file = if !node.file_path.trim().is_empty() {
            node.file_path.clone()
        } else {
            node.name.clone()
        };
        if !file.trim().is_empty() {
            file_by_node_id.insert(node.source_node_id, file);
        }
    }

    // Test-source constellations: any node that is the source of a TESTS or
    // TESTS_FILE edge is a test definition.
    let mut test_sources: BTreeSet<CxId> = BTreeSet::new();
    for edge in &snapshot.edges {
        if is_tests_edge_type(&edge.edge_type)
            && let Some(&src) = cx_by_node_id.get(&edge.source_node_id)
        {
            test_sources.insert(src);
        }
    }

    let mut assembly = GraphAssembly::default();
    for node in &snapshot.nodes {
        let Some(cx_id) = node.cx_id else {
            assembly.nodes_unresolved += 1;
            continue;
        };
        if node.structural {
            // Structural placeholders carry no groundable body.
            assembly.nodes_unresolved += 1;
            continue;
        }
        // One-based inclusive line ranges only; scaffolding nodes (files,
        // packages) carry 0/empty ranges and are not code symbols.
        if node.start_line < 1 || node.end_line < node.start_line {
            assembly.nodes_without_range += 1;
            continue;
        }
        let Ok(line_start) = u32::try_from(node.start_line) else {
            assembly.nodes_without_range += 1;
            continue;
        };
        let Ok(line_end) = u32::try_from(node.end_line) else {
            assembly.nodes_without_range += 1;
            continue;
        };
        assembly.symbols.push(SymbolNode {
            cx_id,
            qualified_name: node.qualified_name.clone(),
            file: node.file_path.clone(),
            line_start,
            line_end,
            is_test: test_sources.contains(&cx_id),
        });
    }

    for edge in &snapshot.edges {
        if edge.edge_type == TESTS_EDGE_TYPE {
            match (
                cx_by_node_id.get(&edge.source_node_id),
                cx_by_node_id.get(&edge.target_node_id),
            ) {
                (Some(&test), Some(&covered)) => {
                    assembly.tests_edges.push(TestsEdge { test, covered });
                }
                _ => assembly.tests_edges_unresolved += 1,
            }
        } else if edge.edge_type == TESTS_FILE_EDGE_TYPE {
            match (
                cx_by_node_id.get(&edge.source_node_id),
                file_by_node_id.get(&edge.target_node_id),
            ) {
                (Some(&test), Some(file)) => {
                    assembly.tests_file_edges.push(TestsFileEdge {
                        test,
                        file: file.clone(),
                    });
                }
                _ => assembly.tests_edges_unresolved += 1,
            }
        }
    }

    assembly
}

fn is_tests_edge_type(edge_type: &str) -> bool {
    matches!(
        EdgeKind::from_cbm_type(edge_type),
        Some(EdgeKind::Tests) | Some(EdgeKind::TestsFile)
    )
}

/// Shared request path for the `coverage_ingest` MCP tool.
///
/// Assembles [`PropagationInputs`] from the live persisted CBM graph (symbol
/// line ranges + `TESTS`/`TESTS_FILE` edges) plus an uploaded coverage report
/// and a suite run report, calls [`plan_propagation`], and ingests the planned
/// coverage (resolved, confidence 1.0) and propagation (proxy,
/// `PROPAGATION_ANCHOR_CONFIDENCE`) anchor requests through the unchanged
/// [`ingest_outcome_anchors`] path — each in its own atomic Grounding-ledger
/// group commit. Every stage is fail-closed: a bad dial, missing vault, a
/// malformed coverage/test report, a non-resolved coverage source, invalid
/// graph ranges, or an empty graph each return a labeled `status: "refused"`
/// envelope with its stable `{code, message, remediation}` and no partial anchor
/// is written. Because all validation (parse + plan) completes before any
/// mutation, an invalid payload is refused whole, never partially ingested.
#[allow(clippy::too_many_arguments)]
pub(crate) fn coverage_ingest_json_at(
    cache_dir: &Path,
    project: &str,
    coverage_format: &str,
    coverage_report: &str,
    test_format: &str,
    test_report: &str,
    coverage_source: &str,
    run_id: &str,
    impact_files: &BTreeSet<String>,
    observed_at: &str,
) -> Result<Value, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(coverage_ingest_refused(
            project,
            coverage_source,
            "ASTRO_COVERAGE_SHADOW_REQUIRED",
            format!("coverage_ingest requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before ingesting coverage",
        ));
    }

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(coverage_ingest_refused(
            project,
            coverage_source,
            "ASTRO_COVERAGE_VAULT_MISSING",
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before ingesting coverage",
        ));
    }

    // --- Parse the uploaded payloads (fail-closed, no mutation yet) -----------
    let coverage_format = match coverage_format_from_wire(coverage_format) {
        Ok(format) => format,
        Err((code, message)) => {
            return Ok(coverage_ingest_refused(
                project,
                coverage_source,
                code,
                message,
                "pass coverage_format as one of lcov, coverage_py_json, cobertura_xml",
            ));
        }
    };
    let coverage = match parse_coverage(coverage_format, coverage_report) {
        Ok(report) => report,
        Err(error) => {
            return Ok(coverage_ingest_refused(
                project,
                coverage_source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };
    let test_format = match TestReportFormat::from_wire(test_format) {
        Ok(format) => format,
        Err(error) => {
            return Ok(coverage_ingest_refused(
                project,
                coverage_source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };
    let run = match parse_test_report(test_format, test_report) {
        Ok(run) => run,
        Err(error) => {
            return Ok(coverage_ingest_refused(
                project,
                coverage_source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };
    let observed_ts = match astrolabe_anchors::parse_observed_at(observed_at) {
        Ok(ts) => ts,
        Err(error) => {
            return Ok(coverage_ingest_refused(
                project,
                coverage_source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };

    // --- Assemble the graph slice from persisted state ------------------------
    // The retained graph read consumes only the exact source families below;
    // the same latest-state handle then commits Anchors with its Ledger/TimeIndex
    // rows, without restoring unrelated MVCC history.
    let vault = open_shadow_vault_writable_latest_selected(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Ledger,
            ColumnFamily::Anchors,
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Blob,
            ColumnFamily::Kv,
            ColumnFamily::Recurrence,
            ColumnFamily::TimeIndex,
        ],
    )?;
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project)?;
    let cx_ids = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;

    let assembly = assemble_graph(&snapshot);
    if assembly.symbols.is_empty() {
        return Ok(coverage_ingest_refused(
            project,
            coverage_source,
            ASTRO_COVERAGE_NO_GRAPH,
            format!(
                "project {project:?} graph has no anchorable symbols with line ranges (nodes: {}, \
                 unresolved: {}, without range: {})",
                snapshot.nodes.len(),
                assembly.nodes_unresolved,
                assembly.nodes_without_range
            ),
            "index the repository with calyx=\"shadow\" so symbol line ranges are persisted, then \
             re-post the coverage report",
        ));
    }

    // --- Plan (still no mutation) ---------------------------------------------
    let inputs = PropagationInputs {
        symbols: &assembly.symbols,
        tests_edges: &assembly.tests_edges,
        tests_file_edges: &assembly.tests_file_edges,
        run: &run,
        impact_files,
        coverage: Some(&coverage),
        coverage_source,
        run_id,
        observed_at: observed_ts,
    };
    let plan = match plan_propagation(&inputs) {
        Ok(plan) => plan,
        Err(error) => {
            return Ok(coverage_ingest_refused(
                project,
                coverage_source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };

    // --- Ingest the planned requests (each an atomic group commit) ------------
    let mut ledger_refs = Vec::new();
    let mut anchors_written = 0usize;
    let mut anchors_deduplicated = 0usize;
    let mut rows_written = 0usize;
    let mut unmapped: BTreeSet<String> = BTreeSet::new();
    let mut coverage_ledger_seq: Option<u64> = None;
    let mut propagation_ledger_seq: Option<u64> = None;

    for (label, planned) in [
        ("coverage", plan.coverage.as_ref()),
        ("propagation", plan.propagation.as_ref()),
    ] {
        let Some(planned) = planned else { continue };
        match ingest_outcome_anchors(
            &vault,
            &planned.request,
            &planned.cx_ids,
            COVERAGE_INGEST_ACTOR,
        ) {
            Ok(report) => {
                anchors_written += report.anchors_written;
                anchors_deduplicated += report.anchors_deduplicated;
                rows_written += report.rows_written;
                unmapped.extend(report.unmapped_subjects.iter().cloned());
                match label {
                    "coverage" => coverage_ledger_seq = Some(report.ledger_ref.seq),
                    _ => propagation_ledger_seq = Some(report.ledger_ref.seq),
                }
                ledger_refs.push((label, report.ledger_ref));
            }
            Err(error) => {
                drop(vault);
                // Payload was valid, but a stored anchor conflicts. Surface it
                // fail-closed, naming any prior commit so no write is silent.
                return Ok(coverage_ingest_refused_partial(
                    project,
                    coverage_source,
                    error.code,
                    error.message,
                    error.remediation,
                    coverage_ledger_seq,
                ));
            }
        }
    }
    drop(vault);

    let status = if anchors_written > 0 {
        "grounded"
    } else {
        "noop"
    };
    let report = &plan.report;
    let mut provenance: Vec<Value> = ledger_refs
        .iter()
        .map(|(label, ledger_ref)| {
            Value::String(format!("ledger:grounding:{label}:seq={}", ledger_ref.seq))
        })
        .collect();
    provenance.push(Value::String(format!("coverage_source:{coverage_source}")));
    provenance.push(Value::String(format!(
        "propagation_source:{}{run_id}",
        astrolabe_anchors::PROPAGATION_SOURCE_PREFIX
    )));

    Ok(json!({
        "schema": COVERAGE_INGEST_SCHEMA,
        "project": project,
        "status": status,
        "coverage_format": coverage_format.as_str(),
        "coverage_source": coverage_source,
        "run_id": run_id,
        "observed_at": observed_ts,
        "anchors_written": anchors_written,
        "anchors_deduplicated": anchors_deduplicated,
        "rows_written": rows_written,
        "unmapped_subjects": unmapped.iter().cloned().collect::<Vec<_>>(),
        "unmapped_subject_count": unmapped.len(),
        "coverage_ledger_seq": coverage_ledger_seq,
        "propagation_ledger_seq": propagation_ledger_seq,
        "graph": {
            "symbols_considered": assembly.symbols.len(),
            "nodes_unresolved": assembly.nodes_unresolved,
            "nodes_without_range": assembly.nodes_without_range,
            "tests_edges": assembly.tests_edges.len(),
            "tests_file_edges": assembly.tests_file_edges.len(),
            "tests_edges_unresolved": assembly.tests_edges_unresolved,
            "node_map_symbols": cx_ids.len(),
        },
        "propagation_report": propagation_report_json(report),
        // Coverage anchors are resolved (Trusted); propagation anchors are proxy
        // (Provisional). The rollup is the weaker of the two present paths.
        "trust": if plan.propagation.is_some() { "provisional" } else { "trusted" },
        "freshness": "fresh",
        "provenance": provenance,
    }))
}

/// Serializes the exact per-symbol accounting a propagation pass produced.
fn propagation_report_json(report: &PropagationReport) -> Value {
    json!({
        "anchored": report.anchored_non_test_symbol_count,
        "non_test_symbol_count": report.non_test_symbol_count,
        "anchored_fraction": report.anchored_fraction(),
        "suite_passed": report.suite_passed,
        "coverage_symbols": report.coverage_symbols.iter().cloned().collect::<Vec<_>>(),
        "propagation_symbols": report.propagation_symbols.iter().cloned().collect::<Vec<_>>(),
        "suppressed_by_precedence": report.suppressed_by_precedence.iter().cloned().collect::<Vec<_>>(),
        "excluded_by_fanout": report.excluded_by_fanout.iter().cloned().collect::<Vec<_>>(),
        "unmatched_test_cases": report.unmatched_test_cases.iter().cloned().collect::<Vec<_>>(),
        "coverage_symbol_count": report.coverage_symbols.len(),
        "propagation_symbol_count": report.propagation_symbols.len(),
        "excluded_by_fanout_count": report.excluded_by_fanout.len(),
        "unmatched_test_case_count": report.unmatched_test_cases.len(),
    })
}

/// Builds a fail-closed refusal envelope with stable `{code, message,
/// remediation}` and HONEST labels; no anchor was written.
fn coverage_ingest_refused(
    project: &str,
    coverage_source: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": COVERAGE_INGEST_SCHEMA,
        "project": project,
        "status": "refused",
        "coverage_source": coverage_source,
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "anchors_written": 0,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:pre-commit:no-anchor-written"],
    })
}

/// Refusal after a valid payload committed the coverage request but the
/// propagation request conflicted. Names the committed ledger seq so the partial
/// commit is disclosed, never silent.
fn coverage_ingest_refused_partial(
    project: &str,
    coverage_source: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
    committed_ledger_seq: Option<u64>,
) -> Value {
    json!({
        "schema": COVERAGE_INGEST_SCHEMA,
        "project": project,
        "status": "refused",
        "coverage_source": coverage_source,
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "anchors_written": 0,
        "committed_ledger_seq": committed_ledger_seq,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": [match committed_ledger_seq {
            Some(seq) => format!("refusal:post-coverage-commit:ledger_seq={seq}"),
            None => "refusal:pre-commit:no-anchor-written".to_string(),
        }],
    })
}

/// MCP dispatch entry point for `coverage_ingest`.
pub(crate) fn handle_coverage_ingest(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("coverage_ingest arguments must be a JSON object");
    };
    let Some(project) = string_arg(args_obj, "project") else {
        return tool_error_result("coverage_ingest requires project");
    };
    let Some(coverage_format) = string_arg(args_obj, "coverage_format") else {
        return tool_error_result(
            "coverage_ingest requires coverage_format (lcov, coverage_py_json, or cobertura_xml)",
        );
    };
    let Some(coverage_report) = string_arg(args_obj, "coverage_report") else {
        return tool_error_result("coverage_ingest requires a non-empty coverage_report");
    };
    let Some(test_format) = string_arg(args_obj, "test_format") else {
        return tool_error_result(
            "coverage_ingest requires test_format (junit_xml, cargo_test_json, pytest_verbose, go_test_json, or vitest_json)",
        );
    };
    let Some(test_report) = string_arg(args_obj, "test_report") else {
        return tool_error_result("coverage_ingest requires a non-empty test_report");
    };
    let Some(coverage_source) = string_arg(args_obj, "coverage_source") else {
        return tool_error_result(
            "coverage_ingest requires a resolved catalog coverage_source (ci:/trace:/review:/git:revert:)",
        );
    };
    let Some(run_id) = string_arg(args_obj, "run_id") else {
        return tool_error_result("coverage_ingest requires a non-empty run_id");
    };
    let impact_files: BTreeSet<String> = string_array_field(&args, "impact_files")
        .into_iter()
        .collect();
    let observed_at = match args_obj.get("observed_at") {
        None | Some(Value::Null) => now_epoch_seconds().to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(_) => {
            return tool_error_result(
                "coverage_ingest observed_at must be a non-negative integer epoch",
            );
        }
    };

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = coverage_ingest_json_at(
        &cache_dir,
        project,
        coverage_format,
        coverage_report,
        test_format,
        test_report,
        coverage_source,
        run_id,
        &impact_files,
        &observed_at,
    )?;
    if value.get("status").and_then(Value::as_str) == Some("refused") {
        tool_json_error_result(value)
    } else {
        tool_json_result(value)
    }
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
