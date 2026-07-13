//! TESTS-edge propagation + direct-coverage attribution (issue #25).
//!
//! Coverage parsers run against REAL coverage.py 7.15.1 output (lcov, native
//! JSON, and Cobertura XML) exported from a tiny real `calc` repo whose two
//! unit tests exercise `add`/`subtract`; the source and all three reports live
//! under `tests/fixtures/coverage/`. Planning tests assert the exact anchored
//! symbol sets, the negative fan-out assertions that are the point of fan-out
//! control, coverage-over-propagation precedence with its confidence ranking,
//! the anchor-inflation bound, and the P4 exit-gate measurement. The final test
//! persists both requests into a real durable Aster vault and independently
//! reads the anchor rows back (FSV).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_anchors::propagation::{
    ASTRO_COVERAGE_PARSE_MALFORMED, ASTRO_PROPAGATION_INPUT_INVALID, CoverageFormat,
    CoverageReport, PROPAGATION_ANCHOR_CONFIDENCE, PropagationInputs, SymbolNode, TestsEdge,
    TestsFileEdge, parse_cobertura_xml, parse_coverage, parse_coverage_py_json, parse_lcov,
    plan_propagation,
};
use astrolabe_anchors::{
    ParsedTestCase, ParsedTestRun, TestReportFormat, TestStatus, ingest_outcome_anchors,
    read_anchor_rows,
};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{AnchorKind, AnchorValue, CxId, SystemClock, Ts, VaultId};

const LCOV: &str = include_str!("fixtures/coverage/coverage.lcov");
const COVERAGE_JSON: &str = include_str!("fixtures/coverage/coverage_py.json");
const COBERTURA: &str = include_str!("fixtures/coverage/cobertura.xml");

/// Real coverage.py executed-line table for `calc/mathops.py`.
const EXECUTED: &[u32] = &[1, 2, 3, 6, 7, 8, 11, 20];

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn cx(byte: u8) -> CxId {
    CxId::from_bytes([byte; 16])
}

fn sym(cx_byte: u8, qn: &str, file: &str, start: u32, end: u32, is_test: bool) -> SymbolNode {
    SymbolNode {
        cx_id: cx(cx_byte),
        qualified_name: qn.to_string(),
        file: file.to_string(),
        line_start: start,
        line_end: end,
        is_test,
    }
}

fn run(cases: &[(&str, TestStatus)]) -> ParsedTestRun {
    ParsedTestRun {
        format: TestReportFormat::CargoTestJson,
        cases: cases
            .iter()
            .map(|(id, status)| ParsedTestCase {
                case_id: id.to_string(),
                status: *status,
            })
            .collect(),
    }
}

fn executed_set() -> BTreeSet<u32> {
    EXECUTED.iter().copied().collect()
}

// --------------------------------------------------------------------------
// Coverage parsers: real coverage.py output, cross-format agreement.
// --------------------------------------------------------------------------

#[test]
fn all_three_real_coverage_formats_agree_on_the_executed_line_table() {
    let lcov = parse_lcov(LCOV).expect("lcov");
    let json = parse_coverage_py_json(COVERAGE_JSON).expect("coverage.py json");
    let xml = parse_cobertura_xml(COBERTURA).expect("cobertura xml");
    for report in [&lcov, &json, &xml] {
        let key = report
            .executed
            .keys()
            .find(|k| k.ends_with("mathops.py"))
            .expect("mathops.py present");
        assert_eq!(
            report.executed[key],
            executed_set(),
            "{:?} executed set mismatch",
            report.format
        );
    }
    assert_eq!(lcov.format, CoverageFormat::Lcov);
    assert_eq!(json.format, CoverageFormat::CoveragePyJson);
    assert_eq!(xml.format, CoverageFormat::CoberturaXml);
}

#[test]
fn coverage_parsers_fail_closed_on_the_edge_triad() {
    // Empty input.
    for format in [
        CoverageFormat::Lcov,
        CoverageFormat::CoveragePyJson,
        CoverageFormat::CoberturaXml,
    ] {
        assert_eq!(
            parse_coverage(format, "")
                .expect_err("empty refused")
                .code(),
            ASTRO_COVERAGE_PARSE_MALFORMED,
            "{format:?} empty",
        );
    }

    // Boundary: a lone valid single-line record parses; line number 0 refuses.
    let ok = parse_lcov("SF:a.rs\nDA:1,1\nend_of_record\n").expect("minimal lcov");
    assert_eq!(ok.executed["a.rs"], BTreeSet::from([1]));
    assert_eq!(
        parse_lcov("SF:a.rs\nDA:0,1\nend_of_record\n")
            .expect_err("line 0 refused")
            .code(),
        ASTRO_COVERAGE_PARSE_MALFORMED,
    );

    // Invalid format for each parser.
    assert_eq!(
        parse_lcov("DA:1,1\n").expect_err("DA before SF").code(),
        ASTRO_COVERAGE_PARSE_MALFORMED
    );
    assert_eq!(
        parse_lcov("SF:a.rs\nDA:1,1\n")
            .expect_err("truncated, no end_of_record")
            .code(),
        ASTRO_COVERAGE_PARSE_MALFORMED
    );
    assert_eq!(
        parse_coverage_py_json("{ not json")
            .expect_err("bad json")
            .code(),
        ASTRO_COVERAGE_PARSE_MALFORMED
    );
    assert_eq!(
        parse_coverage_py_json(r#"{"files":{"a.py":{"executed_lines":"nope"}}}"#)
            .expect_err("executed_lines not an array")
            .code(),
        ASTRO_COVERAGE_PARSE_MALFORMED
    );
    assert_eq!(
        parse_cobertura_xml("<coverage><lines><line number=\"1\" hits=\"1\"/></lines></coverage>")
            .expect_err("<line> before <class>")
            .code(),
        ASTRO_COVERAGE_PARSE_MALFORMED
    );
}

// --------------------------------------------------------------------------
// Line-exact attribution across two functions (via the public plan path).
// --------------------------------------------------------------------------

#[test]
fn coverage_attributes_executed_lines_to_the_containing_symbol_line_exact() {
    let report = parse_lcov(LCOV).expect("lcov");

    // Body-only ranges (def line excluded): add's body {2,3} and subtract's
    // body {7,8} ran; multiply's body {12..17} and divide's body {21..23} did
    // not. Line 3 must attribute to add, line 7 to subtract, never cross over.
    let body_symbols = vec![
        sym(1, "calc.mathops.add", "calc/mathops.py", 2, 3, false),
        sym(2, "calc.mathops.subtract", "calc/mathops.py", 7, 8, false),
        sym(3, "calc.mathops.multiply", "calc/mathops.py", 12, 17, false),
        sym(4, "calc.mathops.divide", "calc/mathops.py", 21, 23, false),
    ];
    let covered = coverage_only_symbols(&body_symbols, &report, "calc/mathops.py");
    assert_eq!(
        covered,
        BTreeSet::from([
            "calc.mathops.add".to_string(),
            "calc.mathops.subtract".to_string()
        ]),
    );

    // Full ranges (incl. def line) additionally cover multiply and divide via
    // executed def lines 11 and 20; a symbol on the never-run lines 4-5 stays
    // uncovered — the range boundary decides attribution, not a whole-file smear.
    let full_symbols = vec![
        sym(1, "add", "calc/mathops.py", 1, 3, false),
        sym(2, "subtract", "calc/mathops.py", 6, 8, false),
        sym(3, "multiply", "calc/mathops.py", 11, 17, false),
        sym(4, "divide", "calc/mathops.py", 20, 23, false),
        sym(5, "gap_symbol", "calc/mathops.py", 4, 5, false),
    ];
    let covered_full = coverage_only_symbols(&full_symbols, &report, "calc/mathops.py");
    assert_eq!(
        covered_full,
        BTreeSet::from([
            "add".to_string(),
            "subtract".to_string(),
            "multiply".to_string(),
            "divide".to_string()
        ]),
    );
}

/// Helper: which symbols a coverage report anchors, using the public plan path
/// with every symbol in the impact set and no test edges.
fn coverage_only_symbols(
    symbols: &[SymbolNode],
    report: &CoverageReport,
    file: &str,
) -> BTreeSet<String> {
    let impact: BTreeSet<String> = BTreeSet::from([file.to_string()]);
    let run = run(&[]);
    let inputs = PropagationInputs {
        symbols,
        tests_edges: &[],
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: Some(report),
        coverage_source: "trace:cov-attr",
        run_id: "attr",
        observed_at: 1_000,
    };
    plan_propagation(&inputs)
        .expect("plan")
        .report
        .coverage_symbols
}

// --------------------------------------------------------------------------
// Propagation golden with negative fan-out assertions.
// --------------------------------------------------------------------------

fn golden_symbols() -> Vec<SymbolNode> {
    vec![
        sym(1, "app.core.parse", "app/core.py", 1, 10, false),
        sym(2, "app.core.encode", "app/core.py", 11, 20, false),
        sym(3, "app.util.helper", "app/util.py", 1, 8, false),
        sym(
            10,
            "tests.test_core.test_parse",
            "tests/test_core.py",
            1,
            5,
            true,
        ),
        sym(
            11,
            "tests.test_core.test_encode",
            "tests/test_core.py",
            6,
            10,
            true,
        ),
        sym(
            12,
            "tests.test_util.test_helper",
            "tests/test_util.py",
            1,
            5,
            true,
        ),
    ]
}

#[test]
fn propagation_golden_anchors_exact_impact_set_and_not_beyond() {
    let symbols = golden_symbols();
    let tests_edges = vec![
        TestsEdge {
            test: cx(10),
            covered: cx(1),
        },
        TestsEdge {
            test: cx(11),
            covered: cx(2),
        },
        TestsEdge {
            test: cx(12),
            covered: cx(3),
        }, // reaches an out-of-impact symbol
    ];
    let impact: BTreeSet<String> = BTreeSet::from(["app/core.py".to_string()]);
    let run = run(&[
        ("tests.test_core.test_parse", TestStatus::Passed),
        ("tests.test_core.test_encode", TestStatus::Passed),
        ("tests.test_util.test_helper", TestStatus::Passed),
    ]);
    let inputs = PropagationInputs {
        symbols: &symbols,
        tests_edges: &tests_edges,
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: None,
        coverage_source: "ci:github:1001",
        run_id: "run-golden",
        observed_at: 1_786_000_000,
    };
    let plan = plan_propagation(&inputs).expect("plan");

    assert_eq!(
        plan.report.propagation_symbols,
        BTreeSet::from(["app.core.parse".to_string(), "app.core.encode".to_string()])
    );
    // Negative fan-out: the reachable out-of-impact symbol is provably NOT
    // anchored and is accounted for (never silently dropped).
    assert!(!plan.report.propagation_symbols.contains("app.util.helper"));
    assert_eq!(
        plan.report.excluded_by_fanout,
        BTreeSet::from(["app.util.helper".to_string()])
    );
    assert!(plan.report.coverage_symbols.is_empty());
    assert!(plan.report.suite_passed);
}

#[test]
fn tests_file_edge_expands_to_non_test_symbols_in_that_file() {
    let symbols = golden_symbols();
    let file_edges = vec![TestsFileEdge {
        test: cx(10),
        file: "app/core.py".to_string(),
    }];
    let impact: BTreeSet<String> = BTreeSet::from(["app/core.py".to_string()]);
    let run = run(&[("tests.test_core.test_parse", TestStatus::Passed)]);
    let inputs = PropagationInputs {
        symbols: &symbols,
        tests_edges: &[],
        tests_file_edges: &file_edges,
        run: &run,
        impact_files: &impact,
        coverage: None,
        coverage_source: "ci:github:1002",
        run_id: "run-file-edge",
        observed_at: 1_786_000_100,
    };
    let plan = plan_propagation(&inputs).expect("plan");
    assert_eq!(
        plan.report.propagation_symbols,
        BTreeSet::from(["app.core.parse".to_string(), "app.core.encode".to_string()])
    );
}

// --------------------------------------------------------------------------
// Precedence: coverage wins and is higher-confidence.
// --------------------------------------------------------------------------

#[test]
fn coverage_takes_precedence_over_tests_edge_and_is_higher_confidence() {
    let symbols = golden_symbols();
    let tests_edges = vec![
        TestsEdge {
            test: cx(10),
            covered: cx(1),
        },
        TestsEdge {
            test: cx(11),
            covered: cx(2),
        },
    ];
    let coverage = CoverageReport {
        format: CoverageFormat::Lcov,
        executed: BTreeMap::from([("app/core.py".to_string(), BTreeSet::from([3]))]),
    };
    let impact: BTreeSet<String> = BTreeSet::from(["app/core.py".to_string()]);
    let run = run(&[
        ("tests.test_core.test_parse", TestStatus::Passed),
        ("tests.test_core.test_encode", TestStatus::Passed),
    ]);
    let inputs = PropagationInputs {
        symbols: &symbols,
        tests_edges: &tests_edges,
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: Some(&coverage),
        coverage_source: "trace:coverage-run-3",
        run_id: "run-precedence",
        observed_at: 1_786_000_200,
    };
    let plan = plan_propagation(&inputs).expect("plan");

    assert_eq!(
        plan.report.coverage_symbols,
        BTreeSet::from(["app.core.parse".to_string()])
    );
    assert_eq!(
        plan.report.propagation_symbols,
        BTreeSet::from(["app.core.encode".to_string()])
    );
    assert_eq!(
        plan.report.suppressed_by_precedence,
        BTreeSet::from(["app.core.parse".to_string()])
    );
    let cov_conf = plan.coverage.as_ref().unwrap().request.confidence;
    let prop_conf = plan.propagation.as_ref().unwrap().request.confidence;
    assert_eq!(cov_conf, 1.0);
    assert_eq!(prop_conf, PROPAGATION_ANCHOR_CONFIDENCE);
    assert!(cov_conf > prop_conf, "coverage must be higher-confidence");
}

// --------------------------------------------------------------------------
// Anchor-inflation regression: unchanged repo anchors only direct coverage.
// --------------------------------------------------------------------------

#[test]
fn unchanged_repo_anchors_only_direct_coverage_symbols_bounded() {
    let symbols = golden_symbols();
    let tests_edges = vec![
        TestsEdge {
            test: cx(10),
            covered: cx(1),
        },
        TestsEdge {
            test: cx(11),
            covered: cx(2),
        },
        TestsEdge {
            test: cx(12),
            covered: cx(3),
        },
    ];
    let empty_impact: BTreeSet<String> = BTreeSet::new(); // no diff
    let coverage = CoverageReport {
        format: CoverageFormat::Lcov,
        executed: BTreeMap::from([("app/core.py".to_string(), BTreeSet::from([2]))]),
    };
    let run = run(&[
        ("tests.test_core.test_parse", TestStatus::Passed),
        ("tests.test_core.test_encode", TestStatus::Passed),
        ("tests.test_util.test_helper", TestStatus::Passed),
    ]);
    let inputs = PropagationInputs {
        symbols: &symbols,
        tests_edges: &tests_edges,
        tests_file_edges: &[],
        run: &run,
        impact_files: &empty_impact,
        coverage: Some(&coverage),
        coverage_source: "ci:github:2002",
        run_id: "run-nodiff",
        observed_at: 1_786_000_300,
    };
    let plan = plan_propagation(&inputs).expect("plan");

    assert_eq!(
        plan.report.coverage_symbols,
        BTreeSet::from(["app.core.parse".to_string()])
    );
    assert!(plan.report.propagation_symbols.is_empty());
    assert!(plan.propagation.is_none());
    assert_eq!(plan.report.anchored_non_test_symbol_count, 1);
    assert!(plan.report.excluded_by_fanout.contains("app.core.encode"));
}

// --------------------------------------------------------------------------
// P4 exit-gate harness: >30% of non-test symbols anchored.
// --------------------------------------------------------------------------

#[test]
fn p4_exit_gate_more_than_thirty_percent_non_test_symbols_anchored() {
    // Scripted measurement on the real coverage.py `calc` repo fixture: its two
    // real unit tests TESTS `add` and `subtract`, so a green suite grounds two
    // of the four non-test functions via propagation on the real topology.
    let symbols = vec![
        sym(1, "calc.mathops.add", "calc/mathops.py", 1, 3, false),
        sym(2, "calc.mathops.subtract", "calc/mathops.py", 6, 8, false),
        sym(3, "calc.mathops.multiply", "calc/mathops.py", 11, 17, false),
        sym(4, "calc.mathops.divide", "calc/mathops.py", 20, 23, false),
        sym(10, "test_mathops.test_add", "test_mathops.py", 5, 6, true),
        sym(
            11,
            "test_mathops.test_subtract",
            "test_mathops.py",
            8,
            9,
            true,
        ),
    ];
    let tests_edges = vec![
        TestsEdge {
            test: cx(10),
            covered: cx(1),
        },
        TestsEdge {
            test: cx(11),
            covered: cx(2),
        },
    ];
    let impact: BTreeSet<String> = BTreeSet::from(["calc/mathops.py".to_string()]);
    let run = run(&[
        ("test_mathops.test_add", TestStatus::Passed),
        ("test_mathops.test_subtract", TestStatus::Passed),
    ]);
    let inputs = PropagationInputs {
        symbols: &symbols,
        tests_edges: &tests_edges,
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: None,
        coverage_source: "ci:github:9001",
        run_id: "p4-exit-gate",
        observed_at: 1_786_000_400,
    };
    let plan = plan_propagation(&inputs).expect("plan");
    let fraction = plan.report.anchored_fraction();
    const P4_EXIT_THRESHOLD: f64 = 0.30;
    assert!(
        fraction > P4_EXIT_THRESHOLD,
        "P4 exit gate: anchored {}/{} = {:.3} non-test symbols, need > {:.2}",
        plan.report.anchored_non_test_symbol_count,
        plan.report.non_test_symbol_count,
        fraction,
        P4_EXIT_THRESHOLD,
    );
    assert_eq!(plan.report.non_test_symbol_count, 4);
    assert_eq!(plan.report.anchored_non_test_symbol_count, 2);
}

// --------------------------------------------------------------------------
// Fail-closed input validation.
// --------------------------------------------------------------------------

#[test]
fn invalid_inputs_fail_closed() {
    let good = sym(1, "a", "a.py", 1, 2, false);
    let impact: BTreeSet<String> = BTreeSet::new();
    let run = run(&[("a", TestStatus::Passed)]);

    // Invalid symbol range (end < start).
    let bad_range = vec![sym(1, "a", "a.py", 5, 2, false)];
    let err = plan_propagation(&PropagationInputs {
        symbols: &bad_range,
        tests_edges: &[],
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: None,
        coverage_source: "ci:github:1",
        run_id: "r",
        observed_at: 1,
    })
    .expect_err("bad range refused");
    assert_eq!(err.code(), ASTRO_PROPAGATION_INPUT_INVALID);

    // Proxy coverage source refused (coverage must be resolved).
    let one = [good.clone()];
    let err = plan_propagation(&PropagationInputs {
        symbols: &one,
        tests_edges: &[],
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: None,
        coverage_source: "agent:codex:s1",
        run_id: "r",
        observed_at: 1,
    })
    .expect_err("proxy coverage source refused");
    assert_eq!(err.code(), ASTRO_PROPAGATION_INPUT_INVALID);

    // Blank run id refused.
    let err = plan_propagation(&PropagationInputs {
        symbols: &one,
        tests_edges: &[],
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: None,
        coverage_source: "ci:github:1",
        run_id: "  ",
        observed_at: 1,
    })
    .expect_err("blank run id refused");
    assert_eq!(err.code(), ASTRO_PROPAGATION_INPUT_INVALID);
}

// --------------------------------------------------------------------------
// FSV: persist both requests into a real durable vault and read them back.
// --------------------------------------------------------------------------

const ANCHOR_TEST_SALT: &[u8] = b"astrolabe-propagation-fsv";

struct TempVaultDir(std::path::PathBuf);

impl Drop for TempVaultDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_vault(dir: &Path) -> AsterVault<SystemClock> {
    AsterVault::new_durable(
        dir,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>().unwrap(),
        ANCHOR_TEST_SALT.to_vec(),
        VaultOptions::default(),
    )
    .expect("open durable vault")
}

fn new_vault(name: &str) -> (TempVaultDir, AsterVault<SystemClock>) {
    let dir = std::env::temp_dir().join(format!(
        "astrolabe-propagation-{name}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create vault dir");
    let vault = open_vault(&dir);
    (TempVaultDir(dir), vault)
}

#[test]
fn planned_requests_persist_and_read_back_with_correct_sources_and_confidence() {
    let symbols = golden_symbols();
    let tests_edges = vec![
        TestsEdge {
            test: cx(10),
            covered: cx(1),
        }, // parse: coverage will win
        TestsEdge {
            test: cx(11),
            covered: cx(2),
        }, // encode: propagation only
        TestsEdge {
            test: cx(12),
            covered: cx(3),
        }, // helper: out of impact -> dropped
    ];
    let coverage = CoverageReport {
        format: CoverageFormat::Lcov,
        executed: BTreeMap::from([("app/core.py".to_string(), BTreeSet::from([5]))]),
    };
    let impact: BTreeSet<String> = BTreeSet::from(["app/core.py".to_string()]);
    let observed_at: Ts = 1_786_500_000;
    let run = run(&[
        ("tests.test_core.test_parse", TestStatus::Passed),
        ("tests.test_core.test_encode", TestStatus::Passed),
        ("tests.test_util.test_helper", TestStatus::Passed),
    ]);
    let inputs = PropagationInputs {
        symbols: &symbols,
        tests_edges: &tests_edges,
        tests_file_edges: &[],
        run: &run,
        impact_files: &impact,
        coverage: Some(&coverage),
        coverage_source: "trace:coverage-run-9",
        run_id: "fsv-run",
        observed_at,
    };
    let plan = plan_propagation(&inputs).expect("plan");

    let (dir, vault) = new_vault("fsv");
    let cov = plan.coverage.expect("coverage request");
    let prop = plan.propagation.expect("propagation request");
    let cov_report = ingest_outcome_anchors(
        &vault,
        &cov.request,
        &cov.cx_ids,
        "astrolabe-propagation-test",
    )
    .expect("ingest coverage");
    let prop_report = ingest_outcome_anchors(
        &vault,
        &prop.request,
        &prop.cx_ids,
        "astrolabe-propagation-test",
    )
    .expect("ingest propagation");
    assert_eq!(cov_report.anchors_written, 1); // parse
    assert_eq!(prop_report.anchors_written, 1); // encode
    drop(vault);

    // Independent readback from a reopened vault.
    let reopened = open_vault(&dir.0);
    let rows = read_anchor_rows(&reopened).expect("read rows");

    let mut by_qn: BTreeMap<String, (String, f32)> = BTreeMap::new();
    // Map cx -> qn from the plan inputs for readback attribution.
    let cx_to_qn: BTreeMap<CxId, String> = symbols
        .iter()
        .map(|s| (s.cx_id, s.qualified_name.clone()))
        .collect();
    for persisted in &rows {
        let qn = cx_to_qn
            .get(&persisted.row.cx_id)
            .expect("row cx maps to a symbol")
            .clone();
        assert_eq!(persisted.row.kind, AnchorKind::TestPass);
        assert_eq!(persisted.row.anchors.len(), 1, "one anchor per symbol");
        let anchor = &persisted.row.anchors[0];
        assert_eq!(anchor.observed_at, observed_at);
        assert_eq!(anchor.value, AnchorValue::Bool(true));
        by_qn.insert(qn, (anchor.source.clone(), anchor.confidence));
    }

    // Precedence: parse persisted ONLY under the resolved coverage source at
    // confidence 1.0 (no propagation row for it).
    assert_eq!(
        by_qn.get("app.core.parse"),
        Some(&("trace:coverage-run-9".to_string(), 1.0)),
    );
    // encode persisted under the proxy propagation source at 0.6.
    assert_eq!(
        by_qn.get("app.core.encode"),
        Some(&(
            "propagation:fsv-run".to_string(),
            PROPAGATION_ANCHOR_CONFIDENCE
        )),
    );
    // Negative fan-out: the out-of-impact symbol has NO persisted row at all.
    assert!(
        !by_qn.contains_key("app.util.helper"),
        "out-of-impact symbol must not be anchored"
    );
    assert_eq!(rows.len(), 2, "exactly two symbols anchored");
    drop(reopened);
}
