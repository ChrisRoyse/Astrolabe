//! TESTS-edge propagation and direct-coverage symbol attribution (blueprint
//! 06 §2.1).
//!
//! A test suite run grounds outcome anchors on the code symbols the tests
//! actually exercise. Two evidence paths feed the same `anchors` CF, ranked by
//! how directly they observe execution:
//!
//! 1. **Direct coverage** (lcov / coverage.py) — the runner recorded which
//!    source lines executed. Each covered line maps to the symbol whose
//!    `[line_start, line_end]` range contains it. This is *resolved* evidence:
//!    the run directly observed the symbol run, so the anchor is Trusted at
//!    confidence `1.0`.
//! 2. **TESTS-edge propagation** — no coverage for the symbol, but a static
//!    `TESTS` / `TESTS_FILE` edge links a passing test to it. This is *proxy*
//!    evidence: the edge is an inference, not an observation, so the anchor is
//!    Provisional at [`PROPAGATION_ANCHOR_CONFIDENCE`].
//!
//! Two invariants keep grounding honest rather than inflated:
//!
//! - **Precedence** — when a symbol has both direct coverage and a TESTS edge,
//!   only the higher-confidence coverage anchor is emitted. Propagation never
//!   downgrades an already-resolved symbol.
//! - **Fan-out control** — propagation anchors are confined to symbols in the
//!   changed files' impact set. A green run on an untouched repo therefore
//!   grounds only the symbols coverage *directly* observed, never the whole
//!   graph. Without this, one passing suite would mark every reachable symbol
//!   "grounded" and the trust signal would be worthless.
//!
//! This module is pure planning: it consumes a graph slice plus a parsed run
//! and coverage report and produces validated [`OutcomeAnchorRequest`]s with
//! their subject→`CxId` maps. Persistence, ledgering, and FSV read-back run
//! through the unchanged [`crate::ingest_outcome_anchors`] path.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::{DomainError, GroundingKind};
use calyx_core::{AnchorKind, AnchorValue, CxId, Ts};

use crate::parsers::{ParsedTestRun, TestStatus};
use crate::{OutcomeAnchorRequest, OutcomeKind, OutcomeSubject, classify_source};

/// Stable failure code for structurally invalid propagation graph input.
pub const ASTRO_PROPAGATION_INPUT_INVALID: &str = "ASTRO_PROPAGATION_INPUT_INVALID";
/// Stable failure code for malformed or partial coverage input.
pub const ASTRO_COVERAGE_PARSE_MALFORMED: &str = "ASTRO_COVERAGE_PARSE_MALFORMED";

/// Registry knob: confidence carried by a TESTS-edge *propagated* anchor.
///
/// Propagation is proxy evidence (a static edge inference, not an observed
/// line hit), so this must sit strictly below the resolved coverage confidence
/// of `1.0` and inside the open interval `(0, 1)` the proxy grounding invariant
/// enforces. Coverage anchors are therefore always marked higher-confidence
/// than propagation anchors for the same symbol.
pub const PROPAGATION_ANCHOR_CONFIDENCE: f32 = 0.6;

/// Registry knob: catalog prefix for propagation-derived proxy anchor sources.
///
/// A propagation source is `propagation:<run_id>`; it classifies as
/// [`GroundingKind::Proxy`] / Provisional through the domain grounding catalog.
pub const PROPAGATION_SOURCE_PREFIX: &str = "propagation:";

const PROPAGATION_REMEDIATION: &str = "supply a well-formed graph slice (validated symbol ranges, resolved coverage source) and re-run propagation";
const COVERAGE_REMEDIATION: &str = "re-export the full coverage report from the runner and re-post the complete file; partial ingest is refused";

/// One code-graph symbol with the metadata propagation and coverage need.
///
/// Line numbers are one-based inclusive, matching
/// [`astrolabe_domain::SymbolRecord`]. A symbol with `is_test = true` is a test
/// definition: it is a propagation *source*, never an anchored target (anchoring
/// a test as `TestPass` would be circular).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolNode {
    /// Constellation id the anchor is keyed under.
    pub cx_id: CxId,
    /// Fully qualified symbol name; also the test-result match key.
    pub qualified_name: String,
    /// Repository-relative source file path.
    pub file: String,
    /// One-based inclusive first line of the symbol body.
    pub line_start: u32,
    /// One-based inclusive last line of the symbol body.
    pub line_end: u32,
    /// Whether this symbol is a test definition.
    pub is_test: bool,
}

impl SymbolNode {
    fn validate(&self) -> Result<(), DomainError> {
        if self.qualified_name.trim().is_empty() {
            return Err(propagation_invalid("symbol has an empty qualified_name"));
        }
        if self.file.trim().is_empty() {
            return Err(propagation_invalid(format!(
                "symbol {:?} has an empty file path",
                self.qualified_name
            )));
        }
        if self.line_start == 0 {
            return Err(propagation_invalid(format!(
                "symbol {:?} has line_start 0; source lines are one-based",
                self.qualified_name
            )));
        }
        if self.line_end < self.line_start {
            return Err(propagation_invalid(format!(
                "symbol {:?} has line_end {} before line_start {}",
                self.qualified_name, self.line_end, self.line_start
            )));
        }
        Ok(())
    }

    fn covers_line(&self, line: u32) -> bool {
        line >= self.line_start && line <= self.line_end
    }
}

/// A `TESTS` edge: a test symbol directly exercises a covered symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestsEdge {
    /// Source test symbol constellation id.
    pub test: CxId,
    /// Destination covered symbol constellation id.
    pub covered: CxId,
}

/// A `TESTS_FILE` edge: a test symbol exercises a whole source file. It expands
/// to every non-test symbol whose `file` matches at planning time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestsFileEdge {
    /// Source test symbol constellation id.
    pub test: CxId,
    /// Repository-relative file the test exercises.
    pub file: String,
}

/// One parsed coverage report: which source lines a run actually executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    /// Originating coverage format.
    pub format: CoverageFormat,
    /// Normalized file path → set of executed (hit-count > 0) line numbers.
    pub executed: BTreeMap<String, BTreeSet<u32>>,
}

/// Supported direct-coverage report formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageFormat {
    /// LCOV tracefile (`SF:`/`DA:`/`end_of_record`).
    Lcov,
    /// coverage.py native JSON (`coverage json`).
    CoveragePyJson,
    /// Cobertura XML (`coverage xml`, gcovr, and friends).
    CoberturaXml,
}

impl CoverageFormat {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lcov => "lcov",
            Self::CoveragePyJson => "coverage_py_json",
            Self::CoberturaXml => "cobertura_xml",
        }
    }
}

/// Inputs to one propagation planning pass.
#[derive(Debug, Clone)]
pub struct PropagationInputs<'a> {
    /// Every symbol in the graph slice under consideration.
    pub symbols: &'a [SymbolNode],
    /// Direct test→symbol edges.
    pub tests_edges: &'a [TestsEdge],
    /// Test→file edges, expanded to that file's non-test symbols.
    pub tests_file_edges: &'a [TestsFileEdge],
    /// Parsed suite run: which test cases passed/failed.
    pub run: &'a ParsedTestRun,
    /// Changed files' impact set (repo-relative). Propagation anchors are
    /// confined to symbols whose `file` is in this set. An empty set means no
    /// diff: propagation grounds nothing and only direct coverage remains.
    pub impact_files: &'a BTreeSet<String>,
    /// Optional direct-coverage report; when present it supersedes propagation
    /// for the symbols it covers.
    pub coverage: Option<&'a CoverageReport>,
    /// Resolved catalog source for coverage anchors (`ci:`/`trace:`/`review:`/
    /// `git:revert:`). Refused fail-closed if it is not resolved evidence.
    pub coverage_source: &'a str,
    /// Opaque run identifier used to build the `propagation:<run_id>` source.
    pub run_id: &'a str,
    /// Server-observed timestamp stamped on every anchor.
    pub observed_at: Ts,
}

/// A validated request paired with its subject→`CxId` map, ready for
/// [`crate::ingest_outcome_anchors`].
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedRequest {
    /// The validated outcome-anchor request.
    pub request: OutcomeAnchorRequest,
    /// Subject id (qualified name) → constellation id for every subject.
    pub cx_ids: BTreeMap<String, CxId>,
}

/// The deterministic plan produced from one propagation pass.
#[derive(Debug, Clone, PartialEq)]
pub struct PropagationPlan {
    /// Coverage-derived anchors (resolved, confidence `1.0`), if any.
    pub coverage: Option<PlannedRequest>,
    /// Propagation-derived anchors (proxy, [`PROPAGATION_ANCHOR_CONFIDENCE`]),
    /// after precedence and fan-out filtering, if any.
    pub propagation: Option<PlannedRequest>,
    /// Accounting for exactly which symbols each path anchored and why.
    pub report: PropagationReport,
}

/// Exact, assertable accounting for one propagation pass. Every symbol the
/// suite could ground is placed in exactly one bucket — none is silently
/// dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationReport {
    /// Non-test symbols anchored by direct coverage.
    pub coverage_symbols: BTreeSet<String>,
    /// Non-test symbols anchored by TESTS-edge propagation.
    pub propagation_symbols: BTreeSet<String>,
    /// Symbols reachable by propagation but suppressed because coverage already
    /// anchored them at higher confidence.
    pub suppressed_by_precedence: BTreeSet<String>,
    /// Symbols reachable by propagation but excluded because their file is
    /// outside the changed-files impact set (fan-out control).
    pub excluded_by_fanout: BTreeSet<String>,
    /// Test-result case ids that matched no test symbol qualified name.
    pub unmatched_test_cases: BTreeSet<String>,
    /// Whether the whole suite passed (no failed and no errored cases).
    pub suite_passed: bool,
    /// Total non-test symbols in the graph slice.
    pub non_test_symbol_count: usize,
    /// Distinct non-test symbols anchored by either path.
    pub anchored_non_test_symbol_count: usize,
}

impl PropagationReport {
    /// Fraction of non-test symbols anchored by either path, in `[0, 1]`.
    /// Zero when the slice has no non-test symbols.
    pub fn anchored_fraction(&self) -> f64 {
        if self.non_test_symbol_count == 0 {
            return 0.0;
        }
        self.anchored_non_test_symbol_count as f64 / self.non_test_symbol_count as f64
    }
}

/// Plans coverage + propagation anchors for one suite run.
///
/// Fail-closed on invalid symbol ranges, a non-resolved coverage source, or a
/// blank run id. Deterministic: identical inputs yield an identical plan and
/// identical persisted bytes.
pub fn plan_propagation(inputs: &PropagationInputs<'_>) -> Result<PropagationPlan, DomainError> {
    for symbol in inputs.symbols {
        symbol.validate()?;
    }
    if inputs.run_id.trim().is_empty() {
        return Err(propagation_invalid("run_id must not be blank"));
    }
    // Coverage anchors are resolved evidence; refuse a proxy coverage source
    // fail-closed rather than silently downgrading the confidence bar.
    let coverage_class = classify_source(inputs.coverage_source)?;
    if coverage_class.grounding_kind != GroundingKind::Resolved {
        return Err(propagation_invalid(format!(
            "coverage_source {:?} is proxy evidence; coverage anchors require a resolved catalog \
             source (ci:/trace:/review:/git:revert:)",
            inputs.coverage_source
        )));
    }

    // Index symbols by constellation id and count non-test symbols.
    let mut by_cx: BTreeMap<CxId, &SymbolNode> = BTreeMap::new();
    for symbol in inputs.symbols {
        by_cx.insert(symbol.cx_id, symbol);
    }
    let non_test_symbol_count = inputs.symbols.iter().filter(|s| !s.is_test).count();

    let suite_passed = suite_passed(inputs.run);

    // --- Direct coverage attribution (resolved) -------------------------------
    // A non-test symbol is covered iff any executed line falls inside its range
    // for a matching file. Line-exact: a line is attributed to the symbol whose
    // range contains it, so two functions sharing a file each collect only their
    // own executed lines.
    let mut coverage_symbols: BTreeMap<String, CxId> = BTreeMap::new();
    if let Some(report) = inputs.coverage {
        for symbol in inputs.symbols {
            if symbol.is_test {
                continue;
            }
            if symbol_is_covered(symbol, report) {
                coverage_symbols.insert(symbol.qualified_name.clone(), symbol.cx_id);
            }
        }
    }
    let covered_cx: BTreeSet<CxId> = coverage_symbols.values().copied().collect();

    // --- TESTS-edge propagation (proxy) ---------------------------------------
    // Match run cases to test symbols by qualified name, then follow edges one
    // hop to covered non-test symbols. A symbol's propagated outcome is the AND
    // of every covering test's outcome (any failing test → false), which is
    // deterministic and dedup-conflict-free.
    let qn_to_cx: BTreeMap<&str, CxId> = inputs
        .symbols
        .iter()
        .map(|s| (s.qualified_name.as_str(), s.cx_id))
        .collect();

    // test cx → aggregated outcome across matched cases (false wins).
    let mut test_outcomes: BTreeMap<CxId, bool> = BTreeMap::new();
    let mut unmatched_test_cases: BTreeSet<String> = BTreeSet::new();
    for case in &inputs.run.cases {
        if !case.status.grounds_anchor() {
            continue; // skipped cases ground nothing
        }
        match qn_to_cx.get(case.case_id.as_str()) {
            Some(&cx_id) => {
                let entry = test_outcomes.entry(cx_id).or_insert(true);
                *entry = *entry && case.status.passed();
            }
            None => {
                unmatched_test_cases.insert(case.case_id.clone());
            }
        }
    }

    // Symbols in the same file, for TESTS_FILE expansion.
    let mut non_test_by_file: BTreeMap<String, Vec<CxId>> = BTreeMap::new();
    for symbol in inputs.symbols {
        if !symbol.is_test {
            non_test_by_file
                .entry(normalize_path(&symbol.file))
                .or_default()
                .push(symbol.cx_id);
        }
    }

    // covered symbol cx → AND of covering test outcomes.
    let mut propagated_outcomes: BTreeMap<CxId, bool> = BTreeMap::new();
    let record = |target: CxId, outcome: bool, acc: &mut BTreeMap<CxId, bool>| {
        let entry = acc.entry(target).or_insert(true);
        *entry = *entry && outcome;
    };
    for edge in inputs.tests_edges {
        if let Some(&outcome) = test_outcomes.get(&edge.test) {
            // Only anchor real non-test symbols that exist in the slice.
            if let Some(symbol) = by_cx.get(&edge.covered)
                && !symbol.is_test
            {
                record(edge.covered, outcome, &mut propagated_outcomes);
            }
        }
    }
    for edge in inputs.tests_file_edges {
        if let Some(&outcome) = test_outcomes.get(&edge.test)
            && let Some(targets) = non_test_by_file.get(&normalize_path(&edge.file))
        {
            for &target in targets {
                record(target, outcome, &mut propagated_outcomes);
            }
        }
    }

    // Apply precedence (coverage wins) and fan-out control (impact set only).
    let impact_norm: BTreeSet<String> = inputs
        .impact_files
        .iter()
        .map(|f| normalize_path(f))
        .collect();
    let mut propagation_symbols: BTreeMap<String, (CxId, bool)> = BTreeMap::new();
    let mut suppressed_by_precedence: BTreeSet<String> = BTreeSet::new();
    let mut excluded_by_fanout: BTreeSet<String> = BTreeSet::new();
    for (&cx_id, &outcome) in &propagated_outcomes {
        let symbol = by_cx.get(&cx_id).expect("propagated cx has a symbol");
        let qn = symbol.qualified_name.clone();
        if covered_cx.contains(&cx_id) {
            suppressed_by_precedence.insert(qn);
            continue;
        }
        if !impact_norm.contains(&normalize_path(&symbol.file)) {
            excluded_by_fanout.insert(qn);
            continue;
        }
        propagation_symbols.insert(qn, (cx_id, outcome));
    }

    // --- Build validated requests ---------------------------------------------
    let coverage_request = if coverage_symbols.is_empty() {
        None
    } else {
        let subjects = coverage_symbols
            .keys()
            .map(|qn| OutcomeSubject {
                subject_id: qn.clone(),
                anchor_kind: AnchorKind::TestPass,
                value: AnchorValue::Bool(suite_passed),
            })
            .collect();
        let request = OutcomeAnchorRequest::new(
            OutcomeKind::TestRun,
            inputs.coverage_source.to_string(),
            inputs.observed_at,
            None, // resolved → defaults to 1.0
            subjects,
        )?;
        Some(PlannedRequest {
            request,
            cx_ids: coverage_symbols
                .iter()
                .map(|(qn, cx)| (qn.clone(), *cx))
                .collect(),
        })
    };

    let propagation_request = if propagation_symbols.is_empty() {
        None
    } else {
        let source = format!("{PROPAGATION_SOURCE_PREFIX}{}", inputs.run_id);
        let subjects = propagation_symbols
            .iter()
            .map(|(qn, (_, outcome))| OutcomeSubject {
                subject_id: qn.clone(),
                anchor_kind: AnchorKind::TestPass,
                value: AnchorValue::Bool(*outcome),
            })
            .collect();
        let request = OutcomeAnchorRequest::new(
            OutcomeKind::TestRun,
            source,
            inputs.observed_at,
            Some(PROPAGATION_ANCHOR_CONFIDENCE),
            subjects,
        )?;
        Some(PlannedRequest {
            request,
            cx_ids: propagation_symbols
                .iter()
                .map(|(qn, (cx, _))| (qn.clone(), *cx))
                .collect(),
        })
    };

    let coverage_qns: BTreeSet<String> = coverage_symbols.keys().cloned().collect();
    let propagation_qns: BTreeSet<String> = propagation_symbols.keys().cloned().collect();
    let anchored: BTreeSet<&String> = coverage_qns.union(&propagation_qns).collect();
    let anchored_non_test_symbol_count = anchored.len();

    Ok(PropagationPlan {
        coverage: coverage_request,
        propagation: propagation_request,
        report: PropagationReport {
            coverage_symbols: coverage_qns,
            propagation_symbols: propagation_qns,
            suppressed_by_precedence,
            excluded_by_fanout,
            unmatched_test_cases,
            suite_passed,
            non_test_symbol_count,
            anchored_non_test_symbol_count,
        },
    })
}

fn suite_passed(run: &ParsedTestRun) -> bool {
    run.cases
        .iter()
        .all(|case| !matches!(case.status, TestStatus::Failed | TestStatus::Errored))
}

fn symbol_is_covered(symbol: &SymbolNode, report: &CoverageReport) -> bool {
    let symbol_path = normalize_path(&symbol.file);
    report.executed.iter().any(|(cov_path, lines)| {
        paths_match(cov_path, &symbol_path) && lines.iter().any(|&line| symbol.covers_line(line))
    })
}

/// Normalizes a path for matching: backslashes → `/`, strip a leading `./`.
fn normalize_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    replaced
        .strip_prefix("./")
        .map(str::to_string)
        .unwrap_or(replaced)
}

/// Two normalized paths match if they are equal or one is a path-suffix of the
/// other (coverage tools may emit absolute paths while symbols are repo-relative).
fn paths_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    a.ends_with(&format!("/{b}")) || b.ends_with(&format!("/{a}"))
}

fn propagation_invalid(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_PROPAGATION_INPUT_INVALID,
        message.into(),
        PROPAGATION_REMEDIATION,
    )
}

fn coverage_malformed(format: CoverageFormat, message: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        ASTRO_COVERAGE_PARSE_MALFORMED,
        format!(
            "{} coverage report is malformed: {message}",
            format.as_str()
        ),
        COVERAGE_REMEDIATION,
    )
}

/// Dispatches to the parser for `format`.
pub fn parse_coverage(format: CoverageFormat, input: &str) -> Result<CoverageReport, DomainError> {
    match format {
        CoverageFormat::Lcov => parse_lcov(input),
        CoverageFormat::CoveragePyJson => parse_coverage_py_json(input),
        CoverageFormat::CoberturaXml => parse_cobertura_xml(input),
    }
}

/// Parses an LCOV tracefile.
///
/// Only line coverage (`DA:<line>,<hit>`) inside an `SF:`…`end_of_record`
/// record is retained; a record with a positive hit count marks its line
/// executed. Fail-closed: a `DA` before any `SF`, a truncated record with no
/// `end_of_record`, an unparsable line/hit field, or an empty tracefile all
/// refuse with [`ASTRO_COVERAGE_PARSE_MALFORMED`].
pub fn parse_lcov(input: &str) -> Result<CoverageReport, DomainError> {
    const FORMAT: CoverageFormat = CoverageFormat::Lcov;
    let mut executed: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut current: Option<(String, BTreeSet<u32>)> = None;
    for (index, raw) in input.lines().enumerate() {
        let line = raw.trim_end();
        if let Some(rest) = line.strip_prefix("SF:") {
            if current.is_some() {
                return Err(coverage_malformed(
                    FORMAT,
                    format!("line {}: new SF: before end_of_record", index + 1),
                ));
            }
            let file = rest.trim();
            if file.is_empty() {
                return Err(coverage_malformed(
                    FORMAT,
                    format!("line {}: SF: with empty file path", index + 1),
                ));
            }
            current = Some((normalize_path(file), BTreeSet::new()));
        } else if let Some(rest) = line.strip_prefix("DA:") {
            let Some((_, lines)) = current.as_mut() else {
                return Err(coverage_malformed(
                    FORMAT,
                    format!("line {}: DA: outside any SF: record", index + 1),
                ));
            };
            let mut fields = rest.split(',');
            let line_field = fields.next().unwrap_or_default();
            let hit_field = fields.next().ok_or_else(|| {
                coverage_malformed(FORMAT, format!("line {}: DA: missing hit count", index + 1))
            })?;
            let line_no: u32 = line_field.trim().parse().map_err(|error| {
                coverage_malformed(
                    FORMAT,
                    format!("line {}: invalid DA line number: {error}", index + 1),
                )
            })?;
            let hits: u64 = hit_field.trim().parse().map_err(|error| {
                coverage_malformed(
                    FORMAT,
                    format!("line {}: invalid DA hit count: {error}", index + 1),
                )
            })?;
            if line_no == 0 {
                return Err(coverage_malformed(
                    FORMAT,
                    format!(
                        "line {}: DA line number 0; source lines are one-based",
                        index + 1
                    ),
                ));
            }
            if hits > 0 {
                lines.insert(line_no);
            }
        } else if line == "end_of_record" {
            let Some((file, lines)) = current.take() else {
                return Err(coverage_malformed(
                    FORMAT,
                    format!(
                        "line {}: end_of_record without an open SF: record",
                        index + 1
                    ),
                ));
            };
            executed.entry(file).or_default().extend(lines);
        }
        // Every other directive (TN, FN, FNDA, FNF, FNH, LF, LH, BRDA, BRF,
        // BRH, VER, and blanks) is not line coverage and is ignored.
    }
    if current.is_some() {
        return Err(coverage_malformed(
            FORMAT,
            "truncated tracefile: final SF: record has no end_of_record",
        ));
    }
    if executed.is_empty() {
        return Err(coverage_malformed(FORMAT, "no SF: records found"));
    }
    Ok(CoverageReport {
        format: FORMAT,
        executed,
    })
}

/// Parses coverage.py native JSON (`coverage json`).
///
/// The `files` object maps each source path to a record whose `executed_lines`
/// array lists the executed one-based line numbers. Fail-closed on a missing
/// `files` object, a non-object file record, a missing/non-array
/// `executed_lines`, a non-integer or zero line number, or an empty report.
pub fn parse_coverage_py_json(input: &str) -> Result<CoverageReport, DomainError> {
    const FORMAT: CoverageFormat = CoverageFormat::CoveragePyJson;
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|error| coverage_malformed(FORMAT, error))?;
    let files = value
        .get("files")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| coverage_malformed(FORMAT, "missing files object"))?;
    let mut executed: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for (path, record) in files {
        let record = record.as_object().ok_or_else(|| {
            coverage_malformed(FORMAT, format!("file {path:?} record is not an object"))
        })?;
        let lines = record
            .get("executed_lines")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                coverage_malformed(
                    FORMAT,
                    format!("file {path:?} missing executed_lines array"),
                )
            })?;
        let mut set = BTreeSet::new();
        for line in lines {
            let number = line.as_u64().ok_or_else(|| {
                coverage_malformed(
                    FORMAT,
                    format!("file {path:?} executed_lines has a non-integer entry"),
                )
            })?;
            if number == 0 || number > u64::from(u32::MAX) {
                return Err(coverage_malformed(
                    FORMAT,
                    format!("file {path:?} executed line number {number} is out of range"),
                ));
            }
            set.insert(number as u32);
        }
        executed.insert(normalize_path(path), set);
    }
    if executed.is_empty() {
        return Err(coverage_malformed(FORMAT, "files object is empty"));
    }
    Ok(CoverageReport {
        format: FORMAT,
        executed,
    })
}

/// Parses a Cobertura XML coverage report (`coverage xml`, gcovr, JaCoCo→cobertura).
///
/// Each `<class filename="…">` scopes a set of `<line number="N" hits="H"/>`
/// entries; a positive `hits` marks line `N` executed for that file. Fail-closed
/// on malformed XML, a `<line>` before any `<class>`, a missing/invalid
/// `number`/`hits` attribute, a zero line number, or a report with no lines.
pub fn parse_cobertura_xml(input: &str) -> Result<CoverageReport, DomainError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;
    const FORMAT: CoverageFormat = CoverageFormat::CoberturaXml;

    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);
    let mut executed: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut current_file: Option<String> = None;
    let mut saw_line = false;

    fn attr(
        reader: &Reader<&[u8]>,
        element: &quick_xml::events::BytesStart<'_>,
        key: &[u8],
    ) -> Result<Option<String>, DomainError> {
        for attribute in element.attributes() {
            let attribute = attribute.map_err(|error| coverage_malformed(FORMAT, error))?;
            if attribute.key.as_ref() == key {
                let value = attribute
                    .decode_and_unescape_value(reader.decoder())
                    .map_err(|error| coverage_malformed(FORMAT, error))?
                    .into_owned();
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn handle_class(
        reader: &Reader<&[u8]>,
        element: &quick_xml::events::BytesStart<'_>,
        current_file: &mut Option<String>,
    ) -> Result<(), DomainError> {
        let filename = attr(reader, element, b"filename")?
            .ok_or_else(|| coverage_malformed(FORMAT, "<class> without a filename attribute"))?;
        if filename.trim().is_empty() {
            return Err(coverage_malformed(FORMAT, "<class> with empty filename"));
        }
        *current_file = Some(normalize_path(filename.trim()));
        Ok(())
    }

    fn handle_line(
        reader: &Reader<&[u8]>,
        element: &quick_xml::events::BytesStart<'_>,
        current_file: &Option<String>,
        executed: &mut BTreeMap<String, BTreeSet<u32>>,
        saw_line: &mut bool,
    ) -> Result<(), DomainError> {
        let Some(file) = current_file else {
            return Err(coverage_malformed(FORMAT, "<line> outside any <class>"));
        };
        *saw_line = true;
        let number = attr(reader, element, b"number")?
            .ok_or_else(|| coverage_malformed(FORMAT, "<line> without a number attribute"))?;
        let hits = attr(reader, element, b"hits")?
            .ok_or_else(|| coverage_malformed(FORMAT, "<line> without a hits attribute"))?;
        let number: u32 = number
            .trim()
            .parse()
            .map_err(|error| coverage_malformed(FORMAT, format!("invalid line number: {error}")))?;
        let hits: u64 = hits
            .trim()
            .parse()
            .map_err(|error| coverage_malformed(FORMAT, format!("invalid hits: {error}")))?;
        if number == 0 {
            return Err(coverage_malformed(
                FORMAT,
                "<line> number 0; source lines are one-based",
            ));
        }
        if hits > 0 {
            executed.entry(file.clone()).or_default().insert(number);
        }
        Ok(())
    }

    loop {
        match reader.read_event() {
            Err(error) => return Err(coverage_malformed(FORMAT, error)),
            Ok(Event::Eof) => break,
            Ok(Event::Start(element)) | Ok(Event::Empty(element)) => {
                match element.name().as_ref() {
                    b"class" => handle_class(&reader, &element, &mut current_file)?,
                    b"line" => handle_line(
                        &reader,
                        &element,
                        &current_file,
                        &mut executed,
                        &mut saw_line,
                    )?,
                    _ => {}
                }
            }
            Ok(Event::End(element)) => {
                if element.name().as_ref() == b"class" {
                    current_file = None;
                }
            }
            Ok(_) => {}
        }
    }
    if !saw_line {
        return Err(coverage_malformed(FORMAT, "no <line> elements found"));
    }
    // A report whose lines all have zero hits is valid but grounds no symbols;
    // `executed` is then empty, which is represented honestly rather than as an
    // error (the report parsed fine, it just recorded no execution).
    Ok(CoverageReport {
        format: FORMAT,
        executed,
    })
}
