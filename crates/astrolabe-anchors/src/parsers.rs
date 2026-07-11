//! Built-in test-result parsers for `anchor_outcome` (blueprint 06 §2.1).
//!
//! Five drop-in formats: JUnit XML, `cargo test` libtest JSON, pytest verbose
//! terminal output, `go test -json`, and the vitest/jest JSON reporter. Every
//! parser is fail-closed: malformed or partial input refuses with
//! [`ASTRO_ANCHOR_PARSE_MALFORMED`] and never yields a partial case set —
//! grounding is mandatory, so a report that cannot be trusted end-to-end
//! produces no anchors at all.

use astrolabe_domain::DomainError;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::Value;

/// Stable failure code for malformed or partial test-report input.
pub const ASTRO_ANCHOR_PARSE_MALFORMED: &str = "ASTRO_ANCHOR_PARSE_MALFORMED";

const PARSE_REMEDIATION: &str = "re-export the full test report from the runner and re-post the complete file; partial ingest is refused";

/// Supported test-report formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestReportFormat {
    /// JUnit / Surefire style `<testsuite>` XML.
    JunitXml,
    /// Rust libtest `--format json` line stream.
    CargoTestJson,
    /// pytest `-v` terminal output.
    PytestVerbose,
    /// `go test -json` event stream.
    GoTestJson,
    /// vitest `--reporter=json` (jest-compatible) document.
    VitestJson,
}

impl TestReportFormat {
    /// Stable wire name for reports and errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JunitXml => "junit_xml",
            Self::CargoTestJson => "cargo_test_json",
            Self::PytestVerbose => "pytest_verbose",
            Self::GoTestJson => "go_test_json",
            Self::VitestJson => "vitest_json",
        }
    }
}

/// Outcome of one test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// The case passed.
    Passed,
    /// The case asserted and failed.
    Failed,
    /// The case errored outside its assertions.
    Errored,
    /// The case was skipped/ignored (no outcome anchor is grounded from it).
    Skipped,
}

impl TestStatus {
    /// Whether this status grounds a boolean outcome anchor.
    pub const fn grounds_anchor(self) -> bool {
        !matches!(self, Self::Skipped)
    }

    /// The grounded boolean outcome for anchor-bearing statuses.
    pub const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// One parsed test case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTestCase {
    /// Runner-native case identifier (suite/class-qualified where available).
    pub case_id: String,
    /// Case outcome.
    pub status: TestStatus,
}

/// One fully parsed test report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTestRun {
    /// Source format.
    pub format: TestReportFormat,
    /// Every case in the report, in report order.
    pub cases: Vec<ParsedTestCase>,
}

impl ParsedTestRun {
    /// Counts cases by status: (passed, failed, errored, skipped).
    pub fn totals(&self) -> (usize, usize, usize, usize) {
        let mut totals = (0, 0, 0, 0);
        for case in &self.cases {
            match case.status {
                TestStatus::Passed => totals.0 += 1,
                TestStatus::Failed => totals.1 += 1,
                TestStatus::Errored => totals.2 += 1,
                TestStatus::Skipped => totals.3 += 1,
            }
        }
        totals
    }
}

fn malformed(format: TestReportFormat, message: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        ASTRO_ANCHOR_PARSE_MALFORMED,
        format!("{} report is malformed: {message}", format.as_str()),
        PARSE_REMEDIATION,
    )
}

/// Parses a JUnit/Surefire-style XML report.
pub fn parse_junit_xml(input: &str) -> Result<ParsedTestRun, DomainError> {
    const FORMAT: TestReportFormat = TestReportFormat::JunitXml;
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut cases = Vec::new();
    let mut open_case: Option<(String, TestStatus)> = None;

    fn testcase_id(
        reader: &Reader<&[u8]>,
        element: &quick_xml::events::BytesStart<'_>,
    ) -> Result<String, DomainError> {
        let mut name = None;
        let mut classname = None;
        for attribute in element.attributes() {
            let attribute =
                attribute.map_err(|error| malformed(TestReportFormat::JunitXml, error))?;
            let value = attribute
                .decode_and_unescape_value(reader.decoder())
                .map_err(|error| malformed(TestReportFormat::JunitXml, error))?
                .into_owned();
            match attribute.key.as_ref() {
                b"name" => name = Some(value),
                b"classname" => classname = Some(value),
                _ => {}
            }
        }
        let Some(name) = name else {
            return Err(malformed(
                TestReportFormat::JunitXml,
                "<testcase> without a name attribute",
            ));
        };
        Ok(match classname {
            Some(classname) if !classname.is_empty() => format!("{classname}::{name}"),
            _ => name,
        })
    }

    loop {
        match reader.read_event() {
            Err(error) => return Err(malformed(FORMAT, error)),
            Ok(Event::Eof) => break,
            Ok(Event::Start(element)) => match element.name().as_ref() {
                b"testcase" => {
                    if open_case.is_some() {
                        return Err(malformed(FORMAT, "nested <testcase> elements"));
                    }
                    open_case = Some((testcase_id(&reader, &element)?, TestStatus::Passed));
                }
                b"failure" => {
                    if let Some((_, status)) = open_case.as_mut() {
                        *status = TestStatus::Failed;
                    }
                }
                b"error" => {
                    if let Some((_, status)) = open_case.as_mut() {
                        *status = TestStatus::Errored;
                    }
                }
                b"skipped" => {
                    if let Some((_, status)) = open_case.as_mut() {
                        *status = TestStatus::Skipped;
                    }
                }
                _ => {}
            },
            Ok(Event::Empty(element)) => match element.name().as_ref() {
                // A self-closing <testcase/> has no child outcome element:
                // it passed.
                b"testcase" => {
                    if open_case.is_some() {
                        return Err(malformed(FORMAT, "nested <testcase> elements"));
                    }
                    cases.push(ParsedTestCase {
                        case_id: testcase_id(&reader, &element)?,
                        status: TestStatus::Passed,
                    });
                }
                b"failure" => {
                    if let Some((_, status)) = open_case.as_mut() {
                        *status = TestStatus::Failed;
                    }
                }
                b"error" => {
                    if let Some((_, status)) = open_case.as_mut() {
                        *status = TestStatus::Errored;
                    }
                }
                b"skipped" => {
                    if let Some((_, status)) = open_case.as_mut() {
                        *status = TestStatus::Skipped;
                    }
                }
                _ => {}
            },
            Ok(Event::End(element)) => {
                if element.name().as_ref() == b"testcase" {
                    let Some((case_id, status)) = open_case.take() else {
                        return Err(malformed(FORMAT, "</testcase> without an open case"));
                    };
                    cases.push(ParsedTestCase { case_id, status });
                }
            }
            Ok(_) => {}
        }
    }
    if open_case.is_some() {
        return Err(malformed(FORMAT, "truncated report: unclosed <testcase>"));
    }
    if cases.is_empty() {
        return Err(malformed(FORMAT, "no <testcase> elements found"));
    }
    Ok(ParsedTestRun {
        format: FORMAT,
        cases,
    })
}

/// Parses a Rust libtest `--format json` line stream (`cargo test`).
pub fn parse_cargo_test_json(input: &str) -> Result<ParsedTestRun, DomainError> {
    const FORMAT: TestReportFormat = TestReportFormat::CargoTestJson;
    let mut cases = Vec::new();
    let mut suite_reported: Option<(u64, u64, u64)> = None;
    for (line_number, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| malformed(FORMAT, format!("line {}: {error}", line_number + 1)))?;
        match value.get("type").and_then(Value::as_str) {
            Some("suite") => {
                if let Some(event) = value.get("event").and_then(Value::as_str)
                    && matches!(event, "ok" | "failed")
                {
                    suite_reported = Some((
                        value.get("passed").and_then(Value::as_u64).unwrap_or(0),
                        value.get("failed").and_then(Value::as_u64).unwrap_or(0),
                        value.get("ignored").and_then(Value::as_u64).unwrap_or(0),
                    ));
                }
            }
            Some("test") => {
                let name = value
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        malformed(
                            FORMAT,
                            format!("line {}: test without name", line_number + 1),
                        )
                    })?
                    .to_string();
                let status = match value.get("event").and_then(Value::as_str) {
                    Some("started") => continue,
                    Some("ok") => TestStatus::Passed,
                    Some("failed") => TestStatus::Failed,
                    Some("ignored") => TestStatus::Skipped,
                    other => {
                        return Err(malformed(
                            FORMAT,
                            format!("line {}: unknown test event {other:?}", line_number + 1),
                        ));
                    }
                };
                cases.push(ParsedTestCase {
                    case_id: name,
                    status,
                });
            }
            Some("bench") => {}
            other => {
                return Err(malformed(
                    FORMAT,
                    format!("line {}: unknown record type {other:?}", line_number + 1),
                ));
            }
        }
    }
    if cases.is_empty() {
        return Err(malformed(FORMAT, "no test events found"));
    }
    let Some((passed, failed, ignored)) = suite_reported else {
        return Err(malformed(
            FORMAT,
            "truncated report: no terminal suite summary event",
        ));
    };
    let (got_passed, got_failed, _errored, got_skipped) = ParsedTestRun {
        format: FORMAT,
        cases: cases.clone(),
    }
    .totals();
    if (got_passed as u64, got_failed as u64, got_skipped as u64) != (passed, failed, ignored) {
        return Err(malformed(
            FORMAT,
            format!(
                "suite summary ({passed} passed / {failed} failed / {ignored} ignored) \
                 disagrees with test events ({got_passed}/{got_failed}/{got_skipped})"
            ),
        ));
    }
    Ok(ParsedTestRun {
        format: FORMAT,
        cases,
    })
}

/// Parses pytest `-v` terminal output.
pub fn parse_pytest_verbose(input: &str) -> Result<ParsedTestRun, DomainError> {
    const FORMAT: TestReportFormat = TestReportFormat::PytestVerbose;
    let mut cases = Vec::new();
    let mut summary: Option<(u64, u64, u64, u64)> = None;
    for line in input.lines() {
        let line = line.trim_end();
        if let Some((case_id, status)) = pytest_case_line(line) {
            cases.push(ParsedTestCase { case_id, status });
            continue;
        }
        if line.starts_with("==") && line.ends_with("==") && line.contains(" in ") {
            summary = Some((
                pytest_summary_count(line, "passed"),
                pytest_summary_count(line, "failed"),
                pytest_summary_count(line, "error").max(pytest_summary_count(line, "errors")),
                pytest_summary_count(line, "skipped"),
            ));
        }
    }
    if cases.is_empty() {
        return Err(malformed(FORMAT, "no verbose test-case result lines found"));
    }
    let Some((passed, failed, errored, skipped)) = summary else {
        return Err(malformed(
            FORMAT,
            "truncated report: final '== ... in ... ==' summary line missing",
        ));
    };
    let (got_passed, got_failed, got_errored, got_skipped) = ParsedTestRun {
        format: FORMAT,
        cases: cases.clone(),
    }
    .totals();
    if (
        got_passed as u64,
        got_failed as u64,
        got_errored as u64,
        got_skipped as u64,
    ) != (passed, failed, errored, skipped)
    {
        return Err(malformed(
            FORMAT,
            format!(
                "summary line ({passed} passed / {failed} failed / {errored} error / \
                 {skipped} skipped) disagrees with case lines \
                 ({got_passed}/{got_failed}/{got_errored}/{got_skipped})"
            ),
        ));
    }
    Ok(ParsedTestRun {
        format: FORMAT,
        cases,
    })
}

fn pytest_case_line(line: &str) -> Option<(String, TestStatus)> {
    let mut parts = line.split_whitespace();
    let case_id = parts.next()?;
    if !case_id.contains("::") {
        return None;
    }
    let status = match parts.next()? {
        "PASSED" | "XPASS" => TestStatus::Passed,
        "FAILED" | "XFAIL" => TestStatus::Failed,
        "ERROR" => TestStatus::Errored,
        "SKIPPED" => TestStatus::Skipped,
        _ => return None,
    };
    Some((case_id.to_string(), status))
}

fn pytest_summary_count(line: &str, label: &str) -> u64 {
    let trimmed = line.trim_matches(['=', ' ']);
    for part in trimmed.split(',') {
        let mut words = part.split_whitespace();
        if let (Some(count), Some(word)) = (words.next(), words.next())
            && word == label
        {
            return count.parse().unwrap_or(0);
        }
    }
    0
}

/// Parses a `go test -json` event stream.
pub fn parse_go_test_json(input: &str) -> Result<ParsedTestRun, DomainError> {
    const FORMAT: TestReportFormat = TestReportFormat::GoTestJson;
    let mut cases = Vec::new();
    for (line_number, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| malformed(FORMAT, format!("line {}: {error}", line_number + 1)))?;
        let action = value.get("Action").and_then(Value::as_str).ok_or_else(|| {
            malformed(
                FORMAT,
                format!("line {}: event without Action", line_number + 1),
            )
        })?;
        let Some(test) = value.get("Test").and_then(Value::as_str) else {
            continue; // package-level event
        };
        let status = match action {
            "pass" => TestStatus::Passed,
            "fail" => TestStatus::Failed,
            "skip" => TestStatus::Skipped,
            "run" | "pause" | "cont" | "output" | "start" | "bench" => continue,
            other => {
                return Err(malformed(
                    FORMAT,
                    format!("line {}: unknown action {other:?}", line_number + 1),
                ));
            }
        };
        let package = value
            .get("Package")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let case_id = if package.is_empty() {
            test.to_string()
        } else {
            format!("{package}::{test}")
        };
        cases.push(ParsedTestCase { case_id, status });
    }
    if cases.is_empty() {
        return Err(malformed(FORMAT, "no per-test pass/fail/skip events found"));
    }
    Ok(ParsedTestRun {
        format: FORMAT,
        cases,
    })
}

/// Parses a vitest `--reporter=json` (jest-compatible) document.
pub fn parse_vitest_json(input: &str) -> Result<ParsedTestRun, DomainError> {
    const FORMAT: TestReportFormat = TestReportFormat::VitestJson;
    let value: Value = serde_json::from_str(input).map_err(|error| malformed(FORMAT, error))?;
    let file_results = value
        .get("testResults")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(FORMAT, "missing testResults array"))?;
    let mut cases = Vec::new();
    for file_result in file_results {
        let file = file_result
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let assertions = file_result
            .get("assertionResults")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed(FORMAT, "file result missing assertionResults"))?;
        for assertion in assertions {
            let title = assertion
                .get("fullName")
                .or_else(|| assertion.get("title"))
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(FORMAT, "assertion without fullName/title"))?;
            let status = match assertion.get("status").and_then(Value::as_str) {
                Some("passed") => TestStatus::Passed,
                Some("failed") => TestStatus::Failed,
                Some("skipped") | Some("pending") | Some("todo") => TestStatus::Skipped,
                other => {
                    return Err(malformed(
                        FORMAT,
                        format!("assertion {title:?} has unknown status {other:?}"),
                    ));
                }
            };
            let case_id = if file.is_empty() {
                title.to_string()
            } else {
                format!("{file}::{title}")
            };
            cases.push(ParsedTestCase { case_id, status });
        }
    }
    if cases.is_empty() {
        return Err(malformed(FORMAT, "no assertion results found"));
    }
    let (got_passed, got_failed, _errored, _skipped) = ParsedTestRun {
        format: FORMAT,
        cases: cases.clone(),
    }
    .totals();
    for (field, got) in [
        ("numPassedTests", got_passed as u64),
        ("numFailedTests", got_failed as u64),
    ] {
        let declared = value
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed(FORMAT, format!("missing {field} total")))?;
        if declared != got {
            return Err(malformed(
                FORMAT,
                format!("{field} = {declared} disagrees with assertion results ({got})"),
            ));
        }
    }
    Ok(ParsedTestRun {
        format: FORMAT,
        cases,
    })
}

/// Dispatches to the parser for `format`.
pub fn parse_test_report(
    format: TestReportFormat,
    input: &str,
) -> Result<ParsedTestRun, DomainError> {
    match format {
        TestReportFormat::JunitXml => parse_junit_xml(input),
        TestReportFormat::CargoTestJson => parse_cargo_test_json(input),
        TestReportFormat::PytestVerbose => parse_pytest_verbose(input),
        TestReportFormat::GoTestJson => parse_go_test_json(input),
        TestReportFormat::VitestJson => parse_vitest_json(input),
    }
}
