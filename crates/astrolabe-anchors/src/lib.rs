#![forbid(unsafe_code)]

//! Grounded outcome anchors for ASTROLABE (blueprint 06 §2.1, 15 §2).
//!
//! Anchors are never synthetic: every anchor comes from a parsed real-world
//! outcome (test run, agent task, review, incident, manual label) with an
//! enforced source-prefix convention and the Poly `grounding.rs` confidence
//! invariants verbatim — a resolved (`ci:*`) source is certain and must carry
//! confidence exactly `1.0`; a provisional (`local:*`) source is an estimate
//! and must carry a finite confidence in the open interval `(0, 1)`. Anything
//! else refuses fail-closed.
//!
//! Storage pairs every mutation with its ledger record: anchor rows land in
//! the `anchors` CF keyed `(CxId, AnchorKind)` and the same atomic group
//! commit appends a `Grounding` ledger entry whose payload is hash-only
//! (counts plus the blake3 of a canonical anchor dump — no raw code, no test
//! source text, no secrets).

use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::{ColumnFamily, anchor_key};
use calyx_aster::vault::AsterVault;
use calyx_core::{
    Anchor, AnchorKind, AnchorValue, CalyxError, Clock, CxId, LedgerRef, Ts, VaultStore,
};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::{Deserialize, Serialize};

mod parsers;

pub use parsers::{
    ASTRO_ANCHOR_PARSE_MALFORMED, ParsedTestCase, ParsedTestRun, TestReportFormat, TestStatus,
    parse_cargo_test_json, parse_go_test_json, parse_junit_xml, parse_pytest_verbose,
    parse_test_report, parse_vitest_json,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

/// Stable failure code for an unrecognized outcome source prefix.
pub const ASTRO_ANCHOR_SOURCE_PREFIX_INVALID: &str = "ASTRO_ANCHOR_SOURCE_PREFIX_INVALID";
/// Stable failure code for a confidence that contradicts its source origin.
pub const ASTRO_ANCHOR_CONFIDENCE_INVALID: &str = "ASTRO_ANCHOR_CONFIDENCE_INVALID";
/// Stable failure code for a re-post that conflicts with a stored anchor.
pub const ASTRO_ANCHOR_DEDUP_CONFLICT: &str = "ASTRO_ANCHOR_DEDUP_CONFLICT";
/// Stable failure code for corrupt or inconsistent persisted anchor rows.
pub const ASTRO_ANCHOR_ROW_CORRUPT: &str = "ASTRO_ANCHOR_ROW_CORRUPT";
/// Stable failure code when the paired ledger entry cannot be recovered.
pub const ASTRO_ANCHOR_LEDGER_MISSING: &str = "ASTRO_ANCHOR_LEDGER_MISSING";

/// Row schema tag for persisted anchor rows.
pub const SCHEMA_ANCHOR_ROW: &str = "astrolabe-anchor-row-v1";
/// Ledger payload schema for one anchor ingest group commit.
pub const ANCHOR_LEDGER_SCHEMA: &str = "astrolabe.anchor_outcome.v1";

/// Confidence carried by every resolved (`ci:*`) anchor — certainty, verbatim
/// from the Poly grounding invariant.
pub const RESOLVED_SOURCE_CONFIDENCE: f32 = 1.0;
/// Default confidence for provisional (`local:*`) anchors (04 §4 convention).
pub const DEFAULT_PROVISIONAL_CONFIDENCE: f32 = 0.8;

const ANCHOR_REMEDIATION: &str =
    "regenerate anchors with astrolabe_anchors::ingest_outcome_anchors from a fresh outcome";
const SOURCE_REMEDIATION: &str = "use 'ci:<provider>:<run_id>' for CI-resolved outcomes or 'local:<context>' for uncommitted local runs";

/// Outcome kinds accepted by `anchor_outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// A parsed test run (the built-in parser path).
    TestRun,
    /// An AI-agent task outcome.
    AgentTask,
    /// A human review verdict.
    Review,
    /// An incident attribution.
    Incident,
    /// A manual label.
    ManualLabel,
}

impl OutcomeKind {
    /// Stable wire name (`test_run`, `agent_task`, ...).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestRun => "test_run",
            Self::AgentTask => "agent_task",
            Self::Review => "review",
            Self::Incident => "incident",
            Self::ManualLabel => "manual_label",
        }
    }
}

/// Grounding origin classified from the source prefix (04 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceOrigin {
    /// `ci:<provider>:<run_id>` — a resolved, certain outcome (Trusted 1.0).
    Resolved,
    /// `local:<context>` — an uncommitted local run (Provisional, default 0.8).
    Provisional,
}

/// Classifies an outcome source string by its enforced prefix convention.
///
/// Refuses fail-closed on anything that is not a well-formed `ci:` or
/// `local:` source — an anchor with an unknown origin would be an unlabeled
/// claim.
pub fn classify_source(source: &str) -> Result<SourceOrigin, astrolabe_domain::DomainError> {
    if let Some(rest) = source.strip_prefix("ci:") {
        let mut parts = rest.splitn(2, ':');
        let provider = parts.next().unwrap_or_default();
        let run_id = parts.next().unwrap_or_default();
        if provider.is_empty() || run_id.is_empty() {
            return Err(astrolabe_domain::DomainError::new(
                ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
                format!("ci source {source:?} must be 'ci:<provider>:<run_id>'"),
                SOURCE_REMEDIATION,
            ));
        }
        return Ok(SourceOrigin::Resolved);
    }
    if let Some(rest) = source.strip_prefix("local:") {
        if rest.trim().is_empty() {
            return Err(astrolabe_domain::DomainError::new(
                ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
                format!("local source {source:?} must name its context"),
                SOURCE_REMEDIATION,
            ));
        }
        return Ok(SourceOrigin::Provisional);
    }
    Err(astrolabe_domain::DomainError::new(
        ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
        format!("outcome source {source:?} has no recognized origin prefix"),
        SOURCE_REMEDIATION,
    ))
}

/// Validates (or defaults) an outcome confidence against its source origin —
/// the Poly `grounding.rs` invariants verbatim.
///
/// - Resolved: certain; `None` defaults to `1.0`, anything other than exactly
///   `1.0` refuses.
/// - Provisional: an estimate; `None` defaults to
///   [`DEFAULT_PROVISIONAL_CONFIDENCE`], anything not finite in the open
///   interval `(0, 1)` refuses.
pub fn validate_confidence(
    origin: SourceOrigin,
    confidence: Option<f32>,
) -> Result<f32, astrolabe_domain::DomainError> {
    match origin {
        SourceOrigin::Resolved => match confidence {
            None => Ok(RESOLVED_SOURCE_CONFIDENCE),
            Some(value) if value == RESOLVED_SOURCE_CONFIDENCE => Ok(value),
            Some(value) => Err(astrolabe_domain::DomainError::new(
                ASTRO_ANCHOR_CONFIDENCE_INVALID,
                format!("resolved (ci:) outcome carries confidence {value}, must be exactly 1.0"),
                "resolved outcomes are certain; omit confidence or pass exactly 1.0",
            )),
        },
        SourceOrigin::Provisional => match confidence {
            None => Ok(DEFAULT_PROVISIONAL_CONFIDENCE),
            Some(value) if value.is_finite() && value > 0.0 && value < 1.0 => Ok(value),
            Some(value) => Err(astrolabe_domain::DomainError::new(
                ASTRO_ANCHOR_CONFIDENCE_INVALID,
                format!(
                    "provisional (local:) outcome carries confidence {value}, must be finite in the open interval (0, 1)"
                ),
                "provisional outcomes are estimates; pass a confidence strictly between 0 and 1",
            )),
        },
    }
}

/// One anchor-bearing subject in an outcome request.
#[derive(Debug, Clone, PartialEq)]
pub struct OutcomeSubject {
    /// Subject identifier the caller resolves to a CxId (test case id,
    /// symbol qualified name, ...).
    pub subject_id: String,
    /// Outcome axis for this subject.
    pub anchor_kind: AnchorKind,
    /// Grounded value on the axis.
    pub value: AnchorValue,
}

/// One validated `anchor_outcome` request.
#[derive(Debug, Clone, PartialEq)]
pub struct OutcomeAnchorRequest {
    /// Outcome kind.
    pub kind: OutcomeKind,
    /// Enforced-prefix source (`ci:<provider>:<run_id>` or `local:<context>`).
    pub source: String,
    /// Server-observed timestamp for every anchor in the request.
    pub observed_at: Ts,
    /// Validated confidence (see [`validate_confidence`]).
    pub confidence: f32,
    /// Anchor-bearing subjects.
    pub subjects: Vec<OutcomeSubject>,
}

impl OutcomeAnchorRequest {
    /// Builds a validated request, enforcing source and confidence
    /// conventions fail-closed.
    pub fn new(
        kind: OutcomeKind,
        source: impl Into<String>,
        observed_at: Ts,
        confidence: Option<f32>,
        subjects: Vec<OutcomeSubject>,
    ) -> Result<Self, astrolabe_domain::DomainError> {
        let source = source.into();
        let origin = classify_source(&source)?;
        let confidence = validate_confidence(origin, confidence)?;
        Ok(Self {
            kind,
            source,
            observed_at,
            confidence,
            subjects,
        })
    }

    /// Builds a `test_run` request from a parsed report: every anchor-bearing
    /// case becomes a `TestPass` boolean anchor; skipped cases ground nothing.
    pub fn from_test_run(
        run: &ParsedTestRun,
        source: impl Into<String>,
        observed_at: Ts,
        confidence: Option<f32>,
    ) -> Result<Self, astrolabe_domain::DomainError> {
        let subjects = run
            .cases
            .iter()
            .filter(|case| case.status.grounds_anchor())
            .map(|case| OutcomeSubject {
                subject_id: case.case_id.clone(),
                anchor_kind: AnchorKind::TestPass,
                value: AnchorValue::Bool(case.status.passed()),
            })
            .collect();
        Self::new(
            OutcomeKind::TestRun,
            source,
            observed_at,
            confidence,
            subjects,
        )
    }
}

/// Persisted `anchors` CF row: every anchor observed for one `(CxId, kind)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorRowV1 {
    /// Always [`SCHEMA_ANCHOR_ROW`].
    pub schema: String,
    /// Subject constellation.
    pub cx_id: CxId,
    /// Outcome axis (also part of the CF key).
    pub kind: AnchorKind,
    /// Observed anchors, deduplicated on `(source, observed_at)`.
    pub anchors: Vec<Anchor>,
}

/// Report for one anchor ingest group commit.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorIngestReport {
    /// New anchors written in this commit.
    pub anchors_written: usize,
    /// Identical re-posts deduplicated on `(cx_id, kind, source, observed_at)`.
    pub anchors_deduplicated: usize,
    /// Subjects with no CxId mapping — explicitly accounted, never silent.
    pub unmapped_subjects: Vec<String>,
    /// CF rows written or rewritten.
    pub rows_written: usize,
    /// Lowercase-hex blake3 of the canonical anchor dump, as ledgered.
    pub anchor_dump_hash: String,
    /// Grounding ledger entry paired with this mutation batch.
    pub ledger_ref: LedgerRef,
}

/// Ingests a validated outcome request into the `anchors` CF.
///
/// `cx_ids` maps subject ids to constellation ids; unmapped subjects are
/// returned in the report (counted skip, no silent fallback). Idempotency:
/// an anchor identical on `(cx_id, kind, source, observed_at, value,
/// confidence)` is deduplicated; the same dedup key with a *different* value
/// or confidence refuses fail-closed (`ASTRO_ANCHOR_DEDUP_CONFLICT`) — an
/// outcome cannot be silently rewritten. The batch and its hash-only
/// `Grounding` ledger entry land in one atomic group commit.
pub fn ingest_outcome_anchors<C>(
    vault: &AsterVault<C>,
    request: &OutcomeAnchorRequest,
    cx_ids: &BTreeMap<String, CxId>,
    actor: impl Into<String>,
) -> calyx_core::Result<AnchorIngestReport>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = BTreeMap::<Vec<u8>, AnchorRowV1>::new();
    let mut dirty_keys = BTreeSet::<Vec<u8>>::new();
    let mut anchors_written = 0usize;
    let mut anchors_deduplicated = 0usize;
    let mut unmapped_subjects = Vec::new();

    for subject in &request.subjects {
        let Some(&cx_id) = cx_ids.get(&subject.subject_id) else {
            unmapped_subjects.push(subject.subject_id.clone());
            continue;
        };
        let key = anchor_key(cx_id, &subject.anchor_kind);
        if !rows.contains_key(&key) {
            let row = match vault.read_cf_at(snapshot, ColumnFamily::Anchors, &key)? {
                Some(bytes) => decode_anchor_row(&key, &bytes, cx_id, &subject.anchor_kind)?,
                None => AnchorRowV1 {
                    schema: SCHEMA_ANCHOR_ROW.to_string(),
                    cx_id,
                    kind: subject.anchor_kind.clone(),
                    anchors: Vec::new(),
                },
            };
            rows.insert(key.clone(), row);
        }
        let row = rows.get_mut(&key).expect("row just inserted");
        let incoming = Anchor {
            kind: subject.anchor_kind.clone(),
            value: subject.value.clone(),
            source: request.source.clone(),
            observed_at: request.observed_at,
            confidence: request.confidence,
        };
        match row.anchors.iter().find(|existing| {
            existing.source == incoming.source && existing.observed_at == incoming.observed_at
        }) {
            Some(existing)
                if existing.value == incoming.value
                    && existing.confidence.to_bits() == incoming.confidence.to_bits() =>
            {
                anchors_deduplicated += 1;
            }
            Some(existing) => {
                return Err(CalyxError {
                    code: ASTRO_ANCHOR_DEDUP_CONFLICT,
                    message: format!(
                        "anchor for cx {cx_id} kind {:?} source {:?} observed_at {} already \
                         holds {:?} (confidence {}); refusing conflicting re-post",
                        subject.anchor_kind,
                        request.source,
                        request.observed_at,
                        existing.value,
                        existing.confidence
                    ),
                    remediation: "post the corrected outcome under a new observed_at or source",
                });
            }
            None => {
                row.anchors.push(incoming);
                dirty_keys.insert(key);
                anchors_written += 1;
            }
        }
    }

    let dump = anchor_dump_bytes(rows.values());
    let anchor_dump_hash = hex_lower(blake3::hash(&dump).as_bytes());

    let mut batch = Vec::new();
    for key in &dirty_keys {
        let row = rows.get(key).expect("dirty key has a row");
        let value = serde_json::to_vec(row)
            .map_err(|error| anchor_corrupt(format!("encode anchor row: {error}")))?;
        batch.push((ColumnFamily::Anchors, key.clone(), value));
    }
    let rows_written = batch.len();

    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": ANCHOR_LEDGER_SCHEMA,
        "outcome_kind": request.kind.as_str(),
        "source": request.source,
        "observed_at": request.observed_at,
        "anchors_written": anchors_written,
        "anchors_deduplicated": anchors_deduplicated,
        "unmapped_subject_count": unmapped_subjects.len(),
        "rows_written": rows_written,
        "anchor_dump_hash": anchor_dump_hash,
    }))
    .map_err(|error| anchor_corrupt(format!("encode anchor ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;

    let subject =
        SubjectId::Query(format!("astrolabe-anchor-outcome:{anchor_dump_hash}").into_bytes());
    let actor = ActorId::Service(actor.into());
    let ledger_ref = if batch.is_empty() {
        vault.append_ledger_entry(EntryKind::Grounding, subject, payload, actor)?
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Grounding,
            subject,
            payload,
            actor,
        )?;
        ledger_ref_at_commit(vault, commit_seq)?
    };
    vault.flush()?;

    Ok(AnchorIngestReport {
        anchors_written,
        anchors_deduplicated,
        unmapped_subjects,
        rows_written,
        anchor_dump_hash,
        ledger_ref,
    })
}

/// One decoded, key-verified anchor row read back from the `anchors` CF.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedAnchorRow {
    /// Full CF key the row was stored under.
    pub key: Vec<u8>,
    /// Decoded row.
    pub row: AnchorRowV1,
}

/// Reads back and key-verifies every persisted anchor row.
pub fn read_anchor_rows<C>(vault: &AsterVault<C>) -> calyx_core::Result<Vec<PersistedAnchorRow>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Anchors)? {
        let row: AnchorRowV1 = serde_json::from_slice(&bytes).map_err(|error| {
            anchor_corrupt(format!("decode anchor row {}: {error}", hex_lower(&key)))
        })?;
        if row.schema != SCHEMA_ANCHOR_ROW {
            return Err(anchor_corrupt(format!(
                "anchor row {} carries schema {:?}",
                hex_lower(&key),
                row.schema
            )));
        }
        if key != anchor_key(row.cx_id, &row.kind) {
            return Err(anchor_corrupt(format!(
                "anchor row key {} does not match its decoded (cx_id, kind)",
                hex_lower(&key)
            )));
        }
        if row.anchors.iter().any(|anchor| anchor.kind != row.kind) {
            return Err(anchor_corrupt(format!(
                "anchor row {} holds anchors of a foreign kind",
                hex_lower(&key)
            )));
        }
        rows.push(PersistedAnchorRow { key, row });
    }
    Ok(rows)
}

/// Canonical byte dump of anchor rows for ledger content hashing (one line
/// per anchor: cx, kind, source, observed_at, confidence bits, value JSON).
pub fn anchor_dump_bytes<'a>(rows: impl Iterator<Item = &'a AnchorRowV1>) -> Vec<u8> {
    let mut lines = Vec::new();
    for row in rows {
        for anchor in &row.anchors {
            lines.push(format!(
                "{}\t{}\t{}\t{}\t{:08x}\t{}",
                row.cx_id,
                serde_json::to_string(&anchor.kind).unwrap_or_default(),
                anchor.source,
                anchor.observed_at,
                anchor.confidence.to_bits(),
                serde_json::to_string(&anchor.value).unwrap_or_default(),
            ));
        }
    }
    lines.sort();
    let mut out = String::new();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out.into_bytes()
}

fn decode_anchor_row(
    key: &[u8],
    bytes: &[u8],
    cx_id: CxId,
    kind: &AnchorKind,
) -> calyx_core::Result<AnchorRowV1> {
    let row: AnchorRowV1 = serde_json::from_slice(bytes).map_err(|error| {
        anchor_corrupt(format!("decode anchor row {}: {error}", hex_lower(key)))
    })?;
    if row.schema != SCHEMA_ANCHOR_ROW || row.cx_id != cx_id || row.kind != *kind {
        return Err(anchor_corrupt(format!(
            "anchor row {} disagrees with its (cx_id, kind) key",
            hex_lower(key)
        )));
    }
    Ok(row)
}

fn ledger_ref_at_commit<C>(vault: &AsterVault<C>, commit_seq: u64) -> calyx_core::Result<LedgerRef>
where
    C: Clock,
{
    let (key, value) = vault
        .scan_cf_at(commit_seq, ColumnFamily::Ledger)?
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0))
        .ok_or_else(|| CalyxError {
            code: ASTRO_ANCHOR_LEDGER_MISSING,
            message: "Ledger CF empty at anchor ingest commit snapshot".to_string(),
            remediation: "verify vault Ledger CF integrity, then re-run the anchor ingest",
        })?;
    let key_seq = calyx_aster::ledger_view::parse_aster_ledger_seq(&key)?;
    let entry = decode_ledger(&value)?;
    if entry.seq != key_seq {
        return Err(CalyxError {
            code: ASTRO_ANCHOR_LEDGER_MISSING,
            message: format!(
                "Ledger CF key seq {key_seq} does not match encoded entry seq {}",
                entry.seq
            ),
            remediation: "verify vault Ledger CF integrity, then re-run the anchor ingest",
        });
    }
    Ok(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    })
}

fn anchor_corrupt(message: String) -> CalyxError {
    CalyxError {
        code: ASTRO_ANCHOR_ROW_CORRUPT,
        message,
        remediation: ANCHOR_REMEDIATION,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use calyx_aster::vault::VaultOptions;
    use calyx_core::{SystemClock, VaultId};

    static NEXT_VAULT_DIR: AtomicU64 = AtomicU64::new(0);
    const ANCHOR_TEST_SALT: &[u8] = b"astrolabe-anchors-fsv";

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn parser_goldens_produce_exact_case_sets_for_all_five_formats() {
        let junit = parse_junit_xml(include_str!("../tests/fixtures/junit_basic.xml"))
            .expect("junit golden");
        assert_eq!(
            cases(&junit),
            vec![
                ("com.demo.CalcTest::adds", TestStatus::Passed),
                ("com.demo.CalcTest::subtracts", TestStatus::Failed),
                ("com.demo.CalcTest::divides", TestStatus::Errored),
                ("com.demo.IoTest::reads", TestStatus::Skipped),
                ("com.demo.IoTest::writes", TestStatus::Passed),
            ]
        );
        assert_eq!(junit.totals(), (2, 1, 1, 1));

        let cargo = parse_cargo_test_json(include_str!("../tests/fixtures/cargo_test.jsonl"))
            .expect("cargo golden");
        assert_eq!(
            cases(&cargo),
            vec![
                ("demo::adds", TestStatus::Passed),
                ("demo::subtracts", TestStatus::Failed),
                ("demo::slow_io", TestStatus::Skipped),
            ]
        );

        let pytest = parse_pytest_verbose(include_str!("../tests/fixtures/pytest_verbose.txt"))
            .expect("pytest golden");
        assert_eq!(
            cases(&pytest),
            vec![
                ("tests/test_calc.py::test_adds", TestStatus::Passed),
                ("tests/test_calc.py::test_subtracts", TestStatus::Failed),
                ("tests/test_io.py::test_reads", TestStatus::Skipped),
                ("tests/test_io.py::test_writes", TestStatus::Passed),
            ]
        );

        let go =
            parse_go_test_json(include_str!("../tests/fixtures/go_test.jsonl")).expect("go golden");
        assert_eq!(
            cases(&go),
            vec![
                ("example.com/demo::TestAdds", TestStatus::Passed),
                ("example.com/demo::TestSubtracts", TestStatus::Failed),
                ("example.com/demo::TestSlowIO", TestStatus::Skipped),
            ]
        );

        let vitest = parse_vitest_json(include_str!("../tests/fixtures/vitest.json"))
            .expect("vitest golden");
        assert_eq!(
            cases(&vitest),
            vec![
                ("src/calc.test.ts::calc > adds", TestStatus::Passed),
                ("src/calc.test.ts::calc > subtracts", TestStatus::Failed),
                ("src/io.test.ts::io > reads", TestStatus::Skipped),
            ]
        );
    }

    #[test]
    fn malformed_or_partial_reports_refuse_fail_closed_with_no_partial_ingest() {
        for (format, input) in [
            (
                TestReportFormat::JunitXml,
                include_str!("../tests/fixtures/junit_truncated.xml"),
            ),
            (
                TestReportFormat::CargoTestJson,
                include_str!("../tests/fixtures/cargo_test_partial.jsonl"),
            ),
            (
                TestReportFormat::PytestVerbose,
                include_str!("../tests/fixtures/pytest_partial.txt"),
            ),
            (
                TestReportFormat::GoTestJson,
                "{\"Action\":\"run\"}\nnot json\n",
            ),
            (
                TestReportFormat::VitestJson,
                include_str!("../tests/fixtures/vitest_mismatch.json"),
            ),
        ] {
            let error = parse_test_report(format, input)
                .expect_err(&format!("{} must refuse", format.as_str()));
            assert_eq!(error.code(), ASTRO_ANCHOR_PARSE_MALFORMED, "{format:?}");
            // Result is Err: by construction no partial case set escapes.
        }
        // Empty input refuses for every format.
        for format in [
            TestReportFormat::JunitXml,
            TestReportFormat::CargoTestJson,
            TestReportFormat::PytestVerbose,
            TestReportFormat::GoTestJson,
            TestReportFormat::VitestJson,
        ] {
            assert!(parse_test_report(format, "").is_err(), "{format:?} empty");
        }
    }

    #[test]
    fn source_prefix_and_confidence_bounds_enforced_verbatim() {
        // Source-prefix conventions (04 §4).
        assert_eq!(
            classify_source("ci:github:12345").expect("ci source"),
            SourceOrigin::Resolved
        );
        assert_eq!(
            classify_source("local:worktree-run").expect("local source"),
            SourceOrigin::Provisional
        );
        for bad in ["ci:github", "ci::42", "local:", "manual", ""] {
            assert_eq!(
                classify_source(bad).expect_err("refuse").code(),
                ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
                "{bad:?}"
            );
        }

        // Resolved: confidence must be exactly 1.0.
        assert_eq!(
            validate_confidence(SourceOrigin::Resolved, None).expect("default"),
            1.0
        );
        assert_eq!(
            validate_confidence(SourceOrigin::Resolved, Some(1.0)).expect("exact"),
            1.0
        );
        for bad in [0.99f32, 0.0, 1.01, f32::NAN] {
            assert_eq!(
                validate_confidence(SourceOrigin::Resolved, Some(bad))
                    .expect_err("refuse")
                    .code(),
                ASTRO_ANCHOR_CONFIDENCE_INVALID,
                "{bad}"
            );
        }

        // Provisional: finite in the open interval (0, 1).
        assert_eq!(
            validate_confidence(SourceOrigin::Provisional, None).expect("default"),
            DEFAULT_PROVISIONAL_CONFIDENCE
        );
        assert_eq!(
            validate_confidence(SourceOrigin::Provisional, Some(0.5)).expect("estimate"),
            0.5
        );
        for bad in [0.0f32, 1.0, -0.2, 1.5, f32::NAN, f32::INFINITY] {
            assert_eq!(
                validate_confidence(SourceOrigin::Provisional, Some(bad))
                    .expect_err("refuse")
                    .code(),
                ASTRO_ANCHOR_CONFIDENCE_INVALID,
                "{bad}"
            );
        }
    }

    #[test]
    fn idempotent_repost_writes_zero_anchors_and_cf_bytes_are_unchanged() {
        let run = parse_junit_xml(include_str!("../tests/fixtures/junit_basic.xml"))
            .expect("junit golden");
        let request =
            OutcomeAnchorRequest::from_test_run(&run, "ci:github:777", 1_786_400_000, None)
                .expect("test_run request");
        let cx_ids = fixture_cx_ids(&request);
        let (dir, vault) = anchor_vault("idempotency");

        let first = ingest_outcome_anchors(&vault, &request, &cx_ids, "astrolabe-anchors-test")
            .expect("first ingest");
        assert_eq!(first.anchors_written, 4); // skipped case grounds nothing
        assert_eq!(first.anchors_deduplicated, 0);
        let before = raw_anchor_bytes(&vault);
        assert_eq!(before.len(), 4);

        let second = ingest_outcome_anchors(&vault, &request, &cx_ids, "astrolabe-anchors-test")
            .expect("idempotent re-post");
        assert_eq!(second.anchors_written, 0);
        assert_eq!(second.anchors_deduplicated, 4);
        assert_eq!(second.rows_written, 0);
        let after = raw_anchor_bytes(&vault);
        assert_eq!(
            before, after,
            "CF rows must be byte-identical after re-post"
        );

        // Conflicting re-post (same dedup key, different value) refuses.
        let mut conflicting = request.clone();
        for subject in &mut conflicting.subjects {
            subject.value = AnchorValue::Bool(!matches!(subject.value, AnchorValue::Bool(true)));
        }
        let error = ingest_outcome_anchors(&vault, &conflicting, &cx_ids, "astrolabe-anchors-test")
            .expect_err("conflicting re-post refused");
        assert_eq!(error.code, ASTRO_ANCHOR_DEDUP_CONFLICT);
        assert_eq!(
            raw_anchor_bytes(&vault),
            after,
            "refusal leaves rows untouched"
        );
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn fsv_pairing_sampled_anchor_rows_match_their_grounding_ledger_entry() {
        let run = parse_cargo_test_json(include_str!("../tests/fixtures/cargo_test.jsonl"))
            .expect("cargo golden");
        let request =
            OutcomeAnchorRequest::from_test_run(&run, "ci:buildkite:42", 1_786_500_000, None)
                .expect("test_run request");
        let cx_ids = fixture_cx_ids(&request);
        let (dir, vault) = anchor_vault("fsv-pairing");
        let report = ingest_outcome_anchors(&vault, &request, &cx_ids, "astrolabe-anchors-test")
            .expect("ingest");
        assert_eq!(report.anchors_written, 2);
        drop(vault);

        // Reopen: everything below reads persisted bytes.
        let reopened = open_anchor_vault(&dir);
        let rows = read_anchor_rows(&reopened).expect("read anchor rows");
        assert_eq!(rows.len(), 2);
        for persisted in &rows {
            assert_eq!(persisted.row.kind, AnchorKind::TestPass);
            assert_eq!(persisted.row.anchors.len(), 1);
            let anchor = &persisted.row.anchors[0];
            assert_eq!(anchor.source, "ci:buildkite:42");
            assert_eq!(anchor.observed_at, 1_786_500_000);
            assert_eq!(anchor.confidence.to_bits(), 1.0f32.to_bits());
        }
        let pass_values = rows
            .iter()
            .map(|persisted| persisted.row.anchors[0].value.clone())
            .collect::<Vec<_>>();
        assert!(pass_values.contains(&AnchorValue::Bool(true)));
        assert!(pass_values.contains(&AnchorValue::Bool(false)));

        // Paired ledger entry: same-commit Grounding entry, hash-only payload
        // matching the recomputed anchor dump.
        let ledger_bytes = reopened
            .read_cf_at(
                reopened.snapshot(),
                ColumnFamily::Ledger,
                &calyx_aster::cf::ledger_key(report.ledger_ref.seq),
            )
            .expect("read ledger row")
            .expect("ledger row present");
        let entry = decode_ledger(&ledger_bytes).expect("decode ledger entry");
        assert_eq!(entry.kind, EntryKind::Grounding);
        assert_eq!(entry.entry_hash, report.ledger_ref.hash);
        let payload: serde_json::Value =
            serde_json::from_slice(&entry.payload).expect("payload json");
        assert_eq!(payload["schema"], ANCHOR_LEDGER_SCHEMA);
        assert_eq!(payload["outcome_kind"], "test_run");
        let recomputed = anchor_dump_bytes(rows.iter().map(|persisted| &persisted.row));
        assert_eq!(
            payload["anchor_dump_hash"],
            hex_lower(blake3::hash(&recomputed).as_bytes())
        );
        // Hash-only payload: no test case ids leak into the ledger.
        let payload_text = String::from_utf8(entry.payload.clone()).expect("utf8 payload");
        assert!(!payload_text.contains("demo::adds"));
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn secret_shaped_source_refused_at_the_ledger_writer_with_no_rows_written() {
        let secret = format!("ci:leaky:{}", "a1b2c3d4".repeat(8));
        let request = OutcomeAnchorRequest::new(
            OutcomeKind::TestRun,
            secret,
            1_786_600_000,
            None,
            vec![OutcomeSubject {
                subject_id: "demo::adds".to_string(),
                anchor_kind: AnchorKind::TestPass,
                value: AnchorValue::Bool(true),
            }],
        )
        .expect("prefix-valid request");
        let cx_ids = fixture_cx_ids(&request);
        let (dir, vault) = anchor_vault("redaction");

        let error = ingest_outcome_anchors(&vault, &request, &cx_ids, "astrolabe-anchors-test")
            .expect_err("secret-shaped source must refuse at the ledger writer");
        assert_eq!(
            error.code, "CALYX_LEDGER_SECRET_IN_PAYLOAD",
            "unexpected refusal: {} ({})",
            error.message, error.code
        );
        assert!(
            raw_anchor_bytes(&vault).is_empty(),
            "refusal must leave zero anchor rows"
        );
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unmapped_subjects_are_accounted_never_silent() {
        let request = OutcomeAnchorRequest::new(
            OutcomeKind::ManualLabel,
            "local:triage-session",
            1_786_700_000,
            Some(0.6),
            vec![
                OutcomeSubject {
                    subject_id: "known.symbol".to_string(),
                    anchor_kind: AnchorKind::Label("security_sensitive".to_string()),
                    value: AnchorValue::Bool(true),
                },
                OutcomeSubject {
                    subject_id: "unknown.symbol".to_string(),
                    anchor_kind: AnchorKind::Label("security_sensitive".to_string()),
                    value: AnchorValue::Bool(true),
                },
            ],
        )
        .expect("manual label request");
        let cx_ids = BTreeMap::from([("known.symbol".to_string(), cx(9))]);
        let (dir, vault) = anchor_vault("unmapped");

        let report = ingest_outcome_anchors(&vault, &request, &cx_ids, "astrolabe-anchors-test")
            .expect("ingest with unmapped subject");
        assert_eq!(report.anchors_written, 1);
        assert_eq!(report.unmapped_subjects, vec!["unknown.symbol".to_string()]);
        let rows = read_anchor_rows(&vault).expect("read rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].row.anchors[0].confidence, 0.6);
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    fn cases(run: &ParsedTestRun) -> Vec<(&str, TestStatus)> {
        run.cases
            .iter()
            .map(|case| (case.case_id.as_str(), case.status))
            .collect()
    }

    fn fixture_cx_ids(request: &OutcomeAnchorRequest) -> BTreeMap<String, CxId> {
        request
            .subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| (subject.subject_id.clone(), cx(index as u8 + 1)))
            .collect()
    }

    fn raw_anchor_bytes(vault: &AsterVault<SystemClock>) -> Vec<(Vec<u8>, Vec<u8>)> {
        vault
            .scan_cf_at(vault.snapshot(), ColumnFamily::Anchors)
            .expect("scan anchors CF")
    }

    fn anchor_vault(name: &str) -> (PathBuf, AsterVault<SystemClock>) {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-anchors-{name}-{}-{}",
            std::process::id(),
            NEXT_VAULT_DIR.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test vault dir");
        let vault = open_anchor_vault(&dir);
        (dir, vault)
    }

    fn open_anchor_vault(dir: &Path) -> AsterVault<SystemClock> {
        AsterVault::new_durable(
            dir,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>().unwrap(),
            ANCHOR_TEST_SALT.to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable anchor vault")
    }

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }
}
