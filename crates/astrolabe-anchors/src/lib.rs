#![forbid(unsafe_code)]

//! Grounded outcome anchors for ASTROLABE (blueprint 06 §2.1, 15 §2).
//!
//! Anchors are never synthetic: every anchor comes from a parsed real-world
//! outcome (test run, agent task, review, incident, manual label) with an
//! enforced source-prefix catalog and the Poly `grounding.rs` confidence
//! invariants verbatim — resolved sources are Trusted at confidence exactly
//! `1.0`; proxy sources are Provisional with finite confidence in `(0, 1)`.
//! Anything else refuses fail-closed.
//!
//! Storage pairs every mutation with its ledger record: anchor rows land in
//! the `anchors` CF keyed `(CxId, AnchorKind)` and the same atomic group
//! commit appends a `Grounding` ledger entry whose payload is hash-only
//! (counts plus the blake3 of a canonical anchor dump — no raw code, no test
//! source text, no secrets).

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::fsv::FsvAck;
pub use astrolabe_domain::{GroundingKind, SourceClassification, TrustTag};
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, anchor_key};
use calyx_aster::vault::AsterVault;
use calyx_core::{
    Anchor, AnchorKind, AnchorValue, CalyxError, Clock, CxId, LedgerRef, Ts, VaultStore,
};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::{Deserialize, Serialize};

pub mod agent_task;
pub mod archaeology;
pub mod hook;
mod parsers;
pub mod propagation;

pub use hook::{HookOutcome, run_hook_process};

pub use agent_task::{
    AGENT_TASK_PACK_LEDGER_SCHEMA, AGENT_TASK_REWARD_CONFIDENCE,
    ANCHOR_CONTRADICTION_LEDGER_SCHEMA, ANCHOR_PROMOTION_LEDGER_SCHEMA, ASTRO_ANCHOR_CONTRADICTION,
    ASTRO_ANCHOR_PACK_CONFLICT, ASTRO_ANCHOR_PACK_INPUT_INVALID, ASTRO_ANCHOR_PACK_UNKNOWN,
    ASTRO_ANCHOR_PROMOTION_INPUT_INVALID, AgentTaskPackManifestV1, AgentTaskPackReport,
    AnchorContradictionV1, AnchorPromotionReport, AnchorPromotionV1, ContradictionPair,
    PromotedPair, SCHEMA_AGENT_TASK_PACK, SCHEMA_ANCHOR_CONTRADICTION, SCHEMA_ANCHOR_PROMOTION,
    effective_anchor_trust, effective_anchor_trust_map, ingest_agent_task_outcome,
    is_anchor_promoted, promote_on_resolution, read_agent_task_pack, read_agent_task_packs,
    read_anchor_contradictions, read_anchor_promotions, record_agent_task_pack,
    rollup_effective_anchor_trust,
};

pub use parsers::{
    ASTRO_ANCHOR_PARSE_MALFORMED, ParsedTestCase, ParsedTestRun, TestReportFormat, TestStatus,
    parse_cargo_test_json, parse_go_test_json, parse_junit_xml, parse_pytest_verbose,
    parse_test_report, parse_vitest_json,
};
pub use propagation::{
    ASTRO_COVERAGE_PARSE_MALFORMED, ASTRO_PROPAGATION_INPUT_INVALID, CoverageFormat,
    CoverageReport, PROPAGATION_ANCHOR_CONFIDENCE, PROPAGATION_SOURCE_PREFIX, PlannedRequest,
    PropagationInputs, PropagationPlan, PropagationReport, SymbolNode, TestsEdge, TestsFileEdge,
    parse_cobertura_xml, parse_coverage, parse_coverage_py_json, parse_lcov, plan_propagation,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

/// Stable failure code for an unrecognized outcome source prefix.
pub const ASTRO_ANCHOR_SOURCE_PREFIX_INVALID: &str =
    astrolabe_domain::ASTRO_ANCHOR_SOURCE_PREFIX_INVALID;
/// Stable failure code for a confidence that contradicts its source origin.
pub const ASTRO_ANCHOR_CONFIDENCE_INVALID: &str = astrolabe_domain::ASTRO_ANCHOR_CONFIDENCE_INVALID;
/// Stable failure code for a malformed or out-of-range observed-at timestamp.
pub const ASTRO_ANCHOR_TIMESTAMP_INVALID: &str = "ASTRO_ANCHOR_TIMESTAMP_INVALID";
/// Stable failure code for a re-post that conflicts with a stored anchor.
pub const ASTRO_ANCHOR_DEDUP_CONFLICT: &str = "ASTRO_ANCHOR_DEDUP_CONFLICT";
/// Stable failure code for corrupt or inconsistent persisted anchor rows.
pub const ASTRO_ANCHOR_ROW_CORRUPT: &str = "ASTRO_ANCHOR_ROW_CORRUPT";
/// Stable failure code when the paired ledger entry cannot be recovered.
pub const ASTRO_ANCHOR_LEDGER_MISSING: &str = "ASTRO_ANCHOR_LEDGER_MISSING";
/// Stable failure code when a producer tries to reuse a retracted source.
pub const ASTRO_ANCHOR_SOURCE_RETRACTED: &str = "ASTRO_ANCHOR_SOURCE_RETRACTED";

/// Row schema tag for persisted anchor rows.
pub const SCHEMA_ANCHOR_ROW: &str = "astrolabe-anchor-row-v1";
/// Schema for an append-only source retraction record in the KV CF.
pub const SCHEMA_ANCHOR_TOMBSTONE: &str = "astrolabe-anchor-tombstone-v1";
/// Ledger payload schema for one anchor ingest group commit.
pub const ANCHOR_LEDGER_SCHEMA: &str = "astrolabe.anchor_outcome.v1";
/// Ledger payload schema for one append-only source retraction.
pub const ANCHOR_ERASURE_LEDGER_SCHEMA: &str = "astrolabe.anchor_erasure.v1";

const ANCHOR_TOMBSTONE_PREFIX: &[u8] = b"astrolabe:anchor-tombstone:v1:";

/// Confidence carried by every resolved (`ci:*`) anchor — certainty, verbatim
/// from the Poly grounding invariant.
pub const RESOLVED_SOURCE_CONFIDENCE: f32 = astrolabe_domain::RESOLVED_SOURCE_CONFIDENCE;
/// Default confidence for provisional proxy anchors (04 §4 convention).
pub const DEFAULT_PROVISIONAL_CONFIDENCE: f32 = astrolabe_domain::DEFAULT_PROVISIONAL_CONFIDENCE;

const ANCHOR_REMEDIATION: &str =
    "regenerate anchors with astrolabe_anchors::ingest_outcome_anchors from a fresh outcome";

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
    /// A label derived from validated Git history evidence.
    GitArchaeology,
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
            Self::GitArchaeology => "git_archaeology",
        }
    }
}

/// Classifies an outcome source string by the exhaustive prefix catalog.
///
/// Unknown prefixes and empty suffixes refuse: accepting either would create an
/// unlabeled claim. Prefix order is deliberate (`git:revert:`/`git:fix:` are
/// catalog entries; a bare `git:` is not).
pub fn classify_source(
    source: &str,
) -> Result<SourceClassification, astrolabe_domain::DomainError> {
    astrolabe_domain::classify_grounding_source(source)
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
    grounding_kind: GroundingKind,
    confidence: Option<f32>,
) -> Result<f32, astrolabe_domain::DomainError> {
    astrolabe_domain::validate_grounding_confidence(grounding_kind, confidence)
}

/// Aggregate trust is Trusted iff at least one contributor exists and every
/// contributor is Trusted. Empty evidence fails closed to Provisional.
pub fn rollup_trust(tags: impl IntoIterator<Item = TrustTag>) -> TrustTag {
    astrolabe_domain::rollup_trust(tags)
}

/// Returns the catalog trust for one source, refusing unknown prefixes.
pub fn trust_for_source(source: &str) -> Result<TrustTag, astrolabe_domain::DomainError> {
    Ok(classify_source(source)?.trust)
}

/// Rolls up trust across active anchor rows. Empty rows are Provisional.
pub fn rollup_anchor_trust<'a>(
    rows: impl IntoIterator<Item = &'a PersistedAnchorRow>,
) -> Result<TrustTag, astrolabe_domain::DomainError> {
    let mut tags = Vec::new();
    for persisted in rows {
        for anchor in &persisted.row.anchors {
            let classification = classify_source(&anchor.source)?;
            validate_confidence(classification.grounding_kind, Some(anchor.confidence))?;
            tags.push(trust_for_source(&anchor.source)?);
        }
    }
    Ok(rollup_trust(tags))
}

/// Validates a server-observed timestamp for an outcome request.
///
/// A grounded outcome must carry a real wall-clock observation, so epoch `0` is
/// refused fail-closed (`ASTRO_ANCHOR_TIMESTAMP_INVALID`) — a zero `observed_at`
/// is the classic "unset" sentinel and would corrupt the `(cx, kind, source,
/// observed_at)` dedup identity. Every other `u64` is accepted verbatim.
pub fn validate_observed_at(observed_at: Ts) -> Result<Ts, astrolabe_domain::DomainError> {
    if observed_at == 0 {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_ANCHOR_TIMESTAMP_INVALID,
            "observed_at is 0; a grounded outcome requires a real server-observed timestamp",
            "pass the wall-clock epoch (seconds or ms) at which the outcome was observed",
        ));
    }
    Ok(observed_at)
}

/// Parses and validates a caller-supplied `observed_at` timestamp string.
///
/// The `anchor_outcome` MCP tool and its `astrolabe cli anchor_outcome`
/// subcommand funnel the raw timestamp through this one helper so both paths
/// share byte-identical fail-closed behavior: blank, non-numeric, negative, or
/// overflowing input refuses with [`ASTRO_ANCHOR_TIMESTAMP_INVALID`], and `0`
/// refuses via [`validate_observed_at`].
pub fn parse_observed_at(raw: &str) -> Result<Ts, astrolabe_domain::DomainError> {
    let trimmed = raw.trim();
    let parsed = trimmed.parse::<Ts>().map_err(|error| {
        astrolabe_domain::DomainError::new(
            ASTRO_ANCHOR_TIMESTAMP_INVALID,
            format!("observed_at {trimmed:?} is not a non-negative integer timestamp: {error}"),
            "pass observed_at as a non-negative integer epoch (seconds or ms)",
        )
    })?;
    validate_observed_at(parsed)
}

/// Builds a validated `test_run` outcome request from raw tool arguments.
///
/// This is the single request-construction path shared by the `anchor_outcome`
/// MCP tool and its `astrolabe cli anchor_outcome` subcommand: both funnel the
/// same raw `format`, `report_text`, `source`, `observed_at`, and `confidence`
/// through here, so identical inputs yield a byte-identical
/// [`OutcomeAnchorRequest`] on both paths by construction — the structural
/// guarantee behind the dual-path byte-identical-state property. Every stage is
/// fail-closed: unknown format, malformed report, malformed timestamp, or a
/// source/confidence that violates the grounding invariants each refuse with
/// their stable code and no request is produced.
pub fn build_test_run_request(
    source: &str,
    observed_at: &str,
    confidence: Option<f32>,
    format: &str,
    report_text: &str,
) -> Result<OutcomeAnchorRequest, astrolabe_domain::DomainError> {
    let observed_at = parse_observed_at(observed_at)?;
    let format = TestReportFormat::from_wire(format)?;
    let run = parse_test_report(format, report_text)?;
    OutcomeAnchorRequest::from_test_run(&run, source, observed_at, confidence)
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
    /// Enforced catalog source (resolved or proxy prefix).
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
        let classification = classify_source(&source)?;
        let confidence = validate_confidence(classification.grounding_kind, confidence)?;
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
    /// All anchors in one request share one catalog source and trust tag.
    pub trust: TrustTag,
    /// Unforgeable full-readback witness when this call changed anchor rows.
    /// An idempotent ledger-only replay carries labeled absence (`None`).
    pub fsv: Option<FsvAck>,
}

/// Append-only retraction of every anchor attributed to one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorTombstoneV1 {
    pub schema: String,
    pub source: String,
    pub retracted_at: Ts,
}

/// Report for one source-erasure mutation.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorErasureReport {
    pub anchors_retracted: usize,
    pub tombstone_written: bool,
    pub ledger_ref: LedgerRef,
    pub fsv: Option<FsvAck>,
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
    let request_trust = classify_source(&request.source)
        .map_err(|error| CalyxError {
            code: error.code(),
            message: error.message().to_string(),
            remediation: error.remediation(),
        })?
        .trust;
    if read_anchor_tombstones(vault)?
        .iter()
        .any(|tombstone| tombstone.source == request.source)
    {
        return Err(CalyxError {
            code: ASTRO_ANCHOR_SOURCE_RETRACTED,
            message: format!(
                "anchor source {:?} was retracted and cannot be reused",
                request.source
            ),
            remediation: "use a new catalog source identifying the replacement evidence",
        });
    }
    // Anchor rows retain their catalog source for provenance. Preserve the
    // existing fail-closed secret screen before hashing that source in the
    // ledger payload; full Git object IDs are the one structurally validated
    // long-token catalog form and are identifiers, not secret material.
    if !is_full_git_oid_source(&request.source) {
        let source_probe = serde_json::to_vec(&serde_json::json!({
            "source": request.source,
        }))
        .map_err(|error| anchor_corrupt(format!("encode anchor source probe: {error}")))?;
        RedactionPolicy::check_payload(&source_probe)?;
    }
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
        "source_hash": hex_lower(blake3::hash(request.source.as_bytes()).as_bytes()),
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
    let mut fsv_plan = VaultMutationPlan::new(
        "ingest_outcome_anchors",
        EntryKind::Grounding,
        &actor,
        &subject,
    );
    for (cf, key, value) in &batch {
        fsv_plan.push_content(*cf, key.clone(), value);
    }
    let (ledger_ref, commit_seq) = if batch.is_empty() {
        (
            vault.append_ledger_entry(EntryKind::Grounding, subject, payload, actor)?,
            None,
        )
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Grounding,
            subject,
            payload,
            actor,
        )?;
        (ledger_ref_at_commit(vault, commit_seq)?, Some(commit_seq))
    };
    vault.flush()?;
    let fsv = commit_seq
        .map(|commit_seq| fsv_plan.verify_committed(vault, commit_seq))
        .transpose()?;

    Ok(AnchorIngestReport {
        anchors_written,
        anchors_deduplicated,
        unmapped_subjects,
        rows_written,
        anchor_dump_hash,
        ledger_ref,
        trust: request_trust,
        fsv,
    })
}

fn is_full_git_oid_source(source: &str) -> bool {
    ["git:fix:", "git:revert:"].iter().any(|prefix| {
        source.strip_prefix(prefix).is_some_and(|oid| {
            matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
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
    let tombstoned_sources = read_anchor_tombstones(vault)?
        .into_iter()
        .map(|tombstone| tombstone.source)
        .collect::<BTreeSet<_>>();
    let mut rows = read_all_anchor_rows(vault)?;
    for persisted in &mut rows {
        persisted
            .row
            .anchors
            .retain(|anchor| !tombstoned_sources.contains(&anchor.source));
    }
    rows.retain(|persisted| !persisted.row.anchors.is_empty());
    Ok(rows)
}

/// Reads original anchor rows without applying retractions. This exists for
/// physical append-only FSV; serving/query paths use [`read_anchor_rows`].
pub fn read_all_anchor_rows<C>(vault: &AsterVault<C>) -> calyx_core::Result<Vec<PersistedAnchorRow>>
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
        for anchor in &row.anchors {
            let classification = classify_source(&anchor.source).map_err(|error| CalyxError {
                code: error.code(),
                message: error.message().to_string(),
                remediation: error.remediation(),
            })?;
            validate_confidence(classification.grounding_kind, Some(anchor.confidence)).map_err(
                |error| CalyxError {
                    code: error.code(),
                    message: error.message().to_string(),
                    remediation: error.remediation(),
                },
            )?;
        }
        rows.push(PersistedAnchorRow { key, row });
    }
    Ok(rows)
}

/// Reads and key-verifies every persisted append-only retraction.
pub fn read_anchor_tombstones<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<AnchorTombstoneV1>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut tombstones = Vec::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if !key.starts_with(ANCHOR_TOMBSTONE_PREFIX) {
            continue;
        }
        let tombstone: AnchorTombstoneV1 = serde_json::from_slice(&bytes).map_err(|error| {
            anchor_corrupt(format!(
                "decode anchor tombstone {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if tombstone.schema != SCHEMA_ANCHOR_TOMBSTONE
            || key != anchor_tombstone_key(&tombstone.source)
        {
            return Err(anchor_corrupt(format!(
                "anchor tombstone {} disagrees with its source key",
                hex_lower(&key)
            )));
        }
        tombstones.push(tombstone);
    }
    tombstones.sort_by(|left, right| left.source.cmp(&right.source));
    Ok(tombstones)
}

/// Retracts every anchor from `source` by appending a tombstone and paired
/// Grounding ledger entry. Original anchor rows are never rewritten.
pub fn erase_anchors_by_source<C>(
    vault: &AsterVault<C>,
    source: &str,
    retracted_at: Ts,
    actor: impl Into<String>,
) -> calyx_core::Result<AnchorErasureReport>
where
    C: Clock,
{
    classify_source(source).map_err(|error| CalyxError {
        code: error.code(),
        message: error.message().to_string(),
        remediation: error.remediation(),
    })?;
    validate_observed_at(retracted_at).map_err(|error| CalyxError {
        code: error.code(),
        message: error.message().to_string(),
        remediation: error.remediation(),
    })?;

    let anchors_retracted = read_all_anchor_rows(vault)?
        .iter()
        .flat_map(|persisted| &persisted.row.anchors)
        .filter(|anchor| anchor.source == source)
        .count();
    let key = anchor_tombstone_key(source);
    let tombstone = AnchorTombstoneV1 {
        schema: SCHEMA_ANCHOR_TOMBSTONE.to_string(),
        source: source.to_string(),
        retracted_at,
    };
    let value = serde_json::to_vec(&tombstone)
        .map_err(|error| anchor_corrupt(format!("encode anchor tombstone: {error}")))?;
    let already_present = vault
        .read_cf_at(vault.snapshot(), ColumnFamily::Kv, &key)?
        .is_some();
    let tombstone_written = anchors_retracted > 0 && !already_present;

    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": ANCHOR_ERASURE_LEDGER_SCHEMA,
        "source": source,
        "retracted_at": retracted_at,
        "anchors_retracted": anchors_retracted,
        "tombstone_written": tombstone_written,
    }))
    .map_err(|error| anchor_corrupt(format!("encode anchor erasure ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;
    let subject = SubjectId::Query(format!("astrolabe-anchor-erasure:{source}").into_bytes());
    let actor = ActorId::Service(actor.into());
    let mut fsv_plan = VaultMutationPlan::new(
        "erase_anchors_by_source",
        EntryKind::Grounding,
        &actor,
        &subject,
    );
    let (ledger_ref, fsv) = if tombstone_written {
        fsv_plan.push_content(ColumnFamily::Kv, key.clone(), &value);
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            vec![(ColumnFamily::Kv, key, value)],
            EntryKind::Grounding,
            subject,
            payload,
            actor,
        )?;
        vault.flush()?;
        (
            ledger_ref_at_commit(vault, commit_seq)?,
            Some(fsv_plan.verify_committed(vault, commit_seq)?),
        )
    } else {
        let ledger_ref =
            vault.append_ledger_entry(EntryKind::Grounding, subject, payload, actor)?;
        vault.flush()?;
        (ledger_ref, None)
    };
    Ok(AnchorErasureReport {
        anchors_retracted,
        tombstone_written,
        ledger_ref,
        fsv,
    })
}

fn anchor_tombstone_key(source: &str) -> Vec<u8> {
    let mut key = ANCHOR_TOMBSTONE_PREFIX.to_vec();
    key.extend_from_slice(blake3::hash(source.as_bytes()).as_bytes());
    key
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

pub(crate) fn ledger_ref_at_commit<C>(
    vault: &AsterVault<C>,
    commit_seq: u64,
) -> calyx_core::Result<LedgerRef>
where
    C: Clock,
{
    let (key, value) = calyx_aster::ledger_view::newest_pairable_ledger(
        vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?,
    )?
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

pub(crate) fn anchor_corrupt(message: String) -> CalyxError {
    CalyxError {
        code: ASTRO_ANCHOR_ROW_CORRUPT,
        message,
        remediation: ANCHOR_REMEDIATION,
    }
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
