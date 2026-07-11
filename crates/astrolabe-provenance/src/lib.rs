#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const GET_PROVENANCE_SCHEMA: &str = "astrolabe.get_provenance.v1";
pub const INTER_AGENT_TRUST_SCHEMA: &str = "astrolabe.inter_agent_trust.v1";
pub const ASTRO_PROVENANCE_UNKNOWN_MODE: &str = "ASTRO_PROVENANCE_UNKNOWN_MODE";
pub const ASTRO_PROVENANCE_NOT_FOUND: &str = "ASTRO_PROVENANCE_NOT_FOUND";
pub const ASTRO_PROVENANCE_MANIFEST_TAMPERED: &str = "ASTRO_PROVENANCE_MANIFEST_TAMPERED";
pub const REPRODUCE_DRIFT_EXCEEDED: &str = "REPRODUCE_DRIFT_EXCEEDED";
pub const ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT: &str = "ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT";

/// Warning code emitted when a `verify_chain` report carries a broken ledger chain.
pub const PROVENANCE_WARN_CHAIN_BROKEN: &str = "chain_broken";
/// Warning code emitted when a `verify_chain` report carries a corrupt ledger chain.
pub const PROVENANCE_WARN_CHAIN_CORRUPT: &str = "chain_corrupt";
/// Warning code emitted when a lineage/answer/reproduce artifact predates the ledger head.
pub const PROVENANCE_WARN_STALE: &str = "stale";

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ProvenanceMode {
    Lineage,
    AnswerTrace,
    VerifyChain,
    Reproduce,
}

impl ProvenanceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lineage => "lineage",
            Self::AnswerTrace => "answer_trace",
            Self::VerifyChain => "verify_chain",
            Self::Reproduce => "reproduce",
        }
    }
}

impl std::str::FromStr for ProvenanceMode {
    type Err = astrolabe_domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lineage" => Ok(Self::Lineage),
            "answer_trace" => Ok(Self::AnswerTrace),
            "verify_chain" => Ok(Self::VerifyChain),
            "reproduce" => Ok(Self::Reproduce),
            _ => Err(astrolabe_domain::DomainError::new(
                ASTRO_PROVENANCE_UNKNOWN_MODE,
                format!("unknown get_provenance mode {value}"),
                "use one of lineage, answer_trace, verify_chain, or reproduce",
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvenanceQuery {
    pub mode: String,
    pub subject_id: Option<String>,
}

impl ProvenanceQuery {
    pub fn new(mode: impl Into<String>, subject_id: Option<&str>) -> Self {
        Self {
            mode: mode.into(),
            subject_id: subject_id.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LedgerPointer {
    pub seq: u64,
    pub chain_hash: String,
}

impl LedgerPointer {
    pub fn new(seq: u64, chain_hash: impl Into<String>) -> Self {
        Self {
            seq,
            chain_hash: chain_hash.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Freshness {
    pub seq: u64,
    pub stale_by: Option<String>,
}

impl Freshness {
    /// Freshness of an artifact that is current as of `seq` (no staleness gap).
    pub fn fresh(seq: u64) -> Self {
        Self {
            seq,
            stale_by: None,
        }
    }

    /// Evaluates the freshness of an artifact computed as of `as_of_seq` against the
    /// current ledger `head_seq`.
    ///
    /// When the artifact predates the head, the exact gap is recorded as a measured,
    /// human-readable `stale_by` label so a consumer can observe a stale provenance
    /// answer instead of the unconditional fresh claim the previous `fresh(head)`
    /// default produced. When the artifact is at or ahead of the head it is fresh.
    pub fn evaluate(as_of_seq: u64, head_seq: u64) -> Self {
        if as_of_seq >= head_seq {
            Self {
                seq: as_of_seq,
                stale_by: None,
            }
        } else {
            let behind = head_seq - as_of_seq;
            Self {
                seq: as_of_seq,
                stale_by: Some(format!(
                    "{behind} ledger entries behind head seq {head_seq}"
                )),
            }
        }
    }

    /// Returns true when this freshness carries a measured staleness gap.
    pub const fn is_stale(&self) -> bool {
        self.stale_by.is_some()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvenanceStore {
    pub vault_fingerprint: String,
    pub ledger_head: LedgerPointer,
    pub chain: ChainVerification,
    pub symbols: BTreeMap<String, SymbolLineage>,
    pub answers: BTreeMap<String, AnswerTrace>,
    pub reproductions: BTreeMap<String, ReproduceRecord>,
    pub manifests: BTreeMap<String, PackManifest>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SymbolLineage {
    pub symbol_id: String,
    pub versions: Vec<LineageEvent>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LineageEvent {
    pub kind: String,
    pub ledger: LedgerPointer,
    pub summary: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AnswerTrace {
    pub answer_id: String,
    pub kernel_entry: Option<LedgerPointer>,
    pub hops: Vec<AnswerHop>,
    pub fusion_weights_ref: Option<LedgerPointer>,
    pub guard_verdict_ref: Option<LedgerPointer>,
    pub freshness: Freshness,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AnswerHop {
    pub from_symbol: String,
    pub to_symbol: String,
    pub ledger: LedgerPointer,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChainVerification {
    pub status: ChainStatus,
    pub checked_from: u64,
    pub checked_to: u64,
    pub provenance: LedgerPointer,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChainStatus {
    Intact,
    Broken { seq: u64 },
    Corrupt { seq: u64, reason: String },
}

impl ChainStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Intact => "intact",
            Self::Broken { .. } => "broken",
            Self::Corrupt { .. } => "corrupt",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReproduceRecord {
    pub answer_id: String,
    pub recorded_digest: String,
    pub current_digest: String,
    pub drift_microunits: u64,
    pub drift_bound_microunits: u64,
    pub ledger: LedgerPointer,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PackManifest {
    pub pack_id: String,
    pub ledger_ref: LedgerPointer,
    pub vault_fingerprint: String,
    pub member_hash: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvenanceResponse {
    pub schema: &'static str,
    pub mode: ProvenanceMode,
    pub trust: &'static str,
    pub freshness: Freshness,
    pub provenance: LedgerPointer,
    pub warnings: Vec<ProvenanceWarning>,
    pub payload: ProvenancePayload,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProvenancePayload {
    Lineage(SymbolLineage),
    AnswerTrace(AnswerTrace),
    VerifyChain(ChainVerification),
    Reproduce(ReproduceReport),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvenanceWarning {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReproduceReport {
    pub answer_id: String,
    pub bit_exact: bool,
    pub drift_microunits: u64,
    pub drift_bound_microunits: u64,
    pub recorded_digest: String,
    pub current_digest: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InterAgentTrustReport {
    pub schema: &'static str,
    pub pack_id: String,
    pub ledger_ref: LedgerPointer,
    pub vault_fingerprint: String,
    pub member_hash: String,
    pub verified_checks: Vec<&'static str>,
    pub freshness: Freshness,
    pub trust: &'static str,
    pub provenance: LedgerPointer,
}

pub fn get_provenance(
    store: &ProvenanceStore,
    query: &ProvenanceQuery,
) -> astrolabe_domain::Result<ProvenanceResponse> {
    let mode = query.mode.parse::<ProvenanceMode>()?;
    match mode {
        ProvenanceMode::Lineage => {
            let subject_id = required_subject(query, mode)?;
            let lineage = store.symbols.get(subject_id).cloned().ok_or_else(|| {
                not_found_error(
                    "symbol lineage",
                    subject_id,
                    "index or import the symbol first",
                )
            })?;
            let provenance = lineage
                .versions
                .last()
                .map(|event| event.ledger.clone())
                .unwrap_or_else(|| store.ledger_head.clone());
            Ok(response(
                mode,
                provenance,
                Freshness::fresh(store.ledger_head.seq),
                Vec::new(),
                ProvenancePayload::Lineage(lineage),
            ))
        }
        ProvenanceMode::AnswerTrace => {
            let subject_id = required_subject(query, mode)?;
            let trace = store.answers.get(subject_id).cloned().ok_or_else(|| {
                not_found_error(
                    "answer trace",
                    subject_id,
                    "request provenance for a recorded answer id",
                )
            })?;
            let freshness = Freshness::evaluate(trace.freshness.seq, store.ledger_head.seq);
            let mut warnings = answer_trace_warnings(&trace);
            warnings.extend(stale_warning(&freshness, &trace.answer_id));
            Ok(response(
                mode,
                store.ledger_head.clone(),
                freshness,
                warnings,
                ProvenancePayload::AnswerTrace(trace),
            ))
        }
        ProvenanceMode::VerifyChain => {
            let warnings = verify_chain_warnings(&store.chain);
            Ok(response(
                mode,
                store.chain.provenance.clone(),
                Freshness::fresh(store.ledger_head.seq),
                warnings,
                ProvenancePayload::VerifyChain(store.chain.clone()),
            ))
        }
        ProvenanceMode::Reproduce => {
            let subject_id = required_subject(query, mode)?;
            let record = store.reproductions.get(subject_id).ok_or_else(|| {
                not_found_error(
                    "reproduce record",
                    subject_id,
                    "record answer seeds before reproducing",
                )
            })?;
            if record.drift_microunits > record.drift_bound_microunits {
                return Err(astrolabe_domain::DomainError::new(
                    REPRODUCE_DRIFT_EXCEEDED,
                    format!(
                        "answer {} drift {} microunits exceeds bound {}",
                        record.answer_id, record.drift_microunits, record.drift_bound_microunits
                    ),
                    "rerun with the recorded lenses/seeds or quarantine the answer until reproduction is bit-exact",
                ));
            }
            // Cross-validate the two independent reproduce signals: a bit-exact digest
            // match must report exactly zero drift, and any nonzero drift must be
            // accompanied by a digest change. A record that violates this invariant is
            // internally contradictory (tampered or malformed) and must never be
            // laundered into a verified-looking report.
            let bit_exact = record.recorded_digest == record.current_digest;
            if bit_exact != (record.drift_microunits == 0) {
                return Err(astrolabe_domain::DomainError::new(
                    ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT,
                    format!(
                        "answer {} reproduce record is inconsistent: digests {} but drift is {} microunits",
                        record.answer_id,
                        if bit_exact { "match" } else { "differ" },
                        record.drift_microunits
                    ),
                    "re-derive the reproduce record; a bit-exact digest match must report zero drift and any drift must accompany a digest change",
                ));
            }
            let report = ReproduceReport {
                answer_id: record.answer_id.clone(),
                bit_exact,
                drift_microunits: record.drift_microunits,
                drift_bound_microunits: record.drift_bound_microunits,
                recorded_digest: record.recorded_digest.clone(),
                current_digest: record.current_digest.clone(),
            };
            let freshness = Freshness::evaluate(record.ledger.seq, store.ledger_head.seq);
            let warnings = stale_warning(&freshness, &record.answer_id);
            Ok(response(
                mode,
                record.ledger.clone(),
                freshness,
                warnings,
                ProvenancePayload::Reproduce(report),
            ))
        }
    }
}

pub fn verify_pack_manifest_claim(
    store: &ProvenanceStore,
    claimed: &PackManifest,
) -> astrolabe_domain::Result<InterAgentTrustReport> {
    let expected = store.manifests.get(&claimed.pack_id).ok_or_else(|| {
        not_found_error(
            "pack manifest",
            &claimed.pack_id,
            "request a manifest that was served from this vault",
        )
    })?;
    if expected != claimed {
        let failing_check = if expected.ledger_ref != claimed.ledger_ref {
            "ledger_ref"
        } else if expected.vault_fingerprint != claimed.vault_fingerprint {
            "vault_fingerprint"
        } else if expected.member_hash != claimed.member_hash {
            "member_hash"
        } else {
            "pack_id"
        };
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_MANIFEST_TAMPERED,
            format!(
                "pack manifest {} failed {failing_check} verification",
                claimed.pack_id
            ),
            "discard the claimed context pack and fetch provenance from the serving vault",
        ));
    }
    Ok(InterAgentTrustReport {
        schema: INTER_AGENT_TRUST_SCHEMA,
        pack_id: expected.pack_id.clone(),
        ledger_ref: expected.ledger_ref.clone(),
        vault_fingerprint: expected.vault_fingerprint.clone(),
        member_hash: expected.member_hash.clone(),
        verified_checks: vec!["pack_id", "ledger_ref", "vault_fingerprint", "member_hash"],
        // Integrity is verified against the stored manifest, but freshness is an
        // orthogonal axis: a manifest recorded behind the current head is reported
        // stale so a consumer can observe the gap even on a passing verification.
        freshness: Freshness::evaluate(expected.ledger_ref.seq, store.ledger_head.seq),
        trust: "verified",
        provenance: store.ledger_head.clone(),
    })
}

pub fn provenance_response_artifact_bytes(response: &ProvenanceResponse) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(response.schema);
    out.push('\n');
    out.push_str("mode=");
    out.push_str(response.mode.as_str());
    out.push('\n');
    out.push_str("trust=");
    out.push_str(response.trust);
    out.push('\n');
    out.push_str("ledger=");
    out.push_str(&response.provenance.seq.to_string());
    out.push(':');
    out.push_str(&response.provenance.chain_hash);
    out.push('\n');
    for warning in &response.warnings {
        out.push_str("warning\t");
        out.push_str(warning.code);
        out.push('\t');
        out.push_str(&warning.message);
        out.push('\n');
    }
    match &response.payload {
        ProvenancePayload::Lineage(lineage) => {
            out.push_str("lineage\t");
            out.push_str(&lineage.symbol_id);
            out.push('\t');
            out.push_str(&lineage.versions.len().to_string());
            out.push('\n');
        }
        ProvenancePayload::AnswerTrace(trace) => {
            out.push_str("answer_trace\t");
            out.push_str(&trace.answer_id);
            out.push('\t');
            out.push_str(&trace.hops.len().to_string());
            out.push('\n');
        }
        ProvenancePayload::VerifyChain(chain) => {
            out.push_str("verify_chain\t");
            out.push_str(chain.status.as_str());
            out.push('\t');
            out.push_str(&chain.checked_from.to_string());
            out.push('\t');
            out.push_str(&chain.checked_to.to_string());
            out.push('\n');
        }
        ProvenancePayload::Reproduce(report) => {
            out.push_str("reproduce\t");
            out.push_str(&report.answer_id);
            out.push('\t');
            out.push_str(if report.bit_exact {
                "bit_exact"
            } else {
                "drift_within_bound"
            });
            out.push('\t');
            out.push_str(&report.current_digest);
            out.push('\n');
        }
    }
    out.into_bytes()
}

fn response(
    mode: ProvenanceMode,
    provenance: LedgerPointer,
    freshness: Freshness,
    warnings: Vec<ProvenanceWarning>,
    payload: ProvenancePayload,
) -> ProvenanceResponse {
    ProvenanceResponse {
        schema: GET_PROVENANCE_SCHEMA,
        mode,
        trust: if warnings.is_empty() {
            "verified"
        } else {
            "provisional"
        },
        freshness,
        provenance,
        warnings,
        payload,
    }
}

/// Emits coded warnings that degrade envelope trust for a non-`Intact` verify_chain
/// report. A broken or corrupt chain is the exact condition `verify_chain` exists to
/// surface, so the report is still served — but never under a `verified` envelope.
fn verify_chain_warnings(chain: &ChainVerification) -> Vec<ProvenanceWarning> {
    match &chain.status {
        ChainStatus::Intact => Vec::new(),
        ChainStatus::Broken { seq } => vec![ProvenanceWarning {
            code: PROVENANCE_WARN_CHAIN_BROKEN,
            message: format!(
                "ledger chain broken at seq {seq}; provenance is not trustworthy at or past this entry"
            ),
        }],
        ChainStatus::Corrupt { seq, reason } => vec![ProvenanceWarning {
            code: PROVENANCE_WARN_CHAIN_CORRUPT,
            message: format!("ledger chain corrupt at seq {seq}: {reason}"),
        }],
    }
}

/// Emits a coded staleness warning (degrading envelope trust) when an artifact
/// predates the ledger head, so a stale provenance answer is observable.
fn stale_warning(freshness: &Freshness, subject_id: &str) -> Vec<ProvenanceWarning> {
    match &freshness.stale_by {
        None => Vec::new(),
        Some(gap) => vec![ProvenanceWarning {
            code: PROVENANCE_WARN_STALE,
            message: format!("{subject_id} provenance is {gap}"),
        }],
    }
}

fn required_subject(
    query: &ProvenanceQuery,
    mode: ProvenanceMode,
) -> astrolabe_domain::Result<&str> {
    query.subject_id.as_deref().ok_or_else(|| {
        astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_NOT_FOUND,
            format!(
                "get_provenance mode {} requires a subject id",
                mode.as_str()
            ),
            "supply the symbol id, answer id, or pack id required by the selected provenance mode",
        )
    })
}

fn answer_trace_warnings(trace: &AnswerTrace) -> Vec<ProvenanceWarning> {
    let mut warnings = Vec::new();
    if trace.kernel_entry.is_none() {
        warnings.push(ProvenanceWarning {
            code: "unprovenanced",
            message: format!("answer {} is missing kernel entry lineage", trace.answer_id),
        });
    }
    if trace.fusion_weights_ref.is_none() {
        warnings.push(ProvenanceWarning {
            code: "unprovenanced",
            message: format!(
                "answer {} is missing fusion weight lineage",
                trace.answer_id
            ),
        });
    }
    if trace.guard_verdict_ref.is_none() {
        warnings.push(ProvenanceWarning {
            code: "unprovenanced",
            message: format!(
                "answer {} is missing guard verdict lineage",
                trace.answer_id
            ),
        });
    }
    warnings
}

fn not_found_error(
    subject_kind: &'static str,
    subject_id: &str,
    remediation: &'static str,
) -> astrolabe_domain::DomainError {
    astrolabe_domain::DomainError::new(
        ASTRO_PROVENANCE_NOT_FOUND,
        format!("{subject_kind} {subject_id} is not present in provenance store"),
        remediation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn all_get_provenance_modes_return_labeled_envelopes() {
        let store = provenance_fixture();
        // Expected freshness seq is the artifact's own as-of seq, not an unconditional
        // head stamp: lineage/verify_chain report current head, answer_trace reports the
        // seq the answer was computed at, reproduce reports the record's ledger seq.
        for (mode, subject, expected_freshness_seq) in [
            ("lineage", Some("symbol:auth.login"), store.ledger_head.seq),
            ("answer_trace", Some("answer:pack-1"), 23),
            ("verify_chain", None, store.ledger_head.seq),
            ("reproduce", Some("answer:pack-1"), 24),
        ] {
            let response = get_provenance(&store, &ProvenanceQuery::new(mode, subject))
                .expect("mode response");
            assert_eq!(response.schema, GET_PROVENANCE_SCHEMA);
            assert_eq!(
                response.freshness.seq, expected_freshness_seq,
                "mode {mode} freshness seq"
            );
            assert!(!response.provenance.chain_hash.is_empty());
            assert!(matches!(response.trust, "verified" | "provisional"));
        }
    }

    #[test]
    fn freshness_evaluate_measures_staleness_gap_exactly() {
        // At or ahead of head: fresh, no gap.
        assert_eq!(Freshness::evaluate(42, 42), Freshness::fresh(42));
        assert_eq!(Freshness::evaluate(50, 42).stale_by, None);
        // Behind head: exact measured gap, artifact seq preserved.
        let stale = Freshness::evaluate(23, 42);
        assert_eq!(stale.seq, 23);
        assert!(stale.is_stale());
        assert_eq!(
            stale.stale_by.as_deref(),
            Some("19 ledger entries behind head seq 42")
        );
    }

    #[test]
    fn stale_answer_trace_is_observable_and_degrades_trust() {
        // Regression for freshness theater: the fixture answer was computed at seq 23
        // while head is 42. The old fresh(head) default hid this; the envelope must now
        // carry the exact staleness and drop out of "verified".
        let store = provenance_fixture();
        let response = get_provenance(
            &store,
            &ProvenanceQuery::new("answer_trace", Some("answer:pack-1")),
        )
        .expect("answer trace");
        assert_eq!(response.freshness.seq, 23);
        assert_eq!(
            response.freshness.stale_by.as_deref(),
            Some("19 ledger entries behind head seq 42")
        );
        assert_eq!(response.trust, "provisional");
        assert!(
            response
                .warnings
                .iter()
                .any(|w| w.code == PROVENANCE_WARN_STALE)
        );

        // A trace computed at head is fresh and stays verified.
        let fresh = get_provenance(
            &store,
            &ProvenanceQuery::new("answer_trace", Some("answer:at-head")),
        )
        .expect("fresh answer trace");
        assert_eq!(fresh.freshness.seq, store.ledger_head.seq);
        assert_eq!(fresh.freshness.stale_by, None);
        assert_eq!(fresh.trust, "verified");
        assert!(fresh.warnings.is_empty());
    }

    #[test]
    fn broken_chain_is_labeled_provisional_not_verified() {
        // Regression for fail-open verify_chain: a broken chain must never be served
        // under a verified envelope, and the broken status must survive byte readback.
        let store = broken_chain_fixture();
        let response =
            get_provenance(&store, &ProvenanceQuery::new("verify_chain", None)).expect("verify");
        assert_eq!(response.trust, "provisional");
        assert_eq!(response.warnings.len(), 1);
        assert_eq!(response.warnings[0].code, PROVENANCE_WARN_CHAIN_BROKEN);
        assert!(response.warnings[0].message.contains("seq 5"));

        let bytes = provenance_response_artifact_bytes(&response);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-provenance-broken-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).expect("write");
        let readback = std::fs::read(&path).expect("read");
        std::fs::remove_file(&path).ok();
        let text = String::from_utf8(readback).expect("utf8");
        assert!(text.contains("trust=provisional"), "text: {text}");
        assert!(text.contains("verify_chain\tbroken"), "text: {text}");
        assert!(text.contains("warning\tchain_broken"), "text: {text}");
    }

    #[test]
    fn corrupt_chain_is_labeled_provisional_not_verified() {
        let store = corrupt_chain_fixture();
        let response =
            get_provenance(&store, &ProvenanceQuery::new("verify_chain", None)).expect("verify");
        assert_eq!(response.trust, "provisional");
        assert_eq!(response.warnings.len(), 1);
        assert_eq!(response.warnings[0].code, PROVENANCE_WARN_CHAIN_CORRUPT);
        assert!(response.warnings[0].message.contains("hash mismatch"));
    }

    #[test]
    fn intact_chain_stays_verified() {
        let store = provenance_fixture();
        let response =
            get_provenance(&store, &ProvenanceQuery::new("verify_chain", None)).expect("verify");
        assert_eq!(response.trust, "verified");
        assert!(response.warnings.is_empty());
    }

    #[test]
    fn inconsistent_reproduce_records_fail_closed() {
        let store = provenance_fixture();
        // Equal digests but nonzero drift: a bit-exact match cannot have drifted.
        let err = get_provenance(
            &store,
            &ProvenanceQuery::new("reproduce", Some("answer:phantom-drift")),
        )
        .expect_err("phantom drift refused");
        assert_eq!(err.code(), ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT);
        assert!(err.message().contains("match"));
        assert!(err.message().contains("500"));

        // Differing digests but zero drift: a changed output cannot report zero drift.
        let err = get_provenance(
            &store,
            &ProvenanceQuery::new("reproduce", Some("answer:phantom-match")),
        )
        .expect_err("phantom match refused");
        assert_eq!(err.code(), ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT);
        assert!(err.message().contains("differ"));
        assert!(
            err.remediation()
                .contains("bit-exact digest match must report zero drift")
        );
    }

    #[test]
    fn invalid_mode_and_unknown_subjects_fail_closed() {
        let store = provenance_fixture();
        let err = get_provenance(&store, &ProvenanceQuery::new("mystery", Some("x")))
            .expect_err("unknown mode refused");
        assert_eq!(err.code(), ASTRO_PROVENANCE_UNKNOWN_MODE);

        let err = get_provenance(
            &store,
            &ProvenanceQuery::new("lineage", Some("symbol:missing")),
        )
        .expect_err("unknown symbol refused");
        assert_eq!(err.code(), ASTRO_PROVENANCE_NOT_FOUND);
        assert!(err.remediation().contains("index or import"));
    }

    #[test]
    fn incomplete_answer_trace_reports_unprovenanced_warning() {
        let store = provenance_fixture();
        let response = get_provenance(
            &store,
            &ProvenanceQuery::new("answer_trace", Some("answer:incomplete")),
        )
        .expect("incomplete answer trace");

        assert_eq!(response.trust, "provisional");
        // Two unprovenanced warnings (missing fusion + guard lineage) plus one stale
        // warning: the incomplete answer was computed at seq 30 while head is 42.
        assert_eq!(response.warnings.len(), 3);
        assert_eq!(
            response
                .warnings
                .iter()
                .filter(|warning| warning.code == "unprovenanced")
                .count(),
            2
        );
        assert_eq!(
            response
                .warnings
                .iter()
                .filter(|warning| warning.code == PROVENANCE_WARN_STALE)
                .count(),
            1
        );
        let ProvenancePayload::AnswerTrace(trace) = response.payload else {
            panic!("expected answer trace payload");
        };
        assert!(trace.kernel_entry.is_some());
        assert!(trace.fusion_weights_ref.is_none());
        assert!(trace.guard_verdict_ref.is_none());
    }

    #[test]
    fn reproduce_reports_bit_exact_or_drift_exceeded() {
        let store = provenance_fixture();
        let exact = get_provenance(
            &store,
            &ProvenanceQuery::new("reproduce", Some("answer:pack-1")),
        )
        .expect("bit exact reproduce");
        let ProvenancePayload::Reproduce(report) = exact.payload else {
            panic!("expected reproduce payload");
        };
        assert!(report.bit_exact);
        assert_eq!(report.drift_microunits, 0);

        let err = get_provenance(
            &store,
            &ProvenanceQuery::new("reproduce", Some("answer:drifted")),
        )
        .expect_err("drift exceeded refused");
        assert_eq!(err.code(), REPRODUCE_DRIFT_EXCEEDED);
        assert!(err.message().contains("2000"));
        assert!(err.message().contains("1000"));
    }

    #[test]
    fn inter_agent_manifest_round_trip_verifies_and_tamper_refuses() {
        let store = provenance_fixture();
        let manifest = store.manifests.get("pack:auth").expect("manifest").clone();
        let report = verify_pack_manifest_claim(&store, &manifest).expect("verify manifest");
        assert_eq!(report.schema, INTER_AGENT_TRUST_SCHEMA);
        assert_eq!(
            report.verified_checks,
            vec!["pack_id", "ledger_ref", "vault_fingerprint", "member_hash"]
        );
        assert_eq!(report.trust, "verified");
        // Verified integrity, but freshness reflects the manifest's own ledger_ref seq
        // (24) against head (42): the old fresh(head) stamp claimed currency it lacked.
        assert_eq!(report.freshness.seq, manifest.ledger_ref.seq);
        assert_eq!(
            report.freshness.stale_by.as_deref(),
            Some("18 ledger entries behind head seq 42")
        );

        let mut tampered = manifest;
        tampered.member_hash = "tampered-members".to_string();
        let err =
            verify_pack_manifest_claim(&store, &tampered).expect_err("tampered manifest refused");
        assert_eq!(err.code(), ASTRO_PROVENANCE_MANIFEST_TAMPERED);
        assert!(err.message().contains("member_hash"));
    }

    #[test]
    fn provenance_response_artifact_reads_back_from_disk() {
        let store = provenance_fixture();
        let response = get_provenance(
            &store,
            &ProvenanceQuery::new("answer_trace", Some("answer:incomplete")),
        )
        .expect("answer trace");
        let bytes = provenance_response_artifact_bytes(&response);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-provenance-{}-{}.txt",
            std::process::id(),
            response.provenance.seq
        ));
        std::fs::write(&path, &bytes).expect("write provenance artifact");
        let readback = std::fs::read(&path).expect("read provenance artifact");
        std::fs::remove_file(&path).ok();

        assert_eq!(readback, bytes);
        let text = String::from_utf8(readback).expect("utf8 provenance artifact");
        assert!(text.contains("warning\tunprovenanced"));
        assert!(text.contains("answer_trace\tanswer:incomplete"));
    }

    fn provenance_fixture() -> ProvenanceStore {
        let ledger_head = LedgerPointer::new(42, "head-hash");
        let mut symbols = BTreeMap::new();
        symbols.insert(
            "symbol:auth.login".to_string(),
            SymbolLineage {
                symbol_id: "symbol:auth.login".to_string(),
                versions: vec![
                    LineageEvent {
                        kind: "version".to_string(),
                        ledger: LedgerPointer::new(7, "hash-7"),
                        summary: "initial import".to_string(),
                    },
                    LineageEvent {
                        kind: "anchor".to_string(),
                        ledger: LedgerPointer::new(9, "hash-9"),
                        summary: "test anchor attached".to_string(),
                    },
                ],
            },
        );

        let mut answers = BTreeMap::new();
        answers.insert(
            "answer:pack-1".to_string(),
            AnswerTrace {
                answer_id: "answer:pack-1".to_string(),
                kernel_entry: Some(LedgerPointer::new(20, "hash-20")),
                hops: vec![AnswerHop {
                    from_symbol: "symbol:auth.login".to_string(),
                    to_symbol: "symbol:auth.token".to_string(),
                    ledger: LedgerPointer::new(21, "hash-21"),
                }],
                fusion_weights_ref: Some(LedgerPointer::new(22, "hash-22")),
                guard_verdict_ref: Some(LedgerPointer::new(23, "hash-23")),
                freshness: Freshness::fresh(23),
            },
        );
        answers.insert(
            "answer:incomplete".to_string(),
            AnswerTrace {
                answer_id: "answer:incomplete".to_string(),
                kernel_entry: Some(LedgerPointer::new(30, "hash-30")),
                hops: Vec::new(),
                fusion_weights_ref: None,
                guard_verdict_ref: None,
                freshness: Freshness::fresh(30),
            },
        );
        answers.insert(
            "answer:at-head".to_string(),
            AnswerTrace {
                answer_id: "answer:at-head".to_string(),
                kernel_entry: Some(LedgerPointer::new(40, "hash-40")),
                hops: Vec::new(),
                fusion_weights_ref: Some(LedgerPointer::new(41, "hash-41")),
                guard_verdict_ref: Some(LedgerPointer::new(42, "hash-42")),
                freshness: Freshness::fresh(42),
            },
        );

        let mut reproductions = BTreeMap::new();
        reproductions.insert(
            "answer:pack-1".to_string(),
            ReproduceRecord {
                answer_id: "answer:pack-1".to_string(),
                recorded_digest: "digest-pack-1".to_string(),
                current_digest: "digest-pack-1".to_string(),
                drift_microunits: 0,
                drift_bound_microunits: 1_000,
                ledger: LedgerPointer::new(24, "hash-24"),
            },
        );
        reproductions.insert(
            "answer:drifted".to_string(),
            ReproduceRecord {
                answer_id: "answer:drifted".to_string(),
                recorded_digest: "digest-old".to_string(),
                current_digest: "digest-new".to_string(),
                drift_microunits: 2_000,
                drift_bound_microunits: 1_000,
                ledger: LedgerPointer::new(31, "hash-31"),
            },
        );
        // Equal digests yet nonzero drift within bound: internally contradictory.
        reproductions.insert(
            "answer:phantom-drift".to_string(),
            ReproduceRecord {
                answer_id: "answer:phantom-drift".to_string(),
                recorded_digest: "digest-same".to_string(),
                current_digest: "digest-same".to_string(),
                drift_microunits: 500,
                drift_bound_microunits: 1_000,
                ledger: LedgerPointer::new(32, "hash-32"),
            },
        );
        // Differing digests yet zero drift: internally contradictory.
        reproductions.insert(
            "answer:phantom-match".to_string(),
            ReproduceRecord {
                answer_id: "answer:phantom-match".to_string(),
                recorded_digest: "digest-a".to_string(),
                current_digest: "digest-b".to_string(),
                drift_microunits: 0,
                drift_bound_microunits: 1_000,
                ledger: LedgerPointer::new(33, "hash-33"),
            },
        );

        let mut manifests = BTreeMap::new();
        manifests.insert(
            "pack:auth".to_string(),
            PackManifest {
                pack_id: "pack:auth".to_string(),
                ledger_ref: LedgerPointer::new(24, "hash-24"),
                vault_fingerprint: "vault-fingerprint".to_string(),
                member_hash: "members-auth".to_string(),
            },
        );

        ProvenanceStore {
            vault_fingerprint: "vault-fingerprint".to_string(),
            ledger_head: ledger_head.clone(),
            chain: ChainVerification {
                status: ChainStatus::Intact,
                checked_from: 0,
                checked_to: ledger_head.seq,
                provenance: ledger_head.clone(),
            },
            symbols,
            answers,
            reproductions,
            manifests,
        }
    }

    fn broken_chain_fixture() -> ProvenanceStore {
        let mut store = provenance_fixture();
        store.chain = ChainVerification {
            status: ChainStatus::Broken { seq: 5 },
            checked_from: 0,
            checked_to: 5,
            provenance: store.ledger_head.clone(),
        };
        store
    }

    fn corrupt_chain_fixture() -> ProvenanceStore {
        let mut store = provenance_fixture();
        store.chain = ChainVerification {
            status: ChainStatus::Corrupt {
                seq: 8,
                reason: "hash mismatch".to_string(),
            },
            checked_from: 0,
            checked_to: 8,
            provenance: store.ledger_head.clone(),
        };
        store
    }
}
