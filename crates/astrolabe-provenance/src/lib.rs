#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub mod reproduce;
pub use reproduce::{
    ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT, ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED,
    KNOB_REPRODUCE_DRIFT_BOUND_MICROUNITS, MICROUNITS_PER_PERMILLE, RECORDED_KERNEL_ANSWER_SCHEMA,
    REPRODUCE_KNOB_REGISTRY_VERSION, REPRODUCE_KNOBS, RecordedKernelAnswer,
    STRUCTURAL_DRIFT_MICROUNITS, answer_drift_microunits, answer_trace_from_kernel_answer,
    parse_recorded_kernel_answer, recorded_kernel_answer_bytes, reproduce_drift_bound_default,
    reproduce_kernel_answer, resolve_drift_bound,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const GET_PROVENANCE_SCHEMA: &str = "astrolabe.get_provenance.v1";
pub const INTER_AGENT_TRUST_SCHEMA: &str = "astrolabe.inter_agent_trust.v1";
pub const ASTRO_PROVENANCE_UNKNOWN_MODE: &str = "ASTRO_PROVENANCE_UNKNOWN_MODE";
pub const ASTRO_PROVENANCE_NOT_FOUND: &str = "ASTRO_PROVENANCE_NOT_FOUND";
pub const ASTRO_PROVENANCE_MANIFEST_TAMPERED: &str = "ASTRO_PROVENANCE_MANIFEST_TAMPERED";
pub const REPRODUCE_DRIFT_EXCEEDED: &str = "REPRODUCE_DRIFT_EXCEEDED";
/// Error code: a lineage was requested for a subject that no persisted ledger
/// row references. Fail closed rather than returning an empty lineage that would
/// read as a verified, complete history of a symbol that was never ledgered.
pub const ASTRO_PROVENANCE_LINEAGE_EMPTY: &str = "ASTRO_PROVENANCE_LINEAGE_EMPTY";
/// Error code: a scanned ledger row that would become a lineage node is missing
/// its provenance pointer (empty entry hash) or names a different subject than
/// the one requested. A node with no ledger pointer is an invented edge, so the
/// whole lineage is refused rather than served with a fabricated link.
pub const ASTRO_PROVENANCE_LINEAGE_GAP: &str = "ASTRO_PROVENANCE_LINEAGE_GAP";
/// Schema tag for the self-describing inter-agent pack-manifest attestation
/// envelope: the byte artifact a serving agent hands a verifying agent.
pub const PACK_MANIFEST_ATTESTATION_SCHEMA: &str = "astrolabe.pack_manifest_attestation.v1";
/// Error code: an attestation envelope failed to parse or its recomputed
/// attestation digest did not match the digest recorded in the envelope — the
/// exact signature of a tampered manifest artifact. Fail closed.
pub const ASTRO_PROVENANCE_ATTESTATION_CORRUPT: &str = "ASTRO_PROVENANCE_ATTESTATION_CORRUPT";
pub const ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT: &str = "ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT";
/// Error code: a verify-relevant provenance metadatum required to evaluate freshness or
/// verification was absent from persisted metadata. Fail closed rather than fabricate a
/// value that reads as fresh/verified.
pub const ASTRO_PROVENANCE_METADATA_MISSING: &str = "ASTRO_PROVENANCE_METADATA_MISSING";
/// Error code: a verify-relevant provenance metadatum was persisted but is empty or
/// unparseable (corrupt). Fail closed rather than silently fall back to a persisted or
/// derived value that would read as verified.
pub const ASTRO_PROVENANCE_METADATA_CORRUPT: &str = "ASTRO_PROVENANCE_METADATA_CORRUPT";

/// Warning code emitted when a `verify_chain` report carries a broken ledger chain.
pub const PROVENANCE_WARN_CHAIN_BROKEN: &str = "chain_broken";
/// Warning code emitted when a `verify_chain` report carries a corrupt ledger chain.
pub const PROVENANCE_WARN_CHAIN_CORRUPT: &str = "chain_corrupt";
/// Warning code emitted when a lineage/answer/reproduce artifact predates the ledger head.
pub const PROVENANCE_WARN_STALE: &str = "stale";
/// Warning code emitted when a `verify_chain` report attested an empty ledger range:
/// zero entries were checked, so chain integrity is unverified — never `verified`.
pub const PROVENANCE_WARN_CHAIN_EMPTY: &str = "chain_empty";

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

/// Requires a persisted, non-empty verify-relevant string metadatum (e.g. a vault
/// fingerprint that participates in verification).
///
/// `raw` is the raw persisted config value: `None` means the key was absent, `Some(text)`
/// is the persisted string. This fails **closed** — with a coded, remediation-bearing
/// [`astrolabe_domain::DomainError`] — rather than defaulting a missing/empty value to a
/// derived value (such as the ledger chain hash) that would let a fingerprint-less
/// artifact read as verified. A verification input that is silently fabricated is
/// indistinguishable from a measured one, which is precisely the "freshness theater" this
/// guards against.
pub fn require_verify_metadata(field: &str, raw: Option<&str>) -> astrolabe_domain::Result<String> {
    match raw.map(str::trim) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        Some(_) => Err(astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_METADATA_CORRUPT,
            format!("verify-relevant provenance metadata `{field}` is present but empty"),
            "re-run index_repository so the provenance surface persists a non-empty value; refusing rather than fabricating a verification input",
        )),
        None => Err(astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_METADATA_MISSING,
            format!("verify-relevant provenance metadata `{field}` is absent"),
            "re-run index_repository so the provenance surface persists this field; refusing rather than defaulting a verification input",
        )),
    }
}

/// Requires a persisted, parseable ledger sequence watermark.
///
/// The sequence is the artifact's "as-of" watermark: freshness is measured as the gap
/// between it and the current ledger head, so a fabricated value produces an unfalsifiable
/// freshness claim. `None` (key absent) fails closed as
/// [`ASTRO_PROVENANCE_METADATA_MISSING`]; a present-but-unparseable value fails closed as
/// [`ASTRO_PROVENANCE_METADATA_CORRUPT`] — never the previous silent fall-back to a
/// persisted sequence.
pub fn require_ledger_seq(field: &str, raw: Option<&str>) -> astrolabe_domain::Result<u64> {
    let Some(text) = raw.map(str::trim) else {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_METADATA_MISSING,
            format!("verify-relevant ledger sequence `{field}` is absent"),
            "re-run index_repository so the provenance surface persists this ledger sequence; refusing rather than defaulting the freshness watermark",
        ));
    };
    text.parse::<u64>().map_err(|_| {
        astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_METADATA_CORRUPT,
            format!("verify-relevant ledger sequence `{field}` is not a valid sequence: {text:?}"),
            "re-run index_repository so the provenance surface persists a valid ledger sequence; refusing rather than defaulting the freshness watermark",
        )
    })
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

/// A decoded ledger row as read back from persisted storage, projected to the
/// fields lineage construction needs.
///
/// The caller (the server's live vault-scan adapter) decodes real persisted
/// `ledger` column-family bytes into these rows — sequence, lower-hex entry hash
/// (the chain pointer), stable kind label, resolved subject, and a summary. This
/// crate never fabricates rows: it turns real scanned rows into a labeled
/// lineage graph or refuses fail-closed when they are absent or incomplete.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LedgerScanRow {
    /// Ledger sequence of the persisted row.
    pub seq: u64,
    /// Lower-hex of the persisted entry hash; the node's provenance pointer.
    pub entry_hash: String,
    /// Stable ledger entry kind label (e.g. `ingest`, `measure`, `guard`).
    pub kind: String,
    /// Subject the row is scoped to — the resolved symbol/series identity.
    pub subject: String,
    /// Human-readable summary of the event.
    pub summary: String,
}

impl LedgerScanRow {
    pub fn new(
        seq: u64,
        entry_hash: impl Into<String>,
        kind: impl Into<String>,
        subject: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            seq,
            entry_hash: entry_hash.into(),
            kind: kind.into(),
            subject: subject.into(),
            summary: summary.into(),
        }
    }
}

/// Builds a symbol's lineage from real persisted ledger rows scanned for that
/// subject, ordering nodes by ledger sequence and stamping every node with its
/// real ledger pointer (`seq` + persisted entry hash).
///
/// This is the honest core of `get_provenance(mode="lineage")`: the server's
/// vault-scan adapter decodes the physical `ledger` CF and passes the rows here;
/// the lineage graph is derived only from what was actually ledgered.
///
/// Fails **closed**, never fabricating an edge:
/// - [`ASTRO_PROVENANCE_LINEAGE_EMPTY`] when no scanned row references `symbol_id`
///   (an empty history would otherwise read as a verified, complete lineage of a
///   symbol that was never ledgered);
/// - [`ASTRO_PROVENANCE_LINEAGE_GAP`] when a scanned row is missing its entry
///   hash (a node with no provenance pointer) or names a different subject than
///   requested (a mis-scoped, invented edge).
pub fn build_symbol_lineage(
    symbol_id: &str,
    rows: &[LedgerScanRow],
) -> astrolabe_domain::Result<SymbolLineage> {
    let mut scoped: Vec<&LedgerScanRow> = Vec::new();
    for row in rows {
        if row.subject != symbol_id {
            return Err(astrolabe_domain::DomainError::new(
                ASTRO_PROVENANCE_LINEAGE_GAP,
                format!(
                    "lineage scan for {symbol_id} contains a row scoped to a different subject {}",
                    row.subject
                ),
                "scan and pass only the ledger rows whose subject resolves to the requested symbol; refusing rather than attaching a mis-scoped node",
            ));
        }
        if row.entry_hash.trim().is_empty() {
            return Err(astrolabe_domain::DomainError::new(
                ASTRO_PROVENANCE_LINEAGE_GAP,
                format!(
                    "lineage row at seq {} for {symbol_id} is missing its entry-hash provenance pointer",
                    row.seq
                ),
                "re-scan the ledger so every lineage node carries its persisted entry hash; refusing rather than inventing a hash-less edge",
            ));
        }
        scoped.push(row);
    }
    if scoped.is_empty() {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_PROVENANCE_LINEAGE_EMPTY,
            format!("no persisted ledger row references subject {symbol_id}"),
            "index or import the symbol so its history is ledgered; refusing rather than returning an empty lineage that reads as verified",
        ));
    }
    scoped.sort_by_key(|row| row.seq);
    let versions = scoped
        .into_iter()
        .map(|row| LineageEvent {
            kind: row.kind.clone(),
            ledger: LedgerPointer::new(row.seq, row.entry_hash.clone()),
            summary: row.summary.clone(),
        })
        .collect();
    Ok(SymbolLineage {
        symbol_id: symbol_id.to_string(),
        versions,
    })
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
    /// Inclusive lower bound of the attested ledger sequence range.
    pub checked_from: u64,
    /// Exclusive upper bound of the attested ledger sequence range. When it equals
    /// `checked_from` the range is empty: zero entries were checked and no sequence is
    /// fabricated as verified. Storing the exclusive end — rather than an inclusive
    /// `checked_to` derived via `end - 1` — removes the empty-range off-by-one that let
    /// an unchecked ledger (`end == 0`) claim seq 0 had been verified.
    pub checked_end: u64,
    pub provenance: LedgerPointer,
}

impl ChainVerification {
    /// True when zero ledger sequences fall in the attested range.
    pub const fn is_empty_range(&self) -> bool {
        self.checked_end <= self.checked_from
    }

    /// Count of ledger sequences attested by this report.
    pub const fn checked_count(&self) -> u64 {
        self.checked_end.saturating_sub(self.checked_from)
    }

    /// Inclusive last sequence actually checked, or `None` for an empty range. An empty
    /// range never fabricates seq 0 (or any other sequence) as checked.
    pub const fn last_checked_seq(&self) -> Option<u64> {
        if self.is_empty_range() {
            None
        } else {
            Some(self.checked_end - 1)
        }
    }
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

/// Domain-separation tag mixed into the pack-manifest attestation digest so it
/// can never collide with any other blake3 use in this crate.
const ATTESTATION_DIGEST_DOMAIN: &[u8] = b"astrolabe:pack-manifest-attestation:v1";

/// Canonical attestation digest binding every field of a pack manifest.
///
/// This is the content-address the blueprint's inter-agent trust model rests on
/// (`pack_id = blake3(members ∪ hashes)`): a serving agent computes it over the
/// manifest it hands out, and any change to `pack_id`, `ledger_ref`,
/// `vault_fingerprint`, or `member_hash` flips the digest. Fields are length-
/// prefixed so no two distinct manifests share a preimage.
pub fn pack_manifest_attestation_digest(manifest: &PackManifest) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ATTESTATION_DIGEST_DOMAIN);
    for field in [
        manifest.pack_id.as_bytes(),
        manifest.ledger_ref.chain_hash.as_bytes(),
        manifest.vault_fingerprint.as_bytes(),
        manifest.member_hash.as_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.update(&manifest.ledger_ref.seq.to_le_bytes());
    hex_lower(hasher.finalize().as_bytes())
}

/// Serializes a pack manifest into a canonical, self-describing attestation
/// envelope carrying its attestation digest.
///
/// This is the exact byte artifact a serving agent (agent A) hands to a
/// verifying agent (agent B). It is line-oriented and deterministic so it round-
/// trips byte-for-byte through persisted storage; the trailing `digest` line
/// binds the four verified fields.
pub fn pack_manifest_attestation_bytes(manifest: &PackManifest) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(PACK_MANIFEST_ATTESTATION_SCHEMA);
    out.push('\n');
    out.push_str("pack_id=");
    out.push_str(&manifest.pack_id);
    out.push('\n');
    out.push_str("ledger_seq=");
    out.push_str(&manifest.ledger_ref.seq.to_string());
    out.push('\n');
    out.push_str("ledger_hash=");
    out.push_str(&manifest.ledger_ref.chain_hash);
    out.push('\n');
    out.push_str("vault_fingerprint=");
    out.push_str(&manifest.vault_fingerprint);
    out.push('\n');
    out.push_str("member_hash=");
    out.push_str(&manifest.member_hash);
    out.push('\n');
    out.push_str("digest=");
    out.push_str(&pack_manifest_attestation_digest(manifest));
    out.push('\n');
    out.into_bytes()
}

/// Parses an attestation envelope and re-verifies its digest against the parsed
/// fields, failing closed on any tamper.
///
/// A verifying agent reads back the persisted envelope bytes and calls this. A
/// missing/duplicated field, an unparseable sequence, a wrong schema, or a
/// digest that does not match the recomputed digest of the parsed fields all
/// yield [`ASTRO_PROVENANCE_ATTESTATION_CORRUPT`]: the attested manifest is only
/// returned when the bytes are internally self-consistent. Cross-checking the
/// returned manifest against the serving vault is [`verify_pack_manifest_claim`].
pub fn parse_pack_manifest_attestation(bytes: &[u8]) -> astrolabe_domain::Result<PackManifest> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| attestation_corrupt("envelope is not UTF-8"))?;
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            attestation_corrupt(format!("envelope line has no key=value: {line:?}"))
        })?;
        if fields.insert(key, value).is_some() {
            return Err(attestation_corrupt(format!(
                "duplicate envelope field {key}"
            )));
        }
    }
    let get = |key: &str| -> astrolabe_domain::Result<String> {
        fields
            .get(key)
            .map(|value| (*value).to_string())
            .ok_or_else(|| attestation_corrupt(format!("envelope is missing field {key}")))
    };
    if get("schema")? != PACK_MANIFEST_ATTESTATION_SCHEMA {
        return Err(attestation_corrupt(
            "envelope schema is not the attestation schema",
        ));
    }
    let seq = get("ledger_seq")?
        .parse::<u64>()
        .map_err(|_| attestation_corrupt("envelope ledger_seq is not a valid sequence"))?;
    let manifest = PackManifest {
        pack_id: get("pack_id")?,
        ledger_ref: LedgerPointer::new(seq, get("ledger_hash")?),
        vault_fingerprint: get("vault_fingerprint")?,
        member_hash: get("member_hash")?,
    };
    let recorded_digest = get("digest")?;
    let recomputed = pack_manifest_attestation_digest(&manifest);
    if recorded_digest != recomputed {
        return Err(attestation_corrupt(format!(
            "envelope attestation digest {recorded_digest} does not match recomputed digest {recomputed}"
        )));
    }
    Ok(manifest)
}

fn attestation_corrupt(message: impl Into<String>) -> astrolabe_domain::DomainError {
    astrolabe_domain::DomainError::new(
        ASTRO_PROVENANCE_ATTESTATION_CORRUPT,
        message.into(),
        "discard the attestation artifact and re-fetch the manifest from the serving vault; refusing rather than trusting a self-inconsistent envelope",
    )
}

/// The genesis chain hash that precedes the first ledger link.
pub const GENESIS_CHAIN_HASH: [u8; 32] = [0u8; 32];

/// A single persisted ledger link as read back from durable storage: its sequence, the
/// payload bytes committed at that sequence, the chain hash it claims to extend, and the
/// rolling chain hash it claims to produce.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LedgerLink {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub prev_chain_hash: [u8; 32],
    pub chain_hash: [u8; 32],
}

impl LedgerLink {
    /// Builds a well-formed link that correctly extends `prev_chain_hash`, computing the
    /// rolling chain hash over the canonical preimage. Production links are sealed the
    /// same way before being persisted, so a chain of `sealed` links verifies intact.
    pub fn sealed(seq: u64, payload: impl Into<Vec<u8>>, prev_chain_hash: [u8; 32]) -> Self {
        let payload = payload.into();
        let chain_hash = link_chain_hash(&prev_chain_hash, seq, &payload);
        Self {
            seq,
            payload,
            prev_chain_hash,
            chain_hash,
        }
    }
}

/// Canonical rolling-hash preimage for a ledger link:
/// `prev_chain_hash (32 bytes) || seq (8 bytes, little-endian) || payload`.
fn link_chain_hash(prev_chain_hash: &[u8; 32], seq: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_chain_hash);
    hasher.update(&seq.to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Recomputes the rolling hash chain over `links` and returns an honest
/// [`ChainVerification`]. The links must form a contiguous sequence beginning at
/// `checked_from`. A link is rejected as [`ChainStatus::Broken`] if it breaks sequence
/// contiguity or fails to extend the previous link's chain hash, and as
/// [`ChainStatus::Corrupt`] if its stored `chain_hash` does not match the value
/// recomputed from its own bytes — the exact signature of a tampered payload or hash. An
/// empty slice yields an explicit empty checked range and never fabricates a checked seq.
pub fn verify_ledger_chain(checked_from: u64, links: &[LedgerLink]) -> ChainVerification {
    let checked_end = checked_from.saturating_add(links.len() as u64);
    let provenance = match links.last() {
        Some(last) => LedgerPointer::new(last.seq, hex_lower(&last.chain_hash)),
        None => LedgerPointer::new(checked_from, hex_lower(&GENESIS_CHAIN_HASH)),
    };
    let mut prev_chain_hash: Option<[u8; 32]> = None;
    let mut expected_seq = checked_from;
    let mut status = ChainStatus::Intact;
    for link in links {
        if link.seq != expected_seq {
            status = ChainStatus::Broken { seq: link.seq };
            break;
        }
        if let Some(prev) = prev_chain_hash
            && link.prev_chain_hash != prev
        {
            status = ChainStatus::Broken { seq: link.seq };
            break;
        }
        let recomputed = link_chain_hash(&link.prev_chain_hash, link.seq, &link.payload);
        if recomputed != link.chain_hash {
            status = ChainStatus::Corrupt {
                seq: link.seq,
                reason: "recomputed chain hash does not match stored chain hash".to_string(),
            };
            break;
        }
        prev_chain_hash = Some(link.chain_hash);
        expected_seq = expected_seq.saturating_add(1);
    }
    ChainVerification {
        status,
        checked_from,
        checked_end,
        provenance,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
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
            out.push_str(&chain.checked_end.to_string());
            out.push('\t');
            match chain.last_checked_seq() {
                Some(seq) => {
                    out.push_str("last_checked_seq=");
                    out.push_str(&seq.to_string());
                }
                None => out.push_str("checked=empty"),
            }
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
        ChainStatus::Intact => {
            if chain.is_empty_range() {
                // An empty attested range verified nothing. Absence of evidence is not
                // evidence of integrity, so the envelope must never read `verified`.
                vec![ProvenanceWarning {
                    code: PROVENANCE_WARN_CHAIN_EMPTY,
                    message: format!(
                        "verify_chain attested an empty ledger range [{}, {}); no entries were checked, so chain integrity is unverified",
                        chain.checked_from, chain.checked_end
                    ),
                }]
            } else {
                Vec::new()
            }
        }
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
    fn require_ledger_seq_measures_freshness_or_fails_closed() {
        // (i) Metadata present + as-of watermark at/ahead of head -> fresh, no gap.
        let as_of = require_ledger_seq("ledger_seq", Some("142")).expect("valid seq");
        assert_eq!(as_of, 142);
        assert_eq!(Freshness::evaluate(as_of, 142).stale_by, None);
        assert!(!Freshness::evaluate(as_of, 142).is_stale());

        // (ii) Metadata present + old watermark -> exact measured staleness delta.
        let old = require_ledger_seq("ledger_seq", Some("42")).expect("valid seq");
        let fr = Freshness::evaluate(old, 142);
        assert!(fr.is_stale());
        assert_eq!(
            fr.stale_by.as_deref(),
            Some("100 ledger entries behind head seq 142")
        );

        // (iii-a) Verify-relevant watermark MISSING -> fail closed, never a silent default.
        let missing = require_ledger_seq("ledger_seq", None).expect_err("must refuse");
        assert_eq!(missing.code(), ASTRO_PROVENANCE_METADATA_MISSING);
        assert!(!missing.remediation().is_empty());

        // (iii-b) Present but corrupt (unparseable) -> fail closed as corrupt, not fall-back.
        let corrupt = require_ledger_seq("ledger_seq", Some("not-a-seq")).expect_err("must refuse");
        assert_eq!(corrupt.code(), ASTRO_PROVENANCE_METADATA_CORRUPT);
        // Empty string is also corrupt, never a defaulted zero.
        assert_eq!(
            require_ledger_seq("ledger_seq", Some("   "))
                .expect_err("must refuse")
                .code(),
            ASTRO_PROVENANCE_METADATA_CORRUPT
        );
    }

    #[test]
    fn require_verify_metadata_refuses_missing_or_empty_fingerprint() {
        // Present + non-empty -> trimmed value returned.
        assert_eq!(
            require_verify_metadata("lowered_vault_fingerprint_sha256", Some("  abc123  "))
                .expect("valid"),
            "abc123"
        );
        // Missing -> fail closed (no fall-back to the ledger chain hash).
        let missing = require_verify_metadata("lowered_vault_fingerprint_sha256", None)
            .expect_err("must refuse");
        assert_eq!(missing.code(), ASTRO_PROVENANCE_METADATA_MISSING);
        // Present but empty -> fail closed as corrupt (no fabricated verification input).
        let empty =
            require_verify_metadata("vault_fingerprint", Some("   ")).expect_err("must refuse");
        assert_eq!(empty.code(), ASTRO_PROVENANCE_METADATA_CORRUPT);
        assert!(!empty.remediation().is_empty());
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

    fn store_with_chain(chain: ChainVerification) -> ProvenanceStore {
        let mut store = provenance_fixture();
        store.chain = chain;
        store
    }

    fn sealed_chain(start: u64, count: u64) -> Vec<LedgerLink> {
        let mut links = Vec::new();
        let mut prev = GENESIS_CHAIN_HASH;
        for offset in 0..count {
            let seq = start + offset;
            let link = LedgerLink::sealed(seq, format!("ledger-entry-{seq}").into_bytes(), prev);
            prev = link.chain_hash;
            links.push(link);
        }
        links
    }

    #[test]
    fn tampered_ledger_link_is_reported_corrupt_not_verified() {
        // Build a genuinely valid chain of real, correctly-sealed links.
        let mut links = sealed_chain(0, 4);
        let intact = verify_ledger_chain(0, &links);
        assert_eq!(intact.status, ChainStatus::Intact);
        // Sanity: the untampered chain rides a verified envelope.
        let intact_response = get_provenance(
            &store_with_chain(intact),
            &ProvenanceQuery::new("verify_chain", None),
        )
        .expect("verify intact");
        assert_eq!(intact_response.trust, "verified");
        assert!(intact_response.warnings.is_empty());

        // Persist a link's payload bytes, flip a single bit, read back, re-verify. This
        // is a real byte-level tamper of persisted chain state, not a hand-built verdict.
        let path =
            std::env::temp_dir().join(format!("astrolabe-ledger-link-{}.bin", std::process::id()));
        std::fs::write(&path, &links[2].payload).expect("persist link payload");
        let mut readback = std::fs::read(&path).expect("read link payload");
        std::fs::remove_file(&path).ok();
        readback[0] ^= 0x01;
        links[2].payload = readback;

        let tampered = verify_ledger_chain(0, &links);
        match &tampered.status {
            ChainStatus::Corrupt { seq, .. } => assert_eq!(*seq, 2, "tamper at seq 2"),
            other => panic!("tampered chain must be Corrupt, got {other:?}"),
        }

        // The envelope must refuse to call the tampered chain verified.
        let response = get_provenance(
            &store_with_chain(tampered),
            &ProvenanceQuery::new("verify_chain", None),
        )
        .expect("verify tampered");
        assert_ne!(
            response.trust, "verified",
            "tampered chain must not be verified"
        );
        assert_eq!(response.trust, "provisional");
        assert_eq!(response.warnings[0].code, PROVENANCE_WARN_CHAIN_CORRUPT);

        // And the verdict survives byte readback of the served artifact (FSV).
        let bytes = provenance_response_artifact_bytes(&response);
        let apath =
            std::env::temp_dir().join(format!("astrolabe-tamper-{}.txt", std::process::id()));
        std::fs::write(&apath, &bytes).expect("write artifact");
        let text = String::from_utf8(std::fs::read(&apath).expect("read artifact")).expect("utf8");
        std::fs::remove_file(&apath).ok();
        assert!(text.contains("trust=provisional"), "text: {text}");
        assert!(text.contains("verify_chain\tcorrupt"), "text: {text}");
        assert!(text.contains("warning\tchain_corrupt"), "text: {text}");
    }

    #[test]
    fn broken_continuity_is_reported_broken_not_verified() {
        let mut links = sealed_chain(0, 3);
        // Sever the link between seq 1 and seq 2, then re-seal seq 2 so its own hash is
        // self-consistent — isolating a continuity break from a hash-mismatch corruption.
        links[2].prev_chain_hash = [0xAB; 32];
        links[2].chain_hash =
            link_chain_hash(&links[2].prev_chain_hash, links[2].seq, &links[2].payload);
        let chain = verify_ledger_chain(0, &links);
        assert_eq!(chain.status, ChainStatus::Broken { seq: 2 });

        let response = get_provenance(
            &store_with_chain(chain),
            &ProvenanceQuery::new("verify_chain", None),
        )
        .expect("verify broken");
        assert_ne!(response.trust, "verified");
        assert_eq!(response.warnings[0].code, PROVENANCE_WARN_CHAIN_BROKEN);
    }

    #[test]
    fn empty_ledger_range_is_unverified_not_falsely_verified() {
        // An empty vault: verifying zero links must not fabricate a checked seq 0, and
        // must not ride a `verified` envelope. Regression for the `end - 1` off-by-one.
        let chain = verify_ledger_chain(0, &[]);
        assert_eq!(chain.status, ChainStatus::Intact);
        assert!(chain.is_empty_range());
        assert_eq!(chain.checked_from, 0);
        assert_eq!(chain.checked_end, 0);
        assert_eq!(
            chain.last_checked_seq(),
            None,
            "empty range must not fabricate a seq"
        );
        assert_eq!(chain.checked_count(), 0);

        let response = get_provenance(
            &store_with_chain(chain),
            &ProvenanceQuery::new("verify_chain", None),
        )
        .expect("verify empty");
        assert_ne!(response.trust, "verified", "empty range is not verified");
        assert_eq!(response.trust, "provisional");
        assert_eq!(response.warnings.len(), 1);
        assert_eq!(response.warnings[0].code, PROVENANCE_WARN_CHAIN_EMPTY);

        // The persisted artifact records the empty range explicitly, never last_checked_seq=0.
        let text = String::from_utf8(provenance_response_artifact_bytes(&response)).expect("utf8");
        assert!(
            text.contains("verify_chain\tintact\t0\t0\tchecked=empty"),
            "text: {text}"
        );
        assert!(
            !text.contains("last_checked_seq"),
            "empty range must not fabricate a seq: {text}"
        );
        assert!(text.contains("trust=provisional"), "text: {text}");
        assert!(text.contains("warning\tchain_empty"), "text: {text}");
    }

    #[test]
    fn single_element_range_checks_exactly_one_seq() {
        // Boundary: a one-entry ledger checks exactly seq `checked_from`; checked_end is
        // exclusive (checked_from + 1). No off-by-one in either direction.
        let links = sealed_chain(7, 1);
        let chain = verify_ledger_chain(7, &links);
        assert_eq!(chain.status, ChainStatus::Intact);
        assert!(!chain.is_empty_range());
        assert_eq!(chain.checked_from, 7);
        assert_eq!(chain.checked_end, 8);
        assert_eq!(chain.last_checked_seq(), Some(7));
        assert_eq!(chain.checked_count(), 1);

        let response = get_provenance(
            &store_with_chain(chain),
            &ProvenanceQuery::new("verify_chain", None),
        )
        .expect("verify single");
        // A genuinely checked single-entry intact chain rides a verified envelope.
        assert_eq!(response.trust, "verified");
        assert!(response.warnings.is_empty());

        let text = String::from_utf8(provenance_response_artifact_bytes(&response)).expect("utf8");
        assert!(
            text.contains("verify_chain\tintact\t7\t8\tlast_checked_seq=7"),
            "text: {text}"
        );
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

    #[test]
    fn build_symbol_lineage_orders_and_labels_nodes_then_refuses_gaps() {
        // Rows arrive unsorted; the builder orders by seq and stamps each node
        // with its real ledger pointer.
        let rows = vec![
            LedgerScanRow::new(
                21,
                "hash-21",
                "measure",
                "symbol:auth.login",
                "metrics measured",
            ),
            LedgerScanRow::new(7, "hash-7", "ingest", "symbol:auth.login", "initial import"),
            LedgerScanRow::new(14, "hash-14", "guard", "symbol:auth.login", "guard verdict"),
        ];
        let lineage = build_symbol_lineage("symbol:auth.login", &rows).expect("lineage");
        assert_eq!(lineage.symbol_id, "symbol:auth.login");
        let seqs: Vec<u64> = lineage
            .versions
            .iter()
            .map(|event| event.ledger.seq)
            .collect();
        assert_eq!(seqs, vec![7, 14, 21], "nodes ordered by ledger seq");
        for event in &lineage.versions {
            assert!(
                !event.ledger.chain_hash.is_empty(),
                "every node carries its provenance pointer"
            );
        }

        // Empty scan refuses rather than returning a verified-looking empty history.
        let empty = build_symbol_lineage("symbol:missing", &[]).expect_err("empty refused");
        assert_eq!(empty.code(), ASTRO_PROVENANCE_LINEAGE_EMPTY);
        assert!(!empty.remediation().is_empty());

        // A hash-less row is an invented edge: refuse.
        let gap_rows = vec![LedgerScanRow::new(
            7,
            "",
            "ingest",
            "symbol:auth.login",
            "import",
        )];
        let gap = build_symbol_lineage("symbol:auth.login", &gap_rows).expect_err("gap refused");
        assert_eq!(gap.code(), ASTRO_PROVENANCE_LINEAGE_GAP);

        // A mis-scoped row (different subject) is also refused.
        let misscoped = vec![LedgerScanRow::new(
            7,
            "hash-7",
            "ingest",
            "symbol:other",
            "import",
        )];
        let err = build_symbol_lineage("symbol:auth.login", &misscoped).expect_err("misscoped");
        assert_eq!(err.code(), ASTRO_PROVENANCE_LINEAGE_GAP);
    }

    #[test]
    fn pack_manifest_attestation_round_trips_byte_for_byte_and_tamper_fails_closed() {
        let store = provenance_fixture();
        let manifest = store.manifests.get("pack:auth").expect("manifest").clone();

        // Agent A serializes the attestation envelope and persists it to disk.
        let bytes = pack_manifest_attestation_bytes(&manifest);
        let path =
            std::env::temp_dir().join(format!("astrolabe-attestation-{}.txt", std::process::id()));
        std::fs::write(&path, &bytes).expect("persist attestation");

        // Agent B reads the persisted bytes back and parses+verifies the digest.
        let readback = std::fs::read(&path).expect("read attestation");
        assert_eq!(readback, bytes, "attestation round-trips byte-for-byte");
        let parsed = parse_pack_manifest_attestation(&readback).expect("parse attestation");
        assert_eq!(
            parsed, manifest,
            "parsed manifest equals the served manifest"
        );

        // Cross-check against the serving vault: verified.
        let report = verify_pack_manifest_claim(&store, &parsed).expect("verify parsed manifest");
        assert_eq!(report.trust, "verified");
        assert_eq!(
            report.verified_checks,
            vec!["pack_id", "ledger_ref", "vault_fingerprint", "member_hash"]
        );

        // Byte-level tamper of the persisted envelope: flip a byte in the
        // member_hash value; the recomputed digest no longer matches, so parse
        // refuses fail-closed before any vault comparison.
        let mut corrupt = readback.clone();
        let member_pos = String::from_utf8(readback.clone())
            .unwrap()
            .find("members-auth")
            .expect("member hash in envelope");
        corrupt[member_pos] ^= 0x01;
        let err = parse_pack_manifest_attestation(&corrupt).expect_err("tamper refused");
        assert_eq!(err.code(), ASTRO_PROVENANCE_ATTESTATION_CORRUPT);
        assert!(err.message().contains("digest"));

        // A digest-consistent envelope whose fields simply do not match the
        // serving vault is caught by the vault cross-check, naming the field.
        let mut foreign = manifest.clone();
        foreign.member_hash = "members-forged".to_string();
        let foreign_bytes = pack_manifest_attestation_bytes(&foreign);
        let foreign_parsed = parse_pack_manifest_attestation(&foreign_bytes)
            .expect("self-consistent forgery parses");
        let vault_err =
            verify_pack_manifest_claim(&store, &foreign_parsed).expect_err("vault refuses forgery");
        assert_eq!(vault_err.code(), ASTRO_PROVENANCE_MANIFEST_TAMPERED);
        assert!(vault_err.message().contains("member_hash"));

        std::fs::remove_file(&path).ok();
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
                // Exclusive end past the head seq: a non-empty attested range.
                checked_end: ledger_head.seq + 1,
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
            checked_end: 6,
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
            checked_end: 9,
            provenance: store.ledger_head.clone(),
        };
        store
    }
}
