//! Live reproduce of a recorded kernel answer (#67 DoD reproduce mode, wiring
//! `astrolabe_kernel::answer` from #40 into `get_provenance(mode="reproduce")`).
//!
//! The reproduce mode does not compare two stored digests: it **re-executes** the
//! grounded kernel answer engine with the answer's frozen lenses and recorded
//! seeds against the *current* vault association graph, then compares the live
//! re-derivation to the recorded answer:
//!
//! - An **unchanged vault** re-derives the answer bit-for-bit — identical canonical
//!   bytes, identical [`astrolabe_kernel::KernelAnswer::answer_hash`], zero drift.
//! - A **perturbed vault** produces a divergent answer; the divergence is measured
//!   on the answer's per-node score vector in microunits (`1.0 == 1_000_000`
//!   microunits) and, when it exceeds the registry-declared drift bound (the
//!   blueprint's `1e-3`, i.e. `1000` microunits), the reproduce fails **closed**
//!   with [`crate::REPRODUCE_DRIFT_EXCEEDED`] naming the drift magnitude.
//!
//! The engine is integer-only and deterministic, so `bit_exact` (recorded hash ==
//! re-derived hash) holds **iff** measured drift is exactly zero; a record that
//! violates that invariant is internally contradictory and refused with
//! [`crate::ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT`] rather than laundered into a
//! verified-looking report.

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result};
use astrolabe_kernel::{
    AnswerConfig, AnswerEdge, AnswerNode, AnswerResolution, KernelAnswer, U64KnobDeclaration,
    answer_query,
};

use crate::{
    ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT, AnswerHop, AnswerTrace, Freshness, LedgerPointer,
    REPRODUCE_DRIFT_EXCEEDED, ReproduceReport,
};

/// Schema tag for the persisted recorded-kernel-answer reproduce artifact.
pub const RECORDED_KERNEL_ANSWER_SCHEMA: &str = "astrolabe.recorded_kernel_answer.v1";
/// Knob registry version for the reproduce knobs.
pub const REPRODUCE_KNOB_REGISTRY_VERSION: &str = "astro.provenance.reproduce_knobs.v1";
/// Knob name: the maximum tolerated live re-derivation drift, in microunits.
pub const KNOB_REPRODUCE_DRIFT_BOUND_MICROUNITS: &str =
    "provenance.reproduce.drift_bound_microunits";

/// Microunit scale: `1_000_000` microunits denote `1.0`. Answer scores are on the
/// permille scale (`1000` permille == `1.0`), so a permille value scales to
/// microunits by `1000` (`1 permille == 1e-3 == 1000 microunits`).
pub const MICROUNITS_PER_PERMILLE: u64 = 1_000;

/// Full-scale drift assigned when a live re-derivation diverges *structurally* from
/// the recorded answer (a different node path), which no per-position score
/// comparison can bound: `1.0` on the microunit scale, always above the bound.
pub const STRUCTURAL_DRIFT_MICROUNITS: u64 = 1_000_000;

/// Error code: a reproduce drift-bound override loosened the declared bound.
/// Overrides may only *tighten* (lower) the bound; a looser bound would let a
/// larger, less faithful re-derivation read as reproduced. Fail closed.
pub const ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED: &str =
    "ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED";

/// Error code: a persisted recorded-kernel-answer reproduce artifact failed to
/// parse or is internally malformed. Fail closed rather than reproduce against a
/// corrupt recorded ground truth.
pub const ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT: &str =
    "ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT";

/// The reproduce knobs, registry-declared with bounds (invariant 4).
pub const REPRODUCE_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: REPRODUCE_KNOB_REGISTRY_VERSION,
    name: KNOB_REPRODUCE_DRIFT_BOUND_MICROUNITS,
    // The blueprint pins the reproduce drift bound at 1e-3. On the microunit scale
    // (1.0 == 1_000_000 microunits) that is exactly 1000 microunits, i.e. one
    // permille of answer-score divergence.
    default: 1_000,
    min: 0,
    max: STRUCTURAL_DRIFT_MICROUNITS,
    unit: "microunits",
    source: "docs/astrolabe-blueprint.md#13-provenance",
    rationale: "reproduce drift bound; the blueprint pins 1e-3 as the maximum tolerated divergence between a recorded kernel answer and its live re-derivation, which is 1000 microunits on the 1.0==1_000_000-microunit answer-score scale",
}];

/// Returns the registry-default reproduce drift bound in microunits (`1000` == `1e-3`).
pub fn reproduce_drift_bound_default() -> u64 {
    REPRODUCE_KNOBS
        .iter()
        .find(|knob| knob.name == KNOB_REPRODUCE_DRIFT_BOUND_MICROUNITS)
        .expect("reproduce drift-bound knob is declared")
        .default
}

/// Resolves the effective drift bound, honoring a **tightening-only** override.
///
/// `None` selects the registry default. A `Some(v)` at or below the default
/// tightens the bound and is accepted; a `Some(v)` above the default would loosen
/// the pinned `1e-3` contract and is refused with
/// [`ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED`].
pub fn resolve_drift_bound(override_microunits: Option<u64>) -> Result<u64> {
    let default = reproduce_drift_bound_default();
    match override_microunits {
        None => Ok(default),
        Some(value) if value <= default => Ok(value),
        Some(value) => Err(DomainError::new(
            ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED,
            format!(
                "reproduce drift-bound override {value} microunits loosens the registry-declared bound {default}",
            ),
            "reproduce overrides may only tighten the drift bound; supply a value at or below the declared default, or omit it to use 1e-3",
        )),
    }
}

/// A recorded kernel answer: the frozen re-execution parameters plus the recorded
/// ground-truth answer that a live re-derivation is compared against.
///
/// The `query`, `config` (frozen lens knobs + recorded seeds) drive the live
/// re-execution; the `recorded_*` fields are the ground truth captured at answer
/// time. Re-execution consumes the *current* vault graph (supplied separately at
/// reproduce time), so an unchanged vault re-derives the recorded ground truth
/// bit-for-bit and a perturbed vault diverges from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedKernelAnswer {
    /// Stable answer id (the `get_provenance(mode="reproduce")` subject).
    pub answer_id: String,
    /// The frozen query the answer was assembled for.
    pub query: String,
    /// The frozen answer-path knobs (attenuation, hop budget, hop-score floor).
    pub config: AnswerConfig,
    /// The recorded answer's canonical content-address hash (the pinned digest).
    pub recorded_answer_hash: String,
    /// The recorded total score in permille.
    pub recorded_total_score_permille: u64,
    /// The recorded answer path node ids (entry first, then each hop destination).
    pub recorded_node_ids: Vec<CxId>,
    /// The recorded per-node scores in permille, aligned with `recorded_node_ids`:
    /// entry weight first, then each hop's attenuated score.
    pub recorded_scores_permille: Vec<u64>,
    /// The ledger pointer proving when the answer was recorded (freshness watermark).
    pub ledger: LedgerPointer,
}

impl RecordedKernelAnswer {
    /// Captures a served [`KernelAnswer`] as a recorded reproduce artifact, freezing
    /// the query and the answer-path `config` used to assemble it and recording the
    /// ground-truth hash, total, node path, and per-node scores.
    pub fn from_answer(
        answer_id: impl Into<String>,
        config: AnswerConfig,
        ledger: LedgerPointer,
        answer: &KernelAnswer,
    ) -> Self {
        Self {
            answer_id: answer_id.into(),
            query: answer.query.clone(),
            config,
            recorded_answer_hash: answer.answer_hash.clone(),
            recorded_total_score_permille: answer.total_score_permille,
            recorded_node_ids: answer.answer_node_ids.clone(),
            recorded_scores_permille: answer_score_vector(answer),
            ledger,
        }
    }
}

/// The per-node score vector of a served answer, aligned with `answer_node_ids`:
/// entry weight first, then each hop's attenuated score.
fn answer_score_vector(answer: &KernelAnswer) -> Vec<u64> {
    let mut scores = Vec::with_capacity(answer.hops.len() + 1);
    scores.push(answer.entry_weight_permille);
    for hop in &answer.hops {
        scores.push(hop.hop_score_permille);
    }
    scores
}

/// The live re-derivation drift between a recorded answer and a freshly re-derived
/// [`KernelAnswer`], in microunits.
///
/// A **structural** divergence — the re-derived node path differs from the recorded
/// path — cannot be bounded by any per-position score comparison and returns
/// [`STRUCTURAL_DRIFT_MICROUNITS`] (`1.0`). Otherwise the drift is the maximum
/// absolute per-position score difference converted permille -> microunits, so a
/// one-permille score change measures exactly `1000` microunits (`1e-3`).
pub fn answer_drift_microunits(recorded: &RecordedKernelAnswer, rederived: &KernelAnswer) -> u64 {
    if rederived.answer_node_ids != recorded.recorded_node_ids {
        return STRUCTURAL_DRIFT_MICROUNITS;
    }
    let rederived_scores = answer_score_vector(rederived);
    if rederived_scores.len() != recorded.recorded_scores_permille.len() {
        // Same node ids but a different score-vector length is itself structural.
        return STRUCTURAL_DRIFT_MICROUNITS;
    }
    let max_permille_diff = recorded
        .recorded_scores_permille
        .iter()
        .zip(rederived_scores.iter())
        .map(|(recorded, live)| recorded.abs_diff(*live))
        .max()
        .unwrap_or(0);
    max_permille_diff
        .saturating_mul(MICROUNITS_PER_PERMILLE)
        .min(STRUCTURAL_DRIFT_MICROUNITS)
}

/// Reproduces a recorded kernel answer by **live re-execution** against the current
/// vault graph (`nodes`/`edges`/`matched_ids`) and comparing to the recorded ground
/// truth, enforcing the drift bound.
///
/// Fail-closed behavior:
/// - `Err(REPRODUCE_DRIFT_EXCEEDED)` when the live re-derivation drifts beyond
///   `drift_bound_microunits` (the message names the drift magnitude), or when the
///   current vault no longer grounds the answer at all (an honest refusal on
///   re-execution is unbounded, structural drift).
/// - `Err(ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT)` when the two independent
///   reproduce signals contradict — a bit-exact digest match with nonzero measured
///   drift, or a digest change with zero measured drift.
/// - Any hard integrity error from the answer engine (knob range, ledger-required
///   provenance gate) propagates unchanged.
pub fn reproduce_kernel_answer(
    recorded: &RecordedKernelAnswer,
    nodes: &[AnswerNode],
    edges: &[AnswerEdge],
    matched_ids: &[CxId],
    drift_bound_microunits: u64,
) -> Result<ReproduceReport> {
    let resolution = answer_query(nodes, edges, matched_ids, &recorded.query, &recorded.config)?;
    let rederived = match resolution {
        AnswerResolution::Answered(answer) => answer,
        AnswerResolution::Refused(refusal) => {
            return Err(DomainError::new(
                REPRODUCE_DRIFT_EXCEEDED,
                format!(
                    "answer {} no longer re-derives against the current vault: the answer engine now refuses it ({}); the drift is unbounded (structural, {} microunits)",
                    recorded.answer_id, refusal.code, STRUCTURAL_DRIFT_MICROUNITS
                ),
                "the frozen lenses no longer ground this answer against the current vault; re-anchor the scope or quarantine the answer until it reproduces",
            ));
        }
    };

    let drift_microunits = answer_drift_microunits(recorded, &rederived);
    let bit_exact = rederived.answer_hash == recorded.recorded_answer_hash;

    // The two independent reproduce signals must agree: a bit-exact digest match
    // means the canonical bytes are identical, which forces zero measured drift,
    // and any nonzero drift must accompany a digest change. A record that violates
    // this is internally contradictory (tampered or malformed) and is never
    // laundered into a verified-looking report.
    if bit_exact != (drift_microunits == 0) {
        return Err(DomainError::new(
            ASTRO_PROVENANCE_REPRODUCE_INCONSISTENT,
            format!(
                "answer {} reproduce is inconsistent: digests {} but measured drift is {} microunits",
                recorded.answer_id,
                if bit_exact { "match" } else { "differ" },
                drift_microunits
            ),
            "re-derive the reproduce artifact; a bit-exact digest match must measure zero drift and any drift must accompany a digest change",
        ));
    }

    if drift_microunits > drift_bound_microunits {
        return Err(DomainError::new(
            REPRODUCE_DRIFT_EXCEEDED,
            format!(
                "answer {} live re-derivation drift {} microunits exceeds bound {} microunits (recorded hash {}, current hash {})",
                recorded.answer_id,
                drift_microunits,
                drift_bound_microunits,
                recorded.recorded_answer_hash,
                rederived.answer_hash
            ),
            "rerun with the recorded frozen lenses/seeds against the unchanged vault, or quarantine the answer until reproduction is within the drift bound",
        ));
    }

    Ok(ReproduceReport {
        answer_id: recorded.answer_id.clone(),
        bit_exact,
        drift_microunits,
        drift_bound_microunits,
        recorded_digest: recorded.recorded_answer_hash.clone(),
        current_digest: rederived.answer_hash.clone(),
    })
}

/// Builds a provenance [`AnswerTrace`] from a served kernel answer (#40) so that
/// `get_provenance(mode="answer_trace")` serves the real answer lineage.
///
/// The kernel entry and every hop carry the answer's real provenance references.
/// The kernel answer alone carries **no** fusion-weight or guard-verdict lineage —
/// those come from the fusion and guard layers — so `fusion_weights_ref` and
/// `guard_verdict_ref` are honestly left `None`, which drives the explicit
/// `unprovenanced` warnings in [`crate::get_provenance`]. No link is ever
/// fabricated for a lineage leg the kernel answer does not actually carry.
pub fn answer_trace_from_kernel_answer(
    answer_id: impl Into<String>,
    answer: &KernelAnswer,
    freshness: Freshness,
) -> AnswerTrace {
    let hops = answer
        .hops
        .iter()
        .map(|hop| AnswerHop {
            from_symbol: hop.from_id.to_string(),
            to_symbol: hop.to_id.to_string(),
            ledger: ledger_pointer_from_ref(&hop.ledger_ref),
        })
        .collect();
    AnswerTrace {
        answer_id: answer_id.into(),
        // The entry is always provenanced on a served answer (the engine refuses to
        // serve an unprovenanced entry), so this is a real link, not a fabricated one.
        kernel_entry: Some(ledger_pointer_from_ref(&answer.entry_provenance_ref)),
        hops,
        // Honestly absent — never fabricated. A kernel answer does not carry fusion
        // or guard lineage, so these legs are reported unprovenanced.
        fusion_weights_ref: None,
        guard_verdict_ref: None,
        freshness,
    }
}

/// Parses a kernel answer provenance reference into a [`LedgerPointer`].
///
/// Accepts the canonical `"seq:chain_hash"` form and captures both parts; any other
/// reference is preserved verbatim as the chain hash with sequence `0`, so the
/// recorded reference is never dropped and no sequence is invented for it.
fn ledger_pointer_from_ref(reference: &str) -> LedgerPointer {
    let reference = reference.trim();
    if let Some((seq_text, hash)) = reference.split_once(':')
        && let Ok(seq) = seq_text.parse::<u64>()
        && !hash.trim().is_empty()
    {
        return LedgerPointer::new(seq, hash.trim());
    }
    LedgerPointer::new(0, reference)
}

/// Canonical, deterministic on-disk bytes of a recorded reproduce artifact.
///
/// Line-oriented so it round-trips byte-for-byte through persisted storage; the
/// server persists these bytes at answer time and reads them back to drive the
/// live reproduce. Node ids are lower-hex; scores and the ledger pointer are
/// rendered verbatim.
pub fn recorded_kernel_answer_bytes(recorded: &RecordedKernelAnswer) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(RECORDED_KERNEL_ANSWER_SCHEMA);
    out.push('\n');
    out.push_str("answer_id=");
    out.push_str(&recorded.answer_id);
    out.push('\n');
    out.push_str("query=");
    out.push_str(&recorded.query);
    out.push('\n');
    out.push_str("attenuation=");
    out.push_str(&recorded.config.attenuation_permille.to_string());
    out.push('\n');
    out.push_str("max_hops=");
    out.push_str(&recorded.config.max_hops.to_string());
    out.push('\n');
    out.push_str("min_hop_score=");
    out.push_str(&recorded.config.min_hop_score_permille.to_string());
    out.push('\n');
    out.push_str("recorded_hash=");
    out.push_str(&recorded.recorded_answer_hash);
    out.push('\n');
    out.push_str("recorded_total=");
    out.push_str(&recorded.recorded_total_score_permille.to_string());
    out.push('\n');
    out.push_str("ledger=");
    out.push_str(&recorded.ledger.seq.to_string());
    out.push(':');
    out.push_str(&recorded.ledger.chain_hash);
    out.push('\n');
    for (id, score) in recorded
        .recorded_node_ids
        .iter()
        .zip(recorded.recorded_scores_permille.iter())
    {
        out.push_str("node\t");
        out.push_str(&id.to_string());
        out.push('\t');
        out.push_str(&score.to_string());
        out.push('\n');
    }
    out.into_bytes()
}

/// Parses the canonical on-disk bytes of a recorded reproduce artifact, failing
/// closed with [`ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT`] on any malformation.
pub fn parse_recorded_kernel_answer(bytes: &[u8]) -> Result<RecordedKernelAnswer> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| reproduce_artifact_corrupt("recorded artifact is not UTF-8"))?;
    let mut answer_id = None;
    let mut query = None;
    let mut attenuation = None;
    let mut max_hops = None;
    let mut min_hop_score = None;
    let mut recorded_hash = None;
    let mut recorded_total = None;
    let mut ledger = None;
    let mut node_ids = Vec::new();
    let mut scores = Vec::new();
    let mut schema_seen = false;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("node\t") {
            let mut parts = rest.split('\t');
            let id_text = parts
                .next()
                .ok_or_else(|| reproduce_artifact_corrupt("node line missing id"))?;
            let score_text = parts
                .next()
                .ok_or_else(|| reproduce_artifact_corrupt("node line missing score"))?;
            let id = id_text.parse::<CxId>().map_err(|_| {
                reproduce_artifact_corrupt(format!("node id {id_text:?} is not a valid CxId"))
            })?;
            let score = score_text
                .parse::<u64>()
                .map_err(|_| reproduce_artifact_corrupt("node score is not a valid permille"))?;
            node_ids.push(id);
            scores.push(score);
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            reproduce_artifact_corrupt(format!("line has no key=value: {line:?}"))
        })?;
        match key {
            "schema" => {
                if value != RECORDED_KERNEL_ANSWER_SCHEMA {
                    return Err(reproduce_artifact_corrupt(format!(
                        "recorded artifact schema {value:?} is not {RECORDED_KERNEL_ANSWER_SCHEMA}"
                    )));
                }
                schema_seen = true;
            }
            "answer_id" => answer_id = Some(value.to_string()),
            "query" => query = Some(value.to_string()),
            "attenuation" => attenuation = Some(parse_u64_field("attenuation", value)?),
            "max_hops" => max_hops = Some(parse_u64_field("max_hops", value)?),
            "min_hop_score" => min_hop_score = Some(parse_u64_field("min_hop_score", value)?),
            "recorded_hash" => recorded_hash = Some(value.to_string()),
            "recorded_total" => recorded_total = Some(parse_u64_field("recorded_total", value)?),
            "ledger" => {
                let (seq_text, hash) = value.split_once(':').ok_or_else(|| {
                    reproduce_artifact_corrupt("ledger pointer must be seq:chain_hash")
                })?;
                ledger = Some(LedgerPointer::new(
                    parse_u64_field("ledger seq", seq_text)?,
                    hash,
                ));
            }
            other => {
                return Err(reproduce_artifact_corrupt(format!(
                    "unknown recorded artifact field {other:?}"
                )));
            }
        }
    }
    if !schema_seen {
        return Err(reproduce_artifact_corrupt(
            "recorded artifact missing schema",
        ));
    }
    let config = AnswerConfig {
        attenuation_permille: attenuation
            .ok_or_else(|| reproduce_artifact_corrupt("missing attenuation"))?,
        max_hops: max_hops.ok_or_else(|| reproduce_artifact_corrupt("missing max_hops"))?,
        min_hop_score_permille: min_hop_score
            .ok_or_else(|| reproduce_artifact_corrupt("missing min_hop_score"))?,
    };
    if node_ids.len() != scores.len() {
        return Err(reproduce_artifact_corrupt(
            "recorded node ids and scores are misaligned",
        ));
    }
    Ok(RecordedKernelAnswer {
        answer_id: answer_id.ok_or_else(|| reproduce_artifact_corrupt("missing answer_id"))?,
        query: query.ok_or_else(|| reproduce_artifact_corrupt("missing query"))?,
        config,
        recorded_answer_hash: recorded_hash
            .ok_or_else(|| reproduce_artifact_corrupt("missing recorded_hash"))?,
        recorded_total_score_permille: recorded_total
            .ok_or_else(|| reproduce_artifact_corrupt("missing recorded_total"))?,
        recorded_node_ids: node_ids,
        recorded_scores_permille: scores,
        ledger: ledger.ok_or_else(|| reproduce_artifact_corrupt("missing ledger"))?,
    })
}

fn parse_u64_field(field: &str, value: &str) -> Result<u64> {
    value.trim().parse::<u64>().map_err(|_| {
        reproduce_artifact_corrupt(format!("{field} is not a valid integer: {value:?}"))
    })
}

fn reproduce_artifact_corrupt(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT,
        message.into(),
        "re-record the reproduce artifact from a freshly served kernel answer; refusing rather than reproducing against a corrupt recorded ground truth",
    )
}
