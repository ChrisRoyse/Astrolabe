//! Full State Verification for the live reproduce path (#67 DoD reproduce mode).
//!
//! Builds a real grounded kernel answer with the #40 answer engine, records it as
//! a reproduce artifact, persists the artifact bytes to disk and reads them back
//! independently, then live-re-executes:
//!   - unchanged vault  -> bit-exact, zero drift;
//!   - within-bound perturbation -> served, measured drift at the 1e-3 bound;
//!   - over-bound perturbation -> REPRODUCE_DRIFT_EXCEEDED naming the magnitude;
//!   - structural perturbation / ungrounded re-execution -> structural drift refusal.
//!
//! Plus the answer_trace-from-kernel-answer honesty (unprovenanced fusion/guard,
//! never a fabricated link) and the unknown-subject refusal shape.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_domain::calyx::CxId;
use astrolabe_kernel::{
    AnswerConfig, AnswerEdge, AnswerNode, AnswerResolution, KernelAnswer, answer_query,
};
use astrolabe_provenance::{
    ASTRO_PROVENANCE_NOT_FOUND, ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT,
    ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED, ChainStatus, ChainVerification, Freshness,
    LedgerPointer, ProvenancePayload, ProvenanceQuery, ProvenanceStore, REPRODUCE_DRIFT_EXCEEDED,
    RecordedKernelAnswer, SymbolLineage, answer_trace_from_kernel_answer, get_provenance,
    parse_recorded_kernel_answer, recorded_kernel_answer_bytes, reproduce_drift_bound_default,
    reproduce_kernel_answer, resolve_drift_bound,
};
use std::collections::BTreeMap;

// --- fixtures (mirror the #40 answer-engine golden) -----------------------

fn cx(n: u16) -> CxId {
    let mut bytes = [0_u8; 16];
    bytes[0] = (n >> 8) as u8;
    bytes[1] = (n & 0xff) as u8;
    CxId::from_bytes(bytes)
}

fn node(n: u16, grounded: bool, prov: Option<&str>, weight: u64) -> AnswerNode {
    AnswerNode::new(
        cx(n),
        format!("sym{n}"),
        grounded,
        prov.map(str::to_string),
        weight,
    )
}

fn edge(a: u16, b: u16, weight: u64, ledger: Option<&str>) -> AnswerEdge {
    AnswerEdge::new(cx(a), cx(b), weight, ledger.map(str::to_string))
}

fn golden_nodes() -> Vec<AnswerNode> {
    vec![
        node(1, true, Some("anchor:E"), 1000),
        node(2, true, Some("prov:A"), 700),
        node(3, false, Some("prov:B"), 400),
        node(4, true, Some("prov:C"), 900),
        node(5, false, Some("prov:D"), 300),
    ]
}

fn golden_edges() -> Vec<AnswerEdge> {
    vec![
        edge(1, 2, 800, Some("ledger:EA")),
        edge(1, 5, 500, Some("ledger:ED")),
        edge(2, 3, 600, Some("ledger:AB")),
        edge(3, 4, 900, Some("ledger:BC")),
    ]
}

fn answered(nodes: &[AnswerNode], edges: &[AnswerEdge], matched: &[CxId]) -> KernelAnswer {
    let config = AnswerConfig::with_registry_defaults();
    match answer_query(nodes, edges, matched, "how does E work", &config).unwrap() {
        AnswerResolution::Answered(answer) => *answer,
        AnswerResolution::Refused(refusal) => panic!("fixture must answer, got {}", refusal.code),
    }
}

fn recorded_golden() -> RecordedKernelAnswer {
    let answer = answered(&golden_nodes(), &golden_edges(), &[cx(1)]);
    RecordedKernelAnswer::from_answer(
        "answer:golden-1",
        AnswerConfig::with_registry_defaults(),
        LedgerPointer::new(42, "chainhash-golden"),
        &answer,
    )
}

fn unique_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "astro-repro-fsv-{}-{}-{}",
        std::process::id(),
        tag,
        id
    ))
}

// --- DoD: reproduce artifact round-trips through disk ----------------------

#[test]
fn recorded_artifact_round_trips_through_disk() {
    let recorded = recorded_golden();
    let bytes = recorded_kernel_answer_bytes(&recorded);

    // Independent persisted-state readback: write, read, parse.
    let path = unique_path("artifact");
    fs::write(&path, &bytes).unwrap();
    let read_back = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        read_back, bytes,
        "recorded artifact bytes survive the round trip"
    );

    let parsed = parse_recorded_kernel_answer(&read_back).expect("parse recorded artifact");
    assert_eq!(
        parsed, recorded,
        "parsed artifact equals the recorded ground truth"
    );

    // The recorded score vector is entry weight + per-hop scores (golden: 1000,720,486,656).
    assert_eq!(parsed.recorded_scores_permille, vec![1000, 720, 486, 656]);
    assert_eq!(parsed.recorded_total_score_permille, 2862);
}

// --- DoD: unchanged vault reproduces bit-for-bit ---------------------------

#[test]
fn unchanged_vault_reproduces_bit_exact() {
    // Read the recorded ground truth back from disk, then live-re-execute against
    // the same (unchanged) vault graph.
    let recorded = recorded_golden();
    let bytes = recorded_kernel_answer_bytes(&recorded);
    let path = unique_path("bitexact");
    fs::write(&path, &bytes).unwrap();
    let recorded = parse_recorded_kernel_answer(&fs::read(&path).unwrap()).unwrap();
    fs::remove_file(&path).unwrap();

    let bound = reproduce_drift_bound_default();
    assert_eq!(
        bound, 1_000,
        "the pinned reproduce drift bound is 1e-3 = 1000 microunits"
    );

    let report =
        reproduce_kernel_answer(&recorded, &golden_nodes(), &golden_edges(), &[cx(1)], bound)
            .expect("unchanged vault reproduces");
    assert!(report.bit_exact, "unchanged vault is bit-exact");
    assert_eq!(report.drift_microunits, 0);
    assert_eq!(report.recorded_digest, report.current_digest);
    assert_eq!(report.answer_id, "answer:golden-1");
}

// --- DoD: within-bound perturbation is served with a measured drift --------

#[test]
fn within_bound_perturbation_is_served_with_measured_drift() {
    let recorded = recorded_golden();
    // Bump edge E->A weight 800 -> 802: hop-0 score 720 -> 721 (+1 permille), a
    // measured drift of exactly 1000 microunits == the 1e-3 bound (not exceeded).
    let mut edges = golden_edges();
    edges[0] = edge(1, 2, 802, Some("ledger:EA"));

    let report = reproduce_kernel_answer(
        &recorded,
        &golden_nodes(),
        &edges,
        &[cx(1)],
        reproduce_drift_bound_default(),
    )
    .expect("within-bound perturbation reproduces");
    assert_eq!(
        report.drift_microunits, 1_000,
        "one-permille score change == 1e-3"
    );
    assert!(!report.bit_exact, "a score change is not bit-exact");
    assert_ne!(report.recorded_digest, report.current_digest);
}

// --- DoD: over-bound perturbation fails closed naming the drift -------------

#[test]
fn perturbed_vault_exceeds_drift_bound_naming_magnitude() {
    let recorded = recorded_golden();
    // Bump edge E->A weight 800 -> 900: hop-0 score 720 -> 810 (+90 permille) =
    // 90000 microunits, far beyond the 1000-microunit bound.
    let mut edges = golden_edges();
    edges[0] = edge(1, 2, 900, Some("ledger:EA"));

    let error = reproduce_kernel_answer(
        &recorded,
        &golden_nodes(),
        &edges,
        &[cx(1)],
        reproduce_drift_bound_default(),
    )
    .expect_err("over-bound perturbation must fail closed");
    assert_eq!(error.code(), REPRODUCE_DRIFT_EXCEEDED);
    assert!(
        error.message().contains("90000"),
        "the refusal names the drift magnitude: {}",
        error.message()
    );
    assert!(!error.remediation().is_empty());
}

// --- DoD: structural / ungrounded re-execution is unbounded drift ----------

#[test]
fn structural_repath_exceeds_bound() {
    let recorded = recorded_golden();
    // Make E->D(999) the strongest edge out of the entry: the path repaths to
    // [E, D] instead of [E, A, B, C]. No per-position score bounds this, so it is
    // structural drift (1.0) and fails closed.
    let mut edges = golden_edges();
    edges[1] = edge(1, 5, 999, Some("ledger:ED"));

    let error = reproduce_kernel_answer(
        &recorded,
        &golden_nodes(),
        &edges,
        &[cx(1)],
        reproduce_drift_bound_default(),
    )
    .expect_err("structural repath must fail closed");
    assert_eq!(error.code(), REPRODUCE_DRIFT_EXCEEDED);
    assert!(
        error.message().contains("1000000"),
        "structural drift is 1.0: {}",
        error.message()
    );
}

#[test]
fn ungrounded_reexecution_is_structural_drift_refusal() {
    let recorded = recorded_golden();
    // The current vault matches nothing (the kernel-first search finds no entry):
    // the answer engine honestly refuses, which is unbounded structural drift.
    let error = reproduce_kernel_answer(
        &recorded,
        &golden_nodes(),
        &golden_edges(),
        &[],
        reproduce_drift_bound_default(),
    )
    .expect_err("an answer that no longer grounds must fail closed");
    assert_eq!(error.code(), REPRODUCE_DRIFT_EXCEEDED);
    assert!(error.message().contains("no longer re-derives"));
}

// --- DoD: drift-bound override is tightening-only --------------------------

#[test]
fn drift_bound_override_is_tightening_only() {
    // Default is the pinned 1e-3.
    assert_eq!(resolve_drift_bound(None).unwrap(), 1_000);
    // Tightening (lower) is accepted.
    assert_eq!(resolve_drift_bound(Some(500)).unwrap(), 500);
    assert_eq!(resolve_drift_bound(Some(0)).unwrap(), 0);
    // Loosening (higher) is refused fail-closed.
    let error = resolve_drift_bound(Some(2_000)).expect_err("looser bound must be refused");
    assert_eq!(error.code(), ASTRO_PROVENANCE_REPRODUCE_BOUND_LOOSENED);
    assert!(!error.remediation().is_empty());
}

#[test]
fn tightened_bound_flips_a_within_default_drift_to_exceeded() {
    let recorded = recorded_golden();
    let mut edges = golden_edges();
    edges[0] = edge(1, 2, 802, Some("ledger:EA")); // drift 1000 microunits

    // Under the default bound (1000) this reproduces.
    assert!(reproduce_kernel_answer(&recorded, &golden_nodes(), &edges, &[cx(1)], 1_000).is_ok());
    // Tighten to 500: the same 1000-microunit drift now exceeds the bound.
    let error = reproduce_kernel_answer(&recorded, &golden_nodes(), &edges, &[cx(1)], 500)
        .expect_err("tightened bound rejects the drift");
    assert_eq!(error.code(), REPRODUCE_DRIFT_EXCEEDED);
}

// --- DoD: corrupt recorded artifact fails closed ---------------------------

#[test]
fn corrupt_recorded_artifact_fails_closed() {
    let recorded = recorded_golden();
    let mut bytes = recorded_kernel_answer_bytes(&recorded);
    // Corrupt the recorded hash line's key so the field is unknown.
    let text = String::from_utf8(bytes.clone())
        .unwrap()
        .replace("recorded_hash=", "bogus_field=");
    bytes = text.into_bytes();
    let error = parse_recorded_kernel_answer(&bytes).expect_err("corrupt artifact must refuse");
    assert_eq!(error.code(), ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT);

    // Not even UTF-8: also refused.
    let error =
        parse_recorded_kernel_answer(&[0xff, 0xfe, 0x00]).expect_err("non-utf8 must refuse");
    assert_eq!(error.code(), ASTRO_PROVENANCE_REPRODUCE_ARTIFACT_CORRUPT);
}

// --- DoD: answer_trace from kernel answer is honestly unprovenanced --------

#[test]
fn answer_trace_from_kernel_answer_never_fabricates_fusion_or_guard() {
    let answer = answered(&golden_nodes(), &golden_edges(), &[cx(1)]);
    let trace = answer_trace_from_kernel_answer("answer:golden-1", &answer, Freshness::fresh(42));

    // The kernel entry and every hop carry the answer's real provenance references.
    assert!(
        trace.kernel_entry.is_some(),
        "the served entry is provenanced"
    );
    assert_eq!(trace.hops.len(), 3);
    // Hop ledger references are the answer's real per-hop refs, not invented.
    assert_eq!(trace.hops[0].ledger.chain_hash, "ledger:EA");
    assert_eq!(trace.hops[2].ledger.chain_hash, "ledger:BC");
    // Fusion and guard lineage are honestly absent — NEVER fabricated.
    assert!(
        trace.fusion_weights_ref.is_none(),
        "no fabricated fusion link"
    );
    assert!(
        trace.guard_verdict_ref.is_none(),
        "no fabricated guard link"
    );

    // Served through get_provenance, the missing legs surface as explicit
    // `unprovenanced` warnings and the envelope drops out of "verified".
    let store = store_with_answer_trace(&trace);
    let response = get_provenance(
        &store,
        &ProvenanceQuery::new("answer_trace", Some("answer:golden-1")),
    )
    .expect("answer_trace served");
    let unprovenanced: Vec<&str> = response
        .warnings
        .iter()
        .filter(|w| w.code == "unprovenanced")
        .map(|w| w.message.as_str())
        .collect();
    assert_eq!(
        unprovenanced.len(),
        2,
        "exactly the fusion + guard legs are unprovenanced"
    );
    assert!(unprovenanced.iter().any(|m| m.contains("fusion")));
    assert!(unprovenanced.iter().any(|m| m.contains("guard")));
    assert_eq!(response.trust, "provisional");
    // The served payload is the real answer trace we built (no fabricated refs).
    match &response.payload {
        ProvenancePayload::AnswerTrace(served) => {
            assert!(served.fusion_weights_ref.is_none());
            assert!(served.guard_verdict_ref.is_none());
            assert_eq!(served.hops.len(), 3);
        }
        other => panic!("expected answer_trace payload, got {other:?}"),
    }
}

// --- DoD: unknown subject refused {code,message,remediation} ---------------

#[test]
fn unknown_answer_id_reproduce_refuses_with_remediation() {
    let store = empty_store();
    let error = get_provenance(
        &store,
        &ProvenanceQuery::new("reproduce", Some("answer:nope")),
    )
    .expect_err("unknown reproduce subject must refuse");
    assert_eq!(error.code(), ASTRO_PROVENANCE_NOT_FOUND);
    assert!(!error.message().is_empty());
    assert!(!error.remediation().is_empty());

    // answer_trace for an unknown subject is likewise refused, not fabricated.
    let error = get_provenance(
        &store,
        &ProvenanceQuery::new("answer_trace", Some("answer:nope")),
    )
    .expect_err("unknown answer_trace subject must refuse");
    assert_eq!(error.code(), ASTRO_PROVENANCE_NOT_FOUND);
    assert!(!error.remediation().is_empty());
}

// --- store helpers --------------------------------------------------------

fn empty_store() -> ProvenanceStore {
    ProvenanceStore {
        vault_fingerprint: "fp".to_string(),
        ledger_head: LedgerPointer::new(42, "head"),
        chain: ChainVerification {
            status: ChainStatus::Intact,
            checked_from: 0,
            checked_end: 43,
            provenance: LedgerPointer::new(42, "head"),
        },
        symbols: BTreeMap::new(),
        answers: BTreeMap::new(),
        reproductions: BTreeMap::new(),
        manifests: BTreeMap::new(),
    }
}

fn store_with_answer_trace(trace: &astrolabe_provenance::AnswerTrace) -> ProvenanceStore {
    let mut store = empty_store();
    store.answers.insert(trace.answer_id.clone(), trace.clone());
    // A symbol so the store is non-empty in a realistic shape (unused by the assert).
    store.symbols.insert(
        "sym1".to_string(),
        SymbolLineage {
            symbol_id: "sym1".to_string(),
            versions: vec![],
        },
    );
    store
}
