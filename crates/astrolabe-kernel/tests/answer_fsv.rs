//! Full State Verification for grounded kernel answer paths (#40).
//!
//! A hand-computable answer-path golden with the 0.9 per-hop attenuation pinned,
//! the ledger-required provenance gate (a deliberately broken hop / node / entry
//! reference refuses with the documented code and never serves), the honest
//! refusal deficit card (no entry / ungrounded scope), the `answer_trace`
//! round-trip (the served path re-derives bit-for-bit and a tampered path is
//! caught), the knob-range and contract guards, a bit-for-bit reproduce with an
//! on-disk artifact-bytes readback, and the kernel gap report.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_domain::calyx::{CxId, content_address};
use astrolabe_kernel::answer::{
    ASTRO_KERNEL_ANSWER_KNOB_RANGE, ASTRO_KERNEL_ANSWER_NO_ENTRY,
    ASTRO_KERNEL_ANSWER_TRACE_MISMATCH, ASTRO_KERNEL_ANSWER_UNGROUNDED,
    CALYX_KERNEL_ANSWER_LEDGER_REQUIRED, KERNEL_ANSWER_HASH_TAG,
};
use astrolabe_kernel::kernel_build::{KernelArtifact, KernelMember, RecallMeasurement};
use astrolabe_kernel::{
    AnswerConfig, AnswerEdge, AnswerNode, AnswerResolution, KernelBuildConfig,
    answer_artifact_bytes, answer_query, attenuation_at, kernel_gap_report, verify_answer_trace,
    weight_to_permille,
};

// --- fixtures -------------------------------------------------------------

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

/// The golden fixture: entry E(1)->A(2)->B(3)->C(4) with a weaker E->D(5)
/// alternative the best-first walk must reject.
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

fn unique_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "astro-answer-fsv-{}-{}-{}",
        std::process::id(),
        tag,
        id
    ))
}

// --- DoD 1: path scoring golden (0.9 attenuation pinned) -------------------

#[test]
fn golden_answer_path_hop_scores_pinned() {
    // Attenuation is pinned at 0.9: att(1)=900, att(2)=810, att(3)=729.
    assert_eq!(attenuation_at(0, 900), 1000);
    assert_eq!(attenuation_at(1, 900), 900);
    assert_eq!(attenuation_at(2, 900), 810);
    assert_eq!(attenuation_at(3, 900), 729);

    let config = AnswerConfig::with_registry_defaults();
    assert_eq!(
        config.attenuation_permille, 900,
        "0.9 is the pinned default"
    );

    let resolution = answer_query(
        &golden_nodes(),
        &golden_edges(),
        &[cx(1)],
        "how does E work",
        &config,
    )
    .unwrap();
    let AnswerResolution::Answered(answer) = resolution else {
        panic!("golden query must be answered");
    };
    println!(
        "path={:?} hops={:?} total={}",
        answer.answer_node_ids,
        answer
            .hops
            .iter()
            .map(|h| (h.depth, h.edge_weight_permille, h.hop_score_permille))
            .collect::<Vec<_>>(),
        answer.total_score_permille
    );

    // Entry is the grounded, highest-weight match; the best-first walk rejects
    // the weaker E->D(500) edge for E->A(800).
    assert_eq!(answer.entry_id, cx(1));
    assert_eq!(answer.answer_node_ids, vec![cx(1), cx(2), cx(3), cx(4)]);
    assert_eq!(answer.hops.len(), 3);

    // hop_score = edge_weight · 0.9^depth (floored).
    assert_eq!(answer.hops[0].hop_score_permille, 720); // 800 · 0.900
    assert_eq!(answer.hops[1].hop_score_permille, 486); // 600 · 0.810
    assert_eq!(answer.hops[2].hop_score_permille, 656); // 900 · 0.729
    assert_eq!(answer.hops[0].attenuation_permille, 900);
    assert_eq!(answer.hops[1].attenuation_permille, 810);
    assert_eq!(answer.hops[2].attenuation_permille, 729);

    // total = entry weight (1000) + 720 + 486 + 656.
    assert_eq!(answer.total_score_permille, 2862);

    // Every hop is ledger-referenced; ordered provenance = entry + per-hop refs.
    assert_eq!(
        answer.provenance_refs,
        vec!["anchor:E", "ledger:EA", "ledger:AB", "ledger:BC"]
    );

    // B(3) is ungrounded, so the answer trust rolls up to provisional.
    assert_eq!(answer.trust, "provisional");
    assert_eq!(answer.freshness, "fresh");
}

// --- DoD 2: ledger-required gate ------------------------------------------

#[test]
fn broken_hop_ledger_refuses_never_serves_unprovenanced() {
    let config = AnswerConfig::with_registry_defaults();

    // Break the final hop's ledger reference: the multi-hop answer must fail
    // closed rather than serve C without its hop's ledger wiring.
    let mut edges = golden_edges();
    edges[3].ledger_ref = None; // B->C
    let error = answer_query(&golden_nodes(), &edges, &[cx(1)], "q", &config).unwrap_err();
    assert_eq!(error.code(), CALYX_KERNEL_ANSWER_LEDGER_REQUIRED);

    // Empty (whitespace) ledger is treated as missing.
    let mut edges = golden_edges();
    edges[3].ledger_ref = Some("   ".to_string());
    let error = answer_query(&golden_nodes(), &edges, &[cx(1)], "q", &config).unwrap_err();
    assert_eq!(error.code(), CALYX_KERNEL_ANSWER_LEDGER_REQUIRED);
}

#[test]
fn missing_node_provenance_refuses() {
    let config = AnswerConfig::with_registry_defaults();
    let mut nodes = golden_nodes();
    nodes[3].provenance_ref = None; // node C
    let error = answer_query(&nodes, &golden_edges(), &[cx(1)], "q", &config).unwrap_err();
    assert_eq!(error.code(), CALYX_KERNEL_ANSWER_LEDGER_REQUIRED);
}

#[test]
fn missing_entry_provenance_refuses() {
    let config = AnswerConfig::with_registry_defaults();
    let mut nodes = golden_nodes();
    nodes[0].provenance_ref = None; // entry E
    let error = answer_query(&nodes, &golden_edges(), &[cx(1)], "q", &config).unwrap_err();
    assert_eq!(error.code(), CALYX_KERNEL_ANSWER_LEDGER_REQUIRED);
}

// --- DoD 3: honest refusal with per-lens deficit --------------------------

#[test]
fn no_matched_candidate_refuses_with_deficit() {
    let config = AnswerConfig::with_registry_defaults();
    let resolution = answer_query(&golden_nodes(), &golden_edges(), &[], "q", &config).unwrap();
    let AnswerResolution::Refused(refusal) = resolution else {
        panic!("empty match must refuse, not serve");
    };
    assert_eq!(refusal.code, ASTRO_KERNEL_ANSWER_NO_ENTRY);
    assert_eq!(refusal.trust, "provisional");
    // Per-lens deficit shape: both lenses present, both unsatisfied.
    let lenses: Vec<(&str, bool)> = refusal
        .deficits
        .iter()
        .map(|d| (d.lens.as_str(), d.satisfied))
        .collect();
    assert_eq!(
        lenses,
        vec![("entry_point", false), ("grounded_anchor", false)]
    );
}

#[test]
fn ungrounded_scope_refuses_with_deficit() {
    let config = AnswerConfig::with_registry_defaults();
    // B(3) matched but is ungrounded: entry_point satisfied, grounded_anchor not.
    let resolution =
        answer_query(&golden_nodes(), &golden_edges(), &[cx(3)], "q", &config).unwrap();
    let AnswerResolution::Refused(refusal) = resolution else {
        panic!("ungrounded-only match must refuse, not serve an empty answer");
    };
    assert_eq!(refusal.code, ASTRO_KERNEL_ANSWER_UNGROUNDED);
    let lenses: Vec<(&str, bool)> = refusal
        .deficits
        .iter()
        .map(|d| (d.lens.as_str(), d.satisfied))
        .collect();
    assert_eq!(
        lenses,
        vec![("entry_point", true), ("grounded_anchor", false)]
    );
}

// --- DoD 4: answer_trace round-trip (FSV pairing) -------------------------

#[test]
fn served_answer_trace_round_trips_and_catches_tampering() {
    let config = AnswerConfig::with_registry_defaults();
    let AnswerResolution::Answered(answer) =
        answer_query(&golden_nodes(), &golden_edges(), &[cx(1)], "q", &config).unwrap()
    else {
        panic!("must answer");
    };

    // The served path re-derives exactly from its own stored hops.
    verify_answer_trace(&answer).expect("served answer trace round-trips");

    // Tamper with a served hop score: the trace must catch the divergence.
    let mut tampered = (*answer).clone();
    tampered.hops[1].hop_score_permille += 1;
    let error = verify_answer_trace(&tampered).unwrap_err();
    assert_eq!(error.code(), ASTRO_KERNEL_ANSWER_TRACE_MISMATCH);

    // Tamper with the served total: also caught.
    let mut tampered = (*answer).clone();
    tampered.total_score_permille += 1;
    let error = verify_answer_trace(&tampered).unwrap_err();
    assert_eq!(error.code(), ASTRO_KERNEL_ANSWER_TRACE_MISMATCH);
}

// --- DoD 5: contract guards -----------------------------------------------

#[test]
fn out_of_range_knobs_refuse() {
    for bad in [
        AnswerConfig {
            attenuation_permille: 0,
            max_hops: 4,
            min_hop_score_permille: 1,
        },
        AnswerConfig {
            attenuation_permille: 1001,
            max_hops: 4,
            min_hop_score_permille: 1,
        },
        AnswerConfig {
            attenuation_permille: 900,
            max_hops: 0,
            min_hop_score_permille: 1,
        },
    ] {
        let error =
            answer_query(&golden_nodes(), &golden_edges(), &[cx(1)], "q", &bad).unwrap_err();
        assert_eq!(error.code(), ASTRO_KERNEL_ANSWER_KNOB_RANGE);
    }
}

#[test]
fn weight_projection_is_bounded_and_rounded() {
    assert_eq!(weight_to_permille(0.0), 0);
    assert_eq!(weight_to_permille(1.0), 1000);
    assert_eq!(weight_to_permille(0.25), 250); // exact
    assert_eq!(weight_to_permille(0.4567), 457); // rounds .7 up
    assert_eq!(weight_to_permille(0.4564), 456); // rounds .4 down
    assert_eq!(weight_to_permille(2.0), 1000); // clamped
    assert_eq!(weight_to_permille(-1.0), 0); // clamped
}

// --- DoD 6: reproduce bit-for-bit + on-disk readback ----------------------

#[test]
fn answer_reproduces_bit_for_bit_with_on_disk_readback() {
    let config = AnswerConfig::with_registry_defaults();
    let AnswerResolution::Answered(first) =
        answer_query(&golden_nodes(), &golden_edges(), &[cx(1)], "q", &config).unwrap()
    else {
        panic!("must answer");
    };
    let AnswerResolution::Answered(second) =
        answer_query(&golden_nodes(), &golden_edges(), &[cx(1)], "q", &config).unwrap()
    else {
        panic!("must answer");
    };

    // Bit-for-bit: identical answer struct, identical canonical bytes and hash.
    assert_eq!(first, second, "recorded answer re-derives identically");
    let first_bytes = answer_artifact_bytes(&first);
    let second_bytes = answer_artifact_bytes(&second);
    assert_eq!(first_bytes, second_bytes);

    // Independent persisted-state readback: write the canonical bytes to disk,
    // read them back, and recompute the content address — it must match the
    // hash the served answer carries.
    let path = unique_path("artifact");
    fs::write(&path, &first_bytes).unwrap();
    let read_back = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        read_back, first_bytes,
        "artifact bytes survive the round trip"
    );
    let recomputed = content_address([KERNEL_ANSWER_HASH_TAG.to_vec(), read_back]);
    let recomputed_hex = hex_lower(&recomputed);
    println!(
        "answer_hash={} readback={}",
        first.answer_hash, recomputed_hex
    );
    assert_eq!(
        recomputed_hex, first.answer_hash,
        "hash re-derives from disk bytes"
    );
}

// --- gap report -----------------------------------------------------------

#[test]
fn gap_report_lists_ungrounded_members() {
    // A hand-built kernel artifact: members 1 & 4 grounded, 2 & 3 gaps.
    let members = vec![
        member(1, true),
        member(2, false),
        member(3, false),
        member(4, true),
    ];
    let artifact = KernelArtifact {
        schema: "astrolabe.kernel.v1".to_string(),
        scope_id: "scope:test".to_string(),
        knob_registry_version: "astro.kernel.build_knobs.v1".to_string(),
        config: KernelBuildConfig::with_registry_defaults(),
        node_count: 4,
        candidate_count: 4,
        fvs_count: 4,
        support_count: 0,
        member_count: 4,
        betweenness_exact: true,
        anchor_grounded: true,
        ungrounded_reason: None,
        recall: RecallMeasurement {
            recalled: 4,
            total: 4,
            permille: 1000,
            gated: true,
        },
        members,
        members_hash: "deadbeef".to_string(),
        freshness: "fresh".to_string(),
        trust: "provisional".to_string(),
    };

    let report = kernel_gap_report(&artifact);
    println!(
        "member_count={} gap_count={} gaps={:?}",
        report.member_count,
        report.gap_count,
        report.gaps.iter().map(|g| g.id).collect::<Vec<_>>()
    );
    assert_eq!(report.member_count, 4);
    assert_eq!(report.grounded_count, 2);
    assert_eq!(report.gap_count, 2);
    assert_eq!(report.grounded_fraction_permille, 500); // 2/4
    assert_eq!(report.recall_permille, 1000);
    assert_eq!(
        report.gaps.iter().map(|g| g.id).collect::<Vec<_>>(),
        vec![cx(2), cx(3)]
    );
    // Gaps present -> provisional even with an anchor in scope.
    assert_eq!(report.trust, "provisional");
}

fn member(n: u16, grounded: bool) -> KernelMember {
    KernelMember {
        id: cx(n),
        score_permille: 500,
        degree: 2,
        betweenness_permille: 100,
        groundedness_permille: if grounded { 800 } else { 0 },
        frequency: 1,
        grounded,
        in_fvs: true,
        support_added: false,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}
