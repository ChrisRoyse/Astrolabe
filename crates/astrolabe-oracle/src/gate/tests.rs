//! Honesty-gate and failure-mode catalog tests (issue #52).
//!
//! Fixtures are hand-computable: sufficiency cards and occurrence records are
//! constructed with exact bit/count values so each refusal is checked against a
//! pre-computed expectation, and the no-ungated-confidence sweep drives the real
//! `predict_impact` surface.

use super::*;

use std::collections::BTreeMap;

use astrolabe_assay::{DeficitSuggestedAction, SlotDeficit, SufficiencyCard};
use astrolabe_domain::TrustTag;
use calyx_core::CxId;

use crate::corpus::OccurrenceRecord;
use crate::predict::{
    ConsequenceEdge, ConsequenceEdgeKind, ConsequenceGraph, ImpactOutcome, OracleEvidence,
    PredictConfig, PredictRequest, grounded_risk, predict_impact,
};

fn cx(byte: u8) -> CxId {
    CxId::from_bytes([byte; 16])
}

/// A single-candidate grounded occurrence record (credit 1.0, Trusted source).
fn rec(subject: CxId, change_id: &str, passed: bool) -> OccurrenceRecord {
    OccurrenceRecord {
        subject,
        change_id: change_id.to_string(),
        source: format!("ci:test:{change_id}"),
        change_ts: 1_000,
        outcome_ts: 4_600,
        lag_s: 3_600,
        decay_weight: 1.0,
        credit: 1.0,
        passed,
        candidate_count: 1,
        trust: TrustTag::Trusted,
    }
}

/// A hand-built insufficient sufficiency card with one routed slot deficit.
fn insufficient_card(
    axis: &str,
    panel_bits: f64,
    entropy_bits: f64,
    slot: &str,
    marginal_bits: f64,
    action: DeficitSuggestedAction,
) -> SufficiencyCard {
    let deficit = (entropy_bits - panel_bits).max(0.0);
    SufficiencyCard {
        axis: axis.to_string(),
        axis_entropy_bits: entropy_bits,
        panel_bits,
        sufficient: false,
        deficit_bits: deficit,
        deficits: vec![SlotDeficit {
            slot: slot.to_string(),
            marginal_bits,
            deficit_bits: deficit,
            action,
        }],
        trust: TrustTag::Provisional,
    }
}

fn sufficient_card(axis: &str) -> SufficiencyCard {
    SufficiencyCard {
        axis: axis.to_string(),
        axis_entropy_bits: 1.0,
        panel_bits: 1.5,
        sufficient: true,
        deficit_bits: 0.0,
        deficits: Vec::new(),
        trust: TrustTag::Trusted,
    }
}

// ------------------------------------------------------------------
// Knob registry sanity (standing invariant 4)
// ------------------------------------------------------------------

#[test]
fn every_gate_knob_declares_bounds_that_contain_its_default() {
    assert!(!ORACLE_GATE_KNOBS.is_empty());
    for knob in ORACLE_GATE_KNOBS {
        assert_eq!(knob.registry_version, ORACLE_GATE_KNOB_REGISTRY_VERSION);
        assert!(knob.min <= knob.max, "{knob:?}");
        assert!(knob.accepts(knob.default), "{knob:?}");
        assert!(!knob.unit.is_empty(), "{knob:?}");
        assert!(!knob.source.is_empty(), "{knob:?}");
        assert!(!knob.rationale.is_empty(), "{knob:?}");
    }
    // The flakiness floor is a probability strictly inside (0, 1).
    assert!(gate_knob(ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB).max < 1000);
    GateConfig::default().validate().expect("default validates");
}

#[test]
fn out_of_bounds_gate_config_fails_closed() {
    let bad = GateConfig {
        flaky_self_consistency_permille: 5_000, // > max 999
        ..GateConfig::default()
    };
    let err = honesty_gate(&EvidenceSnapshot::from_records(&[]), &bad).unwrap_err();
    assert_eq!(err.code, ASTRO_ORACLE_INSUFFICIENT);
}

// ------------------------------------------------------------------
// DoD 1: negative-path suite — 20 planted-insufficient panels MUST refuse
// via the gate in every oracle path.
// ------------------------------------------------------------------

#[test]
fn twenty_insufficient_panels_all_refuse_via_the_gate() {
    let config = GateConfig::default();
    let actions = [
        DeficitSuggestedAction::AddOutcomeAnchor,
        DeficitSuggestedAction::ProposeLens,
        DeficitSuggestedAction::IncreaseSamples,
    ];
    let mut refused = 0usize;
    for i in 0..20u32 {
        // Each planted panel measures strictly below its outcome entropy.
        let axis = format!("axis_{i}");
        let panel_bits = (i as f64) * 0.05; // 0.0 .. 0.95
        let entropy_bits = panel_bits + 0.5 + (i as f64) * 0.03; // always > panel
        let action = actions[(i as usize) % actions.len()];
        let card = insufficient_card(
            &axis,
            panel_bits,
            entropy_bits,
            &format!("slot_{i}"),
            (i as f64) * 0.01,
            action,
        );
        // Path A: a measured panel with a sufficiency card.
        let snap =
            EvidenceSnapshot::from_records(&[rec(cx(1), "c0", false), rec(cx(1), "c1", false)])
                .with_sufficiency(card);
        let verdict = honesty_gate(&snap, &config).unwrap();
        let refusal = verdict.refusal().expect("insufficient panel must refuse");
        assert_eq!(refusal.code, ASTRO_ORACLE_INSUFFICIENT);
        assert_eq!(refusal.degraded_mode, DegradedMode::Refuse);
        assert!(!refusal.deficits.is_empty(), "refusal itemizes the deficit");
        let d = &refusal.deficits[0];
        assert_eq!(d.axis, axis, "deficit names the axis");
        assert!(d.missing_bits > 0.0, "deficit reports missing bits");
        assert!(
            !d.bootstrap.is_empty(),
            "deficit carries a bootstrap command"
        );
        refused += 1;
    }
    assert_eq!(refused, 20, "all 20 planted-insufficient panels refused");
}

#[test]
fn zero_evidence_refuses_via_both_gate_and_predict_impact() {
    // The raw-occurrence path: no grounded history at all. Both the gate and the
    // predict_impact tool must refuse rather than guess.
    let gate_cfg = GateConfig::default();
    let snap = EvidenceSnapshot::from_records(&[]);
    let refusal = honesty_gate(&snap, &gate_cfg)
        .unwrap()
        .refusal()
        .expect("no evidence must refuse")
        .clone();
    assert_eq!(refusal.code, ASTRO_ORACLE_INSUFFICIENT);
    assert_eq!(
        refusal.deficits[0].lens,
        ORACLE_GATE_SENSOR_DIRECT_CHANGE_HISTORY
    );

    // predict_impact over a zero-history seed also refuses.
    let predict_cfg = PredictConfig::default();
    let evidence = OracleEvidence::from_occurrences(&[]);
    let graph = ConsequenceGraph::from_edges(&[ConsequenceEdge {
        from: cx(5),
        to: cx(6),
        kind: ConsequenceEdgeKind::Calls,
    }])
    .unwrap();
    let request = PredictRequest {
        seeds: vec![cx(5)],
        cohort_peers: BTreeMap::new(),
    };
    let outcome = predict_impact(&graph, &evidence, &request, &predict_cfg).unwrap();
    assert!(
        matches!(outcome, ImpactOutcome::Insufficient(_)),
        "predict_impact refuses a zero-history seed"
    );
}

// ------------------------------------------------------------------
// DoD 2: deficit actionability — golden-tested refusal text.
// ------------------------------------------------------------------

#[test]
fn deficit_text_names_axis_missing_bits_and_bootstrap_command_golden() {
    let config = GateConfig::default();
    // panel 0.25 bits vs H 1.00 bits => 0.75 bits short, routed to AddOutcomeAnchor.
    let card = insufficient_card(
        "test_pass",
        0.25,
        1.0,
        "churn",
        0.1,
        DeficitSuggestedAction::AddOutcomeAnchor,
    );
    let snap = EvidenceSnapshot::from_records(&[rec(cx(1), "c0", false), rec(cx(1), "c1", false)])
        .with_sufficiency(card);
    let refusal = honesty_gate(&snap, &config)
        .unwrap()
        .refusal()
        .unwrap()
        .clone();
    let d = &refusal.deficits[0];
    assert_eq!(d.axis, "test_pass");
    assert_eq!(d.lens, "churn");
    assert!((d.have_bits - 0.1).abs() < 1e-12);
    assert!((d.missing_bits - 0.75).abs() < 1e-12);
    assert!((d.need_bits - 0.85).abs() < 1e-12);
    // Golden text: names the axis, the slot, the bits, and a concrete command.
    assert_eq!(
        d.bootstrap,
        "anchor_outcome axis=test_pass slot=churn: add grounded outcomes to close ~0.750 bits of the sufficiency deficit"
    );

    // ProposeLens routes to a lens-proposal command; IncreaseSamples to sampling.
    let propose = insufficient_card(
        "test_pass",
        0.0,
        0.5,
        "dead_lens",
        0.0,
        DeficitSuggestedAction::ProposeLens,
    );
    let snap = EvidenceSnapshot::from_records(&[rec(cx(1), "c0", false), rec(cx(1), "c1", false)])
        .with_sufficiency(propose);
    let r = honesty_gate(&snap, &config)
        .unwrap()
        .refusal()
        .unwrap()
        .clone();
    assert_eq!(
        r.deficits[0].bootstrap,
        "propose_lens axis=test_pass slot=dead_lens: the existing lens carries no usable signal (~0.500 bits short); add a new lens"
    );
}

// ------------------------------------------------------------------
// DoD 3: no-ungated-confidence sweep — every served confidence carries a
// ceiling < 1.0 and a trust tag; a bare/over-ceiling value is refused.
// ------------------------------------------------------------------

#[test]
fn gated_confidence_refuses_every_ungated_construction() {
    // Ceiling at or above 1.0 is refused (no served claim may be certain).
    assert_eq!(
        GatedConfidence::new(0.9, 1.0, TrustTag::Trusted)
            .unwrap_err()
            .code,
        ASTRO_ORACLE_UNGATED_CONFIDENCE
    );
    // Value above its ceiling is refused (the claim is ungated).
    assert_eq!(
        GatedConfidence::new(0.95, 0.9, TrustTag::Trusted)
            .unwrap_err()
            .code,
        ASTRO_ORACLE_UNGATED_CONFIDENCE
    );
    // Non-finite value is refused.
    assert_eq!(
        GatedConfidence::new(f64::NAN, 0.9, TrustTag::Trusted)
            .unwrap_err()
            .code,
        ASTRO_ORACLE_UNGATED_CONFIDENCE
    );
    // Negative value is refused.
    assert!(GatedConfidence::new(-0.1, 0.9, TrustTag::Trusted).is_err());
    // A properly gated value carries its ceiling and trust.
    let g = GatedConfidence::new(0.8, 0.99, TrustTag::Trusted).unwrap();
    assert_eq!(g.value(), 0.8);
    assert_eq!(g.ceiling(), 0.99);
    assert!(g.ceiling() < 1.0);
    assert_eq!(g.trust(), TrustTag::Trusted);
}

#[test]
fn predict_impact_surface_serves_only_gated_confidences() {
    // Sweep many evidence shapes through the real predict_impact surface and
    // assert every served consequence is representable as a GatedConfidence
    // (ceiling < 1.0, value <= ceiling, trust tag present) — a bare confidence
    // would fail the wrap.
    let config = PredictConfig::default();
    for n_fail in 0..=8usize {
        for n_pass in 0..=8usize {
            if n_fail + n_pass == 0 {
                continue;
            }
            let mut records = Vec::new();
            for i in 0..6 {
                records.push(rec(cx(1), &format!("s{i}"), i < 4));
            }
            for i in 0..n_fail {
                records.push(rec(cx(2), &format!("bf{i}"), false));
            }
            for i in 0..n_pass {
                records.push(rec(cx(2), &format!("bp{i}"), true));
            }
            let evidence = OracleEvidence::from_occurrences(&records);
            let graph = ConsequenceGraph::from_edges(&[ConsequenceEdge {
                from: cx(1),
                to: cx(2),
                kind: ConsequenceEdgeKind::Calls,
            }])
            .unwrap();
            let request = PredictRequest {
                seeds: vec![cx(1)],
                cohort_peers: BTreeMap::new(),
            };
            let ImpactOutcome::Grounded(pred) =
                predict_impact(&graph, &evidence, &request, &config).unwrap()
            else {
                panic!("seed cx1 is strongly grounded");
            };
            let gated = pred
                .gated_confidences(&config)
                .expect("every served confidence is gatable");
            assert_eq!(gated.len(), pred.consequences.len());
            for (_, g) in &gated {
                assert!(g.ceiling() < 1.0, "served ceiling is < 1.0");
                assert!(g.value() <= g.ceiling() + 1e-9);
                assert!(g.value() < 1.0);
            }
        }
    }
}

#[test]
fn detect_changes_risk_is_served_as_a_gated_confidence() {
    // Both the grounded and the hop-fallback risk paths serve through the gated
    // type, so a detect_changes risk is never a bare number.
    let config = PredictConfig::default();
    let mut records = Vec::new();
    for i in 0..4 {
        records.push(rec(cx(1), &format!("c{i}"), true));
    }
    for i in 0..2 {
        records.push(rec(cx(1), &format!("f{i}"), false));
    }
    let evidence = OracleEvidence::from_occurrences(&records);
    let grounded = grounded_risk(&evidence, cx(1), 0.9, &config).unwrap();
    let g = grounded.gated().expect("grounded risk is gatable");
    assert!(g.ceiling() < 1.0 && g.value() < 1.0);
    assert_eq!(g.trust(), grounded.trust);

    // Ungrounded fallback also gates.
    let empty = OracleEvidence::from_occurrences(&[]);
    let fallback = grounded_risk(&empty, cx(9), 0.42, &config).unwrap();
    let gf = fallback.gated().expect("fallback risk is gatable");
    assert_eq!(gf.trust(), TrustTag::Provisional);
    assert!((gf.value() - 0.42).abs() < 1e-12);
}

// ------------------------------------------------------------------
// Failure-mode catalog: detection predicates (positive + negative).
// ------------------------------------------------------------------

#[test]
fn sufficient_panel_opens_the_gate() {
    let config = GateConfig::default();
    // Grounded, recurring, self-consistent, sufficient panel => Grounded.
    let snap = EvidenceSnapshot::from_records(&[
        rec(cx(1), "c0", false),
        rec(cx(1), "c1", false),
        rec(cx(1), "c2", false),
    ])
    .with_sufficiency(sufficient_card("test_pass"))
    .with_backtest(true);
    let verdict = honesty_gate(&snap, &config).unwrap();
    assert!(
        verdict.is_grounded(),
        "sufficient grounded panel opens the gate"
    );
    assert!(verdict.refusal().is_none());
}

#[test]
fn flaky_evidence_fires_only_when_self_consistency_is_below_floor() {
    let config = GateConfig::default();
    // 3 fails on distinct changes + 3 passes on distinct changes: pairwise
    // agreement = (C(3,2)+C(3,2))/C(6,2) = (3+3)/15 = 0.4 < 0.5 => flaky.
    let flaky = EvidenceSnapshot::from_records(&[
        rec(cx(1), "a", false),
        rec(cx(1), "b", false),
        rec(cx(1), "c", false),
        rec(cx(1), "d", true),
        rec(cx(1), "e", true),
        rec(cx(1), "f", true),
    ]);
    assert!((flaky.self_consistency - 0.4).abs() < 1e-12);
    let refusal = honesty_gate(&flaky, &config)
        .unwrap()
        .refusal()
        .unwrap()
        .clone();
    assert_eq!(refusal.code, ASTRO_ORACLE_FLAKY_EVIDENCE);
    assert_eq!(refusal.degraded_mode, DegradedMode::Refuse);

    // 5 fails + 1 pass across distinct changes: agreement = (C(5,2)+0)/C(6,2) =
    // 10/15 = 0.667 >= 0.5 => not flaky (fires NO_RECURRENCE? no: 5 distinct
    // failing changes >= 2). => Grounded when a sufficient card is attached.
    let consistent = EvidenceSnapshot::from_records(&[
        rec(cx(1), "a", false),
        rec(cx(1), "b", false),
        rec(cx(1), "c", false),
        rec(cx(1), "d", false),
        rec(cx(1), "e", false),
        rec(cx(1), "f", true),
    ])
    .with_sufficiency(sufficient_card("x"));
    assert!(honesty_gate(&consistent, &config).unwrap().is_grounded());
}

#[test]
fn no_recurrence_fires_when_failures_come_from_too_few_distinct_changes() {
    let config = GateConfig::default();
    // 3 failing occurrences but all from ONE change id => distinct_failing = 1 <
    // recurrence_floor 2. Self-consistent (all fail) so flaky does not pre-empt.
    let one_off = EvidenceSnapshot::from_records(&[
        rec(cx(1), "same", false),
        rec(cx(1), "same", false),
        rec(cx(1), "same", false),
    ]);
    assert_eq!(one_off.distinct_failing_changes, 1);
    assert!((one_off.self_consistency - 1.0).abs() < 1e-12);
    let refusal = honesty_gate(&one_off, &config)
        .unwrap()
        .refusal()
        .unwrap()
        .clone();
    assert_eq!(refusal.code, ASTRO_ORACLE_NO_RECURRENCE);
    assert_eq!(refusal.degraded_mode, DegradedMode::Refuse);

    // Two distinct failing changes clears the recurrence floor.
    let recurring = EvidenceSnapshot::from_records(&[
        rec(cx(1), "one", false),
        rec(cx(1), "two", false),
        rec(cx(1), "three", false),
    ])
    .with_sufficiency(sufficient_card("x"));
    assert!(honesty_gate(&recurring, &config).unwrap().is_grounded());
}

#[test]
fn backtest_not_beaten_offers_structural_mode() {
    let config = GateConfig::default();
    // Sufficient, recurring, consistent — but grounded did NOT beat the baseline.
    let snap = EvidenceSnapshot::from_records(&[
        rec(cx(1), "a", false),
        rec(cx(1), "b", false),
        rec(cx(1), "c", false),
    ])
    .with_sufficiency(sufficient_card("x"))
    .with_backtest(false);
    let refusal = honesty_gate(&snap, &config)
        .unwrap()
        .refusal()
        .unwrap()
        .clone();
    assert_eq!(refusal.code, ASTRO_ORACLE_BACKTEST_NOT_BEATEN);
    assert_eq!(
        refusal.degraded_mode,
        DegradedMode::OfferStructural,
        "backtest-not-beaten offers the structural view, not a hard refusal"
    );
}

#[test]
fn insufficient_pre_empts_flaky_and_no_recurrence() {
    let config = GateConfig::default();
    // Only 1 occurrence: below the grounded floor. INSUFFICIENT must win even
    // though the single record is a one-off failing change.
    let snap = EvidenceSnapshot::from_records(&[rec(cx(1), "only", false)]);
    let refusal = honesty_gate(&snap, &config)
        .unwrap()
        .refusal()
        .unwrap()
        .clone();
    assert_eq!(refusal.code, ASTRO_ORACLE_INSUFFICIENT);
}

// ------------------------------------------------------------------
// DoD 5: error catalog pinned — every ASTRO_ORACLE_* code the gate owns
// asserts code + summary/message + remediation.
// ------------------------------------------------------------------

#[test]
fn failure_mode_catalog_pins_code_summary_and_remediation() {
    // Every catalog entry is structured data: a stable code, a non-empty summary,
    // a non-empty remediation, and a degraded mode.
    let expected: &[(&str, DegradedMode)] = &[
        (ASTRO_ORACLE_INSUFFICIENT, DegradedMode::Refuse),
        (ASTRO_ORACLE_FLAKY_EVIDENCE, DegradedMode::Refuse),
        (ASTRO_ORACLE_NO_RECURRENCE, DegradedMode::Refuse),
        (
            ASTRO_ORACLE_BACKTEST_NOT_BEATEN,
            DegradedMode::OfferStructural,
        ),
    ];
    assert_eq!(ORACLE_FAILURE_MODES.len(), expected.len());
    for (code, mode) in expected {
        let entry = oracle_failure_mode(code).expect("catalog entry present");
        assert_eq!(entry.code, *code);
        assert_eq!(entry.degraded_mode, *mode);
        assert!(!entry.summary.is_empty(), "{code} has a summary");
        assert!(!entry.remediation.is_empty(), "{code} has a remediation");
    }
    // Codes are unique.
    let mut codes: Vec<&str> = ORACLE_FAILURE_MODES.iter().map(|m| m.code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), ORACLE_FAILURE_MODES.len(), "codes are unique");
}

#[test]
fn ungated_confidence_error_pins_code_and_remediation() {
    let err = GatedConfidence::new(1.0, 1.0, TrustTag::Trusted).unwrap_err();
    assert_eq!(err.code, ASTRO_ORACLE_UNGATED_CONFIDENCE);
    assert!(err.message.contains("ceiling"));
    assert!(err.remediation.contains("GatedConfidence"));
}

#[test]
fn every_catalog_code_is_reachable_from_a_planted_snapshot() {
    // Positive proof that each detection predicate can fire (no dead catalog
    // entry): plant the minimal snapshot that triggers each code.
    let config = GateConfig::default();
    let cases: &[(&str, EvidenceSnapshot)] = &[
        (
            ASTRO_ORACLE_INSUFFICIENT,
            EvidenceSnapshot::from_records(&[]),
        ),
        (
            ASTRO_ORACLE_FLAKY_EVIDENCE,
            EvidenceSnapshot::from_records(&[
                rec(cx(1), "a", false),
                rec(cx(1), "b", false),
                rec(cx(1), "c", true),
                rec(cx(1), "d", true),
            ]),
        ),
        (
            ASTRO_ORACLE_NO_RECURRENCE,
            EvidenceSnapshot::from_records(&[
                rec(cx(1), "same", false),
                rec(cx(1), "same", false),
                rec(cx(1), "same", false),
            ]),
        ),
        (
            ASTRO_ORACLE_BACKTEST_NOT_BEATEN,
            EvidenceSnapshot::from_records(&[
                rec(cx(1), "a", false),
                rec(cx(1), "b", false),
                rec(cx(1), "c", false),
            ])
            .with_sufficiency(sufficient_card("x"))
            .with_backtest(false),
        ),
    ];
    for (code, snap) in cases {
        let refusal = honesty_gate(snap, &config)
            .unwrap()
            .refusal()
            .unwrap()
            .clone();
        assert_eq!(refusal.code, *code, "planted snapshot fires {code}");
    }
}
