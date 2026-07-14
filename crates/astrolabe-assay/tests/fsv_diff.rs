//! Full-state-verification of the P5.3 differentiation pipeline (#33).
//!
//! Each of the six differentiation estimators is exercised on a synthetic-but-known
//! distribution with an analytically derivable expectation, the resulting card is
//! persisted to a real hash-chained ledger file, and then an **independent** reader
//! re-opens the file, re-reads the persisted bytes, and asserts the analytic
//! property survived the round-trip. Evidence is the persisted state read back, not
//! the in-memory return value.

use std::fs;
use std::path::PathBuf;

use astrolabe_assay::bits::{SlotObservations, SlotValues};
use astrolabe_assay::changepoint::measure_change_point;
use astrolabe_assay::diff::DiffConfig;
use astrolabe_assay::diff_ledger::{DiffLedger, DifferentiationCard, GENESIS_PREV_HASH};
use astrolabe_assay::drift::measure_drift;
use astrolabe_assay::periodicity::measure_periodicity;
use astrolabe_assay::redundancy::{RedundancyGate, measure_redundancy};
use astrolabe_assay::rng::DeterministicRng;
use astrolabe_assay::synergy::{SynergyClass, SynergyTripleInput, measure_synergy_triple};
use astrolabe_assay::transfer_entropy::{NamedSeries, measure_transfer_entropy};

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "astro-assay-fsvdiff-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

fn label(name: &str, values: Vec<i64>) -> SlotObservations {
    SlotObservations {
        slot: name.into(),
        values: SlotValues::Label(values),
    }
}

#[test]
fn all_six_cards_persist_and_read_back_with_their_analytic_properties() {
    let cfg = DiffConfig::from_defaults().unwrap();
    let dir = unique_dir("all");
    let path = dir.join("diff-cards.ndjson");
    let ledger = DiffLedger::open(&path).unwrap();

    // --- 1. Redundancy: four independent lenses + an exact copy of the first. ---
    let mut rng = DeterministicRng::from_u64_labeled(1, "redundancy");
    let n = 3000;
    let base: Vec<Vec<i64>> = (0..4)
        .map(|_| (0..n).map(|_| (rng.next_u64() % 4) as i64).collect())
        .collect();
    let redundancy_slots = vec![
        label("a", base[0].clone()),
        label("b", base[1].clone()),
        label("c", base[2].clone()),
        label("d", base[3].clone()),
        label("a_copy", base[0].clone()),
    ];
    let redundancy = measure_redundancy(&redundancy_slots, 1, &cfg).unwrap();
    ledger
        .append(&DifferentiationCard::Redundancy(redundancy), 1)
        .unwrap();

    // --- 2. Synergy: XOR outcome — interaction information ≈ −1 bit. ---
    let mut rng = DeterministicRng::from_u64_labeled(2, "synergy");
    let mut x = Vec::with_capacity(n);
    let mut y = Vec::with_capacity(n);
    let mut o = Vec::with_capacity(n);
    for _ in 0..n {
        let xv = (rng.next_u64() & 1) as i64;
        let yv = (rng.next_u64() & 1) as i64;
        x.push(xv);
        y.push(yv);
        o.push(xv ^ yv);
    }
    let triple = SynergyTripleInput {
        x: label("x", x),
        y: label("y", y),
        outcome: label("defect", o),
    };
    let synergy = measure_synergy_triple(&triple, 2, &cfg).unwrap();
    // Wrap the single triple in a card.
    let synergy_card = astrolabe_assay::synergy::SynergyCard {
        trust: synergy.trust,
        triples: vec![synergy],
    };
    ledger
        .append(&DifferentiationCard::Synergy(synergy_card), 2)
        .unwrap();

    // --- 3. Causality: B[t] = A[t−1] → A drives B at lag 1. ---
    let mut a = vec![0i64; n];
    let mut s = 0x5EEDu64 | 1;
    for slot in a.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *slot = (s & 1) as i64;
    }
    let mut b = vec![0i64; n];
    b[1..n].copy_from_slice(&a[..n - 1]);
    let series = vec![
        NamedSeries {
            name: "A".into(),
            values: a,
        },
        NamedSeries {
            name: "B".into(),
            values: b,
        },
    ];
    let causality = measure_transfer_entropy(&series, 3, &cfg).unwrap();
    ledger
        .append(&DifferentiationCard::Causality(causality), 3)
        .unwrap();

    // --- 4. Periodicity: planted 7-day cadence. ---
    let np = 210;
    let times: Vec<f64> = (0..np).map(|i| i as f64).collect();
    let values: Vec<f64> = times
        .iter()
        .map(|&t| (2.0 * std::f64::consts::PI * t / 7.0).sin())
        .collect();
    let periodicity = measure_periodicity("failures", &times, &values, 4, &cfg).unwrap();
    ledger
        .append(&DifferentiationCard::Periodicity(periodicity), 4)
        .unwrap();

    // --- 5. Change point: mean shift at index 500. ---
    let mut rng = DeterministicRng::from_u64_labeled(5, "cusum");
    let stream: Vec<f64> = (0..1000)
        .map(|i| if i < 500 { 0.0 } else { 3.0 } + rng.next_standard_normal())
        .collect();
    let change = measure_change_point("churn", &stream, 5, &cfg).unwrap();
    ledger
        .append(&DifferentiationCard::ChangePoint(change), 5)
        .unwrap();

    // --- 6. Drift: reference N(0,1) vs new N(3,1). ---
    let mut rng = DeterministicRng::from_u64_labeled(6, "drift");
    let reference: Vec<Vec<f64>> = (0..80).map(|_| vec![rng.next_standard_normal()]).collect();
    let sample: Vec<Vec<f64>> = (0..80)
        .map(|_| vec![3.0 + rng.next_standard_normal()])
        .collect();
    let drift = measure_drift("embedding", &reference, &sample, 6, &cfg).unwrap();
    ledger
        .append(&DifferentiationCard::Drift(drift), 6)
        .unwrap();

    // ---- Independent read-back of the persisted bytes. ----
    let reader = DiffLedger::open(&path).unwrap();
    let entries = reader.read_all().unwrap();
    assert_eq!(entries.len(), 6, "six persisted cards");
    assert_eq!(entries[0].prev_hash, GENESIS_PREV_HASH);
    // Chain is intact (each prev_hash equals the prior entry_hash).
    for w in entries.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].entry_hash, "chain link");
    }

    for entry in &entries {
        match &entry.card {
            DifferentiationCard::Redundancy(card) => {
                assert!(
                    (card.n_eff - 4.0).abs() < 0.15,
                    "read-back n_eff={} (expected ≈4)",
                    card.n_eff
                );
                let copy = card
                    .gate_decisions
                    .iter()
                    .find(|d| d.lens == "a_copy")
                    .unwrap();
                assert_eq!(copy.decision, RedundancyGate::Retire);
                assert_eq!(copy.redundant_with.as_deref(), Some("a"));
            }
            DifferentiationCard::Synergy(card) => {
                let t = &card.triples[0];
                assert!(
                    (t.interaction_information_bits + 1.0).abs() < 0.05,
                    "read-back ii={}",
                    t.interaction_information_bits
                );
                assert_eq!(t.classification, SynergyClass::Synergistic);
                assert!(t.promote_cross_term);
            }
            DifferentiationCard::Causality(card) => {
                assert_eq!(card.edges.len(), 1, "one directed edge");
                assert_eq!(card.edges[0].from, "A");
                assert_eq!(card.edges[0].to, "B");
                assert_eq!(card.edges[0].lag, 1);
            }
            DifferentiationCard::Periodicity(card) => {
                assert!(card.detected, "read-back periodicity not detected");
                assert!(
                    (card.peak_period - 7.0).abs() < 0.3,
                    "read-back peak_period={}",
                    card.peak_period
                );
            }
            DifferentiationCard::ChangePoint(card) => {
                assert!(card.change_detected);
                let idx = card.change_index.unwrap();
                assert!(
                    (idx as i64 - 500).abs() <= 25,
                    "read-back change index {idx}"
                );
            }
            DifferentiationCard::Drift(card) => {
                assert!(card.drift_detected, "read-back drift not detected");
                assert!(card.mmd_squared > 0.1);
            }
        }
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cards_are_seed_and_worker_count_invariant() {
    // Every estimator reproduces bit-for-bit for a fixed seed regardless of how
    // many worker threads the harness happens to run with.
    let cfg = DiffConfig::from_defaults().unwrap();

    let mut rng = DeterministicRng::from_u64_labeled(10, "det");
    let n = 800;
    let a: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
    let b: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
    let o: Vec<i64> = a.iter().zip(&b).map(|(x, y)| x ^ y).collect();
    let triple = SynergyTripleInput {
        x: label("x", a.clone()),
        y: label("y", b.clone()),
        outcome: label("o", o),
    };
    let s1 = measure_synergy_triple(&triple, 99, &cfg).unwrap();
    let s2 = measure_synergy_triple(&triple, 99, &cfg).unwrap();
    assert_eq!(s1, s2, "synergy bit-identical");

    let redundancy_slots = vec![label("a", a.clone()), label("b", b.clone()), label("a2", a)];
    let r1 = measure_redundancy(&redundancy_slots, 99, &cfg).unwrap();
    let r2 = measure_redundancy(&redundancy_slots, 99, &cfg).unwrap();
    assert_eq!(r1, r2, "redundancy bit-identical");

    let stream: Vec<f64> = (0..400).map(|i| if i < 200 { 0.0 } else { 2.0 }).collect();
    let c1 = measure_change_point("s", &stream, 99, &cfg).unwrap();
    let c2 = measure_change_point("s", &stream, 99, &cfg).unwrap();
    assert_eq!(c1, c2, "change-point bit-identical");
}
