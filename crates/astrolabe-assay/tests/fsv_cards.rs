//! Full State Verification for the #34 measure_bits card engines: the
//! edge-strategy calibration golden with a durable hash-chained ledger, the
//! P5-exit cross-corpus signal-ranking differentiation with a persisted "fixed
//! weights were wrong" exhibit artifact, and durable read-back of the redundancy,
//! synergy, and causality cards.
//!
//! Every assertion reads back the persisted bytes (ledger ndjson, exhibit JSON,
//! card JSON) through a fresh handle, never a writer return value. Fixtures are
//! hand-computable (exact proportions, XOR/copy structure) so the golden values
//! are checkable by inspection.

use std::fs;
use std::path::PathBuf;

use astrolabe_assay::causality::CausalityEdgeInput;
use astrolabe_assay::{
    AxisValues, BitsConfig, CalibrationConfig, CalibrationLedger, CalibrationSource,
    CausalityConfig, RedundancyConfig, SignalRankingCard, SlotColumn, SlotObservations, SlotValues,
    StrategyCalibration, StrategyObservation, SynergyConfig, SynergyTripleInput,
    build_calibration_card, build_causality_card, build_redundancy_card, build_signal_ranking,
    build_synergy_card, calibration_input_fingerprint,
};
use astrolabe_domain::TrustTag;

fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "astro-assay-fsv-cards-{}-{tag}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A tiny deterministic splitmix64 for reproducible fixture noise (no crate rng
/// dependency, so the fixture is self-contained and hand-auditable).
struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `[-1, 1)`.
    fn jitter(&mut self) -> f64 {
        (self.next() as f64 / u64::MAX as f64) * 2.0 - 1.0
    }
}

// -------- DoD #1: calibration golden + durable ledger --------

fn calibration_golden_observations() -> Vec<StrategyObservation> {
    vec![
        // trace-confirmed truth CONTRADICTS the prior: CBM guesses 0.50 but this
        // repo confirms only 8/40 = 0.20. Above quorum -> measured replaces prior.
        StrategyObservation {
            strategy: "service_pattern".into(),
            prior: 0.50,
            correct: 8,
            total: 40,
        },
        // Also above quorum, and the measurement roughly agrees with the prior.
        StrategyObservation {
            strategy: "import_map".into(),
            prior: 0.95,
            correct: 96,
            total: 100,
        },
        // Below quorum (5 < 30): prior RETAINED as fallback, not measured.
        StrategyObservation {
            strategy: "suffix".into(),
            prior: 0.55,
            correct: 3,
            total: 5,
        },
    ]
}

#[test]
fn calibration_golden_measured_replaces_prior_and_fallback_retained_ledgered() {
    let dir = scratch_dir("calibration");
    let path = dir.join("calibration.ndjson");
    let cfg = CalibrationConfig::from_defaults().unwrap();
    let obs = calibration_golden_observations();

    let card = build_calibration_card(&obs, &cfg).unwrap();

    let find = |name: &str| -> StrategyCalibration {
        card.strategies
            .iter()
            .find(|s| s.strategy == name)
            .cloned()
            .unwrap()
    };

    // STATE 1 — measured precision replaces the contradicted prior, CI attached.
    let sp = find("service_pattern");
    assert_eq!(sp.source, CalibrationSource::Measured);
    assert_eq!(sp.trust, TrustTag::Trusted);
    let m = sp.measured.as_ref().unwrap();
    assert!(
        (m.precision - 0.20).abs() < 1e-12,
        "precision={}",
        m.precision
    );
    assert!((sp.effective_confidence - 0.20).abs() < 1e-12);
    assert!(
        sp.prior == 0.50 && m.ci_lo > 0.0 && m.ci_hi < 0.50,
        "CI must exclude the prior 0.50: {m:?}"
    );
    assert_eq!(m.n, 40);

    // STATE 2 — below-quorum strategy retains its prior as a labeled fallback.
    let sfx = find("suffix");
    assert_eq!(sfx.source, CalibrationSource::PriorFallback);
    assert_eq!(sfx.trust, TrustTag::Provisional);
    assert!(sfx.measured.is_none());
    assert!((sfx.effective_confidence - 0.55).abs() < 1e-12);

    // Ledger the card, then prove the write by reading the ndjson bytes back.
    let ledger = CalibrationLedger::open(&path).unwrap();
    let fp = calibration_input_fingerprint(&obs).unwrap();
    let entry = ledger.append(&card, &fp).unwrap();
    assert_eq!(entry.seq, 0);

    let raw = fs::read_to_string(&path).unwrap();
    let line = raw.lines().next().unwrap();
    let persisted: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(persisted["seq"], serde_json::json!(0));
    // Independently confirm the persisted card carries both states.
    let strategies = persisted["card"]["strategies"].as_array().unwrap();
    let persisted_sp = strategies
        .iter()
        .find(|s| s["strategy"] == "service_pattern")
        .unwrap();
    assert_eq!(persisted_sp["source"], "measured");
    let persisted_sfx = strategies
        .iter()
        .find(|s| s["strategy"] == "suffix")
        .unwrap();
    assert_eq!(persisted_sfx["source"], "prior_fallback");

    // reproduce() re-derives the card bit-for-bit from the recorded inputs.
    let re = ledger.reproduce(0, &obs, &cfg).unwrap();
    assert_eq!(re, card);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn calibration_ledger_reproduce_rejects_mismatched_inputs() {
    let dir = scratch_dir("calibration-mismatch");
    let path = dir.join("calibration.ndjson");
    let cfg = CalibrationConfig::from_defaults().unwrap();
    let obs = calibration_golden_observations();
    let card = build_calibration_card(&obs, &cfg).unwrap();
    let ledger = CalibrationLedger::open(&path).unwrap();
    let fp = calibration_input_fingerprint(&obs).unwrap();
    ledger.append(&card, &fp).unwrap();

    // Perturb one count; reproduce must refuse on the fingerprint mismatch.
    let mut other = obs.clone();
    other[0].correct += 1;
    let err = ledger.reproduce(0, &other, &cfg).unwrap_err();
    assert_eq!(err.code(), "ASTRO_ASSAY_REPRODUCE_MISMATCH");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn calibration_ledger_detects_chain_tamper() {
    let dir = scratch_dir("calibration-tamper");
    let path = dir.join("calibration.ndjson");
    let cfg = CalibrationConfig::from_defaults().unwrap();
    let obs = calibration_golden_observations();
    let card = build_calibration_card(&obs, &cfg).unwrap();
    let ledger = CalibrationLedger::open(&path).unwrap();
    let fp = calibration_input_fingerprint(&obs).unwrap();
    ledger.append(&card, &fp).unwrap();

    // Rewrite the persisted entry with a flipped fingerprint but stale hash.
    let mut entries = ledger.read_all().unwrap();
    entries[0].input_fingerprint = "deadbeef".to_string();
    let mut line = serde_json::to_vec(&entries[0]).unwrap();
    line.push(b'\n');
    fs::write(&path, &line).unwrap();
    let err = ledger.read_all().unwrap_err();
    assert_eq!(err.code(), "ASTRO_ASSAY_STORE_CORRUPT");
    fs::remove_dir_all(&dir).ok();
}

// -------- DoD #4: cross-corpus signal-ranking differentiation --------

/// Builds one synthetic corpus where the named slots carry strong/medium/weak
/// signal about a fair-binary axis, via the mixed (scalar↔discrete) route.
fn corpus(
    strong: &str,
    medium: &str,
    weak: &str,
    seed: u64,
) -> (Vec<SlotObservations>, AxisValues) {
    let n = 160usize;
    let mut rng = SplitMix(seed);
    let axis: Vec<i64> = (0..n).map(|i| (i % 2) as i64).collect();
    let mut strong_v = Vec::with_capacity(n);
    let mut medium_v = Vec::with_capacity(n);
    let mut weak_v = Vec::with_capacity(n);
    for &c in &axis {
        let sign = if c == 1 { 1.0 } else { -1.0 };
        // Strong: well-separated classes (jitter << separation) -> high MI.
        strong_v.push(sign * 3.0 + rng.jitter() * 0.4);
        // Medium: partial overlap -> moderate MI.
        medium_v.push(sign * 0.8 + rng.jitter());
        // Weak: no class dependence -> ~0 MI.
        weak_v.push(rng.jitter());
    }
    let slots = vec![
        SlotObservations {
            slot: strong.into(),
            values: SlotValues::Scalar(strong_v),
        },
        SlotObservations {
            slot: medium.into(),
            values: SlotValues::Scalar(medium_v),
        },
        SlotObservations {
            slot: weak.into(),
            values: SlotValues::Scalar(weak_v),
        },
    ];
    (slots, AxisValues::Discrete(axis))
}

#[test]
fn cross_corpus_signal_ranking_differs_and_exhibits_fixed_weights_wrong() {
    let dir = scratch_dir("cross-corpus");
    let cfg = BitsConfig::from_defaults().unwrap();
    let seed = 4242;

    // Three pinned corpora; the carrier of real signal is a different slot in each.
    let (a_slots, a_axis) = corpus("complexity", "churn", "coverage", 1);
    let (b_slots, b_axis) = corpus("churn", "coverage", "complexity", 2);
    let (c_slots, c_axis) = corpus("coverage", "complexity", "churn", 3);

    let alpha = build_signal_ranking("defect", &a_slots, &a_axis, seed, &cfg).unwrap();
    let beta = build_signal_ranking("defect", &b_slots, &b_axis, seed, &cfg).unwrap();
    let gamma = build_signal_ranking("defect", &c_slots, &c_axis, seed, &cfg).unwrap();

    let order = |card: &SignalRankingCard| -> Vec<String> {
        card.signals.iter().map(|s| s.slot.clone()).collect()
    };
    let (oa, ob, oc) = (order(&alpha), order(&beta), order(&gamma));

    // The measured top signal is the corpus's real carrier — and it differs.
    assert_eq!(oa[0], "complexity", "alpha order={oa:?}");
    assert_eq!(ob[0], "churn", "beta order={ob:?}");
    assert_eq!(oc[0], "coverage", "gamma order={oc:?}");
    assert!(
        oa != ob && ob != oc && oa != oc,
        "rankings must differ across corpora"
    );

    // The "fixed weights were wrong" exhibit: CBM's fixed global order ranks
    // complexity first everywhere; the measured order contradicts it in beta and
    // gamma, proving the fixed weights leave intelligence on the table.
    let fixed_global_order = ["complexity", "churn", "coverage"];
    let fixed_top = fixed_global_order[0];
    assert_ne!(
        ob[0], fixed_top,
        "beta: measured top must differ from fixed weight top"
    );
    assert_ne!(
        oc[0], fixed_top,
        "gamma: measured top must differ from fixed weight top"
    );

    let exhibit = serde_json::json!({
        "schema": "astrolabe.assay.fixed_weights_wrong_exhibit.v1",
        "axis": "defect",
        "fixed_global_order": fixed_global_order,
        "corpora": [
            {"corpus": "alpha", "measured_order": oa, "measured_top": oa[0],
             "matches_fixed_top": oa[0] == fixed_top},
            {"corpus": "beta", "measured_order": ob, "measured_top": ob[0],
             "matches_fixed_top": ob[0] == fixed_top},
            {"corpus": "gamma", "measured_order": oc, "measured_top": oc[0],
             "matches_fixed_top": oc[0] == fixed_top},
        ],
        "verdict": "fixed global weights mis-rank the carrier in 2 of 3 corpora",
    });
    let exhibit_path = dir.join("fixed_weights_wrong_exhibit.json");
    fs::write(&exhibit_path, serde_json::to_vec_pretty(&exhibit).unwrap()).unwrap();

    // FSV: read the exhibit artifact back and confirm the verdict is persisted.
    let readback: serde_json::Value =
        serde_json::from_slice(&fs::read(&exhibit_path).unwrap()).unwrap();
    let mismatches = readback["corpora"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["matches_fixed_top"] == serde_json::json!(false))
        .count();
    assert_eq!(
        mismatches, 2,
        "exhibit must record 2 fixed-weight mis-rankings"
    );

    fs::remove_dir_all(&dir).ok();
}

// -------- durable read-back of the redundancy / synergy / causality cards --------

#[test]
fn redundancy_synergy_causality_cards_round_trip_on_disk() {
    let dir = scratch_dir("cards-roundtrip");
    let n = 400usize;

    // Redundancy: two identical columns collapse to n_eff = 1.
    let a: Vec<i64> = (0..n).map(|i| (i % 2) as i64).collect();
    let red = build_redundancy_card(
        &[
            SlotColumn {
                slot: "s1".into(),
                values: a.clone(),
            },
            SlotColumn {
                slot: "s2".into(),
                values: a.clone(),
            },
        ],
        &RedundancyConfig::from_defaults().unwrap(),
    )
    .unwrap();
    assert!((red.n_eff - 1.0).abs() < 1e-6);

    // Synergy: XOR triple is pure synergy.
    let b: Vec<i64> = (0..n).map(|i| ((i / 2) % 2) as i64).collect();
    let c: Vec<i64> = a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect();
    let syn = build_synergy_card(
        &[SynergyTripleInput {
            a_slot: "a".into(),
            a: a.clone(),
            b_slot: "b".into(),
            b,
            axis: "c".into(),
            outcome: c,
        }],
        &SynergyConfig::from_defaults().unwrap(),
    )
    .unwrap();
    assert!(syn.triples[0].ii_bits > 0.8);

    // Causality: a non-periodic driver sets the target one step later -> positive
    // TE at lag 1. (A periodic driver would make every lag predictive.)
    let mut drv_rng = SplitMix(0xC0FF_EE99);
    let drv: Vec<i64> = (0..n).map(|_| (drv_rng.next() & 1) as i64).collect();
    let mut tgt = vec![0i64; n];
    tgt[1..n].copy_from_slice(&drv[..(n - 1)]);
    let cau = build_causality_card(
        &[CausalityEdgeInput {
            driver_slot: "a".into(),
            driver: drv,
            target_slot: "b".into(),
            target: tgt,
        }],
        &CausalityConfig::from_defaults().unwrap(),
    )
    .unwrap();
    assert_eq!(cau.edges[0].best_lag, 1);
    assert!(cau.edges[0].best_te_bits > 0.8);

    // Persist each card, read the bytes back, and confirm they parse to equal cards.
    for (name, bytes, kind) in [
        ("redundancy", serde_json::to_vec(&red).unwrap(), "red"),
        ("synergy", serde_json::to_vec(&syn).unwrap(), "syn"),
        ("causality", serde_json::to_vec(&cau).unwrap(), "cau"),
    ] {
        let p = dir.join(format!("{name}.json"));
        fs::write(&p, &bytes).unwrap();
        let back = fs::read(&p).unwrap();
        match kind {
            "red" => assert_eq!(
                serde_json::from_slice::<astrolabe_assay::RedundancyCard>(&back).unwrap(),
                red
            ),
            "syn" => assert_eq!(
                serde_json::from_slice::<astrolabe_assay::SynergyCard>(&back).unwrap(),
                syn
            ),
            _ => assert_eq!(
                serde_json::from_slice::<astrolabe_assay::CausalityCard>(&back).unwrap(),
                cau
            ),
        }
    }

    fs::remove_dir_all(&dir).ok();
}
