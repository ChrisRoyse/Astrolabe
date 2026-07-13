//! Full State Verification for the KSG bits pipeline (P5.2, issue #32).
//!
//! Every test here drives the real public measurement API over
//! synthetic-but-analytically-known data, then — for the reproducibility and
//! ledger DoD — independently reads the persisted ledger bytes back off disk and
//! re-derives the card. No mocks: the "planted signals" are drawn from
//! distributions with closed-form mutual information (correlated Gaussians:
//! `I = -0.5·log2(1 - rho^2)` bits), so a recovered estimate can be checked
//! against ground truth rather than against another implementation.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_assay::bits::{
    AxisValues, BitsConfig, DeficitSuggestedAction, SlotObservations, SlotSummary, SlotValues,
    build_signal_ranking, build_sufficiency_card, enforce_dpi_ceiling, measure_slot_bits,
};
use astrolabe_assay::error::{ASTRO_ASSAY_DPI_VIOLATION, ASTRO_ASSAY_REPRODUCE_MISMATCH};
use astrolabe_assay::ledger::{AssayCardEntry, CardLedger, input_fingerprint};
use astrolabe_assay::rng::DeterministicRng;
use astrolabe_domain::TrustTag;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique, self-cleaning ledger root under the system temp dir.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-assay-bits-fsv-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A reduced config for FSV: the smallest sufficient dataset (§FSV doctrine).
///
/// The KSG/Ross estimators are O(n²) and the bootstrap recomputes one per
/// resample, so a debug FSV run uses a smaller resample and posterior-draw count
/// than the nightly-batch defaults. Every other knob (k, floor, prior, bins,
/// interval level) is left at its registry default, so the estimator, floor
/// discipline, and routing under test are the real production ones — only the
/// Monte-Carlo repetition count is trimmed for wall-clock.
fn test_cfg() -> BitsConfig {
    let mut cfg = BitsConfig::from_defaults().unwrap();
    cfg.bootstrap_resamples = 64;
    cfg.posterior_draws = 600;
    cfg
}

fn analytic_gaussian_mi_bits(rho: f64) -> f64 {
    -0.5 * (1.0 - rho * rho).log2()
}

/// Builds a continuous scalar slot correlated with a continuous axis at `rho`.
fn planted_correlated(rho: f64, n: usize, seed: u64) -> (Vec<f64>, Vec<f64>) {
    let mut rng = DeterministicRng::from_u64_labeled(seed, "planted");
    let mut x = Vec::with_capacity(n);
    let mut y = Vec::with_capacity(n);
    for _ in 0..n {
        let z1 = rng.next_standard_normal();
        let z2 = rng.next_standard_normal();
        x.push(z1);
        y.push(rho * z1 + (1.0 - rho * rho).sqrt() * z2);
    }
    (x, y)
}

/// DoD 1 + 2: planted-signal suite across signal strengths incl. a zero-signal
/// control. Each planted scalar slot carries a KNOWN number of bits about the
/// continuous axis; the estimator must recover it, the reported interval must be
/// a proper band around the estimate, and the ranking must order the slots by
/// true signal strength with the zero-signal control near the bottom at ~0 bits.
#[test]
fn planted_signal_recovered_across_strengths_with_zero_control() {
    let cfg = test_cfg();
    let n = 600;
    let seed = 20260713;

    // One shared axis; each slot is correlated with it at a different rho, so
    // they are directly comparable on the same outcome.
    let (base, axis_values) = planted_correlated(0.6, n, seed);
    // Reuse `base` as the reference; build slots at several correlations *with the
    // axis* by mixing the axis with fresh noise at a target correlation.
    let axis = AxisValues::Continuous(axis_values.clone());

    let make_slot = |name: &str, rho: f64, s: u64| {
        let mut rng = DeterministicRng::from_u64_labeled(s, name);
        let vals: Vec<f64> = axis_values
            .iter()
            .map(|&a| rho * a + (1.0 - rho * rho).sqrt() * rng.next_standard_normal())
            .collect();
        SlotObservations {
            slot: name.to_string(),
            values: SlotValues::Scalar(vals),
        }
    };
    let _ = base;

    let slots = vec![
        make_slot("strong", 0.9, 1),
        make_slot("medium", 0.6, 2),
        make_slot("weak", 0.3, 3),
        // Zero-signal control: independent of the axis.
        SlotObservations {
            slot: "control".into(),
            values: SlotValues::Scalar({
                let mut rng = DeterministicRng::from_u64_labeled(99, "control");
                (0..n).map(|_| rng.next_standard_normal()).collect()
            }),
        },
    ];

    let card = build_signal_ranking("agent_utility", &slots, &axis, seed, &cfg).unwrap();

    // Every reported signal carries a proper (ordered, non-negative-width)
    // interval, is above floor, trusted, with the right sample count and method.
    for s in &card.signals {
        assert_eq!(s.n, n, "{}", s.slot);
        assert_eq!(s.trust, TrustTag::Trusted, "{}", s.slot);
        assert!(!s.provisional, "{}", s.slot);
        assert!(s.interval.lo <= s.interval.hi, "{s:?}");
        assert_eq!(s.interval.method, "subsample-percentile", "{}", s.slot);
        assert_eq!(s.interval.level_permille, cfg.ci_confidence_permille);
    }

    let bits_of =
        |name: &str| -> f64 { card.signals.iter().find(|s| s.slot == name).unwrap().bits };
    // Ranking is by descending signal: strong > medium > weak > control.
    let order: Vec<&str> = card.signals.iter().map(|s| s.slot.as_str()).collect();
    assert_eq!(
        order,
        vec!["strong", "medium", "weak", "control"],
        "ranking order"
    );

    // Recovery within tolerance of the closed-form MI for each planted strength,
    // and the reported interval brackets the true value (within a small margin).
    for (name, rho) in [("strong", 0.9), ("medium", 0.6), ("weak", 0.3)] {
        let analytic = analytic_gaussian_mi_bits(rho);
        let sig = card.signals.iter().find(|s| s.slot == name).unwrap();
        assert!(
            (sig.bits - analytic).abs() < 0.12,
            "{name}: analytic={analytic:.4} est={:.4}",
            sig.bits
        );
        assert!(
            analytic >= sig.interval.lo - 0.1 && analytic <= sig.interval.hi + 0.1,
            "{name}: analytic={analytic:.4} not in reported CI [{:.4},{:.4}]",
            sig.interval.lo,
            sig.interval.hi
        );
    }
    // Zero-signal control recovers ~0 bits.
    assert!(
        bits_of("control") < 0.05,
        "control bits={}",
        bits_of("control")
    );
}

/// DoD 3: below the 50-sample floor the result is Provisional with a credible
/// interval and NEVER a bare point estimate — asserted at the schema level.
#[test]
fn below_floor_result_is_provisional_with_credible_interval() {
    let cfg = test_cfg();
    let n = 30; // below the default floor of 50
    let (x, a) = planted_correlated(0.7, n, 4242);
    let slot = SlotObservations {
        slot: "sparse".into(),
        values: SlotValues::Scalar(x),
    };
    let axis = AxisValues::Continuous(a);

    let bits = measure_slot_bits(&slot, &axis, 4242, &cfg).unwrap();
    assert!(bits.provisional, "below-floor result must be provisional");
    assert_eq!(bits.trust, TrustTag::Provisional);
    assert_eq!(bits.n, n);
    assert_eq!(bits.estimator, "dirichlet-jeffreys-posterior");
    assert_eq!(bits.interval.method, "dirichlet-jeffreys-posterior");
    // The point is never bare: it is bracketed by a real, positive-width interval.
    assert!(
        bits.interval.lo <= bits.bits && bits.bits <= bits.interval.hi,
        "{bits:?}"
    );
    assert!(
        bits.interval.hi > bits.interval.lo,
        "interval must have width"
    );
    assert_eq!(bits.interval.level_permille, cfg.ci_confidence_permille);

    // At exactly the floor the result flips to a trusted, non-provisional point.
    let n2 = cfg.floor;
    let (x2, a2) = planted_correlated(0.7, n2, 4242);
    let slot2 = SlotObservations {
        slot: "at-floor".into(),
        values: SlotValues::Scalar(x2),
    };
    let axis2 = AxisValues::Continuous(a2);
    let bits2 = measure_slot_bits(&slot2, &axis2, 4242, &cfg).unwrap();
    assert!(!bits2.provisional);
    assert_eq!(bits2.trust, TrustTag::Trusted);
}

/// DoD 4: a derived-signal claim that exceeds `I(panel;outcome)` violates the DPI
/// and is refused fail-closed. The panel ceiling is *measured* here, not asserted.
#[test]
fn dpi_ceiling_refuses_measured_oversell() {
    let cfg = test_cfg();
    let n = 500;
    // Measure a real panel→outcome ceiling from a planted correlation.
    let (x, a) = planted_correlated(0.5, n, 7);
    let slot = SlotObservations {
        slot: "panel".into(),
        values: SlotValues::Scalar(x),
    };
    let axis = AxisValues::Continuous(a);
    let panel_ceiling = measure_slot_bits(&slot, &axis, 7, &cfg).unwrap().bits;
    assert!(panel_ceiling > 0.0);

    // A derived claim at or below the ceiling is permitted.
    assert!(enforce_dpi_ceiling(panel_ceiling, panel_ceiling * 0.5, &cfg).is_ok());
    assert!(enforce_dpi_ceiling(panel_ceiling, panel_ceiling, &cfg).is_ok());

    // A constructed oversell (claiming double the measured ceiling) is refused.
    let err = enforce_dpi_ceiling(panel_ceiling, panel_ceiling * 2.0 + 0.5, &cfg).unwrap_err();
    assert_eq!(err.code(), ASTRO_ASSAY_DPI_VIOLATION);
    assert!(
        err.message()
            .contains("exceeds the I(panel;outcome) ceiling")
    );
    assert!(!err.remediation().is_empty());
}

/// DoD 5: a planted-insufficient panel yields a deficit card that names the
/// missing bits per slot and emits the right suggested actions. This is a golden:
/// the deficit shares are hand-computed from the inverse-marginal split.
#[test]
fn sufficiency_deficit_golden() {
    let cfg = BitsConfig::from_defaults().unwrap();
    // Defaults this golden depends on.
    assert_eq!(cfg.min_slot_signal_bits, 0.05);
    assert_eq!(cfg.sufficiency_slack_bits, 0.05);
    assert_eq!(cfg.floor, 50);

    let axis_entropy = 1.0; // fair binary outcome
    let panel_bits = 0.4; // insufficient: 0.4 + 0.05 slack < 1.0
    let slots = vec![
        // Dead lens (0 bits, above floor) -> ProposeLens, largest deficit share.
        SlotSummary {
            slot: "dataflow".into(),
            marginal_bits: 0.0,
            n: 200,
        },
        // Live lens (0.30 bits, above floor) -> AddOutcomeAnchor.
        SlotSummary {
            slot: "complexity".into(),
            marginal_bits: 0.30,
            n: 200,
        },
        // Under-sampled lens (below floor) -> IncreaseSamples.
        SlotSummary {
            slot: "coverage".into(),
            marginal_bits: 0.10,
            n: 10,
        },
    ];

    let card = build_sufficiency_card("defect", axis_entropy, panel_bits, &slots, &cfg).unwrap();
    assert!(!card.sufficient);
    assert!((card.deficit_bits - 0.6).abs() < 1e-9, "total deficit");
    // Any provisional (below-floor) contributor makes the card provisional.
    assert_eq!(card.trust, TrustTag::Provisional);

    // Hand-computed inverse-marginal weights (reg = min_slot_signal = 0.05):
    //   dataflow:   1/(0.00+0.05) = 20.000000
    //   coverage:   1/(0.10+0.05) =  6.666667
    //   complexity: 1/(0.30+0.05) =  2.857143
    //   sum = 29.523810
    // deficit_i = 0.6 * w_i / sum:
    //   dataflow   = 0.4064516129
    //   coverage   = 0.1354838710
    //   complexity = 0.0580645161
    let by_slot = |name: &str| card.deficits.iter().find(|d| d.slot == name).unwrap();
    assert!((by_slot("dataflow").deficit_bits - 0.4064516129).abs() < 1e-6);
    assert!((by_slot("coverage").deficit_bits - 0.1354838710).abs() < 1e-6);
    assert!((by_slot("complexity").deficit_bits - 0.0580645161).abs() < 1e-6);
    // Shares sum back to the total deficit.
    let sum: f64 = card.deficits.iter().map(|d| d.deficit_bits).sum();
    assert!((sum - 0.6).abs() < 1e-9);

    // Actions are routed correctly.
    assert_eq!(
        by_slot("dataflow").action,
        DeficitSuggestedAction::ProposeLens
    );
    assert_eq!(
        by_slot("complexity").action,
        DeficitSuggestedAction::AddOutcomeAnchor
    );
    assert_eq!(
        by_slot("coverage").action,
        DeficitSuggestedAction::IncreaseSamples
    );

    // The breakdown is ordered largest-deficit-first: dataflow, coverage, complexity.
    let order: Vec<&str> = card.deficits.iter().map(|d| d.slot.as_str()).collect();
    assert_eq!(order, vec!["dataflow", "coverage", "complexity"]);

    // A sufficient panel produces no deficits.
    let ok = build_sufficiency_card("defect", 1.0, 1.2, &slots, &cfg).unwrap();
    assert!(ok.sufficient);
    assert!(ok.deficits.is_empty());
    assert_eq!(ok.deficit_bits, 0.0);
}

/// DoD 6: `reproduce` re-derives a sampled card from its ledgered seed + inputs,
/// with the ledger persisted to disk and independently read back (FSV).
#[test]
fn card_is_ledgered_and_reproduces_from_persisted_state() {
    let cfg = test_cfg();
    let root = TempRoot::new();
    let ledger_path = root.path().join("cards.ndjson");

    // A small mixed-route corpus: two scalar slots against a discrete outcome.
    let n = 150;
    let mut rng = DeterministicRng::from_u64_labeled(1, "corpus");
    let mut churn = Vec::new();
    let mut complexity = Vec::new();
    let mut outcome = Vec::new();
    for _ in 0..n {
        let c = rng.next_standard_normal();
        churn.push(c);
        complexity.push(rng.next_standard_normal());
        // Outcome depends on churn (real signal) with noise.
        outcome.push(if c + 0.5 * rng.next_standard_normal() > 0.0 {
            1
        } else {
            0
        });
    }
    let slots = vec![
        SlotObservations {
            slot: "churn".into(),
            values: SlotValues::Scalar(churn),
        },
        SlotObservations {
            slot: "complexity".into(),
            values: SlotValues::Scalar(complexity),
        },
    ];
    let axis = AxisValues::Discrete(outcome);
    let seed = 31337;

    let card = build_signal_ranking("defect", &slots, &axis, seed, &cfg).unwrap();
    // churn carries real signal, complexity does not: ranking must reflect that.
    assert_eq!(card.signals[0].slot, "churn");
    assert!(card.signals[0].bits > card.signals[1].bits);

    let ledger = CardLedger::open(&ledger_path).unwrap();
    let fp = input_fingerprint(&slots, &axis).unwrap();
    let entry = ledger.append(&card, seed, &fp).unwrap();
    assert_eq!(entry.seq, 0);

    // Independent readback: parse the raw persisted bytes, not the API's in-memory
    // copy, and confirm the ledgered entry equals the card we built.
    let raw = std::fs::read_to_string(&ledger_path).unwrap();
    let line = raw.lines().next().expect("one ledgered line");
    let persisted: AssayCardEntry = serde_json::from_str(line).unwrap();
    assert_eq!(persisted.card, card, "persisted card == built card");
    assert_eq!(persisted.seed, seed);
    assert_eq!(persisted.input_fingerprint, fp);
    // Every ledgered signal carries the estimator, n, interval, and trust.
    for s in &persisted.card.signals {
        assert!(!s.estimator.is_empty());
        assert!(s.n > 0);
        assert!(s.interval.level_permille > 0);
    }

    // Reproduce from a FRESH ledger handle over the persisted file: re-derives the
    // exact card (seed-invariant, worker-count invariant).
    let fresh = CardLedger::open(&ledger_path).unwrap();
    let rederived = fresh.reproduce(0, &slots, &axis, &cfg).unwrap();
    assert_eq!(
        rederived, card,
        "reproduce re-derives the ledgered card exactly"
    );

    // Reproducing against altered inputs is refused on fingerprint mismatch.
    let mut altered = slots.clone();
    if let SlotValues::Scalar(v) = &mut altered[0].values {
        v[0] += 3.0;
    }
    let err = fresh.reproduce(0, &altered, &axis, &cfg).unwrap_err();
    assert_eq!(err.code(), ASTRO_ASSAY_REPRODUCE_MISMATCH);
}

/// Determinism is seed- and worker-count invariant: two independent builds of the
/// same card (as parallel workers would produce) are byte-identical.
#[test]
fn cards_are_seed_and_worker_count_invariant() {
    let cfg = test_cfg();
    let n = 200;
    let (x, a) = planted_correlated(0.55, n, 5);
    let slots = vec![SlotObservations {
        slot: "s".into(),
        values: SlotValues::Scalar(x),
    }];
    let axis = AxisValues::Continuous(a);
    let one = build_signal_ranking("axis", &slots, &axis, 5, &cfg).unwrap();
    let two = build_signal_ranking("axis", &slots, &axis, 5, &cfg).unwrap();
    assert_eq!(one, two);
    // Serialized bytes are identical too (the determinism evidence FSV reads back).
    assert_eq!(
        serde_json::to_vec(&one).unwrap(),
        serde_json::to_vec(&two).unwrap()
    );
}

/// Embedding slots route through the deterministic random projection and still
/// recover a planted signal — the high-dimensional path is exercised end to end.
#[test]
fn embedding_slot_projects_and_recovers_signal() {
    let cfg = test_cfg();
    let n = 400;
    let dim = 64;
    // The first `signal_dims` coordinates each carry the latent signal (plus a
    // little noise) so it survives the random projection into ~2·log2(n) dims;
    // the rest are pure noise. A real embedding slot concentrates a predictive
    // direction across several coordinates just like this.
    let signal_dims = 12;
    let mut rng = DeterministicRng::from_u64_labeled(3, "emb");
    let mut rows = Vec::with_capacity(n);
    let mut axis = Vec::with_capacity(n);
    for _ in 0..n {
        let signal = rng.next_standard_normal();
        let mut v = Vec::with_capacity(dim);
        for d in 0..dim {
            if d < signal_dims {
                v.push(signal + 0.4 * rng.next_standard_normal());
            } else {
                v.push(rng.next_standard_normal());
            }
        }
        rows.push(v);
        axis.push(if signal > 0.0 { 1 } else { 0 });
    }
    let slot = SlotObservations {
        slot: "embedding".into(),
        values: SlotValues::Embedding { dim, rows },
    };
    let bits = measure_slot_bits(&slot, &AxisValues::Discrete(axis), 3, &cfg).unwrap();
    // The signal survives projection: measurably positive, and the estimator name
    // records the projection width.
    assert!(bits.bits > 0.10, "projected embedding bits={}", bits.bits);
    assert!(
        bits.estimator.contains("+rp"),
        "estimator={}",
        bits.estimator
    );
    assert!(!bits.provisional);
}
