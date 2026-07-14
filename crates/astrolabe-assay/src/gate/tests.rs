//! FSV tests for the per-repo lens capability gate (#35).
//!
//! Every persistence test writes real bytes to a real temp directory and reads
//! the state back through a *fresh* [`GateJournal`] handle, so the evidence is the
//! persisted bytes, never an in-memory return value.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use super::*;
use crate::error::{
    ASTRO_ASSAY_GATE_INPUT_INVALID, ASTRO_ASSAY_GATE_REVERT_INVALID, ASTRO_ASSAY_STORE_CORRUPT,
};

/// A unique temp dir for one test, removed on drop.
struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astro-gate-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn journal(&self) -> GateJournal {
        GateJournal::open(self.path.join("gate.ndjson")).unwrap()
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn axis(bits: f64) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    m.insert("defect".to_string(), bits);
    m
}

/// Builds a minimal but *measured* card: a varying activation across two strata,
/// full coverage, and the given per-axis bits.
fn card(lens: &str, bits: f64) -> LensCapabilityCard {
    let activation = vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0];
    let present = vec![true; 6];
    let strata = vec![
        "a".to_string(),
        "a".to_string(),
        "a".to_string(),
        "b".to_string(),
        "b".to_string(),
        "b".to_string(),
    ];
    build_capability_card(lens, &activation, &present, &strata, axis(bits), 1.0).unwrap()
}

// ---- DoD 1: decision-table + pinned boundaries -----------------------------

#[test]
fn admit_when_signal_and_low_correlation() {
    let cfg = GateConfig::from_defaults().unwrap();
    let c = card("strong", 0.5);
    let d = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.1,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(d.verdict, GateVerdict::Admit);
    assert_eq!(d.reason_code, GATE_REASON_ADMIT_SIGNAL);
}

#[test]
fn retire_when_correlation_exceeds_threshold() {
    let cfg = GateConfig::from_defaults().unwrap();
    let c = card("redundant", 0.9); // strong signal, but redundant
    let d = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.61,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(d.verdict, GateVerdict::Retire);
    assert_eq!(d.reason_code, GATE_REASON_RETIRE_REDUNDANT);
}

#[test]
fn park_when_no_signal_and_not_sole_carrier() {
    let cfg = GateConfig::from_defaults().unwrap();
    let c = card("weak", 0.01); // below 0.05-bit floor
    let d = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.1,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(d.verdict, GateVerdict::Park);
    assert_eq!(d.reason_code, GATE_REASON_PARK_NO_SIGNAL);
}

#[test]
fn stratified_override_admits_weak_sole_carrier() {
    let cfg = GateConfig::from_defaults().unwrap();
    let c = card("error_surface", 0.01); // globally weak
    let d = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.1,
            sole_critical_carrier: true,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(d.verdict, GateVerdict::Admit);
    assert_eq!(d.reason_code, GATE_REASON_ADMIT_OVERRIDE);
}

#[test]
fn boundary_correlation_exactly_threshold_is_not_retired() {
    let cfg = GateConfig::from_defaults().unwrap();
    assert_eq!(cfg.retire_correlation, 0.6);
    let c = card("edge", 0.5);
    // Exactly 0.6 — the comparison is strict (>), so this is NOT retired.
    let d = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.6,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(d.verdict, GateVerdict::Admit);
}

#[test]
fn boundary_signal_exactly_floor_is_not_parked() {
    let cfg = GateConfig::from_defaults().unwrap();
    assert_eq!(cfg.min_signal_bits, 0.05);
    let c = card("edge", 0.05); // exactly the floor
    // Park is strict (< floor), so exactly 0.05 bits is admitted.
    let d = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.1,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(d.verdict, GateVerdict::Admit);
    assert_eq!(d.reason_code, GATE_REASON_ADMIT_SIGNAL);
}

// ---- DoD 2: stratified-override correctness (positive + negative) ----------

#[test]
fn sole_carrier_positive_and_negative() {
    // A rare-critical stratum carried by only `error_surface`.
    let mut carriers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    carriers.insert(
        "incident".to_string(),
        BTreeSet::from(["error_surface".to_string()]),
    );
    assert!(is_sole_critical_carrier("error_surface", &carriers));

    // Plant a second carrier in the same stratum — the override no longer applies.
    carriers
        .get_mut("incident")
        .unwrap()
        .insert("type_surface".into());
    assert!(!is_sole_critical_carrier("error_surface", &carriers));
    assert!(!is_sole_critical_carrier("type_surface", &carriers));
}

#[test]
fn override_flips_park_to_admit_only_when_sole() {
    let cfg = GateConfig::from_defaults().unwrap();
    let c = card("error_surface", 0.02); // globally weak

    // Sole carrier => Admit (override).
    let sole = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.1,
            sole_critical_carrier: true,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(sole.verdict, GateVerdict::Admit);

    // A second carrier exists => not sole => Park.
    let shared = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 0.1,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(shared.verdict, GateVerdict::Park);
}

// ---- DoD 3: reversibility (before/after byte-compare) ----------------------

#[test]
fn revert_restores_prior_serving_state_exactly() {
    let root = TempRoot::new("revert");
    let repo = "acme/widgets";
    let cfg = GateConfig::from_defaults().unwrap();

    let journal = root.journal();
    // seq 0: Admit lens X.
    let admit = gate_lens(
        &GateEvaluation {
            card: &card("x", 0.5),
            max_admitted_correlation: 0.1,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    journal.append_decision(repo, &admit).unwrap();

    // Snapshot the serving state with X admitted (read back through a fresh handle).
    let before = root.journal().serving_state_bytes(repo).unwrap();
    let admitted_before = root.journal().serving_admission(repo).unwrap();
    assert_eq!(admitted_before.admitted, vec!["x".to_string()]);

    // seq 1: Retire lens X (redundancy discovered).
    let retire = gate_lens(
        &GateEvaluation {
            card: &card("x", 0.5),
            max_admitted_correlation: 0.9,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    let retire_entry = journal.append_decision(repo, &retire).unwrap();
    let mid = root.journal().serving_admission(repo).unwrap();
    assert_eq!(mid.retired, vec!["x".to_string()]);
    assert!(mid.admitted.is_empty());

    // Revert seq 1 -> serving state must equal the pre-retire snapshot, byte-for-byte.
    root.journal().revert(retire_entry.seq).unwrap();
    let after = root.journal().serving_state_bytes(repo).unwrap();
    assert_eq!(
        after, before,
        "revert did not restore the prior serving state byte-for-byte"
    );
}

#[test]
fn revert_of_first_decision_returns_to_empty() {
    let root = TempRoot::new("revert-empty");
    let repo = "acme/empty";
    let cfg = GateConfig::from_defaults().unwrap();

    let empty = root.journal().serving_state_bytes(repo).unwrap();

    let journal = root.journal();
    let retire = gate_lens(
        &GateEvaluation {
            card: &card("y", 0.5),
            max_admitted_correlation: 0.95,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    let e = journal.append_decision(repo, &retire).unwrap();
    assert!(
        !root
            .journal()
            .serving_admission(repo)
            .unwrap()
            .retired
            .is_empty()
    );

    journal.revert(e.seq).unwrap();
    let after = root.journal().serving_state_bytes(repo).unwrap();
    assert_eq!(
        after, empty,
        "revert of the only decision did not return to empty"
    );
}

#[test]
fn double_revert_is_rejected() {
    let root = TempRoot::new("double-revert");
    let repo = "acme/x";
    let cfg = GateConfig::from_defaults().unwrap();
    let journal = root.journal();
    let d = gate_lens(
        &GateEvaluation {
            card: &card("z", 0.5),
            max_admitted_correlation: 0.9,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    let e = journal.append_decision(repo, &d).unwrap();
    journal.revert(e.seq).unwrap();
    let err = journal.revert(e.seq).unwrap_err();
    assert_eq!(err.code(), ASTRO_ASSAY_GATE_REVERT_INVALID);
}

// ---- DoD 4 (pure-crate analog): non-destructive — history stays readable ----

#[test]
fn reverted_decision_and_card_stay_readable() {
    let root = TempRoot::new("nondestructive");
    let repo = "acme/history";
    let cfg = GateConfig::from_defaults().unwrap();
    let journal = root.journal();

    let the_card = card("archived", 0.5);
    let d = gate_lens(
        &GateEvaluation {
            card: &the_card,
            max_admitted_correlation: 0.9,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    let e = journal.append_decision(repo, &d).unwrap();
    journal.revert(e.seq).unwrap();

    // The serving fold excludes the reverted lens...
    let serving = root.journal().serving_admission(repo).unwrap();
    assert!(serving.retired.is_empty() && serving.admitted.is_empty());

    // ...but the historical decision entry — and its card hash — remain readable.
    let all = root.journal().read_all().unwrap();
    let decide = all
        .iter()
        .find(|x| x.seq == e.seq)
        .expect("decision still present");
    match &decide.action {
        GateAction::Decide {
            card_hash, verdict, ..
        } => {
            assert_eq!(*verdict, GateVerdict::Retire);
            assert_eq!(*card_hash, the_card.card_hash().unwrap());
        }
        GateAction::Revert { .. } => panic!("seq {} should be a Decide", e.seq),
    }
}

// ---- DoD 5: ledger completeness — every decision carries the input card hash --

#[test]
fn every_decision_entry_carries_its_input_card_hash() {
    let root = TempRoot::new("ledger-complete");
    let repo = "acme/complete";
    let cfg = GateConfig::from_defaults().unwrap();
    let journal = root.journal();

    let cards = [card("a", 0.5), card("b", 0.01), card("c", 0.9)];
    let corrs = [0.1_f64, 0.1, 0.95];
    let mut expected: BTreeMap<u64, String> = BTreeMap::new();
    for (c, corr) in cards.iter().zip(corrs.iter()) {
        let d = gate_lens(
            &GateEvaluation {
                card: c,
                max_admitted_correlation: *corr,
                sole_critical_carrier: false,
            },
            &cfg,
        )
        .unwrap();
        let e = journal.append_decision(repo, &d).unwrap();
        expected.insert(e.seq, c.card_hash().unwrap());
    }

    // Read back through a fresh handle and confirm each Decide pairs with its card.
    for entry in root.journal().read_all().unwrap() {
        match entry.action {
            GateAction::Decide { card_hash, .. } => {
                assert_eq!(card_hash, expected[&entry.seq]);
                assert_eq!(card_hash.len(), 64, "blake3 hex hash");
            }
            GateAction::Revert { .. } => {}
        }
    }
}

// ---- capability-card + correlation measurement checks ----------------------

#[test]
fn capability_card_measures_profile() {
    // Activation perfectly separated by stratum => eta^2 = 1.0; coverage 5/6.
    let activation = vec![0.0, 0.0, 0.0, 10.0, 10.0, 10.0];
    let present = vec![true, true, false, true, true, true];
    let strata = vec![
        "a".to_string(),
        "a".to_string(),
        "a".to_string(),
        "b".to_string(),
        "b".to_string(),
        "b".to_string(),
    ];
    let mut bits = BTreeMap::new();
    bits.insert("defect".to_string(), 0.3);
    bits.insert("runtime".to_string(), 0.7);
    let c = build_capability_card("s", &activation, &present, &strata, bits, 2.5).unwrap();
    assert_eq!(c.n, 6);
    assert!((c.coverage - 5.0 / 6.0).abs() < 1e-12);
    assert!((c.separation - 1.0).abs() < 1e-9, "sep={}", c.separation);
    assert_eq!(c.signal_bits, 0.7); // max over axes
    assert!(c.spread > 0.0);
    assert_eq!(c.cost_units, 2.5);
}

#[test]
fn correlation_is_measured_and_bounded() {
    let a = vec![1.0, 2.0, 3.0, 4.0];
    let b = vec![2.0, 4.0, 6.0, 8.0]; // perfectly collinear
    assert!((pearson_correlation(&a, &b).unwrap() - 1.0).abs() < 1e-12);
    let anti = vec![8.0, 6.0, 4.0, 2.0]; // perfectly anti-collinear -> |r| = 1
    assert!((pearson_correlation(&a, &anti).unwrap() - 1.0).abs() < 1e-12);
    // Constant vector => no variance => treated as uncorrelated.
    let konst = vec![5.0, 5.0, 5.0, 5.0];
    assert_eq!(pearson_correlation(&a, &konst).unwrap(), 0.0);

    let admitted = vec![b.clone(), konst.clone()];
    assert!((max_admitted_correlation(&a, &admitted).unwrap() - 1.0).abs() < 1e-12);
    assert_eq!(max_admitted_correlation(&a, &[]).unwrap(), 0.0);
}

#[test]
fn gate_rejects_out_of_range_correlation() {
    let cfg = GateConfig::from_defaults().unwrap();
    let c = card("x", 0.5);
    let err = gate_lens(
        &GateEvaluation {
            card: &c,
            max_admitted_correlation: 1.5,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap_err();
    assert_eq!(err.code(), ASTRO_ASSAY_GATE_INPUT_INVALID);
}

#[test]
fn build_card_rejects_misaligned_inputs() {
    let err = build_capability_card(
        "x",
        &[1.0, 2.0],
        &[true],
        &["a".to_string(), "b".to_string()],
        axis(0.1),
        1.0,
    )
    .unwrap_err();
    assert_eq!(err.code(), ASTRO_ASSAY_GATE_INPUT_INVALID);
}

// ---- journal integrity -----------------------------------------------------

#[test]
fn journal_chain_detects_tamper() {
    let root = TempRoot::new("tamper");
    let repo = "acme/tamper";
    let cfg = GateConfig::from_defaults().unwrap();
    let journal = root.journal();
    let d = gate_lens(
        &GateEvaluation {
            card: &card("x", 0.5),
            max_admitted_correlation: 0.1,
            sole_critical_carrier: false,
        },
        &cfg,
    )
    .unwrap();
    journal.append_decision(repo, &d).unwrap();

    // Tamper: rewrite the entry's repo but keep the stale hash.
    let mut entries = journal.read_all().unwrap();
    entries[0].repo = "attacker/repo".to_string();
    let mut line = serde_json::to_vec(&entries[0]).unwrap();
    line.push(b'\n');
    fs::write(root.path.join("gate.ndjson"), &line).unwrap();

    let err = journal.read_all().unwrap_err();
    assert_eq!(err.code(), ASTRO_ASSAY_STORE_CORRUPT);
}
