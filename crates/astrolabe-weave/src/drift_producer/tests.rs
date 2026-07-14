use super::*;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_assay::DiffConfig;
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{AnchorKind, SystemClock, VaultId};
use serde_json::Value;

use crate::{AnomalyKind, detect_anomalies, live_anomaly_inputs_from_vault};

const DRIFT_SALT: &[u8] = b"astrolabe-weave-drift-producer-fsv";
const PANEL_VERSION: u32 = 2;
const SEED: u64 = 7;
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn vault_id() -> VaultId {
    "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

fn durable_vault(name: &str) -> (PathBuf, AsterVault<SystemClock>) {
    let dir = std::env::temp_dir().join(format!(
        "astrolabe-weave-drift-{name}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create drift test vault dir");
    let vault = open_durable_vault(&dir);
    (dir, vault)
}

fn open_durable_vault(dir: &Path) -> AsterVault<SystemClock> {
    AsterVault::new_durable(
        dir,
        vault_id(),
        DRIFT_SALT.to_vec(),
        VaultOptions::default(),
    )
    .expect("open durable drift vault")
}

fn cache_key() -> AssayCacheKey {
    AssayCacheKey::scoped(PANEL_VERSION, "drift-fsv", vault_id(), AnchorKind::Reward)
}

/// A linear scalar sample set of `n` points, offset by `base`. Reference (base 0)
/// vs a translated current (base 5) is the same planted mean shift the read-side
/// #68 test uses; identical sets are the stable/no-drift case.
fn scalars(n: usize, base: f64) -> Vec<Vec<f64>> {
    (0..n).map(|i| vec![base + (i as f64) * 0.01]).collect()
}

/// Eight stable slots (reference == current) plus one slot that drifts between
/// reference and current. Returns (reference, current). The eight stable, zero-
/// score cards give the measured calibration its floor; the ninth carries the
/// alarm.
fn shift_fixture() -> (Vec<DriftSlotSamples>, Vec<DriftSlotSamples>) {
    let mut reference = Vec::new();
    let mut current = Vec::new();
    for i in 0..8 {
        reference.push(DriftSlotSamples {
            slot: format!("S{i}"),
            samples: scalars(12, 0.0),
        });
        current.push(DriftSlotSamples {
            slot: format!("S{i}"),
            samples: scalars(12, 0.0),
        });
    }
    reference.push(DriftSlotSamples {
        slot: "S18".to_string(),
        samples: scalars(12, 0.0),
    });
    current.push(DriftSlotSamples {
        slot: "S18".to_string(),
        samples: scalars(12, 5.0),
    });
    (reference, current)
}

#[test]
fn planted_shift_between_imports_surfaces_a_drift_finding_from_persisted_bytes() {
    let (dir, vault) = durable_vault("shift");
    let cfg = DiffConfig::from_defaults().expect("diff config");
    let (reference, current) = shift_fixture();

    // Import 1: snapshot the reference window, and round-trip it back from the
    // persisted Assay CF bytes.
    persist_drift_reference(&vault, cache_key(), "drift:reference", &reference, SEED)
        .expect("persist reference window");
    let reloaded = load_drift_reference(&vault).expect("load reference window");
    assert_eq!(reloaded, reference, "reference window must round-trip");

    // Import 2: produce cards (reference vs shifted current), ledger-paired.
    let ledger = astrolabe_assay::DiffLedger::open(dir.join("drift-cards.ndjson"))
        .expect("open drift card ledger");
    let report = produce_drift_cards(
        &vault,
        cache_key(),
        "drift:cards",
        &reference,
        &current,
        SEED,
        &cfg,
        Some(&ledger),
    )
    .expect("produce drift cards");
    assert_eq!(report.cards_written, 9, "{report:?}");
    assert_eq!(report.cards_ledgered, 9, "{report:?}");
    assert_eq!(report.slots_missing_reference, 0, "{report:?}");
    assert_eq!(report.slots_short_history, 0, "{report:?}");
    assert!(report.cards_payload_persisted, "{report:?}");

    // Hash-chained card ledger reads back with all nine entries.
    assert_eq!(
        ledger.read_all().expect("read card ledger").len(),
        9,
        "every produced card is ledger-paired"
    );

    // Independent readback: reopen the vault, rebuild anomaly inputs from the
    // persisted Assay bytes, and tier drift findings.
    drop(vault);
    let reopened = open_durable_vault(&dir);
    let inputs = live_anomaly_inputs_from_vault(&reopened).expect("live drift inputs");
    assert_eq!(inputs.skipped_rows, 0, "every persisted drift card parsed");
    assert_eq!(
        inputs
            .substrates
            .iter()
            .filter(|substrate| substrate.kind == AnomalyKind::Drift)
            .count(),
        9,
        "nine persisted drift substrates"
    );
    let anomaly = detect_anomalies(
        &inputs.substrates,
        &inputs.calibrations,
        Some("drift"),
        true,
    )
    .expect("tier drift findings");
    assert!(
        anomaly
            .findings
            .iter()
            .any(|finding| finding.kind == AnomalyKind::Drift && finding.subject_id == "slot:S18"),
        "planted-shift slot must surface as a drift finding: {:?}",
        anomaly.findings
    );

    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stable_reimport_raises_no_drift_finding() {
    // Every slot identical between reference and current: no card drifts, the
    // score spread is degenerate, so the calibration is absent and nothing tiers
    // — the false-positive case yields honest silence, not an alarm.
    let (dir, vault) = durable_vault("stable");
    let cfg = DiffConfig::from_defaults().expect("diff config");
    let (reference, _) = shift_fixture();
    let current = reference.clone();

    let report = produce_drift_cards(
        &vault,
        cache_key(),
        "drift:cards",
        &reference,
        &current,
        SEED,
        &cfg,
        None,
    )
    .expect("produce drift cards");
    assert_eq!(report.cards_written, 9, "{report:?}");
    assert!(report.cards_payload_persisted, "{report:?}");

    drop(vault);
    let reopened = open_durable_vault(&dir);
    let inputs = live_anomaly_inputs_from_vault(&reopened).expect("live drift inputs");
    let anomaly = detect_anomalies(
        &inputs.substrates,
        &inputs.calibrations,
        Some("drift"),
        true,
    )
    .expect("tier drift findings");
    assert!(
        !anomaly
            .findings
            .iter()
            .any(|finding| finding.kind == AnomalyKind::Drift),
        "a stable re-import must raise no drift finding: {:?}",
        anomaly.findings
    );

    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_reference_is_a_labeled_absence_not_a_fabricated_card() {
    // First import: no reference window at all. Every populated slot is a labeled
    // absence; no anomaly payload is persisted (no fabricated baseline).
    let (dir, vault) = durable_vault("no-reference");
    let cfg = DiffConfig::from_defaults().expect("diff config");
    let (_, current) = shift_fixture();

    assert!(
        load_drift_reference(&vault)
            .expect("load reference window")
            .is_empty(),
        "a fresh vault has no reference window"
    );

    let report = produce_drift_cards(
        &vault,
        cache_key(),
        "drift:cards",
        &[],
        &current,
        SEED,
        &cfg,
        None,
    )
    .expect("produce drift cards");
    assert_eq!(report.cards_written, 0, "{report:?}");
    assert_eq!(report.slots_missing_reference, 9, "{report:?}");
    assert!(!report.cards_payload_persisted, "{report:?}");

    // No anomaly payload landed, so the read path surfaces no drift substrate.
    let reopened = open_durable_vault(&dir);
    drop(vault);
    let inputs = live_anomaly_inputs_from_vault(&reopened).expect("live drift inputs");
    assert_eq!(
        inputs
            .substrates
            .iter()
            .filter(|substrate| substrate.kind == AnomalyKind::Drift)
            .count(),
        0,
        "no fabricated drift substrate without a reference window"
    );

    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reads the raw persisted reference-row value bytes back from the Assay CF,
/// never trusting an in-memory value. The reference row is the only Assay row
/// carrying [`DRIFT_REFERENCE_PAYLOAD_SCHEMA`].
fn persisted_reference_value(vault: &AsterVault<SystemClock>) -> Vec<u8> {
    for (_key, value) in vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::Assay)
        .expect("scan assay cf")
    {
        if std::str::from_utf8(&value)
            .map(|text| text.contains(DRIFT_REFERENCE_PAYLOAD_SCHEMA))
            .unwrap_or(false)
        {
            return value;
        }
    }
    panic!("no persisted drift reference row in Assay CF");
}

#[test]
fn reference_cap_knob_is_declared_and_within_bounds() {
    let cap = drift_reference_sample_cap().expect("cap resolves");
    assert_eq!(cap, DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP as usize);
    let knob = DRIFT_REFERENCE_KNOBS
        .iter()
        .find(|k| k.name == DRIFT_REFERENCE_SAMPLE_CAP_KNOB)
        .expect("cap knob is declared");
    assert!(
        knob.accepts(knob.default),
        "declared default must be in-bounds"
    );
    assert_eq!(knob.min, DRIFT_REFERENCE_MIN_SAMPLE_CAP);
    assert_eq!(knob.max, DRIFT_REFERENCE_MAX_SAMPLE_CAP);
    assert!(knob.min >= 2, "MMD needs at least two points per side");
    assert_eq!(knob.registry_version, DRIFT_REFERENCE_KNOB_REGISTRY_VERSION);
}

#[test]
fn reservoir_bounds_and_is_deterministic() {
    // cap >= population → whole slot kept; provenance retained == population.
    let small = vec![DriftSlotSamples {
        slot: "S0".to_string(),
        samples: scalars(10, 0.0),
    }];
    let (bounded, prov) = bound_reference_window(&small, 384, 7);
    assert_eq!(bounded[0].samples.len(), 10);
    assert_eq!(prov[0].population, 10);
    assert_eq!(prov[0].retained, 10);

    // cap == population exactly → boundary keeps the whole slot, no reservoir.
    let (bounded_eq, _) = bound_reference_window(&small, 10, 7);
    assert_eq!(bounded_eq[0].samples, small[0].samples);

    // population > cap → retained == cap exactly, only genuine members kept.
    let big = vec![DriftSlotSamples {
        slot: "S0".to_string(),
        samples: scalars(1000, 0.0),
    }];
    let (bounded_big, prov_big) = bound_reference_window(&big, 50, 7);
    assert_eq!(bounded_big[0].samples.len(), 50);
    assert_eq!(prov_big[0].population, 1000);
    assert_eq!(prov_big[0].retained, 50);
    for point in &bounded_big[0].samples {
        assert!(
            big[0].samples.contains(point),
            "reservoir keeps only real population members (no fabrication)"
        );
    }

    // Determinism: same (samples, cap, seed) → byte-identical retained subset.
    let (again, _) = bound_reference_window(&big, 50, 7);
    assert_eq!(
        bounded_big[0].samples, again[0].samples,
        "reservoir is a pure function of (samples, cap, seed)"
    );
    // A different seed selects a different subset.
    let (other_seed, _) = bound_reference_window(&big, 50, 8);
    assert_ne!(
        bounded_big[0].samples, other_seed[0].samples,
        "the reservoir is seed-dependent"
    );
}

#[test]
fn bounded_reference_row_is_independent_of_corpus_size() {
    // #371 DoD box 1: the persisted reference row is bounded and independent of
    // corpus size. Fixed-width samples make the persisted `slots` payload a pure
    // function of the retained COUNT, so two corpora of wildly different size that
    // both exceed the cap persist a byte-identical `slots` payload.
    let cap = drift_reference_sample_cap().expect("declared cap");

    let flat = |n: usize| {
        vec![DriftSlotSamples {
            slot: "S18".to_string(),
            samples: vec![vec![1.0]; n],
        }]
    };

    // Returns (retained-count, persisted-slots-byte-length) read back from bytes.
    let persist_and_read = |name: &str, population: usize| -> (usize, usize) {
        let (dir, vault) = durable_vault(name);
        let report = persist_drift_reference(
            &vault,
            cache_key(),
            "drift:reference",
            &flat(population),
            SEED,
        )
        .expect("persist bounded reference");
        // Independent readback of the persisted Assay CF bytes.
        let value = persisted_reference_value(&vault);
        let row: Value = serde_json::from_slice(&value).expect("row json");
        let persisted_slots = &row["payload"]["slots"];
        let persisted_retained = persisted_slots[0]["samples"]
            .as_array()
            .expect("samples array")
            .len();
        assert_eq!(
            report.total_retained, persisted_retained,
            "in-memory report must match the persisted bytes"
        );
        let slots_len = serde_json::to_vec(persisted_slots)
            .expect("slots bytes")
            .len();
        drop(vault);
        let _ = std::fs::remove_dir_all(&dir);
        (persisted_retained, slots_len)
    };

    let (r_small, b_small) = persist_and_read("bound-small", 100); // below cap
    let (r_500, b_500) = persist_and_read("bound-500", 500); // above cap
    let (r_5000, b_5000) = persist_and_read("bound-5000", 5000); // 10x corpus

    assert_eq!(r_small, 100, "a below-cap slot keeps every sample");
    assert_eq!(r_500, cap, "an above-cap slot bounds to the cap");
    assert_eq!(r_5000, cap, "a 10x-larger corpus bounds to the SAME cap");
    assert_eq!(
        b_500, b_5000,
        "the O(corpus) payload is byte-identical across a 10x corpus difference ({b_500} vs {b_5000})"
    );
    assert!(
        b_small < b_500,
        "a below-cap slot persists strictly fewer bytes"
    );

    // The bound actually shrinks the row: an unbounded 5000-sample persist would
    // be an order of magnitude larger than the bounded payload.
    let unbounded = serde_json::to_vec(&flat(5000))
        .expect("unbounded bytes")
        .len();
    assert!(
        b_5000 * 5 < unbounded,
        "bounding cut the reference far below O(corpus): bounded={b_5000} unbounded={unbounded}"
    );
}

#[test]
fn planted_shift_still_detected_through_the_sampled_reference() {
    // #371 DoD box 2: planted-shift detection stays green with the sampled
    // reference (sensitivity pinned). One reference slot far exceeds the cap and
    // is reservoir-bounded before persistence; the bounded reference is reloaded
    // from bytes and still surfaces a planted shift.
    let (dir, vault) = durable_vault("sampled-sensitivity");
    let cfg = DiffConfig::from_defaults().expect("diff config");
    let cap = drift_reference_sample_cap().expect("declared cap");

    let mut reference = Vec::new();
    for i in 0..8 {
        reference.push(DriftSlotSamples {
            slot: format!("S{i}"),
            samples: scalars(12, 0.0),
        });
    }
    reference.push(DriftSlotSamples {
        slot: "S18".to_string(),
        samples: scalars(500, 0.0),
    });

    let report = persist_drift_reference(&vault, cache_key(), "drift:reference", &reference, SEED)
        .expect("persist bounded reference");
    assert_eq!(report.sample_cap, cap);
    let s18 = report
        .per_slot
        .iter()
        .find(|s| s.slot == "S18")
        .expect("S18 provenance");
    assert_eq!(s18.population, 500);
    assert_eq!(
        s18.retained, cap,
        "the high-population reference slot was bounded"
    );

    // Reload the BOUNDED reference from persisted bytes.
    let bounded_reference = load_drift_reference(&vault).expect("load bounded reference");
    let bounded_s18 = bounded_reference
        .iter()
        .find(|s| s.slot == "S18")
        .expect("reloaded S18");
    assert_eq!(
        bounded_s18.samples.len(),
        cap,
        "reloaded reference is bounded"
    );

    let mut current = Vec::new();
    for i in 0..8 {
        current.push(DriftSlotSamples {
            slot: format!("S{i}"),
            samples: scalars(12, 0.0),
        });
    }
    current.push(DriftSlotSamples {
        slot: "S18".to_string(),
        samples: scalars(300, 100.0),
    });

    let report = produce_drift_cards(
        &vault,
        cache_key(),
        "drift:cards",
        &bounded_reference,
        &current,
        SEED,
        &cfg,
        None,
    )
    .expect("produce drift cards");
    assert_eq!(report.cards_written, 9, "{report:?}");
    assert!(report.cards_payload_persisted, "{report:?}");

    drop(vault);
    let reopened = open_durable_vault(&dir);
    let inputs = live_anomaly_inputs_from_vault(&reopened).expect("live drift inputs");
    let anomaly = detect_anomalies(
        &inputs.substrates,
        &inputs.calibrations,
        Some("drift"),
        true,
    )
    .expect("tier drift findings");
    assert!(
        anomaly
            .findings
            .iter()
            .any(|finding| finding.kind == AnomalyKind::Drift && finding.subject_id == "slot:S18"),
        "planted shift must survive the sampled reference: {:?}",
        anomaly.findings
    );

    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn below_two_point_history_is_a_labeled_short_history_absence() {
    // A slot whose current window has fewer than the two points MMD requires is a
    // labeled short-history absence, never a card.
    let (dir, vault) = durable_vault("short-history");
    let cfg = DiffConfig::from_defaults().expect("diff config");
    let reference = vec![DriftSlotSamples {
        slot: "S0".to_string(),
        samples: scalars(12, 0.0),
    }];
    let current = vec![DriftSlotSamples {
        slot: "S0".to_string(),
        samples: scalars(1, 0.0),
    }];

    let report = produce_drift_cards(
        &vault,
        cache_key(),
        "drift:cards",
        &reference,
        &current,
        SEED,
        &cfg,
        None,
    )
    .expect("produce drift cards");
    assert_eq!(report.cards_written, 0, "{report:?}");
    assert_eq!(report.slots_short_history, 1, "{report:?}");
    assert!(!report.cards_payload_persisted, "{report:?}");

    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
}
