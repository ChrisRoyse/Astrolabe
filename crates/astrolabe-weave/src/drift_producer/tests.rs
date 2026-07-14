use super::*;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_assay::DiffConfig;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{AnchorKind, SystemClock, VaultId};

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
    persist_drift_reference(&vault, cache_key(), "drift:reference", &reference)
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
