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

/// The 8 MiB Calyx memtable byte cap (`calyx-aster` `DEFAULT_MEMTABLE_BYTES`).
/// A single persisted Assay row (`key + value + 4`) above this fails closed with
/// `CALYX_BACKPRESSURE` — the wave-14 live falsification of #371.
const MEMTABLE_BYTE_CAP: usize = 8 * 1024 * 1024;

/// Byte cost the memtable charges one raw row: `key + value + ENTRY_OVERHEAD(4)`.
fn row_entry_size(key: &[u8], value: &[u8]) -> usize {
    key.len() + value.len() + 4
}

/// Every persisted drift-reference row (`(key, value)`) read back from the Assay
/// CF, identified by the schema tag. Multi-chunk references land as several rows.
fn persisted_reference_rows(vault: &AsterVault<SystemClock>) -> Vec<(Vec<u8>, Vec<u8>)> {
    vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::Assay)
        .expect("scan assay cf")
        .into_iter()
        .filter(|(_key, value)| {
            std::str::from_utf8(value)
                .map(|text| text.contains(DRIFT_REFERENCE_PAYLOAD_SCHEMA))
                .unwrap_or(false)
        })
        .collect()
}

/// `n` samples of `dim` floats, offset by `base`; distinct per (i, j) so the JSON
/// is corpus-realistic, not a compressible constant.
fn wide(n: usize, dim: usize, base: f64) -> Vec<Vec<f64>> {
    (0..n)
        .map(|i| {
            (0..dim)
                .map(|j| base + (i as f64) * 0.01 + (j as f64) * 0.001)
                .collect()
        })
        .collect()
}

#[test]
fn chunk_budget_knob_is_declared_within_bounds_and_refuses_out_of_bounds() {
    // #371 edge: the global byte-budget knob resolves, is in-bounds, and a
    // declaration whose default violates its own bounds is refused fail-closed.
    let budget = drift_reference_chunk_budget_bytes().expect("budget resolves");
    assert_eq!(budget, DRIFT_REFERENCE_DEFAULT_CHUNK_BUDGET_BYTES as usize);
    let knob = DRIFT_REFERENCE_KNOBS
        .iter()
        .find(|k| k.name == DRIFT_REFERENCE_CHUNK_BUDGET_KNOB)
        .expect("budget knob is declared");
    assert!(
        knob.accepts(knob.default),
        "declared default must be in-bounds"
    );
    assert_eq!(knob.min, DRIFT_REFERENCE_MIN_CHUNK_BUDGET_BYTES);
    assert_eq!(knob.max, DRIFT_REFERENCE_MAX_CHUNK_BUDGET_BYTES);
    assert_eq!(knob.registry_version, DRIFT_REFERENCE_KNOB_REGISTRY_VERSION);
    // The budget stays strictly below the memtable cap so a max-budget chunk is
    // still admissible after the row envelope is added.
    assert!(
        (knob.max as usize) < MEMTABLE_BYTE_CAP,
        "max chunk budget must leave headroom under the memtable cap"
    );
    // Fail-closed guard: an out-of-bounds default is rejected by the same
    // `accepts` gate the resolver enforces.
    let bad = astrolabe_domain::knobs::U64KnobDeclaration {
        registry_version: DRIFT_REFERENCE_KNOB_REGISTRY_VERSION,
        name: "synthetic_bad",
        default: 0,
        min: DRIFT_REFERENCE_MIN_CHUNK_BUDGET_BYTES,
        max: DRIFT_REFERENCE_MAX_CHUNK_BUDGET_BYTES,
        unit: "bytes",
        source: "test",
        rationale: "test",
    };
    assert!(
        !bad.accepts(bad.default),
        "an out-of-bounds default must be refused, never clamped"
    );
}

#[test]
fn tiny_corpus_persists_one_legacy_row_without_a_chunk_header() {
    // #371 edge: a tiny corpus fits in one chunk → exactly one Assay row, the
    // pre-chunking payload shape (no `chunk` header), byte-identical across a
    // same-seed re-persist.
    let (dir, vault) = durable_vault("tiny-one-row");
    let (reference, _) = shift_fixture();
    let report = persist_drift_reference(&vault, cache_key(), "drift:reference", &reference, SEED)
        .expect("persist tiny reference");
    assert_eq!(report.chunks.len(), 1, "tiny corpus is a single chunk");

    let rows = persisted_reference_rows(&vault);
    assert_eq!(rows.len(), 1, "exactly one persisted reference row");
    let value = rows[0].1.clone();
    let row: Value = serde_json::from_slice(&value).expect("row json");
    assert!(
        row["payload"].get("chunk").is_none(),
        "single-chunk payload keeps the legacy shape (no chunk header)"
    );
    assert!(
        row["payload"]["sampling"]
            .get("chunk_budget_bytes")
            .is_none(),
        "single-chunk sampling block is byte-identical to the pre-chunking format"
    );
    let reloaded = load_drift_reference(&vault).expect("reload");
    assert_eq!(reloaded, reference, "single-chunk round-trips whole");

    // Byte-identical re-persist into a fresh vault (determinism).
    let (dir2, vault2) = durable_vault("tiny-one-row-2");
    persist_drift_reference(&vault2, cache_key(), "drift:reference", &reference, SEED)
        .expect("re-persist");
    assert_eq!(
        persisted_reference_rows(&vault2)[0].1,
        value,
        "same seed → byte-identical persisted reference row"
    );

    drop(vault);
    drop(vault2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn chunk_packer_respects_the_byte_budget_at_the_boundary() {
    // #371 edge: exactly-at-budget boundary. With a budget sized for exactly two
    // slots, two slots pack into one chunk and a third spills to a second — the
    // greedy packer never exceeds the budget.
    // Identical-size slots (same samples, same-length labels) so the budget can
    // be pinned to an exact two-slot boundary.
    let slots: Vec<DriftSlotSamples> = (0..3)
        .map(|i| DriftSlotSamples {
            slot: format!("S{i}"),
            samples: scalars(20, 0.0),
        })
        .collect();
    // No per-slot reduction: cap far above population, so provenance is whole.
    let (bounded, prov) = bound_reference_window(&slots, 10_000, SEED);
    let per_slot_cost = slot_json_cost(&bounded[0]).expect("slot cost");
    // A budget with exactly two slots' worth of slots-budget headroom.
    let budget =
        CHUNK_SCAFFOLD_RESERVE_BYTES + 2 * (per_slot_cost + CHUNK_PER_SLOT_PROVENANCE_BYTES);

    let two = plan_reference_chunks(&bounded[..2], &prov[..2], budget, SEED).expect("plan two");
    assert_eq!(two.len(), 1, "two slots fit exactly one chunk at budget");

    let three = plan_reference_chunks(&bounded, &prov, budget, SEED).expect("plan three");
    assert_eq!(three.len(), 2, "the third slot spills to a second chunk");
    assert_eq!(three[0].slots.len(), 2);
    assert_eq!(three[1].slots.len(), 1);
    for chunk in &three {
        assert!(
            chunk.per_slot.iter().all(|s| !s.budget_downsampled),
            "no slot exceeded the budget, so none was budget-down-sampled"
        );
    }
}

#[test]
fn m_representative_reference_splits_under_the_memtable_cap() {
    // #371 DoD box 1 (byte-budget layer): an M-representative fixture whose
    // UNBOUNDED single reference row exceeds the 8 MiB memtable cap (the wave-14
    // live falsification) persists as multiple chunk rows, EACH under the cap,
    // with byte readback of every row and a byte-identical same-seed re-persist.
    let cap = drift_reference_sample_cap().expect("cap");
    let budget = drift_reference_chunk_budget_bytes().expect("budget");

    // 20 dense slots × 400 samples × dim 256: bounded to the cap this sums to
    // more than 8 MiB in one JSON row.
    let fixture: Vec<DriftSlotSamples> = (0..20)
        .map(|i| DriftSlotSamples {
            slot: format!("S{i}"),
            samples: wide(400, 256, i as f64),
        })
        .collect();

    // Prove the falsification condition: the single bounded row exceeds the cap.
    let (bounded, bound_prov) = bound_reference_window(&fixture, cap, SEED);
    let single_payload = serde_json::json!({
        "schema": DRIFT_REFERENCE_PAYLOAD_SCHEMA,
        "sampling": { "reservoir": "vitter-algorithm-r", "sample_cap": cap, "seed": SEED, "per_slot": bound_prov },
        "slots": bounded,
    });
    let single_value = serde_json::to_vec(&single_payload).expect("single row bytes");
    assert!(
        single_value.len() > MEMTABLE_BYTE_CAP,
        "the unbounded single reference row must exceed the memtable cap ({} bytes)",
        single_value.len()
    );

    // Corroborate: a raw write of that single blob fails closed (backpressure).
    {
        let (probe_dir, probe_vault) = durable_vault("m-backpressure-probe");
        let err = probe_vault
            .write_cf(
                ColumnFamily::Assay,
                b"driftref-probe".to_vec(),
                single_value.clone(),
            )
            .expect_err("an over-cap single row must fail closed");
        assert_eq!(err.code, "CALYX_BACKPRESSURE", "{err:?}");
        drop(probe_vault);
        let _ = std::fs::remove_dir_all(&probe_dir);
    }

    // The chunked producer persists it under the cap.
    let (dir, vault) = durable_vault("m-chunked");
    let report = persist_drift_reference(&vault, cache_key(), "drift:reference", &fixture, SEED)
        .expect("persist chunked reference");
    assert!(
        report.chunks.len() > 1,
        "M reference must split: {report:?}"
    );
    assert_eq!(report.chunk_budget_bytes, budget);
    for info in &report.chunks {
        assert!(info.payload_bytes <= budget, "chunk over budget: {info:?}");
        assert!(
            info.budget_downsampled_slots.is_empty(),
            "no single slot exceeded the budget in this fixture: {info:?}"
        );
    }

    // Byte readback: EVERY persisted row is admissible under the memtable cap.
    let rows = persisted_reference_rows(&vault);
    assert_eq!(rows.len(), report.chunks.len(), "one row per chunk");
    for (key, value) in &rows {
        assert!(
            row_entry_size(key, value) <= MEMTABLE_BYTE_CAP,
            "persisted chunk row {} bytes exceeds the memtable cap",
            row_entry_size(key, value)
        );
    }

    // The merged reload reconstitutes all 20 slots, each bounded to the cap.
    let reloaded = load_drift_reference(&vault).expect("reload merged reference");
    assert_eq!(reloaded.len(), 20, "all slots reconstituted across chunks");
    for slot in &reloaded {
        assert_eq!(
            slot.samples.len(),
            cap,
            "each slot bounded to the cap: {}",
            slot.slot
        );
    }
    let mut labels: Vec<&str> = reloaded.iter().map(|s| s.slot.as_str()).collect();
    labels.sort();
    let mut expected: Vec<String> = (0..20).map(|i| format!("S{i}")).collect();
    expected.sort();
    assert_eq!(
        labels,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );

    // Determinism: a same-seed re-persist into a fresh vault yields a
    // byte-identical set of chunk row values.
    let (dir2, vault2) = durable_vault("m-chunked-2");
    persist_drift_reference(&vault2, cache_key(), "drift:reference", &fixture, SEED)
        .expect("re-persist chunked reference");
    let mut a: Vec<Vec<u8>> = rows.into_iter().map(|(_, v)| v).collect();
    let mut b: Vec<Vec<u8>> = persisted_reference_rows(&vault2)
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "same seed → byte-identical chunked reference");

    drop(vault);
    drop(vault2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn planted_shift_survives_a_multi_chunk_reference() {
    // #371 DoD box 2 (byte-budget layer): a reference large enough to split into
    // multiple chunk rows is reloaded from bytes and STILL surfaces a planted
    // shift — chunking splits storage, not the MMD sample sets, so sensitivity is
    // pinned.
    let (dir, vault) = durable_vault("multi-chunk-shift");
    let cfg = DiffConfig::from_defaults().expect("diff config");
    let budget = drift_reference_chunk_budget_bytes().expect("budget");

    // 27 stable + 1 planted-shift slot, wide enough (dim 512) that the reference
    // exceeds the 4 MiB chunk budget with few enough samples to keep MMD cheap.
    let mut reference = Vec::new();
    let mut current = Vec::new();
    for i in 0..27 {
        reference.push(DriftSlotSamples {
            slot: format!("S{i}"),
            samples: wide(60, 512, 0.0),
        });
        current.push(DriftSlotSamples {
            slot: format!("S{i}"),
            samples: wide(60, 512, 0.0),
        });
    }
    reference.push(DriftSlotSamples {
        slot: "S18".to_string(),
        samples: wide(60, 512, 0.0),
    });
    current.push(DriftSlotSamples {
        slot: "S18".to_string(),
        samples: wide(60, 512, 50.0),
    });

    let report = persist_drift_reference(&vault, cache_key(), "drift:reference", &reference, SEED)
        .expect("persist multi-chunk reference");
    assert!(
        report.chunks.len() > 1,
        "reference must span multiple chunks: {report:?}"
    );
    for info in &report.chunks {
        assert!(info.payload_bytes <= budget, "chunk over budget: {info:?}");
    }

    // Reload the reference from the persisted chunk bytes and produce cards.
    let bounded_reference = load_drift_reference(&vault).expect("reload multi-chunk reference");
    assert_eq!(bounded_reference.len(), 28, "all slots reconstituted");
    let card_report = produce_drift_cards(
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
    assert!(card_report.cards_payload_persisted, "{card_report:?}");

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
        "planted shift must survive a multi-chunk reference: {:?}",
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
