//! Full State Verification for the assay scheduler against a real on-disk store.
//!
//! These tests exercise the real scheduler over a real filesystem store with
//! synthetic-but-real subject populations whose sampled output is hand-computed,
//! then independently read the persisted bytes back and compare them to the
//! claim. No mocks, no fake fixtures.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_assay::scheduler::{IsolationDecision, TickStep, check_serving_isolation};
use astrolabe_assay::strata::stratified_sample;
use astrolabe_assay::{
    AssayScheduler, AssayStore, AssaySubject, CooperativeScorer, Population, SampleRequest,
    ScheduleOutcome,
};
use astrolabe_domain::SeriesId;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique, self-cleaning store root under the system temp dir.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-assay-fsv-{}-{nanos}-{n}",
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

fn subject(byte: u8, stratum: &str, content: u8) -> AssaySubject {
    AssaySubject::new(SeriesId::from_bytes([byte; 16]), stratum, [content; 32]).unwrap()
}

/// Population of 60 functions + 30 classes + 10 traits (N = 100).
fn population_100() -> Population {
    let mut subjects = Vec::new();
    for i in 0..60u8 {
        subjects.push(subject(i, "function", i));
    }
    for i in 60..90u8 {
        subjects.push(subject(i, "class", i));
    }
    for i in 90..100u8 {
        subjects.push(subject(i, "trait", i));
    }
    Population::new(subjects).unwrap()
}

fn request(
    population: Population,
    seed: u64,
    sample_size: u64,
    panel: u32,
    shards: &[&str],
) -> SampleRequest {
    SampleRequest {
        population,
        seed,
        sample_size,
        panel_version: panel,
        shards: shards.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn stratification_proportions_match_hand_computed_allocation() {
    // N = 100 (60/30/10), sample 20 -> exact 12/6/2 by proportion.
    let root = TempRoot::new();
    let store = AssayStore::open(root.path()).unwrap();
    let scheduler = AssayScheduler::new(store);
    let req = request(population_100(), 1234, 20, 1, &["shard-0"]);

    let ScheduleOutcome::Computed { result, .. } = scheduler.schedule(&req, &[]).unwrap() else {
        panic!("expected a computed sample on a cold store");
    };

    let alloc: Vec<(String, usize, usize)> = result
        .allocations
        .iter()
        .map(|a| (a.stratum.clone(), a.population, a.allocated))
        .collect();
    assert_eq!(
        alloc,
        vec![
            ("class".to_string(), 30, 6),
            ("function".to_string(), 60, 12),
            ("trait".to_string(), 10, 2),
        ]
    );
    assert_eq!(result.effective_sample_size, 20);
    // Independent readback: rows on disk carry exactly the apportioned counts.
    let fp = req.fingerprint();
    let rows = scheduler.store().read_rows(&fp).unwrap();
    let class = rows.iter().filter(|r| r.stratum == "class").count();
    let function = rows.iter().filter(|r| r.stratum == "function").count();
    let traits = rows.iter().filter(|r| r.stratum == "trait").count();
    assert_eq!((class, function, traits), (6, 12, 2));
}

#[test]
fn determinism_byte_identical_rows_across_runs_and_worker_orders() {
    // Two independent stores, one built from a forward population and one from a
    // reversed (worker-shuffled) population, must persist byte-identical rows.
    let forward = population_100();
    let reversed = {
        let mut subjects: Vec<AssaySubject> = forward.subjects().to_vec();
        subjects.reverse();
        Population::new(subjects).unwrap()
    };

    let root_a = TempRoot::new();
    let root_b = TempRoot::new();
    let sched_a = AssayScheduler::new(AssayStore::open(root_a.path()).unwrap());
    let sched_b = AssayScheduler::new(AssayStore::open(root_b.path()).unwrap());

    let req_a = request(forward, 777, 25, 3, &["s1", "s2"]);
    let req_b = request(reversed, 777, 25, 3, &["s2", "s1"]);
    assert_eq!(
        req_a.fingerprint(),
        req_b.fingerprint(),
        "same set -> same key"
    );

    sched_a.schedule(&req_a, &[]).unwrap();
    sched_b.schedule(&req_b, &[]).unwrap();

    let fp = req_a.fingerprint();
    let bytes_a = std::fs::read(
        root_a
            .path()
            .join("cache")
            .join(format!("{}.rows.ndjson", fp.to_hex())),
    )
    .unwrap();
    let bytes_b = std::fs::read(
        root_b
            .path()
            .join("cache")
            .join(format!("{}.rows.ndjson", fp.to_hex())),
    )
    .unwrap();
    assert_eq!(
        bytes_a, bytes_b,
        "row bytes must be identical across worker orders"
    );
    assert!(!bytes_a.is_empty());
}

#[test]
fn fsv_readback_matches_seeded_recompute() {
    let root = TempRoot::new();
    let store = AssayStore::open(root.path()).unwrap();
    let scheduler = AssayScheduler::new(store);
    let req = request(population_100(), 42, 20, 1, &["shard-x"]);
    scheduler.schedule(&req, &[]).unwrap();

    let fp = req.fingerprint();
    let persisted_rows = scheduler.store().read_rows(&fp).unwrap();
    // Recompute independently from the seed and compare to the persisted rows.
    let recomputed = stratified_sample(&population_100(), 42, 20, 1, &["shard-x".to_string()]);
    assert_eq!(persisted_rows, recomputed.rows);

    // And the full cached blob round-trips to the same result.
    let cached = scheduler.store().get(&fp).unwrap().unwrap();
    assert_eq!(cached, recomputed);
}

#[test]
fn cache_hit_serves_persisted_result_without_recompute() {
    let root = TempRoot::new();
    let scheduler = AssayScheduler::new(AssayStore::open(root.path()).unwrap());
    let req = request(population_100(), 42, 20, 1, &["shard-x"]);

    assert!(matches!(
        scheduler.schedule(&req, &[]).unwrap(),
        ScheduleOutcome::Computed { .. }
    ));
    assert!(matches!(
        scheduler.schedule(&req, &[]).unwrap(),
        ScheduleOutcome::CacheHit { .. }
    ));
}

#[test]
fn panel_bump_and_shard_change_invalidate_the_stale_entry() {
    let root = TempRoot::new();
    let scheduler = AssayScheduler::new(AssayStore::open(root.path()).unwrap());

    let v1 = request(population_100(), 42, 20, 1, &["shard-x"]);
    let ScheduleOutcome::Computed { .. } = scheduler.schedule(&v1, &[]).unwrap() else {
        panic!("cold compute");
    };
    let fp1 = v1.fingerprint();
    assert_eq!(
        scheduler.store().list_fingerprints().unwrap(),
        vec![fp1.to_hex()]
    );

    // Panel bump moves the key; scheduling sweeps the superseded entry.
    let v2 = request(population_100(), 42, 20, 2, &["shard-x"]);
    let ScheduleOutcome::Computed { invalidated, .. } = scheduler.schedule(&v2, &[]).unwrap()
    else {
        panic!("panel bump recompute");
    };
    assert_eq!(invalidated, vec![fp1.to_hex()], "old fingerprint swept");
    let fp2 = v2.fingerprint();
    // Independent directory readback: only the current fingerprint survives.
    assert_eq!(
        scheduler.store().list_fingerprints().unwrap(),
        vec![fp2.to_hex()]
    );
    assert!(scheduler.store().get(&fp1).unwrap().is_none());

    // Shard change moves the key again and sweeps the panel-v2 entry.
    let v3 = request(population_100(), 42, 20, 2, &["shard-x", "shard-y"]);
    let ScheduleOutcome::Computed { invalidated, .. } = scheduler.schedule(&v3, &[]).unwrap()
    else {
        panic!("shard change recompute");
    };
    assert_eq!(invalidated, vec![fp2.to_hex()]);
    assert_eq!(
        scheduler.store().list_fingerprints().unwrap(),
        vec![v3.fingerprint().to_hex()]
    );
}

#[test]
fn serving_p99_tripwire_defers_background_work_under_saturation() {
    let root = TempRoot::new();
    let scheduler = AssayScheduler::new(AssayStore::open(root.path()).unwrap())
        .with_serving_p99_tripwire_micros(10_000)
        .unwrap();
    let req = request(population_100(), 42, 20, 1, &["shard-x"]);

    // 100 samples mostly fast, but the top ~1% exceed 10ms: p99 trips the wire.
    let mut latencies: Vec<u64> = vec![500; 98];
    latencies.push(12_000);
    latencies.push(15_000);
    match scheduler.schedule(&req, &latencies).unwrap() {
        ScheduleOutcome::Deferred {
            serving_p99_micros,
            tripwire_micros,
        } => {
            assert!(serving_p99_micros > tripwire_micros);
            assert_eq!(tripwire_micros, 10_000);
        }
        other => panic!("expected Deferred under saturation, got {other:?}"),
    }
    // Deferred means nothing was persisted — the background lane stole no cycles.
    assert!(scheduler.store().list_fingerprints().unwrap().is_empty());

    // With serving latency back under budget the same job now computes.
    let calm: Vec<u64> = vec![500; 100];
    assert!(matches!(
        scheduler.schedule(&req, &calm).unwrap(),
        ScheduleOutcome::Computed { .. }
    ));
}

#[test]
fn p99_nearest_rank_and_isolation_decision_are_exact() {
    // 100 samples: ninety-nine 1000s and one 9000. Nearest-rank p99 = rank 99 = 1000.
    let mut samples = vec![1000u64; 99];
    samples.push(9000);
    assert!(matches!(
        check_serving_isolation(&samples, 5000),
        IsolationDecision::Clear {
            observed_p99_micros: Some(1000)
        }
    ));
    // Push the tail so the p99 sample itself exceeds the wire.
    let mut hot = vec![9000u64; 2];
    hot.extend(vec![1000u64; 98]);
    assert!(matches!(
        check_serving_isolation(&hot, 5000),
        IsolationDecision::Trip {
            observed_p99_micros: 9000,
            tripwire_micros: 5000
        }
    ));
    // Empty samples are "clear with no observation", never a fabricated zero.
    assert!(matches!(
        check_serving_isolation(&[], 5000),
        IsolationDecision::Clear {
            observed_p99_micros: None
        }
    ));
}

#[test]
fn cooperative_tick_preemption_yields_in_bounded_slices_with_identical_result() {
    // Drive the scorer tick-by-tick over a small population and observe the
    // cursor advancing in bounded slices and yielding after each.
    let pop = population_100();
    let mut scorer = CooperativeScorer::new(pop.subjects(), 42, 30);
    let mut slices = Vec::new();
    loop {
        match scorer.tick() {
            TickStep::Scored { from, to } => {
                assert!(to - from <= 30, "tick honored the 30-subject budget");
                slices.push((from, to));
            }
            TickStep::Complete => break,
        }
    }
    // 100 subjects / 30 per tick -> slices [0,30) [30,60) [60,90) [90,100).
    assert_eq!(slices, vec![(0, 30), (30, 60), (60, 90), (90, 100)]);
    assert!(scorer.is_complete());
    assert_eq!(scorer.cursor(), 100);

    // The budgeted schedule and an unbudgeted (single-tick) schedule agree byte
    // for byte on the persisted rows.
    let root_small = TempRoot::new();
    let root_big = TempRoot::new();
    let small = AssayScheduler::new(AssayStore::open(root_small.path()).unwrap())
        .with_lane_units_per_tick(7)
        .unwrap();
    let big = AssayScheduler::new(AssayStore::open(root_big.path()).unwrap())
        .with_lane_units_per_tick(1_000_000)
        .unwrap();
    let req = request(population_100(), 42, 20, 1, &["s"]);

    let ScheduleOutcome::Computed {
        tick_report: small_ticks,
        ..
    } = small.schedule(&req, &[]).unwrap()
    else {
        panic!("compute");
    };
    let ScheduleOutcome::Computed {
        tick_report: big_ticks,
        ..
    } = big.schedule(&req, &[]).unwrap()
    else {
        panic!("compute");
    };
    assert_eq!(
        small_ticks.ticks,
        (100 + 6) / 7,
        "ceil(100/7) cooperative ticks"
    );
    assert_eq!(big_ticks.ticks, 1, "unbudgeted pass takes a single tick");

    let fp = req.fingerprint();
    let small_rows = std::fs::read(
        root_small
            .path()
            .join("cache")
            .join(format!("{}.rows.ndjson", fp.to_hex())),
    )
    .unwrap();
    let big_rows = std::fs::read(
        root_big
            .path()
            .join("cache")
            .join(format!("{}.rows.ndjson", fp.to_hex())),
    )
    .unwrap();
    assert_eq!(
        small_rows, big_rows,
        "lane budget must not change the result"
    );
}

#[test]
fn edge_empty_population_samples_to_zero_rows() {
    let root = TempRoot::new();
    let scheduler = AssayScheduler::new(AssayStore::open(root.path()).unwrap());
    let req = request(Population::new([]).unwrap(), 42, 20, 1, &[]);
    let ScheduleOutcome::Computed {
        result,
        tick_report,
        ..
    } = scheduler.schedule(&req, &[]).unwrap()
    else {
        panic!("empty compute");
    };
    assert_eq!(result.rows.len(), 0);
    assert_eq!(result.effective_sample_size, 0);
    assert_eq!(
        tick_report.ticks, 0,
        "no subjects means no cooperative ticks"
    );
    // The empty result is still persisted and reads back as zero rows.
    assert_eq!(
        scheduler
            .store()
            .read_rows(&req.fingerprint())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn edge_population_smaller_than_sample_size_clamps_to_population() {
    let root = TempRoot::new();
    let scheduler = AssayScheduler::new(AssayStore::open(root.path()).unwrap());
    // 3 subjects, ask for 50: every subject is selected, proportions preserved.
    let pop = Population::new([
        subject(1, "function", 1),
        subject(2, "function", 2),
        subject(3, "class", 3),
    ])
    .unwrap();
    let req = request(pop, 42, 50, 1, &[]);
    let ScheduleOutcome::Computed { result, .. } = scheduler.schedule(&req, &[]).unwrap() else {
        panic!("compute");
    };
    assert_eq!(result.effective_sample_size, 3);
    assert_eq!(result.rows.len(), 3);
    let persisted = scheduler.store().read_rows(&req.fingerprint()).unwrap();
    assert_eq!(persisted.len(), 3);
}

#[test]
fn edge_zero_sample_size_is_rejected_fail_closed() {
    let root = TempRoot::new();
    let scheduler = AssayScheduler::new(AssayStore::open(root.path()).unwrap());
    let req = request(population_100(), 42, 0, 1, &[]);
    let err = scheduler.schedule(&req, &[]).unwrap_err();
    assert_eq!(err.code(), "ASTRO_ASSAY_SAMPLE_SIZE_ZERO");
    // Nothing was persisted for an invalid request.
    assert!(scheduler.store().list_fingerprints().unwrap().is_empty());
}
