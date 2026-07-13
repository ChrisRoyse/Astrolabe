//! The background assay job scheduler: cooperative lane budgets, serving
//! isolation, and cache-keyed invalidation tie together here.
//!
//! A scheduled job does three things in order:
//!
//! 1. **Cache lookup by fingerprint.** If the exact inputs were sampled before,
//!    the persisted result is served without recomputing.
//! 2. **Serving-isolation check.** Before spending any background cycles the
//!    lane reads the recent serving-path p99. If it is above the registry
//!    tripwire the job is *deferred* — a labeled degradation, never a silent
//!    skip and never stolen serving latency.
//! 3. **Cooperative scoring + persist + invalidate.** Scoring runs in bounded
//!    cooperative ticks (the lane yields after each budgeted slice), the result
//!    is persisted with read-back verification, and stale cache entries under
//!    superseded fingerprints are swept.

use astrolabe_domain::knobs::U64KnobDeclaration;

use crate::error::{
    ASTRO_ASSAY_KNOB_OUT_OF_BOUNDS, ASTRO_ASSAY_SAMPLE_SIZE_ZERO, AssayError, Result,
};
use crate::fingerprint::InputFingerprint;
use crate::knobs::{
    ASSAY_DEFAULT_LANE_UNITS_PER_TICK, ASSAY_DEFAULT_SERVING_P99_TRIPWIRE_MICROS,
    ASSAY_LANE_UNITS_PER_TICK_KNOB, ASSAY_SAMPLE_SIZE_KNOB, ASSAY_SERVING_P99_TRIPWIRE_MICROS_KNOB,
    assay_knob,
};
use crate::population::{AssaySubject, Population};
use crate::store::AssayStore;
use crate::strata::{KeyedSubject, SampleResult, finalize_keyed, priority_key};

/// A fully specified sampling request.
#[derive(Debug, Clone)]
pub struct SampleRequest {
    /// Validated subject population.
    pub population: Population,
    /// Seed for the deterministic priority keys.
    pub seed: u64,
    /// Requested sample size (clamped to the population size at run time).
    pub sample_size: u64,
    /// Panel version scoping the sample; a bump invalidates prior entries.
    pub panel_version: u32,
    /// Shard set scoping the sample; a change invalidates prior entries.
    pub shards: Vec<String>,
}

impl SampleRequest {
    /// Computes the request fingerprint (the cache key).
    pub fn fingerprint(&self) -> InputFingerprint {
        InputFingerprint::compute(
            &self.population,
            self.seed,
            self.sample_size,
            self.panel_version,
            &self.shards,
        )
    }
}

/// Accounting for one cooperative scoring pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    /// Number of cooperative ticks the pass took.
    pub ticks: usize,
    /// Total subjects scored (equals the population size).
    pub scored: usize,
    /// The lane budget in force, in subjects per tick.
    pub units_per_tick: u64,
}

/// The disposition of a scheduled job.
#[derive(Debug, Clone)]
pub enum ScheduleOutcome {
    /// The fingerprint was already cached; the persisted result was served.
    CacheHit {
        /// The served result.
        result: SampleResult,
    },
    /// The sample was computed, persisted, and stale entries swept.
    Computed {
        /// The freshly computed result.
        result: SampleResult,
        /// Cooperative scoring accounting.
        tick_report: TickReport,
        /// Fingerprint hexes of stale entries removed by the invalidation scan.
        invalidated: Vec<String>,
    },
    /// The serving-isolation tripwire deferred the background work (labeled degradation).
    Deferred {
        /// Observed serving-path p99, in microseconds.
        serving_p99_micros: u64,
        /// The registry tripwire threshold, in microseconds.
        tripwire_micros: u64,
    },
}

/// A resumable cooperative scorer.
///
/// Each [`tick`](CooperativeScorer::tick) scores at most `units_per_tick`
/// subjects and then returns control to the caller — the cooperative
/// preemption point. Driving it to completion yields exactly the same scored
/// set as one unbounded pass, so the lane budget never changes the result, only
/// how the work is sliced.
pub struct CooperativeScorer<'a> {
    subjects: &'a [AssaySubject],
    seed: u64,
    units_per_tick: u64,
    cursor: usize,
    ticks: usize,
    keyed: Vec<KeyedSubject>,
}

/// The outcome of a single cooperative tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickStep {
    /// The tick scored subjects `[from, to)` and yielded the lane.
    Scored {
        /// First subject index scored this tick.
        from: usize,
        /// One past the last subject index scored this tick.
        to: usize,
    },
    /// No subjects remained; scoring is complete.
    Complete,
}

impl<'a> CooperativeScorer<'a> {
    /// Builds a scorer over `subjects` with a per-tick budget.
    pub fn new(subjects: &'a [AssaySubject], seed: u64, units_per_tick: u64) -> Self {
        Self {
            subjects,
            seed,
            units_per_tick,
            cursor: 0,
            ticks: 0,
            keyed: Vec::with_capacity(subjects.len()),
        }
    }

    /// Whether every subject has been scored.
    pub fn is_complete(&self) -> bool {
        self.cursor >= self.subjects.len()
    }

    /// The cursor position (subjects scored so far).
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Scores at most `units_per_tick` subjects, then yields.
    pub fn tick(&mut self) -> TickStep {
        if self.is_complete() {
            return TickStep::Complete;
        }
        let from = self.cursor;
        let to = (self.cursor + self.units_per_tick as usize).min(self.subjects.len());
        for subject in &self.subjects[from..to] {
            self.keyed.push(KeyedSubject {
                stratum: subject.stratum.clone(),
                series_id: subject.series_id,
                key: priority_key(self.seed, &subject.series_id),
            });
        }
        self.cursor = to;
        self.ticks += 1;
        TickStep::Scored { from, to }
    }

    /// Drives the scorer to completion, returning the scored subjects and the
    /// tick accounting.
    fn run_to_completion(mut self) -> (Vec<KeyedSubject>, usize) {
        while let TickStep::Scored { .. } = self.tick() {}
        (self.keyed, self.ticks)
    }
}

/// The nearest-rank p99 of a serving-latency sample set, in microseconds.
///
/// Uses the nearest-rank definition: with `n` sorted samples the p99 is the
/// value at 1-based rank `ceil(0.99 * n)`. Returns `None` for an empty set —
/// no samples means no measured latency, which the caller treats as "clear"
/// rather than fabricating a zero.
pub fn serving_p99_micros(samples: &[u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted: Vec<u64> = samples.to_vec();
    sorted.sort_unstable();
    // ceil(0.99 * n) with integer math, clamped to a valid 1-based rank.
    let n = sorted.len() as u128;
    let rank = ((99 * n) + 99) / 100; // ceil(99n/100)
    let index = (rank.max(1) as usize - 1).min(sorted.len() - 1);
    Some(sorted[index])
}

/// The serving-isolation decision for a candidate background tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationDecision {
    /// Serving latency is within budget; the background lane may run.
    Clear {
        /// Observed p99, or `None` when no serving samples exist.
        observed_p99_micros: Option<u64>,
    },
    /// Serving latency exceeds the tripwire; the background lane must defer.
    Trip {
        /// Observed p99 that tripped the wire.
        observed_p99_micros: u64,
        /// The tripwire threshold.
        tripwire_micros: u64,
    },
}

/// Decides whether the background lane may run given recent serving latencies.
pub fn check_serving_isolation(samples: &[u64], tripwire_micros: u64) -> IsolationDecision {
    match serving_p99_micros(samples) {
        Some(p99) if p99 > tripwire_micros => IsolationDecision::Trip {
            observed_p99_micros: p99,
            tripwire_micros,
        },
        observed => IsolationDecision::Clear {
            observed_p99_micros: observed,
        },
    }
}

/// The background assay job scheduler.
#[derive(Debug, Clone)]
pub struct AssayScheduler {
    store: AssayStore,
    lane_units_per_tick: u64,
    serving_p99_tripwire_micros: u64,
}

fn validate_knob(knob: &U64KnobDeclaration, value: u64) -> Result<u64> {
    if knob.accepts(value) {
        Ok(value)
    } else {
        Err(AssayError::new(
            ASTRO_ASSAY_KNOB_OUT_OF_BOUNDS,
            format!(
                "knob {} value {value} is outside [{}, {}]",
                knob.name, knob.min, knob.max
            ),
            "set the knob to a value inside its registry-declared closed interval",
        ))
    }
}

impl AssayScheduler {
    /// Builds a scheduler with the registry-default lane budget and tripwire.
    pub fn new(store: AssayStore) -> Self {
        Self {
            store,
            lane_units_per_tick: ASSAY_DEFAULT_LANE_UNITS_PER_TICK,
            serving_p99_tripwire_micros: ASSAY_DEFAULT_SERVING_P99_TRIPWIRE_MICROS,
        }
    }

    /// Overrides the lane budget, validating it against its knob bounds.
    pub fn with_lane_units_per_tick(mut self, units: u64) -> Result<Self> {
        let knob = assay_knob(ASSAY_LANE_UNITS_PER_TICK_KNOB).expect("declared");
        self.lane_units_per_tick = validate_knob(knob, units)?;
        Ok(self)
    }

    /// Overrides the serving-isolation tripwire, validating it against its knob bounds.
    pub fn with_serving_p99_tripwire_micros(mut self, micros: u64) -> Result<Self> {
        let knob = assay_knob(ASSAY_SERVING_P99_TRIPWIRE_MICROS_KNOB).expect("declared");
        self.serving_p99_tripwire_micros = validate_knob(knob, micros)?;
        Ok(self)
    }

    /// The store this scheduler persists to.
    pub fn store(&self) -> &AssayStore {
        &self.store
    }

    /// Schedules one job, given the recent serving-path latency samples in
    /// microseconds that gate the background lane.
    pub fn schedule(
        &self,
        request: &SampleRequest,
        serving_latency_micros: &[u64],
    ) -> Result<ScheduleOutcome> {
        let sample_knob = assay_knob(ASSAY_SAMPLE_SIZE_KNOB).expect("declared");
        if request.sample_size == 0 {
            return Err(AssayError::new(
                ASTRO_ASSAY_SAMPLE_SIZE_ZERO,
                "requested sample size is zero",
                "request at least one sampled subject so the result measures a real proportion",
            ));
        }
        validate_knob(sample_knob, request.sample_size)?;

        let fingerprint = request.fingerprint();

        // 1. Cache lookup by fingerprint.
        if let Some(result) = self.store.get(&fingerprint)? {
            return Ok(ScheduleOutcome::CacheHit { result });
        }

        // 2. Serving-isolation check before spending background cycles.
        if let IsolationDecision::Trip {
            observed_p99_micros,
            tripwire_micros,
        } = check_serving_isolation(serving_latency_micros, self.serving_p99_tripwire_micros)
        {
            return Ok(ScheduleOutcome::Deferred {
                serving_p99_micros: observed_p99_micros,
                tripwire_micros,
            });
        }

        // 3. Cooperative scoring, persist with read-back, invalidate stale entries.
        let scorer = CooperativeScorer::new(
            request.population.subjects(),
            request.seed,
            self.lane_units_per_tick,
        );
        let (keyed, ticks) = scorer.run_to_completion();
        let scored = keyed.len();
        let result = finalize_keyed(
            keyed,
            fingerprint,
            request.seed,
            request.sample_size,
            request.panel_version,
            &request.shards,
        );
        self.store.put(&result)?;
        let invalidated = self.store.invalidate_except(&fingerprint)?;

        Ok(ScheduleOutcome::Computed {
            result,
            tick_report: TickReport {
                ticks,
                scored,
                units_per_tick: self.lane_units_per_tick,
            },
            invalidated,
        })
    }
}
