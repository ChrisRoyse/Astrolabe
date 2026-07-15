//! Recurrence forecasting (`forecast`, blueprint 11_ORACLE §5, capability 7.6).
//!
//! "When will this recur, and how sure are we?" answered per *series* — a sorted
//! sequence of recurrence events on one subject (failing occurrences, churn
//! events, ...) drawn from the grounded corpus mined in [`crate::corpus`]. From
//! the series' inter-arrival intervals the forecaster derives a robust cadence
//! (median), a robust dispersion (median absolute deviation, MAD), the
//! next-occurrence estimate with a credible interval, a renewal overdue hazard, a
//! periodicity fit, and CUSUM regime changes. Its products are flaky-test
//! windows, hotspot re-churn horizons, and stale-area detection.
//!
//! ## Honesty
//!
//! * A regular series (near-constant intervals) yields a tight interval and high
//!   confidence; an irregular one yields a wide interval and low confidence —
//!   confidence is `regularity · support`, always strictly `< 1.0`.
//! * Below [`ForecastConfig::small_sample_threshold`] intervals the credible
//!   interval is widened by the posterior-predictive small-sample factor and the
//!   forecast is labeled provisional (HONEST invariant 1).
//! * A series too short to form a cadence refuses with [`ASTRO_NO_RECURRENCE`]
//!   and bootstrap instructions, never a fabricated point estimate.
//! * A flaky pass/fail series (pairwise self-consistency below the floor) refuses
//!   a clean flaky-test window with [`ASTRO_FLAKY_EVIDENCE`], naming the flaky
//!   test rather than forecasting a cadence from noise (HONEST invariant 2).
//!
//! The overdue hazard is the empirical CDF of the intervals evaluated at the
//! elapsed time since the last event: it is monotone non-decreasing in elapsed
//! time and passes 0.5 once the elapsed time reaches the median cadence.

use astrolabe_domain::TrustTag;
use astrolabe_domain::knobs::U64KnobDeclaration;
use calyx_core::{CxId, Ts};

use crate::corpus::{OccurrenceRecord, OracleError};

// ---------------------------------------------------------------------------
// Stable failure codes
// ---------------------------------------------------------------------------

/// Stable failure code for an out-of-bounds forecast configuration.
pub const ASTRO_ORACLE_FORECAST_CONFIG_INVALID: &str = "ASTRO_ORACLE_FORECAST_CONFIG_INVALID";
/// Stable refusal code: too few events to establish a recurrence cadence.
pub const ASTRO_NO_RECURRENCE: &str = "ASTRO_NO_RECURRENCE";
/// Stable refusal code: the pass/fail series is flaky, so no clean window exists.
pub const ASTRO_FLAKY_EVIDENCE: &str = "ASTRO_FLAKY_EVIDENCE";

const FORECAST_REMEDIATION: &str = "supply a validated ForecastConfig and a per-subject event series with at least \
     min_events observations; bootstrap history with ingest_outcome_anchors + mine_corpus";

/// Operator-facing bootstrap text emitted with an [`ASTRO_NO_RECURRENCE`] refusal.
pub const ORACLE_NO_RECURRENCE_REMEDIATION: &str = "Not enough recurrence events to forecast a cadence. Record more outcomes for this subject \
     via anchor_outcome (ingest_outcome_anchors) and re-mine the corpus with mine_corpus; a \
     cadence needs at least min_events observations.";

/// Operator-facing text emitted with an [`ASTRO_FLAKY_EVIDENCE`] refusal.
pub const ORACLE_FLAKY_EVIDENCE_REMEDIATION: &str = "This test's outcome series is flaky (its passes and failures do not agree), so no clean \
     recurrence window can be forecast. Stabilize or quarantine the named flaky test before \
     forecasting its failure window.";

// ---------------------------------------------------------------------------
// Registry-declared forecast knobs (standing invariant 4)
// ---------------------------------------------------------------------------

/// Registry version tag for the recurrence-forecast knobs (#51).
pub const ORACLE_FORECAST_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-forecast-knobs-v1";

/// Name of the minimum-events knob (events).
pub const ORACLE_FORECAST_MIN_EVENTS_KNOB: &str = "oracle_forecast_min_events";
/// Name of the interval half-width knob (permille of MAD).
pub const ORACLE_FORECAST_INTERVAL_MAD_PERMILLE_KNOB: &str =
    "oracle_forecast_interval_mad_permille";
/// Name of the small-sample threshold knob (intervals).
pub const ORACLE_FORECAST_SMALL_SAMPLE_THRESHOLD_KNOB: &str =
    "oracle_forecast_small_sample_threshold";
/// Name of the small-sample widening knob (permille).
pub const ORACLE_FORECAST_SMALL_SAMPLE_WIDEN_PERMILLE_KNOB: &str =
    "oracle_forecast_small_sample_widen_permille";
/// Name of the CUSUM regime-change threshold knob (permille of MAD).
pub const ORACLE_FORECAST_CUSUM_THRESHOLD_PERMILLE_KNOB: &str =
    "oracle_forecast_cusum_threshold_permille";
/// Name of the hard max-confidence cap knob (permille).
pub const ORACLE_FORECAST_MAX_CONFIDENCE_PERMILLE_KNOB: &str =
    "oracle_forecast_max_confidence_permille";
/// Name of the flaky-series self-consistency floor knob (permille).
pub const ORACLE_FORECAST_FLAKY_AGREEMENT_FLOOR_PERMILLE_KNOB: &str =
    "oracle_forecast_flaky_agreement_floor_permille";
/// Name of the support Laplace-smoothing knob (intervals).
pub const ORACLE_FORECAST_SUPPORT_SMOOTHING_KNOB: &str = "oracle_forecast_support_smoothing";

/// The recurrence-forecast knob registry (#51).
///
/// Every default is a seed to be replaced by a measured value once forecast
/// calibration (interval coverage, hazard reliability) is benchmarked per repo.
pub const ORACLE_FORECAST_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_MIN_EVENTS_KNOB,
        default: 3,
        min: 2,
        max: 1_000_000,
        unit: "events",
        source: "ASTROLABE blueprint 11_ORACLE §5: a cadence needs at least two intervals to have a dispersion",
        rationale: "at least 3 events (2 intervals) are required before a median cadence and a MAD dispersion are defined; below this the tool refuses with ASTRO_NO_RECURRENCE rather than inventing a cadence from a single interval; replace with a measured minimum once cadence stability is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_INTERVAL_MAD_PERMILLE_KNOB,
        default: 1000,
        min: 1,
        max: 100_000,
        unit: "permille",
        source: "robust prediction-interval half-width expressed as a multiple of the interval MAD",
        rationale: "the next-occurrence credible interval is next ± (mad_permille/1000)·MAD: a perfectly regular series (MAD 0) yields a point interval, a dispersed one a wide band; 1000 permille = ±1 MAD is the seed half-width; replace with a measured coverage-calibrated multiple once benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_SMALL_SAMPLE_THRESHOLD_KNOB,
        default: 5,
        min: 2,
        max: 1_000_000,
        unit: "intervals",
        source: "ASTROLABE blueprint 11_ORACLE §5 small-sample honesty",
        rationale: "with fewer than this many intervals the point cadence is uncertain, so the credible interval is widened by the posterior-predictive small-sample factor and the forecast is labeled provisional; 5 is the seed threshold; replace with a measured value once the count-to-reliability curve is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_SMALL_SAMPLE_WIDEN_PERMILLE_KNOB,
        default: 2000,
        min: 1000,
        max: 100_000,
        unit: "permille",
        source: "posterior-predictive variance inflation for a small-sample credible interval",
        rationale: "below the small-sample threshold the interval half-width is multiplied by up to this factor (2000 permille = ×2.0), reflecting the wider Bayesian credible interval of a thin sample; the floor of 1000 (×1.0) guarantees small-sample widening never narrows an interval; replace with a measured inflation once benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_CUSUM_THRESHOLD_PERMILLE_KNOB,
        default: 4000,
        min: 1,
        max: 1_000_000,
        unit: "permille",
        source: "tabular CUSUM decision interval expressed as a multiple of the interval MAD",
        rationale: "a cadence regime change is flagged when the cumulative sum of interval deviations from the median crosses (cusum_permille/1000)·MAD; 4000 permille = 4 MAD is the seed decision interval, a common CUSUM sensitivity; replace with a measured value once regime-change precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_MAX_CONFIDENCE_PERMILLE_KNOB,
        default: 990,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE ceilings: confidence never reaches 1.0",
        rationale: "hard upper bound on forecast confidence so that even a long, perfectly-regular series is never certified at 1.0; combined with the regularity·support product this keeps every forecast strictly below certainty; capped below 1000 by construction; replace with a measured ceiling once available",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_FLAKY_AGREEMENT_FLOOR_PERMILLE_KNOB,
        default: 700,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §5 oracle self-consistency (flakiness floor)",
        rationale: "a pass/fail series whose pairwise outcome agreement falls below 0.70 (700 permille) is judged flaky, so forecast_flaky_window refuses with ASTRO_FLAKY_EVIDENCE naming the test rather than forecasting a cadence from self-inconsistent noise; replace with a measured flakiness floor once benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
        name: ORACLE_FORECAST_SUPPORT_SMOOTHING_KNOB,
        default: 1,
        min: 1,
        max: 1_000,
        unit: "intervals",
        source: "Laplace/additive smoothing (add-k) applied to the support factor n/(n+k)",
        rationale: "discounts thin evidence in the confidence: with k=1 a two-interval series yields support 2/3 and the factor saturates toward 1 as intervals accumulate, so a short series cannot mint a confident forecast; replace with a measured value once benchmarked",
    },
];

/// Returns the forecast knob declaration for `name`, or `None`.
pub fn oracle_forecast_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ORACLE_FORECAST_KNOBS.iter().find(|knob| knob.name == name)
}

fn forecast_knob(name: &str) -> &'static U64KnobDeclaration {
    oracle_forecast_knob(name).expect("oracle forecast knob is declared")
}

// ---------------------------------------------------------------------------
// Forecast configuration
// ---------------------------------------------------------------------------

/// Validated recurrence-forecast policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForecastConfig {
    pub min_events: u64,
    pub interval_mad_permille: u64,
    pub small_sample_threshold: u64,
    pub small_sample_widen_permille: u64,
    pub cusum_threshold_permille: u64,
    pub max_confidence_permille: u64,
    pub flaky_agreement_floor_permille: u64,
    pub support_smoothing: u64,
}

impl Default for ForecastConfig {
    fn default() -> Self {
        Self {
            min_events: forecast_knob(ORACLE_FORECAST_MIN_EVENTS_KNOB).default,
            interval_mad_permille: forecast_knob(ORACLE_FORECAST_INTERVAL_MAD_PERMILLE_KNOB)
                .default,
            small_sample_threshold: forecast_knob(ORACLE_FORECAST_SMALL_SAMPLE_THRESHOLD_KNOB)
                .default,
            small_sample_widen_permille: forecast_knob(
                ORACLE_FORECAST_SMALL_SAMPLE_WIDEN_PERMILLE_KNOB,
            )
            .default,
            cusum_threshold_permille: forecast_knob(ORACLE_FORECAST_CUSUM_THRESHOLD_PERMILLE_KNOB)
                .default,
            max_confidence_permille: forecast_knob(ORACLE_FORECAST_MAX_CONFIDENCE_PERMILLE_KNOB)
                .default,
            flaky_agreement_floor_permille: forecast_knob(
                ORACLE_FORECAST_FLAKY_AGREEMENT_FLOOR_PERMILLE_KNOB,
            )
            .default,
            support_smoothing: forecast_knob(ORACLE_FORECAST_SUPPORT_SMOOTHING_KNOB).default,
        }
    }
}

impl ForecastConfig {
    /// Fails closed when any field is outside its declared knob bounds.
    pub fn validate(&self) -> Result<(), OracleError> {
        check(ORACLE_FORECAST_MIN_EVENTS_KNOB, self.min_events)?;
        check(
            ORACLE_FORECAST_INTERVAL_MAD_PERMILLE_KNOB,
            self.interval_mad_permille,
        )?;
        check(
            ORACLE_FORECAST_SMALL_SAMPLE_THRESHOLD_KNOB,
            self.small_sample_threshold,
        )?;
        check(
            ORACLE_FORECAST_SMALL_SAMPLE_WIDEN_PERMILLE_KNOB,
            self.small_sample_widen_permille,
        )?;
        check(
            ORACLE_FORECAST_CUSUM_THRESHOLD_PERMILLE_KNOB,
            self.cusum_threshold_permille,
        )?;
        check(
            ORACLE_FORECAST_MAX_CONFIDENCE_PERMILLE_KNOB,
            self.max_confidence_permille,
        )?;
        check(
            ORACLE_FORECAST_FLAKY_AGREEMENT_FLOOR_PERMILLE_KNOB,
            self.flaky_agreement_floor_permille,
        )?;
        check(
            ORACLE_FORECAST_SUPPORT_SMOOTHING_KNOB,
            self.support_smoothing,
        )?;
        Ok(())
    }

    fn max_confidence(&self) -> f64 {
        self.max_confidence_permille as f64 / 1000.0
    }
    fn flaky_agreement_floor(&self) -> f64 {
        self.flaky_agreement_floor_permille as f64 / 1000.0
    }
}

fn check(name: &str, value: u64) -> Result<(), OracleError> {
    let declared = forecast_knob(name);
    if declared.accepts(value) {
        Ok(())
    } else {
        Err(OracleError {
            code: ASTRO_ORACLE_FORECAST_CONFIG_INVALID,
            message: format!(
                "forecast knob {name} value {value} is outside declared bounds [{}, {}]",
                declared.min, declared.max
            ),
            remediation: FORECAST_REMEDIATION,
        })
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// A dominant-periodicity fit for a series.
#[derive(Debug, Clone, PartialEq)]
pub struct PeriodicityFit {
    /// The dominant period (the robust median cadence), in seconds.
    pub period_secs: u64,
    /// Fit strength `[0, 1]` — the regularity of the intervals about the period.
    pub strength: f64,
}

/// The direction of a detected cadence regime change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegimeDirection {
    /// Intervals shortened — the series sped up (more frequent recurrence).
    Speedup,
    /// Intervals lengthened — the series slowed down (less frequent recurrence).
    Slowdown,
}

/// One CUSUM-detected cadence regime change.
#[derive(Debug, Clone, PartialEq)]
pub struct RegimeChange {
    /// Index into the event series where the change was detected (the event
    /// closing the interval that crossed the decision interval).
    pub at_event_index: usize,
    /// Timestamp of that event.
    pub at_ts: Ts,
    pub direction: RegimeDirection,
}

/// A recurrence forecast for one series.
#[derive(Debug, Clone, PartialEq)]
pub struct ForecastReport {
    /// The subject the series belongs to, when the call carried one.
    pub subject: Option<CxId>,
    pub event_count: usize,
    pub interval_count: usize,
    /// Robust median inter-arrival cadence, in seconds.
    pub median_cadence_secs: u64,
    /// Robust dispersion (median absolute deviation of the intervals), seconds.
    pub mad_secs: u64,
    /// Next-occurrence estimate: last event + median cadence.
    pub next_occurrence_ts: Ts,
    /// Credible-interval lower bound on the next occurrence.
    pub interval_low_ts: Ts,
    /// Credible-interval upper bound on the next occurrence.
    pub interval_high_ts: Ts,
    /// Interval regularity `[0, 1]` (1 = perfectly regular).
    pub regularity: f64,
    /// Forecast confidence `regularity · support`, strictly `< 1.0`.
    pub confidence: f64,
    /// Renewal overdue hazard at `now`: the empirical fraction of intervals no
    /// longer than the elapsed time since the last event, in `[0, 1]`.
    pub overdue_hazard: f64,
    /// Whether the series is below the small-sample threshold (interval widened,
    /// trust provisional).
    pub small_sample: bool,
    pub trust: TrustTag,
    pub periodicity: PeriodicityFit,
    /// CUSUM-detected cadence regime changes, in event order.
    pub regime_changes: Vec<RegimeChange>,
}

/// An [`ASTRO_NO_RECURRENCE`] refusal: too few events to forecast a cadence.
#[derive(Debug, Clone, PartialEq)]
pub struct RecurrenceRefusal {
    pub subject: Option<CxId>,
    pub have_events: usize,
    pub need_events: usize,
    pub code: &'static str,
    pub remediation: &'static str,
}

/// An [`ASTRO_FLAKY_EVIDENCE`] refusal: the pass/fail series is flaky.
#[derive(Debug, Clone, PartialEq)]
pub struct FlakyRefusal {
    /// The flaky test named in the refusal.
    pub test: CxId,
    /// Measured pairwise self-consistency of the outcome series.
    pub self_consistency: f64,
    /// The floor it fell below.
    pub floor: f64,
    pub code: &'static str,
    pub remediation: &'static str,
}

/// The outcome of a raw-series [`forecast_recurrence`] call.
#[derive(Debug, Clone, PartialEq)]
pub enum ForecastOutcome {
    Forecast(ForecastReport),
    NoRecurrence(RecurrenceRefusal),
}

/// The outcome of a [`forecast_flaky_window`] call.
#[derive(Debug, Clone, PartialEq)]
pub enum FlakyOutcome {
    /// A clean failure-recurrence window for the (non-flaky) test.
    Window(ForecastReport),
    /// The series is flaky; no clean window exists.
    Flaky(FlakyRefusal),
    /// The failure series is too short to forecast a cadence.
    NoRecurrence(RecurrenceRefusal),
}

// ---------------------------------------------------------------------------
// forecast_recurrence
// ---------------------------------------------------------------------------

/// Forecasts the recurrence cadence of a raw event series.
///
/// `events` are wall-clock event instants (any order; sorted internally); `now`
/// is the reference instant for the overdue hazard. Returns
/// [`ForecastOutcome::NoRecurrence`] when the series has fewer than
/// `config.min_events` events (a labeled refusal, not an error). `subject` is
/// carried through into the report and refusal for provenance.
pub fn forecast_recurrence(
    events: &[Ts],
    now: Ts,
    subject: Option<CxId>,
    config: &ForecastConfig,
) -> Result<ForecastOutcome, OracleError> {
    config.validate()?;

    // Sort and de-duplicate coincident events; a recurrence is a distinct instant.
    let mut sorted: Vec<Ts> = events.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    if sorted.len() < config.min_events as usize {
        return Ok(ForecastOutcome::NoRecurrence(RecurrenceRefusal {
            subject,
            have_events: sorted.len(),
            need_events: config.min_events as usize,
            code: ASTRO_NO_RECURRENCE,
            remediation: ORACLE_NO_RECURRENCE_REMEDIATION,
        }));
    }

    // Inter-arrival intervals (strictly positive after de-dup).
    let intervals: Vec<u64> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
    let interval_count = intervals.len();
    let median_cadence = lower_median(&intervals);
    let mad = median_absolute_deviation(&intervals, median_cadence);

    let last_event = *sorted.last().expect("min_events >= 2 guarantees a last");
    let next_occurrence_ts = last_event + median_cadence;

    // Credible interval: ±(mad_permille/1000)·MAD, widened for a small sample.
    let small_sample = interval_count < config.small_sample_threshold as usize;
    let widen = if small_sample {
        config.small_sample_widen_permille as f64 / 1000.0
    } else {
        1.0
    };
    let half_width =
        ((config.interval_mad_permille as f64 / 1000.0) * mad as f64 * widen).round() as u64;
    let interval_low_ts = next_occurrence_ts.saturating_sub(half_width);
    let interval_high_ts = next_occurrence_ts + half_width;

    // Regularity: 1 − MAD/median (dispersion), clamped to [0, 1].
    let regularity = if median_cadence > 0 {
        (1.0 - mad as f64 / median_cadence as f64).clamp(0.0, 1.0)
    } else if mad == 0 {
        1.0
    } else {
        0.0
    };
    let support = interval_count as f64 / (interval_count as f64 + config.support_smoothing as f64);
    let confidence = (regularity * support).min(config.max_confidence());

    // Renewal overdue hazard: empirical CDF of intervals at the elapsed time.
    let elapsed = now.saturating_sub(last_event);
    let overdue_hazard =
        intervals.iter().filter(|&&iv| iv <= elapsed).count() as f64 / interval_count as f64;

    let trust = if small_sample {
        TrustTag::Provisional
    } else {
        TrustTag::Trusted
    };

    let periodicity = PeriodicityFit {
        period_secs: median_cadence,
        strength: regularity,
    };
    let regime_changes = cusum_regime_changes(&sorted, &intervals, median_cadence, mad, config);

    Ok(ForecastOutcome::Forecast(ForecastReport {
        subject,
        event_count: sorted.len(),
        interval_count,
        median_cadence_secs: median_cadence,
        mad_secs: mad,
        next_occurrence_ts,
        interval_low_ts,
        interval_high_ts,
        regularity,
        confidence,
        overdue_hazard,
        small_sample,
        trust,
        periodicity,
        regime_changes,
    }))
}

// ---------------------------------------------------------------------------
// forecast_flaky_window
// ---------------------------------------------------------------------------

/// Forecasts a test's *failure* recurrence window, refusing on flaky evidence.
///
/// `outcomes` are the test's `(instant, passed)` observations. When their
/// pairwise self-consistency falls below `config.flaky_agreement_floor` the test
/// is flaky and the call refuses with [`FlakyOutcome::Flaky`] (naming the test) —
/// forecasting a cadence from self-inconsistent noise would be a confident guess.
/// Otherwise the failing instants form the recurrence series and are forecast as
/// in [`forecast_recurrence`].
pub fn forecast_flaky_window(
    outcomes: &[(Ts, bool)],
    test: CxId,
    now: Ts,
    config: &ForecastConfig,
) -> Result<FlakyOutcome, OracleError> {
    config.validate()?;

    let n = outcomes.len();
    let n_pass = outcomes.iter().filter(|(_, passed)| *passed).count();
    let n_fail = n - n_pass;

    // Flakiness is pairwise outcome agreement; it needs at least one pair and a
    // genuine mix of outcomes (an all-pass or all-fail series is not "flaky").
    if n_pass > 0 && n_fail > 0 {
        let pairs = choose2(n);
        let agree = choose2(n_pass) + choose2(n_fail);
        let self_consistency = agree as f64 / pairs as f64;
        if self_consistency < config.flaky_agreement_floor() {
            return Ok(FlakyOutcome::Flaky(FlakyRefusal {
                test,
                self_consistency,
                floor: config.flaky_agreement_floor(),
                code: ASTRO_FLAKY_EVIDENCE,
                remediation: ORACLE_FLAKY_EVIDENCE_REMEDIATION,
            }));
        }
    }

    // Not flaky: forecast the failing-instant recurrence series.
    let failures: Vec<Ts> = outcomes
        .iter()
        .filter(|(_, passed)| !*passed)
        .map(|(ts, _)| *ts)
        .collect();
    match forecast_recurrence(&failures, now, Some(test), config)? {
        ForecastOutcome::Forecast(report) => Ok(FlakyOutcome::Window(report)),
        ForecastOutcome::NoRecurrence(refusal) => Ok(FlakyOutcome::NoRecurrence(refusal)),
    }
}

// ---------------------------------------------------------------------------
// Adapters from the grounded corpus
// ---------------------------------------------------------------------------

/// Extracts a subject's *failing* occurrence instants (the failure-recurrence
/// series), sorted ascending, from mined [`OccurrenceRecord`]s.
pub fn failure_events_from_occurrences(records: &[OccurrenceRecord], subject: CxId) -> Vec<Ts> {
    let mut events: Vec<Ts> = records
        .iter()
        .filter(|r| r.subject == subject && !r.passed)
        .map(|r| r.outcome_ts)
        .collect();
    events.sort_unstable();
    events
}

/// Extracts a subject's `(instant, passed)` outcome series, sorted by instant,
/// from mined [`OccurrenceRecord`]s — the input to [`forecast_flaky_window`].
pub fn outcome_series_from_occurrences(
    records: &[OccurrenceRecord],
    subject: CxId,
) -> Vec<(Ts, bool)> {
    let mut series: Vec<(Ts, bool)> = records
        .iter()
        .filter(|r| r.subject == subject)
        .map(|r| (r.outcome_ts, r.passed))
        .collect();
    series.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    series
}

// ---------------------------------------------------------------------------
// Robust statistics and CUSUM
// ---------------------------------------------------------------------------

/// Lower median of a non-empty slice: element at index `(len − 1) / 2` of the
/// sorted values. Deterministic and tie-stable.
fn lower_median(values: &[u64]) -> u64 {
    debug_assert!(!values.is_empty());
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[(sorted.len() - 1) / 2]
}

/// Median absolute deviation about `center`: the lower median of `|x − center|`.
fn median_absolute_deviation(values: &[u64], center: u64) -> u64 {
    let deviations: Vec<u64> = values.iter().map(|&v| v.abs_diff(center)).collect();
    lower_median(&deviations)
}

/// Tabular CUSUM over the interval series (target = median cadence, zero slack).
///
/// The upward accumulator `C+` sums positive deviations (longer intervals) and
/// the downward accumulator `C-` sums negative deviations (shorter intervals);
/// crossing the decision interval `H = (cusum_permille/1000)·MAD` flags a
/// [`RegimeDirection::Slowdown`] or [`RegimeDirection::Speedup`] respectively at
/// the event closing that interval, and resets the accumulator. A perfectly
/// regular series (every deviation zero) never accumulates and flags nothing.
fn cusum_regime_changes(
    sorted_events: &[Ts],
    intervals: &[u64],
    median: u64,
    mad: u64,
    config: &ForecastConfig,
) -> Vec<RegimeChange> {
    let h = (config.cusum_threshold_permille as f64 / 1000.0) * mad as f64;
    let mut c_up = 0.0f64;
    let mut c_down = 0.0f64;
    let mut changes = Vec::new();
    for (i, &interval) in intervals.iter().enumerate() {
        let deviation = interval as f64 - median as f64;
        c_up = (c_up + deviation).max(0.0);
        c_down = (c_down - deviation).max(0.0);
        // The interval at index `i` closes the event at index `i + 1`.
        let event_index = i + 1;
        if c_up > h {
            changes.push(RegimeChange {
                at_event_index: event_index,
                at_ts: sorted_events[event_index],
                direction: RegimeDirection::Slowdown,
            });
            c_up = 0.0;
        } else if c_down > h {
            changes.push(RegimeChange {
                at_event_index: event_index,
                at_ts: sorted_events[event_index],
                direction: RegimeDirection::Speedup,
            });
            c_down = 0.0;
        }
    }
    changes
}

fn choose2(k: usize) -> usize {
    k.saturating_mul(k.saturating_sub(1)) / 2
}
