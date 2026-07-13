//! Registry-declared knobs for the assay job scheduler (standing invariant 4).
//!
//! Every budget, rate, and threshold the scheduler depends on is a *declared*
//! knob with explicit bounds, a unit, a source, and a rationale — never a bare
//! constant. The declaration type is reused from `astrolabe-domain` so the
//! whole workspace shares one knob shape.

use astrolabe_domain::knobs::U64KnobDeclaration;

/// Registry version tag for the assay scheduler knobs.
pub const ASSAY_KNOB_REGISTRY_VERSION: &str = "astrolabe-assay-knobs-v1";

/// Name of the default sample-size knob.
pub const ASSAY_SAMPLE_SIZE_KNOB: &str = "assay_sample_size";
/// Name of the lane cost-units-per-cooperative-tick knob.
pub const ASSAY_LANE_UNITS_PER_TICK_KNOB: &str = "assay_lane_units_per_tick";
/// Name of the serving-isolation p99 tripwire knob.
pub const ASSAY_SERVING_P99_TRIPWIRE_MICROS_KNOB: &str = "assay_serving_p99_tripwire_micros";

/// Default target sample size across the whole population.
///
/// Seeded from the classic Cochran fixed-precision sample-size guidance: at a
/// 95% confidence level and a 5% margin the required sample plateaus near 385
/// regardless of how large the population grows, so a few hundred sampled
/// symbols already pins a stratum proportion to within a few percent. 384 is
/// that plateau (Cochran n0 = 1.96^2 * 0.25 / 0.05^2 = 384.16).
pub const ASSAY_DEFAULT_SAMPLE_SIZE: u64 = 384;
/// Smallest legal sample size. Zero is illegal: a zero-size sample produces an
/// ack for a stratum proportion it never measured, the unlabeled-claim failure
/// the HONEST invariants forbid.
pub const ASSAY_MIN_SAMPLE_SIZE: u64 = 1;
/// Largest legal sample size. An upper bound keeps one scheduled job a bounded
/// unit of work even against a pathologically large population; a job that wants
/// the whole population still clamps to the population size at call time.
pub const ASSAY_MAX_SAMPLE_SIZE: u64 = 1_000_000;

/// Default number of per-subject scoring cost units a cooperative tick spends
/// before it yields the background lane.
///
/// Mirrors the ZFS scrub posture already adopted by the FSV janitor
/// (`FSV_JANITOR_ROWS_PER_SLICE`): background re-verification runs in bounded
/// slices that interleave with live I/O rather than one stop-the-world pass. A
/// scoring cost unit is one subject hashed into its priority key, so this bounds
/// how many subjects one tick touches before it checks the serving tripwire and
/// yields.
pub const ASSAY_DEFAULT_LANE_UNITS_PER_TICK: u64 = 4_096;
/// Smallest legal lane budget: a tick must make forward progress on at least one
/// subject, or the lane livelocks yielding without ever advancing the cursor.
pub const ASSAY_MIN_LANE_UNITS_PER_TICK: u64 = 1;
/// Largest legal lane budget. An upper bound keeps a tick a bounded slice even
/// on a huge population; the lane still loops ticks until the population is
/// fully scored, so this caps burst size, never completeness.
pub const ASSAY_MAX_LANE_UNITS_PER_TICK: u64 = 1_000_000;

/// Default serving-path p99 latency, in microseconds, above which the background
/// assay lane refuses to run so it never steals cycles from live serving.
///
/// Seeded from the ASTROLABE five-second M-scale convergence budget's
/// interactive-serving sub-budget: a 25ms p99 leaves the interactive serving
/// path two orders of magnitude of headroom under the human-perceptible ~100ms
/// threshold, so the background lane backs off well before serving latency
/// becomes user-visible. Replace with a measured serving-SLO once the live
/// serving path is benchmarked.
pub const ASSAY_DEFAULT_SERVING_P99_TRIPWIRE_MICROS: u64 = 25_000;
/// Smallest legal tripwire: a serving path that must answer within 1 microsecond
/// is the tightest isolation the lane can honor.
pub const ASSAY_MIN_SERVING_P99_TRIPWIRE_MICROS: u64 = 1;
/// Largest legal tripwire: one full second, past which serving latency is no
/// longer interactive and the isolation guarantee is meaningless.
pub const ASSAY_MAX_SERVING_P99_TRIPWIRE_MICROS: u64 = 1_000_000;

/// The assay scheduler knob registry.
pub const ASSAY_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ASSAY_KNOB_REGISTRY_VERSION,
        name: ASSAY_SAMPLE_SIZE_KNOB,
        default: ASSAY_DEFAULT_SAMPLE_SIZE,
        min: ASSAY_MIN_SAMPLE_SIZE,
        max: ASSAY_MAX_SAMPLE_SIZE,
        unit: "subjects",
        source: "Cochran, Sampling Techniques 3rd ed. (fixed-precision n0 = z^2 p(1-p)/e^2 = 1.96^2*0.25/0.05^2 = 384.16 at 95% confidence, 5% margin)",
        rationale: "seed target sample size; ~384 pins a stratum proportion to within a few percent independent of population size; a job clamps to the population size when it is smaller; replace with a measured precision target once MI variance is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_KNOB_REGISTRY_VERSION,
        name: ASSAY_LANE_UNITS_PER_TICK_KNOB,
        default: ASSAY_DEFAULT_LANE_UNITS_PER_TICK,
        min: ASSAY_MIN_LANE_UNITS_PER_TICK,
        max: ASSAY_MAX_LANE_UNITS_PER_TICK,
        unit: "subjects",
        source: "https://openzfs.github.io/openzfs-docs/man/v2.4/8/zpool-scrub.8.html (scrub interleaves with live I/O in bounded, resumable slices) and astrolabe-domain FSV_JANITOR_ROWS_PER_SLICE",
        rationale: "bounds the subjects one cooperative tick scores before it yields the background lane so scheduling never becomes an unbounded stop-the-world pass; the lane loops ticks until the population is scored, so this caps burst size, not completeness; replace with a measured CPU-time budget once scoring throughput is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_KNOB_REGISTRY_VERSION,
        name: ASSAY_SERVING_P99_TRIPWIRE_MICROS_KNOB,
        default: ASSAY_DEFAULT_SERVING_P99_TRIPWIRE_MICROS,
        min: ASSAY_MIN_SERVING_P99_TRIPWIRE_MICROS,
        max: ASSAY_MAX_SERVING_P99_TRIPWIRE_MICROS,
        unit: "microseconds",
        source: "ASTROLABE #23 five-second M-scale convergence budget (interactive-serving sub-budget) over the ~100ms human-perceptible interaction threshold (Nielsen, Response Times: The 3 Important Limits)",
        rationale: "serving-path p99 above which the background assay lane refuses to run so it never steals cycles from live serving; 25ms keeps serving two orders of magnitude under the human-perceptible threshold; replace with a measured serving SLO once the live serving path is benchmarked",
    },
];

/// Returns the assay declaration for `name`, or `None` when the knob is undeclared.
pub fn assay_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ASSAY_KNOBS.iter().find(|knob| knob.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_assay_knob_declares_bounds_that_contain_its_default() {
        assert!(!ASSAY_KNOBS.is_empty());
        for knob in ASSAY_KNOBS {
            assert_eq!(
                knob.registry_version, ASSAY_KNOB_REGISTRY_VERSION,
                "{knob:?}"
            );
            assert!(knob.min <= knob.max, "{knob:?}");
            assert!(knob.accepts(knob.default), "{knob:?}");
            assert!(!knob.unit.is_empty(), "{knob:?}");
            assert!(!knob.source.is_empty(), "{knob:?}");
            assert!(!knob.rationale.is_empty(), "{knob:?}");
        }
    }

    #[test]
    fn sample_size_zero_is_not_a_legal_knob_value() {
        let knob = assay_knob(ASSAY_SAMPLE_SIZE_KNOB).expect("declared");
        assert!(!knob.accepts(0));
        assert!(knob.accepts(ASSAY_DEFAULT_SAMPLE_SIZE));
        assert!(knob.accepts(ASSAY_MIN_SAMPLE_SIZE));
        assert!(knob.accepts(ASSAY_MAX_SAMPLE_SIZE));
        assert!(!knob.accepts(ASSAY_MAX_SAMPLE_SIZE + 1));
    }

    #[test]
    fn lane_budget_and_tripwire_reject_zero_and_over_max() {
        for name in [
            ASSAY_LANE_UNITS_PER_TICK_KNOB,
            ASSAY_SERVING_P99_TRIPWIRE_MICROS_KNOB,
        ] {
            let knob = assay_knob(name).expect("declared");
            assert!(!knob.accepts(0), "{name} must reject zero");
            assert!(knob.accepts(knob.min), "{name} accepts min");
            assert!(knob.accepts(knob.max), "{name} accepts max");
            assert!(!knob.accepts(knob.max + 1), "{name} rejects over max");
        }
    }
}
