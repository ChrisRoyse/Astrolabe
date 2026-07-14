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

/// Registry version tag for the KSG bits-measurement knobs (#32).
pub const ASSAY_BITS_KNOB_REGISTRY_VERSION: &str = "astrolabe-assay-bits-knobs-v1";

/// Name of the KSG neighbour-count knob.
pub const ASSAY_KSG_NEIGHBORS_K_KNOB: &str = "assay_ksg_neighbors_k";
/// Name of the small-sample floor knob (below which results go provisional).
pub const ASSAY_FLOOR_SAMPLE_SIZE_KNOB: &str = "assay_floor_sample_size";
/// Name of the bootstrap resample-count knob.
pub const ASSAY_BOOTSTRAP_RESAMPLES_KNOB: &str = "assay_bootstrap_resamples";
/// Name of the subsample-fraction knob (permille of n) for the interval.
pub const ASSAY_BOOTSTRAP_SUBSAMPLE_PERMILLE_KNOB: &str = "assay_bootstrap_subsample_permille";
/// Name of the confidence/credible-interval level knob (permille).
pub const ASSAY_CI_CONFIDENCE_PERMILLE_KNOB: &str = "assay_ci_confidence_permille";
/// Name of the small-sample posterior draw-count knob.
pub const ASSAY_POSTERIOR_DRAWS_KNOB: &str = "assay_posterior_draws";
/// Name of the small-sample posterior Dirichlet prior concentration knob (permille).
pub const ASSAY_POSTERIOR_PRIOR_ALPHA_PERMILLE_KNOB: &str = "assay_posterior_prior_alpha_permille";
/// Name of the small-sample discretization bin-count knob.
pub const ASSAY_FLOOR_DISCRETIZATION_BINS_KNOB: &str = "assay_floor_discretization_bins";
/// Name of the random-projection dimension factor knob (permille of log2 n).
pub const ASSAY_PROJECTION_FACTOR_PERMILLE_KNOB: &str = "assay_projection_factor_permille";
/// Name of the sufficiency-comparison slack knob (millibits).
pub const ASSAY_SUFFICIENCY_SLACK_MILLIBITS_KNOB: &str = "assay_sufficiency_slack_millibits";
/// Name of the DPI-ceiling slack knob (millibits).
pub const ASSAY_DPI_CEILING_SLACK_MILLIBITS_KNOB: &str = "assay_dpi_ceiling_slack_millibits";
/// Name of the minimum-per-slot-signal knob (millibits) that routes a dead lens
/// to a lens proposal rather than to more grounding.
pub const ASSAY_MIN_SLOT_SIGNAL_MILLIBITS_KNOB: &str = "assay_min_slot_signal_millibits";

/// Default KSG neighbour count. The blueprint fixes k = 3 (08 §, capability 4.1).
pub const ASSAY_DEFAULT_KSG_NEIGHBORS_K: u64 = 3;
/// Smallest legal neighbour count: k = 1 is the tightest estimator.
pub const ASSAY_MIN_KSG_NEIGHBORS_K: u64 = 1;
/// Largest legal neighbour count: past a few dozen neighbours the local density
/// estimate is no longer local at practical sample sizes.
pub const ASSAY_MAX_KSG_NEIGHBORS_K: u64 = 64;

/// Default small-sample floor. Below 50 samples per (slot, axis) the KSG point
/// estimate is not trustworthy and the result goes provisional (blueprint §1).
pub const ASSAY_DEFAULT_FLOOR_SAMPLE_SIZE: u64 = 50;
/// Smallest legal floor: at least two samples are needed to estimate anything.
pub const ASSAY_MIN_FLOOR_SAMPLE_SIZE: u64 = 2;
/// Largest legal floor. An upper bound keeps the provisional regime bounded.
pub const ASSAY_MAX_FLOOR_SAMPLE_SIZE: u64 = 1_000_000;

/// Default bootstrap resample count for the confidence interval.
///
/// The KSG/Ross estimators are O(n²) per estimate, and a bootstrap recomputes the
/// estimate once per resample, so the resample count is the dominant cost of a
/// card. 200 is the low end of Efron's percentile-interval range — enough for a
/// stable two-sided band — chosen because the per-resample cost is a full k-NN MI
/// estimate rather than a cheap statistic; the whole sweep is a nightly batch.
pub const ASSAY_DEFAULT_BOOTSTRAP_RESAMPLES: u64 = 200;
/// Smallest legal resample count: a CI needs at least a handful of resamples.
pub const ASSAY_MIN_BOOTSTRAP_RESAMPLES: u64 = 2;
/// Largest legal resample count. An upper bound bounds the per-card CPU.
pub const ASSAY_MAX_BOOTSTRAP_RESAMPLES: u64 = 100_000;

/// Default subsample size, in permille of n: 800 = 0.8·n. Subsampling *without*
/// replacement (rather than bootstrap with replacement) is used for the interval
/// because k-NN MI estimators are corrupted by the tied (zero-distance) duplicate
/// points a with-replacement resample creates.
pub const ASSAY_DEFAULT_BOOTSTRAP_SUBSAMPLE_PERMILLE: u64 = 800;
/// Smallest legal subsample fraction (permille): 100 = 0.1·n.
pub const ASSAY_MIN_BOOTSTRAP_SUBSAMPLE_PERMILLE: u64 = 100;
/// Largest legal subsample fraction (permille): 999. It stops short of 1000
/// because a full-size subsample without replacement is the original sample, so
/// every draw would be identical and the interval would have zero width.
pub const ASSAY_MAX_BOOTSTRAP_SUBSAMPLE_PERMILLE: u64 = 999;

/// Default two-sided interval level, in permille: 950 = 95%.
pub const ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE: u64 = 950;
/// Smallest legal interval level: a 50% interval is the loosest still useful band.
pub const ASSAY_MIN_CI_CONFIDENCE_PERMILLE: u64 = 500;
/// Largest legal interval level: 999 permille (99.9%), short of the degenerate 100%.
pub const ASSAY_MAX_CI_CONFIDENCE_PERMILLE: u64 = 999;

/// Default posterior draw count for the small-sample credible interval.
pub const ASSAY_DEFAULT_POSTERIOR_DRAWS: u64 = 2_000;
/// Smallest legal posterior draw count.
pub const ASSAY_MIN_POSTERIOR_DRAWS: u64 = 2;
/// Largest legal posterior draw count.
pub const ASSAY_MAX_POSTERIOR_DRAWS: u64 = 100_000;

/// Default Dirichlet prior concentration, in permille: 500 = 0.5, the Jeffreys
/// reference prior for a multinomial cell. It is a principled reference value,
/// not a tuned knob.
pub const ASSAY_DEFAULT_POSTERIOR_PRIOR_ALPHA_PERMILLE: u64 = 500;
/// Smallest legal prior concentration (permille): 1 = 0.001, a near-Haldane prior.
pub const ASSAY_MIN_POSTERIOR_PRIOR_ALPHA_PERMILLE: u64 = 1;
/// Largest legal prior concentration (permille): 10000 = 10.0, a strong prior.
pub const ASSAY_MAX_POSTERIOR_PRIOR_ALPHA_PERMILLE: u64 = 10_000;

/// Default number of equal-frequency bins for small-sample discretization.
pub const ASSAY_DEFAULT_FLOOR_DISCRETIZATION_BINS: u64 = 4;
/// Smallest legal bin count: two bins is the coarsest non-trivial discretization.
pub const ASSAY_MIN_FLOOR_DISCRETIZATION_BINS: u64 = 2;
/// Largest legal bin count. An upper bound keeps the contingency table small at
/// the tiny sample sizes the floor path runs on.
pub const ASSAY_MAX_FLOOR_DISCRETIZATION_BINS: u64 = 64;

/// Default random-projection dimension factor, in permille: 2000 = 2.0, so the
/// target dimension is `2·log2(n)` (blueprint §1).
pub const ASSAY_DEFAULT_PROJECTION_FACTOR_PERMILLE: u64 = 2_000;
/// Smallest legal projection factor (permille): 1 keeps at least a sliver of the
/// log2(n) rule.
pub const ASSAY_MIN_PROJECTION_FACTOR_PERMILLE: u64 = 1;
/// Largest legal projection factor (permille): 100000 = 100.0.
pub const ASSAY_MAX_PROJECTION_FACTOR_PERMILLE: u64 = 100_000;

/// Default sufficiency-comparison slack, in millibits: 50 = 0.05 bits, one
/// estimator-noise band, so a panel that measures within noise of `H(axis)` is
/// not flagged insufficient on noise alone.
pub const ASSAY_DEFAULT_SUFFICIENCY_SLACK_MILLIBITS: u64 = 50;
/// Smallest legal sufficiency slack: zero is illegal because a zero slack flags a
/// panel insufficient on estimator noise below the measurement floor.
pub const ASSAY_MIN_SUFFICIENCY_SLACK_MILLIBITS: u64 = 1;
/// Largest legal sufficiency slack, in millibits: 1000 = 1.0 bit.
pub const ASSAY_MAX_SUFFICIENCY_SLACK_MILLIBITS: u64 = 1_000;

/// Default DPI-ceiling slack, in millibits: 50 = 0.05 bits, so a derived claim is
/// only refused when it exceeds the panel ceiling by more than estimator noise.
pub const ASSAY_DEFAULT_DPI_CEILING_SLACK_MILLIBITS: u64 = 50;
/// Smallest legal DPI slack: zero is illegal because a zero slack would refuse a
/// derived claim that merely equals the ceiling within estimator noise.
pub const ASSAY_MIN_DPI_CEILING_SLACK_MILLIBITS: u64 = 1;
/// Largest legal DPI slack, in millibits: 1000 = 1.0 bit.
pub const ASSAY_MAX_DPI_CEILING_SLACK_MILLIBITS: u64 = 1_000;

/// Default minimum per-slot signal, in millibits: 50 = 0.05 bits, the blueprint's
/// lens-admission floor (10.3: `≥ 0.05 bits`). A slot below it carries no usable
/// signal, so its deficit routes to a lens proposal rather than to more grounding.
pub const ASSAY_DEFAULT_MIN_SLOT_SIGNAL_MILLIBITS: u64 = 50;
/// Smallest legal minimum-signal threshold: zero is illegal because it would
/// classify a dead slot as carrying signal.
pub const ASSAY_MIN_MIN_SLOT_SIGNAL_MILLIBITS: u64 = 1;
/// Largest legal minimum-signal threshold, in millibits: 1000 = 1.0 bit.
pub const ASSAY_MAX_MIN_SLOT_SIGNAL_MILLIBITS: u64 = 1_000;

/// The KSG bits-measurement knob registry (#32).
pub const ASSAY_BITS_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_KSG_NEIGHBORS_K_KNOB,
        default: ASSAY_DEFAULT_KSG_NEIGHBORS_K,
        min: ASSAY_MIN_KSG_NEIGHBORS_K,
        max: ASSAY_MAX_KSG_NEIGHBORS_K,
        unit: "neighbors",
        source: "Kraskov, Stögbauer & Grassberger, 'Estimating mutual information', Phys. Rev. E 69 066138 (2004), and ASTROLABE blueprint 08_ASSAY §1 (KSG k-NN MI, k=3)",
        rationale: "neighbour count for the KSG/Ross k-NN MI estimators; k=3 is the blueprint-fixed low-bias/low-variance operating point KSG recommends; larger k trades variance for bias and is a deliberate operator choice",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_FLOOR_SAMPLE_SIZE_KNOB,
        default: ASSAY_DEFAULT_FLOOR_SAMPLE_SIZE,
        min: ASSAY_MIN_FLOOR_SAMPLE_SIZE,
        max: ASSAY_MAX_FLOOR_SAMPLE_SIZE,
        unit: "samples",
        source: "ASTROLABE blueprint 08_ASSAY §1 (50-sample floor, provisional-below-floor via Bayesian posteriors)",
        rationale: "per (slot, axis) sample count below which the KSG point estimate is not trusted and the result is reported provisional with a posterior credible interval instead of a bare point estimate",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_BOOTSTRAP_RESAMPLES_KNOB,
        default: ASSAY_DEFAULT_BOOTSTRAP_RESAMPLES,
        min: ASSAY_MIN_BOOTSTRAP_RESAMPLES,
        max: ASSAY_MAX_BOOTSTRAP_RESAMPLES,
        unit: "resamples",
        source: "Efron & Tibshirani, 'An Introduction to the Bootstrap' (1993): 100–1000 resamples for a two-sided percentile interval, lower end acceptable when each resample is expensive",
        rationale: "number of seeded paired resamples used to build the above-floor confidence interval; each resample recomputes a full O(n²) k-NN MI estimate, so 200 (the low end of the percentile-CI range) balances interval stability against the nightly-batch CPU budget; more resamples tighten the Monte-Carlo error of the endpoints at linear CPU cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_BOOTSTRAP_SUBSAMPLE_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_BOOTSTRAP_SUBSAMPLE_PERMILLE,
        min: ASSAY_MIN_BOOTSTRAP_SUBSAMPLE_PERMILLE,
        max: ASSAY_MAX_BOOTSTRAP_SUBSAMPLE_PERMILLE,
        unit: "permille",
        source: "Politis, Romano & Wolf, 'Subsampling' (1999): subsampling without replacement for statistics of dependent/degenerate data; and Kraskov et al. (2004) on the k-NN estimator's sensitivity to tied points",
        rationale: "size of each without-replacement subsample, as a fraction of n, whose estimates form the interval; subsampling is used instead of the classic with-replacement bootstrap because duplicate (zero-distance) points corrupt the k-NN MI estimator; 800 permille = 0.8·n keeps the subsample near full size (little bias shift) while still varying membership; must stay below 1000 or every draw is the whole sample",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_CI_CONFIDENCE_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE,
        min: ASSAY_MIN_CI_CONFIDENCE_PERMILLE,
        max: ASSAY_MAX_CI_CONFIDENCE_PERMILLE,
        unit: "permille",
        source: "conventional 95% two-sided interval level (Efron & Tibshirani, 1993)",
        rationale: "two-sided level of both the bootstrap confidence interval and the small-sample posterior credible interval; 950 permille = 95% is the reporting convention; tighter or looser bands are a deliberate operator choice",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_POSTERIOR_DRAWS_KNOB,
        default: ASSAY_DEFAULT_POSTERIOR_DRAWS,
        min: ASSAY_MIN_POSTERIOR_DRAWS,
        max: ASSAY_MAX_POSTERIOR_DRAWS,
        unit: "draws",
        source: "Monte-Carlo posterior summarization guidance (Gelman et al., 'Bayesian Data Analysis' 3rd ed.): a couple thousand draws stabilize interval quantiles",
        rationale: "number of Dirichlet-posterior draws whose per-draw plug-in MI forms the small-sample credible interval; 2000 stabilizes the 2.5/97.5 quantiles; more draws reduce Monte-Carlo error at linear CPU cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_POSTERIOR_PRIOR_ALPHA_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_POSTERIOR_PRIOR_ALPHA_PERMILLE,
        min: ASSAY_MIN_POSTERIOR_PRIOR_ALPHA_PERMILLE,
        max: ASSAY_MAX_POSTERIOR_PRIOR_ALPHA_PERMILLE,
        unit: "permille",
        source: "Jeffreys, 'Theory of Probability' (1961): the Jeffreys reference prior for a multinomial is Dirichlet(1/2)",
        rationale: "per-cell Dirichlet concentration of the small-sample posterior over the (slot, axis) contingency table; 500 permille = 0.5 is the Jeffreys reference prior (invariant, minimally informative), not a tuned value; alternatives (Haldane 0, uniform 1.0) are deliberate reference-prior choices",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_FLOOR_DISCRETIZATION_BINS_KNOB,
        default: ASSAY_DEFAULT_FLOOR_DISCRETIZATION_BINS,
        min: ASSAY_MIN_FLOOR_DISCRETIZATION_BINS,
        max: ASSAY_MAX_FLOOR_DISCRETIZATION_BINS,
        unit: "bins",
        source: "equal-frequency (quantile) binning guidance for small-sample contingency-table MI (Cover & Thomas, 'Elements of Information Theory' 2nd ed., §8 on quantization)",
        rationale: "number of equal-frequency bins the small-sample posterior path discretizes a continuous slot/axis into before forming the contingency table; 4 keeps expected per-cell counts non-trivial at n<50; more bins sharpen resolution but thin the table",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_PROJECTION_FACTOR_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_PROJECTION_FACTOR_PERMILLE,
        min: ASSAY_MIN_PROJECTION_FACTOR_PERMILLE,
        max: ASSAY_MAX_PROJECTION_FACTOR_PERMILLE,
        unit: "permille",
        source: "Johnson & Lindenstrauss (1984) distance-preserving embedding into O(log n) dimensions, and ASTROLABE blueprint 08_ASSAY §1 (target dim ≈ 2·log2(n))",
        rationale: "multiplier on log2(n) that sets the random-projection target dimension for embedding slots before KSG; 2000 permille = 2.0 gives the blueprint's 2·log2(n); larger keeps more dimensions at the cost of k-NN distance contrast",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_SUFFICIENCY_SLACK_MILLIBITS_KNOB,
        default: ASSAY_DEFAULT_SUFFICIENCY_SLACK_MILLIBITS,
        min: ASSAY_MIN_SUFFICIENCY_SLACK_MILLIBITS,
        max: ASSAY_MAX_SUFFICIENCY_SLACK_MILLIBITS,
        unit: "millibits",
        source: "ASTROLABE blueprint 08_ASSAY §2 (sufficiency I(panel;axis) ≥ H(axis)); slack sized to one KSG estimator-noise band (~0.05 bits at the operating sample sizes)",
        rationale: "bits of headroom by which panel MI may fall short of H(axis) before the axis is flagged insufficient, so a within-noise shortfall is not reported as a deficit; zero is illegal because it flags insufficiency on estimator noise",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_DPI_CEILING_SLACK_MILLIBITS_KNOB,
        default: ASSAY_DEFAULT_DPI_CEILING_SLACK_MILLIBITS,
        min: ASSAY_MIN_DPI_CEILING_SLACK_MILLIBITS,
        max: ASSAY_MAX_DPI_CEILING_SLACK_MILLIBITS,
        unit: "millibits",
        source: "Data Processing Inequality (Cover & Thomas §2.8) and ASTROLABE blueprint capability 4.13 (derived signal never exceeds I(panel;outcome)); slack sized to one KSG estimator-noise band",
        rationale: "bits by which a derived-signal claim may exceed the measured panel→outcome ceiling before it is refused fail-closed, so the refusal fires on a real DPI violation rather than on estimator noise; zero is illegal because it refuses a claim that merely equals the ceiling within noise",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_BITS_KNOB_REGISTRY_VERSION,
        name: ASSAY_MIN_SLOT_SIGNAL_MILLIBITS_KNOB,
        default: ASSAY_DEFAULT_MIN_SLOT_SIGNAL_MILLIBITS,
        min: ASSAY_MIN_MIN_SLOT_SIGNAL_MILLIBITS,
        max: ASSAY_MAX_MIN_SLOT_SIGNAL_MILLIBITS,
        unit: "millibits",
        source: "ASTROLABE blueprint 14 §4 / capability 10.3 lens-admission gate (≥ 0.05 bits)",
        rationale: "per-slot marginal-bits floor below which a slot is treated as carrying no usable signal, so its share of a sufficiency deficit routes to ProposeLens (replace the dead lens) rather than to AddOutcomeAnchor (more grounding for a live lens); zero is illegal because it would classify a dead slot as informative",
    },
];

/// Returns the bits-measurement declaration for `name`, or `None` when undeclared.
pub fn assay_bits_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ASSAY_BITS_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for the P5.3 differentiation knobs (#33).
pub const ASSAY_DIFF_KNOB_REGISTRY_VERSION: &str = "astrolabe-assay-diff-knobs-v1";

/// Name of the number-of-equal-frequency-bins knob for differentiation.
pub const ASSAY_DIFF_DISCRETIZATION_BINS_KNOB: &str = "assay_diff_discretization_bins";
/// Name of the redundancy retire-gate NMI threshold knob (permille).
pub const ASSAY_REDUNDANCY_RETIRE_NMI_PERMILLE_KNOB: &str = "assay_redundancy_retire_nmi_permille";
/// Name of the synergy classification resample-count knob.
pub const ASSAY_SYNERGY_RESAMPLES_KNOB: &str = "assay_synergy_resamples";
/// Name of the synergy minimum-effect-magnitude knob (millibits).
pub const ASSAY_SYNERGY_MIN_EFFECT_MILLIBITS_KNOB: &str = "assay_synergy_min_effect_millibits";
/// Name of the transfer-entropy minimum-lag knob.
pub const ASSAY_TE_MIN_LAG_KNOB: &str = "assay_te_min_lag";
/// Name of the transfer-entropy maximum-lag knob.
pub const ASSAY_TE_MAX_LAG_KNOB: &str = "assay_te_max_lag";
/// Name of the transfer-entropy permutation-count knob.
pub const ASSAY_TE_PERMUTATIONS_KNOB: &str = "assay_te_permutations";
/// Name of the periodicity permutation-count knob.
pub const ASSAY_PERIODICITY_PERMUTATIONS_KNOB: &str = "assay_periodicity_permutations";
/// Name of the periodicity frequency-grid oversampling-factor knob.
pub const ASSAY_PERIODICITY_OVERSAMPLE_KNOB: &str = "assay_periodicity_oversample";
/// Name of the periodicity false-alarm-probability threshold knob (permille).
pub const ASSAY_FAP_THRESHOLD_PERMILLE_KNOB: &str = "assay_fap_threshold_permille";
/// Name of the CUSUM minimum-segment-length knob.
pub const ASSAY_CUSUM_MIN_SEGMENT_KNOB: &str = "assay_cusum_min_segment";
/// Name of the CUSUM bootstrap-permutation-count knob.
pub const ASSAY_CUSUM_PERMUTATIONS_KNOB: &str = "assay_cusum_permutations";
/// Name of the MMD permutation-count knob.
pub const ASSAY_MMD_PERMUTATIONS_KNOB: &str = "assay_mmd_permutations";
/// Name of the two-sample significance-level knob (permille) shared by TE and MMD.
pub const ASSAY_SIGNIFICANCE_PERMILLE_KNOB: &str = "assay_significance_permille";
/// Name of the transfer-entropy effective-sample quorum knob.
pub const ASSAY_TE_QUORUM_KNOB: &str = "assay_te_quorum";

/// Default equal-frequency bin count for differentiation discretization.
pub const ASSAY_DEFAULT_DIFF_DISCRETIZATION_BINS: u64 = 4;
/// Smallest legal differentiation bin count.
pub const ASSAY_MIN_DIFF_DISCRETIZATION_BINS: u64 = 2;
/// Largest legal differentiation bin count.
pub const ASSAY_MAX_DIFF_DISCRETIZATION_BINS: u64 = 64;

/// Default redundancy retire-gate NMI threshold, permille: 600 = 0.6 (blueprint
/// 05: retire when max pairwise correlation with an admitted lens > 0.6).
pub const ASSAY_DEFAULT_REDUNDANCY_RETIRE_NMI_PERMILLE: u64 = 600;
/// Smallest legal retire threshold: 1 permille (any dependence retires).
pub const ASSAY_MIN_REDUNDANCY_RETIRE_NMI_PERMILLE: u64 = 1;
/// Largest legal retire threshold: 1000 permille (only an exact duplicate retires).
pub const ASSAY_MAX_REDUNDANCY_RETIRE_NMI_PERMILLE: u64 = 1_000;

/// Default synergy classification resample count for the interaction-information
/// interval.
pub const ASSAY_DEFAULT_SYNERGY_RESAMPLES: u64 = 200;
/// Smallest legal synergy resample count.
pub const ASSAY_MIN_SYNERGY_RESAMPLES: u64 = 2;
/// Largest legal synergy resample count.
pub const ASSAY_MAX_SYNERGY_RESAMPLES: u64 = 100_000;

/// Default synergy minimum effect magnitude, millibits: 50 = 0.05 bits (the
/// blueprint's lens-admission bit floor, reused as the smallest interaction worth
/// classifying above finite-sample plug-in bias).
pub const ASSAY_DEFAULT_SYNERGY_MIN_EFFECT_MILLIBITS: u64 = 50;
/// Smallest legal synergy minimum effect: 1 millibit.
pub const ASSAY_MIN_SYNERGY_MIN_EFFECT_MILLIBITS: u64 = 1;
/// Largest legal synergy minimum effect: 1000 millibits = 1.0 bit.
pub const ASSAY_MAX_SYNERGY_MIN_EFFECT_MILLIBITS: u64 = 1_000;

/// Default transfer-entropy minimum lag (blueprint 08 §6 sweep {1,2,4,8}).
pub const ASSAY_DEFAULT_TE_MIN_LAG: u64 = 1;
/// Smallest legal transfer-entropy minimum lag.
pub const ASSAY_MIN_TE_MIN_LAG: u64 = 1;
/// Largest legal transfer-entropy minimum lag.
pub const ASSAY_MAX_TE_MIN_LAG: u64 = 1_024;

/// Default transfer-entropy maximum lag (blueprint 08 §6 sweep {1,2,4,8}).
pub const ASSAY_DEFAULT_TE_MAX_LAG: u64 = 8;
/// Smallest legal transfer-entropy maximum lag.
pub const ASSAY_MIN_TE_MAX_LAG: u64 = 1;
/// Largest legal transfer-entropy maximum lag.
pub const ASSAY_MAX_TE_MAX_LAG: u64 = 1_024;

/// Default transfer-entropy permutation count for the significance null.
pub const ASSAY_DEFAULT_TE_PERMUTATIONS: u64 = 200;
/// Smallest legal transfer-entropy permutation count.
pub const ASSAY_MIN_TE_PERMUTATIONS: u64 = 2;
/// Largest legal transfer-entropy permutation count.
pub const ASSAY_MAX_TE_PERMUTATIONS: u64 = 100_000;

/// Default periodicity permutation count for the false-alarm-probability null.
pub const ASSAY_DEFAULT_PERIODICITY_PERMUTATIONS: u64 = 200;
/// Smallest legal periodicity permutation count.
pub const ASSAY_MIN_PERIODICITY_PERMUTATIONS: u64 = 2;
/// Largest legal periodicity permutation count.
pub const ASSAY_MAX_PERIODICITY_PERMUTATIONS: u64 = 100_000;

/// Default Lomb–Scargle frequency-grid oversampling factor (Press & Rybicki: 4×).
pub const ASSAY_DEFAULT_PERIODICITY_OVERSAMPLE: u64 = 4;
/// Smallest legal oversampling factor.
pub const ASSAY_MIN_PERIODICITY_OVERSAMPLE: u64 = 1;
/// Largest legal oversampling factor.
pub const ASSAY_MAX_PERIODICITY_OVERSAMPLE: u64 = 64;

/// Default periodicity FAP threshold, permille: 50 = 0.05.
pub const ASSAY_DEFAULT_FAP_THRESHOLD_PERMILLE: u64 = 50;
/// Smallest legal FAP threshold.
pub const ASSAY_MIN_FAP_THRESHOLD_PERMILLE: u64 = 1;
/// Largest legal FAP threshold: 500 = 0.5 (looser than a coin flip is meaningless).
pub const ASSAY_MAX_FAP_THRESHOLD_PERMILLE: u64 = 500;

/// Default CUSUM minimum segment length before/after a change.
pub const ASSAY_DEFAULT_CUSUM_MIN_SEGMENT: u64 = 10;
/// Smallest legal CUSUM minimum segment length.
pub const ASSAY_MIN_CUSUM_MIN_SEGMENT: u64 = 1;
/// Largest legal CUSUM minimum segment length.
pub const ASSAY_MAX_CUSUM_MIN_SEGMENT: u64 = 1_000_000;

/// Default CUSUM bootstrap permutation count for the change-confidence null.
pub const ASSAY_DEFAULT_CUSUM_PERMUTATIONS: u64 = 200;
/// Smallest legal CUSUM permutation count.
pub const ASSAY_MIN_CUSUM_PERMUTATIONS: u64 = 2;
/// Largest legal CUSUM permutation count.
pub const ASSAY_MAX_CUSUM_PERMUTATIONS: u64 = 100_000;

/// Default MMD permutation count for the drift null.
pub const ASSAY_DEFAULT_MMD_PERMUTATIONS: u64 = 200;
/// Smallest legal MMD permutation count.
pub const ASSAY_MIN_MMD_PERMUTATIONS: u64 = 2;
/// Largest legal MMD permutation count.
pub const ASSAY_MAX_MMD_PERMUTATIONS: u64 = 100_000;

/// Default two-sample significance level, permille: 950 = require the observed
/// statistic to exceed 95% of the permutation null (p ≤ 0.05).
pub const ASSAY_DEFAULT_SIGNIFICANCE_PERMILLE: u64 = 950;
/// Smallest legal significance level: 500 permille (median of the null).
pub const ASSAY_MIN_SIGNIFICANCE_PERMILLE: u64 = 500;
/// Largest legal significance level: 999 permille (short of the degenerate 100%).
pub const ASSAY_MAX_SIGNIFICANCE_PERMILLE: u64 = 999;

/// Default transfer-entropy effective-sample quorum (blueprint 08 §6 / perf table:
/// only top lead/lag pairs, quorum 50).
pub const ASSAY_DEFAULT_TE_QUORUM: u64 = 50;
/// Smallest legal transfer-entropy quorum.
pub const ASSAY_MIN_TE_QUORUM: u64 = 2;
/// Largest legal transfer-entropy quorum.
pub const ASSAY_MAX_TE_QUORUM: u64 = 1_000_000;

/// The P5.3 differentiation knob registry (#33).
pub const ASSAY_DIFF_KNOBS: &[U64KnobDeclaration] = &[
    // The redundancy/synergy quorum knobs are shared with the card registry
    // (#34's `assay_card_knob`); lane #33's differentiation path resolves them
    // through `assay_diff_knob`, so the same knob name is declared in both
    // registries against the one set of `ASSAY_*_QUORUM` bounds constants.
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_REDUNDANCY_QUORUM_KNOB,
        default: ASSAY_DEFAULT_REDUNDANCY_QUORUM,
        min: ASSAY_MIN_REDUNDANCY_QUORUM,
        max: ASSAY_MAX_REDUNDANCY_QUORUM,
        unit: "samples",
        source: "ASTROLABE blueprint 08_ASSAY §3 (total-correlation quorum 50/slot)",
        rationale: "minimum aligned sample count below which the total-correlation / n_eff card is reported provisional; the plug-in joint entropy over many slots is badly under-sampled below it",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_SYNERGY_QUORUM_KNOB,
        default: ASSAY_DEFAULT_SYNERGY_QUORUM,
        min: ASSAY_MIN_SYNERGY_QUORUM,
        max: ASSAY_MAX_SYNERGY_QUORUM,
        unit: "samples",
        source: "ASTROLABE blueprint 08_ASSAY §4 (three-way interaction-information quorum 150)",
        rationale: "minimum aligned sample count below which a synergy triple is reported provisional; a three-way contingency table needs more support than a pairwise one before its interaction-information sign is trusted",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_DIFF_DISCRETIZATION_BINS_KNOB,
        default: ASSAY_DEFAULT_DIFF_DISCRETIZATION_BINS,
        min: ASSAY_MIN_DIFF_DISCRETIZATION_BINS,
        max: ASSAY_MAX_DIFF_DISCRETIZATION_BINS,
        unit: "bins",
        source: "equal-frequency (quantile) binning for plug-in contingency-table entropy (Cover & Thomas, 'Elements of Information Theory' 2nd ed., §8 on quantization)",
        rationale: "number of equal-frequency bins a continuous slot/series is reduced to before the discrete plug-in entropy estimators run; 4 keeps expected per-cell counts non-trivial at the quorum sample sizes; more bins sharpen resolution but thin the joint table",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_REDUNDANCY_RETIRE_NMI_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_REDUNDANCY_RETIRE_NMI_PERMILLE,
        min: ASSAY_MIN_REDUNDANCY_RETIRE_NMI_PERMILLE,
        max: ASSAY_MAX_REDUNDANCY_RETIRE_NMI_PERMILLE,
        unit: "permille",
        source: "ASTROLABE blueprint 05 §6 / 08 §3 capability gate (retire a lens when its max pairwise correlation with an already-admitted lens exceeds 0.6)",
        rationale: "normalized-MI above which a lens is judged redundant with an earlier kept lens and recommended for retirement; 600 permille = 0.6 is the blueprint gate; a duplicate lens sits at 1.0 and is always caught",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_SYNERGY_RESAMPLES_KNOB,
        default: ASSAY_DEFAULT_SYNERGY_RESAMPLES,
        min: ASSAY_MIN_SYNERGY_RESAMPLES,
        max: ASSAY_MAX_SYNERGY_RESAMPLES,
        unit: "resamples",
        source: "Efron & Tibshirani, 'An Introduction to the Bootstrap' (1993): 100–1000 resamples for a two-sided percentile interval",
        rationale: "number of seeded without-replacement subsamples whose interaction-information forms the interval used to classify a triple synergistic/redundant/unclear by whether the interval straddles zero (BUILDING_ON_CALYX §4)",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_SYNERGY_MIN_EFFECT_MILLIBITS_KNOB,
        default: ASSAY_DEFAULT_SYNERGY_MIN_EFFECT_MILLIBITS,
        min: ASSAY_MIN_SYNERGY_MIN_EFFECT_MILLIBITS,
        max: ASSAY_MAX_SYNERGY_MIN_EFFECT_MILLIBITS,
        unit: "millibits",
        source: "ASTROLABE blueprint 14 §4 / capability 10.3 lens-admission floor (≥ 0.05 bits), reused as the interaction-information effect floor; plug-in interaction information is finite-sample biased away from zero (Cover & Thomas §8), so a tiny confident interval must not be called synergistic",
        rationale: "minimum absolute interaction information whose interval must clear (below −effect for synergy, above +effect for redundancy) before a triple is classified; below it the triple is Unclear, so finite-sample plug-in bias on truly independent variables does not masquerade as synergy; zero is illegal because it would classify bias as signal",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_TE_MIN_LAG_KNOB,
        default: ASSAY_DEFAULT_TE_MIN_LAG,
        min: ASSAY_MIN_TE_MIN_LAG,
        max: ASSAY_MAX_TE_MIN_LAG,
        unit: "steps",
        source: "ASTROLABE blueprint 08_ASSAY §6 (transfer-entropy dyadic lag sweep {1,2,4,8})",
        rationale: "smallest lag in the dyadic transfer-entropy sweep; the sweep is the powers of two in [min_lag, max_lag], giving the blueprint's {1,2,4,8} at the defaults",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_TE_MAX_LAG_KNOB,
        default: ASSAY_DEFAULT_TE_MAX_LAG,
        min: ASSAY_MIN_TE_MAX_LAG,
        max: ASSAY_MAX_TE_MAX_LAG,
        unit: "steps",
        source: "ASTROLABE blueprint 08_ASSAY §6 (transfer-entropy dyadic lag sweep {1,2,4,8})",
        rationale: "largest lag in the dyadic transfer-entropy sweep; the sweep is the powers of two in [min_lag, max_lag], giving the blueprint's {1,2,4,8} at the defaults",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_TE_PERMUTATIONS_KNOB,
        default: ASSAY_DEFAULT_TE_PERMUTATIONS,
        min: ASSAY_MIN_TE_PERMUTATIONS,
        max: ASSAY_MAX_TE_PERMUTATIONS,
        unit: "permutations",
        source: "permutation-test significance for information-theoretic statistics (Good, 'Permutation, Parametric, and Bootstrap Tests of Hypotheses' 3rd ed.)",
        rationale: "number of seeded source-shuffle permutations that build the transfer-entropy null; the observed TE must exceed the significance quantile of this null to emit a DRIVES edge; more permutations sharpen the p-value at linear cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_PERIODICITY_PERMUTATIONS_KNOB,
        default: ASSAY_DEFAULT_PERIODICITY_PERMUTATIONS,
        min: ASSAY_MIN_PERIODICITY_PERMUTATIONS,
        max: ASSAY_MAX_PERIODICITY_PERMUTATIONS,
        unit: "permutations",
        source: "permutation false-alarm probability for the Lomb–Scargle periodogram (VanderPlas, 'Understanding the Lomb–Scargle Periodogram', ApJS 2018, §7.4)",
        rationale: "number of seeded value-shuffle permutations that build the peak-power null used for the periodogram false-alarm probability; more permutations sharpen a small FAP at linear cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_PERIODICITY_OVERSAMPLE_KNOB,
        default: ASSAY_DEFAULT_PERIODICITY_OVERSAMPLE,
        min: ASSAY_MIN_PERIODICITY_OVERSAMPLE,
        max: ASSAY_MAX_PERIODICITY_OVERSAMPLE,
        unit: "factor",
        source: "Press, Teukolsky, Vetterling & Flannery, 'Numerical Recipes' 3rd ed. §13.8 (Lomb–Scargle frequency oversampling factor 4)",
        rationale: "how finely the Lomb–Scargle frequency grid is sampled relative to the natural 1/T spacing; 4× is the standard oversampling that resolves the peak period without aliasing; higher densifies the grid at linear cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_FAP_THRESHOLD_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_FAP_THRESHOLD_PERMILLE,
        min: ASSAY_MIN_FAP_THRESHOLD_PERMILLE,
        max: ASSAY_MAX_FAP_THRESHOLD_PERMILLE,
        unit: "permille",
        source: "conventional 0.05 false-alarm probability for periodicity detection (VanderPlas 2018, §7)",
        rationale: "false-alarm probability below which a periodogram peak is reported as a real detected period; 50 permille = 0.05 is the reporting convention; a white-noise series sits well above it and is not flagged",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_CUSUM_MIN_SEGMENT_KNOB,
        default: ASSAY_DEFAULT_CUSUM_MIN_SEGMENT,
        min: ASSAY_MIN_CUSUM_MIN_SEGMENT,
        max: ASSAY_MAX_CUSUM_MIN_SEGMENT,
        unit: "samples",
        source: "minimum-segment guard for change-point estimators (Truong, Oudre & Vayatis, 'Selective review of offline change point detection', Signal Processing 2020, §3.3)",
        rationale: "minimum number of samples that must precede a reported change point so a change in the first few noisy samples is not over-claimed; a stream shorter than twice this carries no admissible change point",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_CUSUM_PERMUTATIONS_KNOB,
        default: ASSAY_DEFAULT_CUSUM_PERMUTATIONS,
        min: ASSAY_MIN_CUSUM_PERMUTATIONS,
        max: ASSAY_MAX_CUSUM_PERMUTATIONS,
        unit: "permutations",
        source: "Taylor, 'Change-Point Analysis: A Powerful New Tool for Detecting Changes' (2000): bootstrap the CUSUM range under label exchangeability to get a change confidence",
        rationale: "number of seeded value-shuffle bootstraps that build the null for the CUSUM range (max−min of the cumulative sum of deviations); the observed range must exceed the significance quantile of this null to declare a change point; more bootstraps sharpen the confidence at linear cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_MMD_PERMUTATIONS_KNOB,
        default: ASSAY_DEFAULT_MMD_PERMUTATIONS,
        min: ASSAY_MIN_MMD_PERMUTATIONS,
        max: ASSAY_MAX_MMD_PERMUTATIONS,
        unit: "permutations",
        source: "Gretton et al., 'A Kernel Two-Sample Test', JMLR 13 (2012), §5 (permutation null for the MMD statistic)",
        rationale: "number of seeded label-shuffle permutations that build the MMD null used for the drift p-value; the observed MMD must exceed the significance quantile of this null to raise a drift alarm; more permutations sharpen the p-value at linear cost",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_SIGNIFICANCE_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_SIGNIFICANCE_PERMILLE,
        min: ASSAY_MIN_SIGNIFICANCE_PERMILLE,
        max: ASSAY_MAX_SIGNIFICANCE_PERMILLE,
        unit: "permille",
        source: "conventional 0.05 permutation-test significance level (Good, 'Permutation, Parametric, and Bootstrap Tests of Hypotheses' 3rd ed.)",
        rationale: "fraction of the permutation null the observed statistic must exceed to be called significant, shared by the transfer-entropy DRIVES gate and the MMD drift alarm; 950 permille = require p ≤ 0.05; a null (independent series, identical distributions) sits below it and raises no edge/alarm",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_DIFF_KNOB_REGISTRY_VERSION,
        name: ASSAY_TE_QUORUM_KNOB,
        default: ASSAY_DEFAULT_TE_QUORUM,
        min: ASSAY_MIN_TE_QUORUM,
        max: ASSAY_MAX_TE_QUORUM,
        unit: "samples",
        source: "ASTROLABE blueprint 08_ASSAY §6 and the performance table (transfer entropy: only top lead/lag pairs, quorum 50)",
        rationale: "minimum effective (post-lag) sample count below which a transfer-entropy causality card is reported provisional; the lagged joint history table is badly under-sampled below it",
    },
];

/// Returns the differentiation declaration for `name`, or `None` when undeclared.
pub fn assay_diff_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ASSAY_DIFF_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for the card-shaping knobs (calibration, redundancy,
/// synergy, causality) that back the `measure_bits` tool's non-signal modes (#34).
pub const ASSAY_CARD_KNOB_REGISTRY_VERSION: &str = "astrolabe-assay-card-knobs-v1";

/// Name of the minimum ground-truth-sample knob below which an edge strategy's
/// prior confidence is retained as a fallback instead of being measured.
pub const ASSAY_CALIBRATION_MIN_SAMPLES_KNOB: &str = "assay_calibration_min_samples";
/// Name of the per-slot redundancy quorum knob (min samples per slot before its
/// entropy contributes to the total-correlation / effective-rank card).
pub const ASSAY_REDUNDANCY_QUORUM_KNOB: &str = "assay_redundancy_quorum";
/// Name of the synergy quorum knob (min aligned samples before a three-way
/// interaction-information triple is measured).
pub const ASSAY_SYNERGY_QUORUM_KNOB: &str = "assay_synergy_quorum";
/// Name of the causality minimum-series-length knob (min aligned time-series
/// steps before a transfer-entropy edge is measured).
pub const ASSAY_CAUSALITY_MIN_SERIES_KNOB: &str = "assay_causality_min_series";
/// Name of the causality maximum-lag knob (largest lag in the power-of-two lag
/// sweep the transfer-entropy card evaluates).
pub const ASSAY_CAUSALITY_MAX_LAG_KNOB: &str = "assay_causality_max_lag";

/// Default minimum ground-truth samples to measure an edge strategy's precision.
///
/// Below this the per-strategy precision `x/n` is too noisy to replace the CBM
/// prior, so the prior is retained as a labeled fallback. 30 is the classic
/// large-sample rule of thumb (the CLT normal approximation is usually adequate
/// by n≈30); Brown, Cai & DasGupta (2001) recommend the Wilson interval used
/// here for all n, but a strategy's *measured* precision only supersedes its
/// prior once the sample is at least this large.
pub const ASSAY_DEFAULT_CALIBRATION_MIN_SAMPLES: u64 = 30;
/// Smallest legal calibration min-samples: at least two trials define a proportion.
pub const ASSAY_MIN_CALIBRATION_MIN_SAMPLES: u64 = 2;
/// Largest legal calibration min-samples. An upper bound keeps the measured
/// regime reachable on a real per-repo ground-truth set.
pub const ASSAY_MAX_CALIBRATION_MIN_SAMPLES: u64 = 1_000_000;

/// Default per-slot redundancy quorum (blueprint 08 §3: "quorum 50/slot").
pub const ASSAY_DEFAULT_REDUNDANCY_QUORUM: u64 = 50;
/// Smallest legal redundancy quorum: at least two samples estimate any entropy.
pub const ASSAY_MIN_REDUNDANCY_QUORUM: u64 = 2;
/// Largest legal redundancy quorum. An upper bound keeps the gate reachable.
pub const ASSAY_MAX_REDUNDANCY_QUORUM: u64 = 1_000_000;

/// Default synergy quorum (blueprint 08 §4: "Quorum 150").
pub const ASSAY_DEFAULT_SYNERGY_QUORUM: u64 = 150;
/// Smallest legal synergy quorum: a three-way table needs several samples.
pub const ASSAY_MIN_SYNERGY_QUORUM: u64 = 3;
/// Largest legal synergy quorum. An upper bound keeps the gate reachable.
pub const ASSAY_MAX_SYNERGY_QUORUM: u64 = 1_000_000;

/// Default minimum series length for a transfer-entropy edge. A transfer-entropy
/// estimate conditions on the target's own past, so it needs enough lagged
/// (future, target-past, driver-past) triples to fill the conditional table; 50
/// mirrors the per-slot MI quorum so a causality edge is held to the same
/// evidence floor as a redundancy slot.
pub const ASSAY_DEFAULT_CAUSALITY_MIN_SERIES: u64 = 50;
/// Smallest legal causality series length: at least one lagged triple past the
/// largest lag plus a couple of observations.
pub const ASSAY_MIN_CAUSALITY_MIN_SERIES: u64 = 4;
/// Largest legal causality series length. An upper bound keeps the gate reachable.
pub const ASSAY_MAX_CAUSALITY_MIN_SERIES: u64 = 1_000_000;

/// Default maximum transfer-entropy lag (blueprint 08 §6 lag sweep {1,2,4,8}).
pub const ASSAY_DEFAULT_CAUSALITY_MAX_LAG: u64 = 8;
/// Smallest legal maximum lag: a one-step lag is the tightest causal window.
pub const ASSAY_MIN_CAUSALITY_MAX_LAG: u64 = 1;
/// Largest legal maximum lag. An upper bound keeps the lagged table populated at
/// realistic series lengths.
pub const ASSAY_MAX_CAUSALITY_MAX_LAG: u64 = 1_024;

/// The card-shaping knob registry (#34).
pub const ASSAY_CARD_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ASSAY_CARD_KNOB_REGISTRY_VERSION,
        name: ASSAY_CALIBRATION_MIN_SAMPLES_KNOB,
        default: ASSAY_DEFAULT_CALIBRATION_MIN_SAMPLES,
        min: ASSAY_MIN_CALIBRATION_MIN_SAMPLES,
        max: ASSAY_MAX_CALIBRATION_MIN_SAMPLES,
        unit: "samples",
        source: "Brown, Cai & DasGupta, 'Interval Estimation for a Binomial Proportion', Statistical Science 16(2) (2001) (Wilson interval for all n) and the classic n≈30 CLT large-sample rule of thumb",
        rationale: "minimum LSP/trace-confirmed ground-truth observations before an edge strategy's measured precision x/n supersedes its CBM prior confidence; below it the prior is retained as a labeled fallback rather than replaced by a noisy point; zero/one is illegal because a proportion needs at least two trials",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_CARD_KNOB_REGISTRY_VERSION,
        name: ASSAY_REDUNDANCY_QUORUM_KNOB,
        default: ASSAY_DEFAULT_REDUNDANCY_QUORUM,
        min: ASSAY_MIN_REDUNDANCY_QUORUM,
        max: ASSAY_MAX_REDUNDANCY_QUORUM,
        unit: "samples",
        source: "ASTROLABE blueprint 08_ASSAY §3 (total correlation / effective rank, 'quorum 50/slot')",
        rationale: "minimum aligned samples a slot must carry before its marginal entropy contributes to the total-correlation and effective-rank (n_eff) card; below it the slot is reported as below-quorum rather than folded into a noisy redundancy estimate",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_CARD_KNOB_REGISTRY_VERSION,
        name: ASSAY_SYNERGY_QUORUM_KNOB,
        default: ASSAY_DEFAULT_SYNERGY_QUORUM,
        min: ASSAY_MIN_SYNERGY_QUORUM,
        max: ASSAY_MAX_SYNERGY_QUORUM,
        unit: "samples",
        source: "ASTROLABE blueprint 08_ASSAY §4 (interaction information over designed triples, 'Quorum 150')",
        rationale: "minimum aligned samples a designed triple must carry before its three-way interaction information is measured; a three-way contingency table thins fast, so below quorum the triple is reported below-quorum rather than measured on a sparse table",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_CARD_KNOB_REGISTRY_VERSION,
        name: ASSAY_CAUSALITY_MIN_SERIES_KNOB,
        default: ASSAY_DEFAULT_CAUSALITY_MIN_SERIES,
        min: ASSAY_MIN_CAUSALITY_MIN_SERIES,
        max: ASSAY_MAX_CAUSALITY_MIN_SERIES,
        unit: "steps",
        source: "ASTROLABE blueprint 08_ASSAY §6 (transfer entropy over change/failure series) and the §3 per-slot MI quorum (50)",
        rationale: "minimum aligned time-series steps before a transfer-entropy edge is measured; TE conditions on the target's own past, so it needs enough lagged triples to fill the conditional table; below it the edge is reported below-quorum",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_CARD_KNOB_REGISTRY_VERSION,
        name: ASSAY_CAUSALITY_MAX_LAG_KNOB,
        default: ASSAY_DEFAULT_CAUSALITY_MAX_LAG,
        min: ASSAY_MIN_CAUSALITY_MAX_LAG,
        max: ASSAY_MAX_CAUSALITY_MAX_LAG,
        unit: "steps",
        source: "ASTROLABE blueprint 08_ASSAY §6 (transfer-entropy lag sweep {1,2,4,8})",
        rationale: "largest lag in the power-of-two lag sweep the transfer-entropy card evaluates; the reported direction is the lag with the largest TE; 8 is the blueprint's top window, larger sweeps need proportionally longer series",
    },
];

/// Returns the card-shaping declaration for `name`, or `None` when undeclared.
pub fn assay_card_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ASSAY_CARD_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for the lens capability-gate knobs (#35, P5.5).
pub const ASSAY_GATE_KNOB_REGISTRY_VERSION: &str = "astrolabe-assay-gate-knobs-v1";

/// Name of the retire-by-correlation threshold knob (permille of a correlation).
pub const ASSAY_GATE_RETIRE_CORRELATION_PERMILLE_KNOB: &str =
    "assay_gate_retire_correlation_permille";

/// Default retire-by-correlation threshold, in permille of a Pearson correlation.
///
/// The blueprint (`05_LENS_PANEL.md` capability 1.8/4.8) retires a candidate lens
/// whose maximum pairwise correlation with an already-admitted lens *exceeds*
/// 0.6: past that the two lenses carry substantially the same variance and the
/// second is redundant. 600 permille = 0.60; the comparison is strict (`>`), so a
/// lens at exactly 0.60 is not retired on that ground.
pub const ASSAY_DEFAULT_GATE_RETIRE_CORRELATION_PERMILLE: u64 = 600;
/// Smallest legal retire-correlation threshold: 1 permille (0.001). Zero is
/// illegal because a zero threshold retires every lens that carries any shared
/// variance at all, collapsing the panel.
pub const ASSAY_MIN_GATE_RETIRE_CORRELATION_PERMILLE: u64 = 1;
/// Largest legal retire-correlation threshold: 1000 permille (1.0). A Pearson
/// correlation cannot exceed 1.0 in magnitude, so a threshold at the ceiling
/// only retires a perfectly collinear duplicate.
pub const ASSAY_MAX_GATE_RETIRE_CORRELATION_PERMILLE: u64 = 1_000;

/// The lens capability-gate knob registry (#35).
pub const ASSAY_GATE_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: ASSAY_GATE_KNOB_REGISTRY_VERSION,
    name: ASSAY_GATE_RETIRE_CORRELATION_PERMILLE_KNOB,
    default: ASSAY_DEFAULT_GATE_RETIRE_CORRELATION_PERMILLE,
    min: ASSAY_MIN_GATE_RETIRE_CORRELATION_PERMILLE,
    max: ASSAY_MAX_GATE_RETIRE_CORRELATION_PERMILLE,
    unit: "permille",
    source: "ASTROLABE blueprint 05_LENS_PANEL.md §6 capability 1.8/4.8 (retire a lens whose max pairwise correlation with an admitted lens exceeds 0.6)",
    rationale: "Pearson-correlation ceiling above which a candidate lens is redundant with an already-admitted lens and is retired; 600 permille = 0.60 is the blueprint threshold; the gate compares strictly (>) so a lens at exactly the threshold is kept; replace with a per-repo measured redundancy target once the panel-wide correlation spectrum is benchmarked",
}];

/// Returns the capability-gate declaration for `name`, or `None` when undeclared.
pub fn assay_gate_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ASSAY_GATE_KNOBS.iter().find(|knob| knob.name == name)
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
    fn every_bits_knob_declares_bounds_that_contain_its_default() {
        assert!(!ASSAY_BITS_KNOBS.is_empty());
        for knob in ASSAY_BITS_KNOBS {
            assert_eq!(
                knob.registry_version, ASSAY_BITS_KNOB_REGISTRY_VERSION,
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
    fn bits_knobs_reject_zero_where_zero_disables_protection() {
        for name in [
            ASSAY_FLOOR_SAMPLE_SIZE_KNOB,
            ASSAY_SUFFICIENCY_SLACK_MILLIBITS_KNOB,
            ASSAY_DPI_CEILING_SLACK_MILLIBITS_KNOB,
            ASSAY_MIN_SLOT_SIGNAL_MILLIBITS_KNOB,
            ASSAY_KSG_NEIGHBORS_K_KNOB,
        ] {
            let knob = assay_bits_knob(name).expect("declared");
            assert!(!knob.accepts(0), "{name} must reject zero");
            assert!(knob.accepts(knob.default), "{name} accepts default");
        }
        // The Jeffreys prior default is exactly 0.5 (500 permille).
        let prior = assay_bits_knob(ASSAY_POSTERIOR_PRIOR_ALPHA_PERMILLE_KNOB).expect("declared");
        assert_eq!(prior.default, 500);
        // k defaults to the blueprint-fixed 3.
        let k = assay_bits_knob(ASSAY_KSG_NEIGHBORS_K_KNOB).expect("declared");
        assert_eq!(k.default, 3);
    }

    #[test]
    fn every_card_knob_declares_bounds_that_contain_its_default() {
        assert!(!ASSAY_CARD_KNOBS.is_empty());
        for knob in ASSAY_CARD_KNOBS {
            assert_eq!(
                knob.registry_version, ASSAY_CARD_KNOB_REGISTRY_VERSION,
                "{knob:?}"
            );
            assert!(knob.min <= knob.max, "{knob:?}");
            assert!(knob.accepts(knob.default), "{knob:?}");
            assert!(!knob.unit.is_empty(), "{knob:?}");
            assert!(!knob.source.is_empty(), "{knob:?}");
            assert!(!knob.rationale.is_empty(), "{knob:?}");
        }
        // Blueprint-fixed defaults: 50/slot redundancy, 150 synergy, lag sweep top 8.
        assert_eq!(
            assay_card_knob(ASSAY_REDUNDANCY_QUORUM_KNOB)
                .unwrap()
                .default,
            50
        );
        assert_eq!(
            assay_card_knob(ASSAY_SYNERGY_QUORUM_KNOB).unwrap().default,
            150
        );
        assert_eq!(
            assay_card_knob(ASSAY_CAUSALITY_MAX_LAG_KNOB)
                .unwrap()
                .default,
            8
        );
    }

    #[test]
    fn every_gate_knob_declares_bounds_that_contain_its_default() {
        assert!(!ASSAY_GATE_KNOBS.is_empty());
        for knob in ASSAY_GATE_KNOBS {
            assert_eq!(
                knob.registry_version, ASSAY_GATE_KNOB_REGISTRY_VERSION,
                "{knob:?}"
            );
            assert!(knob.min <= knob.max, "{knob:?}");
            assert!(knob.accepts(knob.default), "{knob:?}");
            assert!(!knob.unit.is_empty(), "{knob:?}");
            assert!(!knob.source.is_empty(), "{knob:?}");
            assert!(!knob.rationale.is_empty(), "{knob:?}");
        }
        // The retire-correlation threshold defaults to the blueprint's 0.6 (600 permille).
        let corr = assay_gate_knob(ASSAY_GATE_RETIRE_CORRELATION_PERMILLE_KNOB).expect("declared");
        assert_eq!(corr.default, 600);
        assert!(!corr.accepts(0), "correlation threshold must reject zero");
        assert!(corr.accepts(1_000), "correlation threshold accepts 1.0");
        assert!(
            !corr.accepts(1_001),
            "correlation threshold rejects over 1.0"
        );
    }

    #[test]
    fn card_knobs_reject_zero_and_one_where_meaningless() {
        for name in [
            ASSAY_CALIBRATION_MIN_SAMPLES_KNOB,
            ASSAY_REDUNDANCY_QUORUM_KNOB,
            ASSAY_SYNERGY_QUORUM_KNOB,
            ASSAY_CAUSALITY_MIN_SERIES_KNOB,
        ] {
            let knob = assay_card_knob(name).expect("declared");
            assert!(!knob.accepts(0), "{name} must reject zero");
            assert!(!knob.accepts(1), "{name} must reject one");
            assert!(knob.accepts(knob.default), "{name} accepts default");
        }
    }

    #[test]
    fn every_diff_knob_declares_bounds_that_contain_its_default() {
        assert!(!ASSAY_DIFF_KNOBS.is_empty());
        for knob in ASSAY_DIFF_KNOBS {
            assert_eq!(
                knob.registry_version, ASSAY_DIFF_KNOB_REGISTRY_VERSION,
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
    fn diff_knob_defaults_match_the_blueprint() {
        // Retire gate 0.6; the dyadic TE sweep spans {1,2,4,8}.
        assert_eq!(
            assay_diff_knob(ASSAY_REDUNDANCY_RETIRE_NMI_PERMILLE_KNOB)
                .unwrap()
                .default,
            600
        );
        assert_eq!(assay_diff_knob(ASSAY_TE_MIN_LAG_KNOB).unwrap().default, 1);
        assert_eq!(assay_diff_knob(ASSAY_TE_MAX_LAG_KNOB).unwrap().default, 8);
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
