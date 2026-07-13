//! Per-signal bits, signal-ranking cards, sufficiency + deficit cards, and DPI
//! ceiling enforcement (P5.2, blueprint 08_ASSAY §1–2, capabilities 4.1/4.3/4.13).
//!
//! This module turns aligned slot/axis observations into the tool-facing cards
//! (08 §8): a **signal-ranking card** (each slot → bits ± interval, trust, sample
//! count) and a **sufficiency card** (`I(panel;axis)` vs `H(axis)`, with the
//! deficit split across slots and routed to a suggested action). It layers three
//! disciplines over the raw estimators in [`crate::estimators`]:
//!
//! * **Interval reporting.** Above the 50-sample floor a bits estimate carries a
//!   seeded bootstrap percentile interval; below it the KSG point is not trusted
//!   and the result is reported *provisional* with a Dirichlet(Jeffreys) posterior
//!   credible interval instead of a bare point estimate.
//! * **Sufficiency & deficits.** The panel↔axis MI is compared against the axis
//!   entropy; a shortfall is split across slots inversely to their marginal bits
//!   and each share is routed to `AddOutcomeAnchor` / `ProposeLens` /
//!   `IncreaseSamples`.
//! * **DPI ceiling.** A derived-signal claim that exceeds the measured
//!   `I(panel;outcome)` violates the Data Processing Inequality and is refused
//!   fail-closed.
//!
//! Every stochastic step is seeded, so a card is a pure function of `(inputs,
//! seed, config)` and reproduces bit-for-bit regardless of worker count.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::error::{
    ASTRO_ASSAY_DPI_VIOLATION, ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result,
};
use crate::estimators::{mi_continuous_ksg, mi_discrete, mi_from_joint, mi_mixed_ross};
use crate::knobs::{
    ASSAY_BOOTSTRAP_RESAMPLES_KNOB, ASSAY_BOOTSTRAP_SUBSAMPLE_PERMILLE_KNOB,
    ASSAY_CI_CONFIDENCE_PERMILLE_KNOB, ASSAY_DEFAULT_BOOTSTRAP_RESAMPLES,
    ASSAY_DEFAULT_BOOTSTRAP_SUBSAMPLE_PERMILLE, ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE,
    ASSAY_DEFAULT_DPI_CEILING_SLACK_MILLIBITS, ASSAY_DEFAULT_FLOOR_DISCRETIZATION_BINS,
    ASSAY_DEFAULT_FLOOR_SAMPLE_SIZE, ASSAY_DEFAULT_KSG_NEIGHBORS_K,
    ASSAY_DEFAULT_MIN_SLOT_SIGNAL_MILLIBITS, ASSAY_DEFAULT_POSTERIOR_DRAWS,
    ASSAY_DEFAULT_POSTERIOR_PRIOR_ALPHA_PERMILLE, ASSAY_DEFAULT_PROJECTION_FACTOR_PERMILLE,
    ASSAY_DEFAULT_SUFFICIENCY_SLACK_MILLIBITS, ASSAY_DPI_CEILING_SLACK_MILLIBITS_KNOB,
    ASSAY_FLOOR_DISCRETIZATION_BINS_KNOB, ASSAY_FLOOR_SAMPLE_SIZE_KNOB, ASSAY_KSG_NEIGHBORS_K_KNOB,
    ASSAY_MIN_SLOT_SIGNAL_MILLIBITS_KNOB, ASSAY_POSTERIOR_DRAWS_KNOB,
    ASSAY_POSTERIOR_PRIOR_ALPHA_PERMILLE_KNOB, ASSAY_PROJECTION_FACTOR_PERMILLE_KNOB,
    ASSAY_SUFFICIENCY_SLACK_MILLIBITS_KNOB, assay_bits_knob,
};
use crate::projection::{random_projection, target_dimension};
use crate::rng::DeterministicRng;

/// The measured values of one panel slot across the aligned sample.
///
/// Row `i` of every variant corresponds to sample `i`, and to `axis` element `i`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SlotValues {
    /// A single continuous scalar per sample (e.g. complexity, churn).
    Scalar(Vec<f64>),
    /// A fixed-width continuous embedding per sample (e.g. a 768-d slot).
    Embedding {
        /// The embedding width; every row must have this length.
        dim: usize,
        /// One embedding vector per sample.
        rows: Vec<Vec<f64>>,
    },
    /// A discrete class label per sample (e.g. a symbol-kind lens).
    Label(Vec<i64>),
}

impl SlotValues {
    /// The number of samples this slot carries.
    pub fn len(&self) -> usize {
        match self {
            SlotValues::Scalar(v) => v.len(),
            SlotValues::Embedding { rows, .. } => rows.len(),
            SlotValues::Label(v) => v.len(),
        }
    }

    /// Whether the slot carries no samples.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A named panel slot and its measured values across the sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotObservations {
    /// Stable slot name (used in reports and as the deficit routing key).
    pub slot: String,
    /// The slot's measured values, aligned with the axis.
    pub values: SlotValues,
}

/// The measured outcome axis across the aligned sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AxisValues {
    /// A continuous outcome per sample (e.g. runtime, agent-utility score).
    Continuous(Vec<f64>),
    /// A discrete outcome per sample (e.g. test-pass, defect class).
    Discrete(Vec<i64>),
}

impl AxisValues {
    /// The number of samples the axis carries.
    pub fn len(&self) -> usize {
        match self {
            AxisValues::Continuous(v) => v.len(),
            AxisValues::Discrete(v) => v.len(),
        }
    }

    /// Whether the axis carries no samples.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A two-sided interval on a bits estimate, with the method that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BitsInterval {
    /// Lower endpoint, in bits.
    pub lo: f64,
    /// Upper endpoint, in bits.
    pub hi: f64,
    /// Two-sided level of the interval, in permille (950 = 95%).
    pub level_permille: u64,
    /// How the interval was produced (`bootstrap-percentile` or the posterior).
    pub method: String,
}

/// One slot's measured signal about an axis: bits, interval, trust, and count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalBits {
    /// Slot name.
    pub slot: String,
    /// Point estimate of the mutual information, in bits.
    pub bits: f64,
    /// Interval around the point estimate.
    pub interval: BitsInterval,
    /// Trust tag: `Trusted` above the sample floor, `Provisional` below it.
    pub trust: TrustTag,
    /// Number of samples the estimate was computed over.
    pub n: usize,
    /// The estimator that produced the point (e.g. `ksg-continuous-k3`).
    pub estimator: String,
    /// Whether this is a below-floor provisional posterior result.
    pub provisional: bool,
}

/// A signal-ranking card for one axis: every slot's bits, ordered by signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalRankingCard {
    /// The axis these signals were measured about.
    pub axis: String,
    /// Per-slot signals, ordered by descending bits then ascending slot name.
    pub signals: Vec<SignalBits>,
}

/// The remediation a sufficiency deficit routes to (blueprint 08 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeficitSuggestedAction {
    /// Ground more outcomes for a live but under-anchored lens.
    AddOutcomeAnchor,
    /// Propose a new lens: the existing slot carries no usable signal.
    ProposeLens,
    /// Gather more samples: the slot is below the measurement floor.
    IncreaseSamples,
}

/// One slot's contribution to an axis's sufficiency deficit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotDeficit {
    /// Slot name.
    pub slot: String,
    /// The slot's measured marginal bits about the axis.
    pub marginal_bits: f64,
    /// The share of the panel deficit attributed to this slot, in bits.
    pub deficit_bits: f64,
    /// The remediation this slot's deficit routes to.
    pub action: DeficitSuggestedAction,
}

/// One slot's summary the sufficiency card consumes (its marginal bits + count).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotSummary {
    /// Slot name.
    pub slot: String,
    /// The slot's measured marginal bits about the axis.
    pub marginal_bits: f64,
    /// Number of samples the slot was measured over.
    pub n: usize,
}

/// A sufficiency card: is `I(panel;axis) ≥ H(axis)`, and if not, the deficit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SufficiencyCard {
    /// The axis under test.
    pub axis: String,
    /// Entropy of the axis, in bits — the sufficiency target.
    pub axis_entropy_bits: f64,
    /// Measured joint mutual information of the whole panel about the axis.
    pub panel_bits: f64,
    /// Whether the panel carries enough bits (within the declared slack).
    pub sufficient: bool,
    /// Total shortfall, in bits (zero when sufficient).
    pub deficit_bits: f64,
    /// Per-slot deficit breakdown (empty when sufficient).
    pub deficits: Vec<SlotDeficit>,
    /// Trust of the card: `Provisional` if any contributing slot is below floor.
    pub trust: TrustTag,
}

/// Resolved configuration for the bits pipeline, drawn from the registry knobs.
///
/// Built from the declared defaults with [`BitsConfig::from_defaults`] and
/// validated against the knob bounds, so no field is a bare constant. Bits-valued
/// fields are stored as `f64` bits (converted from the millibits/permille knobs).
#[derive(Debug, Clone, PartialEq)]
pub struct BitsConfig {
    /// KSG/Ross neighbour count.
    pub k: usize,
    /// Sample floor below which results go provisional.
    pub floor: usize,
    /// Number of without-replacement subsamples for the above-floor interval.
    pub bootstrap_resamples: usize,
    /// Subsample size, in permille of n, for each interval draw.
    pub bootstrap_subsample_permille: u64,
    /// Two-sided interval level, in permille.
    pub ci_confidence_permille: u64,
    /// Posterior draw count for the below-floor credible interval.
    pub posterior_draws: usize,
    /// Dirichlet per-cell prior concentration (Jeffreys 0.5 by default).
    pub posterior_prior_alpha: f64,
    /// Equal-frequency bin count for below-floor discretization.
    pub floor_bins: usize,
    /// Random-projection dimension factor, in permille of log2(n).
    pub projection_factor_permille: u64,
    /// Sufficiency slack, in bits.
    pub sufficiency_slack_bits: f64,
    /// DPI ceiling slack, in bits.
    pub dpi_slack_bits: f64,
    /// Minimum per-slot signal, in bits, below which a lens is treated as dead.
    pub min_slot_signal_bits: f64,
}

impl BitsConfig {
    /// Builds the config from the registry knob defaults.
    ///
    /// This reads each declared default and asserts (via the knob's own
    /// `accepts`) that it is inside its bounds, so a mis-declared default fails
    /// closed at construction rather than silently mis-measuring.
    pub fn from_defaults() -> Result<Self> {
        fn checked(name: &str, value: u64) -> Result<u64> {
            let knob = assay_bits_knob(name).ok_or_else(|| {
                AssayError::new(
                    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                    format!("bits knob {name} is not declared"),
                    "declare the knob in ASSAY_BITS_KNOBS before using it",
                )
            })?;
            if !knob.accepts(value) {
                return Err(AssayError::new(
                    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                    format!("bits knob {name} default {value} is outside its declared bounds"),
                    "correct the knob default so it lies within [min, max]",
                ));
            }
            Ok(value)
        }
        Ok(Self {
            k: checked(ASSAY_KSG_NEIGHBORS_K_KNOB, ASSAY_DEFAULT_KSG_NEIGHBORS_K)? as usize,
            floor: checked(
                ASSAY_FLOOR_SAMPLE_SIZE_KNOB,
                ASSAY_DEFAULT_FLOOR_SAMPLE_SIZE,
            )? as usize,
            bootstrap_resamples: checked(
                ASSAY_BOOTSTRAP_RESAMPLES_KNOB,
                ASSAY_DEFAULT_BOOTSTRAP_RESAMPLES,
            )? as usize,
            bootstrap_subsample_permille: checked(
                ASSAY_BOOTSTRAP_SUBSAMPLE_PERMILLE_KNOB,
                ASSAY_DEFAULT_BOOTSTRAP_SUBSAMPLE_PERMILLE,
            )?,
            ci_confidence_permille: checked(
                ASSAY_CI_CONFIDENCE_PERMILLE_KNOB,
                ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE,
            )?,
            posterior_draws: checked(ASSAY_POSTERIOR_DRAWS_KNOB, ASSAY_DEFAULT_POSTERIOR_DRAWS)?
                as usize,
            posterior_prior_alpha: checked(
                ASSAY_POSTERIOR_PRIOR_ALPHA_PERMILLE_KNOB,
                ASSAY_DEFAULT_POSTERIOR_PRIOR_ALPHA_PERMILLE,
            )? as f64
                / 1000.0,
            floor_bins: checked(
                ASSAY_FLOOR_DISCRETIZATION_BINS_KNOB,
                ASSAY_DEFAULT_FLOOR_DISCRETIZATION_BINS,
            )? as usize,
            projection_factor_permille: checked(
                ASSAY_PROJECTION_FACTOR_PERMILLE_KNOB,
                ASSAY_DEFAULT_PROJECTION_FACTOR_PERMILLE,
            )?,
            sufficiency_slack_bits: checked(
                ASSAY_SUFFICIENCY_SLACK_MILLIBITS_KNOB,
                ASSAY_DEFAULT_SUFFICIENCY_SLACK_MILLIBITS,
            )? as f64
                / 1000.0,
            dpi_slack_bits: checked(
                ASSAY_DPI_CEILING_SLACK_MILLIBITS_KNOB,
                ASSAY_DEFAULT_DPI_CEILING_SLACK_MILLIBITS,
            )? as f64
                / 1000.0,
            min_slot_signal_bits: checked(
                ASSAY_MIN_SLOT_SIGNAL_MILLIBITS_KNOB,
                ASSAY_DEFAULT_MIN_SLOT_SIGNAL_MILLIBITS,
            )? as f64
                / 1000.0,
        })
    }
}

/// A route-normalized (post-projection) pair ready for estimation and resampling.
#[derive(Debug, Clone)]
enum Prepared {
    /// Continuous↔continuous (KSG algorithm 1).
    ContCont { x: Vec<Vec<f64>>, y: Vec<Vec<f64>> },
    /// Continuous↔discrete (Ross mixed estimator).
    Mixed { cont: Vec<Vec<f64>>, disc: Vec<i64> },
    /// Discrete↔discrete (plug-in).
    DiscDisc { a: Vec<i64>, b: Vec<i64> },
}

impl Prepared {
    fn n(&self) -> usize {
        match self {
            Prepared::ContCont { x, .. } => x.len(),
            Prepared::Mixed { cont, .. } => cont.len(),
            Prepared::DiscDisc { a, .. } => a.len(),
        }
    }

    fn point_bits(&self, k: usize) -> f64 {
        match self {
            Prepared::ContCont { x, y } => mi_continuous_ksg(x, y, k),
            Prepared::Mixed { cont, disc } => mi_mixed_ross(cont, disc, k),
            Prepared::DiscDisc { a, b } => mi_discrete(a, b),
        }
    }

    fn resample(&self, indices: &[usize]) -> Prepared {
        match self {
            Prepared::ContCont { x, y } => Prepared::ContCont {
                x: indices.iter().map(|&i| x[i].clone()).collect(),
                y: indices.iter().map(|&i| y[i].clone()).collect(),
            },
            Prepared::Mixed { cont, disc } => Prepared::Mixed {
                cont: indices.iter().map(|&i| cont[i].clone()).collect(),
                disc: indices.iter().map(|&i| disc[i]).collect(),
            },
            Prepared::DiscDisc { a, b } => Prepared::DiscDisc {
                a: indices.iter().map(|&i| a[i]).collect(),
                b: indices.iter().map(|&i| b[i]).collect(),
            },
        }
    }
}

fn validate_finite_scalars(values: &[f64], what: &str) -> Result<()> {
    if values.iter().any(|v| !v.is_finite()) {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("{what} carries a non-finite value"),
            "supply only finite measured values to the bits estimator",
        ));
    }
    Ok(())
}

/// Prepares a slot/axis pair for measurement, projecting embedding slots first.
fn prepare(
    slot: &SlotObservations,
    axis: &AxisValues,
    seed: u64,
    cfg: &BitsConfig,
) -> Result<(Prepared, String)> {
    let n = slot.values.len();
    if n == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("slot {} carries no samples", slot.slot),
            "measure a non-empty sample before requesting bits",
        ));
    }
    if axis.len() != n {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!(
                "slot {} has {n} samples but the axis has {}",
                slot.slot,
                axis.len()
            ),
            "align the slot and axis to the same sample set before measuring",
        ));
    }
    // Validate axis contents and require variation: MI against a constant axis is
    // trivially zero and signals a mis-specified measurement, not a real signal.
    match axis {
        AxisValues::Continuous(v) => {
            validate_finite_scalars(v, "axis")?;
            let first = v[0];
            if v.iter().all(|&x| x == first) {
                return Err(AssayError::new(
                    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                    "continuous axis has no variation (constant)",
                    "measure against an axis that varies across the sample",
                ));
            }
        }
        AxisValues::Discrete(v) => {
            let first = v[0];
            if v.iter().all(|&x| x == first) {
                return Err(AssayError::new(
                    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                    "discrete axis has no variation (single class)",
                    "measure against an axis with at least two classes",
                ));
            }
        }
    }

    let ksg_name = format!("ksg-continuous-k{}", cfg.k);
    let ross_name = format!("ross-mixed-k{}", cfg.k);
    let prepared = match (&slot.values, axis) {
        (SlotValues::Scalar(s), AxisValues::Continuous(a)) => {
            validate_finite_scalars(s, "scalar slot")?;
            (
                Prepared::ContCont {
                    x: s.iter().map(|&v| vec![v]).collect(),
                    y: a.iter().map(|&v| vec![v]).collect(),
                },
                ksg_name,
            )
        }
        (SlotValues::Scalar(s), AxisValues::Discrete(a)) => {
            validate_finite_scalars(s, "scalar slot")?;
            (
                Prepared::Mixed {
                    cont: s.iter().map(|&v| vec![v]).collect(),
                    disc: a.clone(),
                },
                ross_name,
            )
        }
        (SlotValues::Embedding { dim, rows }, axis_v) => {
            for row in rows {
                if row.len() != *dim {
                    return Err(AssayError::new(
                        ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                        format!(
                            "embedding slot {} has a row of width {} but dim is {dim}",
                            slot.slot,
                            row.len()
                        ),
                        "give every embedding row the declared dim width",
                    ));
                }
                validate_finite_scalars(row, "embedding slot")?;
            }
            let target = target_dimension(n, *dim, cfg.projection_factor_permille);
            let projected = random_projection(rows, *dim, target, seed);
            match axis_v {
                AxisValues::Continuous(a) => (
                    Prepared::ContCont {
                        x: projected,
                        y: a.iter().map(|&v| vec![v]).collect(),
                    },
                    format!("{ksg_name}+rp{target}"),
                ),
                AxisValues::Discrete(a) => (
                    Prepared::Mixed {
                        cont: projected,
                        disc: a.clone(),
                    },
                    format!("{ross_name}+rp{target}"),
                ),
            }
        }
        (SlotValues::Label(s), AxisValues::Continuous(a)) => {
            // One-hot continuous↔discrete route with the label as the discrete side.
            (
                Prepared::Mixed {
                    cont: a.iter().map(|&v| vec![v]).collect(),
                    disc: s.clone(),
                },
                ross_name,
            )
        }
        (SlotValues::Label(s), AxisValues::Discrete(a)) => (
            Prepared::DiscDisc {
                a: s.clone(),
                b: a.clone(),
            },
            "discrete-plugin".to_string(),
        ),
    };
    Ok(prepared)
}

/// Linear-interpolated quantile of an already-sorted, finite slice.
fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let pos = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

/// Seeded subsample percentile interval over without-replacement subsamples of
/// `prepared`.
///
/// The classic with-replacement bootstrap cannot be used here: it produces
/// duplicate (zero-distance) points, and a k-nearest-neighbour MI estimator reads
/// those ties as infinite local density and reports a wildly inflated estimate.
/// Subsampling *without* replacement keeps every drawn point distinct, so each
/// subsample is a clean input to the estimator. Each draw is a partial
/// Fisher–Yates shuffle of a shared index array, so the interval is a pure
/// function of the seed.
fn bootstrap_interval(prepared: &Prepared, seed: u64, cfg: &BitsConfig) -> BitsInterval {
    let n = prepared.n();
    // m = subsample size, kept in [k+2, n-1] so the estimator has enough distinct
    // points and every draw can still differ from the full sample.
    let raw = (cfg.bootstrap_subsample_permille as u128 * n as u128 / 1000) as usize;
    let m = raw.clamp((cfg.k + 2).min(n), n.saturating_sub(1).max(1));
    let mut rng = DeterministicRng::from_u64_labeled(seed, "subsample");
    let mut indices: Vec<usize> = (0..n).collect();
    let mut stats = Vec::with_capacity(cfg.bootstrap_resamples);
    for _ in 0..cfg.bootstrap_resamples {
        // Partial Fisher–Yates: randomize the first m positions of a permutation.
        for i in 0..m {
            let j = i + (rng.next_u64() % (n - i) as u64) as usize;
            indices.swap(i, j);
        }
        stats.push(prepared.resample(&indices[..m]).point_bits(cfg.k));
    }
    stats.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let alpha = 1.0 - cfg.ci_confidence_permille as f64 / 1000.0;
    BitsInterval {
        lo: quantile_sorted(&stats, alpha / 2.0),
        hi: quantile_sorted(&stats, 1.0 - alpha / 2.0),
        level_permille: cfg.ci_confidence_permille,
        method: "subsample-percentile".to_string(),
    }
}

/// Equal-frequency (quantile) bin indices for a continuous vector.
fn quantile_bins(values: &[f64], bins: usize) -> Vec<i64> {
    let n = values.len();
    let mut idx: Vec<usize> = (0..n).collect();
    // Stable sort keeps ties in input order, so binning is deterministic.
    idx.sort_by(|&a, &b| values[a].partial_cmp(&values[b]).unwrap());
    let mut out = vec![0i64; n];
    for (rank, &i) in idx.iter().enumerate() {
        let bin = (rank * bins) / n;
        out[i] = bin.min(bins - 1) as i64;
    }
    out
}

/// Maps arbitrary integer labels to compact `0..classes` indices, returning the
/// remapped vector and the class count.
fn compact_labels(labels: &[i64]) -> (Vec<i64>, usize) {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<i64, i64> = BTreeMap::new();
    let mut next = 0i64;
    let mut out = Vec::with_capacity(labels.len());
    for &l in labels {
        let id = *map.entry(l).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        out.push(id);
    }
    (out, next as usize)
}

/// Below-floor posterior interval: discretize each side, then draw a Dirichlet
/// posterior over the contingency table and summarize its per-draw plug-in MI.
fn posterior_interval(prepared: &Prepared, seed: u64, cfg: &BitsConfig) -> (f64, BitsInterval) {
    // Reduce every route to two categorical vectors (a: rows, b: cols).
    let (a, rows, b, cols) = match prepared {
        Prepared::ContCont { x, y } => {
            let xs: Vec<f64> = x.iter().map(|v| v[0]).collect();
            let ys: Vec<f64> = y.iter().map(|v| v[0]).collect();
            let ba = quantile_bins(&xs, cfg.floor_bins);
            let bb = quantile_bins(&ys, cfg.floor_bins);
            (ba, cfg.floor_bins, bb, cfg.floor_bins)
        }
        Prepared::Mixed { cont, disc } => {
            let xs: Vec<f64> = cont.iter().map(|v| v[0]).collect();
            let ba = quantile_bins(&xs, cfg.floor_bins);
            let (bb, cols) = compact_labels(disc);
            (ba, cfg.floor_bins, bb, cols)
        }
        Prepared::DiscDisc { a, b } => {
            let (ca, rows) = compact_labels(a);
            let (cb, cols) = compact_labels(b);
            (ca, rows, cb, cols)
        }
    };
    let rows = rows.max(1);
    let cols = cols.max(1);
    let mut counts = vec![0.0_f64; rows * cols];
    for (&r, &c) in a.iter().zip(b.iter()) {
        counts[r as usize * cols + c as usize] += 1.0;
    }
    let conc: Vec<f64> = counts
        .iter()
        .map(|c| c + cfg.posterior_prior_alpha)
        .collect();
    let mut rng = DeterministicRng::from_u64_labeled(seed, "posterior");
    let mut draws = Vec::with_capacity(cfg.posterior_draws);
    for _ in 0..cfg.posterior_draws {
        let p = rng.next_dirichlet(&conc);
        draws.push(mi_from_joint(&p, rows, cols));
    }
    draws.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let alpha = 1.0 - cfg.ci_confidence_permille as f64 / 1000.0;
    let point = quantile_sorted(&draws, 0.5);
    let interval = BitsInterval {
        lo: quantile_sorted(&draws, alpha / 2.0),
        hi: quantile_sorted(&draws, 1.0 - alpha / 2.0),
        level_permille: cfg.ci_confidence_permille,
        method: "dirichlet-jeffreys-posterior".to_string(),
    };
    (point, interval)
}

/// Measures one slot's bits about an axis, choosing the above/below-floor path.
///
/// Above the floor: the KSG/Ross/plug-in point estimate with a seeded bootstrap
/// percentile interval, tagged `Trusted`. Below the floor: the Dirichlet(Jeffreys)
/// posterior median with a credible interval, tagged `Provisional` — the point is
/// never reported bare of its interval.
pub fn measure_slot_bits(
    slot: &SlotObservations,
    axis: &AxisValues,
    seed: u64,
    cfg: &BitsConfig,
) -> Result<SignalBits> {
    let (prepared, base_estimator) = prepare(slot, axis, seed, cfg)?;
    let n = prepared.n();
    if n < cfg.floor {
        let (point, interval) = posterior_interval(&prepared, seed, cfg);
        return Ok(SignalBits {
            slot: slot.slot.clone(),
            bits: point,
            interval,
            trust: TrustTag::Provisional,
            n,
            estimator: "dirichlet-jeffreys-posterior".to_string(),
            provisional: true,
        });
    }
    let point = prepared.point_bits(cfg.k);
    let interval = bootstrap_interval(&prepared, seed, cfg);
    Ok(SignalBits {
        slot: slot.slot.clone(),
        bits: point,
        interval,
        trust: TrustTag::Trusted,
        n,
        estimator: base_estimator,
        provisional: false,
    })
}

/// Builds a signal-ranking card by measuring every slot and ordering by bits.
///
/// Slots are measured independently and then sorted by descending bits with the
/// slot name as a deterministic tie-break, so the ordering is a pure function of
/// the measured values.
pub fn build_signal_ranking(
    axis_name: impl Into<String>,
    slots: &[SlotObservations],
    axis: &AxisValues,
    seed: u64,
    cfg: &BitsConfig,
) -> Result<SignalRankingCard> {
    let mut signals = Vec::with_capacity(slots.len());
    for slot in slots {
        signals.push(measure_slot_bits(slot, axis, seed, cfg)?);
    }
    signals.sort_by(|a, b| {
        b.bits
            .partial_cmp(&a.bits)
            .unwrap()
            .then_with(|| a.slot.cmp(&b.slot))
    });
    Ok(SignalRankingCard {
        axis: axis_name.into(),
        signals,
    })
}

/// Builds a sufficiency card from a measured panel MI and per-slot summaries.
///
/// The panel is sufficient when `panel_bits + slack ≥ H(axis)`. Otherwise the
/// shortfall `H(axis) − panel_bits` is split across slots *inversely* to their
/// marginal bits (the weakest lenses carry the largest share), regularized by the
/// minimum-signal knob so a zero-bit slot does not take an unbounded share, and
/// each slot's share is routed:
///
/// * below the sample floor → `IncreaseSamples`;
/// * else below the minimum-signal threshold → `ProposeLens` (the lens is dead);
/// * else → `AddOutcomeAnchor` (a live lens that needs more grounding).
pub fn build_sufficiency_card(
    axis_name: impl Into<String>,
    axis_entropy_bits: f64,
    panel_bits: f64,
    slots: &[SlotSummary],
    cfg: &BitsConfig,
) -> Result<SufficiencyCard> {
    if !axis_entropy_bits.is_finite() || axis_entropy_bits < 0.0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("axis entropy {axis_entropy_bits} is not a finite non-negative bit value"),
            "supply a finite non-negative H(axis) from the entropy estimator",
        ));
    }
    if !panel_bits.is_finite() || panel_bits < 0.0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("panel bits {panel_bits} is not a finite non-negative bit value"),
            "supply a finite non-negative I(panel;axis) from the KSG estimator",
        ));
    }
    for s in slots {
        if !s.marginal_bits.is_finite() || s.marginal_bits < 0.0 {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "slot {} marginal bits {} is not finite non-negative",
                    s.slot, s.marginal_bits
                ),
                "supply finite non-negative marginal bits per slot",
            ));
        }
    }

    let axis_name = axis_name.into();
    let any_provisional = slots.iter().any(|s| s.n < cfg.floor);
    let trust = if any_provisional {
        TrustTag::Provisional
    } else {
        TrustTag::Trusted
    };

    let sufficient = panel_bits + cfg.sufficiency_slack_bits >= axis_entropy_bits;
    if sufficient || slots.is_empty() {
        return Ok(SufficiencyCard {
            axis: axis_name,
            axis_entropy_bits,
            panel_bits,
            sufficient,
            deficit_bits: 0.0,
            deficits: Vec::new(),
            trust,
        });
    }

    let total_deficit = axis_entropy_bits - panel_bits;
    // Inverse-marginal weights, regularized by the minimum-signal knob so a dead
    // slot's weight is bounded rather than infinite.
    let reg = cfg.min_slot_signal_bits;
    let weights: Vec<f64> = slots
        .iter()
        .map(|s| 1.0 / (s.marginal_bits + reg))
        .collect();
    let weight_sum: f64 = weights.iter().sum();

    let mut deficits = Vec::with_capacity(slots.len());
    for (s, w) in slots.iter().zip(weights.iter()) {
        let share = if weight_sum > 0.0 {
            total_deficit * (w / weight_sum)
        } else {
            total_deficit / slots.len() as f64
        };
        let action = if s.n < cfg.floor {
            DeficitSuggestedAction::IncreaseSamples
        } else if s.marginal_bits < cfg.min_slot_signal_bits {
            DeficitSuggestedAction::ProposeLens
        } else {
            DeficitSuggestedAction::AddOutcomeAnchor
        };
        deficits.push(SlotDeficit {
            slot: s.slot.clone(),
            marginal_bits: s.marginal_bits,
            deficit_bits: share,
            action,
        });
    }
    // Order the deficit breakdown by descending share so the operator sees the
    // largest gap first; tie-break by slot name for determinism.
    deficits.sort_by(|a, b| {
        b.deficit_bits
            .partial_cmp(&a.deficit_bits)
            .unwrap()
            .then_with(|| a.slot.cmp(&b.slot))
    });

    Ok(SufficiencyCard {
        axis: axis_name,
        axis_entropy_bits,
        panel_bits,
        sufficient: false,
        deficit_bits: total_deficit,
        deficits,
        trust,
    })
}

/// Enforces the Data Processing Inequality ceiling (capability 4.13).
///
/// A derived signal is a function of the panel, so by the DPI it can carry no
/// more information about the outcome than the panel itself. A claim that exceeds
/// the measured `I(panel;outcome)` by more than the declared slack is refused
/// fail-closed rather than served — a derived signal is structurally impossible
/// to oversell.
pub fn enforce_dpi_ceiling(
    panel_outcome_bits: f64,
    derived_claim_bits: f64,
    cfg: &BitsConfig,
) -> Result<()> {
    if !panel_outcome_bits.is_finite() || !derived_claim_bits.is_finite() {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "DPI ceiling check received a non-finite bit value",
            "supply finite panel and derived bit measurements",
        ));
    }
    if derived_claim_bits > panel_outcome_bits + cfg.dpi_slack_bits {
        return Err(AssayError::new(
            ASTRO_ASSAY_DPI_VIOLATION,
            format!(
                "derived-signal claim of {derived_claim_bits:.6} bits exceeds the I(panel;outcome) ceiling of {panel_outcome_bits:.6} bits (slack {:.6})",
                cfg.dpi_slack_bits
            ),
            "cap the derived-signal claim at the measured panel→outcome mutual information; a derived signal cannot carry more than its source",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BitsConfig {
        BitsConfig::from_defaults().unwrap()
    }

    #[test]
    fn dpi_allows_claim_at_or_below_ceiling() {
        let c = cfg();
        assert!(enforce_dpi_ceiling(1.0, 1.0, &c).is_ok());
        assert!(enforce_dpi_ceiling(1.0, 0.5, &c).is_ok());
        // Within slack is allowed.
        assert!(enforce_dpi_ceiling(1.0, 1.0 + c.dpi_slack_bits, &c).is_ok());
    }

    #[test]
    fn dpi_refuses_oversell() {
        let c = cfg();
        let err = enforce_dpi_ceiling(0.5, 1.5, &c).unwrap_err();
        assert_eq!(err.code(), crate::error::ASTRO_ASSAY_DPI_VIOLATION);
    }

    #[test]
    fn empty_slot_is_rejected() {
        let c = cfg();
        let slot = SlotObservations {
            slot: "empty".into(),
            values: SlotValues::Scalar(vec![]),
        };
        let axis = AxisValues::Discrete(vec![]);
        let err = measure_slot_bits(&slot, &axis, 1, &c).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn mismatched_lengths_are_rejected() {
        let c = cfg();
        let slot = SlotObservations {
            slot: "s".into(),
            values: SlotValues::Scalar(vec![1.0, 2.0, 3.0]),
        };
        let axis = AxisValues::Discrete(vec![0, 1]);
        let err = measure_slot_bits(&slot, &axis, 1, &c).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn constant_axis_is_rejected() {
        let c = cfg();
        let slot = SlotObservations {
            slot: "s".into(),
            values: SlotValues::Scalar(vec![1.0, 2.0, 3.0, 4.0]),
        };
        let axis = AxisValues::Discrete(vec![7, 7, 7, 7]);
        let err = measure_slot_bits(&slot, &axis, 1, &c).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn nonfinite_value_is_rejected() {
        let c = cfg();
        let slot = SlotObservations {
            slot: "s".into(),
            values: SlotValues::Scalar(vec![1.0, f64::NAN, 3.0, 4.0]),
        };
        let axis = AxisValues::Discrete(vec![0, 1, 0, 1]);
        let err = measure_slot_bits(&slot, &axis, 1, &c).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }
}
