//! Deterministic ANN candidate generation for the L2 similarity planner.
//!
//! Two candidate generators feed the exact-cosine admission path in `lib.rs`:
//!
//! - **MinHash/LSH banding** for sparse slot vectors (S1-style trigram and
//!   hashed-set shapes) — the CBM candidate generator retained as an O(n)
//!   pass, re-derived deterministically from the configured seed.
//! - **Seeded, scalar8-quantized HNSW** (`calyx-sextant`) for dense slot
//!   vectors, where set-based LSH does not apply. The index receives raw input
//!   once, physically stores one-byte scalar codes, and scores those codes
//!   directly with the per-pool measured scale. Construction order is sorted
//!   qualified name, which makes construction and search deterministic.
//!
//! Both generators only *propose* pairs; every proposed pair is re-scored with
//! the exact cosine on the raw vectors and admitted under the same canonical
//! ownership (lower qualified name owns), sorted admission, and per-node cap
//! as the exhaustive planner. Candidate *recording* is single-threaded, so the
//! proposed set is worker-count invariant; the compute-heavy stages (MinHash
//! signatures, HNSW queries, and — under the `weave_dense_ann_strategy` exact
//! build (#441) — the per-source exact kNN scans) shard across the declared
//! worker count over frozen, read-only inputs.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
};

use calyx_core::{CxId, SlotVector};
use calyx_sextant::{HnswIndex, QuantConfig, SextantIndex};

use crate::{
    AnnCandidateConfig, IndexedVector, NormalizedVector, ParallelScheduleTelemetry,
    SimilarityFamily, SimilarityPlanError,
    knobs::ResolvedSimilarityKnobs,
    ordered_parallel::{OrderedParallelFailure, OrderedParallelFailureKind, run_ordered_parallel},
};

/// Number of representable positive int8 quantization levels in the sextant
/// `Scalar8` codec (`i8` clamps to ±127). Structural constant of the codec,
/// not a tunable: the measured per-pool scale is `max_abs / 127`.
const SCALAR8_POSITIVE_LEVELS: f32 = 127.0;

/// Per-family ANN candidate-generation accounting.
///
/// Every field is a count or a measured value; the report makes the ANN pass
/// auditable instead of a silent candidate source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnnFamilyReport {
    /// Nodes routed to the MinHash/LSH generator (sparse slot vectors).
    pub sparse_pool_nodes: usize,
    /// Nodes routed to the quantized HNSW generator (dense slot vectors).
    pub dense_pool_nodes: usize,
    /// Non-empty LSH band buckets observed.
    pub lsh_buckets: usize,
    /// Distinct candidate pairs proposed by LSH banding.
    pub lsh_candidate_pairs: usize,
    /// Dense dimensionality groups (one HNSW index per group).
    pub hnsw_dim_groups: usize,
    /// Distinct candidate pairs proposed by all dense generators.
    pub dense_candidate_pairs: usize,
    /// Physical dense candidate strategy selected for each processed dimension
    /// group, in ascending dimension order.
    pub dense_strategy_measurements: Vec<DenseStrategyMeasurement>,
    /// Measured scalar8 quantization scales, one per dense dimension group.
    pub quant_scale_measurements: Vec<QuantScaleMeasurement>,
}

/// The physically executed dense candidate generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenseCandidateStrategy {
    SeededHnsw,
    ExactKnn,
}

impl DenseCandidateStrategy {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SeededHnsw => "seeded_hnsw",
            Self::ExactKnn => "exact_knn",
        }
    }
}

/// One immutable dense routing decision made from the resolved runtime knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenseStrategyMeasurement {
    pub dim: u32,
    pub pool_nodes: usize,
    pub strategy: DenseCandidateStrategy,
}

/// One measured scalar8 quantization scale (recorded as the exact IEEE-754 bit
/// pattern so the report stays `Eq` and byte-comparable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuantScaleMeasurement {
    /// Dense dimensionality of the pool this scale was measured on.
    pub dim: u32,
    /// Number of vectors in the pool.
    pub pool_nodes: usize,
    /// `f32::to_bits` of the measured scale (`max_abs / 127`).
    pub scale_bits: u32,
}

impl QuantScaleMeasurement {
    /// Returns the measured quantization scale.
    pub fn scale(&self) -> f32 {
        f32::from_bits(self.scale_bits)
    }
}

/// Candidate targets per source index plus the generation accounting.
pub(crate) struct FamilyCandidates {
    /// `per_source[i]` holds strictly-greater target indices, sorted ascending.
    pub(crate) per_source: Vec<Vec<usize>>,
    pub(crate) report: AnnFamilyReport,
    pub(crate) scheduler_telemetry: Vec<ParallelScheduleTelemetry>,
}

/// Generates deterministic ANN candidate pairs for one similarity family.
///
/// `vectors` must be sorted ascending by qualified name (the planner's
/// invariant), so index order is qualified-name order and pair
/// canonicalization to `(min_index, max_index)` implements "lower qualified
/// name owns".
pub(crate) fn generate_family_candidates(
    family: SimilarityFamily,
    vectors: &[IndexedVector],
    config: &AnnCandidateConfig,
    runtime: &ResolvedSimilarityKnobs,
    per_node_cap: usize,
) -> Result<FamilyCandidates, SimilarityPlanError> {
    let mut report = AnnFamilyReport::default();
    let mut scheduler_telemetry = Vec::new();
    let mut per_source: Vec<Vec<usize>> = vec![Vec::new(); vectors.len()];

    let mut sparse_pool = Vec::new();
    let mut dense_groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, vector) in vectors.iter().enumerate() {
        match &vector.vector {
            NormalizedVector::Sparse { .. } => sparse_pool.push(index),
            NormalizedVector::Dense { dim, .. } => {
                dense_groups.entry(*dim).or_default().push(index);
            }
        }
    }
    report.sparse_pool_nodes = sparse_pool.len();
    report.dense_pool_nodes = dense_groups.values().map(Vec::len).sum();
    report.hnsw_dim_groups = dense_groups.len();

    let span = per_node_cap
        .checked_mul(config.candidate_multiplier)
        .ok_or_else(|| SimilarityPlanError::AnnCandidateFailure {
            family,
            message: format!(
                "ASTRO_WEAVE_ANN_SPAN_OVERFLOW: {family} per_node_cap={per_node_cap} times candidate_multiplier={} exceeded usize; no partial similarity plan was published",
                config.candidate_multiplier
            ),
        })?;

    if sparse_pool.len() >= 2 {
        let (pairs, telemetry) = lsh_banding_candidates(
            LshBandingPlan {
                family,
                vectors,
                sparse_pool: &sparse_pool,
                config,
                worker_count: runtime.similarity_workers_resolved(),
                span,
            },
            &mut per_source,
            &mut report.lsh_buckets,
        )?;
        report.lsh_candidate_pairs = pairs;
        scheduler_telemetry.push(telemetry);
    }

    for (dim, group) in &dense_groups {
        if group.len() < 2 {
            continue;
        }
        let dense_pairs = dense_candidates(
            family,
            vectors,
            *dim,
            group,
            config,
            runtime,
            span,
            &mut per_source,
            &mut report.dense_strategy_measurements,
            &mut report.quant_scale_measurements,
            &mut scheduler_telemetry,
        )?;
        report.dense_candidate_pairs = report
            .dense_candidate_pairs
            .checked_add(dense_pairs)
            .ok_or_else(|| SimilarityPlanError::AnnCandidateFailure {
                family,
                message: format!(
                    "ASTRO_WEAVE_DENSE_PAIR_COUNT_OVERFLOW: {family} exceeded usize after dimension {dim}; no partial similarity plan was published"
                ),
            })?;
    }

    for targets in &mut per_source {
        targets.sort_unstable();
        targets.dedup();
    }

    Ok(FamilyCandidates {
        per_source,
        report,
        scheduler_telemetry,
    })
}

/// Records the canonical `(min, max)` form of a proposed pair; returns whether
/// the pair was new. Duplicates across bands/queries are deduplicated later by
/// the sort+dedup pass, but new-pair counting must happen at insert time.
fn record_pair(per_source: &mut [Vec<usize>], left: usize, right: usize) -> bool {
    if left == right {
        return false;
    }
    let (source, target) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    let targets = &mut per_source[source];
    if targets.contains(&target) {
        return false;
    }
    targets.push(target);
    true
}

/// MinHash/LSH banding over the non-zero support sets of a sparse pool.
///
/// Each permutation is a multiply-shift universal hash whose parameters are
/// derived from `blake3(seed, family, permutation)`. Bucket keys are the exact
/// per-band signature slices, kept in a `BTreeMap` so iteration (and thus the
/// pair proposal order) is deterministic. Within a bucket, members (already in
/// qualified-name order) are paired with their next `span` bucket neighbors —
/// bounding the worst-case near-duplicate bucket to O(members × span) pairs
/// while preserving the exhaustive planner's tie-break neighborhood (nearest
/// following qualified names) for identical vectors.
struct LshBandingPlan<'a> {
    family: SimilarityFamily,
    vectors: &'a [IndexedVector],
    sparse_pool: &'a [usize],
    config: &'a AnnCandidateConfig,
    worker_count: usize,
    span: usize,
}

fn lsh_banding_candidates(
    plan: LshBandingPlan<'_>,
    per_source: &mut [Vec<usize>],
    bucket_count: &mut usize,
) -> Result<(usize, ParallelScheduleTelemetry), SimilarityPlanError> {
    let LshBandingPlan {
        family,
        vectors,
        sparse_pool,
        config,
        worker_count,
        span,
    } = plan;
    let permutations = config.minhash_permutations;
    let hash_params: Vec<(u64, u64)> = (0..permutations)
        .map(|permutation| minhash_params(config.seed, family, permutation))
        .collect();

    // Each signature is a pure function of one immutable source row. The shared
    // scheduler computes strided rows concurrently and appends them in exact pool
    // order, so no worker count can change the band buckets below.
    let mut signatures = Vec::new();
    signatures.try_reserve_exact(sparse_pool.len()).map_err(|error| {
        SimilarityPlanError::AnnCandidateFailure {
            family,
            message: format!(
                "ASTRO_WEAVE_LSH_CAPACITY_EXHAUSTED: reserve {} signature rows: {error}; no partial similarity plan was published",
                sparse_pool.len()
            ),
        }
    })?;
    let telemetry = run_ordered_parallel(
        format!("ann_generate.{family}.lsh_signatures"),
        sparse_pool.len(),
        worker_count,
        |_| Ok::<_, String>(()),
        |_, pool_position| {
            let index = sparse_pool[pool_position];
            let NormalizedVector::Sparse { entries, .. } = &vectors[index].vector else {
                return Err("sparse pool contained a non-sparse vector".to_string());
            };
            let mut signature = Vec::new();
            signature.try_reserve_exact(hash_params.len()).map_err(|error| {
                format!(
                    "ASTRO_WEAVE_LSH_CAPACITY_EXHAUSTED: reserve {} signature values for pool ordinal {pool_position}: {error}",
                    hash_params.len()
                )
            })?;
            for &(mul, add) in &hash_params {
                let minhash = entries
                    .iter()
                    .filter(|entry| entry.val != 0.0)
                    .map(|entry| mul.wrapping_mul(u64::from(entry.idx).wrapping_add(add)))
                    .min()
                    .ok_or_else(|| {
                        format!(
                            "ASTRO_WEAVE_LSH_ZERO_SUPPORT: sparse pool ordinal {pool_position} has no non-zero support after upstream normalization; no partial similarity plan was published"
                        )
                    })?;
                signature.push(minhash);
            }
            Ok(signature)
        },
        |_, signature| {
            signatures.push(signature);
            Ok::<_, String>(())
        },
    )
    .map_err(|failure| SimilarityPlanError::AnnCandidateFailure {
        family,
        message: ann_ordered_failure_message(family, "lsh_signatures", *failure),
    })?;

    let rows_per_band = permutations / config.lsh_bands;
    let mut new_pairs = 0usize;
    for band in 0..config.lsh_bands {
        let range = band * rows_per_band..(band + 1) * rows_per_band;
        let mut buckets: BTreeMap<&[u64], Vec<usize>> = BTreeMap::new();
        for (pool_position, &global_index) in sparse_pool.iter().enumerate() {
            buckets
                .entry(&signatures[pool_position][range.clone()])
                .or_default()
                .push(global_index);
        }
        *bucket_count = bucket_count.checked_add(buckets.len()).ok_or_else(|| {
            SimilarityPlanError::AnnCandidateFailure {
                family,
                message: format!(
                    "ASTRO_WEAVE_LSH_BUCKET_COUNT_OVERFLOW: {family} exceeded usize while accepting band {band}; no partial similarity plan was published"
                ),
            }
        })?;
        for members in buckets.values() {
            if members.len() < 2 {
                continue;
            }
            for (position, &left) in members.iter().enumerate() {
                for &right in members.iter().skip(position + 1).take(span) {
                    if record_pair(per_source, left, right) {
                        new_pairs = new_pairs.checked_add(1).ok_or_else(|| {
                            SimilarityPlanError::AnnCandidateFailure {
                                family,
                                message: format!(
                                    "ASTRO_WEAVE_LSH_PAIR_COUNT_OVERFLOW: {family} exceeded usize while accepting band {band}; no partial similarity plan was published"
                                ),
                            }
                        })?;
                    }
                }
            }
        }
    }
    Ok((new_pairs, telemetry))
}

fn ann_ordered_failure_message(
    family: SimilarityFamily,
    stage: &str,
    failure: OrderedParallelFailure<String>,
) -> String {
    let telemetry = failure.telemetry;
    let topology = format!(
        "requested_workers={}, effective_workers={}, started_workers={}, completed_sources={}/{}",
        telemetry.requested_workers,
        telemetry.effective_workers,
        telemetry.started_workers,
        telemetry.completed_sources,
        telemetry.source_count
    );
    match failure.kind {
        OrderedParallelFailureKind::InvalidWorkerCount => format!(
            "ASTRO_WEAVE_ANN_WORKER_COUNT_INVALID: {family} stage={stage}, {topology}; set the declared similarity worker count to a positive resolved value; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Capacity {
            component,
            requested_items,
            message,
        } => format!(
            "ASTRO_WEAVE_ANN_CAPACITY_EXHAUSTED: {family} stage={stage}, component={component}, requested_items={requested_items}, {topology}: {message}; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Telemetry { field, message } => format!(
            "ASTRO_WEAVE_ANN_TELEMETRY_INVALID: {family} stage={stage}, field={field}, {topology}: {message}; preserve the source generation and diagnose the native monotonic clock/accounting fault; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Spawn {
            worker_index,
            message,
        } => format!(
            "ASTRO_WEAVE_ANN_WORKER_SPAWN_FAILED: {family} stage={stage}, worker_index={worker_index}, {topology}: {message}; inspect the native thread-creation error and host resource state; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Compute { source, error } => format!(
            "ASTRO_WEAVE_ANN_WORKER_FAILED: {family} stage={stage}, source_ordinal={source}, {topology}: {error}; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Accept { source, error } => format!(
            "ASTRO_WEAVE_ANN_ACCEPT_FAILED: {family} stage={stage}, source_ordinal={source}, {topology}: {error}; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Disconnected {
            worker_index,
            expected_source,
            message,
        } => format!(
            "ASTRO_WEAVE_ANN_WORKER_DISCONNECTED: {family} stage={stage}, worker_index={worker_index}, expected_source_ordinal={expected_source}, {topology}: {message}; inspect the worker panic/resource diagnostics; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::OrderDrift {
            worker_index,
            expected_source,
            observed_source,
        } => format!(
            "ASTRO_WEAVE_ANN_ORDER_DRIFT: {family} stage={stage}, worker_index={worker_index}, expected_source_ordinal={expected_source}, observed_source_ordinal={observed_source}, {topology}; preserve the source generation and scheduler telemetry for diagnosis; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::WorkerPanicked {
            worker_index,
            message,
        } => format!(
            "ASTRO_WEAVE_ANN_WORKER_PANICKED: {family} stage={stage}, worker_index={worker_index}, {topology}: {message}; preserve the source generation and inspect the exact worker failure; no partial similarity plan was published"
        ),
    }
}

/// Derives one multiply-shift hash parameter pair from the deterministic seed.
fn minhash_params(seed: u64, family: SimilarityFamily, permutation: usize) -> (u64, u64) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrolabe-weave-minhash-v1");
    hasher.update(&seed.to_be_bytes());
    hasher.update(&[family.sort_index()]);
    hasher.update(&(permutation as u64).to_be_bytes());
    let bytes = hasher.finalize();
    let bytes = bytes.as_bytes();
    let mul = u64::from_be_bytes(bytes[0..8].try_into().expect("blake3 slice")) | 1;
    let add = u64::from_be_bytes(bytes[8..16].try_into().expect("blake3 slice"));
    (mul, add)
}

/// Dense kNN candidate generation for one dense dimension group.
///
/// The scalar8 scale is measured from the pool (`max_abs / 127`) and recorded in
/// the report; every candidate strategy scores the *same* quantized approximations
/// (built in qualified-name order with ordinal `CxId`s), so the measured scale and
/// the candidate breadth (`per_node_cap × candidate_multiplier + 1` neighbors, self
/// included) are strategy-invariant. The registry-declared `weave_dense_ann_strategy`
/// knob (#441) then selects the build, routing on this group's `dim` via
/// [`ResolvedSimilarityKnobs::dense_ann_use_exact`]:
///
/// - **Sequential seeded HNSW** ([`hnsw_dense_candidates`]): the #433 build/query —
///   deterministic because inserts run once per ordinal and mutate the shared graph
///   in that fixed order. Selected for high-dim groups under the dim-aware default
///   (e.g. `SIM_SEMANTIC` dim=768, where the wave-24 matrix measured exact kNN
///   regressing ~9% at bevy n=41,311), or globally under strategy `0`.
/// - **Exact blocked kNN** ([`exact_dense_candidates`]): a deterministic, parallel,
///   graph-free per-source exact top-k scan over the identical quantized pool —
///   byte-identical across runs and worker counts, and a strict recall improvement
///   over the approximate HNSW graph search on the same pool (see the knob). Selected
///   for low-dim groups under the dim-aware default (e.g. `SIM_PROFILE` dim=24, the
///   dominant #441 cost, measured 7.7–20× faster than HNSW), or globally under
///   strategy `1`.
#[expect(
    clippy::too_many_arguments,
    reason = "single private call site; splitting into a context struct adds indirection without reuse"
)]
fn dense_candidates(
    family: SimilarityFamily,
    vectors: &[IndexedVector],
    dim: u32,
    group: &[usize],
    config: &AnnCandidateConfig,
    runtime: &ResolvedSimilarityKnobs,
    span: usize,
    per_source: &mut [Vec<usize>],
    strategy_measurements: &mut Vec<DenseStrategyMeasurement>,
    scale_measurements: &mut Vec<QuantScaleMeasurement>,
    scheduler_telemetry: &mut Vec<ParallelScheduleTelemetry>,
) -> Result<usize, SimilarityPlanError> {
    let mut max_abs = 0.0f32;
    for &index in group {
        let NormalizedVector::Dense { data, .. } = &vectors[index].vector else {
            unreachable!("dense group holds only dense vectors");
        };
        for value in data {
            max_abs = max_abs.max(value.abs());
        }
    }
    // Zero-norm vectors were skipped upstream, so max_abs > 0 here.
    let scale = max_abs / SCALAR8_POSITIVE_LEVELS;
    scale_measurements.push(QuantScaleMeasurement {
        dim,
        pool_nodes: group.len(),
        scale_bits: scale.to_bits(),
    });

    let quant = QuantConfig::scalar8(scale);

    let use_exact = runtime.dense_ann_use_exact(dim).map_err(|error| {
        SimilarityPlanError::AnnCandidateFailure {
            family,
            message: error.to_string(),
        }
    })?;
    strategy_measurements.push(DenseStrategyMeasurement {
        dim,
        pool_nodes: group.len(),
        strategy: if use_exact {
            DenseCandidateStrategy::ExactKnn
        } else {
            DenseCandidateStrategy::SeededHnsw
        },
    });
    if use_exact {
        let mut approximations = Vec::new();
        approximations
            .try_reserve_exact(group.len())
            .map_err(|error| SimilarityPlanError::AnnCandidateFailure {
                family,
                message: format!(
                    "ASTRO_WEAVE_EXACT_KNN_CAPACITY_EXHAUSTED: scalar8 approximation row-table reserve failed for {family} dim {dim}, pool={}, requested_rows={}: {error}; no partial similarity plan was published",
                    group.len(),
                    group.len()
                ),
            })?;
        for &index in group {
            let NormalizedVector::Dense { data, .. } = &vectors[index].vector else {
                unreachable!("dense group holds only dense vectors");
            };
            let row =
                quant
                    .pack(data)
                    .map_err(|error| SimilarityPlanError::AnnCandidateFailure {
                        family,
                        message: format!(
                            "exact scalar8 pool packing failed for dim {dim}: {} ({})",
                            error.message, error.code
                        ),
                    })?;
            let approximation = quant.approx_f32(&row).map_err(|error| {
                SimilarityPlanError::AnnCandidateFailure {
                    family,
                    message: format!(
                        "exact scalar8 approximation failed for dim {dim}: {} ({})",
                        error.message, error.code
                    ),
                }
            })?;
            approximations.push(approximation);
        }
        let (pairs, telemetry) = exact_dense_candidates(
            family,
            dim,
            &approximations,
            group,
            span,
            runtime.similarity_workers_resolved(),
            per_source,
        )
        .map_err(|message| SimilarityPlanError::AnnCandidateFailure { family, message })?;
        scheduler_telemetry.push(telemetry);
        return Ok(pairs);
    }
    hnsw_dense_candidates(
        HnswDenseCandidatePlan {
            family,
            dim,
            vectors,
            quant,
            config,
            worker_count: runtime.similarity_workers_resolved(),
            span,
            group,
        },
        per_source,
        scheduler_telemetry,
    )
}

/// Borrows the raw dense row selected by one dense-group ordinal.
fn dense_group_row<'a>(vectors: &'a [IndexedVector], group: &[usize], ordinal: usize) -> &'a [f32] {
    let NormalizedVector::Dense { data, .. } = &vectors[group[ordinal]].vector else {
        unreachable!("dense group holds only dense vectors");
    };
    data
}

/// Formats the single fail-closed resource-exhaustion code for exact kNN.
#[derive(Clone, Copy)]
struct ExactKnnContext {
    family: SimilarityFamily,
    dim: u32,
    pool: usize,
    k: usize,
}

fn exact_knn_capacity_error(
    context: ExactKnnContext,
    component: &str,
    requested_items: usize,
    source: Option<usize>,
    error: &impl std::fmt::Display,
) -> String {
    let ExactKnnContext {
        family,
        dim,
        pool,
        k,
    } = context;
    let source = source
        .map(|ordinal| ordinal.to_string())
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "ASTRO_WEAVE_EXACT_KNN_CAPACITY_EXHAUSTED: {component} reserve failed for {family} dim {dim}, pool={pool}, k={k}, source_ordinal={source}, requested_items={requested_items}: {error}; no partial similarity plan was published"
    )
}

/// Immutable inputs for one seeded-HNSW dense candidate build.
///
/// Keeping these related values in one named plan makes their meaning explicit at
/// the call boundary while leaving the separately mutable candidate destination
/// visible.
struct HnswDenseCandidatePlan<'a> {
    family: SimilarityFamily,
    dim: u32,
    vectors: &'a [IndexedVector],
    quant: QuantConfig,
    config: &'a AnnCandidateConfig,
    worker_count: usize,
    span: usize,
    group: &'a [usize],
}

/// Sequential seeded-HNSW dense candidate build (#433) — the byte-parity default.
///
/// `HnswIndex::insert` is called once per pool ordinal in qualified-name order, so
/// the shared-graph mutations (back-edges, neighbor pruning) happen in a fixed order
/// and the build is deterministic. The per-ordinal queries over the frozen index are
/// sharded across `weave_similarity_workers` (read-only searches, so worker-count
/// invariant), and the pair recording stays sequential in ordinal order.
fn hnsw_dense_candidates(
    plan: HnswDenseCandidatePlan<'_>,
    per_source: &mut [Vec<usize>],
    scheduler_telemetry: &mut Vec<ParallelScheduleTelemetry>,
) -> Result<usize, SimilarityPlanError> {
    let HnswDenseCandidatePlan {
        family,
        dim,
        vectors,
        quant,
        config,
        worker_count,
        span,
        group,
    } = plan;
    let ann_failure =
        |message: String| SimilarityPlanError::AnnCandidateFailure { family, message };
    let mut index = HnswIndex::new(family.slot(), dim, config.seed)
        .with_quant(quant)
        .map_err(|error| {
            ann_failure(format!(
                "hnsw quantizer setup failed for {family} dim {dim}: {} ({})",
                error.message, error.code
            ))
        })?;
    for ordinal in 0..group.len() {
        index
            .insert(
                ordinal_cx_id(ordinal),
                SlotVector::Dense {
                    dim,
                    data: dense_group_row(vectors, group, ordinal).to_vec(),
                },
                ordinal as u64,
            )
            .map_err(|error| {
                ann_failure(format!(
                    "hnsw insert failed for {family} dim {dim}: {} ({})",
                    error.message, error.code
                ))
            })?;
    }

    let k = span
        .checked_add(1)
        .ok_or_else(|| {
            ann_failure(format!(
                "ASTRO_WEAVE_ANN_SPAN_OVERFLOW: hnsw query for {family} dim {dim} cannot add its self neighbor to span {span}; no partial similarity plan was published"
            ))
        })?
        .min(group.len());
    let ef = config.hnsw_ef_search.max(k);
    // Queries are independent reads over the frozen index. Strided computation
    // and canonical acceptance keep pair recording byte-identical while bounding
    // retained hit rows to one per worker.
    let mut new_pairs = 0usize;
    let telemetry = run_ordered_parallel(
        format!("ann_generate.{family}.hnsw_query.dim{dim}"),
        group.len(),
        worker_count,
        |_| Ok::<_, String>(()),
        |_, ordinal| {
            let NormalizedVector::Dense { data, .. } = &vectors[group[ordinal]].vector else {
                return Err("dense group contained a non-dense vector".to_string());
            };
            let hits = index
                .search(
                    &SlotVector::Dense {
                        dim,
                        data: data.to_vec(),
                    },
                    k,
                    Some(ef),
                )
                .map_err(|error| {
                    format!(
                        "hnsw search failed for {family} dim {dim}: {} ({})",
                        error.message, error.code
                    )
                })?;
            hits.into_iter()
                .map(|hit| {
                    cx_id_ordinal(hit.cx_id).ok_or_else(|| {
                        format!(
                            "hnsw returned a cx id outside the ordinal namespace for {family} dim {dim}"
                        )
                    })
                })
                .collect::<Result<Vec<usize>, _>>()
        },
        |ordinal, hit_ordinals| {
            for hit_ordinal in hit_ordinals {
                if hit_ordinal == ordinal || hit_ordinal >= group.len() {
                    continue;
                }
                if record_pair(per_source, group[ordinal], group[hit_ordinal]) {
                    new_pairs = new_pairs.checked_add(1).ok_or_else(|| {
                        format!(
                            "ASTRO_WEAVE_ANN_PAIR_COUNT_OVERFLOW: {family} hnsw query dim {dim} exceeded usize while accepting source ordinal {ordinal}; no partial similarity plan was published"
                        )
                    })?;
                }
            }
            Ok::<_, String>(())
        },
    )
    .map_err(|failure| {
        ann_failure(ann_ordered_failure_message(
            family,
            &format!("hnsw_query.dim{dim}"),
            *failure,
        ))
    })?;
    scheduler_telemetry.push(telemetry);
    Ok(new_pairs)
}

/// Heap row for exact kNN selection. A max-heap surfaces the least-preferred
/// retained candidate: lower score first, then larger ordinal.
#[derive(Debug)]
struct ExactCandidate {
    score: f32,
    target: usize,
}

impl PartialEq for ExactCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ExactCandidate {}

impl PartialOrd for ExactCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExactCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| self.target.cmp(&other.target))
    }
}

/// Deterministic, parallel, **exact** blocked kNN dense candidate build (#441).
///
/// For every source ordinal `s` this computes the exact cosine of its quantized
/// approximation against every pool member, takes the top `k = span + 1`
/// (self-inclusive, the identical candidate breadth the HNSW query uses), drops
/// self, and records the surviving neighbors as candidate pairs. The tie-break is
/// (score descending, ordinal ascending) — ordinals are qualified-name order, so it
/// is fully deterministic with no RNG.
///
/// Production diagnosis (#441, 2026-08-12): the physical self-host graph had
/// 192,873 nodes and the prior contiguous-range/capacity-one topology exposed
/// 1.119 effective workers on a 32-thread host. This implementation assigns
/// strided ordinals and accepts one row from each worker per canonical round.
/// Each worker reuses one `k`-entry heap; at most one completed row per worker is
/// buffered, so retained candidate scratch is O(workers * k), invariant in pool
/// N (PC-17/PC-22/PC-29/PC-38/PC-41).
fn exact_dense_candidates(
    family: SimilarityFamily,
    dim: u32,
    approximations: &[Vec<f32>],
    group: &[usize],
    span: usize,
    worker_count: usize,
    per_source: &mut [Vec<usize>],
) -> Result<(usize, ParallelScheduleTelemetry), String> {
    let pool = approximations.len();
    // Same candidate breadth as the HNSW query (`span + 1`, self included), clamped
    // to the pool so a tiny group asks for at most `pool` neighbors.
    let k = span
        .checked_add(1)
        .ok_or_else(|| {
            format!(
                "ASTRO_WEAVE_EXACT_KNN_SPAN_OVERFLOW: {family} dim {dim}, pool={pool}, span={span}; no partial similarity plan was published"
            )
        })?
        .min(pool);
    let context = ExactKnnContext {
        family,
        dim,
        pool,
        k,
    };
    let mut new_pairs = 0usize;
    let telemetry = run_ordered_parallel(
        format!("ann_generate.{family}.exact_knn.dim{dim}"),
        pool,
        worker_count,
        |_| {
            let mut top = BinaryHeap::new();
            top.try_reserve_exact(k).map_err(|error| {
                exact_knn_capacity_error(context, "worker top-k heap", k, None, &error)
            })?;
            Ok::<_, String>(top)
        },
        |top, source| {
            top.clear();
            let query = &approximations[source];
            for (target, approximation) in approximations.iter().enumerate() {
                let candidate = ExactCandidate {
                    score: cosine(query, approximation),
                    target,
                };
                if top.len() < k {
                    top.push(candidate);
                } else if top
                    .peek()
                    .is_some_and(|worst| candidate.cmp(worst) == Ordering::Less)
                {
                    top.pop();
                    top.push(candidate);
                }
            }

            let mut neighbors = Vec::new();
            neighbors.try_reserve_exact(k).map_err(|error| {
                exact_knn_capacity_error(
                    context,
                    "neighbor row",
                    k,
                    Some(source),
                    &error,
                )
            })?;
            // `pop` yields worst-to-best under `ExactCandidate::cmp`; reversing
            // restores the historical `(score desc, ordinal asc)` row order.
            while let Some(candidate) = top.pop() {
                if candidate.target != source {
                    neighbors.push(candidate.target);
                }
            }
            neighbors.reverse();
            Ok(neighbors)
        },
        |source, neighbors| {
            for target in neighbors {
                if record_pair(per_source, group[source], group[target]) {
                    new_pairs = new_pairs.checked_add(1).ok_or_else(|| {
                        format!(
                            "ASTRO_WEAVE_EXACT_KNN_PAIR_COUNT_OVERFLOW: {family} dim {dim}, pool={pool}, k={k}, source_ordinal={source}; no partial similarity plan was published"
                        )
                    })?;
                }
            }
            Ok::<_, String>(())
        },
    )
    .map_err(|failure| exact_ordered_failure_message(context, *failure))?;
    Ok((new_pairs, telemetry))
}

fn exact_ordered_failure_message(
    context: ExactKnnContext,
    failure: OrderedParallelFailure<String>,
) -> String {
    let ExactKnnContext {
        family,
        dim,
        pool,
        k,
    } = context;
    let telemetry = failure.telemetry;
    let topology = format!(
        "requested_workers={}, effective_workers={}, started_workers={}, completed_sources={}/{}",
        telemetry.requested_workers,
        telemetry.effective_workers,
        telemetry.started_workers,
        telemetry.completed_sources,
        telemetry.source_count
    );
    match failure.kind {
        OrderedParallelFailureKind::InvalidWorkerCount => format!(
            "ASTRO_WEAVE_EXACT_KNN_WORKER_COUNT_INVALID: {family} dim {dim}, pool={pool}, k={k}, {topology}; set the declared similarity worker count to a positive resolved value; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Capacity {
            component,
            requested_items,
            message,
        } => format!(
            "ASTRO_WEAVE_EXACT_KNN_CAPACITY_EXHAUSTED: {component} reserve failed for {family} dim {dim}, pool={pool}, k={k}, requested_items={requested_items}, {topology}: {message}; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Telemetry { field, message } => format!(
            "ASTRO_WEAVE_EXACT_KNN_TELEMETRY_INVALID: {family} dim {dim}, pool={pool}, k={k}, field={field}, {topology}: {message}; preserve the corpus and diagnose the native monotonic clock/accounting fault; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Spawn {
            worker_index,
            message,
        } => format!(
            "ASTRO_WEAVE_EXACT_KNN_WORKER_SPAWN_FAILED: {family} dim {dim}, pool={pool}, k={k}, worker_index={worker_index}, {topology}: {message}; inspect the native thread-creation error and host resource state, then retry the unchanged corpus; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Compute { source, error } => {
            format!("{error}; failed_source_ordinal={source}; {topology}")
        }
        OrderedParallelFailureKind::Accept { source, error } => format!(
            "ASTRO_WEAVE_EXACT_KNN_ACCEPT_FAILED: {family} dim {dim}, pool={pool}, k={k}, source_ordinal={source}, {topology}: {error}; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::Disconnected {
            worker_index,
            expected_source,
            message,
        } => format!(
            "ASTRO_WEAVE_EXACT_KNN_WORKER_DISCONNECTED: {family} dim {dim}, pool={pool}, k={k}, worker_index={worker_index}, expected_source_ordinal={expected_source}, {topology}: {message}; inspect the worker panic/resource diagnostics and retry the unchanged corpus; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::OrderDrift {
            worker_index,
            expected_source,
            observed_source,
        } => format!(
            "ASTRO_WEAVE_EXACT_KNN_ORDER_DRIFT: {family} dim {dim}, pool={pool}, k={k}, worker_index={worker_index}, expected_source_ordinal={expected_source}, observed_source_ordinal={observed_source}, {topology}; preserve the corpus and scheduler telemetry for diagnosis; no partial similarity plan was published"
        ),
        OrderedParallelFailureKind::WorkerPanicked {
            worker_index,
            message,
        } => format!(
            "ASTRO_WEAVE_EXACT_KNN_WORKER_PANICKED: {family} dim {dim}, pool={pool}, k={k}, worker_index={worker_index}, {topology}: {message}; inspect the exact worker generation and retry the unchanged corpus; no partial similarity plan was published"
        ),
    }
}

/// Cosine similarity over two equal-length dense vectors, byte-identical to the
/// `calyx-sextant` `util::cosine` the HNSW path scores with, so the exact strategy
/// ranks candidates in the same quantized space as the sequential build.
fn cosine(left: &[f32], right: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;
    for (x, y) in left.iter().zip(right) {
        dot += x * y;
        left_norm += x * x;
        right_norm += y * y;
    }
    if left_norm == 0.0 || right_norm == 0.0 {
        0.0
    } else {
        dot / (left_norm.sqrt() * right_norm.sqrt())
    }
}

/// Maps a pool ordinal to a synthetic, deterministic `CxId` (big-endian u128).
fn ordinal_cx_id(ordinal: usize) -> CxId {
    CxId::from_bytes((ordinal as u128).to_be_bytes())
}

/// Recovers the pool ordinal from a synthetic `CxId`.
fn cx_id_ordinal(cx_id: CxId) -> Option<usize> {
    usize::try_from(u128::from_be_bytes(*cx_id.as_bytes())).ok()
}
