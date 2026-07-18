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

use std::collections::BTreeMap;

use calyx_core::{CxId, SlotVector};
use calyx_sextant::{HnswIndex, QuantConfig, SextantIndex};

use crate::{
    AnnCandidateConfig, IndexedVector, NormalizedVector, SimilarityFamily, SimilarityPlanError,
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
    /// Distinct candidate pairs proposed by HNSW queries.
    pub hnsw_candidate_pairs: usize,
    /// Measured scalar8 quantization scales, one per dense dimension group.
    pub quant_scale_measurements: Vec<QuantScaleMeasurement>,
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
    per_node_cap: usize,
) -> Result<FamilyCandidates, SimilarityPlanError> {
    let mut report = AnnFamilyReport::default();
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

    let span = per_node_cap.saturating_mul(config.candidate_multiplier);

    if sparse_pool.len() >= 2 {
        report.lsh_candidate_pairs = lsh_banding_candidates(
            family,
            vectors,
            &sparse_pool,
            config,
            span,
            &mut per_source,
            &mut report.lsh_buckets,
        );
    }

    for (dim, group) in &dense_groups {
        if group.len() < 2 {
            continue;
        }
        report.hnsw_candidate_pairs += dense_candidates(
            family,
            vectors,
            *dim,
            group,
            config,
            span,
            &mut per_source,
            &mut report.quant_scale_measurements,
        )?;
    }

    for targets in &mut per_source {
        targets.sort_unstable();
        targets.dedup();
    }

    Ok(FamilyCandidates { per_source, report })
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
fn lsh_banding_candidates(
    family: SimilarityFamily,
    vectors: &[IndexedVector],
    sparse_pool: &[usize],
    config: &AnnCandidateConfig,
    span: usize,
    per_source: &mut [Vec<usize>],
    bucket_count: &mut usize,
) -> usize {
    let permutations = config.minhash_permutations;
    let hash_params: Vec<(u64, u64)> = (0..permutations)
        .map(|permutation| minhash_params(config.seed, family, permutation))
        .collect();

    // #433: each node's MinHash signature is a pure function of its own support
    // set and the fixed hash parameters, so chunking the signature pass across the
    // declared worker count cannot change any signature. Chunk outputs are
    // concatenated in pool order, keeping the banding below byte-identical to the
    // serial pass.
    let signature_workers = crate::knobs::weave_similarity_workers()
        .min(sparse_pool.len())
        .max(1);
    let signature_chunk = sparse_pool.len().div_ceil(signature_workers);
    let signatures: Vec<Vec<u64>> = std::thread::scope(|scope| {
        let hash_params = &hash_params;
        sparse_pool
            .chunks(signature_chunk.max(1))
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|&index| {
                            let NormalizedVector::Sparse { entries, .. } = &vectors[index].vector
                            else {
                                unreachable!("sparse pool holds only sparse vectors");
                            };
                            hash_params
                                .iter()
                                .map(|&(mul, add)| {
                                    entries
                                        .iter()
                                        .filter(|entry| entry.val != 0.0)
                                        .map(|entry| {
                                            mul.wrapping_mul(u64::from(entry.idx).wrapping_add(add))
                                        })
                                        .min()
                                        // Zero-norm vectors were skipped upstream, so a
                                        // sparse vector always has non-zero support;
                                        // `u64::MAX` keeps the arm total anyway.
                                        .unwrap_or(u64::MAX)
                                })
                                .collect::<Vec<u64>>()
                        })
                        .collect::<Vec<Vec<u64>>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|handle| handle.join().expect("lsh signature worker panicked"))
            .collect()
    });

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
        *bucket_count += buckets.len();
        for members in buckets.values() {
            if members.len() < 2 {
                continue;
            }
            for (position, &left) in members.iter().enumerate() {
                for &right in members.iter().skip(position + 1).take(span) {
                    if record_pair(per_source, left, right) {
                        new_pairs += 1;
                    }
                }
            }
        }
    }
    new_pairs
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
/// [`crate::knobs::weave_dense_ann_use_exact`]:
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
    span: usize,
    per_source: &mut [Vec<usize>],
    scale_measurements: &mut Vec<QuantScaleMeasurement>,
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
    let dense_inputs: Vec<Vec<f32>> = group
        .iter()
        .map(|&index| {
            let NormalizedVector::Dense { data, .. } = &vectors[index].vector else {
                unreachable!("dense group holds only dense vectors");
            };
            data.clone()
        })
        .collect();

    if crate::knobs::weave_dense_ann_use_exact(dim) {
        // The exact strategy has no persistent index object, so materialize the
        // same scalar8 representable values it scans. The HNSW path below must
        // receive raw values: Sextant owns packing and keeps no f32 copy.
        let approximations: Vec<Vec<f32>> = dense_inputs
            .iter()
            .map(|data| {
                let row = quant.pack(data)?;
                quant.approx_f32(&row)
            })
            .collect::<calyx_core::Result<Vec<_>>>()
            .map_err(|error| SimilarityPlanError::AnnCandidateFailure {
                family,
                message: format!(
                    "exact scalar8 pool packing failed for dim {dim}: {} ({})",
                    error.message, error.code
                ),
            })?;
        return Ok(exact_dense_candidates(
            &approximations,
            group,
            span,
            per_source,
        ));
    }
    hnsw_dense_candidates(
        family,
        dim,
        &dense_inputs,
        quant,
        config,
        span,
        group,
        per_source,
    )
}

/// Sequential seeded-HNSW dense candidate build (#433) — the byte-parity default.
///
/// `HnswIndex::insert` is called once per pool ordinal in qualified-name order, so
/// the shared-graph mutations (back-edges, neighbor pruning) happen in a fixed order
/// and the build is deterministic. The per-ordinal queries over the frozen index are
/// sharded across `weave_similarity_workers` (read-only searches, so worker-count
/// invariant), and the pair recording stays sequential in ordinal order.
fn hnsw_dense_candidates(
    family: SimilarityFamily,
    dim: u32,
    dense_inputs: &[Vec<f32>],
    quant: QuantConfig,
    config: &AnnCandidateConfig,
    span: usize,
    group: &[usize],
    per_source: &mut [Vec<usize>],
) -> Result<usize, SimilarityPlanError> {
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
    for (ordinal, input) in dense_inputs.iter().enumerate() {
        index
            .insert(
                ordinal_cx_id(ordinal),
                SlotVector::Dense {
                    dim,
                    data: input.clone(),
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

    let k = span.saturating_add(1).min(group.len());
    let ef = config.hnsw_ef_search.max(k);
    // #433: the per-ordinal queries are independent read-only searches over the
    // frozen index (`search(&self, ..)`, no interior mutability), so chunking them
    // across the declared worker count cannot change any hit list. Per-ordinal hit
    // lists are collected in ordinal order and the pair recording below stays
    // sequential, keeping the proposed candidate set byte-identical to the serial
    // query loop. Measurement drove this: `similarity_plan` was the largest weave
    // sub-stage and its cost is dominated by these queries, previously serial.
    let workers = crate::knobs::weave_similarity_workers()
        .min(dense_inputs.len())
        .max(1);
    let chunk_size = dense_inputs.len().div_ceil(workers);
    let hit_lists: Vec<Result<Vec<Vec<usize>>, SimilarityPlanError>> = std::thread::scope(
        |scope| {
            let index = &index;
            dense_inputs
                .chunks(chunk_size.max(1))
                .map(|chunk| {
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|input| {
                                let hits = index
                                    .search(
                                        &SlotVector::Dense {
                                            dim,
                                            data: input.clone(),
                                        },
                                        k,
                                        Some(ef),
                                    )
                                    .map_err(|error| {
                                        ann_failure(format!(
                                            "hnsw search failed for {family} dim {dim}: {} ({})",
                                            error.message, error.code
                                        ))
                                    })?;
                                hits.into_iter()
                                    .map(|hit| {
                                        cx_id_ordinal(hit.cx_id).ok_or_else(|| {
                                            ann_failure(format!(
                                                "hnsw returned a cx id outside the ordinal namespace for {family} dim {dim}"
                                            ))
                                        })
                                    })
                                    .collect::<Result<Vec<usize>, _>>()
                            })
                            .collect::<Result<Vec<Vec<usize>>, _>>()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(ann_failure("hnsw query worker panicked".into())))
                })
                .collect()
        },
    );
    let mut new_pairs = 0usize;
    let mut ordinal = 0usize;
    for chunk in hit_lists {
        for hit_ordinals in chunk? {
            for hit_ordinal in hit_ordinals {
                if hit_ordinal == ordinal || hit_ordinal >= group.len() {
                    continue;
                }
                if record_pair(per_source, group[ordinal], group[hit_ordinal]) {
                    new_pairs += 1;
                }
            }
            ordinal += 1;
        }
    }
    Ok(new_pairs)
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
/// Determinism / parity: each source's neighbor list is a pure function of the
/// frozen quantized pool `approximations`, with no graph and no cross-source
/// mutation, so the per-source scans are sharded across `weave_similarity_workers`
/// with results concatenated in ordinal order — the proposed candidate set is
/// byte-identical across runs and worker counts (the pair recording is single
/// threaded). Because the exact top-k over the quantized pool strictly dominates
/// HNSW's approximate graph search on the *same* pool (it removes only the
/// graph-approximation error over the shared quantization error), candidate recall
/// against the exhaustive planner cannot drop; see the knob declaration.
fn exact_dense_candidates(
    approximations: &[Vec<f32>],
    group: &[usize],
    span: usize,
    per_source: &mut [Vec<usize>],
) -> usize {
    let pool = approximations.len();
    // Same candidate breadth as the HNSW query (`span + 1`, self included), clamped
    // to the pool so a tiny group asks for at most `pool` neighbors.
    let k = span.saturating_add(1).min(pool);
    let indices: Vec<usize> = (0..pool).collect();
    let workers = crate::knobs::weave_similarity_workers().min(pool).max(1);
    let chunk_size = indices.len().div_ceil(workers).max(1);
    let neighbor_lists: Vec<Vec<usize>> = std::thread::scope(|scope| {
        indices
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|&source| {
                            let query = &approximations[source];
                            let mut scored: Vec<(usize, f32)> = (0..pool)
                                .map(|target| (target, cosine(query, &approximations[target])))
                                .collect();
                            // Mirrors calyx-sextant `top_k` ordering (score desc)
                            // with an ordinal tie-break for full determinism.
                            scored.sort_by(|left, right| {
                                right
                                    .1
                                    .total_cmp(&left.1)
                                    .then_with(|| left.0.cmp(&right.0))
                            });
                            scored.truncate(k);
                            scored
                                .into_iter()
                                .map(|(target, _)| target)
                                .filter(|&target| target != source)
                                .collect::<Vec<usize>>()
                        })
                        .collect::<Vec<Vec<usize>>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|handle| handle.join().expect("exact knn worker panicked"))
            .collect()
    });

    let mut new_pairs = 0usize;
    for (source, neighbors) in neighbor_lists.into_iter().enumerate() {
        for target in neighbors {
            if record_pair(per_source, group[source], group[target]) {
                new_pairs += 1;
            }
        }
    }
    new_pairs
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
