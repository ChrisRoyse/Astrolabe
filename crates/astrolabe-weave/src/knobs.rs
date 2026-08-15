//! Registry-declared knobs owned by the weave crate (standing invariant 4).
//!
//! Every budget, cap, or worker count the weave path depends on is a *declared*
//! knob with explicit bounds, a unit, a source, and a rationale — never a bare
//! constant. The declaration type is reused from `astrolabe-domain` so the whole
//! workspace shares one knob shape, exactly as `astrolabe-assay`'s knob registry
//! does (`ASSAY_BITS_KNOBS`).

use std::error::Error;
use std::fmt;

use astrolabe_domain::knobs::U64KnobDeclaration;
use serde::Serialize;

/// Registry version tag for the weave performance knobs (#433).
pub const WEAVE_KNOB_REGISTRY_VERSION: &str = "astrolabe-weave-knobs-v2";

/// Name of the neighborhood cross-term peer sample-cap knob.
pub const WEAVE_NEIGHBORHOOD_SAMPLE_CAP_KNOB: &str = "weave_neighborhood_sample_cap";
/// Name of the similarity-planner worker-count knob.
pub const WEAVE_SIMILARITY_WORKERS_KNOB: &str = "weave_similarity_workers";
/// Environment override for the similarity-planner worker-count knob.
pub const WEAVE_SIMILARITY_WORKERS_ENV: &str = "ASTRO_WEAVE_SIMILARITY_WORKERS";
/// Name of the dense ANN candidate-build strategy knob (#441).
pub const WEAVE_DENSE_ANN_STRATEGY_KNOB: &str = "weave_dense_ann_strategy";
/// Name of the exact-kNN physical executor knob (#1057).
pub const WEAVE_EXACT_KNN_EXECUTOR_KNOB: &str = "weave_exact_knn_executor";
/// Environment override for the exact-kNN physical executor.
pub const WEAVE_EXACT_KNN_EXECUTOR_ENV: &str = "ASTRO_WEAVE_EXACT_KNN_EXECUTOR";

/// Default neighborhood peer sample-cap (#433): the largest peer set the O(n²)
/// per-symbol neighborhood-agreement cross-term profiles run over before a seeded
/// without-replacement subsample bounds it.
///
/// Five of the six eager cross-term kinds (`NAME_TRUTH`, `CLONE_TAXONOMY`,
/// `COMPLEXITY_CHURN`, `CENTRALITY_COVERAGE`, `ROUTE_MATCH`) score each symbol's
/// agreement as the cosine between its two per-slot *similarity neighborhood
/// profiles* — the vector of that symbol's cosine similarity to every other
/// symbol in a slot. Building each profile against all `n` peers makes the pass
/// Θ(n²) per kind, which #401/#433 measured re-dominating the cold index at
/// monorepo scale (real astrolabe binary, ASTRO_SHADOW_TIMING: cbm/src n≈2574
/// eager cross-terms 3.3s → full-cbm n≈5369 13.1s, a 4.0× phase rise for a 2.09×
/// symbol rise — the textbook n² slope). At the calyx-scale ~10× point this term
/// alone would cost ~100× baseline.
///
/// The neighborhood profile is a landmark/Nyström approximation of the full
/// similarity structure (Ray, Monath, McCallum & Musco, "Sublinear Time
/// Approximation of Text Similarity Matrices", AAAI 2022, arXiv:2112.09631 —
/// exact similarities against a subset of `s` landmark columns recover within ~1
/// F1 point at 90% and ~1.5 at 50% of the data; Zadeh & Carlsson, "Dimension
/// Independent Similarity Computation", ICML 2013, arXiv:1206.2082 — DIMSUM
/// removes the dependence on the peer count by sampling). The cosine of two such
/// sampled profiles is a Monte-Carlo estimate of the full-peer profile cosine
/// whose variance is O(1/m) in the sampled peer count `m` (Smith, Ortmann,
/// Abbas-Aghababazadeh, Smirnov & Haibe-Kains, "On the distribution of cosine
/// similarity", arXiv:2310.13994 — cosine-similarity variance follows 1/n), so
/// the standard error at m=2048 is ≈ 1/√2048 ≈ 0.022 in the agreement value —
/// well inside ordinary agreement-value noise — and further peers buy no accuracy
/// while costing O(n). Capping converts the per-kind cost from O(n²) to a
/// corpus-size-independent O(n·cap). 2048 mirrors the #422 estimator sample cap
/// (a power-of-two plateau ≈5× the Cochran fixed-precision sample of 384).
pub const WEAVE_DEFAULT_NEIGHBORHOOD_SAMPLE_CAP: u64 = 2_048;
/// Smallest legal neighborhood sample cap: the Cochran fixed-precision plateau
/// (384), below which the sampled profile loses the peer support that pins the
/// agreement estimate within its noise band.
pub const WEAVE_MIN_NEIGHBORHOOD_SAMPLE_CAP: u64 = 384;
/// Largest legal neighborhood sample cap: an upper bound keeps one kind's
/// per-symbol profile work bounded even when an operator raises the cap; a corpus
/// with fewer comparable peers than the cap is scored whole (the cap only ever
/// subsamples down).
pub const WEAVE_MAX_NEIGHBORHOOD_SAMPLE_CAP: u64 = 1_000_000;

/// Fixed RNG seed for the neighborhood peer subsample. A declared RNG seed (not a
/// threshold): the per-symbol without-replacement peer subsample is a pure
/// function of this seed, the symbol's qualified name, the comparable-peer count,
/// and the cap, so a byte-identical corpus produces byte-identical sampled
/// profiles across runs. A fixed identity ("WEAVENBR" as big-endian ASCII); any
/// value yields a valid deterministic sample, so it is pinned for reproducibility.
pub const WEAVE_NEIGHBORHOOD_SAMPLE_SEED: u64 = u64::from_be_bytes(*b"WEAVENBR");

/// Default similarity-planner worker count sentinel (#433): `0` means "resolve to
/// the measured host parallelism at call time" (`std::thread::available_parallelism`),
/// exactly as the SQLite import already sizes its corpus-wide passes.
///
/// The similarity edge planner shards its exact-cosine rescoring across
/// `worker_count` source-range workers; the sharding is proven byte-identical to
/// the serial plan (order-invariant per-shard reduction plus the caller's total
/// `stable_edge_order` sort — the candidate sets are generated single-threaded and
/// are worker-count invariant by construction), so the worker count changes only
/// wall-clock, never the persisted edge set. #433 measured `similarity_plan` as
/// the largest weave sub-stage (cbm/src 6.0s → full-cbm 19.3s) running fully
/// single-threaded on a many-core host because the prior default was a bare `1`.
/// Resolving to host parallelism recovers that idle parallelism as a pure,
/// output-equivalent speedup. A positive value pins an explicit worker count for
/// reproducible benches.
pub const WEAVE_DEFAULT_SIMILARITY_WORKERS: u64 = 0;
/// Smallest legal value: `0` (resolve to host parallelism). The resolver clamps
/// the resolved count to at least one worker, so a single-core host still runs.
pub const WEAVE_MIN_SIMILARITY_WORKERS: u64 = 0;
/// Largest legal explicit worker count. An upper bound keeps a misconfiguration
/// from requesting an unbounded thread fan-out; the planner clamps the effective
/// count to the source count regardless, so this caps the request, not correctness.
pub const WEAVE_MAX_SIMILARITY_WORKERS: u64 = 4_096;

/// Dense ANN candidate-build strategy (#441): the sequential seeded-HNSW build.
///
/// `0` is the seeded, scalar8-quantized HNSW index build/query that #433 shipped:
/// `HnswIndex::insert` is called once per pool ordinal in qualified-name order and
/// each insert mutates the shared graph (back-edges + neighbor pruning of earlier
/// rows), so the build is strictly sequential *by design for determinism* — a
/// parallel insert reorders those mutations and yields a different graph (Zhu et
/// al., "SHINE: A Scalable HNSW Index in Disaggregated Memory", arXiv:2507.17647,
/// and the hnswlib/usearch per-node-lock construction: concurrent insertion order
/// is non-deterministic, so the same vectors produce a different topology). This
/// value reproduces the pre-#441 build byte-for-byte and is the shipped default
/// until the exact strategy is proven byte-parity on the orchestrator's real-corpus
/// edge_dump probe.
pub const WEAVE_DENSE_ANN_STRATEGY_SEQUENTIAL_HNSW: u64 = 0;
/// Dense ANN candidate-build strategy (#441/#1057): deterministic, **exact**
/// kNN over the identical scalar8-quantized approximations.
///
/// `1` replaces HNSW build+query with Forge exact top-k over the same physical
/// scalar8 pool (`k = per_node_cap × candidate_multiplier + 1`, self included).
/// The separately declared executor chooses explicit CPU oracle or required CUDA;
/// the shipping CUDA executor uploads the pool once, reuses one query/score/top-k
/// workspace, and serializes callers around its attested context/default stream.
/// It has no graph or RNG, so every neighbor row is a pure function of the frozen
/// codes. Removing HNSW's graph-approximation layer cannot reduce candidate recall
/// relative to approximate search on those same codes; raw vectors are still the
/// final admission authority.
pub const WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN: u64 = 1;
/// Dense ANN candidate-build strategy (#441): **dim-aware routing** — per dense
/// dimension group, use the exact blocked kNN when the group's dimensionality is
/// `<= weave_dense_ann_exact_max_dim`, else the sequential HNSW build.
///
/// `2` is the historical #441 CPU-routing policy and remains an explicit diagnostic
/// mode. Strategies 0 and 1 are global (all dense groups one way); this routes
/// **per group by dim**,
/// because the wave-24 scaling matrix (astrolabe binary, ASTRO_SHADOW_TIMING, four
/// real Rust corpora zoxide n=471 → bevy n=41,311) showed the two paths cross over
/// with dimensionality:
///
/// - **Low-dim `SIM_PROFILE` (RECORD_VEC dim=24)** — the dominant #441 cost. Exact
///   kNN beats HNSW at every measured size (bevy: HNSW `ann_generate.SIM_PROFILE`
///   135,951ms → exact 17,648ms, **7.7×**; smaller corpora 10–20×). HNSW's fixed
///   per-node graph bookkeeping (exhaustive-construction prefix, back-edge pruning,
///   `diversified_neighbors`) dwarfs a 24-dim brute-force scan, so exact wins by a
///   wide margin with no crossover in the target regime.
/// - **High-dim `SIM_SEMANTIC` (nomic embedding dim=768)** — exact kNN wins at small
///   n (atuin n=6,865: HNSW 14,623ms → exact 2,248ms, 6.5×) but **crosses over and
///   regresses ~9% at bevy n=41,311** (HNSW 121,571ms → exact 133,000ms), because
///   exact kNN is Θ(dim·n²) and at dim=768 the memory-bound n² scan overtakes HNSW's
///   sub-quadratic approximate graph search. Routing semantic to HNSW keeps that
///   family byte-identical to the pre-#441 default (no regression, negligible
///   small-n opportunity cost).
///
/// So dim-aware routing captures the profile win (the bulk of #441) with **zero**
/// semantic regression: vs the pre-#441 all-HNSW default only the profile family's
/// edges change (to the recall-non-decreasing exact set, see below), semantic edges
/// are unchanged. Both underlying paths are deterministic and the routing is a pure
/// function of each group's dim, so the pass stays byte-identical across runs.
pub const WEAVE_DENSE_ANN_STRATEGY_DIM_AWARE: u64 = 2;
/// Smallest legal dense ANN strategy ordinal (sequential HNSW).
pub const WEAVE_MIN_DENSE_ANN_STRATEGY: u64 = WEAVE_DENSE_ANN_STRATEGY_SEQUENTIAL_HNSW;
/// Largest legal dense ANN strategy ordinal (dim-aware routing).
pub const WEAVE_MAX_DENSE_ANN_STRATEGY: u64 = WEAVE_DENSE_ANN_STRATEGY_DIM_AWARE;
/// Default dense ANN strategy: global exact kNN (#1057). The earlier #441 CPU
/// matrix routed dim=768 to HNSW because CPU exact regressed at production N;
/// Forge's required CUDA executor removes that CPU wall-clock premise and buys
/// back exact candidate recall. Strategy `0` remains an explicit deterministic
/// HNSW comparison mode and strategy `2` remains an explicit dimension-aware
/// diagnostic mode; neither is selected after a CUDA failure.
pub const WEAVE_DEFAULT_DENSE_ANN_STRATEGY: u64 = WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN;
/// Environment override for the dense ANN strategy knob. A declared operator/probe
/// channel (not a hidden constant): the value is parsed as the knob ordinal and
/// **validated against the declaration's closed interval**. Unset selects the
/// declared default; present invalid input returns a structured refusal and no
/// weave generation may begin. This is the mechanism the #441 probe uses to exercise
/// global OFF (0, sequential HNSW) vs global ON (1, exact kNN) on one consolidated
/// binary; unset selects the global exact default (1).
pub const WEAVE_DENSE_ANN_STRATEGY_ENV: &str = "ASTRO_WEAVE_DENSE_ANN_STRATEGY";

/// Name of the dim-aware exact-kNN dimensionality cutoff knob (#441).
pub const WEAVE_DENSE_ANN_EXACT_MAX_DIM_KNOB: &str = "weave_dense_ann_exact_max_dim";
/// Environment override for the dim-aware exact-kNN cutoff.
pub const WEAVE_DENSE_ANN_EXACT_MAX_DIM_ENV: &str = "ASTRO_WEAVE_DENSE_ANN_EXACT_MAX_DIM";
/// Largest dense-group dimensionality for which the dim-aware strategy (2) selects
/// exact blocked kNN; groups with a larger dim use sequential HNSW (#441).
///
/// Default `1040`: the largest dimension for which signed-int8 dot/norm sums
/// remain strictly below `2^24`, making Forge's attested f32 reduction an exact
/// integer accumulation independent of reduction order. Wider dimensions need a
/// separately attested wider-accumulator kernel and therefore fail closed on the
/// global exact strategy.
pub const WEAVE_DEFAULT_DENSE_ANN_EXACT_MAX_DIM: u64 = 1_040;
/// Smallest legal cutoff: `24` (`RECORD_VEC` dim), so the low-dim profile family is
/// always eligible for exact kNN under the dim-aware strategy.
pub const WEAVE_MIN_DENSE_ANN_EXACT_MAX_DIM: u64 = 24;
/// Largest legal cutoff is the exact signed-int8 accumulation domain (`1040`).
pub const WEAVE_MAX_DENSE_ANN_EXACT_MAX_DIM: u64 = 1_040;

/// Explicit CPU parity/oracle mode. It is never selected after a CUDA error.
pub const WEAVE_EXACT_KNN_EXECUTOR_CPU: u64 = 0;
/// GPU-required production mode using Forge's attested resident CUDA operation.
pub const WEAVE_EXACT_KNN_EXECUTOR_CUDA: u64 = 1;
pub const WEAVE_DEFAULT_EXACT_KNN_EXECUTOR: u64 = WEAVE_EXACT_KNN_EXECUTOR_CUDA;
pub const WEAVE_MIN_EXACT_KNN_EXECUTOR: u64 = WEAVE_EXACT_KNN_EXECUTOR_CPU;
pub const WEAVE_MAX_EXACT_KNN_EXECUTOR: u64 = WEAVE_EXACT_KNN_EXECUTOR_CUDA;

/// The weave performance knob registry (#433).
pub const WEAVE_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: WEAVE_KNOB_REGISTRY_VERSION,
        name: WEAVE_NEIGHBORHOOD_SAMPLE_CAP_KNOB,
        default: WEAVE_DEFAULT_NEIGHBORHOOD_SAMPLE_CAP,
        min: WEAVE_MIN_NEIGHBORHOOD_SAMPLE_CAP,
        max: WEAVE_MAX_NEIGHBORHOOD_SAMPLE_CAP,
        unit: "peers",
        source: "Ray, Monath, McCallum & Musco, 'Sublinear Time Approximation of Text Similarity Matrices' (AAAI 2022, arXiv:2112.09631); Zadeh & Carlsson, 'Dimension Independent Similarity Computation' (ICML 2013, arXiv:1206.2082); Smith et al., 'On the distribution of cosine similarity' (arXiv:2310.13994, cosine variance O(1/n)); ASTROLABE #422 estimator sample cap (2048 plateau ≈5× Cochran 384)",
        rationale: "largest peer set a per-symbol neighborhood-agreement cross-term profile scores before a seeded without-replacement subsample bounds it; the profile cosine's Monte-Carlo variance is O(1/m), so m=2048 pins the agreement estimate within ≈0.022 noise while further peers cost O(n) for no accuracy; converts the per-kind cost from O(n²) to O(n·cap); a corpus with fewer comparable peers than the cap is scored whole; replace with a measured agreement-noise target once neighborhood-agreement variance is benchmarked on real corpora",
    },
    U64KnobDeclaration {
        registry_version: WEAVE_KNOB_REGISTRY_VERSION,
        name: WEAVE_SIMILARITY_WORKERS_KNOB,
        default: WEAVE_DEFAULT_SIMILARITY_WORKERS,
        min: WEAVE_MIN_SIMILARITY_WORKERS,
        max: WEAVE_MAX_SIMILARITY_WORKERS,
        unit: "workers",
        source: "ASTROLABE #433 similarity_plan phase measurement (single-threaded default left the largest weave sub-stage serial on a many-core host) and astrolabe-ingest SqliteImportOptions::with_workers(available_parallelism) precedent",
        rationale: "worker count for the similarity edge planner's exact-cosine rescoring; 0 resolves to std::thread::available_parallelism at call time exactly as the SQLite import sizes its corpus-wide passes; the sharding is proven byte-identical to the serial plan, so this changes only wall-clock, never the persisted edge set; the planner clamps the effective count to the source count",
    },
    U64KnobDeclaration {
        registry_version: WEAVE_KNOB_REGISTRY_VERSION,
        name: WEAVE_DENSE_ANN_STRATEGY_KNOB,
        default: WEAVE_DEFAULT_DENSE_ANN_STRATEGY,
        min: WEAVE_MIN_DENSE_ANN_STRATEGY,
        max: WEAVE_MAX_DENSE_ANN_STRATEGY,
        unit: "strategy_ordinal",
        source: "ASTROLABE #441 wave-24 real-corpus scaling matrix (astrolabe binary, ASTRO_SHADOW_TIMING, four real Rust corpora zoxide n=471 / ripgrep n=4,511 / atuin n=6,865 / bevy n=41,311): the seeded-HNSW candidate-index BUILD is the ~O(n²) weave sub-stage (bevy reproduced #441: ann_generate.SIM_PROFILE 135,951ms + SIM_SEMANTIC 121,571ms), and the exact-vs-HNSW crossover is dimensionality-dependent — exact kNN beats HNSW on low-dim SIM_PROFILE (dim=24) at every size (bevy 7.7×) but regresses ~9% on high-dim SIM_SEMANTIC (dim=768) at bevy scale; Zhu et al. 'SHINE: A Scalable HNSW Index in Disaggregated Memory' (arXiv:2507.17647) and hnswlib/usearch per-node-lock construction (parallel insert order is non-deterministic → different graph); myscale.com HNSW-vs-KNN and marqo.ai 'Understanding Recall in HNSW' (brute-force exact kNN is Θ(dim·n²), zero build overhead, 100% recall; HNSW never reaches 100%)",
        rationale: "selects the dense candidate producer: 0 = deterministic seeded HNSW comparison mode, 1 = global exact scalar8 kNN through the separately declared Forge executor (shipping default), 2 = explicit dimension-aware diagnostic routing; the #441 CPU-only crossover justified the old dim-aware default, but #1057 commissions the resident attested CUDA operation for both dim=24 and dim=768, so CPU wall-clock no longer selects an approximate graph; no strategy is selected as a fallback after executor failure",
    },
    U64KnobDeclaration {
        registry_version: WEAVE_KNOB_REGISTRY_VERSION,
        name: WEAVE_DENSE_ANN_EXACT_MAX_DIM_KNOB,
        default: WEAVE_DEFAULT_DENSE_ANN_EXACT_MAX_DIM,
        min: WEAVE_MIN_DENSE_ANN_EXACT_MAX_DIM,
        max: WEAVE_MAX_DENSE_ANN_EXACT_MAX_DIM,
        unit: "dimensions",
        source: "ASTROLABE #1057 signed-int8 exactness bound: 127^2 * 1040 = 16,774,160 < 2^24; Forge cuda-kernel-policy-v1 fixed reduction tree with fmad=false",
        rationale: "largest dense dimension eligible for Forge's exact scalar8 f32 accumulation contract; at or below 1040 every integer dot/norm partial sum is exactly representable regardless of reduction order; a wider group requires a separately attested wider-accumulator kernel and the global exact strategy fails closed",
    },
    U64KnobDeclaration {
        registry_version: WEAVE_KNOB_REGISTRY_VERSION,
        name: WEAVE_EXACT_KNN_EXECUTOR_KNOB,
        default: WEAVE_DEFAULT_EXACT_KNN_EXECUTOR,
        min: WEAVE_MIN_EXACT_KNN_EXECUTOR,
        max: WEAVE_MAX_EXACT_KNN_EXECUTOR,
        unit: "executor_ordinal",
        source: "ASTROLABE #1057 owner GPU directive and the 2026-08-12 self-host receipt (45,159 semantic vectors at dim=768); Forge cuda-kernel-policy-v1 exact sm_120a distance/topk attestation",
        rationale: "physical executor for every exact scalar8 kNN group: 0 is an explicit CPU oracle, 1 is the GPU-required production default; CUDA failure is returned unchanged and never selects CPU; the Forge operation uploads the pool once, reuses one query/score/top-k workspace, and persists a stable device/kernel/transfer receipt",
    },
];

/// Returns the weave declaration for `name`, or `None` when the knob is undeclared.
pub fn weave_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    WEAVE_KNOBS.iter().find(|knob| knob.name == name)
}

/// The resolved neighborhood peer sample cap as a `usize`. The single accessor the
/// weave cross-term planner uses (#433).
pub fn weave_neighborhood_sample_cap() -> usize {
    const VALUE: usize = {
        assert!(WEAVE_DEFAULT_NEIGHBORHOOD_SAMPLE_CAP <= usize::MAX as u64);
        WEAVE_DEFAULT_NEIGHBORHOOD_SAMPLE_CAP as usize
    };
    VALUE
}

/// Immutable, once-resolved configuration used by every similarity family.
///
/// `similarity_workers_requested=0` is the declared "use host parallelism"
/// sentinel. `similarity_workers_resolved` records the positive host count found
/// before admission; each scheduler receipt separately records the effective
/// count after clamping to its physical source cardinality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedSimilarityKnobs {
    registry_version: &'static str,
    dense_ann_strategy: u64,
    dense_ann_exact_max_dim: usize,
    exact_knn_executor: u64,
    similarity_workers_requested: u64,
    similarity_workers_resolved: usize,
}

impl ResolvedSimilarityKnobs {
    pub const fn registry_version(&self) -> &'static str {
        self.registry_version
    }

    pub const fn dense_ann_strategy(&self) -> u64 {
        self.dense_ann_strategy
    }

    pub const fn dense_ann_exact_max_dim(&self) -> usize {
        self.dense_ann_exact_max_dim
    }

    pub const fn exact_knn_executor(&self) -> u64 {
        self.exact_knn_executor
    }

    pub const fn similarity_workers_requested(&self) -> u64 {
        self.similarity_workers_requested
    }

    pub const fn similarity_workers_resolved(&self) -> usize {
        self.similarity_workers_resolved
    }

    /// Pure dense-group routing over already-resolved scalar configuration.
    pub fn dense_ann_use_exact(&self, dim: u32) -> Result<bool, WeaveRuntimeConfigError> {
        match self.dense_ann_strategy {
            WEAVE_DENSE_ANN_STRATEGY_SEQUENTIAL_HNSW => Ok(false),
            WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN => Ok(true),
            WEAVE_DENSE_ANN_STRATEGY_DIM_AWARE => {
                Ok(dim as usize <= self.dense_ann_exact_max_dim)
            }
            observed => Err(WeaveRuntimeConfigError {
                code: "ASTRO_WEAVE_RUNTIME_CONFIG_INVALID",
                message: format!(
                    "resolved dense ANN strategy {observed} is outside [{WEAVE_MIN_DENSE_ANN_STRATEGY}..={WEAVE_MAX_DENSE_ANN_STRATEGY}]"
                ),
                remediation:
                    "discard the invalid in-memory plan and resolve it again from the declared weave knob registry"
                        .to_string(),
                knob: WEAVE_DENSE_ANN_STRATEGY_KNOB,
                environment: None,
                observed_value: Some(observed.to_string()),
            }),
        }
    }
}

/// Structured runtime-configuration refusal. A present invalid override never
/// selects a default and never starts a weave generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WeaveRuntimeConfigError {
    pub code: &'static str,
    pub message: String,
    pub remediation: String,
    pub knob: &'static str,
    pub environment: Option<&'static str>,
    pub observed_value: Option<String>,
}

impl fmt::Display for WeaveRuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; remediation: {}",
            self.code, self.message, self.remediation
        )
    }
}

impl Error for WeaveRuntimeConfigError {}

fn invalid_override(
    code: &'static str,
    declaration: &'static U64KnobDeclaration,
    environment: &'static str,
    observed_value: Option<String>,
    reason: impl fmt::Display,
) -> WeaveRuntimeConfigError {
    WeaveRuntimeConfigError {
        code,
        message: format!(
            "{environment} cannot resolve declared knob {}: {reason}; accepted integer interval is [{}..={}]",
            declaration.name, declaration.min, declaration.max
        ),
        remediation: format!(
            "unset {environment} to select declared default {}, or set one base-10 integer in [{}..={}]",
            declaration.default, declaration.min, declaration.max
        ),
        knob: declaration.name,
        environment: Some(environment),
        observed_value,
    }
}

fn resolve_declared_override(
    knob: &'static str,
    environment: &'static str,
) -> Result<u64, WeaveRuntimeConfigError> {
    let declaration = weave_knob(knob).ok_or_else(|| WeaveRuntimeConfigError {
        code: "ASTRO_WEAVE_KNOB_DECLARATION_MISSING",
        message: format!("runtime resolver could not find declared weave knob {knob}"),
        remediation: "restore the knob declaration and registry entry before starting weave"
            .to_string(),
        knob,
        environment: Some(environment),
        observed_value: None,
    })?;
    let Some(raw_os) = std::env::var_os(environment) else {
        return Ok(declaration.default);
    };
    let raw = raw_os.into_string().map_err(|_| {
        invalid_override(
            "ASTRO_WEAVE_KNOB_NON_UNICODE",
            declaration,
            environment,
            None,
            "present value is not Unicode",
        )
    })?;
    if raw.is_empty() {
        return Err(invalid_override(
            "ASTRO_WEAVE_KNOB_EMPTY",
            declaration,
            environment,
            Some(raw),
            "present value is empty",
        ));
    }
    if raw != raw.trim() {
        return Err(invalid_override(
            "ASTRO_WEAVE_KNOB_WHITESPACE",
            declaration,
            environment,
            Some(raw),
            "present value contains leading or trailing whitespace",
        ));
    }
    let value = raw.parse::<u64>().map_err(|error| {
        invalid_override(
            "ASTRO_WEAVE_KNOB_NON_NUMERIC",
            declaration,
            environment,
            Some(raw.clone()),
            format_args!("present value is not a base-10 u64: {error}"),
        )
    })?;
    if !declaration.accepts(value) {
        return Err(invalid_override(
            "ASTRO_WEAVE_KNOB_OUT_OF_RANGE",
            declaration,
            environment,
            Some(raw),
            format_args!("parsed value {value} is outside the declaration"),
        ));
    }
    Ok(value)
}

fn usize_value(knob: &'static str, value: u64) -> Result<usize, WeaveRuntimeConfigError> {
    usize::try_from(value).map_err(|error| WeaveRuntimeConfigError {
        code: "ASTRO_WEAVE_KNOB_PLATFORM_RANGE",
        message: format!(
            "declared knob {knob} value {value} cannot be represented as usize on this native target: {error}"
        ),
        remediation:
            "preserve the requested configuration and run the supported native Windows x86_64 artifact"
                .to_string(),
        knob,
        environment: None,
        observed_value: Some(value.to_string()),
    })
}

/// Resolve every output- or scheduling-affecting similarity knob exactly once.
///
/// Resolution is O(1), performs no corpus/store access, and has no substitute
/// path: present invalid input or host-parallelism discovery failure returns a
/// structured error before admission identity or generation publication.
pub fn resolve_similarity_knobs() -> Result<ResolvedSimilarityKnobs, WeaveRuntimeConfigError> {
    let dense_ann_strategy =
        resolve_declared_override(WEAVE_DENSE_ANN_STRATEGY_KNOB, WEAVE_DENSE_ANN_STRATEGY_ENV)?;
    let exact_max_dim = resolve_declared_override(
        WEAVE_DENSE_ANN_EXACT_MAX_DIM_KNOB,
        WEAVE_DENSE_ANN_EXACT_MAX_DIM_ENV,
    )?;
    let exact_knn_executor =
        resolve_declared_override(WEAVE_EXACT_KNN_EXECUTOR_KNOB, WEAVE_EXACT_KNN_EXECUTOR_ENV)?;
    let similarity_workers_requested =
        resolve_declared_override(WEAVE_SIMILARITY_WORKERS_KNOB, WEAVE_SIMILARITY_WORKERS_ENV)?;
    let similarity_workers_resolved = if similarity_workers_requested == 0 {
        std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .map_err(|error| WeaveRuntimeConfigError {
                code: "ASTRO_WEAVE_HOST_PARALLELISM_UNAVAILABLE",
                message: format!(
                    "host parallelism discovery failed while resolving declared knob {WEAVE_SIMILARITY_WORKERS_KNOB}: {error}"
                ),
                remediation: format!(
                    "set {WEAVE_SIMILARITY_WORKERS_ENV} to an explicit integer in [1..={WEAVE_MAX_SIMILARITY_WORKERS}] after diagnosing the native host query"
                ),
                knob: WEAVE_SIMILARITY_WORKERS_KNOB,
                environment: Some(WEAVE_SIMILARITY_WORKERS_ENV),
                observed_value: Some(similarity_workers_requested.to_string()),
            })?
    } else {
        usize_value(WEAVE_SIMILARITY_WORKERS_KNOB, similarity_workers_requested)?
    };

    Ok(ResolvedSimilarityKnobs {
        registry_version: WEAVE_KNOB_REGISTRY_VERSION,
        dense_ann_strategy,
        dense_ann_exact_max_dim: usize_value(WEAVE_DENSE_ANN_EXACT_MAX_DIM_KNOB, exact_max_dim)?,
        exact_knn_executor,
        similarity_workers_requested,
        similarity_workers_resolved,
    })
}
