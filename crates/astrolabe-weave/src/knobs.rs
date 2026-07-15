//! Registry-declared knobs owned by the weave crate (standing invariant 4).
//!
//! Every budget, cap, or worker count the weave path depends on is a *declared*
//! knob with explicit bounds, a unit, a source, and a rationale — never a bare
//! constant. The declaration type is reused from `astrolabe-domain` so the whole
//! workspace shares one knob shape, exactly as `astrolabe-assay`'s knob registry
//! does (`ASSAY_BITS_KNOBS`).

use astrolabe_domain::knobs::U64KnobDeclaration;

/// Registry version tag for the weave performance knobs (#433).
pub const WEAVE_KNOB_REGISTRY_VERSION: &str = "astrolabe-weave-knobs-v1";

/// Name of the neighborhood cross-term peer sample-cap knob.
pub const WEAVE_NEIGHBORHOOD_SAMPLE_CAP_KNOB: &str = "weave_neighborhood_sample_cap";
/// Name of the similarity-planner worker-count knob.
pub const WEAVE_SIMILARITY_WORKERS_KNOB: &str = "weave_similarity_workers";
/// Name of the dense ANN candidate-build strategy knob (#441).
pub const WEAVE_DENSE_ANN_STRATEGY_KNOB: &str = "weave_dense_ann_strategy";

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
/// Dense ANN candidate-build strategy (#441): deterministic, parallel, **exact**
/// blocked kNN over the identical scalar8-quantized approximations.
///
/// `1` replaces the sequential HNSW build+query with a per-source exact top-k scan
/// over the same quantized pool the HNSW path scores (`k = per_node_cap ×
/// candidate_multiplier + 1`, the identical candidate breadth), sharded across the
/// `weave_similarity_workers` count exactly as #433 shards the HNSW queries. It has
/// **no graph, no RNG, and no cross-source mutation**: every source's neighbor list
/// is a pure function of the frozen quantized pool, so the pass is embarrassingly
/// parallel, byte-identical across runs and worker counts, and cannot deadlock or
/// reorder. Rationale (#441): the seeded-HNSW *build* is the remaining superlinear
/// weave sub-stage (`ann_generate.SIM_PROFILE` 136,956ms at n=45,557, ~O(n²) from
/// the exhaustive-construction prefix and per-insert back-edge pruning), and exact
/// blocked kNN is Θ(dim·n²) with a tiny SIMD-friendly constant and perfect
/// parallelism — for the sizes involved (< ~50k dense vectors, RECORD_VEC dim=24 /
/// embedding dim) brute-force exact kNN is both cheaper in wall-clock than the
/// already-O(n²) graph build and *exact* where HNSW is approximate (myscale.com,
/// marqo.ai: brute force has zero build overhead and 100% recall for <50k vectors;
/// HNSW never reaches 100% recall). Candidate-recall argument (standing invariant 3
/// / #441 output-equivalence): the exact top-k over the quantized pool is a strict
/// improvement in approximation of the exhaustive raw-cosine ground truth over
/// HNSW's approximate graph search on the *same* quantized pool — it removes the
/// graph-approximation error layer while keeping the shared quantization layer — so
/// recall against the exhaustive planner cannot drop; specific edges the HNSW graph
/// missed are *added*, and the rescoring per-node cap admits the higher raw-cosine
/// pairs. Any resulting edge_dump drift is therefore a labeled, recall-improving
/// change, disclosed and measured on the driving issue — never silent.
pub const WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN: u64 = 1;
/// Smallest legal dense ANN strategy ordinal (sequential HNSW).
pub const WEAVE_MIN_DENSE_ANN_STRATEGY: u64 = WEAVE_DENSE_ANN_STRATEGY_SEQUENTIAL_HNSW;
/// Largest legal dense ANN strategy ordinal (exact blocked kNN).
pub const WEAVE_MAX_DENSE_ANN_STRATEGY: u64 = WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN;
/// Default dense ANN strategy: the sequential seeded-HNSW build (#441). Held at the
/// byte-parity-safe value until the exact strategy's edge_dump parity/drift is
/// measured on real corpora by the orchestrator; an operator (or that probe) selects
/// the exact strategy via the `ASTRO_WEAVE_DENSE_ANN_STRATEGY` override below.
pub const WEAVE_DEFAULT_DENSE_ANN_STRATEGY: u64 = WEAVE_DENSE_ANN_STRATEGY_SEQUENTIAL_HNSW;
/// Environment override for the dense ANN strategy knob. A declared operator/probe
/// channel (not a hidden constant): the value is parsed as the knob ordinal and
/// **validated against the declaration's closed interval** — an unset, unparseable,
/// or out-of-range value fails closed to [`WEAVE_DEFAULT_DENSE_ANN_STRATEGY`], never
/// to an undeclared value. This is the single mechanism the #441 probe uses to
/// exercise OFF (sequential HNSW) vs ON (exact kNN) on one consolidated binary.
pub const WEAVE_DENSE_ANN_STRATEGY_ENV: &str = "ASTRO_WEAVE_DENSE_ANN_STRATEGY";

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
        source: "ASTROLABE #441 ann_generate build profile (SIM_PROFILE 136,956ms + SIM_SEMANTIC 56,890ms at n=45,557: the seeded-HNSW candidate-index BUILD is the remaining ~O(n²) weave sub-stage, inserts sequential by design for determinism); Zhu et al. 'SHINE: A Scalable HNSW Index in Disaggregated Memory' (arXiv:2507.17647) and hnswlib/usearch per-node-lock construction (parallel insert order is non-deterministic → different graph); myscale.com HNSW-vs-KNN and marqo.ai 'Understanding Recall in HNSW' (brute-force exact kNN is Θ(dim·n²) with zero build overhead and 100% recall for <50k vectors, where HNSW never reaches 100%); Chen & Cai 'Fast Approximate kNN Graph Construction' (JMLR 2009, NN-descent) as the surveyed approximate-graph alternative",
        rationale: "selects the dense ANN candidate-index build: 0 = the #433 sequential seeded-HNSW build/query (strictly sequential because each insert mutates earlier rows' back-edges; a parallel insert reorders those mutations into a different graph, so bit-determinism is impossible under parallel insert), 1 = deterministic parallel EXACT blocked kNN over the identical scalar8-quantized pool with the identical candidate breadth (k = per_node_cap·candidate_multiplier+1), sharded over weave_similarity_workers with no graph/RNG/cross-source mutation so it is byte-identical across runs and worker counts; the exact strategy removes only the graph-approximation error layer over the shared quantization layer, so candidate recall vs the exhaustive planner cannot drop and any edge_dump change is a labeled recall-improving drift measured on #441; default holds at 0 (byte-parity-safe) until that probe proves parity, and the ASTRO_WEAVE_DENSE_ANN_STRATEGY env override (clamped to this declaration) selects the strategy for benches/probes; replace the default with the exact strategy once its real-corpus parity/drift and wall-clock are recorded",
    },
];

/// Returns the weave declaration for `name`, or `None` when the knob is undeclared.
pub fn weave_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    WEAVE_KNOBS.iter().find(|knob| knob.name == name)
}

/// The resolved neighborhood peer sample cap as a `usize`. The single accessor the
/// weave cross-term planner uses (#433).
pub fn weave_neighborhood_sample_cap() -> usize {
    usize::try_from(WEAVE_DEFAULT_NEIGHBORHOOD_SAMPLE_CAP).unwrap_or(2_048)
}

/// The resolved similarity-planner worker count as a `usize` (#433). `0` (the
/// default) resolves to the measured host parallelism, clamped to at least one, so
/// the planner shards its rescoring across every available core; a positive knob
/// value pins an explicit count. The planner further clamps the effective count to
/// the source count.
pub fn weave_similarity_workers() -> usize {
    match usize::try_from(WEAVE_DEFAULT_SIMILARITY_WORKERS).unwrap_or(0) {
        0 => std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1)
            .max(1),
        explicit => explicit,
    }
}

/// The resolved dense ANN candidate-build strategy ordinal (#441).
///
/// Resolves the [`WEAVE_DENSE_ANN_STRATEGY_ENV`] override, parses it as the knob
/// ordinal, and **fails closed** to [`WEAVE_DEFAULT_DENSE_ANN_STRATEGY`] when the
/// value is unset, unparseable, or outside the declared closed interval — an
/// operator can never select an undeclared strategy. When the override is absent
/// the shipped default is returned, so the sequential-HNSW path is byte-identical
/// to the pre-#441 build.
pub fn weave_dense_ann_strategy() -> u64 {
    let declaration = weave_knob(WEAVE_DENSE_ANN_STRATEGY_KNOB);
    std::env::var(WEAVE_DENSE_ANN_STRATEGY_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| declaration.is_some_and(|knob| knob.accepts(*value)))
        .unwrap_or(WEAVE_DEFAULT_DENSE_ANN_STRATEGY)
}

/// Whether the deterministic parallel exact blocked-kNN dense ANN strategy is
/// selected (#441). `false` is the sequential seeded-HNSW build (the shipped
/// default and byte-parity baseline).
pub fn weave_dense_ann_exact() -> bool {
    weave_dense_ann_strategy() == WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN
}
