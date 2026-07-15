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
