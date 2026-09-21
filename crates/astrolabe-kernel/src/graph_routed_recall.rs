//! Exact admission evidence for bounded graph-routed kernel retrieval (#1148).
//!
//! Kernel members are routing entry points into the complete association graph;
//! they are never treated as a replacement for the vector corpus.  Every
//! admission query is an independently persisted real-query record whose
//! [`CxId`] is disjoint from the graph and kernel-entry rosters, and is
//! evaluated against an exhaustive cosine ranking over the complete corpus.
//! The routed ranking is produced by a deterministic best-first walk over the
//! weak projection of the exact source graph.  Exhausting the caller's route
//! budget is a refusal, never a truncated success or an exhaustive serving
//! fallback.
//!
//! Cost contract (#1064, PC-03/07/16/24/37/38/41): against the production
//! source measured 2026-08-20 at N=192,873 and E=328,899, setup compiles one
//! weak graph, independently derives one source identity, and performs one
//! fused vector validation/hash pass; admission's exact oracle consumes
//! `Q * N * D` scalar coordinates plus bounded `Q * N * log(top_k)` ranking
//! comparisons; routing consumes at most `Q * (K + C) * D` scalar coordinates
//! under the explicit per-query distance ceiling.  Source, projection, vector,
//! entry, query, and parameter identities are invariant for the complete
//! report generation.  This evaluator belongs
//! at generation admission/readback, never on an ordinary answer request.  The
//! public persisted-state validator deliberately pays one second complete
//! evaluation against separately read authoritative inputs; that is the
//! independent readback boundary, not an ordinary duplicate pipeline pass.

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kernel_build::{
    KERNEL_ARTIFACT_SCHEMA, KernelArtifact, KernelProjectionIdentity, KernelSourceIdentity,
    kernel_source_identity, members_hash,
};
use crate::kernel_graph::{IndexedGraph, KernelGraph};

/// Persisted report schema.
pub const GRAPH_ROUTED_RECALL_SCHEMA: &str = "astrolabe.kernel.graph_routed_recall.v2";
/// Exact deterministic search semantics bound into every report.
pub const GRAPH_ROUTED_SEARCH_SEMANTICS: &str =
    "query_exact_kernel_entries.weak_graph_best_first.exact_cosine_bits.v1";
/// Exact query-selection contract bound into every report.
pub const GRAPH_ROUTED_QUERY_SEMANTICS: &str =
    "persisted_external_query.cxid_framed_stable_source_content_v1.disjoint_complete_graph.v2";
/// Hash framing used for every report-owned identity digest.
pub const GRAPH_ROUTED_HASH_SEMANTICS: &str = "sha256.length_delimited_be_u128.v1";

/// The source graph, artifact, vector roster, or derived identity drifted.
pub const ASTRO_KERNEL_ROUTE_IDENTITY_DRIFT: &str = "ASTRO_KERNEL_ROUTE_IDENTITY_DRIFT";
/// A required graph, entry, vector, or real-query roster is empty.
pub const ASTRO_KERNEL_ROUTE_EMPTY_INPUT: &str = "ASTRO_KERNEL_ROUTE_EMPTY_INPUT";
/// The weak graph has no non-self edge over which retrieval can route.
pub const ASTRO_KERNEL_ROUTE_NO_EDGES: &str = "ASTRO_KERNEL_ROUTE_NO_EDGES";
/// A vector is missing, malformed, non-finite, zero-norm, or dimensionally inconsistent.
pub const ASTRO_KERNEL_ROUTE_VECTOR_INVALID: &str = "ASTRO_KERNEL_ROUTE_VECTOR_INVALID";
/// A real-query roster is malformed, duplicated, or overlaps the graph corpus.
pub const ASTRO_KERNEL_ROUTE_QUERY_INVALID: &str = "ASTRO_KERNEL_ROUTE_QUERY_INVALID";
/// Caller-supplied evaluation controls are internally inconsistent.
pub const ASTRO_KERNEL_ROUTE_PARAMS_INVALID: &str = "ASTRO_KERNEL_ROUTE_PARAMS_INVALID";
/// Exact or routed distance work would exceed the caller-supplied hard ceiling.
pub const ASTRO_KERNEL_ROUTE_BUDGET_EXCEEDED: &str = "ASTRO_KERNEL_ROUTE_BUDGET_EXCEEDED";
/// A route completed but could not produce the requested number of candidates.
pub const ASTRO_KERNEL_ROUTE_INSUFFICIENT_CANDIDATES: &str =
    "ASTRO_KERNEL_ROUTE_INSUFFICIENT_CANDIDATES";
/// The exact member fraction exceeds the caller-supplied compactness ceiling.
pub const ASTRO_KERNEL_ROUTE_COMPACTNESS_EXCEEDED: &str = "ASTRO_KERNEL_ROUTE_COMPACTNESS_EXCEEDED";
/// Aggregate exact recall is below the caller-supplied admission floor.
pub const ASTRO_KERNEL_ROUTE_RECALL_BELOW_FLOOR: &str = "ASTRO_KERNEL_ROUTE_RECALL_BELOW_FLOOR";
/// Persisted report fields do not reproduce their rosters, hashes, counters, or aggregates.
pub const ASTRO_KERNEL_ROUTE_REPORT_INVALID: &str = "ASTRO_KERNEL_ROUTE_REPORT_INVALID";

/// Caller-owned controls for one exact graph-routed recall admission.
///
/// There is deliberately no [`Default`] implementation: every work ceiling and
/// admission threshold is a measured caller decision and is persisted in the
/// report identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRoutedRecallParams {
    /// Number of exact results retained for each query.
    pub top_k: usize,
    /// Exact persisted corpus/query vector dimension expected by this admission.
    pub expected_vector_dimension: usize,
    /// Number of exact query-nearest kernel members used as route entries.
    pub entry_point_count: usize,
    /// Maximum number of scored corpus candidates retained by best-first routing.
    pub ef_search: usize,
    /// Hard ceiling on entry plus graph-neighbour cosine computations per query.
    pub max_route_distance_computations_per_query: usize,
    /// Hard ceiling on exhaustive-oracle cosine computations for the full query roster.
    pub max_exact_distance_computations: usize,
    /// Minimum admitted aggregate recall, in integer permille (`1..=1000`).
    pub min_recall_permille: u64,
    /// Maximum admitted exact kernel-member fraction, in permille (`1..=999`).
    pub max_kernel_member_fraction_permille: u64,
}

/// One independently persisted real query used for recall admission.
///
/// The caller obtains this row from its authoritative query corpus; this module
/// never selects graph nodes, fabricates text, synthesizes vectors, or derives
/// pseudo-queries.  `query_cx_id` is domain-separated from `stable_id`,
/// `source`, and the exact UTF-8 `content`; `content_hash` is the lowercase
/// SHA-256 of those content bytes; and `vector` is that same record's persisted
/// embedding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRoutedQuery {
    /// Stable source-local identifier of the persisted query record.
    pub stable_id: String,
    /// Exact source/query-log identity from which the record was read.
    pub source: String,
    /// Exact persisted UTF-8 query content used to derive hashes and identity.
    pub content: String,
    /// Content-addressed external-query identity; it must not be a graph node.
    pub query_cx_id: CxId,
    /// Lowercase SHA-256 of the exact persisted query content.
    pub content_hash: String,
    /// Persisted finite, nonzero vector in the complete corpus dimension.
    pub vector: Vec<f32>,
}

/// One result identity and the exact IEEE-754 bits of its cosine score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRoutedScoredIdentity {
    /// Persisted corpus identity.
    pub cx_id: CxId,
    /// Exact `f32::to_bits` value used for ranking.
    pub cosine_bits: u32,
}

impl GraphRoutedScoredIdentity {
    /// Reconstructs the finite cosine value carried by [`Self::cosine_bits`].
    pub fn cosine(self) -> f32 {
        f32::from_bits(self.cosine_bits)
    }
}

/// Persistable proof for one independently persisted real query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRoutedRecallQueryEvidence {
    /// Persisted external-query identity.
    pub query_cx_id: CxId,
    /// Stable source-local identifier bound into [`Self::query_cx_id`].
    pub query_stable_id: String,
    /// Exact source/query-log identity bound into [`Self::query_cx_id`].
    pub query_source: String,
    /// Lowercase SHA-256 of the exact persisted query content.
    pub query_content_hash: String,
    /// Lowercase SHA-256 of the exact persisted query vector bits.
    pub query_vector_hash: String,
    /// Exact query-nearest kernel entries, in score order.
    pub entry_points: Vec<GraphRoutedScoredIdentity>,
    /// Exhaustive top-k over every vector in the complete graph corpus.
    pub exact_full_hits: Vec<GraphRoutedScoredIdentity>,
    /// Bounded graph-routed top-k after exact reranking.
    pub routed_hits: Vec<GraphRoutedScoredIdentity>,
    /// Number of exact-hit identities also present in the routed hit roster.
    pub matched_hit_count: usize,
    /// Per-query recall in integer permille.
    pub recall_permille: u64,
    /// Number of unique graph identities encountered by the route walk, including seeds.
    pub visited_node_count: usize,
    /// Hash of the ascending visited identity set.
    pub visited_node_ids_hash: String,
    /// Number of corpus candidates retained when routing terminated.
    pub retained_candidate_count: usize,
    /// Hash of the ascending retained-candidate identity set.
    pub retained_candidate_ids_hash: String,
    /// Number of candidates removed from the best-first frontier for expansion.
    pub frontier_pop_count: usize,
    /// Exact cosine work used to rank every kernel entry.
    pub entry_distance_computations: usize,
    /// Exact cosine work used for newly visited non-entry graph neighbours.
    pub routed_distance_computations: usize,
    /// Sum of entry and routed distance computations.
    pub route_distance_computations: usize,
    /// Exhaustive comparator distance computations (`node_count`).
    pub exact_distance_computations: usize,
}

/// Complete, content-bound graph-routed recall admission evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRoutedRecallReport {
    /// Report schema discriminator.
    pub schema: String,
    /// Search semantics discriminator.
    pub search_semantics: String,
    /// Query roster semantics discriminator.
    pub query_semantics: String,
    /// Hash algorithm and part-framing discriminator.
    pub hash_semantics: String,
    /// Exact kernel source identity reproduced from the graph and build configuration.
    pub source_identity: KernelSourceIdentity,
    /// SHA-256 hash of the complete embedded source-identity record.
    pub source_identity_hash: String,
    /// Exact projection-only identity reproduced from the graph.
    pub projection_identity: KernelProjectionIdentity,
    /// Hash binding every projection identity field.
    pub projection_identity_hash: String,
    /// Hash of the complete serialized kernel artifact used for entries.
    pub kernel_artifact_hash: String,
    /// Hash of every complete-corpus identity and exact vector component bit.
    pub vector_roster_hash: String,
    /// Hash of the exact ascending kernel-entry identity roster.
    pub entry_roster_hash: String,
    /// Hash of the exact ascending real-query identity roster.
    pub query_roster_hash: String,
    /// Hash of every caller-supplied parameter.
    pub params_hash: String,
    /// Complete source node count.
    pub node_count: usize,
    /// Complete source directed-edge row count.
    pub directed_edge_count: usize,
    /// Unique non-self edge count in the weak routing projection.
    pub weak_edge_count: usize,
    /// Shared complete-corpus vector dimension.
    pub vector_dimension: usize,
    /// Exact ascending kernel entry roster.
    pub entry_member_ids: Vec<CxId>,
    /// Exact ascending real-query roster.
    pub query_ids: Vec<CxId>,
    /// Caller-owned controls used by this admission.
    pub params: GraphRoutedRecallParams,
    /// Exact kernel member count.
    pub kernel_member_count: usize,
    /// Exact floor of `kernel_member_count * 1000 / node_count`.
    pub kernel_member_fraction_permille: u64,
    /// Whether exact cross-multiplication satisfies the persisted compactness ceiling.
    pub compactness_admitted: bool,
    /// Per-query evidence in ascending query-identity order.
    pub queries: Vec<GraphRoutedRecallQueryEvidence>,
    /// Sum of per-query exact/routed hit-identity overlaps.
    pub matched_hit_count: usize,
    /// `query_count * top_k`, the aggregate recall denominator.
    pub relevant_hit_count: usize,
    /// Aggregate exact recall in integer permille.
    pub recall_permille: u64,
    /// Minimum route distance work across queries.
    pub min_route_distance_computations: usize,
    /// Maximum route distance work across queries.
    pub max_route_distance_computations: usize,
    /// Total route distance work across queries.
    pub total_route_distance_computations: usize,
    /// Total exhaustive-oracle distance work across queries.
    pub total_exact_distance_computations: usize,
    /// Minimum unique visited-node count across queries.
    pub min_visited_node_count: usize,
    /// Maximum unique visited-node count across queries.
    pub max_visited_node_count: usize,
    /// Total unique visited-node counts across queries.
    pub total_visited_node_count: usize,
    /// Minimum retained-candidate count across queries.
    pub min_retained_candidate_count: usize,
    /// Maximum retained-candidate count across queries.
    pub max_retained_candidate_count: usize,
    /// Total retained-candidate counts across queries.
    pub total_retained_candidate_count: usize,
    /// True only after both exact recall and compactness admission succeed.
    pub admitted: bool,
    /// Hash of the complete report with this field cleared.
    pub report_hash: String,
}

impl GraphRoutedRecallReport {
    /// Returns deterministic pretty JSON bytes after validating all internal
    /// rosters, counters, aggregates, parameter hashes, and the report hash.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>> {
        validate_report_structure(self)?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            report_error(format!(
                "graph-routed report could not be serialized after validation: {error}"
            ))
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Builds exact graph-routed recall admission evidence from current source state.
///
/// The complete vector map must have exactly the graph's identity set.  The
/// real-query slice must be nonempty, strictly ordered by query identity, and
/// disjoint from the entire graph (and therefore from every kernel entry).  A
/// report is returned only when both the explicit recall floor and compactness
/// ceiling are satisfied.
pub fn evaluate_graph_routed_recall(
    graph: &KernelGraph,
    kernel: &KernelArtifact,
    complete_vectors: &BTreeMap<CxId, Vec<f32>>,
    real_queries: &[GraphRoutedQuery],
    params: &GraphRoutedRecallParams,
) -> Result<GraphRoutedRecallReport> {
    build_report(graph, kernel, complete_vectors, real_queries, params)
}

/// Independently rebuilds a persisted report from the authoritative graph,
/// artifact, complete vector map, query roster, and expected parameters.
///
/// Return-value equality is not trusted: the function first validates the
/// persisted report's own rosters/counters/hashes, then executes a separate
/// full evaluation and requires exact structural equality including every
/// cosine bit and work counter.
pub fn validate_graph_routed_recall_report(
    report: &GraphRoutedRecallReport,
    graph: &KernelGraph,
    kernel: &KernelArtifact,
    complete_vectors: &BTreeMap<CxId, Vec<f32>>,
    real_queries: &[GraphRoutedQuery],
    expected_params: &GraphRoutedRecallParams,
) -> Result<()> {
    validate_report_structure(report)?;
    if &report.params != expected_params {
        return Err(identity_error(format!(
            "graph-routed parameter drift: persisted={:?} expected={expected_params:?}; persisted_params_hash={} expected_params_hash={}",
            report.params,
            report.params_hash,
            params_hash(expected_params),
        )));
    }
    let rebuilt = build_report(
        graph,
        kernel,
        complete_vectors,
        real_queries,
        expected_params,
    )?;
    if &rebuilt != report {
        return Err(identity_error(format!(
            "graph-routed report readback drift: persisted_report_hash={} rebuilt_report_hash={} source expected={} observed={} projection expected={} observed={} vectors expected={} observed={} entries expected={} observed={} queries expected={} observed={} params expected={} observed={}",
            report.report_hash,
            rebuilt.report_hash,
            report.source_identity_hash,
            rebuilt.source_identity_hash,
            report.projection_identity_hash,
            rebuilt.projection_identity_hash,
            report.vector_roster_hash,
            rebuilt.vector_roster_hash,
            report.entry_roster_hash,
            rebuilt.entry_roster_hash,
            report.query_roster_hash,
            rebuilt.query_roster_hash,
            report.params_hash,
            rebuilt.params_hash,
        )));
    }
    Ok(())
}

/// Computes the exact artifact hash stored in
/// [`GraphRoutedRecallReport::kernel_artifact_hash`].
///
/// Atomic publishers use this function rather than duplicating the report's
/// domain separation or byte framing.  The hash covers the canonical
/// [`KernelArtifact::kernel_json_bytes`] representation.
pub fn graph_routed_kernel_artifact_hash(kernel: &KernelArtifact) -> String {
    bytes_hash(
        b"astro.kernel.graph_route.kernel_artifact.v1\0",
        &kernel.kernel_json_bytes(),
    )
}

/// Computes the lowercase SHA-256 required by [`GraphRoutedQuery::content_hash`]
/// from the exact persisted query bytes.
pub fn graph_routed_query_content_hash(content: &[u8]) -> String {
    hex_lower(&Sha256::digest(content))
}

/// Derives the domain-separated external-query identity from the exact
/// `{stable_id, source, content bytes}` tuple.
///
/// The fixed `panel_version=1` passed to [`CxId::from_input`] is the version of
/// this query-identity schema, not an observed embedding-panel value.  Embedding
/// identity is bound separately by the exact query-vector hash in the report.
pub fn graph_routed_query_cx_id(stable_id: &str, source: &str, content: &[u8]) -> CxId {
    let mut canonical = Vec::with_capacity(
        stable_id
            .len()
            .saturating_add(source.len())
            .saturating_add(content.len())
            .saturating_add(64),
    );
    append_query_identity_part(
        &mut canonical,
        b"astro.kernel.graph_route.external_query.v1",
    );
    append_query_identity_part(&mut canonical, stable_id.as_bytes());
    append_query_identity_part(&mut canonical, source.as_bytes());
    append_query_identity_part(&mut canonical, content);
    CxId::from_input(
        &canonical,
        1,
        b"astro.kernel.graph_route.external_query.cxid.v1",
    )
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    cx_id: CxId,
    node_index: usize,
    score: f32,
}

impl Candidate {
    fn scored_identity(self) -> GraphRoutedScoredIdentity {
        GraphRoutedScoredIdentity {
            cx_id: self.cx_id,
            cosine_bits: self.score.to_bits(),
        }
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.cx_id.cmp(&self.cx_id))
    }
}

struct ValidatedInputs<'a> {
    indexed: IndexedGraph,
    vectors: &'a BTreeMap<CxId, Vec<f32>>,
    vector_dimension: usize,
    entries: Vec<CxId>,
    query_ids: Vec<CxId>,
    queries: &'a [GraphRoutedQuery],
    query_vector_hashes: BTreeMap<CxId, String>,
    weak_edge_count: usize,
    source_identity: KernelSourceIdentity,
    source_identity_hash: String,
    projection_identity: KernelProjectionIdentity,
    projection_identity_hash: String,
    kernel_artifact_hash: String,
    vector_roster_hash: String,
    entry_roster_hash: String,
    query_roster_hash: String,
    params_hash: String,
    kernel_member_fraction_permille: u64,
    compactness_admitted: bool,
}

struct RouteOutcome {
    entry_points: Vec<GraphRoutedScoredIdentity>,
    hits: Vec<GraphRoutedScoredIdentity>,
    visited_node_count: usize,
    visited_node_ids_hash: String,
    retained_candidate_count: usize,
    retained_candidate_ids_hash: String,
    frontier_pop_count: usize,
    entry_distance_computations: usize,
    routed_distance_computations: usize,
}

fn build_report(
    graph: &KernelGraph,
    kernel: &KernelArtifact,
    complete_vectors: &BTreeMap<CxId, Vec<f32>>,
    real_queries: &[GraphRoutedQuery],
    params: &GraphRoutedRecallParams,
) -> Result<GraphRoutedRecallReport> {
    let input = validate_inputs(graph, kernel, complete_vectors, real_queries, params)?;

    let mut queries = Vec::with_capacity(input.query_ids.len());
    for query in input.queries {
        let query_cx_id = query.query_cx_id;
        let exact_full_hits =
            exact_full_hits(query_cx_id, &query.vector, input.vectors, params.top_k)?;
        let routed = route_query(&input, query_cx_id, &query.vector, params)?;
        let exact_ids = exact_full_hits
            .iter()
            .map(|hit| hit.cx_id)
            .collect::<BTreeSet<_>>();
        let matched_hit_count = routed
            .hits
            .iter()
            .filter(|hit| exact_ids.contains(&hit.cx_id))
            .count();
        let recall_permille = ratio_permille(matched_hit_count, params.top_k)?;
        let route_distance_computations = routed
            .entry_distance_computations
            .checked_add(routed.routed_distance_computations)
            .ok_or_else(|| {
                budget_error(
                    "route_counter_overflow",
                    query_cx_id,
                    usize::MAX,
                    params.max_route_distance_computations_per_query,
                    routed.entry_distance_computations,
                    routed.routed_distance_computations,
                )
            })?;
        queries.push(GraphRoutedRecallQueryEvidence {
            query_cx_id,
            query_stable_id: query.stable_id.clone(),
            query_source: query.source.clone(),
            query_content_hash: query.content_hash.clone(),
            query_vector_hash: input
                .query_vector_hashes
                .get(&query_cx_id)
                .cloned()
                .ok_or_else(|| {
                    identity_error(format!(
                        "validated external query {query_cx_id} lost its vector hash"
                    ))
                })?,
            entry_points: routed.entry_points,
            exact_full_hits,
            routed_hits: routed.hits,
            matched_hit_count,
            recall_permille,
            visited_node_count: routed.visited_node_count,
            visited_node_ids_hash: routed.visited_node_ids_hash,
            retained_candidate_count: routed.retained_candidate_count,
            retained_candidate_ids_hash: routed.retained_candidate_ids_hash,
            frontier_pop_count: routed.frontier_pop_count,
            entry_distance_computations: routed.entry_distance_computations,
            routed_distance_computations: routed.routed_distance_computations,
            route_distance_computations,
            exact_distance_computations: input.indexed.len(),
        });
    }

    let matched_hit_count = checked_sum(
        queries.iter().map(|query| query.matched_hit_count),
        "matched-hit aggregate",
    )?;
    let relevant_hit_count = input
        .query_ids
        .len()
        .checked_mul(params.top_k)
        .ok_or_else(|| params_error("query_count * top_k overflowed usize"))?;
    let recall_permille = ratio_permille(matched_hit_count, relevant_hit_count)?;
    let total_route_distance_computations = checked_sum(
        queries
            .iter()
            .map(|query| query.route_distance_computations),
        "route-distance aggregate",
    )?;
    let total_exact_distance_computations = checked_sum(
        queries
            .iter()
            .map(|query| query.exact_distance_computations),
        "exact-distance aggregate",
    )?;
    let total_visited_node_count = checked_sum(
        queries.iter().map(|query| query.visited_node_count),
        "visited-node aggregate",
    )?;
    let total_retained_candidate_count = checked_sum(
        queries.iter().map(|query| query.retained_candidate_count),
        "retained-candidate aggregate",
    )?;

    if recall_permille < params.min_recall_permille {
        let worst_query = queries
            .iter()
            .min_by(|left, right| {
                left.recall_permille
                    .cmp(&right.recall_permille)
                    .then_with(|| left.query_cx_id.cmp(&right.query_cx_id))
            })
            .ok_or_else(|| empty_error("query evidence roster is empty after evaluation"))?;
        return Err(DomainError::new(
            ASTRO_KERNEL_ROUTE_RECALL_BELOW_FLOOR,
            format!(
                "graph-routed recall admission failed: matched_hits={matched_hit_count} relevant_hits={relevant_hit_count} observed_permille={recall_permille} declared_floor_permille={} queries={} top_k={} worst_query={} worst_query_recall_permille={} worst_query_visited={} worst_query_route_work={} source_hash={} projection_hash={} vector_hash={} entry_hash={} query_hash={} params_hash={}",
                params.min_recall_permille,
                input.query_ids.len(),
                params.top_k,
                worst_query.query_cx_id,
                worst_query.recall_permille,
                worst_query.visited_node_count,
                worst_query.route_distance_computations,
                input.source_identity_hash,
                input.projection_identity_hash,
                input.vector_roster_hash,
                input.entry_roster_hash,
                input.query_roster_hash,
                input.params_hash,
            ),
            "change the graph/kernel/vector generation or explicitly select a measured route configuration; never lower the floor or substitute topology coverage without new real-query evidence",
        ));
    }

    let min_route_distance_computations = queries
        .iter()
        .map(|query| query.route_distance_computations)
        .min()
        .ok_or_else(|| empty_error("query evidence roster is empty after validated evaluation"))?;
    let max_route_distance_computations = queries
        .iter()
        .map(|query| query.route_distance_computations)
        .max()
        .ok_or_else(|| empty_error("query evidence roster is empty after validated evaluation"))?;
    let min_visited_node_count = queries
        .iter()
        .map(|query| query.visited_node_count)
        .min()
        .ok_or_else(|| empty_error("query evidence roster is empty after validated evaluation"))?;
    let max_visited_node_count = queries
        .iter()
        .map(|query| query.visited_node_count)
        .max()
        .ok_or_else(|| empty_error("query evidence roster is empty after validated evaluation"))?;
    let min_retained_candidate_count = queries
        .iter()
        .map(|query| query.retained_candidate_count)
        .min()
        .ok_or_else(|| empty_error("query evidence roster is empty after validated evaluation"))?;
    let max_retained_candidate_count = queries
        .iter()
        .map(|query| query.retained_candidate_count)
        .max()
        .ok_or_else(|| empty_error("query evidence roster is empty after validated evaluation"))?;

    let mut report = GraphRoutedRecallReport {
        schema: GRAPH_ROUTED_RECALL_SCHEMA.to_string(),
        search_semantics: GRAPH_ROUTED_SEARCH_SEMANTICS.to_string(),
        query_semantics: GRAPH_ROUTED_QUERY_SEMANTICS.to_string(),
        hash_semantics: GRAPH_ROUTED_HASH_SEMANTICS.to_string(),
        source_identity_hash: input.source_identity_hash,
        source_identity: input.source_identity,
        projection_identity: input.projection_identity,
        projection_identity_hash: input.projection_identity_hash,
        kernel_artifact_hash: input.kernel_artifact_hash,
        vector_roster_hash: input.vector_roster_hash,
        entry_roster_hash: input.entry_roster_hash,
        query_roster_hash: input.query_roster_hash,
        params_hash: input.params_hash,
        node_count: input.indexed.len(),
        directed_edge_count: graph.edge_count(),
        weak_edge_count: input.weak_edge_count,
        vector_dimension: input.vector_dimension,
        entry_member_ids: input.entries,
        query_ids: input.query_ids,
        params: params.clone(),
        kernel_member_count: kernel.member_count,
        kernel_member_fraction_permille: input.kernel_member_fraction_permille,
        compactness_admitted: input.compactness_admitted,
        queries,
        matched_hit_count,
        relevant_hit_count,
        recall_permille,
        min_route_distance_computations,
        max_route_distance_computations,
        total_route_distance_computations,
        total_exact_distance_computations,
        min_visited_node_count,
        max_visited_node_count,
        total_visited_node_count,
        min_retained_candidate_count,
        max_retained_candidate_count,
        total_retained_candidate_count,
        admitted: true,
        report_hash: String::new(),
    };
    report.report_hash = compute_report_hash(&report)?;
    validate_report_structure(&report)?;
    Ok(report)
}

fn validate_inputs<'a>(
    graph: &KernelGraph,
    kernel: &KernelArtifact,
    complete_vectors: &'a BTreeMap<CxId, Vec<f32>>,
    real_queries: &'a [GraphRoutedQuery],
    params: &GraphRoutedRecallParams,
) -> Result<ValidatedInputs<'a>> {
    validate_params(params)?;
    if graph.node_count() == 0 {
        return Err(empty_error(
            "graph-routed recall requires a nonempty canonical source graph",
        ));
    }
    if complete_vectors.is_empty() {
        return Err(empty_error(
            "graph-routed recall requires the complete persisted vector roster",
        ));
    }
    if real_queries.is_empty() {
        return Err(empty_error(
            "graph-routed recall requires a nonempty caller-supplied real-query roster",
        ));
    }
    if kernel.members.is_empty() {
        return Err(empty_error(
            "graph-routed recall requires a nonempty exact kernel-entry roster",
        ));
    }
    let first_query_id = real_queries
        .first()
        .map(|query| query.query_cx_id)
        .ok_or_else(|| empty_error("real-query roster is empty"))?;

    let indexed = graph.compile()?;
    let weak_degree_sum = (0..indexed.len()).try_fold(0usize, |sum, index| {
        sum.checked_add(indexed.undirected_neighbors(index).len())
    });
    let weak_degree_sum = weak_degree_sum.ok_or_else(|| {
        identity_error("weak graph degree sum overflowed usize while deriving edge identity")
    })?;
    if weak_degree_sum % 2 != 0 {
        return Err(identity_error(format!(
            "weak graph degree sum {weak_degree_sum} is odd after canonical compilation"
        )));
    }
    let weak_edge_count = weak_degree_sum / 2;
    if weak_edge_count == 0 {
        return Err(DomainError::new(
            ASTRO_KERNEL_ROUTE_NO_EDGES,
            format!(
                "source graph has directed_edge_rows={} but weak_non_self_edges=0 over nodes={}; no graph route exists",
                graph.edge_count(),
                graph.node_count(),
            ),
            "supply a source generation containing at least one non-self association edge; an isolated/self-loop-only graph cannot prove routed retrieval",
        ));
    }

    let identity_sets_equal = indexed.len() == complete_vectors.len()
        && indexed
            .ids()
            .iter()
            .copied()
            .eq(complete_vectors.keys().copied());
    if !identity_sets_equal {
        let first_mismatch = indexed
            .ids()
            .iter()
            .copied()
            .zip(complete_vectors.keys().copied())
            .find(|(graph_id, vector_id)| graph_id != vector_id);
        return Err(vector_error(format!(
            "graph/vector identity sets differ: graph_nodes={} vector_rows={} first_ordered_mismatch={first_mismatch:?}",
            indexed.len(),
            complete_vectors.len(),
        )));
    }
    let (vector_dimension, vector_roster_hash) = validate_and_hash_vector_roster(complete_vectors)?;
    if vector_dimension != params.expected_vector_dimension {
        return Err(vector_error(format!(
            "complete corpus dimension {vector_dimension} differs from caller-declared expected_vector_dimension={}",
            params.expected_vector_dimension,
        )));
    }

    validate_kernel_artifact(graph, &indexed, kernel)?;
    let source_identity = kernel_source_identity(graph, &kernel.config)?;
    if source_identity != kernel.source_identity {
        return Err(identity_error(format!(
            "kernel source identity drift: artifact={:?} observed={source_identity:?}",
            kernel.source_identity,
        )));
    }
    let projection_identity = source_identity.projection_identity();
    let projection_identity_hash = projection_hash(&projection_identity);

    let entries = kernel
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    if !real_queries
        .windows(2)
        .all(|pair| pair[0].query_cx_id < pair[1].query_cx_id)
    {
        return Err(query_error(
            "external real queries must be strictly ascending by query_cx_id and unique",
        ));
    }
    let mut query_vector_hashes = BTreeMap::new();
    let mut stable_ids = BTreeSet::new();
    let mut content_identities = BTreeSet::new();
    for query in real_queries {
        if query.stable_id.trim().is_empty()
            || query.source.trim().is_empty()
            || query.content.trim().is_empty()
        {
            return Err(query_error(format!(
                "external query {} has an empty stable_id, source, or content: stable_id={:?} source={:?} content_bytes={}",
                query.query_cx_id,
                query.stable_id,
                query.source,
                query.content.len(),
            )));
        }
        if !stable_ids.insert(query.stable_id.as_str()) {
            return Err(query_error(format!(
                "external query stable_id {:?} is duplicated",
                query.stable_id,
            )));
        }
        if indexed.ids().binary_search(&query.query_cx_id).is_ok() {
            return Err(query_error(format!(
                "external query {} overlaps the complete graph/vector identity set; leave-one-graph-node-out evaluation is forbidden",
                query.query_cx_id,
            )));
        }
        if !is_lower_sha256(&query.content_hash) {
            return Err(query_error(format!(
                "external query {} content_hash is not a 64-character lowercase SHA-256: {}",
                query.query_cx_id, query.content_hash,
            )));
        }
        let observed_content_hash = graph_routed_query_content_hash(query.content.as_bytes());
        if query.content_hash != observed_content_hash {
            return Err(query_error(format!(
                "external query {} content hash drift: persisted={} recomputed={observed_content_hash} stable_id={:?} source={:?}",
                query.query_cx_id, query.content_hash, query.stable_id, query.source,
            )));
        }
        if !content_identities.insert(query.content_hash.as_str()) {
            return Err(query_error(format!(
                "external query content identity {} is duplicated",
                query.content_hash,
            )));
        }
        let observed_query_cx_id =
            graph_routed_query_cx_id(&query.stable_id, &query.source, query.content.as_bytes());
        if query.query_cx_id != observed_query_cx_id {
            return Err(query_error(format!(
                "external query identity drift: persisted={} recomputed={observed_query_cx_id} stable_id={:?} source={:?} content_hash={}",
                query.query_cx_id, query.stable_id, query.source, query.content_hash,
            )));
        }
        let vector_hash = validate_and_hash_query_vector(query, vector_dimension)?;
        query_vector_hashes.insert(query.query_cx_id, vector_hash);
    }
    if params.entry_point_count > entries.len() {
        return Err(params_error(format!(
            "entry_point_count={} exceeds exact kernel entries={}",
            params.entry_point_count,
            entries.len(),
        )));
    }
    if params.top_k > indexed.len() {
        return Err(params_error(format!(
            "top_k={} exceeds complete corpus candidates={}",
            params.top_k,
            indexed.len(),
        )));
    }
    if params.ef_search > indexed.len() {
        return Err(params_error(format!(
            "ef_search={} exceeds complete corpus candidates={}; implicit capping is forbidden",
            params.ef_search,
            indexed.len(),
        )));
    }
    if params.max_route_distance_computations_per_query < entries.len() {
        return Err(budget_error(
            "entry_selection",
            first_query_id,
            entries.len(),
            params.max_route_distance_computations_per_query,
            entries.len(),
            0,
        ));
    }
    let planned_exact = real_queries
        .len()
        .checked_mul(indexed.len())
        .ok_or_else(|| {
            budget_error(
                "exact_oracle_plan_overflow",
                first_query_id,
                usize::MAX,
                params.max_exact_distance_computations,
                0,
                0,
            )
        })?;
    if planned_exact > params.max_exact_distance_computations {
        return Err(budget_error(
            "exact_oracle_plan",
            first_query_id,
            planned_exact,
            params.max_exact_distance_computations,
            0,
            0,
        ));
    }

    let kernel_member_fraction_permille = ratio_permille(entries.len(), indexed.len())?;
    if !compactness_within_ceiling(
        entries.len(),
        indexed.len(),
        params.max_kernel_member_fraction_permille,
    )? {
        return Err(DomainError::new(
            ASTRO_KERNEL_ROUTE_COMPACTNESS_EXCEEDED,
            format!(
                "kernel compactness refused before query work: members={} source_nodes={} observed_floor_permille={} declared_ceiling_permille={}",
                entries.len(),
                indexed.len(),
                kernel_member_fraction_permille,
                params.max_kernel_member_fraction_permille,
            ),
            "rebuild a strictly smaller exact kernel or set a measured explicit ceiling below 1000; never admit a whole-corpus entry roster",
        ));
    }

    let query_ids = real_queries
        .iter()
        .map(|query| query.query_cx_id)
        .collect::<Vec<_>>();
    Ok(ValidatedInputs {
        indexed,
        vectors: complete_vectors,
        vector_dimension,
        weak_edge_count,
        source_identity,
        source_identity_hash: serialized_hash(
            b"astro.kernel.graph_route.kernel_source_identity.v1\0",
            &kernel.source_identity,
        )?,
        projection_identity,
        projection_identity_hash,
        kernel_artifact_hash: graph_routed_kernel_artifact_hash(kernel),
        vector_roster_hash,
        entry_roster_hash: ids_hash(b"astro.kernel.graph_route.entries.v1\0", &entries),
        query_roster_hash: query_roster_hash(real_queries, &query_vector_hashes)?,
        params_hash: params_hash(params),
        entries,
        query_ids,
        queries: real_queries,
        query_vector_hashes,
        kernel_member_fraction_permille,
        compactness_admitted: true,
    })
}

fn validate_kernel_artifact(
    graph: &KernelGraph,
    indexed: &IndexedGraph,
    kernel: &KernelArtifact,
) -> Result<()> {
    if kernel.schema != KERNEL_ARTIFACT_SCHEMA {
        return Err(identity_error(format!(
            "kernel artifact schema drift: expected={KERNEL_ARTIFACT_SCHEMA} observed={}",
            kernel.schema,
        )));
    }
    if kernel.node_count != indexed.len() || kernel.source_identity.node_count != indexed.len() {
        return Err(identity_error(format!(
            "kernel node-count drift: graph={} artifact={} source_identity={}",
            indexed.len(),
            kernel.node_count,
            kernel.source_identity.node_count,
        )));
    }
    if kernel.source_identity.edge_count != graph.edge_count() {
        return Err(identity_error(format!(
            "kernel edge-count drift: graph={} source_identity={}",
            graph.edge_count(),
            kernel.source_identity.edge_count,
        )));
    }
    if kernel.member_count == 0 || kernel.member_count != kernel.members.len() {
        return Err(identity_error(format!(
            "kernel member-count drift: declared={} rows={}",
            kernel.member_count,
            kernel.members.len(),
        )));
    }
    if !kernel
        .members
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(identity_error(
            "kernel member identities are not strictly ascending and unique",
        ));
    }
    let entry_ids = kernel
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    if kernel.members_hash != members_hash(&entry_ids) {
        return Err(identity_error(format!(
            "kernel member-roster hash drift: persisted={} recomputed={}",
            kernel.members_hash,
            members_hash(&entry_ids),
        )));
    }
    if let Some(missing) = entry_ids
        .iter()
        .find(|cx_id| indexed.ids().binary_search(*cx_id).is_err())
    {
        return Err(identity_error(format!(
            "kernel entry {missing} is absent from the exact source graph"
        )));
    }
    let observed_fraction = ratio_permille(kernel.member_count, indexed.len())?;
    let compactness = kernel.compactness;
    let compactness_matches = compactness.member_count == kernel.member_count
        && compactness.source_node_count == indexed.len()
        && compactness.member_fraction_permille == observed_fraction
        && compactness.max_member_fraction_permille == kernel.config.max_member_fraction_permille
        && compactness.admitted
        && compactness_within_ceiling(
            kernel.member_count,
            indexed.len(),
            compactness.max_member_fraction_permille,
        )?;
    if !compactness_matches {
        return Err(identity_error(format!(
            "kernel compactness proof drift: persisted={compactness:?} observed_members={} observed_nodes={} observed_floor_permille={} config_ceiling={}",
            kernel.member_count,
            indexed.len(),
            observed_fraction,
            kernel.config.max_member_fraction_permille,
        )));
    }
    Ok(())
}

fn validate_and_hash_vector_roster(vectors: &BTreeMap<CxId, Vec<f32>>) -> Result<(usize, String)> {
    let dimension = vectors
        .first_key_value()
        .map(|(_, vector)| vector.len())
        .ok_or_else(|| empty_error("complete vector roster is empty"))?;
    let mut hasher = identity_hasher(b"astro.kernel.graph_route.complete_vectors.v1\0");
    update_hash_part(&mut hasher, &(vectors.len() as u128).to_be_bytes());
    update_hash_part(&mut hasher, &(dimension as u128).to_be_bytes());
    let vector_bytes_capacity = dimension
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| vector_error("vector byte width overflowed usize"))?;
    let mut vector_bytes = Vec::with_capacity(vector_bytes_capacity);
    for (cx_id, vector) in vectors {
        if vector.is_empty() {
            return Err(vector_error(format!("vector {cx_id} has zero dimension")));
        }
        if vector.len() != dimension {
            return Err(vector_error(format!(
                "vector {cx_id} has dimension {}, expected {dimension}",
                vector.len(),
            )));
        }
        vector_bytes.clear();
        let mut has_nonzero_component = false;
        for (offset, value) in vector.iter().enumerate() {
            if !value.is_finite() {
                return Err(vector_error(format!(
                    "vector {cx_id} has non-finite component at offset {offset}: bits={:08x}",
                    value.to_bits(),
                )));
            }
            has_nonzero_component |= *value != 0.0;
            vector_bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        if !has_nonzero_component {
            return Err(vector_error(format!("vector {cx_id} has zero norm")));
        }
        update_hash_part(&mut hasher, cx_id.as_bytes());
        update_hash_part(&mut hasher, &vector_bytes);
    }
    Ok((dimension, finish_hash(hasher)))
}

fn validate_and_hash_query_vector(
    query: &GraphRoutedQuery,
    expected_dimension: usize,
) -> Result<String> {
    if query.vector.len() != expected_dimension {
        return Err(vector_error(format!(
            "external query {} has vector dimension {}, expected complete-corpus dimension {expected_dimension}",
            query.query_cx_id,
            query.vector.len(),
        )));
    }
    let mut has_nonzero_component = false;
    for (offset, value) in query.vector.iter().enumerate() {
        if !value.is_finite() {
            return Err(vector_error(format!(
                "external query {} has non-finite vector component at offset {offset}: bits={:08x}",
                query.query_cx_id,
                value.to_bits(),
            )));
        }
        has_nonzero_component |= *value != 0.0;
    }
    if !has_nonzero_component {
        return Err(vector_error(format!(
            "external query {} has a zero-norm vector",
            query.query_cx_id,
        )));
    }
    Ok(graph_routed_query_vector_hash(&query.vector))
}

/// Hashes one exact graph-routed query vector using the persisted v1 framing.
///
/// The vector's dimension is one framed part and all big-endian IEEE-754 bits
/// are one contiguous framed part. Callers validate finite, nonzero, and
/// dimension contracts separately before admitting the resulting identity.
pub fn graph_routed_query_vector_hash(vector: &[f32]) -> String {
    let mut hasher = identity_hasher(b"astro.kernel.graph_route.query_vector.v1\0");
    update_hash_part(&mut hasher, &(vector.len() as u128).to_be_bytes());
    hasher.update(((vector.len() as u128) * 4).to_be_bytes());
    for value in vector {
        hasher.update(value.to_bits().to_be_bytes());
    }
    finish_hash(hasher)
}

fn exact_full_hits(
    query_cx_id: CxId,
    query_vector: &[f32],
    vectors: &BTreeMap<CxId, Vec<f32>>,
    top_k: usize,
) -> Result<Vec<GraphRoutedScoredIdentity>> {
    let mut retained = BinaryHeap::<Reverse<Candidate>>::with_capacity(top_k);
    for (&cx_id, vector) in vectors {
        let candidate = Candidate {
            cx_id,
            node_index: 0,
            score: cosine(query_cx_id, cx_id, query_vector, vector)?,
        };
        let should_retain = retained.len() < top_k
            || candidate
                > retained
                    .peek()
                    .ok_or_else(|| report_error("exact top-k heap is unexpectedly empty"))?
                    .0;
        if should_retain {
            retained.push(Reverse(candidate));
            if retained.len() > top_k {
                retained.pop();
            }
        }
    }
    let mut ranked = retained
        .into_iter()
        .map(|Reverse(candidate)| candidate)
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.cmp(left));
    if ranked.len() < top_k {
        return Err(insufficient_error(
            "exact_oracle",
            query_cx_id,
            ranked.len(),
            top_k,
            vectors.len(),
            0,
        ));
    }
    Ok(ranked
        .into_iter()
        .take(top_k)
        .map(Candidate::scored_identity)
        .collect())
}

fn route_query(
    input: &ValidatedInputs<'_>,
    query_cx_id: CxId,
    query_vector: &[f32],
    params: &GraphRoutedRecallParams,
) -> Result<RouteOutcome> {
    let mut entry_rank = Vec::with_capacity(input.entries.len());
    for &entry_id in &input.entries {
        let entry_vector = input.vectors.get(&entry_id).ok_or_else(|| {
            vector_error(format!(
                "kernel entry {entry_id} is missing from the complete vector map"
            ))
        })?;
        let node_index = input.indexed.ids().binary_search(&entry_id).map_err(|_| {
            identity_error(format!(
                "kernel entry {entry_id} is missing from the compiled graph index"
            ))
        })?;
        entry_rank.push(Candidate {
            cx_id: entry_id,
            node_index,
            score: cosine(query_cx_id, entry_id, query_vector, entry_vector)?,
        });
    }
    let entry_distance_computations = entry_rank.len();
    if entry_distance_computations > params.max_route_distance_computations_per_query {
        return Err(budget_error(
            "entry_selection",
            query_cx_id,
            entry_distance_computations,
            params.max_route_distance_computations_per_query,
            entry_distance_computations,
            0,
        ));
    }
    let entry_scores = entry_rank
        .iter()
        .map(|candidate| (candidate.cx_id, candidate.score))
        .collect::<BTreeMap<_, _>>();
    entry_rank.sort_by(|left, right| right.cmp(left));
    let selected_entries = entry_rank
        .into_iter()
        .take(params.entry_point_count)
        .collect::<Vec<_>>();
    if selected_entries.len() != params.entry_point_count {
        return Err(insufficient_error(
            "entry_selection",
            query_cx_id,
            selected_entries.len(),
            params.entry_point_count,
            0,
            entry_distance_computations,
        ));
    }

    let mut visited = vec![false; input.indexed.len()];
    let mut visited_node_count = 0usize;
    let mut frontier = BinaryHeap::new();
    let mut retained = BinaryHeap::<Reverse<Candidate>>::new();
    for entry in &selected_entries {
        if visited[entry.node_index] {
            return Err(identity_error(format!(
                "query {query_cx_id} selected duplicate entry {}",
                entry.cx_id,
            )));
        }
        visited[entry.node_index] = true;
        visited_node_count = visited_node_count.checked_add(1).ok_or_else(|| {
            report_error(format!(
                "query {query_cx_id} visited-node counter overflowed usize"
            ))
        })?;
        frontier.push(*entry);
        retained.push(Reverse(*entry));
    }

    let mut routed_distance_computations = 0usize;
    let mut frontier_pop_count = 0usize;
    while let Some(current) = frontier.pop() {
        frontier_pop_count = frontier_pop_count.checked_add(1).ok_or_else(|| {
            budget_error(
                "frontier_pop_counter_overflow",
                query_cx_id,
                usize::MAX,
                params.max_route_distance_computations_per_query,
                entry_distance_computations,
                routed_distance_computations,
            )
        })?;
        if retained.len() >= params.ef_search {
            let worst = retained
                .peek()
                .ok_or_else(|| report_error("retained route heap is unexpectedly empty"))?
                .0;
            // `Candidate` includes the deterministic CxId tie-break. Comparing
            // only scores would expand an already-evicted equal-score candidate
            // even though no remaining frontier row can improve the retained
            // roster, consuming route budget without changing any result.
            if current < worst {
                break;
            }
        }

        for &neighbor in input.indexed.undirected_neighbors(current.node_index) {
            if visited[neighbor] {
                continue;
            }
            visited[neighbor] = true;
            visited_node_count = visited_node_count.checked_add(1).ok_or_else(|| {
                report_error(format!(
                    "query {query_cx_id} visited-node counter overflowed usize"
                ))
            })?;
            let neighbor_id = input.indexed.id(neighbor);
            let score = match entry_scores.get(&neighbor_id).copied() {
                Some(entry_score) => entry_score,
                None => {
                    let next_routed =
                        routed_distance_computations.checked_add(1).ok_or_else(|| {
                            budget_error(
                                "route_counter_overflow",
                                query_cx_id,
                                usize::MAX,
                                params.max_route_distance_computations_per_query,
                                entry_distance_computations,
                                usize::MAX,
                            )
                        })?;
                    let next_total = entry_distance_computations
                        .checked_add(next_routed)
                        .ok_or_else(|| {
                            budget_error(
                                "route_total_counter_overflow",
                                query_cx_id,
                                usize::MAX,
                                params.max_route_distance_computations_per_query,
                                entry_distance_computations,
                                next_routed,
                            )
                        })?;
                    if next_total > params.max_route_distance_computations_per_query {
                        return Err(budget_error(
                            "weak_graph_expansion",
                            query_cx_id,
                            next_total,
                            params.max_route_distance_computations_per_query,
                            entry_distance_computations,
                            next_routed,
                        ));
                    }
                    routed_distance_computations = next_routed;
                    let neighbor_vector = input.vectors.get(&neighbor_id).ok_or_else(|| {
                        vector_error(format!(
                            "visited graph node {neighbor_id} is missing from the complete vector map"
                        ))
                    })?;
                    cosine(query_cx_id, neighbor_id, query_vector, neighbor_vector)?
                }
            };
            let candidate = Candidate {
                cx_id: neighbor_id,
                node_index: neighbor,
                score,
            };

            let should_retain = retained.len() < params.ef_search
                || candidate
                    > retained
                        .peek()
                        .ok_or_else(|| report_error("retained route heap is unexpectedly empty"))?
                        .0;
            if should_retain {
                frontier.push(candidate);
                retained.push(Reverse(candidate));
                if retained.len() > params.ef_search {
                    retained.pop();
                }
            }
        }
    }

    let retained_candidate_count = retained.len();
    let mut retained_ranked = retained
        .into_iter()
        .map(|Reverse(candidate)| candidate)
        .collect::<Vec<_>>();
    retained_ranked.sort_by(|left, right| right.cmp(left));
    if retained_ranked.len() < params.top_k {
        return Err(insufficient_error(
            "weak_graph_route",
            query_cx_id,
            retained_ranked.len(),
            params.top_k,
            visited_node_count,
            entry_distance_computations + routed_distance_computations,
        ));
    }
    let hits = retained_ranked
        .iter()
        .take(params.top_k)
        .copied()
        .map(Candidate::scored_identity)
        .collect::<Vec<_>>();
    let mut retained_ids = retained_ranked
        .iter()
        .map(|candidate| candidate.cx_id)
        .collect::<Vec<_>>();
    retained_ids.sort_unstable();
    let visited_ids = visited
        .iter()
        .enumerate()
        .filter_map(|(index, was_visited)| (*was_visited).then_some(input.indexed.id(index)))
        .collect::<Vec<_>>();

    Ok(RouteOutcome {
        entry_points: selected_entries
            .into_iter()
            .map(Candidate::scored_identity)
            .collect(),
        hits,
        visited_node_count: visited_ids.len(),
        visited_node_ids_hash: ids_hash(
            b"astro.kernel.graph_route.query.visited.v1\0",
            &visited_ids,
        ),
        retained_candidate_count,
        retained_candidate_ids_hash: ids_hash(
            b"astro.kernel.graph_route.query.retained.v1\0",
            &retained_ids,
        ),
        frontier_pop_count,
        entry_distance_computations,
        routed_distance_computations,
    })
}

fn validate_report_structure(report: &GraphRoutedRecallReport) -> Result<()> {
    validate_params(&report.params)?;
    if report.schema != GRAPH_ROUTED_RECALL_SCHEMA
        || report.search_semantics != GRAPH_ROUTED_SEARCH_SEMANTICS
        || report.query_semantics != GRAPH_ROUTED_QUERY_SEMANTICS
        || report.hash_semantics != GRAPH_ROUTED_HASH_SEMANTICS
    {
        return Err(report_error(format!(
            "report semantics drift: schema expected={GRAPH_ROUTED_RECALL_SCHEMA} observed={} search expected={GRAPH_ROUTED_SEARCH_SEMANTICS} observed={} query expected={GRAPH_ROUTED_QUERY_SEMANTICS} observed={} hash expected={GRAPH_ROUTED_HASH_SEMANTICS} observed={}",
            report.schema, report.search_semantics, report.query_semantics, report.hash_semantics,
        )));
    }
    if report.node_count == 0
        || report.directed_edge_count == 0
        || report.weak_edge_count == 0
        || report.vector_dimension == 0
        || report.entry_member_ids.is_empty()
        || report.query_ids.is_empty()
        || report.queries.is_empty()
    {
        return Err(report_error(format!(
            "report contains an empty required source: nodes={} directed_edges={} weak_edges={} dimension={} entries={} query_ids={} query_evidence={}",
            report.node_count,
            report.directed_edge_count,
            report.weak_edge_count,
            report.vector_dimension,
            report.entry_member_ids.len(),
            report.query_ids.len(),
            report.queries.len(),
        )));
    }
    if !strictly_ascending(&report.entry_member_ids) || !strictly_ascending(&report.query_ids) {
        return Err(report_error(
            "entry and query identity rosters must each be strictly ascending and unique",
        ));
    }
    let entry_set = report
        .entry_member_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if let Some(overlap) = report
        .query_ids
        .iter()
        .find(|cx_id| entry_set.contains(cx_id))
    {
        return Err(report_error(format!(
            "external real query {overlap} overlaps the persisted entry roster"
        )));
    }
    if report.kernel_member_count != report.entry_member_ids.len()
        || report.vector_dimension != report.params.expected_vector_dimension
        || report.source_identity.node_count != report.node_count
        || report.source_identity.edge_count != report.directed_edge_count
        || report.projection_identity != report.source_identity.projection_identity()
        || report.projection_identity.node_count != report.node_count
        || report.projection_identity.edge_count != report.directed_edge_count
    {
        return Err(report_error(format!(
            "report source/count identity mismatch: nodes={} directed_edges={} vector_dimension={} expected_vector_dimension={} members={} entry_rows={} source={:?} projection={:?}",
            report.node_count,
            report.directed_edge_count,
            report.vector_dimension,
            report.params.expected_vector_dimension,
            report.kernel_member_count,
            report.entry_member_ids.len(),
            report.source_identity,
            report.projection_identity,
        )));
    }
    let observed_fraction = ratio_permille(report.kernel_member_count, report.node_count)?;
    let observed_compactness = compactness_within_ceiling(
        report.kernel_member_count,
        report.node_count,
        report.params.max_kernel_member_fraction_permille,
    )?;
    if report.kernel_member_fraction_permille != observed_fraction
        || !report.compactness_admitted
        || !observed_compactness
    {
        return Err(report_error(format!(
            "report compactness mismatch: members={} nodes={} persisted_fraction={} observed_fraction={} ceiling={} persisted_admitted={} observed_admitted={observed_compactness}",
            report.kernel_member_count,
            report.node_count,
            report.kernel_member_fraction_permille,
            observed_fraction,
            report.params.max_kernel_member_fraction_permille,
            report.compactness_admitted,
        )));
    }
    let observed_source_identity_hash = serialized_hash(
        b"astro.kernel.graph_route.kernel_source_identity.v1\0",
        &report.source_identity,
    )?;
    if report.source_identity_hash != observed_source_identity_hash
        || report.projection_identity_hash != projection_hash(&report.projection_identity)
        || report.entry_roster_hash
            != ids_hash(
                b"astro.kernel.graph_route.entries.v1\0",
                &report.entry_member_ids,
            )
        || report.query_roster_hash != evidence_query_roster_hash(&report.queries)
        || report.params_hash != params_hash(&report.params)
    {
        return Err(report_error(format!(
            "report identity hash mismatch: source persisted={} embedded={} projection persisted={} recomputed={} entries persisted={} recomputed={} queries persisted={} recomputed={} params persisted={} recomputed={}",
            report.source_identity_hash,
            observed_source_identity_hash,
            report.projection_identity_hash,
            projection_hash(&report.projection_identity),
            report.entry_roster_hash,
            ids_hash(
                b"astro.kernel.graph_route.entries.v1\0",
                &report.entry_member_ids,
            ),
            report.query_roster_hash,
            evidence_query_roster_hash(&report.queries),
            report.params_hash,
            params_hash(&report.params),
        )));
    }
    for (label, hash) in [
        ("source", report.source_identity_hash.as_str()),
        ("projection", report.projection_identity_hash.as_str()),
        ("kernel_artifact", report.kernel_artifact_hash.as_str()),
        ("vectors", report.vector_roster_hash.as_str()),
        ("entries", report.entry_roster_hash.as_str()),
        ("queries", report.query_roster_hash.as_str()),
        ("params", report.params_hash.as_str()),
        ("report", report.report_hash.as_str()),
    ] {
        if !is_lower_hex_hash(hash) {
            return Err(report_error(format!(
                "report {label} hash is not a 64-character lowercase hex digest: {hash}"
            )));
        }
    }
    if report.queries.len() != report.query_ids.len() {
        return Err(report_error(format!(
            "query evidence count {} differs from query roster count {}",
            report.queries.len(),
            report.query_ids.len(),
        )));
    }

    let mut query_stable_ids = BTreeSet::new();
    let mut query_content_identities = BTreeSet::new();
    for (&query_id, evidence) in report.query_ids.iter().zip(&report.queries) {
        if !query_stable_ids.insert(evidence.query_stable_id.as_str())
            || !query_content_identities.insert(evidence.query_content_hash.as_str())
        {
            return Err(report_error(format!(
                "query evidence duplicates stable_id or content identity: query={query_id} stable_id={:?} content_hash={}",
                evidence.query_stable_id, evidence.query_content_hash,
            )));
        }
        validate_query_evidence(report, &entry_set, query_id, evidence)?;
    }

    let matched_hit_count = checked_sum(
        report.queries.iter().map(|query| query.matched_hit_count),
        "persisted matched-hit aggregate",
    )?;
    let relevant_hit_count = report
        .query_ids
        .len()
        .checked_mul(report.params.top_k)
        .ok_or_else(|| report_error("persisted query_count * top_k overflowed usize"))?;
    let recall_permille = ratio_permille(matched_hit_count, relevant_hit_count)?;
    let min_route = report
        .queries
        .iter()
        .map(|query| query.route_distance_computations)
        .min()
        .ok_or_else(|| report_error("persisted query evidence is empty"))?;
    let max_route = report
        .queries
        .iter()
        .map(|query| query.route_distance_computations)
        .max()
        .ok_or_else(|| report_error("persisted query evidence is empty"))?;
    let total_route = checked_sum(
        report
            .queries
            .iter()
            .map(|query| query.route_distance_computations),
        "persisted route-distance aggregate",
    )?;
    let total_exact = checked_sum(
        report
            .queries
            .iter()
            .map(|query| query.exact_distance_computations),
        "persisted exact-distance aggregate",
    )?;
    let min_visited = report
        .queries
        .iter()
        .map(|query| query.visited_node_count)
        .min()
        .ok_or_else(|| report_error("persisted query evidence is empty"))?;
    let max_visited = report
        .queries
        .iter()
        .map(|query| query.visited_node_count)
        .max()
        .ok_or_else(|| report_error("persisted query evidence is empty"))?;
    let total_visited = checked_sum(
        report.queries.iter().map(|query| query.visited_node_count),
        "persisted visited-node aggregate",
    )?;
    let min_retained = report
        .queries
        .iter()
        .map(|query| query.retained_candidate_count)
        .min()
        .ok_or_else(|| report_error("persisted query evidence is empty"))?;
    let max_retained = report
        .queries
        .iter()
        .map(|query| query.retained_candidate_count)
        .max()
        .ok_or_else(|| report_error("persisted query evidence is empty"))?;
    let total_retained = checked_sum(
        report
            .queries
            .iter()
            .map(|query| query.retained_candidate_count),
        "persisted retained-candidate aggregate",
    )?;
    let planned_exact = report
        .query_ids
        .len()
        .checked_mul(report.node_count)
        .ok_or_else(|| report_error("persisted exact work plan overflowed usize"))?;

    let aggregates_match = report.matched_hit_count == matched_hit_count
        && report.relevant_hit_count == relevant_hit_count
        && report.recall_permille == recall_permille
        && report.min_route_distance_computations == min_route
        && report.max_route_distance_computations == max_route
        && report.total_route_distance_computations == total_route
        && report.total_exact_distance_computations == total_exact
        && total_exact == planned_exact
        && total_exact <= report.params.max_exact_distance_computations
        && report.min_visited_node_count == min_visited
        && report.max_visited_node_count == max_visited
        && report.total_visited_node_count == total_visited
        && report.min_retained_candidate_count == min_retained
        && report.max_retained_candidate_count == max_retained
        && report.total_retained_candidate_count == total_retained
        && report.recall_permille >= report.params.min_recall_permille
        && report.admitted;
    if !aggregates_match {
        return Err(report_error(format!(
            "report aggregate mismatch: matched persisted={} observed={} relevant persisted={} observed={} recall persisted={} observed={} route min/max/total persisted={}/{}/{} observed={min_route}/{max_route}/{total_route} exact persisted={} observed={total_exact} planned={planned_exact} visited min/max/total persisted={}/{}/{} observed={min_visited}/{max_visited}/{total_visited} retained min/max/total persisted={}/{}/{} observed={min_retained}/{max_retained}/{total_retained} floor={} admitted={}",
            report.matched_hit_count,
            matched_hit_count,
            report.relevant_hit_count,
            relevant_hit_count,
            report.recall_permille,
            recall_permille,
            report.min_route_distance_computations,
            report.max_route_distance_computations,
            report.total_route_distance_computations,
            report.total_exact_distance_computations,
            report.min_visited_node_count,
            report.max_visited_node_count,
            report.total_visited_node_count,
            report.min_retained_candidate_count,
            report.max_retained_candidate_count,
            report.total_retained_candidate_count,
            report.params.min_recall_permille,
            report.admitted,
        )));
    }
    let observed_report_hash = compute_report_hash(report)?;
    if report.report_hash != observed_report_hash {
        return Err(report_error(format!(
            "report hash mismatch: persisted={} recomputed={observed_report_hash}",
            report.report_hash,
        )));
    }
    Ok(())
}

fn validate_query_evidence(
    report: &GraphRoutedRecallReport,
    entry_set: &BTreeSet<CxId>,
    query_id: CxId,
    evidence: &GraphRoutedRecallQueryEvidence,
) -> Result<()> {
    if evidence.query_cx_id != query_id {
        return Err(report_error(format!(
            "query evidence order drift: roster={query_id} evidence={}",
            evidence.query_cx_id,
        )));
    }
    if evidence.query_stable_id.trim().is_empty()
        || evidence.query_source.trim().is_empty()
        || !is_lower_sha256(&evidence.query_content_hash)
        || !is_lower_sha256(&evidence.query_vector_hash)
    {
        return Err(report_error(format!(
            "query {query_id} stable/source/content/vector identity is invalid: stable_id={:?} source={:?} content_hash={} vector_hash={}",
            evidence.query_stable_id,
            evidence.query_source,
            evidence.query_content_hash,
            evidence.query_vector_hash,
        )));
    }
    validate_ranked_scored_roster("entry_points", query_id, &evidence.entry_points)?;
    validate_ranked_scored_roster("exact_full_hits", query_id, &evidence.exact_full_hits)?;
    validate_ranked_scored_roster("routed_hits", query_id, &evidence.routed_hits)?;
    if evidence.entry_points.len() != report.params.entry_point_count
        || evidence.exact_full_hits.len() != report.params.top_k
        || evidence.routed_hits.len() != report.params.top_k
    {
        return Err(report_error(format!(
            "query {query_id} roster lengths drift: entries={} expected={} exact_hits={} routed_hits={} expected_hits={}",
            evidence.entry_points.len(),
            report.params.entry_point_count,
            evidence.exact_full_hits.len(),
            evidence.routed_hits.len(),
            report.params.top_k,
        )));
    }
    if evidence
        .entry_points
        .iter()
        .any(|entry| !entry_set.contains(&entry.cx_id) || entry.cx_id == query_id)
        || evidence
            .exact_full_hits
            .iter()
            .any(|hit| hit.cx_id == query_id)
        || evidence.routed_hits.iter().any(|hit| hit.cx_id == query_id)
    {
        return Err(report_error(format!(
            "query {query_id} contains an entry outside the exact kernel roster or contains itself as a hit"
        )));
    }
    let exact_ids = evidence
        .exact_full_hits
        .iter()
        .map(|hit| hit.cx_id)
        .collect::<BTreeSet<_>>();
    let exact_scores = evidence
        .exact_full_hits
        .iter()
        .map(|hit| (hit.cx_id, hit.cosine_bits))
        .collect::<BTreeMap<_, _>>();
    let entry_scores = evidence
        .entry_points
        .iter()
        .map(|entry| (entry.cx_id, entry.cosine_bits))
        .collect::<BTreeMap<_, _>>();
    let overlapping_scores_match = evidence.routed_hits.iter().all(|hit| {
        exact_scores
            .get(&hit.cx_id)
            .into_iter()
            .chain(entry_scores.get(&hit.cx_id))
            .all(|expected_bits| *expected_bits == hit.cosine_bits)
    });
    let matched = evidence
        .routed_hits
        .iter()
        .filter(|hit| exact_ids.contains(&hit.cx_id))
        .count();
    let recall = ratio_permille(matched, report.params.top_k)?;
    let route_total = evidence
        .entry_distance_computations
        .checked_add(evidence.routed_distance_computations)
        .ok_or_else(|| report_error(format!("query {query_id} route work overflowed usize")))?;
    let counters_match = evidence.matched_hit_count == matched
        && evidence.recall_permille == recall
        && overlapping_scores_match
        && evidence.visited_node_count >= evidence.entry_points.len()
        && evidence.visited_node_count <= report.node_count
        && evidence.retained_candidate_count >= report.params.top_k
        && evidence.retained_candidate_count <= report.params.ef_search
        && evidence.frontier_pop_count <= evidence.visited_node_count
        && evidence.entry_distance_computations == report.entry_member_ids.len()
        && evidence.route_distance_computations == route_total
        && route_total <= report.params.max_route_distance_computations_per_query
        && evidence.exact_distance_computations == report.node_count
        && is_lower_hex_hash(&evidence.visited_node_ids_hash)
        && is_lower_hex_hash(&evidence.retained_candidate_ids_hash);
    if !counters_match {
        return Err(report_error(format!(
            "query {query_id} evidence counter mismatch: matched persisted={} observed={matched} recall persisted={} observed={recall} overlapping_scores_match={overlapping_scores_match} visited={} entries={} retained={} top_k={} ef={} frontier_pops={} entry_work={} expected_entry_work={} route_work persisted={} recomputed={route_total} route_budget={} exact_work={} expected_exact={} visited_hash={} retained_hash={}",
            evidence.matched_hit_count,
            evidence.recall_permille,
            evidence.visited_node_count,
            evidence.entry_points.len(),
            evidence.retained_candidate_count,
            report.params.top_k,
            report.params.ef_search,
            evidence.frontier_pop_count,
            evidence.entry_distance_computations,
            report.entry_member_ids.len(),
            evidence.route_distance_computations,
            report.params.max_route_distance_computations_per_query,
            evidence.exact_distance_computations,
            report.node_count,
            evidence.visited_node_ids_hash,
            evidence.retained_candidate_ids_hash,
        )));
    }
    Ok(())
}

fn validate_ranked_scored_roster(
    label: &str,
    query_id: CxId,
    rows: &[GraphRoutedScoredIdentity],
) -> Result<()> {
    let unique = rows
        .iter()
        .map(|row| row.cx_id)
        .collect::<BTreeSet<_>>()
        .len()
        == rows.len();
    let finite = rows.iter().all(|row| row.cosine().is_finite());
    let ordered = rows.windows(2).all(|pair| {
        let left = Candidate {
            cx_id: pair[0].cx_id,
            node_index: 0,
            score: pair[0].cosine(),
        };
        let right = Candidate {
            cx_id: pair[1].cx_id,
            node_index: 0,
            score: pair[1].cosine(),
        };
        left > right
    });
    if !unique || !finite || !ordered {
        return Err(report_error(format!(
            "query {query_id} {label} is not a unique finite deterministic score-descending/id-ascending roster: rows={} unique={unique} finite={finite} ordered={ordered}",
            rows.len(),
        )));
    }
    Ok(())
}

fn validate_params(params: &GraphRoutedRecallParams) -> Result<()> {
    if params.top_k == 0 {
        return Err(params_error("top_k must be greater than zero"));
    }
    if params.expected_vector_dimension == 0 {
        return Err(params_error(
            "expected_vector_dimension must be greater than zero",
        ));
    }
    if params.entry_point_count == 0 {
        return Err(params_error("entry_point_count must be greater than zero"));
    }
    if params.ef_search < params.top_k || params.ef_search < params.entry_point_count {
        return Err(params_error(format!(
            "ef_search={} must be at least top_k={} and entry_point_count={}",
            params.ef_search, params.top_k, params.entry_point_count,
        )));
    }
    if params.max_route_distance_computations_per_query == 0
        || params.max_exact_distance_computations == 0
    {
        return Err(params_error(format!(
            "distance ceilings must be positive: route_per_query={} exact_total={}",
            params.max_route_distance_computations_per_query,
            params.max_exact_distance_computations,
        )));
    }
    if !(1..=1000).contains(&params.min_recall_permille) {
        return Err(params_error(format!(
            "min_recall_permille={} is outside 1..=1000",
            params.min_recall_permille,
        )));
    }
    if !(1..=999).contains(&params.max_kernel_member_fraction_permille) {
        return Err(params_error(format!(
            "max_kernel_member_fraction_permille={} is outside 1..=999; a 1000-permille ceiling could admit the whole corpus",
            params.max_kernel_member_fraction_permille,
        )));
    }
    Ok(())
}

fn cosine(
    query_cx_id: CxId,
    candidate_cx_id: CxId,
    query: &[f32],
    candidate: &[f32],
) -> Result<f32> {
    if query.is_empty() || query.len() != candidate.len() {
        return Err(vector_error(format!(
            "cosine dimension mismatch for query={query_cx_id} candidate={candidate_cx_id}: query_dim={} candidate_dim={}",
            query.len(),
            candidate.len(),
        )));
    }
    let mut dot = 0.0_f64;
    let mut query_norm = 0.0_f64;
    let mut candidate_norm = 0.0_f64;
    for (&left, &right) in query.iter().zip(candidate) {
        let left = f64::from(left);
        let right = f64::from(right);
        dot += left * right;
        query_norm += left * left;
        candidate_norm += right * right;
    }
    if !dot.is_finite()
        || !query_norm.is_finite()
        || !candidate_norm.is_finite()
        || query_norm <= 0.0
        || candidate_norm <= 0.0
    {
        return Err(vector_error(format!(
            "cosine accumulation is invalid for query={query_cx_id} candidate={candidate_cx_id}: dot={dot} query_norm={query_norm} candidate_norm={candidate_norm}"
        )));
    }
    let score = (dot / (query_norm.sqrt() * candidate_norm.sqrt())) as f32;
    if !score.is_finite() {
        return Err(vector_error(format!(
            "cosine score is non-finite for query={query_cx_id} candidate={candidate_cx_id}: bits={:08x}",
            score.to_bits(),
        )));
    }
    // Canonicalize the two IEEE zero encodings; zero cosine has one persisted
    // representation and therefore one cross-generation rank identity.
    Ok(if score == 0.0 { 0.0 } else { score })
}

fn ratio_permille(numerator: usize, denominator: usize) -> Result<u64> {
    if denominator == 0 {
        return Err(params_error(
            "cannot compute a permille ratio with denominator zero",
        ));
    }
    let scaled = (numerator as u128)
        .checked_mul(1000)
        .ok_or_else(|| params_error("permille numerator overflowed u128"))?
        / denominator as u128;
    u64::try_from(scaled).map_err(|_| params_error("permille result exceeded u64"))
}

fn compactness_within_ceiling(
    member_count: usize,
    node_count: usize,
    ceiling_permille: u64,
) -> Result<bool> {
    if node_count == 0 || member_count == 0 {
        return Ok(false);
    }
    let left = (member_count as u128)
        .checked_mul(1000)
        .ok_or_else(|| params_error("compactness member product overflowed u128"))?;
    let right = (node_count as u128)
        .checked_mul(u128::from(ceiling_permille))
        .ok_or_else(|| params_error("compactness ceiling product overflowed u128"))?;
    Ok(member_count < node_count && left <= right)
}

fn checked_sum(values: impl Iterator<Item = usize>, label: &str) -> Result<usize> {
    values.try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| report_error(format!("{label} overflowed usize")))
    })
}

fn projection_hash(identity: &KernelProjectionIdentity) -> String {
    let mut hasher = identity_hasher(b"astro.kernel.graph_route.projection.v1\0");
    update_hash_part(&mut hasher, &(identity.node_count as u128).to_be_bytes());
    update_hash_part(&mut hasher, &(identity.edge_count as u128).to_be_bytes());
    update_hash_part(&mut hasher, identity.node_roster_hash.as_bytes());
    update_hash_part(&mut hasher, identity.directed_topology_hash.as_bytes());
    update_hash_part(&mut hasher, identity.weighted_edge_roster_hash.as_bytes());
    finish_hash(hasher)
}

fn ids_hash(domain: &[u8], ids: &[CxId]) -> String {
    let mut hasher = identity_hasher(domain);
    update_hash_part(&mut hasher, &(ids.len() as u128).to_be_bytes());
    for cx_id in ids {
        update_hash_part(&mut hasher, cx_id.as_bytes());
    }
    finish_hash(hasher)
}

fn query_roster_hash(
    queries: &[GraphRoutedQuery],
    vector_hashes: &BTreeMap<CxId, String>,
) -> Result<String> {
    let mut hasher = identity_hasher(b"astro.kernel.graph_route.external_queries.v2\0");
    update_hash_part(&mut hasher, &(queries.len() as u128).to_be_bytes());
    for query in queries {
        update_hash_part(&mut hasher, query.query_cx_id.as_bytes());
        update_hash_part(&mut hasher, query.stable_id.as_bytes());
        update_hash_part(&mut hasher, query.source.as_bytes());
        update_hash_part(&mut hasher, query.content_hash.as_bytes());
        let vector_hash = vector_hashes.get(&query.query_cx_id).ok_or_else(|| {
            identity_error(format!(
                "external query {} is missing its precomputed vector hash",
                query.query_cx_id,
            ))
        })?;
        update_hash_part(&mut hasher, vector_hash.as_bytes());
    }
    Ok(finish_hash(hasher))
}

fn evidence_query_roster_hash(queries: &[GraphRoutedRecallQueryEvidence]) -> String {
    let mut hasher = identity_hasher(b"astro.kernel.graph_route.external_queries.v2\0");
    update_hash_part(&mut hasher, &(queries.len() as u128).to_be_bytes());
    for query in queries {
        update_hash_part(&mut hasher, query.query_cx_id.as_bytes());
        update_hash_part(&mut hasher, query.query_stable_id.as_bytes());
        update_hash_part(&mut hasher, query.query_source.as_bytes());
        update_hash_part(&mut hasher, query.query_content_hash.as_bytes());
        update_hash_part(&mut hasher, query.query_vector_hash.as_bytes());
    }
    finish_hash(hasher)
}

fn params_hash(params: &GraphRoutedRecallParams) -> String {
    let mut hasher = identity_hasher(b"astro.kernel.graph_route.params.v1\0");
    update_hash_part(&mut hasher, &(params.top_k as u128).to_be_bytes());
    update_hash_part(
        &mut hasher,
        &(params.expected_vector_dimension as u128).to_be_bytes(),
    );
    update_hash_part(
        &mut hasher,
        &(params.entry_point_count as u128).to_be_bytes(),
    );
    update_hash_part(&mut hasher, &(params.ef_search as u128).to_be_bytes());
    update_hash_part(
        &mut hasher,
        &(params.max_route_distance_computations_per_query as u128).to_be_bytes(),
    );
    update_hash_part(
        &mut hasher,
        &(params.max_exact_distance_computations as u128).to_be_bytes(),
    );
    update_hash_part(&mut hasher, &params.min_recall_permille.to_be_bytes());
    update_hash_part(
        &mut hasher,
        &params.max_kernel_member_fraction_permille.to_be_bytes(),
    );
    finish_hash(hasher)
}

fn serialized_hash(value_domain: &[u8], value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        report_error(format!(
            "could not serialize content-addressed graph-routed value: {error}"
        ))
    })?;
    Ok(bytes_hash(value_domain, &bytes))
}

fn compute_report_hash(report: &GraphRoutedRecallReport) -> Result<String> {
    let mut hash_input = report.clone();
    hash_input.report_hash.clear();
    serialized_hash(b"astro.kernel.graph_route.report.v1\0", &hash_input)
}

fn bytes_hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = identity_hasher(domain);
    update_hash_part(&mut hasher, bytes);
    finish_hash(hasher)
}

fn identity_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    update_hash_part(&mut hasher, domain);
    hasher
}

fn update_hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u128).to_be_bytes());
    hasher.update(bytes);
}

fn append_query_identity_part(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u128).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn finish_hash(hasher: Sha256) -> String {
    hex_lower(&hasher.finalize())
}

fn strictly_ascending(ids: &[CxId]) -> bool {
    ids.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_sha256(value: &str) -> bool {
    is_lower_hex_hash(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn empty_error(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_EMPTY_INPUT,
        message,
        "supply one exact nonempty source graph, complete vector roster, compact kernel artifact, and disjoint persisted query roster",
    )
}

fn identity_error(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_IDENTITY_DRIFT,
        message,
        "re-read the graph, kernel artifact, complete corpus vectors, independently persisted query rows, and parameters from one exact admission snapshot and rebuild the report",
    )
}

fn vector_error(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_VECTOR_INVALID,
        message,
        "materialize exactly one finite, nonzero, same-dimension persisted vector for every graph identity before admission",
    )
}

fn query_error(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_QUERY_INVALID,
        message,
        "supply exact nonempty persisted external query rows with stable/source/content identity and vectors, strictly ordered, duplicate-free, and disjoint from the complete graph identity set",
    )
}

fn params_error(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_PARAMS_INVALID,
        message,
        "supply positive explicit top-k, vector dimension, entry, candidate, and work limits plus a recall floor in 1..=1000 and compactness ceiling in 1..=999",
    )
}

fn budget_error(
    stage: &str,
    query_cx_id: CxId,
    actual: usize,
    maximum: usize,
    entry_work: usize,
    routed_work: usize,
) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_BUDGET_EXCEEDED,
        format!(
            "graph-routed distance budget exceeded: stage={stage} query={query_cx_id} actual={actual} maximum={maximum} entry_work={entry_work} routed_work={routed_work}"
        ),
        "measure the named query/stage against the exact source, then explicitly choose a sufficient generation-admission budget or change the graph/kernel; no truncated or exhaustive fallback is permitted",
    )
}

fn insufficient_error(
    stage: &str,
    query_cx_id: CxId,
    actual_candidates: usize,
    required_candidates: usize,
    visited_nodes: usize,
    distance_work: usize,
) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_INSUFFICIENT_CANDIDATES,
        format!(
            "graph-routed candidates are insufficient: stage={stage} query={query_cx_id} actual={actual_candidates} required={required_candidates} visited_nodes={visited_nodes} distance_work={distance_work}"
        ),
        "change the exact graph/kernel generation or explicitly select measured route controls that can reach top-k; never fill missing hits from an exhaustive or truncated fallback",
    )
}

fn report_error(message: impl Into<String>) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ROUTE_REPORT_INVALID,
        message,
        "discard the invalid report, re-read all exact generation inputs, rebuild it, persist it atomically, and validate the persisted bytes through a separate read",
    )
}
