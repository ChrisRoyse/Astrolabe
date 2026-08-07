//! Grounded, end-to-end association discovery over one retained source generation (#1012).
//!
//! The source graph remains a typed multigraph.  A separate max-weight endpoint
//! projection is built once for algorithms that require a scalar graph; no typed
//! evidence is discarded from the persisted artifact.  Discovery is deliberately
//! two-phase: [`prepare_association_discovery`] constructs candidates and the
//! exact evidence packet an evaluator may cite, while
//! [`finalize_association_discovery`] accepts only independent, citation-valid
//! evaluator receipts and combines them with leakage-free held-out evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result, TrustTag};
pub use calyx_lodestar::EvaluatorRun;
use calyx_lodestar::{
    ChainWalkParams, ChainWalkReport, ChainWalkSeed, ChainWalkSeedKind, DiscoveryChainParams,
    DiscoveryGateVerdict, HypothesisEvaluationInput, HypothesisEvaluationParams,
    HypothesisEvaluationReport, HypothesisEvaluationVerdict, RankedHypothesisParams,
    RankedHypothesisReport, RetrievedEvidence, SpectralCommunityParams, SpectralCommunityReport,
    TraceableHypothesisInput, aggregate_hypothesis_evaluations, rank_traceable_hypotheses,
    run_chain_walks_with_gate, spectral_community_report,
};
use calyx_paths::AssocGraph;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    KernelBuildConfig, KernelGraph, KernelGraphEdge, KernelGraphNode, LatentConfig,
    LatentDiscoveryReport, LatentPair, LatentRelation, build_kernel, latent_corpus_sweep,
};

/// Schema for the prepared, evaluator-independent discovery generation.
pub const DISCOVERY_PREPARED_SCHEMA: &str = "astrolabe.association_discovery.prepared.v1";
/// Schema for the finalized reasoning generation.
pub const DISCOVERY_FINAL_SCHEMA: &str = "astrolabe.association_discovery.final.v1";
/// Refusal raised for incomplete or internally inconsistent source state.
pub const ASTRO_DISCOVERY_SOURCE_INCOMPLETE: &str = "ASTRO_DISCOVERY_SOURCE_INCOMPLETE";
/// Refusal raised for a graph that cannot support the requested mathematics.
pub const ASTRO_DISCOVERY_GRAPH_INVALID: &str = "ASTRO_DISCOVERY_GRAPH_INVALID";
/// Refusal raised when evaluator evidence is absent, mismatched, or invalid.
pub const ASTRO_DISCOVERY_EVALUATOR_INVALID: &str = "ASTRO_DISCOVERY_EVALUATOR_INVALID";
/// Refusal raised when bounded worker-pool construction fails.
pub const ASTRO_DISCOVERY_WORKERS_INVALID: &str = "ASTRO_DISCOVERY_WORKERS_INVALID";

/// Exact physical-completeness proof produced by assay/loom/weave reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationCompletenessWitness {
    pub constellation_count: u64,
    pub source_slot_count: u64,
    pub pair_count: u64,
    pub completion_witness_state_hash: String,
    pub xterm_key_stream_hash: String,
    pub xterm_value_stream_hash: String,
}

/// One exact source concept.  Normalization is an additional deterministic
/// identity; it never replaces `cx_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryConceptInput {
    pub cx_id: CxId,
    pub symbol_kind: String,
    pub language: String,
    pub qualified_name: String,
    pub signature_or_shape: String,
    pub file_path: String,
    pub source_sha256: String,
    pub source_excerpt: String,
    pub frequency: u64,
    pub anchor_trust: Option<TrustTag>,
}

/// One evidence row of the typed multigraph.  Parallel rows are first-class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryTypedEdgeInput {
    pub evidence_id: String,
    pub src: CxId,
    pub dst: CxId,
    pub edge_type_code: i64,
    pub edge_type_name: String,
    pub family: String,
    pub weight: f32,
    pub trust: TrustTag,
    pub temporal_direction: Option<String>,
    pub observed_at_millis: Option<u64>,
    pub ledger_ref: String,
    pub provenance: Vec<String>,
    pub source_generation_sha256: String,
}

/// All inputs retained at one MVCC sequence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssociationDiscoveryInput {
    pub project: String,
    pub source_seq: u64,
    pub source_generation_sha256: String,
    pub concepts: Vec<DiscoveryConceptInput>,
    pub typed_edges: Vec<DiscoveryTypedEdgeInput>,
    pub completeness: AssociationCompletenessWitness,
}

/// All measured limits and thresholds used by discovery.  They are serialized
/// into every generation so no cap or score boundary is hidden.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssociationDiscoveryConfig {
    pub max_intermediary_degree: u64,
    pub min_shared_intermediaries: u64,
    pub pair_budget: u64,
    pub latent_top_k: u64,
    pub listed_intermediaries: u64,
    pub spectral_eigen_k: usize,
    pub spectral_eigen_max_iter: usize,
    pub spectral_centrality_max_iter: usize,
    pub spectral_centrality_tolerance: f32,
    pub spectral_candidate_limit: usize,
    pub walk_max_hops: usize,
    pub walk_branch_width: usize,
    pub walk_probe_width: usize,
    pub walk_max_groundedness_distance: usize,
    pub walk_min_gate_confidence: f32,
    pub walk_min_edge_weight: f32,
    pub walk_provisional_trust_multiplier: f32,
    pub walk_seed_limit: usize,
    pub walk_hypotheses_per_seed: usize,
    pub allowed_walk_edge_families: BTreeSet<String>,
    pub cross_validation_folds: usize,
    pub cross_validation_top_k: usize,
    pub workers: usize,
    pub evaluator: HypothesisEvaluationParams,
    pub ranking: RankedHypothesisParams,
    pub reasoning_kernel: KernelBuildConfig,
}

impl Default for AssociationDiscoveryConfig {
    fn default() -> Self {
        let latent = LatentConfig::with_registry_defaults();
        Self {
            max_intermediary_degree: latent.max_intermediary_degree,
            min_shared_intermediaries: latent.min_shared_intermediaries,
            pair_budget: latent.pair_budget,
            latent_top_k: latent.top_k,
            listed_intermediaries: latent.listed_intermediaries,
            spectral_eigen_k: 3,
            spectral_eigen_max_iter: 256,
            spectral_centrality_max_iter: 128,
            spectral_centrality_tolerance: 1.0e-6,
            spectral_candidate_limit: 64,
            walk_max_hops: 4,
            walk_branch_width: 3,
            walk_probe_width: 16,
            walk_max_groundedness_distance: 3,
            walk_min_gate_confidence: 0.25,
            walk_min_edge_weight: 0.05,
            walk_provisional_trust_multiplier: 0.5,
            walk_seed_limit: 32,
            walk_hypotheses_per_seed: 8,
            allowed_walk_edge_families: BTreeSet::from([
                "structural".to_string(),
                "semantic".to_string(),
                "cross_term".to_string(),
                "temporal".to_string(),
            ]),
            cross_validation_folds: 3,
            cross_validation_top_k: 100,
            workers: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
                .clamp(1, 16),
            evaluator: HypothesisEvaluationParams::default(),
            ranking: RankedHypothesisParams::default(),
            reasoning_kernel: KernelBuildConfig::with_registry_defaults(),
        }
    }
}

/// Deterministic semantic view of an exact concept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedConcept {
    pub cx_id: CxId,
    pub normalized_key: String,
    pub tokens: Vec<String>,
    pub symbol_kind: String,
    pub language: String,
    pub signature_or_shape: String,
    pub qualified_name: String,
    pub file_path: String,
    pub source_sha256: String,
    pub anchor_trust: Option<TrustTag>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNoveltyClass {
    NoDirectTypedEdge,
    CrossCommunityBridge,
    TemporalNewRegion,
    PreviouslyKnownOrRecurring,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableLatentIntermediary {
    pub id: CxId,
    pub degree: u64,
    pub resource_allocation_micro: u64,
    pub adamic_adar_micro: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableLatentPair {
    pub a: CxId,
    pub c: CxId,
    pub shared_count: u64,
    pub resource_allocation_micro: u64,
    pub adamic_adar_micro: u64,
    pub intermediaries: Vec<SerializableLatentIntermediary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatentRelationArtifact {
    pub relation: String,
    pub pairs: Vec<SerializableLatentPair>,
    pub intermediaries_considered: u64,
    pub intermediaries_over_broad: u64,
    pub intermediaries_unshared: u64,
    pub pairs_direct_edge: u64,
    pub pairs_accumulated: u64,
    pub pairs_below_min_shared: u64,
    pub pairs_truncated: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryHypothesisCandidate {
    pub hypothesis_id: String,
    pub relation: String,
    pub a: CxId,
    pub b: CxId,
    pub c: CxId,
    pub novelty: GraphNoveltyClass,
    pub cross_community: bool,
    pub grounded_confidence: f32,
    pub claim: String,
    pub evidence: Vec<RetrievedEvidence>,
    pub evidence_ids: Vec<String>,
    pub provenance: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpectralDiscoveryArtifact {
    pub laplacian: String,
    pub eigenproblem: String,
    pub fiedler_eigenvalue: f32,
    pub eigenvalues: Vec<f32>,
    pub partition_gap_lambda3_minus_lambda2: f32,
    pub partition_stability: String,
    pub report: SpectralCommunityReport,
    pub inferred_cross_community_hypothesis_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidationFold {
    pub fold: usize,
    pub training_edge_count: usize,
    pub held_out_edge_count: usize,
    pub held_out_pair_count: usize,
    pub future_excluded_edge_count: usize,
    pub future_excluded_pair_count: usize,
    pub training_leakage_pair_count: usize,
    pub predicted_pair_count: usize,
    pub hits_at_k: usize,
    pub precision_at_k: f64,
    pub recall_at_k: f64,
    pub reciprocal_rank: f64,
    pub coverage: f64,
    pub brier_score: Option<f64>,
    pub null_hits_at_k: usize,
    pub usable: bool,
    pub unusable_reason: Option<String>,
    pub validated_pair_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrossValidationReport {
    pub split_kind: String,
    pub folds: Vec<ValidationFold>,
    pub usable_fold_count: usize,
    pub mean_precision_at_k: f64,
    pub mean_recall_at_k: f64,
    pub mean_reciprocal_rank: f64,
    pub mean_coverage: f64,
    pub mean_null_hits_at_k: f64,
    pub validated_pair_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryGateCounts {
    pub accepted: usize,
    pub refused: usize,
    pub direct_edge_excluded: usize,
    pub missing_typed_evidence: usize,
    pub disallowed_edge_family: usize,
    pub below_edge_weight: usize,
    pub provisional_edge_attenuated: usize,
    pub ungrounded: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreparedAssociationDiscovery {
    pub schema: String,
    pub project: String,
    pub source_seq: u64,
    pub source_generation_sha256: String,
    pub config: AssociationDiscoveryConfig,
    pub completeness: AssociationCompletenessWitness,
    pub normalized_concepts: Vec<NormalizedConcept>,
    pub typed_edges: Vec<DiscoveryTypedEdgeInput>,
    pub algorithm_projection_edge_count: usize,
    pub latent: Vec<LatentRelationArtifact>,
    pub spectral: SpectralDiscoveryArtifact,
    pub walks: ChainWalkReport,
    pub gate_counts: DiscoveryGateCounts,
    pub candidates: Vec<DiscoveryHypothesisCandidate>,
    pub validation: CrossValidationReport,
    pub graph_compile_count: usize,
    pub worker_pool_reused: bool,
    pub trust: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreparedAssociationDiscoveryEnvelope {
    pub artifact_sha256: String,
    pub artifact: PreparedAssociationDiscovery,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactReasoningKernel {
    pub schema: String,
    pub trust: String,
    pub member_ids: Vec<CxId>,
    pub members_hash: String,
    pub hypothesis_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub retained_typed_edges: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FinalAssociationDiscovery {
    pub schema: String,
    pub prepared_artifact_sha256: String,
    pub evaluator: HypothesisEvaluationReport,
    pub ranked: RankedHypothesisReport,
    pub reasoning_kernel: CompactReasoningKernel,
    pub trust: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FinalAssociationDiscoveryEnvelope {
    pub artifact_sha256: String,
    pub artifact: FinalAssociationDiscovery,
}

static WORKER_POOLS: OnceLock<Mutex<BTreeMap<usize, Arc<rayon::ThreadPool>>>> = OnceLock::new();

fn worker_pool(workers: usize) -> Result<(Arc<rayon::ThreadPool>, bool)> {
    if workers == 0 || workers > 256 {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_WORKERS_INVALID,
            format!("workers={workers} is outside the declared range 1..=256"),
            "set discovery workers to a positive bounded value no greater than 256",
        ));
    }
    let pools = WORKER_POOLS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut guard = pools.lock().map_err(|_| {
        DomainError::new(
            ASTRO_DISCOVERY_WORKERS_INVALID,
            "the retained discovery worker-pool registry is poisoned",
            "restart the Astrolabe process and inspect the preceding worker panic",
        )
    })?;
    if let Some(pool) = guard.get(&workers) {
        return Ok((Arc::clone(pool), true));
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|index| format!("astrolabe-discovery-{index}"))
        .build()
        .map_err(|error| {
            DomainError::new(
                ASTRO_DISCOVERY_WORKERS_INVALID,
                format!("failed to construct {workers}-worker discovery pool: {error}"),
                "reduce the declared worker count or repair host thread creation before retrying",
            )
        })?;
    let pool = Arc::new(pool);
    guard.insert(workers, Arc::clone(&pool));
    Ok((pool, false))
}

/// Prepares every deterministic discovery stage over one exact source.
pub fn prepare_association_discovery(
    input: &AssociationDiscoveryInput,
    config: &AssociationDiscoveryConfig,
) -> Result<PreparedAssociationDiscoveryEnvelope> {
    validate_config(config)?;
    validate_input(input)?;
    let (pool, worker_pool_reused) = worker_pool(config.workers)?;
    let normalized_concepts = normalize_concepts(&input.concepts);
    let kernel_graph = kernel_graph(input)?;
    let indexed = kernel_graph.compile()?;
    let algorithm_graph = assoc_graph(input)?;
    let evidence_index = DiscoveryEvidenceIndex::new(input);

    let latent_config = latent_config(config);
    let relations = [
        LatentRelation::Coupling,
        LatentRelation::CoCitation,
        LatentRelation::Undirected,
    ];
    let latent_reports = pool.install(|| {
        relations
            .par_iter()
            .map(|relation| {
                latent_corpus_sweep(&indexed, *relation, &latent_config)
                    .map(serializable_latent_report)
            })
            .collect::<Vec<_>>()
    });
    let latent = collect_domain_results(latent_reports)?;

    let spectral_params = SpectralCommunityParams {
        eigen_k: config.spectral_eigen_k,
        eigen_max_iter: config.spectral_eigen_max_iter,
        centrality_max_iter: config.spectral_centrality_max_iter,
        centrality_tol: config.spectral_centrality_tolerance,
        max_bridge_candidates: config.spectral_candidate_limit,
        max_centrality_candidates: config.spectral_candidate_limit,
    };
    let spectral_report =
        spectral_community_report(&algorithm_graph, &spectral_params).map_err(map_lodestar)?;
    if spectral_report.eigenvalues.len() < 3 {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_GRAPH_INVALID,
            "spectral discovery did not produce lambda1, lambda2, and lambda3",
            "supply a graph with at least three connected concepts and a convergent three-eigenpair configuration",
        ));
    }
    let partition_gap = spectral_report.eigenvalues[2] - spectral_report.eigenvalues[1];
    if !partition_gap.is_finite() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_GRAPH_INVALID,
            "spectral partition stability gap is non-finite",
            "repair non-finite graph weights or increase the declared eigensolver iteration budget",
        ));
    }

    let candidates = build_candidates(input, &evidence_index, &latent, &spectral_report);
    if candidates.is_empty() {
        let intermediaries_considered = latent
            .iter()
            .map(|report| report.intermediaries_considered)
            .sum::<u64>();
        let intermediaries_over_broad = latent
            .iter()
            .map(|report| report.intermediaries_over_broad)
            .sum::<u64>();
        let pairs_accumulated = latent
            .iter()
            .map(|report| report.pairs_accumulated)
            .sum::<u64>();
        let pairs_below_min_shared = latent
            .iter()
            .map(|report| report.pairs_below_min_shared)
            .sum::<u64>();
        let pairs_direct_edge = latent
            .iter()
            .map(|report| report.pairs_direct_edge)
            .sum::<u64>();
        return Err(DomainError::new(
            ASTRO_DISCOVERY_GRAPH_INVALID,
            format!(
                "no latent candidate exists after the declared association gates: \
                 intermediaries_considered={intermediaries_considered}, \
                 intermediaries_over_broad={intermediaries_over_broad}, \
                 pairs_accumulated={pairs_accumulated}, \
                 pairs_below_min_shared={pairs_below_min_shared}, \
                 pairs_direct_edge={pairs_direct_edge}"
            ),
            "inspect the disclosed gate counts; change a breadth/shared-intermediary limit only with measured evidence, or repair missing graph associations",
        ));
    }
    let (walks, gate_counts) = run_typed_walks(
        input,
        &evidence_index,
        &algorithm_graph,
        &candidates,
        config,
    )?;
    let candidates = merge_walk_candidates(input, &evidence_index, candidates, &walks);
    let validation = cross_validate(input, config, &pool)?;
    let cross_ids = candidates
        .iter()
        .filter(|candidate| candidate.cross_community)
        .map(|candidate| candidate.hypothesis_id.clone())
        .collect();
    let spectral = SpectralDiscoveryArtifact {
        laplacian: "unnormalized_degree_minus_adjacency".to_string(),
        eigenproblem: "sparse_lanczos_smallest_eigenpairs".to_string(),
        fiedler_eigenvalue: spectral_report.fiedler_eigenvalue,
        eigenvalues: spectral_report.eigenvalues.clone(),
        partition_gap_lambda3_minus_lambda2: partition_gap,
        partition_stability: if partition_gap > f32::EPSILON {
            "measured_positive_partition_gap".to_string()
        } else {
            "ambiguous_zero_partition_gap".to_string()
        },
        report: spectral_report,
        inferred_cross_community_hypothesis_ids: cross_ids,
    };
    let artifact = PreparedAssociationDiscovery {
        schema: DISCOVERY_PREPARED_SCHEMA.to_string(),
        project: input.project.clone(),
        source_seq: input.source_seq,
        source_generation_sha256: input.source_generation_sha256.clone(),
        config: config.clone(),
        completeness: input.completeness.clone(),
        normalized_concepts,
        typed_edges: sorted_typed_edges(&input.typed_edges),
        algorithm_projection_edge_count: algorithm_graph.edge_count(),
        latent,
        spectral,
        walks,
        gate_counts,
        candidates,
        validation,
        graph_compile_count: 1,
        worker_pool_reused,
        trust: "provisional_pending_independent_evaluator".to_string(),
    };
    let artifact_sha256 = sha256_hex(&canonical_json_bytes(&artifact)?);
    Ok(PreparedAssociationDiscoveryEnvelope {
        artifact_sha256,
        artifact,
    })
}

/// Finalizes a prepared artifact only when evaluator receipts cite its exact
/// evidence and satisfy Lodestar's independent-run contract.
pub fn finalize_association_discovery(
    prepared: &PreparedAssociationDiscoveryEnvelope,
    evaluator_runs: &BTreeMap<String, Vec<EvaluatorRun>>,
) -> Result<FinalAssociationDiscoveryEnvelope> {
    let rederived = sha256_hex(&canonical_json_bytes(&prepared.artifact)?);
    if rederived != prepared.artifact_sha256 {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            format!(
                "prepared artifact hash mismatch: declared {} rederived {rederived}",
                prepared.artifact_sha256
            ),
            "reload the exact prepared generation and submit evaluator receipts against its physical hash",
        ));
    }
    if prepared.artifact.candidates.is_empty() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "prepared generation contains no hypotheses to evaluate",
            "repair the association source or discovery gates before attempting publication",
        ));
    }
    if evaluator_runs.is_empty() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "no independent evaluator receipts were supplied",
            "evaluate at least one prepared hypothesis with the required independent prompt and temperature variants",
        ));
    }
    let candidates = prepared
        .artifact
        .candidates
        .iter()
        .map(|candidate| (candidate.hypothesis_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = Vec::with_capacity(evaluator_runs.len());
    for (hypothesis_id, runs) in evaluator_runs {
        let candidate = candidates
            .get(hypothesis_id.as_str())
            .copied()
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!("evaluator receipt names unknown hypothesis {hypothesis_id}"),
                    "cite a hypothesis_id from the exact hash-bound prepared artifact",
                )
            })?;
        inputs.push(HypothesisEvaluationInput {
            hypothesis_id: candidate.hypothesis_id.clone(),
            a: candidate.a,
            b: candidate.b,
            c: candidate.c,
            claim: candidate.claim.clone(),
            grounded_confidence: candidate.grounded_confidence,
            chain_provenance: candidate.provenance.clone(),
            retrieved_evidence: candidate.evidence.clone(),
            evaluator_runs: runs.clone(),
        });
    }
    let evaluator = aggregate_hypothesis_evaluations(&inputs, &prepared.artifact.config.evaluator)
        .map_err(map_evaluator_lodestar)?;
    let by_id = prepared
        .artifact
        .candidates
        .iter()
        .map(|candidate| (candidate.hypothesis_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let validated = prepared
        .artifact
        .validation
        .validated_pair_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut rank_inputs = Vec::new();
    for evaluation in &evaluator.evaluations {
        if evaluation.verdict != HypothesisEvaluationVerdict::RetainForRanking {
            continue;
        }
        let candidate = by_id[&evaluation.hypothesis_id.as_str()];
        rank_inputs.push(TraceableHypothesisInput {
            hypothesis_id: evaluation.hypothesis_id.clone(),
            a: evaluation.a,
            b: evaluation.b,
            c: evaluation.c,
            claim: evaluation.claim.clone(),
            novelty_score: evaluation.novelty_mean,
            grounded_confidence: evaluation.grounded_confidence,
            cross_domain_distance: 2,
            evaluator_plausibility_score: evaluation.plausible_mean,
            evaluator_aggregate_score: evaluation.aggregate_score,
            sufficiency_proof: if validated.contains(&pair_id(evaluation.a, evaluation.c)) {
                "held_out_endpoint_pair_predicted_without_training_pair_leakage".to_string()
            } else {
                "independent_evaluator_only; held_out_support_absent".to_string()
            },
            provenance: candidate.provenance.clone(),
            evidence_ids: candidate.evidence_ids.clone(),
        });
    }
    if rank_inputs.is_empty() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "no evaluator-scored hypothesis passed the declared retention floor",
            "supply more grounded evidence or retain the prepared generation as explicitly provisional",
        ));
    }
    let ranked = rank_traceable_hypotheses(&rank_inputs, &prepared.artifact.config.ranking)
        .map_err(map_evaluator_lodestar)?;
    let reasoning_kernel = compact_reasoning_kernel(prepared, &evaluator, &ranked, &validated)?;
    let trust = reasoning_kernel.trust.clone();
    let artifact = FinalAssociationDiscovery {
        schema: DISCOVERY_FINAL_SCHEMA.to_string(),
        prepared_artifact_sha256: prepared.artifact_sha256.clone(),
        evaluator,
        ranked,
        reasoning_kernel,
        trust,
    };
    let artifact_sha256 = sha256_hex(&canonical_json_bytes(&artifact)?);
    Ok(FinalAssociationDiscoveryEnvelope {
        artifact_sha256,
        artifact,
    })
}

fn validate_config(config: &AssociationDiscoveryConfig) -> Result<()> {
    latent_config(config).validate()?;
    config.reasoning_kernel.validate()?;
    if config.spectral_eigen_k < 3
        || config.spectral_eigen_max_iter == 0
        || config.spectral_centrality_max_iter == 0
        || !config.spectral_centrality_tolerance.is_finite()
        || config.spectral_centrality_tolerance <= 0.0
        || config.spectral_candidate_limit == 0
        || config.walk_max_hops < 2
        || config.walk_branch_width == 0
        || config.walk_probe_width == 0
        || config.walk_seed_limit == 0
        || config.walk_hypotheses_per_seed == 0
        || config.cross_validation_folds < 2
        || config.cross_validation_folds > 32
        || config.cross_validation_top_k == 0
        || config.allowed_walk_edge_families.is_empty()
    {
        return invalid_graph(
            "one or more declared discovery limits are zero or mathematically insufficient",
        );
    }
    for score in [
        config.walk_min_gate_confidence,
        config.walk_min_edge_weight,
        config.walk_provisional_trust_multiplier,
    ] {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return invalid_graph(
                "walk confidence, edge-weight, and provisional-trust values must be finite in [0,1]",
            );
        }
    }
    Ok(())
}

fn validate_input(input: &AssociationDiscoveryInput) -> Result<()> {
    if input.project.trim().is_empty()
        || input.source_generation_sha256.trim().is_empty()
        || input.concepts.len() < 3
        || input.typed_edges.is_empty()
    {
        return incomplete(
            "project, source generation, at least three concepts, and typed edges are required",
        );
    }
    let witness = &input.completeness;
    if witness.constellation_count == 0
        || witness.source_slot_count == 0
        || witness.pair_count == 0
        || witness.completion_witness_state_hash.is_empty()
        || witness.xterm_key_stream_hash.is_empty()
        || witness.xterm_value_stream_hash.is_empty()
    {
        return incomplete(
            "complete Base/Slot/XTerm physical witness counts and hashes are required",
        );
    }
    let mut concepts = BTreeSet::new();
    for concept in &input.concepts {
        if !concepts.insert(concept.cx_id)
            || concept.symbol_kind.trim().is_empty()
            || concept.language.trim().is_empty()
            || concept.qualified_name.trim().is_empty()
            || concept.file_path.trim().is_empty()
            || concept.source_sha256.trim().is_empty()
            || concept.source_excerpt.trim().is_empty()
            || concept.frequency == 0
        {
            return incomplete(
                "concept identities must be unique and every concept must carry kind, language, name, file, source hash/excerpt, and positive frequency",
            );
        }
    }
    let mut evidence = BTreeSet::new();
    let mut structural = 0_usize;
    let mut semantic = 0_usize;
    for edge in &input.typed_edges {
        if !concepts.contains(&edge.src)
            || !concepts.contains(&edge.dst)
            || !edge.weight.is_finite()
            || !(0.0..=1.0).contains(&edge.weight)
            || edge.evidence_id.trim().is_empty()
            || !evidence.insert(edge.evidence_id.as_str())
            || edge.edge_type_name.trim().is_empty()
            || edge.family.trim().is_empty()
            || edge.ledger_ref.trim().is_empty()
            || edge.provenance.is_empty()
            || edge.source_generation_sha256 != input.source_generation_sha256
        {
            return incomplete(
                "typed edges must have unique evidence ids, valid endpoints/weights, type/family/ledger/provenance, and the exact retained source hash",
            );
        }
        structural += usize::from(edge.family == "structural");
        semantic += usize::from(edge.family == "semantic" || edge.family == "cross_term");
    }
    if structural == 0 || semantic == 0 {
        return incomplete(
            "both structural and encoded/embedded semantic association families are required",
        );
    }
    Ok(())
}

fn normalize_concepts(concepts: &[DiscoveryConceptInput]) -> Vec<NormalizedConcept> {
    let mut normalized = concepts
        .iter()
        .map(|concept| {
            let tokens = concept_tokens(&concept.qualified_name);
            let preimage = format!(
                "{}\0{}\0{}\0{}",
                concept.symbol_kind.to_lowercase(),
                concept.language.to_lowercase(),
                tokens.join("\u{1f}"),
                concept.signature_or_shape.trim().to_lowercase()
            );
            NormalizedConcept {
                cx_id: concept.cx_id,
                normalized_key: sha256_hex(preimage.as_bytes()),
                tokens,
                symbol_kind: concept.symbol_kind.clone(),
                language: concept.language.clone(),
                signature_or_shape: concept.signature_or_shape.clone(),
                qualified_name: concept.qualified_name.clone(),
                file_path: concept.file_path.clone(),
                source_sha256: concept.source_sha256.clone(),
                anchor_trust: concept.anchor_trust,
            }
        })
        .collect::<Vec<_>>();
    normalized.sort_by_key(|concept| concept.cx_id);
    normalized
}

fn concept_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut prior_lower = false;
    for ch in value.chars() {
        if ch.is_alphanumeric() {
            if ch.is_uppercase() && prior_lower && !current.is_empty() {
                tokens.push(current.to_lowercase());
                current.clear();
            }
            prior_lower = ch.is_lowercase();
            current.push(ch);
        } else {
            if !current.is_empty() {
                tokens.push(current.to_lowercase());
                current.clear();
            }
            prior_lower = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current.to_lowercase());
    }
    tokens
}

fn kernel_graph(input: &AssociationDiscoveryInput) -> Result<KernelGraph> {
    kernel_graph_from_edges(&input.concepts, input.typed_edges.iter())
}

fn kernel_graph_from_edges<'a>(
    concepts: &[DiscoveryConceptInput],
    edges: impl IntoIterator<Item = &'a DiscoveryTypedEdgeInput>,
) -> Result<KernelGraph> {
    let nodes = concepts
        .iter()
        .map(|concept| KernelGraphNode::new(concept.cx_id, concept.frequency, concept.anchor_trust))
        .collect();
    let edges = edges
        .into_iter()
        .map(|edge| KernelGraphEdge::new(edge.src, edge.dst, edge.weight))
        .collect();
    KernelGraph::new(nodes, edges)
}

fn assoc_graph(input: &AssociationDiscoveryInput) -> Result<AssocGraph> {
    let mut builder = AssocGraph::builder();
    for concept in &input.concepts {
        builder
            .add_node(concept.cx_id, concept.frequency as f32)
            .map_err(map_paths)?;
    }
    for edge in &input.typed_edges {
        builder
            .add_edge(edge.src, edge.dst, edge.weight)
            .map_err(map_paths)?;
    }
    Ok(builder.build())
}

fn latent_config(config: &AssociationDiscoveryConfig) -> LatentConfig {
    LatentConfig {
        max_intermediary_degree: config.max_intermediary_degree,
        min_shared_intermediaries: config.min_shared_intermediaries,
        pair_budget: config.pair_budget,
        top_k: config.latent_top_k,
        listed_intermediaries: config.listed_intermediaries,
    }
}

fn serializable_latent_report(report: LatentDiscoveryReport) -> LatentRelationArtifact {
    LatentRelationArtifact {
        relation: report.relation.as_str().to_string(),
        pairs: report.pairs.iter().map(serializable_latent_pair).collect(),
        intermediaries_considered: report.disclosure.intermediaries_considered,
        intermediaries_over_broad: report.disclosure.intermediaries_over_broad,
        intermediaries_unshared: report.disclosure.intermediaries_unshared,
        pairs_direct_edge: report.disclosure.pairs_direct_edge,
        pairs_accumulated: report.disclosure.pairs_accumulated,
        pairs_below_min_shared: report.disclosure.pairs_below_min_shared,
        pairs_truncated: report.disclosure.pairs_truncated,
    }
}

fn serializable_latent_pair(pair: &LatentPair) -> SerializableLatentPair {
    SerializableLatentPair {
        a: pair.a,
        c: pair.c,
        shared_count: pair.shared_count,
        resource_allocation_micro: pair.resource_allocation_micro,
        adamic_adar_micro: pair.adamic_adar_micro,
        intermediaries: pair
            .intermediaries
            .iter()
            .map(|row| SerializableLatentIntermediary {
                id: row.id,
                degree: row.degree,
                resource_allocation_micro: row.resource_allocation_micro,
                adamic_adar_micro: row.adamic_adar_micro,
            })
            .collect(),
    }
}

struct DiscoveryEvidenceIndex<'a> {
    concepts: BTreeMap<CxId, &'a DiscoveryConceptInput>,
    edges_by_direction: BTreeMap<(CxId, CxId), Vec<&'a DiscoveryTypedEdgeInput>>,
    direct_pairs: BTreeSet<(CxId, CxId)>,
    temporal_new_nodes: BTreeSet<CxId>,
}

impl<'a> DiscoveryEvidenceIndex<'a> {
    fn new(input: &'a AssociationDiscoveryInput) -> Self {
        let concepts = input
            .concepts
            .iter()
            .map(|concept| (concept.cx_id, concept))
            .collect();
        let mut edges_by_direction = BTreeMap::<(CxId, CxId), Vec<&DiscoveryTypedEdgeInput>>::new();
        let mut direct_pairs = BTreeSet::new();
        let mut temporal_new_nodes = BTreeSet::new();
        for edge in &input.typed_edges {
            edges_by_direction
                .entry((edge.src, edge.dst))
                .or_default()
                .push(edge);
            direct_pairs.insert(canonical_pair(edge.src, edge.dst));
            if edge.family == "temporal" && edge.temporal_direction.as_deref() == Some("new_region")
            {
                temporal_new_nodes.extend([edge.src, edge.dst]);
            }
        }
        Self {
            concepts,
            edges_by_direction,
            direct_pairs,
            temporal_new_nodes,
        }
    }
}

fn build_candidates(
    input: &AssociationDiscoveryInput,
    evidence_index: &DiscoveryEvidenceIndex<'_>,
    latent: &[LatentRelationArtifact],
    spectral: &SpectralCommunityReport,
) -> Vec<DiscoveryHypothesisCandidate> {
    let concepts = &evidence_index.concepts;
    let communities = spectral
        .members
        .iter()
        .map(|member| (member.cx_id, member.community))
        .collect::<BTreeMap<_, _>>();
    let mut candidates = Vec::new();
    for report in latent {
        for pair in &report.pairs {
            let Some(intermediary) = pair.intermediaries.first() else {
                continue;
            };
            let cross_community = communities.get(&pair.a) != communities.get(&pair.c);
            let temporal_new = evidence_index.temporal_new_nodes.contains(&pair.a)
                || evidence_index.temporal_new_nodes.contains(&pair.c);
            let novelty = if evidence_index
                .direct_pairs
                .contains(&canonical_pair(pair.a, pair.c))
            {
                GraphNoveltyClass::PreviouslyKnownOrRecurring
            } else if temporal_new {
                GraphNoveltyClass::TemporalNewRegion
            } else if cross_community {
                GraphNoveltyClass::CrossCommunityBridge
            } else {
                GraphNoveltyClass::NoDirectTypedEdge
            };
            let evidence = evidence_for_abc(input, evidence_index, pair.a, intermediary.id, pair.c);
            let evidence_ids = evidence.iter().map(|row| row.evidence_id.clone()).collect();
            let hypothesis_id = hypothesis_id(&report.relation, pair.a, intermediary.id, pair.c);
            candidates.push(DiscoveryHypothesisCandidate {
                hypothesis_id,
                relation: report.relation.clone(),
                a: pair.a,
                b: intermediary.id,
                c: pair.c,
                novelty,
                cross_community,
                grounded_confidence: grounded_confidence(
                    &concepts,
                    pair.a,
                    intermediary.id,
                    pair.c,
                ),
                claim: format!(
                    "{} and {} may share a latent code relationship through {} ({})",
                    concepts[&pair.a].qualified_name,
                    concepts[&pair.c].qualified_name,
                    concepts[&intermediary.id].qualified_name,
                    report.relation
                ),
                evidence,
                evidence_ids,
                provenance: vec![
                    format!(
                        "source_generation_sha256={}",
                        input.source_generation_sha256
                    ),
                    format!("latent_relation={}", report.relation),
                    format!("shared_intermediaries={}", pair.shared_count),
                    format!(
                        "resource_allocation_micro={}",
                        pair.resource_allocation_micro
                    ),
                    format!("adamic_adar_micro={}", pair.adamic_adar_micro),
                    "direct_typed_a_c_edge=absent".to_string(),
                ],
            });
        }
    }
    candidates.sort_by(|left, right| left.hypothesis_id.cmp(&right.hypothesis_id));
    candidates.dedup_by(|left, right| left.hypothesis_id == right.hypothesis_id);
    candidates
}

fn run_typed_walks(
    input: &AssociationDiscoveryInput,
    evidence_index: &DiscoveryEvidenceIndex<'_>,
    graph: &AssocGraph,
    candidates: &[DiscoveryHypothesisCandidate],
    config: &AssociationDiscoveryConfig,
) -> Result<(ChainWalkReport, DiscoveryGateCounts)> {
    let mut starts = BTreeSet::new();
    let mut seeds = Vec::new();
    for candidate in candidates {
        if starts.insert(candidate.a) {
            seeds.push(ChainWalkSeed {
                seed_id: format!("latent-seed:{}", candidate.hypothesis_id),
                kind: ChainWalkSeedKind::StaticCandidate,
                start: candidate.a,
                question: None,
                rationale: candidate.claim.clone(),
                provenance: candidate.provenance.clone(),
            });
            if seeds.len() == config.walk_seed_limit {
                break;
            }
        }
    }
    if seeds.is_empty() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_GRAPH_INVALID,
            "non-empty candidate set yielded no distinct gated-walk seed",
            "preserve the generation and inspect candidate endpoint identities; every candidate must carry a valid A endpoint",
        ));
    }
    let anchors = input
        .concepts
        .iter()
        .filter(|concept| concept.anchor_trust == Some(TrustTag::Trusted))
        .map(|concept| concept.cx_id)
        .collect::<Vec<_>>();
    let mut counts = DiscoveryGateCounts {
        accepted: 0,
        refused: 0,
        direct_edge_excluded: 0,
        missing_typed_evidence: 0,
        disallowed_edge_family: 0,
        below_edge_weight: 0,
        provisional_edge_attenuated: 0,
        ungrounded: 0,
    };
    let params = ChainWalkParams {
        chain: DiscoveryChainParams {
            max_hops: config.walk_max_hops,
            branch_width: config.walk_branch_width,
            probe_width: config.walk_probe_width,
            max_groundedness_distance: config.walk_max_groundedness_distance,
            min_gate_confidence: config.walk_min_gate_confidence,
            novelty_weight: 0.35,
        },
        max_hypotheses_per_seed: config.walk_hypotheses_per_seed,
        min_terminal_confidence: config.walk_min_gate_confidence,
    };
    let direct = &evidence_index.direct_pairs;
    let mut report = run_chain_walks_with_gate(graph, &seeds, &anchors, &params, |candidate| {
        let Some(rows) = evidence_index
            .edges_by_direction
            .get(&(candidate.from, candidate.to))
        else {
            counts.refused += 1;
            counts.missing_typed_evidence += 1;
            return DiscoveryGateVerdict {
                passed: false,
                confidence: 0.0,
                code: "ASTRO_DISCOVERY_TYPED_EVIDENCE_MISSING".to_string(),
                reason: "algorithm projection edge has no exact typed evidence row".to_string(),
                evidence: vec![],
            };
        };
        let allowed = rows
            .iter()
            .filter(|edge| config.allowed_walk_edge_families.contains(&edge.family))
            .collect::<Vec<_>>();
        if allowed.is_empty() {
            counts.refused += 1;
            counts.disallowed_edge_family += 1;
            return DiscoveryGateVerdict {
                passed: false,
                confidence: 0.0,
                code: "ASTRO_DISCOVERY_EDGE_FAMILY_REFUSED".to_string(),
                reason: "no typed evidence row belongs to the declared walk allowlist".to_string(),
                evidence: rows.iter().map(|edge| edge.evidence_id.clone()).collect(),
            };
        }
        let strongest = allowed
            .iter()
            .max_by(|left, right| {
                trusted_edge_weight(left, config).total_cmp(&trusted_edge_weight(right, config))
            })
            .expect("allowed evidence is non-empty");
        let trusted_weight = trusted_edge_weight(strongest, config);
        if strongest.trust == TrustTag::Provisional {
            counts.provisional_edge_attenuated += 1;
        }
        if trusted_weight < config.walk_min_edge_weight {
            counts.refused += 1;
            counts.below_edge_weight += 1;
            return DiscoveryGateVerdict {
                passed: false,
                confidence: trusted_weight,
                code: "ASTRO_DISCOVERY_EDGE_WEIGHT_REFUSED".to_string(),
                reason:
                    "trust-adjusted typed evidence is below the declared walk edge-weight floor"
                        .to_string(),
                evidence: allowed
                    .iter()
                    .map(|edge| edge.evidence_id.clone())
                    .collect(),
            };
        }
        let grounding = candidate
            .groundedness_distance
            .map(|distance| {
                1.0 - distance as f32 / (config.walk_max_groundedness_distance + 1) as f32
            })
            .unwrap_or(0.0);
        let confidence = trusted_weight.min(grounding);
        if confidence < config.walk_min_gate_confidence {
            counts.refused += 1;
            counts.ungrounded += 1;
            return DiscoveryGateVerdict {
                passed: false,
                confidence,
                code: "ASTRO_DISCOVERY_GROUNDING_REFUSED".to_string(),
                reason: "typed edge lacks a sufficiently close Trusted anchor".to_string(),
                evidence: allowed
                    .iter()
                    .map(|edge| edge.evidence_id.clone())
                    .collect(),
            };
        }
        counts.accepted += 1;
        DiscoveryGateVerdict {
            passed: true,
            confidence,
            code: "ASTRO_DISCOVERY_TYPED_GROUNDED_PASS".to_string(),
            reason: "typed evidence family, weight, and Trusted-anchor distance passed".to_string(),
            evidence: allowed
                .iter()
                .flat_map(|edge| [edge.evidence_id.clone(), edge.ledger_ref.clone()])
                .collect(),
        }
    })
    .map_err(map_lodestar)?;
    for result in &mut report.results {
        result.hypotheses.retain(|hypothesis| {
            let absent = !direct.contains(&canonical_pair(hypothesis.a, hypothesis.c));
            if !absent {
                counts.direct_edge_excluded += 1;
            }
            absent
        });
    }
    report.hypothesis_count = report.results.iter().map(|row| row.hypotheses.len()).sum();
    report.completed_chain_count = report
        .results
        .iter()
        .filter(|row| !row.hypotheses.is_empty())
        .count();
    Ok((report, counts))
}

fn merge_walk_candidates(
    input: &AssociationDiscoveryInput,
    evidence_index: &DiscoveryEvidenceIndex<'_>,
    mut candidates: Vec<DiscoveryHypothesisCandidate>,
    walks: &ChainWalkReport,
) -> Vec<DiscoveryHypothesisCandidate> {
    let existing = candidates
        .iter()
        .map(|candidate| (candidate.a, candidate.b, candidate.c))
        .collect::<BTreeSet<_>>();
    for result in &walks.results {
        for hypothesis in &result.hypotheses {
            if existing.contains(&(hypothesis.a, hypothesis.b, hypothesis.c)) {
                continue;
            }
            let evidence = evidence_for_abc(
                input,
                evidence_index,
                hypothesis.a,
                hypothesis.b,
                hypothesis.c,
            );
            if evidence.is_empty() {
                continue;
            }
            let evidence_ids = evidence.iter().map(|row| row.evidence_id.clone()).collect();
            candidates.push(DiscoveryHypothesisCandidate {
                hypothesis_id: hypothesis_id(
                    "gated_multi_hop",
                    hypothesis.a,
                    hypothesis.b,
                    hypothesis.c,
                ),
                relation: "gated_multi_hop".to_string(),
                a: hypothesis.a,
                b: hypothesis.b,
                c: hypothesis.c,
                novelty: GraphNoveltyClass::NoDirectTypedEdge,
                cross_community: false,
                grounded_confidence: hypothesis.terminal_confidence,
                claim: hypothesis.testable_claim.clone(),
                evidence,
                evidence_ids,
                provenance: hypothesis.provenance.clone(),
            });
        }
    }
    candidates.sort_by(|left, right| left.hypothesis_id.cmp(&right.hypothesis_id));
    candidates.dedup_by(|left, right| left.hypothesis_id == right.hypothesis_id);
    candidates
}

fn trusted_edge_weight(edge: &DiscoveryTypedEdgeInput, config: &AssociationDiscoveryConfig) -> f32 {
    edge.weight
        * if edge.trust == TrustTag::Trusted {
            1.0
        } else {
            config.walk_provisional_trust_multiplier
        }
}

fn cross_validate(
    input: &AssociationDiscoveryInput,
    config: &AssociationDiscoveryConfig,
    pool: &rayon::ThreadPool,
) -> Result<CrossValidationReport> {
    let plan = validation_plan(input, config.cross_validation_folds);
    let folds = pool.install(|| {
        plan.folds
            .par_iter()
            .enumerate()
            .map(|(fold, fold_plan)| validation_fold(input, config, fold, fold_plan))
            .collect::<Vec<_>>()
    });
    let folds = collect_domain_results(folds)?;
    let usable = folds.iter().filter(|fold| fold.usable).collect::<Vec<_>>();
    let denominator = usable.len().max(1) as f64;
    let mut validated = usable
        .iter()
        .flat_map(|fold| fold.validated_pair_ids.iter().cloned())
        .collect::<Vec<_>>();
    validated.sort();
    validated.dedup();
    Ok(CrossValidationReport {
        split_kind: plan.split_kind.to_string(),
        usable_fold_count: usable.len(),
        mean_precision_at_k: usable.iter().map(|fold| fold.precision_at_k).sum::<f64>()
            / denominator,
        mean_recall_at_k: usable.iter().map(|fold| fold.recall_at_k).sum::<f64>() / denominator,
        mean_reciprocal_rank: usable.iter().map(|fold| fold.reciprocal_rank).sum::<f64>()
            / denominator,
        mean_coverage: usable.iter().map(|fold| fold.coverage).sum::<f64>() / denominator,
        mean_null_hits_at_k: usable
            .iter()
            .map(|fold| fold.null_hits_at_k as f64)
            .sum::<f64>()
            / denominator,
        folds,
        validated_pair_ids: validated,
    })
}

#[derive(Debug)]
struct ValidationPlan {
    split_kind: &'static str,
    folds: Vec<ValidationFoldPlan>,
}

#[derive(Debug)]
struct ValidationFoldPlan {
    training_pairs: BTreeSet<(CxId, CxId)>,
    held_out_pairs: BTreeSet<(CxId, CxId)>,
    future_excluded_pairs: BTreeSet<(CxId, CxId)>,
}

fn validation_plan(input: &AssociationDiscoveryInput, fold_count: usize) -> ValidationPlan {
    let concepts = input
        .concepts
        .iter()
        .map(|concept| (concept.cx_id, concept.file_path.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut pair_timestamps = BTreeMap::<(CxId, CxId), Option<u64>>::new();
    for edge in &input.typed_edges {
        let pair = canonical_pair(edge.src, edge.dst);
        pair_timestamps
            .entry(pair)
            .and_modify(|timestamp| {
                if let Some(observed) = edge.observed_at_millis {
                    *timestamp = Some(timestamp.unwrap_or(0).max(observed));
                }
            })
            .or_insert(edge.observed_at_millis);
    }
    if pair_timestamps.values().all(Option::is_some) {
        let mut ordered = pair_timestamps
            .into_iter()
            .map(|(pair, timestamp)| (timestamp.expect("all timestamps checked"), pair))
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        let mut buckets = vec![BTreeSet::new(); fold_count];
        let pair_count = ordered.len();
        for (rank, (_, pair)) in ordered.into_iter().enumerate() {
            let bucket = rank
                .saturating_mul(fold_count)
                .checked_div(pair_count.max(1))
                .unwrap_or(0)
                .min(fold_count - 1);
            buckets[bucket].insert(pair);
        }
        let folds = (0..fold_count)
            .map(|fold| ValidationFoldPlan {
                training_pairs: buckets[..fold]
                    .iter()
                    .flat_map(|pairs| pairs.iter().copied())
                    .collect(),
                held_out_pairs: buckets[fold].clone(),
                future_excluded_pairs: buckets[fold + 1..]
                    .iter()
                    .flat_map(|pairs| pairs.iter().copied())
                    .collect(),
            })
            .collect();
        return ValidationPlan {
            split_kind: "temporal_forward_endpoint_pair_group",
            folds,
        };
    }

    let mut buckets = vec![BTreeSet::new(); fold_count];
    for pair in pair_timestamps.keys().copied() {
        let fold = deterministic_pair_fold(pair, &concepts, fold_count);
        buckets[fold].insert(pair);
    }
    let all_pairs = pair_timestamps.keys().copied().collect::<BTreeSet<_>>();
    let folds = buckets
        .into_iter()
        .map(|held_out_pairs| ValidationFoldPlan {
            training_pairs: all_pairs.difference(&held_out_pairs).copied().collect(),
            held_out_pairs,
            future_excluded_pairs: BTreeSet::new(),
        })
        .collect();
    ValidationPlan {
        split_kind: "deterministic_file_endpoint_pair_group",
        folds,
    }
}

fn validation_fold(
    input: &AssociationDiscoveryInput,
    config: &AssociationDiscoveryConfig,
    fold: usize,
    plan: &ValidationFoldPlan,
) -> Result<ValidationFold> {
    let training_edges = input
        .typed_edges
        .iter()
        .filter(|edge| {
            plan.training_pairs
                .contains(&canonical_pair(edge.src, edge.dst))
        })
        .collect::<Vec<_>>();
    let training_pairs = direct_pairs_iter(training_edges.iter().copied());
    let leakage = plan.held_out_pairs.intersection(&training_pairs).count();
    if leakage != 0 {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_SOURCE_INCOMPLETE,
            format!(
                "cross-validation fold {fold} retained {leakage} held-out endpoint pairs in training"
            ),
            "group all parallel typed evidence for one endpoint pair into the same held-out fold",
        ));
    }
    let held_out_edge_count = input
        .typed_edges
        .iter()
        .filter(|edge| {
            plan.held_out_pairs
                .contains(&canonical_pair(edge.src, edge.dst))
        })
        .count();
    let future_excluded_edge_count = input
        .typed_edges
        .iter()
        .filter(|edge| {
            plan.future_excluded_pairs
                .contains(&canonical_pair(edge.src, edge.dst))
        })
        .count();
    if plan.held_out_pairs.is_empty() || training_edges.is_empty() {
        return Ok(ValidationFold {
            fold,
            training_edge_count: training_edges.len(),
            held_out_edge_count,
            held_out_pair_count: plan.held_out_pairs.len(),
            future_excluded_edge_count,
            future_excluded_pair_count: plan.future_excluded_pairs.len(),
            training_leakage_pair_count: 0,
            predicted_pair_count: 0,
            hits_at_k: 0,
            precision_at_k: 0.0,
            recall_at_k: 0.0,
            reciprocal_rank: 0.0,
            coverage: 0.0,
            brier_score: None,
            null_hits_at_k: 0,
            usable: false,
            unusable_reason: Some("fold has no held-out pairs or no training edges".to_string()),
            validated_pair_ids: vec![],
        });
    }
    let graph = kernel_graph_from_edges(&input.concepts, training_edges.iter().copied())?;
    let indexed = graph.compile()?;
    let latent_config = latent_config(config);
    let mut predicted = BTreeMap::<(CxId, CxId), u64>::new();
    for relation in [
        LatentRelation::Coupling,
        LatentRelation::CoCitation,
        LatentRelation::Undirected,
    ] {
        let report = latent_corpus_sweep(&indexed, relation, &latent_config)?;
        for pair in report.pairs {
            predicted
                .entry(canonical_pair(pair.a, pair.c))
                .and_modify(|score| *score = (*score).max(pair.resource_allocation_micro))
                .or_insert(pair.resource_allocation_micro);
        }
    }
    let mut predicted = predicted.into_iter().collect::<Vec<_>>();
    predicted.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| left.0.0.cmp(&right.0.0))
            .then_with(|| left.0.1.cmp(&right.0.1))
    });
    let k = config.cross_validation_top_k.min(predicted.len());
    let ranked = &predicted[..k];
    let hits = ranked
        .iter()
        .filter(|(pair, _)| plan.held_out_pairs.contains(pair))
        .count();
    let reciprocal_rank = ranked
        .iter()
        .position(|(pair, _)| plan.held_out_pairs.contains(pair))
        .map(|index| 1.0 / (index + 1) as f64)
        .unwrap_or(0.0);
    let maximum = ranked
        .iter()
        .map(|(_, score)| *score)
        .max()
        .unwrap_or(1)
        .max(1) as f64;
    let brier = if ranked.is_empty() {
        None
    } else {
        Some(
            ranked
                .iter()
                .map(|(pair, score)| {
                    let probability = *score as f64 / maximum;
                    let outcome = f64::from(plan.held_out_pairs.contains(pair));
                    (probability - outcome).powi(2)
                })
                .sum::<f64>()
                / ranked.len() as f64,
        )
    };
    let mut permuted = predicted.clone();
    permuted.sort_by_key(|(pair, _)| sha256_hex(pair_id(pair.0, pair.1).as_bytes()));
    let null_hits = permuted
        .iter()
        .take(k)
        .filter(|(pair, _)| plan.held_out_pairs.contains(pair))
        .count();
    let mut validated = ranked
        .iter()
        .filter(|(pair, _)| plan.held_out_pairs.contains(pair))
        .map(|(pair, _)| pair_id(pair.0, pair.1))
        .collect::<Vec<_>>();
    validated.sort();
    Ok(ValidationFold {
        fold,
        training_edge_count: training_edges.len(),
        held_out_edge_count,
        held_out_pair_count: plan.held_out_pairs.len(),
        future_excluded_edge_count,
        future_excluded_pair_count: plan.future_excluded_pairs.len(),
        training_leakage_pair_count: leakage,
        predicted_pair_count: predicted.len(),
        hits_at_k: hits,
        precision_at_k: hits as f64 / k.max(1) as f64,
        recall_at_k: hits as f64 / plan.held_out_pairs.len() as f64,
        reciprocal_rank,
        coverage: k as f64 / predicted.len().max(1) as f64,
        brier_score: brier,
        null_hits_at_k: null_hits,
        usable: true,
        unusable_reason: None,
        validated_pair_ids: validated,
    })
}

fn compact_reasoning_kernel(
    prepared: &PreparedAssociationDiscoveryEnvelope,
    evaluator: &HypothesisEvaluationReport,
    ranked: &RankedHypothesisReport,
    validated: &BTreeSet<String>,
) -> Result<CompactReasoningKernel> {
    let retained = evaluator
        .evaluations
        .iter()
        .filter(|row| row.verdict == HypothesisEvaluationVerdict::RetainForRanking)
        .map(|row| row.hypothesis_id.as_str())
        .collect::<BTreeSet<_>>();
    let candidates = prepared
        .artifact
        .candidates
        .iter()
        .map(|row| (row.hypothesis_id.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let mut member_ids = BTreeSet::new();
    let mut hypothesis_ids = Vec::new();
    let mut evidence_ids = BTreeSet::new();
    for hypothesis in &ranked.hypotheses {
        if !retained.contains(hypothesis.hypothesis_id.as_str()) {
            continue;
        }
        let candidate = candidates[&hypothesis.hypothesis_id.as_str()];
        member_ids.extend([candidate.a, candidate.b, candidate.c]);
        hypothesis_ids.push(candidate.hypothesis_id.clone());
        evidence_ids.extend(candidate.evidence_ids.iter().cloned());
    }
    let graph = KernelGraph::new(
        prepared
            .artifact
            .normalized_concepts
            .iter()
            .filter(|concept| member_ids.contains(&concept.cx_id))
            .map(|concept| KernelGraphNode::new(concept.cx_id, 1, concept.anchor_trust))
            .collect(),
        prepared
            .artifact
            .typed_edges
            .iter()
            .filter(|edge| member_ids.contains(&edge.src) && member_ids.contains(&edge.dst))
            .map(|edge| KernelGraphEdge::new(edge.src, edge.dst, edge.weight))
            .collect(),
    )?;
    let compact = build_kernel(
        &graph,
        &format!("discovery:{}", prepared.artifact_sha256),
        &prepared.artifact.config.reasoning_kernel,
    )?;
    let retained_typed_edges = prepared
        .artifact
        .typed_edges
        .iter()
        .filter(|edge| member_ids.contains(&edge.src) && member_ids.contains(&edge.dst))
        .map(|edge| edge.evidence_id.clone())
        .collect::<Vec<_>>();
    let all_validated = ranked
        .hypotheses
        .iter()
        .all(|row| validated.contains(&pair_id(row.a, row.c)));
    let all_fully_grounded = ranked.hypotheses.iter().all(|row| {
        candidates
            .get(row.hypothesis_id.as_str())
            .is_some_and(|candidate| candidate.grounded_confidence >= 1.0)
    });
    Ok(CompactReasoningKernel {
        schema: "astrolabe.discovery_reasoning_kernel.v1".to_string(),
        trust: if all_validated && all_fully_grounded {
            "grounded_evaluator_and_held_out".to_string()
        } else {
            "provisional_evaluator_grounded_held_out_incomplete".to_string()
        },
        member_ids: compact.members.iter().map(|member| member.id).collect(),
        members_hash: compact.members_hash,
        hypothesis_ids,
        evidence_ids: evidence_ids.into_iter().collect(),
        retained_typed_edges,
    })
}

fn evidence_for_abc(
    input: &AssociationDiscoveryInput,
    evidence_index: &DiscoveryEvidenceIndex<'_>,
    a: CxId,
    b: CxId,
    c: CxId,
) -> Vec<RetrievedEvidence> {
    let mut rows = Vec::new();
    for id in [a, b, c] {
        if let Some(concept) = evidence_index.concepts.get(&id) {
            rows.push(RetrievedEvidence {
                evidence_id: format!("source:{}", concept.cx_id),
                source_cx_id: concept.cx_id,
                title: concept.qualified_name.clone(),
                abstract_text: concept.source_excerpt.clone(),
                grounding_confidence: if concept.anchor_trust == Some(TrustTag::Trusted) {
                    1.0
                } else {
                    0.5
                },
                provenance: vec![
                    format!("source_sha256={}", concept.source_sha256),
                    format!(
                        "source_generation_sha256={}",
                        input.source_generation_sha256
                    ),
                    format!("file={}", concept.file_path),
                ],
            });
        }
    }
    for direction in [(a, b), (b, a), (b, c), (c, b)] {
        for edge in evidence_index
            .edges_by_direction
            .get(&direction)
            .into_iter()
            .flatten()
        {
            rows.push(RetrievedEvidence {
                evidence_id: edge.evidence_id.clone(),
                source_cx_id: edge.src,
                title: format!("{}:{}", edge.family, edge.edge_type_name),
                abstract_text: format!(
                    "typed association {} -> {} weight={} trust={:?}",
                    edge.src, edge.dst, edge.weight, edge.trust
                ),
                grounding_confidence: edge.weight,
                provenance: edge
                    .provenance
                    .iter()
                    .cloned()
                    .chain([edge.ledger_ref.clone()])
                    .collect(),
            });
        }
    }
    rows.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    rows.dedup_by(|left, right| left.evidence_id == right.evidence_id);
    rows
}

fn grounded_confidence(
    concepts: &BTreeMap<CxId, &DiscoveryConceptInput>,
    a: CxId,
    b: CxId,
    c: CxId,
) -> f32 {
    let trusted = [a, b, c]
        .iter()
        .filter(|id| concepts[id].anchor_trust == Some(TrustTag::Trusted))
        .count();
    trusted as f32 / 3.0
}

fn sorted_typed_edges(edges: &[DiscoveryTypedEdgeInput]) -> Vec<DiscoveryTypedEdgeInput> {
    let mut edges = edges.to_vec();
    edges.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    edges
}

fn deterministic_pair_fold(
    pair: (CxId, CxId),
    concepts: &BTreeMap<CxId, &str>,
    fold_count: usize,
) -> usize {
    let (left, right) = pair;
    let mut parts = [concepts[&left], concepts[&right]];
    parts.sort_unstable();
    let digest = Sha256::digest(format!("{}\0{}", parts[0], parts[1]).as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("sha256 prefix")) as usize % fold_count
}

fn direct_pairs(edges: &[DiscoveryTypedEdgeInput]) -> BTreeSet<(CxId, CxId)> {
    direct_pairs_iter(edges.iter())
}

fn direct_pairs_iter<'a>(
    edges: impl IntoIterator<Item = &'a DiscoveryTypedEdgeInput>,
) -> BTreeSet<(CxId, CxId)> {
    edges
        .into_iter()
        .map(|edge| canonical_pair(edge.src, edge.dst))
        .collect()
}

fn canonical_pair(a: CxId, c: CxId) -> (CxId, CxId) {
    if a <= c { (a, c) } else { (c, a) }
}

fn pair_id(a: CxId, c: CxId) -> String {
    let (a, c) = canonical_pair(a, c);
    format!("{a}:{c}")
}

fn hypothesis_id(relation: &str, a: CxId, b: CxId, c: CxId) -> String {
    sha256_hex(format!("{relation}\0{a}\0{b}\0{c}").as_bytes())
}

fn collect_domain_results<T>(rows: Vec<Result<T>>) -> Result<Vec<T>> {
    rows.into_iter().collect()
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        DomainError::new(
            ASTRO_DISCOVERY_SOURCE_INCOMPLETE,
            format!("association discovery artifact serialization failed: {error}"),
            "repair non-serializable or non-finite discovery state before publication",
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn incomplete<T>(message: impl Into<String>) -> Result<T> {
    Err(DomainError::new(
        ASTRO_DISCOVERY_SOURCE_INCOMPLETE,
        message,
        "reconcile the exact retained Graph/Base/Slot/XTerm generation and retry without partial input",
    ))
}

fn invalid_graph<T>(message: impl Into<String>) -> Result<T> {
    Err(DomainError::new(
        ASTRO_DISCOVERY_GRAPH_INVALID,
        message,
        "supply a complete graph and set every discovery limit within its declared mathematical bounds",
    ))
}

fn map_lodestar(error: calyx_lodestar::LodestarError) -> DomainError {
    DomainError::new(
        error.code(),
        error.to_string(),
        "inspect the exact discovery stage input and repair the named Calyx mathematical invariant before retrying",
    )
}

fn map_evaluator_lodestar(error: calyx_lodestar::LodestarError) -> DomainError {
    DomainError::new(
        ASTRO_DISCOVERY_EVALUATOR_INVALID,
        error.to_string(),
        "repair the independent evaluator receipts against the exact prepared generation and retry publication",
    )
}

fn map_paths(error: calyx_paths::PathsError) -> DomainError {
    DomainError::new(
        error.code(),
        error.to_string(),
        "repair the typed graph endpoint or finite weight named by the graph error before retrying",
    )
}
