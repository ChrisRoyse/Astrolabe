//! Grounded, end-to-end association discovery over one retained source generation (#1012).
//!
//! The source graph remains a typed multigraph.  A separate max-weight endpoint
//! projection is built once for algorithms that require a scalar graph; no typed
//! evidence is discarded from the persisted artifact.  Discovery is deliberately
//! two-phase: [`prepare_association_discovery`] constructs candidates and the
//! exact evidence packet an evaluator may cite, while
//! [`finalize_association_discovery`] accepts only citation-valid receipts with
//! unique caller-attested external invocation identities and combines them with
//! leakage-free held-out evidence. Local code binds capture bytes but cannot
//! prove that a remote provider call occurred.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write as IoWrite};
use std::sync::{Arc, Mutex, OnceLock};

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result, TrustTag};
use calyx_lodestar::{
    ChainWalkParams, ChainWalkReport, ChainWalkSeed, ChainWalkSeedKind, DiscoveryChainParams,
    DiscoveryGateVerdict, HypothesisEvaluationInput, HypothesisEvaluationParams,
    HypothesisEvaluationReport, HypothesisEvaluationVerdict, RankedHypothesisParams,
    RetrievedEvidence, SpectralCommunityParams, SpectralCommunityReport,
    aggregate_hypothesis_evaluations, run_chain_walks_with_gate, spectral_community_report,
};
use calyx_paths::AssocGraph;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    KernelArtifact, KernelBuildConfig, KernelGraph, KernelGraphEdge, KernelGraphNode, LatentConfig,
    LatentDiscoveryReport, LatentPair, LatentRelation, build_kernel, latent_corpus_sweep,
};

/// Schema for the prepared, evaluator-independent discovery generation.
pub const DISCOVERY_PREPARED_SCHEMA: &str = "astrolabe.association_discovery.prepared.v4";
/// Schema for the finalized reasoning generation.
pub const DISCOVERY_FINAL_SCHEMA: &str = "astrolabe.association_discovery.final.v4";
/// Canonical source-manifest schema.
pub const DISCOVERY_SOURCE_MANIFEST_SCHEMA: &str =
    "astrolabe.association_discovery.source_manifest.v3";
/// Exact evaluator-binding roster schema.
pub const DISCOVERY_EVALUATION_ROSTER_SCHEMA: &str =
    "astrolabe.association_discovery.evaluation_roster.v2";
/// Exact evaluator request schema emitted by preparation.
pub const DISCOVERY_EVALUATOR_REQUEST_SCHEMA: &str =
    "astrolabe.association_discovery.evaluator_request.v1";
/// Strict evaluator response schema accepted by finalization.
pub const DISCOVERY_EVALUATOR_RESPONSE_SCHEMA: &str =
    "astrolabe.association_discovery.evaluator_response.v1";
/// Evaluator receipt schema persisted in the final generation.
pub const DISCOVERY_EVALUATOR_RECEIPT_SCHEMA: &str =
    "astrolabe.association_discovery.evaluator_receipt.v2";
/// Caller-attested capture metadata for the trusted single-operator external
/// evaluator boundary. The bytes are identity-bound and auditable; this local
/// code does not claim it can prove that a remote provider call occurred.
pub const DISCOVERY_EXTERNAL_CAPTURE_SCHEMA: &str =
    "astrolabe.association_discovery.trusted_external_capture.v1";
/// Refusal raised for incomplete or internally inconsistent source state.
pub const ASTRO_DISCOVERY_SOURCE_INCOMPLETE: &str = "ASTRO_DISCOVERY_SOURCE_INCOMPLETE";
/// Refusal raised for a graph that cannot support the requested mathematics.
pub const ASTRO_DISCOVERY_GRAPH_INVALID: &str = "ASTRO_DISCOVERY_GRAPH_INVALID";
/// Refusal raised when evaluator evidence is absent, mismatched, or invalid.
pub const ASTRO_DISCOVERY_EVALUATOR_INVALID: &str = "ASTRO_DISCOVERY_EVALUATOR_INVALID";
/// Refusal raised when the retained source no longer matches its manifest.
pub const ASTRO_DISCOVERY_SOURCE_CHANGED: &str = "ASTRO_DISCOVERY_SOURCE_CHANGED";
/// Refusal raised when bounded worker-pool construction fails.
pub const ASTRO_DISCOVERY_WORKERS_INVALID: &str = "ASTRO_DISCOVERY_WORKERS_INVALID";

/// Exact physical-completeness proof produced by assay/loom/weave reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationCompletenessWitness {
    pub constellation_count: u64,
    pub source_slot_count: u64,
    pub pair_count: u64,
    pub completion_witness_state_hash: String,
    pub xterm_key_stream_hash: String,
    pub xterm_value_stream_hash: String,
}

/// Physical source observations and frozen completion semantics. Every column
/// family named here is consumed, directly or transitively, by discovery. The
/// generation values diagnose the retained physical read but are not logical
/// source identity. Later admission rederives the exact logical graph and
/// verified Base/Slot/Compression/XTerm source instead of trusting handle
/// bookkeeping as a substitute for the source bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationSourcePhysicalBinding {
    pub retained_snapshot_seq: u64,
    pub projection_source_fingerprint_blake3: String,
    pub graph_cf_generation: u64,
    pub anchors_cf_generation: u64,
    pub base_cf_generation: u64,
    pub xterm_cf_generation: u64,
    pub completion_witness_cf_generation: u64,
    pub compression_cf_generation: u64,
    pub slot_cf_generations: BTreeMap<u16, u64>,
    pub panel_schema_ids: BTreeMap<u32, String>,
    pub panel_manifest_sha256: BTreeMap<u32, String>,
    pub completion_pair_block_schema: String,
    pub completion_witness_schema: String,
    pub completion_ledger_schema: String,
    pub completion_metric_contract: Vec<String>,
    pub completion_incompatibility_contract: Vec<String>,
}

/// Canonical manifest for every field consumed by one discovery preparation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationSourceManifest {
    pub schema: String,
    pub project: String,
    pub source_seq: u64,
    pub physical: AssociationSourcePhysicalBinding,
    pub completeness: AssociationCompletenessWitness,
    pub concept_count: usize,
    pub concept_stream_sha256: String,
    pub typed_edge_count: usize,
    pub typed_edge_stream_sha256: String,
    pub discovery_prepared_schema: String,
    pub discovery_final_schema: String,
    pub discovery_config_sha256: String,
}

#[derive(Serialize)]
struct StableAssociationSourcePhysicalIdentity<'a> {
    projection_source_fingerprint_blake3: &'a str,
    panel_schema_ids: &'a BTreeMap<u32, String>,
    panel_manifest_sha256: &'a BTreeMap<u32, String>,
    completion_pair_block_schema: &'a str,
    completion_witness_schema: &'a str,
    completion_ledger_schema: &'a str,
    completion_metric_contract: &'a [String],
    completion_incompatibility_contract: &'a [String],
}

#[derive(Serialize)]
struct StableAssociationSourceIdentity<'a> {
    schema: &'static str,
    source_manifest_schema: &'a str,
    project: &'a str,
    physical: StableAssociationSourcePhysicalIdentity<'a>,
    completeness: &'a AssociationCompletenessWitness,
    concept_count: usize,
    concept_stream_sha256: &'a str,
    typed_edge_count: usize,
    typed_edge_stream_sha256: &'a str,
    discovery_prepared_schema: &'a str,
    discovery_final_schema: &'a str,
    discovery_config_sha256: &'a str,
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
    pub source_manifest: AssociationSourceManifest,
    pub concepts: Vec<DiscoveryConceptInput>,
    pub typed_edges: Vec<DiscoveryTypedEdgeInput>,
    pub completeness: AssociationCompletenessWitness,
}

/// All measured limits and thresholds used by discovery.  They are serialized
/// into every generation so no cap or score boundary is hidden.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Caller-owned hard limits. `None` is always refused; no evaluator or
    /// persistence budget is inferred from the machine or corpus.
    pub budgets: Option<AssociationDiscoveryBudgets>,
    /// Exact evaluator/model/prompt variants to expand across every prepared
    /// hypothesis. Empty declarations are a refusal, never an implicit model.
    pub evaluator_declarations: Vec<EvaluatorDeclaration>,
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
            budgets: None,
            evaluator_declarations: Vec::new(),
            evaluator: HypothesisEvaluationParams::default(),
            ranking: RankedHypothesisParams::default(),
            reasoning_kernel: KernelBuildConfig::with_registry_defaults(),
        }
    }
}

/// Mandatory evaluator and durable-generation budgets. They are serialized
/// into the discovery configuration and therefore source/artifact identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationDiscoveryBudgets {
    pub max_evaluation_bindings: usize,
    pub max_request_bytes_per_binding: usize,
    pub max_request_bytes_total: usize,
    pub max_response_bytes_per_binding: usize,
    pub max_response_bytes_total: usize,
    /// Maximum discovery-owned Kernel/Assay physical rows in one publication,
    /// including pointer, manifest, and retention tombstones. Ledger/TimeIndex
    /// protocol rows are owned and bounded by Aster's ledger configuration.
    pub max_generation_rows: usize,
    /// Maximum discovery key+value bytes plus exact Ledger payload bytes in one
    /// publication, before Aster's fixed ledger/time-index framing.
    pub max_generation_bytes: usize,
}

/// One evaluator variant declared before candidate preparation. The prompt is
/// retained as exact UTF-8 bytes; no server-side template or default is used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorDeclaration {
    pub evaluator_id: String,
    pub model_id: String,
    pub prompt_id: String,
    pub temperature_x100: u16,
    pub prompt_utf8: String,
}

/// Typed availability of one source field. Missing source state is evidence of
/// absence, not permission to manufacture a path, excerpt, signature, or hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StructuralEvidenceField {
    Available { value: String },
    Unavailable { reason: String },
}

/// Exact structural evidence inventory for a source concept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConceptStructuralEvidence {
    pub cx_id: CxId,
    pub language: StructuralEvidenceField,
    pub signature_or_shape: StructuralEvidenceField,
    pub file_path: StructuralEvidenceField,
    pub source_sha256: StructuralEvidenceField,
    pub source_excerpt: StructuralEvidenceField,
}

/// Deterministic semantic view of an exact concept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedConcept {
    pub cx_id: CxId,
    /// Hash of kind, language, qualified-name tokens, and signature/shape only.
    /// It is retained separately so lexical equivalence never silently merges
    /// concepts whose measured graph contexts differ.
    pub lexical_key: String,
    /// Hash of every incident typed association in canonical evidence order.
    pub association_signature_sha256: String,
    /// Exact count of incident typed evidence rows. A self-edge counts once.
    pub incident_typed_edge_count: u64,
    /// Exact incident evidence counts by the source-declared association family.
    pub association_family_counts: BTreeMap<String, u64>,
    /// Contextual normalization over both `lexical_key` and the measured
    /// `association_signature_sha256`. This remains an additional identity;
    /// `cx_id` is never replaced or merged.
    pub normalized_key: String,
    pub tokens: Vec<String>,
    pub symbol_kind: String,
    pub language: String,
    pub signature_or_shape: String,
    pub qualified_name: String,
    pub file_path: String,
    pub source_sha256: String,
    pub source_excerpt: String,
    pub frequency: u64,
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
    /// Typed source-field availability for A/B/C. This remains separate from
    /// retrieved evaluator evidence so an unavailable excerpt cannot become
    /// fabricated prose.
    pub structural_evidence: Vec<ConceptStructuralEvidence>,
    pub evidence: Vec<RetrievedEvidence>,
    pub evidence_ids: Vec<String>,
    pub provenance: Vec<String>,
}

/// One exact evaluator invocation prepared for one exact hypothesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationBinding {
    pub invocation_id: String,
    pub source_generation_sha256: String,
    pub hypothesis_id: String,
    pub hypothesis_content_sha256: String,
    pub evaluator_id: String,
    pub model_id: String,
    pub prompt_id: String,
    pub temperature_x100: u16,
    pub prompt_utf8: String,
    pub prompt_sha256: String,
    pub request_utf8: String,
    pub request_sha256: String,
}

/// Exact Cartesian product of prepared hypotheses and declared evaluator
/// variants. Finalization accepts exactly this roster, neither a subset nor a
/// structurally plausible superset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRoster {
    pub schema: String,
    pub hypothesis_count: usize,
    pub evaluator_declaration_count: usize,
    pub binding_count: usize,
    pub request_bytes_total: usize,
    pub bindings_sha256: String,
    pub bindings: Vec<EvaluationBinding>,
}

/// Strict JSON object parsed from exact evaluator response bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorResponseParseResult {
    pub schema: String,
    pub plausible_score: f32,
    pub novelty_score: f32,
    pub testability_score: f32,
    pub falsifiability_score: f32,
    pub justification: String,
    pub falsification_test: String,
    pub cited_evidence_ids: Vec<String>,
}

/// Durable receipt for one real external evaluator invocation. All scores and
/// prose below are checked against `response_utf8`; caller-supplied parsed data
/// can never override the exact response bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorReceipt {
    pub schema: String,
    pub invocation_id: String,
    /// Caller-attested unique identity returned by, or assigned to, the
    /// external call. Local code binds but cannot independently prove it. It
    /// must not recur anywhere else in the generation.
    pub external_invocation_id: String,
    /// Exact provider-side response identity captured by the trusted operator.
    pub provider_response_id: String,
    /// Explicit boundary contract plus operator-owned capture provenance. These
    /// fields are attestations, not proof manufactured by local code.
    pub capture_schema: String,
    pub capture_provenance: Vec<String>,
    pub prepared_artifact_sha256: String,
    pub source_generation_sha256: String,
    pub hypothesis_id: String,
    pub hypothesis_content_sha256: String,
    pub evaluator_id: String,
    pub model_id: String,
    pub prompt_id: String,
    pub temperature_x100: u16,
    pub prompt_utf8: String,
    pub prompt_sha256: String,
    pub request_utf8: String,
    pub request_sha256: String,
    pub response_utf8: String,
    pub response_sha256: String,
    pub parse_result: EvaluatorResponseParseResult,
}

/// Cross-domain distance is not inferred from a constant. Until a persisted
/// domain-distance measurement exists, ranking records its absence and excludes
/// the term from the score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CrossDomainMeasurement {
    Measured {
        distance: usize,
        evidence_ids: Vec<String>,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssociationRankedHypothesis {
    pub rank: usize,
    pub hypothesis_id: String,
    pub a: CxId,
    pub b: CxId,
    pub c: CxId,
    pub claim: String,
    pub novelty_score: f32,
    pub grounded_confidence: f32,
    pub cross_domain: CrossDomainMeasurement,
    pub evaluator_plausibility_score: f32,
    pub evaluator_aggregate_score: f32,
    pub rank_score: f32,
    pub score_semantics: String,
    pub human_review_flag: bool,
    pub sufficiency_proof: String,
    pub provenance: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssociationRankedHypothesisReport {
    pub schema: String,
    pub input_count: usize,
    pub ranked_count: usize,
    pub human_review_count: usize,
    pub hypotheses: Vec<AssociationRankedHypothesis>,
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
    /// Complete evaluation universe: every predicted pair plus each held-out
    /// pair absent from the candidate set.
    pub evaluation_pair_count: usize,
    /// Exact number of ranked candidates admitted by the declared top-K cutoff.
    pub top_k_evaluated_count: usize,
    /// Exact held-out positives present anywhere in the produced candidate set.
    pub held_out_candidate_count: usize,
    pub hits_at_k: usize,
    pub false_positives_at_k: usize,
    pub false_negatives_at_k: usize,
    pub precision_at_k: f64,
    pub recall_at_k: f64,
    pub reciprocal_rank: f64,
    /// Fraction of the produced candidate ranking inspected by top-K.
    pub candidate_coverage_at_k: f64,
    /// Fraction of held-out positive pairs present anywhere in the produced
    /// candidate ranking, independently of the top-K cutoff.
    pub held_out_candidate_coverage: f64,
    /// Brier score of the explicit binary top-K decision policy over the full
    /// evaluation universe. Resource Allocation remains a rank score and is
    /// never relabeled as a probability.
    pub binary_brier_at_k: Option<f64>,
    pub no_skill_binary_brier: Option<f64>,
    pub binary_brier_skill_at_k: Option<f64>,
    pub rank_score_semantics: String,
    pub null_hits_at_k: usize,
    pub usable: bool,
    pub unusable_reason: Option<String>,
    pub validated_pair_ids: Vec<String>,
}

/// Cross-fold stability of one exactly named validation metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidationMetricStability {
    pub sample_count: usize,
    pub mean: f64,
    pub population_stddev: f64,
    pub minimum: f64,
    pub maximum: f64,
}

/// Stability is separate from means so a volatile result cannot look like a
/// stable one merely because its average is attractive.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrossValidationStability {
    pub precision_at_k: Option<ValidationMetricStability>,
    pub recall_at_k: Option<ValidationMetricStability>,
    pub reciprocal_rank: Option<ValidationMetricStability>,
    pub candidate_coverage_at_k: Option<ValidationMetricStability>,
    pub held_out_candidate_coverage: Option<ValidationMetricStability>,
    pub binary_brier_at_k: Option<ValidationMetricStability>,
    pub no_skill_binary_brier: Option<ValidationMetricStability>,
    pub binary_brier_skill_at_k: Option<ValidationMetricStability>,
    pub null_hits_at_k: Option<ValidationMetricStability>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrossValidationReport {
    pub split_kind: String,
    pub temporal_evidence: TemporalEvidenceStatus,
    pub folds: Vec<ValidationFold>,
    pub usable_fold_count: usize,
    pub mean_precision_at_k: f64,
    pub mean_recall_at_k: f64,
    pub mean_reciprocal_rank: f64,
    pub mean_candidate_coverage_at_k: f64,
    pub mean_held_out_candidate_coverage: f64,
    pub mean_binary_brier_at_k: Option<f64>,
    pub mean_no_skill_binary_brier: Option<f64>,
    pub mean_binary_brier_skill_at_k: Option<f64>,
    pub mean_null_hits_at_k: f64,
    pub stability: CrossValidationStability,
    pub validated_pair_ids: Vec<String>,
}

/// Whether temporal ordering was measured from every persisted relationship or
/// was unavailable and therefore excluded from the validation claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TemporalEvidenceStatus {
    Measured {
        timestamped_edge_count: usize,
        relationship_edge_count: usize,
    },
    Unavailable {
        timestamped_edge_count: usize,
        relationship_edge_count: usize,
        reason: String,
    },
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
#[serde(deny_unknown_fields)]
pub struct PreparedAssociationDiscovery {
    pub schema: String,
    pub project: String,
    pub source_seq: u64,
    pub source_generation_sha256: String,
    pub source_manifest: AssociationSourceManifest,
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
    pub evaluation_roster: EvaluationRoster,
    pub validation: CrossValidationReport,
    pub graph_compile_count: usize,
    pub trust: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreparedAssociationDiscoveryTelemetry {
    pub worker_pool_reused: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAssociationDiscoveryEnvelope {
    pub artifact_sha256: String,
    pub artifact: PreparedAssociationDiscovery,
    /// Truthful process-local history. It is deliberately excluded from JSON
    /// and therefore from prepared artifact identity and persistence.
    #[serde(skip)]
    pub telemetry: PreparedAssociationDiscoveryTelemetry,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactReasoningKernel {
    pub schema: String,
    pub trust: String,
    /// Exact post-pruning kernel roster. Every retained typed edge endpoint
    /// belongs to this set.
    pub member_ids: Vec<CxId>,
    pub members_hash: String,
    /// Retained hypothesis endpoints not selected into the compact kernel.
    pub support_ids: Vec<CxId>,
    /// Hash of the complete member-plus-support reasoning roster.
    pub reasoning_roster_hash: String,
    pub hypothesis_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    /// Complete retained typed rows whose endpoints are both in `member_ids`.
    pub retained_typed_edges: Vec<DiscoveryTypedEdgeInput>,
    pub retained_typed_edges_sha256: String,
    /// SHA-256 of the canonical complete kernel artifact bytes below.
    pub kernel_artifact_sha256: String,
    /// Complete scores/config/source/FVS/coverage/compactness evidence. It is
    /// retained rather than collapsed to a member hash.
    pub kernel_artifact: KernelArtifact,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalAssociationDiscovery {
    pub schema: String,
    pub prepared_artifact_sha256: String,
    pub source_manifest: AssociationSourceManifest,
    pub evaluation_roster: EvaluationRoster,
    pub evaluator_receipts: Vec<EvaluatorReceipt>,
    pub evaluator: HypothesisEvaluationReport,
    pub ranked: AssociationRankedHypothesisReport,
    pub reasoning_kernel: CompactReasoningKernel,
    pub trust: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Builds the canonical, complete source manifest and its generation SHA-256.
/// The edge-local `source_generation_sha256` field is deliberately excluded
/// because it is the redundant backlink populated from the returned hash; all
/// evidence fields actually consumed by discovery are framed below.
pub fn derive_association_source_manifest(
    project: &str,
    source_seq: u64,
    physical: &AssociationSourcePhysicalBinding,
    concepts: &[DiscoveryConceptInput],
    typed_edges: &[DiscoveryTypedEdgeInput],
    completeness: &AssociationCompletenessWitness,
    config: &AssociationDiscoveryConfig,
) -> Result<(AssociationSourceManifest, String)> {
    let mut concept_digest = Sha256::new();
    update_framed_digest(
        &mut concept_digest,
        b"astrolabe.association_discovery.concept_stream.v1",
    );
    let mut ordered_concepts = concepts.iter().collect::<Vec<_>>();
    ordered_concepts.sort_by_key(|concept| concept.cx_id);
    for concept in ordered_concepts {
        update_framed_digest(&mut concept_digest, concept.cx_id.as_bytes());
        update_framed_digest(&mut concept_digest, concept.symbol_kind.as_bytes());
        update_framed_digest(&mut concept_digest, concept.language.as_bytes());
        update_framed_digest(&mut concept_digest, concept.qualified_name.as_bytes());
        update_framed_digest(&mut concept_digest, concept.signature_or_shape.as_bytes());
        update_framed_digest(&mut concept_digest, concept.file_path.as_bytes());
        update_framed_digest(&mut concept_digest, concept.source_sha256.as_bytes());
        update_framed_digest(&mut concept_digest, concept.source_excerpt.as_bytes());
        update_framed_digest(&mut concept_digest, &concept.frequency.to_be_bytes());
        update_framed_digest(
            &mut concept_digest,
            concept
                .anchor_trust
                .map(TrustTag::as_str)
                .unwrap_or("absent")
                .as_bytes(),
        );
    }
    let mut edge_digest = Sha256::new();
    update_framed_digest(
        &mut edge_digest,
        b"astrolabe.association_discovery.typed_edge_stream.v1",
    );
    let mut ordered_edges = typed_edges.iter().collect::<Vec<_>>();
    ordered_edges.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    for edge in ordered_edges {
        update_framed_digest(&mut edge_digest, edge.evidence_id.as_bytes());
        update_framed_digest(&mut edge_digest, edge.src.as_bytes());
        update_framed_digest(&mut edge_digest, edge.dst.as_bytes());
        update_framed_digest(&mut edge_digest, &edge.edge_type_code.to_be_bytes());
        update_framed_digest(&mut edge_digest, edge.edge_type_name.as_bytes());
        update_framed_digest(&mut edge_digest, edge.family.as_bytes());
        update_framed_digest(&mut edge_digest, &edge.weight.to_bits().to_be_bytes());
        update_framed_digest(&mut edge_digest, edge.trust.as_str().as_bytes());
        update_optional_str(&mut edge_digest, edge.temporal_direction.as_deref());
        match edge.observed_at_millis {
            Some(value) => {
                update_framed_digest(&mut edge_digest, b"observed_at:present");
                update_framed_digest(&mut edge_digest, &value.to_be_bytes());
            }
            None => update_framed_digest(&mut edge_digest, b"observed_at:unavailable"),
        }
        update_framed_digest(&mut edge_digest, edge.ledger_ref.as_bytes());
        update_framed_digest(
            &mut edge_digest,
            &(edge.provenance.len() as u64).to_be_bytes(),
        );
        for provenance in &edge.provenance {
            update_framed_digest(&mut edge_digest, provenance.as_bytes());
        }
    }
    let config_sha256 = sha256_hex(&canonical_json_bytes(config)?);
    let manifest = AssociationSourceManifest {
        schema: DISCOVERY_SOURCE_MANIFEST_SCHEMA.to_string(),
        project: project.to_string(),
        source_seq,
        physical: physical.clone(),
        completeness: completeness.clone(),
        concept_count: concepts.len(),
        concept_stream_sha256: digest_hex(&concept_digest.finalize()),
        typed_edge_count: typed_edges.len(),
        typed_edge_stream_sha256: digest_hex(&edge_digest.finalize()),
        discovery_prepared_schema: DISCOVERY_PREPARED_SCHEMA.to_string(),
        discovery_final_schema: DISCOVERY_FINAL_SCHEMA.to_string(),
        discovery_config_sha256: config_sha256,
    };
    let generation_sha256 = association_source_generation_sha256(&manifest)?;
    Ok((manifest, generation_sha256))
}

/// Stable logical identity of every source byte and schema/config contract
/// consumed by discovery. MVCC sequence/generation observations remain
/// persisted in the manifest for physical diagnostics, but are deliberately
/// not logical identity. Current-source admission must re-run the exact graph
/// and complete Base/Slot/XTerm verification before comparing this hash.
pub fn association_source_generation_sha256(
    manifest: &AssociationSourceManifest,
) -> Result<String> {
    validate_source_manifest_contract(manifest)?;
    let identity = StableAssociationSourceIdentity {
        schema: "astrolabe.association_discovery.source_identity.v2",
        source_manifest_schema: &manifest.schema,
        project: &manifest.project,
        physical: StableAssociationSourcePhysicalIdentity {
            projection_source_fingerprint_blake3: &manifest
                .physical
                .projection_source_fingerprint_blake3,
            panel_schema_ids: &manifest.physical.panel_schema_ids,
            panel_manifest_sha256: &manifest.physical.panel_manifest_sha256,
            completion_pair_block_schema: &manifest.physical.completion_pair_block_schema,
            completion_witness_schema: &manifest.physical.completion_witness_schema,
            completion_ledger_schema: &manifest.physical.completion_ledger_schema,
            completion_metric_contract: &manifest.physical.completion_metric_contract,
            completion_incompatibility_contract: &manifest
                .physical
                .completion_incompatibility_contract,
        },
        completeness: &manifest.completeness,
        concept_count: manifest.concept_count,
        concept_stream_sha256: &manifest.concept_stream_sha256,
        typed_edge_count: manifest.typed_edge_count,
        typed_edge_stream_sha256: &manifest.typed_edge_stream_sha256,
        discovery_prepared_schema: &manifest.discovery_prepared_schema,
        discovery_final_schema: &manifest.discovery_final_schema,
        discovery_config_sha256: &manifest.discovery_config_sha256,
    };
    Ok(sha256_hex(&canonical_json_bytes(&identity)?))
}

/// Prepares every deterministic discovery stage over one exact source.
pub fn prepare_association_discovery(
    input: &AssociationDiscoveryInput,
    config: &AssociationDiscoveryConfig,
) -> Result<PreparedAssociationDiscoveryEnvelope> {
    validate_config(config)?;
    validate_input(input)?;
    let (source_manifest, source_generation_sha256) = derive_association_source_manifest(
        &input.project,
        input.source_seq,
        &input.source_manifest.physical,
        &input.concepts,
        &input.typed_edges,
        &input.completeness,
        config,
    )?;
    if source_manifest != input.source_manifest
        || source_generation_sha256 != input.source_generation_sha256
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_SOURCE_CHANGED,
            format!(
                "association source manifest mismatch: declared={} rederived={source_generation_sha256}",
                input.source_generation_sha256
            ),
            "reload Graph/Base/Slot/Compression/XTerm source generations and prepare from their exact canonical manifest",
        ));
    }
    if input
        .typed_edges
        .iter()
        .any(|edge| edge.source_generation_sha256 != source_generation_sha256)
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_SOURCE_CHANGED,
            "one or more typed evidence rows do not backlink to the exact canonical source generation",
            "rebuild every typed evidence row from the same source manifest before preparation",
        ));
    }
    let (pool, worker_pool_reused) = worker_pool(config.workers)?;
    // The typed edge sort is already required for canonical artifact bytes.
    // Reuse that one order for association-aware normalization rather than
    // building a second per-concept edge inventory (PC-04/PC-29, #1097).
    let typed_edges = sorted_typed_edges(&input.typed_edges);
    let normalized_concepts = normalize_concepts(&input.concepts, &typed_edges);
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
    let evaluation_roster = build_evaluation_roster(
        &source_generation_sha256,
        &candidates,
        &config.evaluator_declarations,
        required_budgets(config)?,
    )?;
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
        source_generation_sha256,
        source_manifest,
        config: config.clone(),
        completeness: input.completeness.clone(),
        normalized_concepts,
        typed_edges,
        algorithm_projection_edge_count: algorithm_graph.edge_count(),
        latent,
        spectral,
        walks,
        gate_counts,
        candidates,
        evaluation_roster,
        validation,
        graph_compile_count: 1,
        trust: "provisional_pending_trusted_operator_external_capture".to_string(),
    };
    let artifact_sha256 = sha256_hex(&canonical_json_bytes(&artifact)?);
    Ok(PreparedAssociationDiscoveryEnvelope {
        artifact_sha256,
        artifact,
        telemetry: PreparedAssociationDiscoveryTelemetry { worker_pool_reused },
    })
}

/// Finalizes a prepared artifact only when evaluator receipts cite its exact
/// evidence and satisfy the trusted single-operator capture contract.
pub fn finalize_association_discovery(
    prepared: &PreparedAssociationDiscoveryEnvelope,
    evaluator_receipts: &[EvaluatorReceipt],
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
    let (source_manifest, source_generation_sha256) = derive_association_source_manifest(
        &prepared.artifact.project,
        prepared.artifact.source_seq,
        &prepared.artifact.source_manifest.physical,
        &prepared
            .artifact
            .normalized_concepts
            .iter()
            .map(discovery_concept_from_normalized)
            .collect::<Vec<_>>(),
        &prepared.artifact.typed_edges,
        &prepared.artifact.completeness,
        &prepared.artifact.config,
    )?;
    if source_manifest != prepared.artifact.source_manifest
        || source_generation_sha256 != prepared.artifact.source_generation_sha256
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_SOURCE_CHANGED,
            format!(
                "prepared source manifest mismatch during evaluator admission: declared={} rederived={source_generation_sha256}",
                prepared.artifact.source_generation_sha256
            ),
            "discard the stale prepared generation and prepare again from the current exact source",
        ));
    }
    let expected_roster = build_evaluation_roster(
        &prepared.artifact.source_generation_sha256,
        &prepared.artifact.candidates,
        &prepared.artifact.config.evaluator_declarations,
        required_budgets(&prepared.artifact.config)?,
    )?;
    if expected_roster != prepared.artifact.evaluation_roster {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "prepared evaluation roster does not exactly rederive from its hypotheses and evaluator declarations",
            "preserve the prepared bytes and regenerate the exact evaluator roster before invoking any evaluator",
        ));
    }
    let (evaluator_runs, evaluator_receipts) =
        validate_evaluator_receipts(prepared, evaluator_receipts)?;
    let candidates = prepared
        .artifact
        .candidates
        .iter()
        .map(|candidate| (candidate.hypothesis_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = Vec::with_capacity(candidates.len());
    for (hypothesis_id, candidate) in &candidates {
        let runs = evaluator_runs.get(*hypothesis_id).ok_or_else(|| {
            DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!("exact receipt validation produced no evaluator runs for hypothesis {hypothesis_id}"),
                "submit exactly one receipt for every prepared evaluator binding",
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
    let ranked = rank_evaluated_hypotheses(
        &evaluator,
        &by_id,
        &validated,
        &prepared.artifact.config.ranking,
    )?;
    let reasoning_kernel = compact_reasoning_kernel(prepared, &evaluator, &ranked, &validated)?;
    let trust = reasoning_kernel.trust.clone();
    let artifact = FinalAssociationDiscovery {
        schema: DISCOVERY_FINAL_SCHEMA.to_string(),
        prepared_artifact_sha256: prepared.artifact_sha256.clone(),
        source_manifest: prepared.artifact.source_manifest.clone(),
        evaluation_roster: prepared.artifact.evaluation_roster.clone(),
        evaluator_receipts,
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

#[derive(Serialize)]
struct PreparedEvaluatorRequest<'a> {
    schema: &'static str,
    source_generation_sha256: &'a str,
    hypothesis_id: &'a str,
    hypothesis_content_sha256: &'a str,
    evaluator_id: &'a str,
    model_id: &'a str,
    prompt_id: &'a str,
    temperature_x100: u16,
    prompt_utf8: &'a str,
    hypothesis: &'a DiscoveryHypothesisCandidate,
}

fn build_evaluation_roster(
    source_generation_sha256: &str,
    candidates: &[DiscoveryHypothesisCandidate],
    declarations: &[EvaluatorDeclaration],
    budgets: &AssociationDiscoveryBudgets,
) -> Result<EvaluationRoster> {
    if candidates.is_empty() || declarations.is_empty() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "an exact evaluation roster requires non-empty hypotheses and evaluator declarations",
            "prepare candidates and explicitly declare every evaluator/model/prompt variant before invocation",
        ));
    }
    let binding_count = candidates
        .len()
        .checked_mul(declarations.len())
        .ok_or_else(|| {
            DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                "evaluation binding count overflow",
                "partition discovery into smaller source scopes without omitting a declared evaluator binding",
            )
        })?;
    if binding_count > budgets.max_evaluation_bindings {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            format!(
                "evaluation binding count {binding_count} exceeds caller budget {}",
                budgets.max_evaluation_bindings
            ),
            "raise the explicit binding budget with measured evidence or narrow the hypothesis/evaluator roster",
        ));
    }
    let mut candidates = candidates.iter().collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.hypothesis_id.cmp(&right.hypothesis_id));
    let mut declarations = declarations.iter().collect::<Vec<_>>();
    declarations.sort_by(|left, right| {
        left.evaluator_id
            .cmp(&right.evaluator_id)
            .then_with(|| left.model_id.cmp(&right.model_id))
            .then_with(|| left.prompt_id.cmp(&right.prompt_id))
            .then_with(|| left.temperature_x100.cmp(&right.temperature_x100))
            .then_with(|| left.prompt_utf8.cmp(&right.prompt_utf8))
    });
    let mut bindings = Vec::with_capacity(binding_count);
    let mut request_bytes_total = 0usize;
    for candidate in candidates {
        let hypothesis_content_sha256 = sha256_hex(&canonical_json_bytes(candidate)?);
        for declaration in &declarations {
            let prompt_sha256 = sha256_hex(declaration.prompt_utf8.as_bytes());
            let request = PreparedEvaluatorRequest {
                schema: DISCOVERY_EVALUATOR_REQUEST_SCHEMA,
                source_generation_sha256,
                hypothesis_id: &candidate.hypothesis_id,
                hypothesis_content_sha256: &hypothesis_content_sha256,
                evaluator_id: &declaration.evaluator_id,
                model_id: &declaration.model_id,
                prompt_id: &declaration.prompt_id,
                temperature_x100: declaration.temperature_x100,
                prompt_utf8: &declaration.prompt_utf8,
                hypothesis: candidate,
            };
            let request_byte_count = canonical_json_byte_count(&request)?;
            if request_byte_count > budgets.max_request_bytes_per_binding {
                return Err(DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "evaluator request for hypothesis {} is {} bytes, exceeding caller per-binding budget {}",
                        candidate.hypothesis_id,
                        request_byte_count,
                        budgets.max_request_bytes_per_binding
                    ),
                    "raise the explicit per-binding request budget with measured evidence or reduce the exact evidence packet",
                ));
            }
            request_bytes_total = request_bytes_total
                .checked_add(request_byte_count)
                .ok_or_else(|| {
                    DomainError::new(
                        ASTRO_DISCOVERY_EVALUATOR_INVALID,
                        "total evaluator request bytes overflow usize",
                        "narrow the exact evaluator roster before preparing requests",
                    )
                })?;
            if request_bytes_total > budgets.max_request_bytes_total {
                return Err(DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "total evaluator request bytes {request_bytes_total} exceed caller budget {}",
                        budgets.max_request_bytes_total
                    ),
                    "raise the explicit total request budget with measured evidence or narrow the hypothesis/evaluator roster",
                ));
            }
            let request_bytes = canonical_json_bytes(&request)?;
            if request_bytes.len() != request_byte_count {
                return Err(DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    "evaluator request allocation differs from its preallocation byte count",
                    "repair the canonical serializer before invoking an evaluator",
                ));
            }
            let request_sha256 = sha256_hex(&request_bytes);
            let request_utf8 = String::from_utf8(request_bytes).map_err(|error| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!("prepared evaluator request is not UTF-8: {error}"),
                    "repair the canonical evaluator request serializer before invoking a model",
                )
            })?;
            let mut invocation_digest = Sha256::new();
            update_framed_digest(
                &mut invocation_digest,
                b"astrolabe.association_discovery.evaluator_invocation.v1",
            );
            let temperature_bytes = declaration.temperature_x100.to_be_bytes();
            for bytes in [
                source_generation_sha256.as_bytes(),
                candidate.hypothesis_id.as_bytes(),
                hypothesis_content_sha256.as_bytes(),
                declaration.evaluator_id.as_bytes(),
                declaration.model_id.as_bytes(),
                declaration.prompt_id.as_bytes(),
                &temperature_bytes,
                prompt_sha256.as_bytes(),
                request_sha256.as_bytes(),
            ] {
                update_framed_digest(&mut invocation_digest, bytes);
            }
            bindings.push(EvaluationBinding {
                invocation_id: digest_hex(&invocation_digest.finalize()),
                source_generation_sha256: source_generation_sha256.to_string(),
                hypothesis_id: candidate.hypothesis_id.clone(),
                hypothesis_content_sha256: hypothesis_content_sha256.clone(),
                evaluator_id: declaration.evaluator_id.clone(),
                model_id: declaration.model_id.clone(),
                prompt_id: declaration.prompt_id.clone(),
                temperature_x100: declaration.temperature_x100,
                prompt_utf8: declaration.prompt_utf8.clone(),
                prompt_sha256,
                request_utf8,
                request_sha256,
            });
        }
    }
    let unique = bindings
        .iter()
        .map(|binding| binding.invocation_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() != binding_count {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "deterministic evaluator invocation identities collided",
            "preserve the prepared inputs and repair the exact evaluator declaration identity",
        ));
    }
    let bindings_sha256 = sha256_hex(&canonical_json_bytes(&bindings)?);
    Ok(EvaluationRoster {
        schema: DISCOVERY_EVALUATION_ROSTER_SCHEMA.to_string(),
        hypothesis_count: candidates_len_from_bindings(&bindings),
        evaluator_declaration_count: declarations.len(),
        binding_count,
        request_bytes_total,
        bindings_sha256,
        bindings,
    })
}

fn candidates_len_from_bindings(bindings: &[EvaluationBinding]) -> usize {
    bindings
        .iter()
        .map(|binding| binding.hypothesis_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn validate_evaluator_receipts(
    prepared: &PreparedAssociationDiscoveryEnvelope,
    receipts: &[EvaluatorReceipt],
) -> Result<(
    BTreeMap<String, Vec<calyx_lodestar::EvaluatorRun>>,
    Vec<EvaluatorReceipt>,
)> {
    let budgets = required_budgets(&prepared.artifact.config)?;
    if receipts.len() > budgets.max_evaluation_bindings {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            format!(
                "receipt count {} exceeds caller binding budget {}",
                receipts.len(),
                budgets.max_evaluation_bindings
            ),
            "submit only the exact prepared roster within its identity-bound caller budget",
        ));
    }
    let mut request_bytes_total = 0usize;
    let mut response_bytes_total = 0usize;
    for receipt in receipts {
        let request_bytes = receipt.request_utf8.len();
        let response_bytes = receipt.response_utf8.len();
        if request_bytes > budgets.max_request_bytes_per_binding
            || response_bytes > budgets.max_response_bytes_per_binding
        {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "receipt {} exceeds a caller per-binding byte budget: request={request_bytes}/{} response={response_bytes}/{}",
                    receipt.invocation_id,
                    budgets.max_request_bytes_per_binding,
                    budgets.max_response_bytes_per_binding,
                ),
                "preserve the exact receipt and explicitly raise the relevant measured budget before preparing a new generation",
            ));
        }
        request_bytes_total = request_bytes_total
            .checked_add(request_bytes)
            .ok_or_else(|| evaluator_budget_overflow("request"))?;
        response_bytes_total = response_bytes_total
            .checked_add(response_bytes)
            .ok_or_else(|| evaluator_budget_overflow("response"))?;
        if request_bytes_total > budgets.max_request_bytes_total
            || response_bytes_total > budgets.max_response_bytes_total
        {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "receipt bytes exceed caller totals: request={request_bytes_total}/{} response={response_bytes_total}/{}",
                    budgets.max_request_bytes_total, budgets.max_response_bytes_total,
                ),
                "preserve the receipts and explicitly raise the measured total budget before preparing a new generation",
            ));
        }
    }
    if request_bytes_total != prepared.artifact.evaluation_roster.request_bytes_total {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            format!(
                "receipt request-byte total {request_bytes_total} differs from prepared roster total {}",
                prepared.artifact.evaluation_roster.request_bytes_total
            ),
            "submit every exact prepared request byte once, with no replacement or omission",
        ));
    }
    let expected = prepared
        .artifact
        .evaluation_roster
        .bindings
        .iter()
        .map(|binding| (binding.invocation_id.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeMap::new();
    let mut duplicate_ids = BTreeSet::new();
    for receipt in receipts {
        if observed
            .insert(receipt.invocation_id.as_str(), receipt)
            .is_some()
        {
            duplicate_ids.insert(receipt.invocation_id.as_str());
        }
    }
    let missing = expected
        .keys()
        .filter(|identity| !observed.contains_key(**identity))
        .copied()
        .collect::<Vec<_>>();
    let extra = observed
        .keys()
        .filter(|identity| !expected.contains_key(**identity))
        .copied()
        .collect::<Vec<_>>();
    if !duplicate_ids.is_empty()
        || !missing.is_empty()
        || !extra.is_empty()
        || receipts.len() != expected.len()
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            format!(
                "evaluator receipt roster mismatch: expected={} observed={} missing={missing:?} extra={extra:?} duplicate={duplicate_ids:?}",
                expected.len(),
                receipts.len(),
            ),
            "submit one and only one receipt for every exact invocation in the prepared evaluation roster",
        ));
    }
    let candidates = prepared
        .artifact
        .candidates
        .iter()
        .map(|candidate| (candidate.hypothesis_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut external_invocation_ids = BTreeSet::new();
    let mut runs = BTreeMap::<String, Vec<calyx_lodestar::EvaluatorRun>>::new();
    let mut ordered_receipts = Vec::with_capacity(expected.len());
    for binding in &prepared.artifact.evaluation_roster.bindings {
        let receipt = observed
            .get(binding.invocation_id.as_str())
            .copied()
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "prepared evaluator binding {} has no receipt after exact roster validation",
                        binding.invocation_id
                    ),
                    "preserve the prepared artifact and repair receipt roster validation",
                )
            })?;
        if receipt.schema != DISCOVERY_EVALUATOR_RECEIPT_SCHEMA
            || receipt.prepared_artifact_sha256 != prepared.artifact_sha256
            || receipt.source_generation_sha256 != prepared.artifact.source_generation_sha256
            || receipt.invocation_id != binding.invocation_id
            || receipt.hypothesis_id != binding.hypothesis_id
            || receipt.hypothesis_content_sha256 != binding.hypothesis_content_sha256
            || receipt.evaluator_id != binding.evaluator_id
            || receipt.model_id != binding.model_id
            || receipt.prompt_id != binding.prompt_id
            || receipt.temperature_x100 != binding.temperature_x100
            || receipt.prompt_utf8 != binding.prompt_utf8
            || receipt.prompt_sha256 != binding.prompt_sha256
            || receipt.request_utf8 != binding.request_utf8
            || receipt.request_sha256 != binding.request_sha256
        {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "evaluator receipt {} disagrees with its prepared/source/hypothesis/evaluator/model/prompt/request binding",
                    binding.invocation_id
                ),
                "use the exact prepared binding bytes for the real evaluator call and return them unchanged",
            ));
        }
        if sha256_hex(receipt.prompt_utf8.as_bytes()) != receipt.prompt_sha256
            || sha256_hex(receipt.request_utf8.as_bytes()) != receipt.request_sha256
            || sha256_hex(receipt.response_utf8.as_bytes()) != receipt.response_sha256
        {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "evaluator receipt {} has a byte/hash mismatch",
                    binding.invocation_id
                ),
                "preserve and resubmit the exact prompt, request, and response bytes with their rederived SHA-256 values",
            ));
        }
        if receipt.external_invocation_id.trim().is_empty()
            || !external_invocation_ids.insert(receipt.external_invocation_id.as_str())
        {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "evaluator receipt {} has an absent or replayed external invocation identity {:?}",
                    binding.invocation_id, receipt.external_invocation_id
                ),
                "retain the unique identity of each genuine external evaluator call; never reuse one invocation across bindings",
            ));
        }
        if receipt.capture_schema != DISCOVERY_EXTERNAL_CAPTURE_SCHEMA
            || receipt.provider_response_id.trim().is_empty()
            || receipt.capture_provenance.is_empty()
            || receipt
                .capture_provenance
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "evaluator receipt {} lacks the exact trusted external-capture schema, provider response identity, or non-empty capture provenance",
                    receipt.invocation_id
                ),
                "record the provider response identity and truthful operator-owned capture provenance; local validation binds these bytes but does not prove a remote call occurred",
            ));
        }
        let parsed: EvaluatorResponseParseResult =
            serde_json::from_slice(receipt.response_utf8.as_bytes()).map_err(|error| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "evaluator response {} does not parse under the strict response schema: {error}",
                        binding.invocation_id
                    ),
                    "return one exact strict evaluator response JSON object with no extra or missing fields",
                )
            })?;
        if parsed != receipt.parse_result || parsed.schema != DISCOVERY_EVALUATOR_RESPONSE_SCHEMA {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "evaluator response {} parse result does not equal the result persisted in its receipt",
                    binding.invocation_id
                ),
                "derive scores and prose only by parsing the exact response bytes",
            ));
        }
        let candidate = candidates
            .get(binding.hypothesis_id.as_str())
            .copied()
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "prepared evaluator binding {} names absent hypothesis {}",
                        binding.invocation_id, binding.hypothesis_id
                    ),
                    "preserve the prepared artifact and rebuild its exact candidate/evaluator roster",
                )
            })?;
        validate_parsed_evaluator_response(&parsed, candidate)?;
        runs.entry(binding.hypothesis_id.clone())
            .or_default()
            .push(calyx_lodestar::EvaluatorRun {
                prompt_id: binding.prompt_id.clone(),
                temperature_x100: binding.temperature_x100,
                plausible_score: parsed.plausible_score,
                novelty_score: parsed.novelty_score,
                testability_score: parsed.testability_score,
                falsifiability_score: parsed.falsifiability_score,
                justification: parsed.justification.clone(),
                falsification_test: parsed.falsification_test.clone(),
                cited_evidence_ids: parsed.cited_evidence_ids.clone(),
            });
        ordered_receipts.push(receipt.clone());
    }
    Ok((runs, ordered_receipts))
}

fn validate_parsed_evaluator_response(
    parsed: &EvaluatorResponseParseResult,
    candidate: &DiscoveryHypothesisCandidate,
) -> Result<()> {
    if parsed.justification.trim().is_empty()
        || parsed.falsification_test.trim().is_empty()
        || parsed.cited_evidence_ids.is_empty()
        || [
            parsed.plausible_score,
            parsed.novelty_score,
            parsed.testability_score,
            parsed.falsifiability_score,
        ]
        .into_iter()
        .any(|score| !score.is_finite() || !(0.0..=1.0).contains(&score))
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "parsed evaluator response requires finite [0,1] scores, prose, a falsification test, and citations",
            "repair the real evaluator response and invoke the exact binding again",
        ));
    }
    let mut canonical_citations = parsed.cited_evidence_ids.clone();
    canonical_citations.sort();
    canonical_citations.dedup();
    if canonical_citations != parsed.cited_evidence_ids {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "evaluator citations must be unique and in canonical byte order",
            "emit each prepared evidence id once in ascending byte order",
        ));
    }
    let available = candidate
        .evidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if let Some(unknown) = parsed
        .cited_evidence_ids
        .iter()
        .find(|identity| !available.contains(identity.as_str()))
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            format!("evaluator response cites unavailable evidence {unknown:?}"),
            "cite only evidence ids present in the exact prepared hypothesis request",
        ));
    }
    Ok(())
}

fn rank_evaluated_hypotheses(
    evaluator: &HypothesisEvaluationReport,
    candidates: &BTreeMap<&str, &DiscoveryHypothesisCandidate>,
    validated: &BTreeSet<String>,
    params: &RankedHypothesisParams,
) -> Result<AssociationRankedHypothesisReport> {
    if params.max_ranked == 0
        || !params.min_review_score.is_finite()
        || !(0.0..=1.0).contains(&params.min_review_score)
    {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "ranking requires positive max_ranked and a finite review floor in [0,1]",
            "repair the exact prepared ranking configuration before evaluator invocation",
        ));
    }
    let mut hypotheses = Vec::new();
    for evaluation in &evaluator.evaluations {
        if evaluation.verdict != HypothesisEvaluationVerdict::RetainForRanking {
            continue;
        }
        let candidate = candidates
            .get(evaluation.hypothesis_id.as_str())
            .copied()
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "evaluator report names absent prepared hypothesis {}",
                        evaluation.hypothesis_id
                    ),
                    "preserve the prepared artifact and rebuild the exact candidate/evaluator roster",
                )
            })?;
        let rank_score = (evaluation.novelty_mean * 0.25
            + evaluation.grounded_confidence * 0.30
            + evaluation.plausible_mean * 0.25)
            / 0.80;
        if !rank_score.is_finite() || !(0.0..=1.0).contains(&rank_score) {
            return Err(DomainError::new(
                ASTRO_DISCOVERY_EVALUATOR_INVALID,
                format!(
                    "hypothesis {} produced invalid rank score {rank_score}",
                    evaluation.hypothesis_id
                ),
                "repair the parsed evaluator scores; unmeasured cross-domain evidence remains excluded",
            ));
        }
        hypotheses.push(AssociationRankedHypothesis {
            rank: 0,
            hypothesis_id: evaluation.hypothesis_id.clone(),
            a: evaluation.a,
            b: evaluation.b,
            c: evaluation.c,
            claim: evaluation.claim.clone(),
            novelty_score: evaluation.novelty_mean,
            grounded_confidence: evaluation.grounded_confidence,
            cross_domain: CrossDomainMeasurement::Unavailable {
                reason: "no persisted cross-domain distance measurement exists; the distance term is excluded from rank_score".to_string(),
            },
            evaluator_plausibility_score: evaluation.plausible_mean,
            evaluator_aggregate_score: evaluation.aggregate_score,
            rank_score,
            score_semantics: "renormalized_novelty_0.25_grounding_0.30_evaluator_plausibility_0.25; cross_domain_unavailable_excluded; uncalibrated_ranking_score".to_string(),
            human_review_flag: false,
            sufficiency_proof: if validated.contains(&pair_id(evaluation.a, evaluation.c)) {
                "held_out_endpoint_pair_predicted_without_training_pair_leakage".to_string()
            } else {
                "trusted_operator_evaluator_capture_only; held_out_support_absent".to_string()
            },
            provenance: candidate.provenance.clone(),
            evidence_ids: candidate.evidence_ids.clone(),
        });
    }
    if hypotheses.is_empty() {
        return Err(DomainError::new(
            ASTRO_DISCOVERY_EVALUATOR_INVALID,
            "no evaluator-scored hypothesis passed the declared retention floor",
            "supply more grounded evidence; a prepared generation is never promoted with an empty ranked roster",
        ));
    }
    hypotheses.sort_by(|left, right| {
        right
            .rank_score
            .total_cmp(&left.rank_score)
            .then_with(|| {
                right
                    .grounded_confidence
                    .total_cmp(&left.grounded_confidence)
            })
            .then_with(|| left.hypothesis_id.cmp(&right.hypothesis_id))
    });
    hypotheses.truncate(params.max_ranked);
    for (index, hypothesis) in hypotheses.iter_mut().enumerate() {
        hypothesis.rank = index + 1;
        hypothesis.human_review_flag =
            index < params.review_top_n && hypothesis.rank_score >= params.min_review_score;
    }
    Ok(AssociationRankedHypothesisReport {
        schema: "astrolabe.association_discovery.ranked.v1".to_string(),
        input_count: evaluator.retained_count,
        ranked_count: hypotheses.len(),
        human_review_count: hypotheses
            .iter()
            .filter(|hypothesis| hypothesis.human_review_flag)
            .count(),
        hypotheses,
    })
}

fn discovery_concept_from_normalized(concept: &NormalizedConcept) -> DiscoveryConceptInput {
    DiscoveryConceptInput {
        cx_id: concept.cx_id,
        symbol_kind: concept.symbol_kind.clone(),
        language: concept.language.clone(),
        qualified_name: concept.qualified_name.clone(),
        signature_or_shape: concept.signature_or_shape.clone(),
        file_path: concept.file_path.clone(),
        source_sha256: concept.source_sha256.clone(),
        source_excerpt: concept.source_excerpt.clone(),
        frequency: concept.frequency,
        anchor_trust: concept.anchor_trust,
    }
}

fn validate_config(config: &AssociationDiscoveryConfig) -> Result<()> {
    latent_config(config).validate()?;
    config.reasoning_kernel.validate()?;
    let budgets = required_budgets(config)?;
    if budgets.max_evaluation_bindings == 0
        || budgets.max_request_bytes_per_binding == 0
        || budgets.max_request_bytes_total == 0
        || budgets.max_response_bytes_per_binding == 0
        || budgets.max_response_bytes_total == 0
        || budgets.max_generation_rows == 0
        || budgets.max_generation_bytes == 0
        || budgets.max_request_bytes_total < budgets.max_request_bytes_per_binding
        || budgets.max_response_bytes_total < budgets.max_response_bytes_per_binding
    {
        return invalid_graph(
            "every caller-owned evaluator/persistence budget must be positive and each total byte budget must cover at least one per-binding budget",
        );
    }
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
        || config.evaluator_declarations.is_empty()
    {
        return invalid_graph(
            "one or more declared discovery limits are zero or mathematically insufficient",
        );
    }
    let mut declaration_ids = BTreeSet::new();
    let mut prompt_variants = BTreeSet::new();
    let mut temperature_variants = BTreeSet::new();
    for declaration in &config.evaluator_declarations {
        if declaration.evaluator_id.trim().is_empty()
            || declaration.model_id.trim().is_empty()
            || declaration.prompt_id.trim().is_empty()
            || declaration.prompt_utf8.trim().is_empty()
        {
            return invalid_graph(
                "every evaluator declaration requires explicit evaluator/model/prompt identity and non-empty exact prompt bytes",
            );
        }
        let identity = (
            declaration.evaluator_id.as_str(),
            declaration.model_id.as_str(),
            declaration.prompt_id.as_str(),
            declaration.temperature_x100,
        );
        if !declaration_ids.insert(identity) {
            return invalid_graph("evaluator declarations must have unique exact identities");
        }
        prompt_variants.insert(declaration.prompt_id.as_str());
        temperature_variants.insert(declaration.temperature_x100);
    }
    if config.evaluator_declarations.len() < config.evaluator.min_runs_per_hypothesis
        || prompt_variants.len() < config.evaluator.min_prompt_variants
        || temperature_variants.len() < config.evaluator.min_temperature_variants
    {
        return invalid_graph(
            "declared evaluator roster cannot satisfy its exact run, prompt-variant, and temperature-variant contract",
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

fn required_budgets(config: &AssociationDiscoveryConfig) -> Result<&AssociationDiscoveryBudgets> {
    config.budgets.as_ref().ok_or_else(|| {
        DomainError::new(
            ASTRO_DISCOVERY_GRAPH_INVALID,
            "association discovery requires explicit caller-owned evaluator and persistence budgets; no defaults are permitted",
            "set max binding, per/total request, per/total response, and generation row/byte budgets before preparation",
        )
    })
}

fn evaluator_budget_overflow(kind: &str) -> DomainError {
    DomainError::new(
        ASTRO_DISCOVERY_EVALUATOR_INVALID,
        format!("total evaluator {kind} bytes overflow usize"),
        "narrow the exact evaluator roster before submitting receipts",
    )
}

fn validate_input(input: &AssociationDiscoveryInput) -> Result<()> {
    if input.project.trim().is_empty()
        || !is_canonical_hash(&input.source_generation_sha256)
        || input.source_manifest.schema != DISCOVERY_SOURCE_MANIFEST_SCHEMA
        || input.source_manifest.project != input.project
        || input.source_manifest.source_seq != input.source_seq
        || input.source_manifest.completeness != input.completeness
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
        || !is_canonical_hash(&witness.completion_witness_state_hash)
        || !is_canonical_hash(&witness.xterm_key_stream_hash)
        || !is_canonical_hash(&witness.xterm_value_stream_hash)
    {
        return incomplete(
            "complete Base/Slot/XTerm physical witness counts and hashes are required",
        );
    }
    let physical = &input.source_manifest.physical;
    if physical.retained_snapshot_seq == 0
        || !is_canonical_hash(&physical.projection_source_fingerprint_blake3)
        || physical.slot_cf_generations.is_empty()
        || physical.panel_schema_ids.is_empty()
        || physical.panel_manifest_sha256.is_empty()
        || physical.panel_schema_ids.keys().collect::<Vec<_>>()
            != physical.panel_manifest_sha256.keys().collect::<Vec<_>>()
        || physical
            .panel_schema_ids
            .values()
            .any(|schema| schema.trim().is_empty())
        || physical
            .panel_manifest_sha256
            .values()
            .any(|hash| !is_canonical_hash(hash))
        || physical.completion_pair_block_schema != "astrolabe.complete_pair_block.v2"
        || physical.completion_witness_schema != "astrolabe.complete_pair_witness.v2"
        || physical.completion_ledger_schema != "astrolabe.complete_association_commit.v2"
        || physical
            .completion_metric_contract
            .iter()
            .map(String::as_str)
            .ne(["cosine", "symmetric_mean_maxsim_cosine"])
        || physical
            .completion_incompatibility_contract
            .iter()
            .map(String::as_str)
            .ne(["absent_slot", "shape_mismatch", "zero_norm"])
    {
        return incomplete(
            "source manifest requires retained snapshot, projection identity, every consumed slot generation, panel schema/config identities, and complete-association schema/config",
        );
    }
    let mut concepts = BTreeSet::new();
    for concept in &input.concepts {
        if !concepts.insert(concept.cx_id)
            || concept.symbol_kind.trim().is_empty()
            || concept.qualified_name.trim().is_empty()
            || concept.frequency == 0
        {
            return incomplete(
                "concept identities must be unique and every concept must carry kind, name, and positive frequency; absent language/signature/file/hash/excerpt fields remain explicitly unavailable",
            );
        }
        if !concept.source_sha256.is_empty()
            && (concept.source_sha256.len() != 64
                || !concept
                    .source_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return incomplete(
                "available concept source_sha256 values must be canonical SHA-256 hex",
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
            || !is_canonical_ledger_ref(&edge.ledger_ref)
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

fn validate_source_manifest_contract(manifest: &AssociationSourceManifest) -> Result<()> {
    let physical = &manifest.physical;
    let completeness = &manifest.completeness;
    if manifest.schema != DISCOVERY_SOURCE_MANIFEST_SCHEMA
        || manifest.project.trim().is_empty()
        || manifest.source_seq == 0
        || manifest.physical.retained_snapshot_seq == 0
        || manifest.source_seq != manifest.physical.retained_snapshot_seq
        || manifest.concept_count == 0
        || manifest.typed_edge_count == 0
        || manifest.discovery_prepared_schema != DISCOVERY_PREPARED_SCHEMA
        || manifest.discovery_final_schema != DISCOVERY_FINAL_SCHEMA
        || !is_canonical_hash(&manifest.concept_stream_sha256)
        || !is_canonical_hash(&manifest.typed_edge_stream_sha256)
        || !is_canonical_hash(&manifest.discovery_config_sha256)
        || !is_canonical_hash(&physical.projection_source_fingerprint_blake3)
        || physical.slot_cf_generations.is_empty()
        || physical.panel_schema_ids.is_empty()
        || physical.panel_schema_ids.keys().collect::<Vec<_>>()
            != physical.panel_manifest_sha256.keys().collect::<Vec<_>>()
        || physical
            .panel_schema_ids
            .values()
            .any(|schema| schema.trim().is_empty())
        || physical
            .panel_manifest_sha256
            .values()
            .any(|hash| !is_canonical_hash(hash))
        || physical.completion_pair_block_schema != "astrolabe.complete_pair_block.v2"
        || physical.completion_witness_schema != "astrolabe.complete_pair_witness.v2"
        || physical.completion_ledger_schema != "astrolabe.complete_association_commit.v2"
        || physical
            .completion_metric_contract
            .iter()
            .map(String::as_str)
            .ne(["cosine", "symmetric_mean_maxsim_cosine"])
        || physical
            .completion_incompatibility_contract
            .iter()
            .map(String::as_str)
            .ne(["absent_slot", "shape_mismatch", "zero_norm"])
        || completeness.constellation_count == 0
        || completeness.source_slot_count == 0
        || completeness.pair_count == 0
        || !is_canonical_hash(&completeness.completion_witness_state_hash)
        || !is_canonical_hash(&completeness.xterm_key_stream_hash)
        || !is_canonical_hash(&completeness.xterm_value_stream_hash)
    {
        return incomplete(
            "association source manifest violates its exact schema, source, or canonical SHA-256 contract",
        );
    }
    Ok(())
}

fn is_canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_ledger_ref(value: &str) -> bool {
    let Some((seq, hash)) = value.split_once(':') else {
        return false;
    };
    !seq.is_empty()
        && !seq.starts_with('0')
        && seq.parse::<u64>().is_ok_and(|seq| seq > 0)
        && is_canonical_hash(hash)
}

struct ConceptAssociationAccumulator {
    digest: Sha256,
    incident_typed_edge_count: u64,
    association_family_counts: BTreeMap<String, u64>,
}

impl ConceptAssociationAccumulator {
    fn new() -> Self {
        let mut digest = Sha256::new();
        update_framed_digest(&mut digest, b"astrolabe.concept_association_context.v1");
        Self {
            digest,
            incident_typed_edge_count: 0,
            association_family_counts: BTreeMap::new(),
        }
    }

    fn observe(&mut self, edge: &DiscoveryTypedEdgeInput, role: &[u8], counterpart: CxId) {
        update_framed_digest(&mut self.digest, role);
        update_framed_digest(&mut self.digest, counterpart.as_bytes());
        update_framed_digest(&mut self.digest, &edge.edge_type_code.to_be_bytes());
        update_framed_digest(&mut self.digest, edge.edge_type_name.as_bytes());
        update_framed_digest(&mut self.digest, edge.family.as_bytes());
        update_framed_digest(&mut self.digest, &edge.weight.to_bits().to_be_bytes());
        update_framed_digest(&mut self.digest, edge.trust.as_str().as_bytes());
        match &edge.temporal_direction {
            Some(direction) => {
                update_framed_digest(&mut self.digest, b"temporal_direction:present");
                update_framed_digest(&mut self.digest, direction.as_bytes());
            }
            None => update_framed_digest(&mut self.digest, b"temporal_direction:absent"),
        }
        match edge.observed_at_millis {
            Some(observed_at_millis) => {
                update_framed_digest(&mut self.digest, b"observed_at:present");
                update_framed_digest(&mut self.digest, &observed_at_millis.to_be_bytes());
            }
            None => update_framed_digest(&mut self.digest, b"observed_at:absent"),
        }
        self.incident_typed_edge_count += 1;
        *self
            .association_family_counts
            .entry(edge.family.clone())
            .or_default() += 1;
    }
}

fn normalize_concepts(
    concepts: &[DiscoveryConceptInput],
    typed_edges: &[DiscoveryTypedEdgeInput],
) -> Vec<NormalizedConcept> {
    let mut association_context = concepts
        .iter()
        .map(|concept| (concept.cx_id, ConceptAssociationAccumulator::new()))
        .collect::<BTreeMap<_, _>>();
    for edge in typed_edges {
        if edge.src == edge.dst {
            association_context
                .get_mut(&edge.src)
                .expect("validated typed-edge source")
                .observe(edge, b"self", edge.src);
        } else {
            association_context
                .get_mut(&edge.src)
                .expect("validated typed-edge source")
                .observe(edge, b"outgoing", edge.dst);
            association_context
                .get_mut(&edge.dst)
                .expect("validated typed-edge destination")
                .observe(edge, b"incoming", edge.src);
        }
    }
    let mut normalized = concepts
        .iter()
        .map(|concept| {
            let tokens = concept_tokens(&concept.qualified_name);
            let lexical_preimage = format!(
                "{}\0{}\0{}\0{}",
                concept.symbol_kind.to_lowercase(),
                concept.language.to_lowercase(),
                tokens.join("\u{1f}"),
                concept.signature_or_shape.trim().to_lowercase()
            );
            let lexical_key = sha256_hex(lexical_preimage.as_bytes());
            let association = association_context
                .remove(&concept.cx_id)
                .expect("every validated concept has an association accumulator");
            let association_digest = association.digest.finalize();
            let association_signature_sha256 = digest_hex(&association_digest);
            let mut contextual = Sha256::new();
            update_framed_digest(
                &mut contextual,
                b"astrolabe.contextual_concept_normalization.v2",
            );
            update_framed_digest(&mut contextual, lexical_key.as_bytes());
            update_framed_digest(&mut contextual, association_signature_sha256.as_bytes());
            NormalizedConcept {
                cx_id: concept.cx_id,
                lexical_key,
                association_signature_sha256,
                incident_typed_edge_count: association.incident_typed_edge_count,
                association_family_counts: association.association_family_counts,
                normalized_key: digest_hex(&contextual.finalize()),
                tokens,
                symbol_kind: concept.symbol_kind.clone(),
                language: concept.language.clone(),
                signature_or_shape: concept.signature_or_shape.clone(),
                qualified_name: concept.qualified_name.clone(),
                file_path: concept.file_path.clone(),
                source_sha256: concept.source_sha256.clone(),
                source_excerpt: concept.source_excerpt.clone(),
                frequency: concept.frequency,
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
                grounded_confidence: grounded_confidence(concepts, pair.a, intermediary.id, pair.c),
                claim: format!(
                    "{} and {} may share a latent code relationship through {} ({})",
                    concepts[&pair.a].qualified_name,
                    concepts[&pair.c].qualified_name,
                    concepts[&intermediary.id].qualified_name,
                    report.relation
                ),
                structural_evidence: structural_evidence_for_abc(
                    evidence_index,
                    pair.a,
                    intermediary.id,
                    pair.c,
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
                structural_evidence: structural_evidence_for_abc(
                    evidence_index,
                    hypothesis.a,
                    hypothesis.b,
                    hypothesis.c,
                ),
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
    if usable.is_empty() {
        let reasons = folds
            .iter()
            .map(|fold| {
                format!(
                    "fold={} reason={}",
                    fold.fold,
                    fold.unusable_reason.as_deref().unwrap_or("unreported")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(DomainError::new(
            ASTRO_DISCOVERY_GRAPH_INVALID,
            format!("cross-validation produced zero usable folds: {reasons}"),
            "supply enough real endpoint-pair evidence for at least one leakage-free training/held-out fold; zero aggregates are never published",
        ));
    }
    let mut validated = usable
        .iter()
        .flat_map(|fold| fold.validated_pair_ids.iter().cloned())
        .collect::<Vec<_>>();
    validated.sort();
    validated.dedup();
    let precision_at_k = metric_stability(
        "precision_at_k",
        usable.iter().map(|fold| fold.precision_at_k),
    )?;
    let recall_at_k = metric_stability("recall_at_k", usable.iter().map(|fold| fold.recall_at_k))?;
    let reciprocal_rank = metric_stability(
        "reciprocal_rank",
        usable.iter().map(|fold| fold.reciprocal_rank),
    )?;
    let candidate_coverage_at_k = metric_stability(
        "candidate_coverage_at_k",
        usable.iter().map(|fold| fold.candidate_coverage_at_k),
    )?;
    let held_out_candidate_coverage = metric_stability(
        "held_out_candidate_coverage",
        usable.iter().map(|fold| fold.held_out_candidate_coverage),
    )?;
    let binary_brier_at_k = metric_stability(
        "binary_brier_at_k",
        usable.iter().filter_map(|fold| fold.binary_brier_at_k),
    )?;
    let no_skill_binary_brier = metric_stability(
        "no_skill_binary_brier",
        usable.iter().filter_map(|fold| fold.no_skill_binary_brier),
    )?;
    let binary_brier_skill_at_k = metric_stability(
        "binary_brier_skill_at_k",
        usable
            .iter()
            .filter_map(|fold| fold.binary_brier_skill_at_k),
    )?;
    let null_hits_at_k = metric_stability(
        "null_hits_at_k",
        usable.iter().map(|fold| fold.null_hits_at_k as f64),
    )?;
    let mean_precision_at_k = precision_at_k.as_ref().map_or(0.0, |row| row.mean);
    let mean_recall_at_k = recall_at_k.as_ref().map_or(0.0, |row| row.mean);
    let mean_reciprocal_rank = reciprocal_rank.as_ref().map_or(0.0, |row| row.mean);
    let mean_candidate_coverage_at_k = candidate_coverage_at_k.as_ref().map_or(0.0, |row| row.mean);
    let mean_held_out_candidate_coverage = held_out_candidate_coverage
        .as_ref()
        .map_or(0.0, |row| row.mean);
    let mean_binary_brier_at_k = binary_brier_at_k.as_ref().map(|row| row.mean);
    let mean_no_skill_binary_brier = no_skill_binary_brier.as_ref().map(|row| row.mean);
    let mean_binary_brier_skill_at_k = binary_brier_skill_at_k.as_ref().map(|row| row.mean);
    let mean_null_hits_at_k = null_hits_at_k.as_ref().map_or(0.0, |row| row.mean);
    Ok(CrossValidationReport {
        split_kind: plan.split_kind.to_string(),
        temporal_evidence: plan.temporal_evidence,
        usable_fold_count: usable.len(),
        mean_precision_at_k,
        mean_recall_at_k,
        mean_reciprocal_rank,
        mean_candidate_coverage_at_k,
        mean_held_out_candidate_coverage,
        mean_binary_brier_at_k,
        mean_no_skill_binary_brier,
        mean_binary_brier_skill_at_k,
        mean_null_hits_at_k,
        stability: CrossValidationStability {
            precision_at_k,
            recall_at_k,
            reciprocal_rank,
            candidate_coverage_at_k,
            held_out_candidate_coverage,
            binary_brier_at_k,
            no_skill_binary_brier,
            binary_brier_skill_at_k,
            null_hits_at_k,
        },
        folds,
        validated_pair_ids: validated,
    })
}

fn metric_stability(
    name: &str,
    values: impl IntoIterator<Item = f64>,
) -> Result<Option<ValidationMetricStability>> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    if values.iter().any(|value| !value.is_finite()) {
        return invalid_graph(format!(
            "cross-validation metric {name} contains a non-finite fold value"
        ));
    }
    let sample_count = values.len();
    let mean = values.iter().sum::<f64>() / sample_count as f64;
    let population_stddev = (values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / sample_count as f64)
        .sqrt();
    let minimum = values
        .iter()
        .copied()
        .min_by(f64::total_cmp)
        .expect("non-empty validation metric");
    let maximum = values
        .iter()
        .copied()
        .max_by(f64::total_cmp)
        .expect("non-empty validation metric");
    Ok(Some(ValidationMetricStability {
        sample_count,
        mean,
        population_stddev,
        minimum,
        maximum,
    }))
}

#[derive(Debug)]
struct ValidationPlan {
    split_kind: &'static str,
    temporal_evidence: TemporalEvidenceStatus,
    folds: Vec<ValidationFoldPlan>,
}

#[derive(Debug)]
struct ValidationFoldPlan {
    training_pairs: BTreeSet<(CxId, CxId)>,
    held_out_pairs: BTreeSet<(CxId, CxId)>,
    future_excluded_pairs: BTreeSet<(CxId, CxId)>,
}

fn validation_plan(input: &AssociationDiscoveryInput, fold_count: usize) -> ValidationPlan {
    let mut pair_timestamps = BTreeMap::<(CxId, CxId), Option<u64>>::new();
    let timestamped_edge_count = input
        .typed_edges
        .iter()
        .filter(|edge| edge.observed_at_millis.is_some())
        .count();
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
    if timestamped_edge_count == input.typed_edges.len()
        && pair_timestamps.values().all(Option::is_some)
    {
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
            temporal_evidence: TemporalEvidenceStatus::Measured {
                timestamped_edge_count,
                relationship_edge_count: input.typed_edges.len(),
            },
            folds,
        };
    }

    let mut buckets = vec![BTreeSet::new(); fold_count];
    for pair in pair_timestamps.keys().copied() {
        let fold = deterministic_pair_fold(pair, fold_count);
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
        split_kind: "deterministic_endpoint_pair_group_temporal_unavailable",
        temporal_evidence: TemporalEvidenceStatus::Unavailable {
            timestamped_edge_count,
            relationship_edge_count: input.typed_edges.len(),
            reason: "at least one persisted relationship has no observed timestamp; temporal ordering was excluded from validation".to_string(),
        },
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
            evaluation_pair_count: 0,
            top_k_evaluated_count: 0,
            held_out_candidate_count: 0,
            hits_at_k: 0,
            false_positives_at_k: 0,
            false_negatives_at_k: 0,
            precision_at_k: 0.0,
            recall_at_k: 0.0,
            reciprocal_rank: 0.0,
            candidate_coverage_at_k: 0.0,
            held_out_candidate_coverage: 0.0,
            binary_brier_at_k: None,
            no_skill_binary_brier: None,
            binary_brier_skill_at_k: None,
            rank_score_semantics: "resource_allocation_rank_score_not_a_calibrated_probability"
                .to_string(),
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
    let held_out_candidates = predicted
        .iter()
        .filter(|(pair, _)| plan.held_out_pairs.contains(pair))
        .count();
    let false_positives_at_k = k.saturating_sub(hits);
    let false_negatives_at_k = plan.held_out_pairs.len().saturating_sub(hits);
    let evaluation_pair_count = predicted.len().saturating_add(
        plan.held_out_pairs
            .len()
            .saturating_sub(held_out_candidates),
    );
    let binary_brier_at_k =
        (false_positives_at_k + false_negatives_at_k) as f64 / evaluation_pair_count.max(1) as f64;
    let prevalence = plan.held_out_pairs.len() as f64 / evaluation_pair_count.max(1) as f64;
    let no_skill_binary_brier = prevalence * (1.0 - prevalence);
    let binary_brier_skill_at_k = if no_skill_binary_brier > f64::EPSILON {
        Some(1.0 - binary_brier_at_k / no_skill_binary_brier)
    } else {
        None
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
        evaluation_pair_count,
        top_k_evaluated_count: k,
        held_out_candidate_count: held_out_candidates,
        hits_at_k: hits,
        false_positives_at_k,
        false_negatives_at_k,
        precision_at_k: hits as f64 / k.max(1) as f64,
        recall_at_k: hits as f64 / plan.held_out_pairs.len() as f64,
        reciprocal_rank,
        candidate_coverage_at_k: k as f64 / predicted.len().max(1) as f64,
        held_out_candidate_coverage: held_out_candidates as f64 / plan.held_out_pairs.len() as f64,
        binary_brier_at_k: Some(binary_brier_at_k),
        no_skill_binary_brier: Some(no_skill_binary_brier),
        binary_brier_skill_at_k,
        rank_score_semantics: "resource_allocation_rank_score_not_a_calibrated_probability"
            .to_string(),
        null_hits_at_k: null_hits,
        usable: true,
        unusable_reason: None,
        validated_pair_ids: validated,
    })
}

fn compact_reasoning_kernel(
    prepared: &PreparedAssociationDiscoveryEnvelope,
    evaluator: &HypothesisEvaluationReport,
    ranked: &AssociationRankedHypothesisReport,
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
        let candidate = candidates
            .get(hypothesis.hypothesis_id.as_str())
            .copied()
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_DISCOVERY_EVALUATOR_INVALID,
                    format!(
                        "ranked report names absent prepared hypothesis {}",
                        hypothesis.hypothesis_id
                    ),
                    "preserve the prepared artifact and rebuild the exact candidate/evaluator roster",
                )
            })?;
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
    let compact_member_ids = compact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<BTreeSet<_>>();
    if !compact_member_ids.is_subset(&member_ids) {
        let unexpected = compact_member_ids
            .difference(&member_ids)
            .next()
            .expect("non-subset has an unexpected member");
        return invalid_graph(format!(
            "compact reasoning kernel selected member {unexpected} outside the retained hypothesis endpoint roster"
        ));
    }
    let support_ids = member_ids
        .difference(&compact_member_ids)
        .copied()
        .collect::<Vec<_>>();
    let reasoning_roster = compact_member_ids
        .union(&member_ids)
        .copied()
        .collect::<BTreeSet<_>>();
    let reasoning_roster_ids = reasoning_roster.iter().copied().collect::<Vec<_>>();
    let reasoning_roster_hash = discovery_member_roster_hash(&reasoning_roster_ids);
    let final_member_ids = compact_member_ids.iter().copied().collect::<Vec<_>>();
    let mut retained_typed_edges = prepared
        .artifact
        .typed_edges
        .iter()
        .filter(|edge| {
            compact_member_ids.contains(&edge.src) && compact_member_ids.contains(&edge.dst)
        })
        .cloned()
        .collect::<Vec<_>>();
    retained_typed_edges.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    if retained_typed_edges.iter().any(|edge| {
        !compact_member_ids.contains(&edge.src) || !compact_member_ids.contains(&edge.dst)
    }) {
        return invalid_graph(
            "compact reasoning kernel retained a typed edge outside its final member roster",
        );
    }
    let retained_typed_edges_sha256 = sha256_hex(&canonical_json_bytes(&retained_typed_edges)?);
    let all_validated = ranked
        .hypotheses
        .iter()
        .all(|row| validated.contains(&pair_id(row.a, row.c)));
    let all_fully_grounded = ranked.hypotheses.iter().all(|row| {
        candidates
            .get(row.hypothesis_id.as_str())
            .is_some_and(|candidate| candidate.grounded_confidence >= 1.0)
    });
    let kernel_artifact_sha256 = sha256_hex(&compact.kernel_json_bytes());
    Ok(CompactReasoningKernel {
        schema: "astrolabe.discovery_reasoning_kernel.v2".to_string(),
        trust: if all_validated && all_fully_grounded {
            "grounded_source_held_out_with_trusted_operator_evaluator_capture".to_string()
        } else {
            "provisional_trusted_operator_evaluator_capture_held_out_incomplete".to_string()
        },
        member_ids: final_member_ids,
        members_hash: compact.members_hash.clone(),
        support_ids,
        reasoning_roster_hash,
        hypothesis_ids,
        evidence_ids: evidence_ids.into_iter().collect(),
        retained_typed_edges,
        retained_typed_edges_sha256,
        kernel_artifact_sha256,
        kernel_artifact: compact,
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
            if concept.source_excerpt.is_empty() {
                continue;
            }
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
                    if concept.source_sha256.is_empty() {
                        "source_sha256=unavailable:persisted_source_hash_absent".to_string()
                    } else {
                        format!("source_sha256={}", concept.source_sha256)
                    },
                    format!(
                        "source_generation_sha256={}",
                        input.source_generation_sha256
                    ),
                    if concept.file_path.is_empty() {
                        "file=unavailable:persisted_file_path_absent".to_string()
                    } else {
                        format!("file={}", concept.file_path)
                    },
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

fn structural_evidence_for_abc(
    evidence_index: &DiscoveryEvidenceIndex<'_>,
    a: CxId,
    b: CxId,
    c: CxId,
) -> Vec<ConceptStructuralEvidence> {
    [a, b, c]
        .into_iter()
        .filter_map(|cx_id| evidence_index.concepts.get(&cx_id).copied())
        .map(|concept| ConceptStructuralEvidence {
            cx_id: concept.cx_id,
            language: structural_field(&concept.language, "persisted file language is unavailable"),
            signature_or_shape: structural_field(
                &concept.signature_or_shape,
                "persisted signature or shape is unavailable",
            ),
            file_path: structural_field(&concept.file_path, "persisted file path is unavailable"),
            source_sha256: structural_field(
                &concept.source_sha256,
                "persisted source hash is unavailable",
            ),
            source_excerpt: structural_field(
                &concept.source_excerpt,
                "persisted source excerpt is unavailable",
            ),
        })
        .collect()
}

fn structural_field(value: &str, reason: &str) -> StructuralEvidenceField {
    if value.is_empty() {
        StructuralEvidenceField::Unavailable {
            reason: reason.to_string(),
        }
    } else {
        StructuralEvidenceField::Available {
            value: value.to_string(),
        }
    }
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

fn deterministic_pair_fold(pair: (CxId, CxId), fold_count: usize) -> usize {
    let (left, right) = pair;
    let digest = Sha256::digest(pair_id(left, right).as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("sha256 prefix")) as usize % fold_count
}

/// Canonical SHA-256 for an exact sorted unique discovery member roster.
pub fn discovery_member_roster_hash(ids: &[CxId]) -> String {
    let mut digest = Sha256::new();
    update_framed_digest(&mut digest, b"astrolabe.discovery.reasoning_roster.v1");
    update_framed_digest(&mut digest, &(ids.len() as u64).to_be_bytes());
    for id in ids {
        update_framed_digest(&mut digest, id.as_bytes());
    }
    digest_hex(&digest.finalize())
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

struct DiscoveryByteCounter {
    bytes: usize,
}

impl IoWrite for DiscoveryByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("association discovery byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_json_byte_count<T: Serialize>(value: &T) -> Result<usize> {
    let mut counter = DiscoveryByteCounter { bytes: 0 };
    serde_json::to_writer_pretty(&mut counter, value).map_err(|error| {
        DomainError::new(
            ASTRO_DISCOVERY_SOURCE_INCOMPLETE,
            format!("association discovery artifact sizing failed: {error}"),
            "repair non-serializable or non-finite discovery state before allocation",
        )
    })?;
    counter.bytes.checked_add(1).ok_or_else(|| {
        DomainError::new(
            ASTRO_DISCOVERY_SOURCE_INCOMPLETE,
            "association discovery artifact size overflow",
            "narrow the exact discovery generation before allocation",
        )
    })
}

fn update_framed_digest(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn update_optional_str(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            update_framed_digest(digest, b"present");
            update_framed_digest(digest, value.as_bytes());
        }
        None => update_framed_digest(digest, b"unavailable"),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(&Sha256::digest(bytes))
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
        "repair the trusted operator-captured evaluator receipts against the exact prepared generation and retry publication",
    )
}

fn map_paths(error: calyx_paths::PathsError) -> DomainError {
    DomainError::new(
        error.code(),
        error.to_string(),
        "repair the typed graph endpoint or finite weight named by the graph error before retrying",
    )
}
