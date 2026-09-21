//! Physical-truth compression measurement and admission.
//!
//! Registry owns this path because it is the first layer that can combine the
//! exact registered slot/lens interpretation, Aster's independently reopened
//! commit inventory, raw sidecar truth, and the production packed scorer. The
//! public request contains only policy and real held-out query inputs; byte
//! counts, hashes, scores, errors, backend observations, and admission state
//! are derived here and never accepted from the caller.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::time::Instant;

use calyx_aster::cf::{
    ColumnFamily, KeyRange, base_key, compression_admission_evaluation_pointer_key,
    compression_admission_pointer_key, compression_admission_receipt_key, compression_manifest_key,
    parse_compression_admission_evaluation_pointer_key, parse_compression_admission_pointer_key,
    parse_compression_lifecycle_key, parse_compression_membership_proof_key,
};
use calyx_aster::vault::{
    AsterVault, PhysicalCommitComponentRole, PhysicalCommitInventory, RetainedSnapshot, encode,
};
use calyx_core::{Clock, CxId, LedgerRef, QuantPolicy, Result, Seq, Slot, SlotShape, SlotVector};
use calyx_forge::quant::{binary_work_shape, turboquant_work_shape};
use calyx_forge::{BackendKind, QuantLevel, TURBOQUANT_MAX_DIM, TurboQuantGeometryKind};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::codec::{CodecDescriptor, raw_generation_root};
use super::index::generation_identity_without_codec_at;
use super::{
    CompressedGenerationIdentity, CompressedSlotHit, CompressedSlotIndex, CompressionQuery,
    StoredSlotCodec, compression_error,
};
use crate::spec::LensSpec;

pub const COMPRESSION_ADMISSION_SCHEMA: &str = "calyx.registry.compression_admission.v3";
const LEGACY_COMPRESSION_ADMISSION_SCHEMA: &str = "calyx.registry.compression_admission.v2";
pub const COMPRESSION_CANDIDATE_SELECTION_SCHEMA: &str =
    "calyx.registry.compression_candidate_selection.v1";
pub const CALYX_COMPRESSION_ADMISSION_REFUSED: &str = "CALYX_COMPRESSION_ADMISSION_REFUSED";

const PACKED_KERNEL_ID: &str = "calyx_registry::CompressedSlotIndex::search_at/cpu/v1";
const BUILD_PROTOCOL: &str = "calyx_registry::compress_streamed_column/registry_timed/v2";
const LEGACY_BUILD_PROTOCOL: &str = "calyx_registry::compress_streamed_column/registry_timed/v1";
const WORK_MODEL: &str = "calyx.registry.compression_work.v3";
const PREFLIGHT_PAGE_ROWS: usize = 1_024;
const LEGACY_WORKING_SET_GATE: &str = "maximum_working_set_bytes";
const WORKING_SET_AFTER_MEASURED_SEARCH_GATE: &str =
    "maximum_working_set_bytes_after_measured_search";
const SELECTION_PROTOCOL: &str =
    "calyx_registry::select_compression_candidate/exact_rational_physical_bits/v1";
const CPU_VRAM_REASON: &str =
    "not applicable: observed packed kernel executes on CPU and has no device-VRAM provider";
const ALLOCATION_SCOPE: &str = "exact Registry-visible owned corpus, reconstruction, truth, packed-result, latency-sample, and physical-inventory structures; allocator-internal calls and capacities are not inferred";

/// Policy and real held-out inputs for one current immutable generation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdmissionRequest {
    pub generation_seq: Seq,
    pub requested_backend: BackendKind,
    pub queries: Vec<CompressionQuery>,
    pub k: u32,
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub work_limits: CompressionAdmissionWorkLimits,
    pub gates: CompressionAdmissionGates,
}

/// Policy and real held-out inputs for a Registry-owned build-and-evaluate
/// operation. The generation sequence is deliberately absent: Registry derives
/// it from the compressed generation it just persisted and timed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateEvaluationRequest {
    pub requested_backend: BackendKind,
    pub queries: Vec<CompressionQuery>,
    pub k: u32,
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub work_limits: CompressionAdmissionWorkLimits,
    pub gates: CompressionAdmissionGates,
}

/// Pure v3 operation-shape preflight for callers that must refuse malformed or
/// over-limit work before opening a vault, resolving a codec, or traversing an
/// external chain. It validates candidate cardinality/identity uniqueness,
/// every required work limit, query cardinality/identity uniqueness, lifecycle
/// search count, backend, and gates; it performs no I/O (#1064 PC-03/13/43).
pub fn preflight_compression_candidate_operation(
    candidate_slot_ids: &[u16],
    request: &CompressionCandidateEvaluationRequest,
) -> Result<()> {
    preflight_compression_candidate_operation_inner(
        candidate_slot_ids.len(),
        candidate_slot_ids.iter().copied(),
        request,
    )
    .map(|_| ())
}

/// Caller-declared pre-execution limits over the real generation cardinality.
///
/// Registry derives the v3 accounting model from the canonical corpus shape
/// and each codec's allocation-free work shape. It checks every v3 limit
/// before codec allocation or any generation write; callers cannot assert the
/// accounted values. Required candidate/row/query limits separately bound
/// validation, preflight, and source-read passes outside the named accounting
/// categories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdmissionWorkLimits {
    pub maximum_corpus_rows: u64,
    pub maximum_held_out_queries: u64,
    /// V3 bounds build-recall plus warmup/measured packed searches. Canonical
    /// legacy-v2 receipts retain their original evaluation-only arithmetic.
    pub maximum_total_packed_searches: u64,
    pub maximum_pairwise_score_evaluations: u64,
    pub maximum_coefficient_evaluations: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub maximum_candidate_slots: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub maximum_peak_codec_geometry_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub maximum_aggregate_codec_retained_entry_and_sample_bound: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub maximum_aggregate_codec_transform_coefficient_visits: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub maximum_aggregate_pairwise_score_evaluations: u64,
    /// Maximum checked sum of the separately named retained-entry/sample,
    /// transform, auxiliary, pairwise, and Registry coefficient categories.
    /// It is an admission proxy, not a complete codec-work or instruction
    /// count, and it does not combine memory bytes into CPU work.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub maximum_total_accounted_work_units: u64,
}

/// Every admission gate is explicit and persisted with its observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdmissionGates {
    pub minimum_recall_at_k: f64,
    pub maximum_mean_cosine_error: f64,
    pub maximum_cosine_error: f64,
    pub maximum_p99_latency_ns: u64,
    pub maximum_total_physical_bytes: u64,
    /// V3 maximum endpoint RSS sampled after the measured packed-search phase;
    /// this is not a candidate transient-peak measurement. Legacy-v2 receipts
    /// retain their original gate label and arithmetic.
    pub maximum_working_set_bytes: u64,
    pub maximum_materialized_primary_bytes_per_query: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAdmissionVerdict {
    Admitted,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionPhysicalComponent {
    pub role: String,
    pub container: String,
    pub relative_path: String,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionScoredHit {
    pub cx_id: CxId,
    pub score: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionQueryObservation {
    pub query_cx_id: CxId,
    pub exact_top_k: Vec<CompressionScoredHit>,
    pub packed_top_k: Vec<CompressedSlotHit>,
    pub recall_at_k: f64,
    pub latency_samples_ns: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionReconstructionEvidence {
    pub cx_id: CxId,
    pub cosine_error: f64,
}

/// Wall-clock observation owned by the Registry operation that both creates
/// and evaluates a candidate. Callers cannot construct or inject this into the
/// public build-and-evaluate API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionBuildObservation {
    pub protocol: String,
    pub source_seq: Seq,
    pub generation_seq: Seq,
    pub elapsed_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "applicability", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompressionVramObservation {
    NotApplicable {
        reason: String,
    },
    /// Reserved for a device implementation that supplies a real provider
    /// observation. CPU execution never populates or estimates these fields.
    ProviderObserved {
        provider_identity: String,
        bytes_before: u64,
        bytes_after: u64,
        peak_bytes: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionPlacementObservation {
    pub requested_backend: BackendKind,
    pub observed_backend: BackendKind,
    pub device_identity: String,
    pub kernel_identity: String,
    pub vram: CompressionVramObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAllocationObservation {
    /// Exact scope of this count; it deliberately does not claim allocator-
    /// internal calls hidden below the stable Registry/Aster API boundary.
    pub scope: String,
    pub physical_inventory_row_records: u64,
    pub physical_inventory_component_records: u64,
    pub raw_truth_column_buffers: u64,
    pub raw_truth_vector_buffers: u64,
    pub raw_truth_rows: u64,
    pub raw_truth_encoded_bytes: u64,
    pub reconstruction_result_buffers: u64,
    pub reconstruction_rows: u64,
    pub exact_truth_result_buffers: u64,
    pub exact_truth_scored_rows: u64,
    pub packed_search_calls: u64,
    pub packed_result_buffers_returned: u64,
    pub packed_hits_returned: u64,
    pub retained_packed_result_buffers: u64,
    pub retained_packed_hits: u64,
    pub latency_sample_buffers: u64,
    pub latency_samples: u64,
    pub materialized_primary_rows_per_packed_search: u64,
    pub materialized_primary_bytes_per_packed_search: u64,
}

/// Immutable reference to one separately persisted candidate evaluation. V3
/// publication accepts only the exact full roster persisted by one common
/// commission; arbitrary subsets and single-candidate diagnostic receipts are
/// not selection cohorts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateReference {
    pub slot: Slot,
    pub receipt_sha256: [u8; 32],
}

/// Canonical summary of a candidate included in the selection source of truth.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateSelectionEntry {
    pub slot_id: u16,
    pub slot_key: String,
    pub receipt_sha256: String,
    pub generation_seq: Seq,
    pub codec: StoredSlotCodec,
    pub level: String,
    pub verdict: CompressionAdmissionVerdict,
    pub total_physical_bytes: u64,
    pub logical_values: u64,
    pub effective_bits_per_value: f64,
    pub build_elapsed_ns: u64,
}

/// Full deterministic candidate set persisted inside the selected receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateSelectionReceipt {
    pub schema: String,
    pub protocol: String,
    pub candidate_set_sha256: String,
    pub candidates: Vec<CompressionCandidateSelectionEntry>,
    pub winner_slot_id: u16,
    pub winner_receipt_sha256: String,
    pub ordering: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionResourceObservation {
    pub process_read_operations: u64,
    pub process_read_bytes: u64,
    pub process_page_faults: u64,
    pub working_set_bytes_after: u64,
    /// Process-lifetime OS peak at the post-search sample, recorded separately
    /// and never used as a candidate-scoped transient-peak gate.
    pub peak_working_set_bytes_after: u64,
    pub private_bytes_after: u64,
    /// Process-lifetime OS private-byte peak at the same endpoint sample.
    pub peak_private_bytes_after: u64,
}

/// Legacy local evaluation cardinalities plus the v3 deterministic admission
/// accounting model. The v3 fields are pre-execution bounds/accounted
/// categories, not observations of executed instructions or complete runtime
/// cost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionWorkObservation {
    pub corpus_rows: u64,
    pub held_out_queries: u64,
    pub warmup_packed_searches: u64,
    pub measured_packed_searches: u64,
    pub exact_truth_pairwise_scores: u64,
    pub packed_pairwise_scores: u64,
    pub reconstruction_rows: u64,
    pub coefficient_evaluations: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub work_model: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub candidate_slots: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_work: Vec<CompressionCandidateWorkObservation>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub peak_codec_geometry_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub aggregate_codec_retained_entry_and_sample_bound: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub aggregate_codec_transform_coefficient_visits: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub aggregate_codec_auxiliary_work_units: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub aggregate_pairwise_score_evaluations: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub aggregate_registry_coefficient_evaluations: u64,
    /// Checked heterogeneous sum documented on the matching limit. It is a
    /// deterministic v3 admission proxy, not observed instructions or a claim
    /// to account for every codec setup operation.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_accounted_work_units: u64,
}

/// One allocation-free candidate accounting bound. These are
/// structural loop/storage cardinalities, not claims about data-dependent
/// executed work: zero-valued codec paths may short-circuit. Candidate entries
/// are canonical by slot id and the aggregate is checked before codec
/// allocation or any generation write (#557/#1064 PC-03/16/35/37/41).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateWorkObservation {
    pub slot_id: u16,
    pub quant_policy: QuantPolicy,
    pub raw_dim: u32,
    pub stored_dim: u32,
    pub corpus_rows: u64,
    pub geometry_physical_bytes: u64,
    /// Checked sum of retained geometry entries and the codec planner's cold
    /// codebook sample-evaluation bound. This is not complete codec setup work.
    pub codec_retained_entry_and_sample_bound: u64,
    pub encode_calls: u64,
    pub decode_calls: u64,
    pub query_prepare_calls: u64,
    pub packed_score_calls: u64,
    pub codec_transform_coefficient_visits: u64,
    pub codec_auxiliary_work_units: u64,
    pub pairwise_score_evaluations: u64,
    pub registry_coefficient_evaluations: u64,
    /// Checked sum of this entry's retained-entry/sample, transform, codec
    /// auxiliary, pairwise, and Registry coefficient categories only.
    pub accounted_work_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionGateComparison {
    AtLeast,
    AtMost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionGateObservation {
    pub gate: String,
    pub comparison: CompressionGateComparison,
    pub observed: String,
    pub threshold: String,
    pub passed: bool,
}

/// Full raw receipt persisted immutably before any current pointer can move.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdmissionReceipt {
    pub schema: String,
    pub slot_id: u16,
    pub slot_key: String,
    pub generation_seq: Seq,
    pub manifest_seq: u64,
    pub codec: StoredSlotCodec,
    pub level: String,
    pub raw_dim: u32,
    pub stored_dim: u32,
    pub corpus_rows: u32,
    pub logical_values: u64,
    pub codec_context_sha256: String,
    pub generation_sha256: String,
    pub raw_generation_sha256: String,
    pub membership_sha256: String,
    pub source_values_sha256: String,
    /// Exact held-out input values used to derive truth and packed samples.
    /// Retaining them makes the query and exact-ground-truth digests
    /// independently recomputable from the immutable receipt.
    pub held_out_queries: Vec<CompressionQuery>,
    pub query_values_sha256: String,
    pub exact_ground_truth_sha256: String,
    pub query_ids_disjoint: bool,
    pub metric: String,
    pub k: u32,
    pub requested_backend: BackendKind,
    pub observed_backend: BackendKind,
    pub device_identity: String,
    pub kernel_identity: String,
    pub build: CompressionBuildObservation,
    pub placement: CompressionPlacementObservation,
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub physical_components: Vec<CompressionPhysicalComponent>,
    pub total_physical_bytes: u64,
    pub effective_bits_per_value: f64,
    pub primary_value_bytes: u64,
    pub queries: Vec<CompressionQueryObservation>,
    pub reconstruction: Vec<CompressionReconstructionEvidence>,
    pub mean_reconstruction_cosine_error: f64,
    pub max_reconstruction_cosine_error: f64,
    pub latency_p50_ns: u64,
    pub latency_p95_ns: u64,
    pub latency_p99_ns: u64,
    pub vectors_per_second: f64,
    pub bytes_per_second: f64,
    pub allocations: CompressionAllocationObservation,
    pub resources: CompressionResourceObservation,
    pub work_limits: CompressionAdmissionWorkLimits,
    pub work: CompressionWorkObservation,
    pub gates: CompressionAdmissionGates,
    pub gate_observations: Vec<CompressionGateObservation>,
    pub verdict: CompressionAdmissionVerdict,
    /// Present only on the newly persisted winner receipt created after the
    /// complete candidate set was read back and deterministically selected.
    pub candidate_selection: Option<CompressionCandidateSelectionReceipt>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateEvaluationReadback {
    pub generation: super::SlotCompressionReport,
    pub evaluation: CompressionAdmissionReadback,
}

/// Payload-free generation summary retained across a multi-candidate
/// commission. The full report remains available only from the explicit
/// single-candidate diagnostic API.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateGenerationSummary {
    pub slot_id: u16,
    pub slot_key: String,
    pub requested_quant: QuantPolicy,
    pub stored_codec: StoredSlotCodec,
    pub fallback_reason: Option<String>,
    pub corpus_rows: u32,
    pub raw_bytes_total: usize,
    pub stored_bytes_total: usize,
    pub codec_payload_bytes_total: usize,
    pub registry_envelope_bytes_total: usize,
    pub generation_manifest_bytes_total: usize,
    pub membership_proof_bytes_total: usize,
    pub membership_proof_key_bytes_total: usize,
    pub codec_header_bytes_total: usize,
    pub logical_data_bits_total: u64,
    pub written_value_bytes_total: usize,
    pub logical_data_bits_per_channel: f32,
    pub codec_payload_bits_per_channel: f32,
    pub written_value_bits_per_channel: f32,
    pub recall_at_k_raw: f32,
    pub recall_at_k_compressed: f32,
    pub recall_drop: f32,
    pub truncate_dim: Option<u32>,
    pub generation_seq: Seq,
    pub generation_ledger: LedgerRef,
}

/// Compact persisted identity for one member of a common v3 commission. Full
/// immutable receipt bytes remain in Aster and are independently reopened by
/// selection; this value deliberately owns no row, query, hit, reconstruction,
/// proof, manifest, or receipt payload vectors (#1064 PC-29/35).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateCommissionEntry {
    pub generation: CompressionCandidateGenerationSummary,
    pub schema: String,
    pub receipt_sha256: String,
    pub receipt_commit_seq: Seq,
    pub receipt_ledger: LedgerRef,
    pub codec_context_sha256: String,
    pub generation_sha256: String,
    pub raw_generation_sha256: String,
    pub membership_sha256: String,
    pub level: String,
    pub raw_dim: u32,
    pub stored_dim: u32,
    pub verdict: CompressionAdmissionVerdict,
    pub total_physical_bytes: u64,
    pub effective_bits_per_value: f64,
    pub build_elapsed_ns: u64,
    pub trust: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionCandidateCommissionReadback {
    pub candidates: Vec<CompressionCandidateCommissionEntry>,
    pub selected: CompressionAdmissionReadback,
}

fn compact_commission_candidate(
    candidate: CompressionCandidateEvaluationReadback,
) -> Result<CompressionCandidateCommissionEntry> {
    let generation_seq = candidate.generation.snapshot.ok_or_else(|| {
        admission_error("commission candidate generation has no durable sequence")
    })?;
    let generation_ledger = candidate.generation.ledger.clone().ok_or_else(|| {
        admission_error("commission candidate generation has no paired Ledger entry")
    })?;
    let receipt_commit_seq = candidate.evaluation.receipt_commit_seq.ok_or_else(|| {
        admission_error("commission candidate receipt has no durable commit sequence")
    })?;
    let receipt_ledger = candidate.evaluation.receipt_ledger.clone().ok_or_else(|| {
        admission_error("commission candidate receipt has no paired Ledger entry")
    })?;
    let corpus_rows = u32::try_from(candidate.generation.rows.len())
        .map_err(|_| admission_error("commission candidate row count exceeds u32"))?;
    let receipt = &candidate.evaluation.receipt;
    if candidate.evaluation.current
        || !candidate.evaluation.active_generation_current
        || receipt.candidate_selection.is_some()
        || receipt.generation_seq != generation_seq
        || receipt.corpus_rows != corpus_rows
        || receipt.slot_id != candidate.generation.slot_id
        || receipt.slot_key != candidate.generation.slot_key
        || receipt.codec != candidate.generation.stored_codec
        || receipt.build.elapsed_ns == 0
    {
        return Err(admission_error(
            "commission candidate compact identity does not match its unpublished durable generation/receipt readback",
        ));
    }
    let generation = CompressionCandidateGenerationSummary {
        slot_id: candidate.generation.slot_id,
        slot_key: candidate.generation.slot_key.clone(),
        requested_quant: candidate.generation.requested_quant,
        stored_codec: candidate.generation.stored_codec,
        fallback_reason: candidate.generation.fallback_reason.clone(),
        corpus_rows,
        raw_bytes_total: candidate.generation.raw_bytes_total,
        stored_bytes_total: candidate.generation.stored_bytes_total,
        codec_payload_bytes_total: candidate.generation.codec_payload_bytes_total,
        registry_envelope_bytes_total: candidate.generation.registry_envelope_bytes_total,
        generation_manifest_bytes_total: candidate.generation.generation_manifest_bytes_total,
        membership_proof_bytes_total: candidate.generation.membership_proof_bytes_total,
        membership_proof_key_bytes_total: candidate.generation.membership_proof_key_bytes_total,
        codec_header_bytes_total: candidate.generation.codec_header_bytes_total,
        logical_data_bits_total: candidate.generation.logical_data_bits_total,
        written_value_bytes_total: candidate.generation.written_value_bytes_total,
        logical_data_bits_per_channel: candidate.generation.logical_data_bits_per_channel,
        codec_payload_bits_per_channel: candidate.generation.codec_payload_bits_per_channel,
        written_value_bits_per_channel: candidate.generation.written_value_bits_per_channel,
        recall_at_k_raw: candidate.generation.recall_at_k_raw,
        recall_at_k_compressed: candidate.generation.recall_at_k_compressed,
        recall_drop: candidate.generation.recall_drop,
        truncate_dim: candidate.generation.truncate_dim,
        generation_seq,
        generation_ledger,
    };
    Ok(CompressionCandidateCommissionEntry {
        generation,
        schema: receipt.schema.clone(),
        receipt_sha256: candidate.evaluation.receipt_sha256.clone(),
        receipt_commit_seq,
        receipt_ledger,
        codec_context_sha256: receipt.codec_context_sha256.clone(),
        generation_sha256: receipt.generation_sha256.clone(),
        raw_generation_sha256: receipt.raw_generation_sha256.clone(),
        membership_sha256: receipt.membership_sha256.clone(),
        level: receipt.level.clone(),
        raw_dim: receipt.raw_dim,
        stored_dim: receipt.stored_dim,
        verdict: receipt.verdict,
        total_physical_bytes: receipt.total_physical_bytes,
        effective_bits_per_value: receipt.effective_bits_per_value,
        build_elapsed_ns: receipt.build.elapsed_ns,
        trust: candidate.evaluation.trust.clone(),
    })
}

/// Result of immutable receipt publication and optional pointer publication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdmissionReadback {
    pub receipt_sha256: String,
    pub receipt: CompressionAdmissionReceipt,
    pub receipt_commit_seq: Option<Seq>,
    pub receipt_ledger: Option<LedgerRef>,
    pub pointer_commit_seq: Option<Seq>,
    pub pointer_ledger: Option<LedgerRef>,
    pub current: bool,
    /// Explicit hash readback and every mutation/selection assertion compare
    /// the receipt generation sequence with the active manifest's exact visible
    /// MVCC row version. Pointer-driven latest-only readback instead compares
    /// the immutable content identity under Aster's mandatory generation-change
    /// tombstones for both admission pointer families.
    pub active_generation_current: bool,
    pub trust: String,
}

/// Bounded status read: the latest evaluation includes refusals, while the
/// current admission changes only after an admitted receipt is read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdmissionStatus {
    pub latest_evaluation: Option<CompressionAdmissionReadback>,
    pub current_admission: Option<CompressionAdmissionReadback>,
}

struct RawCorpus {
    rows: Vec<(CxId, Vec<f32>)>,
    source_sha256: [u8; 32],
    encoded_value_bytes: u64,
}

/// Creates one candidate generation and evaluates it without publishing a
/// current-admission pointer. The build timer is owned by this operation and
/// spans the real Registry compression write, including its durable commit.
/// This diagnostic receipt cannot later form an arbitrary selection cohort.
/// MXFP4 remains available here with its real shared-Assay source read; that
/// Assay-row cardinality is not a v3 commission limit, so multi-candidate MXFP4
/// is refused by the pure pre-mutation boundary (#1064 PC-03/43).
pub(crate) fn build_and_evaluate_candidate<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    request: CompressionCandidateEvaluationRequest,
) -> Result<CompressionCandidateEvaluationReadback> {
    let slots = [slot.clone()];
    let mut resolve_lens = |_slot: &Slot| Ok(lens);
    let preflight = preflight_candidate_set(vault, &slots, &request, &mut resolve_lens)?;
    let candidate = preflight
        .candidates
        .first()
        .ok_or_else(|| admission_error("single-candidate preflight returned no slot"))?;
    let planned_work = materialize_candidate_work(
        candidate,
        &preflight.canonical_rows,
        &request,
        &preflight.work_entries,
        &preflight.work_aggregates,
    )?;
    build_and_evaluate_candidate_rows(
        vault,
        &candidate.slot,
        &candidate.lens,
        request,
        &preflight.canonical_rows,
        planned_work,
        candidate.mxfp4_evidence.as_ref(),
    )
}

fn build_and_evaluate_candidate_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    request: CompressionCandidateEvaluationRequest,
    preflight_rows: &[(CxId, Vec<f32>)],
    planned_work: CompressionWorkObservation,
    preflight_mxfp4_evidence: Option<&super::MxFp4AssayEvidence>,
) -> Result<CompressionCandidateEvaluationReadback> {
    let refreshed_mxfp4_evidence = preflight_mxfp4_evidence
        .map(|evidence| {
            super::reload_mxfp4_assay_evidence_at(vault, slot, lens, evidence, vault.latest_seq())
        })
        .transpose()?;
    let started = Instant::now();
    let product = super::write_fresh_compressed_slot_batch_with_context_and_assay_evidence(
        vault,
        slot,
        lens,
        preflight_rows,
        &request.queries,
        request.k as usize,
        refreshed_mxfp4_evidence.as_ref(),
    )?;
    let super::CompressionBuildProduct {
        report: generation,
        codec,
        source_seq,
    } = product;
    let source_seq = source_seq.ok_or_else(|| {
        admission_error("Registry candidate build did not return its guarded source sequence")
    })?;
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| admission_error("candidate build elapsed time exceeds u64 nanoseconds"))?;
    if elapsed_ns == 0 {
        return Err(admission_error(
            "candidate build produced a zero-nanosecond timing observation",
        ));
    }
    let generation_seq = generation.snapshot.ok_or_else(|| {
        admission_error("Registry candidate build did not return a persisted generation sequence")
    })?;
    if generation.ledger.is_none() {
        return Err(admission_error(
            "Registry candidate build did not return its paired generation Ledger entry",
        ));
    }
    let build = CompressionBuildObservation {
        protocol: BUILD_PROTOCOL.to_string(),
        source_seq,
        generation_seq,
        elapsed_ns,
    };
    let evaluation = evaluate_candidate(
        vault,
        slot,
        lens,
        CompressionAdmissionRequest {
            generation_seq,
            requested_backend: request.requested_backend,
            queries: request.queries,
            k: request.k,
            warmup_runs: request.warmup_runs,
            measured_runs: request.measured_runs,
            work_limits: request.work_limits,
            gates: request.gates,
        },
        build,
        codec,
        planned_work,
    )?;
    Ok(CompressionCandidateEvaluationReadback {
        generation,
        evaluation,
    })
}

fn evaluate_candidate<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    request: CompressionAdmissionRequest,
    build: CompressionBuildObservation,
    codec: super::codec::CodecContext,
    planned_work: CompressionWorkObservation,
) -> Result<CompressionAdmissionReadback> {
    validate_request(slot, &request)?;
    if request.requested_backend != BackendKind::Cpu {
        return Err(admission_error(format!(
            "compressed slot {} requested backend {} but its active persisted packed path is CPU-only",
            slot.slot_id.get(),
            request.requested_backend
        )));
    }
    let evaluation_snapshot_lease = vault.retain_latest_snapshot();
    let evaluation_snapshot = evaluation_snapshot_lease.seq();
    if request.generation_seq != evaluation_snapshot {
        return Err(admission_error(format!(
            "compression admission generation seq {} is not the current vault seq {}; re-read the immutable generation before measuring",
            request.generation_seq, evaluation_snapshot
        )));
    }
    let expected_generation_seq = build.source_seq.checked_add(1).ok_or_else(|| {
        admission_error("Registry-owned candidate build source sequence overflow")
    })?;
    if build.protocol != BUILD_PROTOCOL
        || build.generation_seq != request.generation_seq
        || expected_generation_seq != build.generation_seq
        || build.elapsed_ns == 0
    {
        return Err(admission_error(
            "Registry-owned candidate build observation is inconsistent with the persisted generation",
        ));
    }

    vault.flush_with_report()?;
    let inventory = vault.physical_commit_inventory(
        request.generation_seq,
        &[
            ColumnFamily::slot(slot.slot_id),
            ColumnFamily::slot_raw(slot.slot_id),
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    validate_generation_inventory(slot, &inventory)?;
    evaluation_snapshot_lease.record_progress();

    let index = CompressedSlotIndex::open_with_context(vault, slot, lens, codec)?;
    let generation = index.generation_identity_at(request.generation_seq)?;
    validate_planned_work_for_generation(
        &planned_work,
        &generation,
        slot,
        &request,
        index.codec_geometry_physical_bytes()?,
    )?;
    evaluation_snapshot_lease.record_progress();
    let work = planned_work;
    let mut queries = request.queries.clone();
    queries.sort_by(|left, right| left.cx_id.as_bytes().cmp(right.cx_id.as_bytes()));
    validate_query_identities(&queries)?;

    let raw = load_raw_corpus(
        vault,
        slot,
        request.generation_seq,
        &generation,
        &evaluation_snapshot_lease,
    )?;
    let reconstruction = index
        .reconstruction_observations_against_at(request.generation_seq, &raw.rows)?
        .into_iter()
        .map(|observation| CompressionReconstructionEvidence {
            cx_id: observation.cx_id,
            cosine_error: observation.cosine_error,
        })
        .collect::<Vec<_>>();
    evaluation_snapshot_lease.record_progress();
    let (mean_error, max_error) = reconstruction_summary(&reconstruction)?;
    let corpus_ids = raw
        .rows
        .iter()
        .map(|(cx_id, _)| *cx_id)
        .collect::<BTreeSet<_>>();
    if let Some(overlap) = queries
        .iter()
        .find(|query| corpus_ids.contains(&query.cx_id))
    {
        return Err(admission_error(format!(
            "held-out query {} is present in the compressed corpus; self-query recall evidence is refused",
            overlap.cx_id
        )));
    }
    let exact_truth = exact_truth(
        &raw.rows,
        &queries,
        request.k as usize,
        &evaluation_snapshot_lease,
    )?;
    let source_values_sha256 = raw.source_sha256;
    let raw_truth_encoded_bytes = raw.encoded_value_bytes;
    drop(raw);

    for _ in 0..request.warmup_runs {
        for query in &queries {
            index.search_at(&query.values, request.k as usize, request.generation_seq)?;
            evaluation_snapshot_lease.record_progress();
        }
    }

    let usage_before = vault.process_usage_snapshot()?;
    let mut packed_results: Vec<Option<Vec<CompressedSlotHit>>> = vec![None; queries.len()];
    let mut latency_samples =
        vec![Vec::with_capacity(request.measured_runs as usize); queries.len()];
    for _sample in 0..request.measured_runs {
        for (query_index, query) in queries.iter().enumerate() {
            let started = Instant::now();
            let hits =
                index.search_at(&query.values, request.k as usize, request.generation_seq)?;
            let elapsed = u64::try_from(started.elapsed().as_nanos())
                .map_err(|_| admission_error("packed search latency exceeds u64 nanoseconds"))?;
            if elapsed == 0 {
                return Err(admission_error(
                    "packed search produced a zero-nanosecond timing observation",
                ));
            }
            if let Some(first) = &packed_results[query_index] {
                if first != &hits {
                    return Err(admission_error(format!(
                        "packed search results changed across measured runs for query {}",
                        query.cx_id
                    )));
                }
            } else {
                packed_results[query_index] = Some(hits);
            }
            latency_samples[query_index].push(elapsed);
            evaluation_snapshot_lease.record_progress();
        }
    }
    let usage = vault.process_usage_snapshot()?.phase_since(usage_before);

    let query_observations = build_query_observations(
        &queries,
        exact_truth,
        packed_results,
        latency_samples,
        request.k as usize,
    )?;

    let mut all_samples = query_observations
        .iter()
        .flat_map(|observation| observation.latency_samples_ns.iter().copied())
        .collect::<Vec<_>>();
    all_samples.sort_unstable();
    let p50 = percentile(&all_samples, 50)?;
    let p95 = percentile(&all_samples, 95)?;
    let p99 = percentile(&all_samples, 99)?;
    let primary_value_bytes = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::slot(slot.slot_id))
        .try_fold(0_u64, |total, row| {
            total
                .checked_add(row.value_length)
                .ok_or_else(|| admission_error("primary value byte total overflow"))
        })?;
    let logical_values = u64::from(generation.row_count)
        .checked_mul(u64::from(generation.raw_dim))
        .ok_or_else(|| admission_error("logical value count overflow"))?;
    let physical_bits = inventory
        .total_physical_bytes
        .checked_mul(8)
        .ok_or_else(|| admission_error("physical bit total overflow"))?;
    let effective_bits_per_value = physical_bits as f64 / logical_values as f64;
    let median_seconds = p50 as f64 / 1_000_000_000.0;
    let vectors_per_second = f64::from(generation.row_count) / median_seconds;
    let bytes_per_second = primary_value_bytes as f64 / median_seconds;
    if !effective_bits_per_value.is_finite()
        || !vectors_per_second.is_finite()
        || !bytes_per_second.is_finite()
    {
        return Err(admission_error(
            "derived physical rate or packed throughput is non-finite",
        ));
    }

    let query_values_sha256 = query_digest(&queries);
    let exact_ground_truth_sha256 = truth_digest(&query_observations);
    let minimum_recall = query_observations
        .iter()
        .map(|observation| observation.recall_at_k)
        .reduce(f64::min)
        .ok_or_else(|| admission_error("no query recall observations were produced"))?;
    let gate_observations = evaluate_gates(
        &request.gates,
        minimum_recall,
        mean_error,
        max_error,
        p99,
        inventory.total_physical_bytes,
        usage.working_set_bytes_after,
        primary_value_bytes,
        WORKING_SET_AFTER_MEASURED_SEARCH_GATE,
    );
    let verdict = if gate_observations.iter().all(|gate| gate.passed) {
        CompressionAdmissionVerdict::Admitted
    } else {
        CompressionAdmissionVerdict::Refused
    };
    let measured_searches = u64::from(request.measured_runs)
        .checked_mul(queries.len() as u64)
        .ok_or_else(|| admission_error("measured search count overflow"))?;
    let packed_search_calls = work
        .warmup_packed_searches
        .checked_add(work.measured_packed_searches)
        .ok_or_else(|| admission_error("packed-search allocation count overflow"))?;
    let packed_hits_returned = packed_search_calls
        .checked_mul(u64::from(request.k))
        .ok_or_else(|| admission_error("packed-hit allocation count overflow"))?;
    let retained_packed_hits = (queries.len() as u64)
        .checked_mul(u64::from(request.k))
        .ok_or_else(|| admission_error("retained packed-hit count overflow"))?;
    let exact_truth_scored_rows = (queries.len() as u64)
        .checked_mul(u64::from(generation.row_count))
        .ok_or_else(|| admission_error("exact-truth scored-row count overflow"))?;
    evaluation_snapshot_lease.record_progress();
    let active_snapshot_lease = vault.retain_latest_snapshot();
    let active_snapshot = active_snapshot_lease.seq();
    let active_generation =
        generation_identity_without_codec_at(vault, slot, lens, active_snapshot)?;
    if active_generation != generation {
        return Err(admission_error(
            "compressed candidate generation changed during retained admission evaluation",
        ));
    }
    active_snapshot_lease.record_progress();
    drop(active_snapshot_lease);
    evaluation_snapshot_lease.record_progress();
    let receipt = CompressionAdmissionReceipt {
        schema: COMPRESSION_ADMISSION_SCHEMA.to_string(),
        slot_id: slot.slot_id.get(),
        slot_key: slot.slot_key.key().to_string(),
        generation_seq: request.generation_seq,
        manifest_seq: inventory.manifest_seq,
        codec: generation.codec,
        level: generation.level,
        raw_dim: generation.raw_dim,
        stored_dim: generation.stored_dim,
        corpus_rows: generation.row_count,
        logical_values,
        codec_context_sha256: generation.codec_context_sha256,
        generation_sha256: generation.generation_sha256,
        raw_generation_sha256: generation.raw_generation_sha256,
        membership_sha256: generation.membership_sha256,
        source_values_sha256: hex(&source_values_sha256),
        held_out_queries: queries.clone(),
        query_values_sha256: hex(&query_values_sha256),
        exact_ground_truth_sha256: hex(&exact_ground_truth_sha256),
        query_ids_disjoint: true,
        metric: "cosine".to_string(),
        k: request.k,
        requested_backend: request.requested_backend,
        observed_backend: BackendKind::Cpu,
        device_identity: cpu_device_identity(),
        kernel_identity: PACKED_KERNEL_ID.to_string(),
        build,
        placement: CompressionPlacementObservation {
            requested_backend: request.requested_backend,
            observed_backend: BackendKind::Cpu,
            device_identity: cpu_device_identity(),
            kernel_identity: PACKED_KERNEL_ID.to_string(),
            vram: CompressionVramObservation::NotApplicable {
                reason: CPU_VRAM_REASON.to_string(),
            },
        },
        warmup_runs: request.warmup_runs,
        measured_runs: request.measured_runs,
        physical_components: physical_components(&inventory),
        total_physical_bytes: inventory.total_physical_bytes,
        effective_bits_per_value,
        primary_value_bytes,
        queries: query_observations,
        reconstruction,
        mean_reconstruction_cosine_error: mean_error,
        max_reconstruction_cosine_error: max_error,
        latency_p50_ns: p50,
        latency_p95_ns: p95,
        latency_p99_ns: p99,
        vectors_per_second,
        bytes_per_second,
        allocations: CompressionAllocationObservation {
            scope: ALLOCATION_SCOPE.to_string(),
            physical_inventory_row_records: inventory.rows.len() as u64,
            physical_inventory_component_records: inventory.components.len() as u64,
            raw_truth_column_buffers: 1,
            raw_truth_vector_buffers: u64::from(generation.row_count),
            raw_truth_rows: u64::from(generation.row_count),
            raw_truth_encoded_bytes,
            reconstruction_result_buffers: 1,
            reconstruction_rows: u64::from(generation.row_count),
            exact_truth_result_buffers: queries.len() as u64,
            exact_truth_scored_rows,
            packed_search_calls,
            packed_result_buffers_returned: packed_search_calls,
            packed_hits_returned,
            retained_packed_result_buffers: queries.len() as u64,
            retained_packed_hits,
            latency_sample_buffers: queries.len() as u64,
            latency_samples: measured_searches,
            materialized_primary_rows_per_packed_search: u64::from(generation.row_count),
            materialized_primary_bytes_per_packed_search: primary_value_bytes,
        },
        resources: CompressionResourceObservation {
            process_read_operations: usage.read_operations,
            process_read_bytes: usage.read_bytes,
            process_page_faults: usage.page_faults,
            working_set_bytes_after: usage.working_set_bytes_after,
            peak_working_set_bytes_after: usage.peak_working_set_bytes_after,
            private_bytes_after: usage.private_bytes_after,
            peak_private_bytes_after: usage.peak_private_bytes_after,
        },
        work_limits: request.work_limits,
        work,
        gates: request.gates,
        gate_observations,
        verdict,
        candidate_selection: None,
    };
    drop(evaluation_snapshot_lease);
    persist_evaluation_receipt(vault, slot, lens, receipt)
}

pub(crate) fn read_admission<'a, C, F>(
    vault: &AsterVault<C>,
    slot: &Slot,
    receipt_sha256: Option<[u8; 32]>,
    resolve_lens: F,
) -> Result<Option<CompressionAdmissionReadback>>
where
    C: Clock,
    F: FnOnce() -> Result<&'a LensSpec>,
{
    let snapshot_lease = vault.retain_latest_snapshot();
    let snapshot = snapshot_lease.seq();
    let explicitly_addressed = receipt_sha256.is_some();
    let (receipt_sha256, current_pointer) = match receipt_sha256 {
        Some(digest) => {
            let pointer = read_pointer_digest(
                vault,
                slot,
                snapshot,
                &compression_admission_pointer_key(slot.slot_id),
                "current-admission",
            )?;
            (digest, pointer == Some(digest))
        }
        None => {
            let Some(digest) = read_pointer_digest(
                vault,
                slot,
                snapshot,
                &compression_admission_pointer_key(slot.slot_id),
                "current-admission",
            )?
            else {
                return Ok(None);
            };
            (digest, true)
        }
    };
    snapshot_lease.record_progress();
    let receipt = read_receipt_at(vault, slot, snapshot, receipt_sha256)?;
    snapshot_lease.record_progress();
    let lens = resolve_lens()?;
    let generation = generation_identity_without_codec_at(vault, slot, lens, snapshot)?;
    let active_generation_current = if explicitly_addressed {
        receipt_binds_active_generation_at(vault, &receipt, slot, &generation, snapshot)?
    } else {
        receipt_binds_generation_content(&receipt, slot, &generation)
    };
    snapshot_lease.record_progress();
    if current_pointer {
        if receipt.candidate_selection.is_none() {
            return Err(admission_error(
                "current compression admission does not carry a full candidate-set selection receipt",
            ));
        }
        if !active_generation_current {
            return Err(admission_error(
                "current compression admission does not bind the active manifested generation",
            ));
        }
    }
    Ok(Some(CompressionAdmissionReadback {
        receipt_sha256: hex(&receipt_sha256),
        receipt,
        receipt_commit_seq: None,
        receipt_ledger: None,
        pointer_commit_seq: None,
        pointer_ledger: None,
        current: current_pointer,
        active_generation_current,
        trust: if current_pointer && active_generation_current {
            "verified_physical_readback_current_pointer_and_active_generation".to_string()
        } else if active_generation_current {
            "verified_historical_hash_and_active_generation".to_string()
        } else {
            "verified_historical_hash_and_inactive_generation".to_string()
        },
    }))
}

pub(crate) fn admission_status<'a, C, F>(
    vault: &AsterVault<C>,
    slot: &Slot,
    resolve_lens: F,
) -> Result<CompressionAdmissionStatus>
where
    C: Clock,
    F: FnOnce() -> Result<&'a LensSpec>,
{
    let snapshot_lease = vault.retain_latest_snapshot();
    let snapshot = snapshot_lease.seq();
    let latest_digest = read_pointer_digest(
        vault,
        slot,
        snapshot,
        &compression_admission_evaluation_pointer_key(slot.slot_id),
        "latest-evaluation",
    )?;
    let current_digest = read_pointer_digest(
        vault,
        slot,
        snapshot,
        &compression_admission_pointer_key(slot.slot_id),
        "current-admission",
    )?;
    snapshot_lease.record_progress();
    if latest_digest.is_none() && current_digest.is_none() {
        return Ok(CompressionAdmissionStatus {
            latest_evaluation: None,
            current_admission: None,
        });
    }
    if latest_digest.is_none() && current_digest.is_some() {
        return Err(admission_error(format!(
            "slot {} has a current compression admission but no latest-evaluation pointer",
            slot.slot_id.get()
        )));
    }
    let lens = resolve_lens()?;
    let generation = generation_identity_without_codec_at(vault, slot, lens, snapshot)?;
    snapshot_lease.record_progress();

    let latest_evaluation = if let Some(digest) = latest_digest {
        let receipt = read_receipt_at(vault, slot, snapshot, digest)?;
        validate_pointer_bound_generation(&receipt, slot, &generation)?;
        snapshot_lease.record_progress();
        let is_current = current_digest == Some(digest);
        Some(CompressionAdmissionReadback {
            receipt_sha256: hex(&digest),
            receipt,
            receipt_commit_seq: None,
            receipt_ledger: None,
            pointer_commit_seq: None,
            pointer_ledger: None,
            current: is_current,
            active_generation_current: true,
            trust: "verified_latest_evaluation_and_active_generation".to_string(),
        })
    } else {
        None
    };
    let current_admission = if let Some(digest) = current_digest {
        let receipt = if latest_digest == Some(digest) {
            latest_evaluation
                .as_ref()
                .expect("equal latest/current digest has a latest receipt")
                .receipt
                .clone()
        } else {
            let receipt = read_receipt_at(vault, slot, snapshot, digest)?;
            validate_pointer_bound_generation(&receipt, slot, &generation)?;
            snapshot_lease.record_progress();
            receipt
        };
        if receipt.verdict != CompressionAdmissionVerdict::Admitted
            || receipt.candidate_selection.is_none()
        {
            return Err(admission_error(format!(
                "slot {} current-admission pointer references a refused or unselected receipt {}",
                slot.slot_id.get(),
                hex(&digest)
            )));
        }
        Some(CompressionAdmissionReadback {
            receipt_sha256: hex(&digest),
            receipt,
            receipt_commit_seq: None,
            receipt_ledger: None,
            pointer_commit_seq: None,
            pointer_ledger: None,
            current: true,
            active_generation_current: true,
            trust: "verified_current_admission_and_active_generation".to_string(),
        })
    } else {
        None
    };
    Ok(CompressionAdmissionStatus {
        latest_evaluation,
        current_admission,
    })
}

struct PreflightCandidate {
    slot: Slot,
    lens: LensSpec,
    descriptor: CodecDescriptor,
    mxfp4_evidence: Option<super::MxFp4AssayEvidence>,
    minimum_work: CompressionCandidateWorkObservation,
}

struct CandidatePreflight {
    candidates: Vec<PreflightCandidate>,
    canonical_rows: Vec<(CxId, Vec<f32>)>,
    work_entries: Vec<CompressionCandidateWorkObservation>,
    work_aggregates: WorkAggregates,
}

#[derive(Clone, Debug, PartialEq)]
struct CandidateCohortIdentity {
    schema: String,
    work_model: String,
    candidate_slots: u64,
    candidate_work: Vec<CompressionCandidateWorkObservation>,
    peak_codec_geometry_bytes: u64,
    aggregate_codec_retained_entry_and_sample_bound: u64,
    aggregate_codec_transform_coefficient_visits: u64,
    aggregate_codec_auxiliary_work_units: u64,
    aggregate_pairwise_score_evaluations: u64,
    aggregate_registry_coefficient_evaluations: u64,
    total_accounted_work_units: u64,
    source_values_sha256: String,
    raw_dim: u32,
    corpus_rows: u32,
    held_out_query_count: u64,
    query_values_sha256: String,
    exact_ground_truth_sha256: String,
    metric: String,
    k: u32,
    requested_backend: BackendKind,
    observed_backend: BackendKind,
    device_identity: String,
    kernel_identity: String,
    placement: CompressionPlacementObservation,
    warmup_runs: u32,
    measured_runs: u32,
    build_protocol: String,
    work_limits: CompressionAdmissionWorkLimits,
    gate_float_bits: [u64; 3],
    gate_integer_thresholds: [u64; 4],
}

impl CandidateCohortIdentity {
    fn from_receipt(receipt: &CompressionAdmissionReceipt) -> Result<Self> {
        Ok(Self {
            schema: receipt.schema.clone(),
            work_model: receipt.work.work_model.clone(),
            candidate_slots: receipt.work.candidate_slots,
            candidate_work: receipt.work.candidate_work.clone(),
            peak_codec_geometry_bytes: receipt.work.peak_codec_geometry_bytes,
            aggregate_codec_retained_entry_and_sample_bound: receipt
                .work
                .aggregate_codec_retained_entry_and_sample_bound,
            aggregate_codec_transform_coefficient_visits: receipt
                .work
                .aggregate_codec_transform_coefficient_visits,
            aggregate_codec_auxiliary_work_units: receipt.work.aggregate_codec_auxiliary_work_units,
            aggregate_pairwise_score_evaluations: receipt.work.aggregate_pairwise_score_evaluations,
            aggregate_registry_coefficient_evaluations: receipt
                .work
                .aggregate_registry_coefficient_evaluations,
            total_accounted_work_units: receipt.work.total_accounted_work_units,
            source_values_sha256: receipt.source_values_sha256.clone(),
            raw_dim: receipt.raw_dim,
            corpus_rows: receipt.corpus_rows,
            held_out_query_count: u64::try_from(receipt.held_out_queries.len())
                .map_err(|_| admission_error("candidate held-out query count exceeds u64"))?,
            query_values_sha256: receipt.query_values_sha256.clone(),
            exact_ground_truth_sha256: receipt.exact_ground_truth_sha256.clone(),
            metric: receipt.metric.clone(),
            k: receipt.k,
            requested_backend: receipt.requested_backend,
            observed_backend: receipt.observed_backend,
            device_identity: receipt.device_identity.clone(),
            kernel_identity: receipt.kernel_identity.clone(),
            placement: receipt.placement.clone(),
            warmup_runs: receipt.warmup_runs,
            measured_runs: receipt.measured_runs,
            build_protocol: receipt.build.protocol.clone(),
            work_limits: receipt.work_limits.clone(),
            gate_float_bits: [
                receipt.gates.minimum_recall_at_k.to_bits(),
                receipt.gates.maximum_mean_cosine_error.to_bits(),
                receipt.gates.maximum_cosine_error.to_bits(),
            ],
            gate_integer_thresholds: [
                receipt.gates.maximum_p99_latency_ns,
                receipt.gates.maximum_total_physical_bytes,
                receipt.gates.maximum_working_set_bytes,
                receipt.gates.maximum_materialized_primary_bytes_per_query,
            ],
        })
    }
}

struct LoadedCandidateSet {
    references: Vec<CompressionCandidateReference>,
    selection: CompressionCandidateSelectionReceipt,
    winner_reference: CompressionCandidateReference,
    winner_receipt: CompressionAdmissionReceipt,
}

/// Production commission path: preflights every registered candidate against
/// the same immutable vault sequence before the first write, then builds and
/// evaluates each real raw primary column and selects the independently
/// persisted winner. A physical fault after preflight may leave an explicitly
/// inspectable prefix of candidate evaluations; it is never represented as an
/// atomic commission.
///
/// The v3 work vector is derived with checked arithmetic before the first codec
/// allocation or write. One canonical corpus allocation remains live through
/// candidate builds and drops before selection; every later candidate
/// comparison buffer is dropped before the next scan. One
/// held-out-query identity set is invariant across every candidate/row
/// membership check. Each full generation/evaluation result is converted to a
/// payload-free typed entry and dropped before the next candidate build; the
/// returned candidate vector contains only identities, scalar totals, and
/// publication references (#1064 PC-03/13/29/35/41).
pub(crate) fn commission_and_select_candidates<'a, C, F>(
    vault: &AsterVault<C>,
    candidate_slots: &[Slot],
    request: CompressionCandidateEvaluationRequest,
    mut resolve_lens: F,
) -> Result<CompressionCandidateCommissionReadback>
where
    C: Clock,
    F: FnMut(&Slot) -> Result<&'a LensSpec>,
{
    let preflight = preflight_candidates(vault, candidate_slots, &request, &mut resolve_lens)?;
    let mut evaluations = Vec::with_capacity(preflight.candidates.len());
    for candidate in &preflight.candidates {
        let planned_work = materialize_candidate_work(
            candidate,
            &preflight.canonical_rows,
            &request,
            &preflight.work_entries,
            &preflight.work_aggregates,
        )?;
        let full = build_and_evaluate_candidate_rows(
            vault,
            &candidate.slot,
            &candidate.lens,
            request.clone(),
            &preflight.canonical_rows,
            planned_work,
            candidate.mxfp4_evidence.as_ref(),
        )?;
        evaluations.push(compact_commission_candidate(full)?);
    }
    let references = preflight
        .candidates
        .iter()
        .zip(&evaluations)
        .map(|(candidate, evaluation)| {
            Ok(CompressionCandidateReference {
                slot: candidate.slot.clone(),
                receipt_sha256: decode_hex_32(
                    &evaluation.receipt_sha256,
                    "candidate receipt SHA-256",
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // Selection reopens immutable receipts and no longer needs source vectors
    // or the shared work roster; drop both payloads before the first replay.
    drop(preflight.canonical_rows);
    drop(preflight.work_entries);
    let selected = select_compression_candidate(vault, &references, |slot| {
        preflight
            .candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == slot.slot_id)
            .map(|candidate| &candidate.lens)
            .ok_or_else(|| admission_error("selected candidate slot was absent from preflight"))
    })?;
    Ok(CompressionCandidateCommissionReadback {
        candidates: evaluations,
        selected,
    })
}

fn preflight_candidates<'a, C, F>(
    vault: &AsterVault<C>,
    candidate_slots: &[Slot],
    request: &CompressionCandidateEvaluationRequest,
    resolve_lens: &mut F,
) -> Result<CandidatePreflight>
where
    C: Clock,
    F: FnMut(&Slot) -> Result<&'a LensSpec>,
{
    if candidate_slots.len() < 2 {
        return Err(admission_error(
            "compression commission requires at least two registered candidate slots",
        ));
    }
    preflight_candidate_set(vault, candidate_slots, request, resolve_lens)
}

fn preflight_candidate_set<'a, C, F>(
    vault: &AsterVault<C>,
    candidate_slots: &[Slot],
    request: &CompressionCandidateEvaluationRequest,
    resolve_lens: &mut F,
) -> Result<CandidatePreflight>
where
    C: Clock,
    F: FnMut(&Slot) -> Result<&'a LensSpec>,
{
    let held_out_query_ids = preflight_compression_candidate_operation_inner(
        candidate_slots.len(),
        candidate_slots.iter().map(|slot| slot.slot_id.get()),
        request,
    )?;
    let multiple_candidates = candidate_slots.len() > 1;
    if multiple_candidates
        && candidate_slots
            .iter()
            .any(|slot| slot.quant == QuantPolicy::MxFp4)
    {
        return Err(admission_error(
            "multi-candidate v3 commission refuses MXFP4 before any vault, source, codec, or mutation work because initial Assay evidence discovery is not governed by a declared Assay-row bound; use the real single-candidate diagnostic until a bounded exact evidence key is available (#1064 PC-03/43)",
        ));
    }
    let mut canonical_slots = candidate_slots.to_vec();
    canonical_slots.sort_by_key(|slot| slot.slot_id.get());
    let snapshot_lease = vault.retain_latest_snapshot();
    let snapshot = snapshot_lease.seq();
    let query_count = u64::try_from(request.queries.len())
        .map_err(|_| admission_error("held-out query count exceeds u64"))?;
    let lifecycle_query_runs = u64::from(request.warmup_runs)
        .checked_add(u64::from(request.measured_runs))
        .and_then(|runs| runs.checked_add(1))
        .ok_or_else(|| admission_error("candidate query-run count overflow"))?;
    let mut preflight: Vec<PreflightCandidate> = Vec::with_capacity(canonical_slots.len());
    for slot in canonical_slots {
        validate_candidate_evaluation_request_for_slot(&slot, request)?;
        let lens = resolve_lens(&slot)?.clone();
        let descriptor = CodecDescriptor::for_read(&slot, &lens)?;
        validate_codec_work_shape(slot.quant, descriptor.dim())?;
        let SlotShape::Dense(raw_dim) = slot.shape else {
            return Err(admission_error("compression candidate slot is not dense"));
        };
        let stored_dim = u32::try_from(descriptor.dim())
            .map_err(|_| admission_error("candidate stored dimension exceeds u32"))?;
        derive_and_validate_work_counts(
            1,
            raw_dim,
            stored_dim,
            query_count,
            request.warmup_runs,
            request.measured_runs,
            &request.work_limits,
        )?;
        let minimum_work = derive_candidate_work_observation(
            slot.slot_id.get(),
            slot.quant,
            raw_dim,
            stored_dim,
            1,
            query_count,
            lifecycle_query_runs,
        )?;
        for (key, kind) in [
            (
                compression_manifest_key(slot.slot_id),
                "generation manifest",
            ),
            (
                compression_admission_evaluation_pointer_key(slot.slot_id),
                "latest-evaluation pointer",
            ),
            (
                compression_admission_pointer_key(slot.slot_id),
                "current-admission pointer",
            ),
        ] {
            if vault
                .read_cf_at(snapshot, ColumnFamily::Compression, &key)?
                .is_some()
            {
                return Err(admission_error(format!(
                    "candidate slot {} already has a {kind}; commission requires an unmanifested raw primary column",
                    slot.slot_id.get()
                )));
            }
            snapshot_lease.record_progress();
        }
        preflight.push(PreflightCandidate {
            slot,
            lens,
            descriptor,
            mxfp4_evidence: None,
            minimum_work,
        });
    }
    let minimum_aggregates =
        aggregate_candidate_work(preflight.iter().map(|candidate| &candidate.minimum_work))?;
    validate_v3_minimum_aggregate_limits(&minimum_aggregates, &request.work_limits)?;
    snapshot_lease.record_progress();
    let mut canonical_rows: Option<Vec<(CxId, Vec<f32>)>> = None;
    for candidate in &mut preflight {
        let rows = scan_preflight_candidate_rows(
            vault,
            &snapshot_lease,
            &candidate.slot,
            request,
            &held_out_query_ids,
        )?;
        if candidate.slot.quant == QuantPolicy::MxFp4 {
            candidate.mxfp4_evidence = Some(super::load_mxfp4_assay_evidence_at(
                vault,
                &candidate.slot,
                &candidate.lens,
                snapshot,
            )?);
            snapshot_lease.record_progress();
        }
        if let Some(canonical) = &canonical_rows {
            if !raw_corpus_rows_equal(canonical, &rows) {
                return Err(admission_error(format!(
                    "candidate slot {} raw source rows differ from the first candidate",
                    candidate.slot.slot_id.get()
                )));
            }
        } else {
            canonical_rows = Some(rows);
        }
    }
    let canonical_rows = canonical_rows.ok_or_else(|| {
        admission_error("compression candidate preflight did not retain a canonical corpus")
    })?;
    let (work_entries, work_aggregates) = derive_and_validate_v3_work(
        &preflight,
        u32::try_from(canonical_rows.len())
            .map_err(|_| admission_error("candidate row count exceeds u32"))?,
        request,
    )?;
    if work_entries.len() != preflight.len() {
        return Err(admission_error(
            "compression work planner returned the wrong candidate cardinality",
        ));
    }
    snapshot_lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(admission_error(
            "compression candidate preflight vault sequence changed before first mutation",
        ));
    }
    Ok(CandidatePreflight {
        candidates: preflight,
        canonical_rows,
        work_entries,
        work_aggregates,
    })
}

fn raw_corpus_rows_equal(left: &[(CxId, Vec<f32>)], right: &[(CxId, Vec<f32>)]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|((left_id, left_values), (right_id, right_values))| {
                left_id == right_id
                    && left_values.len() == right_values.len()
                    && left_values
                        .iter()
                        .zip(right_values)
                        .all(|(left, right)| left.to_bits() == right.to_bits())
            })
}

fn scan_preflight_candidate_rows<C: Clock>(
    vault: &AsterVault<C>,
    snapshot_lease: &RetainedSnapshot<'_>,
    slot: &Slot,
    request: &CompressionCandidateEvaluationRequest,
    held_out_query_ids: &BTreeSet<CxId>,
) -> Result<Vec<(CxId, Vec<f32>)>> {
    let snapshot = snapshot_lease.seq();
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(admission_error("compression candidate slot is not dense"));
    };
    let range = KeyRange {
        start: Vec::new(),
        end: None,
    };
    let mut after_key: Option<Vec<u8>> = None;
    let mut rows: Vec<(CxId, Vec<f32>)> = Vec::new();
    loop {
        let seen = u64::try_from(rows.len())
            .map_err(|_| admission_error("candidate preflight row count exceeds u64"))?;
        let remaining = request.work_limits.maximum_corpus_rows.saturating_sub(seen);
        let page_limit_u64 = remaining.saturating_add(1).min(PREFLIGHT_PAGE_ROWS as u64);
        let page_limit = usize::try_from(page_limit_u64)
            .map_err(|_| admission_error("candidate preflight page limit exceeds usize"))?;
        let page = vault.scan_cf_range_page_at(
            snapshot,
            ColumnFamily::slot(slot.slot_id),
            &range,
            after_key.as_deref(),
            page_limit,
        )?;
        snapshot_lease.record_progress();
        if page.is_empty() {
            break;
        }
        let next_after = page
            .last()
            .map(|(key, _)| key.clone())
            .ok_or_else(|| admission_error("nonempty preflight page has no final key"))?;
        if after_key
            .as_ref()
            .is_some_and(|previous| previous >= &next_after)
        {
            return Err(admission_error(
                "candidate preflight page did not advance in strict key order",
            ));
        }
        for (key, bytes) in page {
            let observed_rows = u64::try_from(rows.len())
                .map_err(|_| admission_error("candidate preflight row count exceeds u64"))?
                .checked_add(1)
                .ok_or_else(|| admission_error("candidate preflight row count overflow"))?;
            if observed_rows > request.work_limits.maximum_corpus_rows {
                return Err(admission_error(format!(
                    "candidate slot {} corpus rows exceed declared pre-execution limit: rows={observed_rows}/{}",
                    slot.slot_id.get(),
                    request.work_limits.maximum_corpus_rows
                )));
            }
            if bytes.first().copied() == Some(super::COMPRESSED_SLOT_TAG) {
                return Err(admission_error(format!(
                    "candidate slot {} primary row is already compressed",
                    slot.slot_id.get()
                )));
            }
            let cx_id = cx_id_from_key(&key)?;
            let SlotVector::Dense { dim, data } = encode::decode_slot_vector(&bytes)? else {
                return Err(admission_error(format!(
                    "candidate slot {} row {cx_id} is not dense",
                    slot.slot_id.get()
                )));
            };
            if dim != raw_dim || data.iter().any(|value| !value.is_finite()) {
                return Err(admission_error(format!(
                    "candidate slot {} row {cx_id} has invalid shape or non-finite coefficients",
                    slot.slot_id.get()
                )));
            }
            let canonical_source_bytes = encode::encode_slot_vector(&SlotVector::Dense {
                dim,
                data: data.clone(),
            })?;
            if canonical_source_bytes != bytes {
                return Err(admission_error(format!(
                    "candidate slot {} row {cx_id} is not the canonical dense source encoding required by the guarded rewrite",
                    slot.slot_id.get()
                )));
            }
            let base_bytes = vault
                .read_cf_at(snapshot, ColumnFamily::Base, &base_key(cx_id))?
                .ok_or_else(|| {
                    admission_error(format!(
                        "candidate slot {} source row {cx_id} has no immutable Base constellation at seq={snapshot}",
                        slot.slot_id.get()
                    ))
                })?;
            let base_identity = encode::decode_constellation_base_identity(&base_bytes)?;
            let observed_source_hash = blake3::hash(&bytes);
            let expected_source_hash = base_identity.slot_hashes.get(&slot.slot_id).ok_or_else(|| {
                admission_error(format!(
                    "candidate slot {} source row {cx_id} is absent from its immutable Base slot hashes at seq={snapshot}",
                    slot.slot_id.get()
                ))
            })?;
            if base_identity.cx_id != cx_id
                || observed_source_hash.as_bytes() != expected_source_hash
            {
                return Err(admission_error(format!(
                    "candidate slot {} source row {cx_id} does not match its immutable Base identity/hash at seq={snapshot}",
                    slot.slot_id.get()
                )));
            }
            snapshot_lease.record_progress();
            if held_out_query_ids.contains(&cx_id) {
                return Err(admission_error(format!(
                    "candidate slot {} held-out query {cx_id} is present in its source corpus",
                    slot.slot_id.get()
                )));
            }
            if rows
                .last()
                .is_some_and(|(previous, _)| previous.as_bytes() >= cx_id.as_bytes())
            {
                return Err(admission_error(format!(
                    "candidate slot {} source keys are not strictly canonical",
                    slot.slot_id.get()
                )));
            }
            rows.push((cx_id, data));
            snapshot_lease.record_progress();
        }
        after_key = Some(next_after);
    }
    let raw_sidecar = vault.scan_cf_range_page_at(
        snapshot,
        ColumnFamily::slot_raw(slot.slot_id),
        &range,
        None,
        1,
    )?;
    snapshot_lease.record_progress();
    if !raw_sidecar.is_empty() {
        return Err(admission_error(format!(
            "candidate slot {} already has a raw sidecar; commission requires a fresh raw Create source",
            slot.slot_id.get()
        )));
    }
    if rows.is_empty() {
        return Err(admission_error(format!(
            "candidate slot {} raw primary column is empty",
            slot.slot_id.get()
        )));
    }
    if u64::from(request.k)
        > u64::try_from(rows.len())
            .map_err(|_| admission_error("candidate preflight row count exceeds u64"))?
    {
        return Err(admission_error(format!(
            "candidate slot {} k={} exceeds {} source rows",
            slot.slot_id.get(),
            request.k,
            rows.len()
        )));
    }
    Ok(rows)
}

fn derive_and_validate_v3_work(
    candidates: &[PreflightCandidate],
    row_count: u32,
    request: &CompressionCandidateEvaluationRequest,
) -> Result<(Vec<CompressionCandidateWorkObservation>, WorkAggregates)> {
    let query_count = u64::try_from(request.queries.len())
        .map_err(|_| admission_error("held-out query count exceeds u64"))?;
    let lifecycle_query_runs = u64::from(request.warmup_runs)
        .checked_add(u64::from(request.measured_runs))
        .and_then(|runs| runs.checked_add(1))
        .ok_or_else(|| admission_error("candidate query-run count overflow"))?;
    let entries = candidates
        .iter()
        .map(|candidate| {
            derive_candidate_work_observation(
                candidate.slot.slot_id.get(),
                candidate.slot.quant,
                match candidate.slot.shape {
                    SlotShape::Dense(dim) => dim,
                    _ => return Err(admission_error("compression candidate slot is not dense")),
                },
                u32::try_from(candidate.descriptor.dim())
                    .map_err(|_| admission_error("candidate stored dimension exceeds u32"))?,
                row_count,
                query_count,
                lifecycle_query_runs,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    validate_candidate_work_entries(&entries, request)?;
    let aggregates = aggregate_candidate_work(&entries)?;
    validate_v3_aggregate_limits(&aggregates, &request.work_limits)?;
    Ok((entries, aggregates))
}

/// Materializes only the current candidate's receipt work around one shared
/// canonical roster/aggregate. The prior candidate's full receipt work drops
/// before the next candidate is built (#1064 PC-29/35).
fn materialize_candidate_work(
    candidate: &PreflightCandidate,
    canonical_rows: &[(CxId, Vec<f32>)],
    request: &CompressionCandidateEvaluationRequest,
    entries: &[CompressionCandidateWorkObservation],
    aggregates: &WorkAggregates,
) -> Result<CompressionWorkObservation> {
    let row_count = u32::try_from(canonical_rows.len())
        .map_err(|_| admission_error("candidate row count exceeds u32"))?;
    let raw_dim = match candidate.slot.shape {
        SlotShape::Dense(dim) => dim,
        _ => return Err(admission_error("compression candidate slot is not dense")),
    };
    let query_count = u64::try_from(request.queries.len())
        .map_err(|_| admission_error("held-out query count exceeds u64"))?;
    let mut work = derive_and_validate_work_counts(
        row_count,
        raw_dim,
        u32::try_from(candidate.descriptor.dim())
            .map_err(|_| admission_error("candidate stored dimension exceeds u32"))?,
        query_count,
        request.warmup_runs,
        request.measured_runs,
        &request.work_limits,
    )?;
    apply_v3_aggregate_work(&mut work, entries, aggregates)?;
    Ok(work)
}

#[derive(Clone, Copy)]
struct WorkAggregates {
    candidate_slots: u64,
    peak_codec_geometry_bytes: u64,
    retained_entry_and_sample_bound: u64,
    transform_visits: u64,
    auxiliary: u64,
    pairwise: u64,
    registry_coefficients: u64,
    accounted: u64,
}

fn derive_candidate_work_observation(
    slot_id: u16,
    quant_policy: QuantPolicy,
    raw_dim: u32,
    stored_dim: u32,
    row_count: u32,
    query_count: u64,
    lifecycle_query_runs: u64,
) -> Result<CompressionCandidateWorkObservation> {
    let rows = u64::from(row_count);
    let stored = u64::from(stored_dim);
    let raw = u64::from(raw_dim);
    let encode_calls = rows;
    let decode_calls = rows;
    let query_prepare_calls = checked_work_mul(
        lifecycle_query_runs,
        query_count,
        "candidate query-prepare calls",
    )?;
    let packed_score_calls =
        checked_work_mul(query_prepare_calls, rows, "candidate packed-score calls")?;
    let pairwise_score_evaluations = checked_work_mul(
        checked_work_add(lifecycle_query_runs, 2, "candidate pairwise run factor")?,
        checked_work_mul(query_count, rows, "candidate query-row pairs")?,
        "candidate pairwise scores",
    )?;
    let exact_registry_coefficients = checked_work_mul(
        2,
        checked_work_mul(
            checked_work_mul(query_count, rows, "candidate exact query-row pairs")?,
            raw,
            "candidate exact raw coefficients",
        )?,
        "candidate build/evaluation exact coefficients",
    )?;
    let reconstruction_coefficients = checked_work_mul(
        rows,
        checked_work_add(raw, stored, "candidate reconstruction dimensions")?,
        "candidate reconstruction coefficients",
    )?;
    let registry_coefficient_evaluations = checked_work_add(
        exact_registry_coefficients,
        reconstruction_coefficients,
        "candidate Registry coefficients",
    )?;

    let (geometry_physical_bytes, retained_entry_and_sample_bound, transform_visits, auxiliary) =
        match quant_policy {
            QuantPolicy::TurboQuant {
                bits_per_channel_x2,
            }
            | QuantPolicy::TurboQuantHadamard {
                bits_per_channel_x2,
            } => {
                let level = turboquant_level(bits_per_channel_x2)?;
                let geometry_kind = match quant_policy {
                    QuantPolicy::TurboQuant { .. } => TurboQuantGeometryKind::DenseHaarGaussianV2,
                    QuantPolicy::TurboQuantHadamard { .. } => {
                        TurboQuantGeometryKind::StructuredHadamardV1
                    }
                    _ => unreachable!("TurboQuant match is exhaustive"),
                };
                let shape = turboquant_work_shape(stored_dim as usize, level, geometry_kind)
                    .map_err(forge_work_error)?;
                let retained_entry_and_sample_bound = checked_work_add(
                    shape.geometry_retained_entries,
                    shape.codebook_setup_sample_evaluations,
                    "TurboQuant retained-entry/sample bound",
                )?;
                let transform_calls = checked_work_add(
                    checked_work_add(encode_calls, decode_calls, "TurboQuant row transforms")?,
                    query_prepare_calls,
                    "TurboQuant total transforms",
                )?;
                let transform_visits = checked_work_mul(
                    transform_calls,
                    shape.transform_pair_coefficient_visits,
                    "TurboQuant transform coefficient visits",
                )?;
                let encode_auxiliary = checked_work_mul(
                    encode_calls,
                    shape.encode_scalar_centroid_visits,
                    "TurboQuant encode centroid visits",
                )?;
                let decode_auxiliary = checked_work_mul(
                    decode_calls,
                    shape.decode_scalar_centroid_lookups,
                    "TurboQuant decode centroid lookups",
                )?;
                let query_auxiliary = checked_work_mul(
                    query_prepare_calls,
                    checked_work_add(
                        shape.query_lut_allocated_entries,
                        shape.query_lut_filled_entries,
                        "TurboQuant query LUT work",
                    )?,
                    "TurboQuant aggregate query LUT work",
                )?;
                let score_auxiliary = checked_work_mul(
                    packed_score_calls,
                    shape.packed_score_coefficient_visits,
                    "TurboQuant packed score visits",
                )?;
                let auxiliary = checked_work_add(
                    checked_work_add(
                        encode_auxiliary,
                        decode_auxiliary,
                        "TurboQuant encode/decode auxiliary work",
                    )?,
                    checked_work_add(
                        query_auxiliary,
                        score_auxiliary,
                        "TurboQuant query/score auxiliary work",
                    )?,
                    "TurboQuant auxiliary work",
                )?;
                (
                    shape.geometry_physical_bytes,
                    retained_entry_and_sample_bound,
                    transform_visits,
                    auxiliary,
                )
            }
            QuantPolicy::Binary => {
                let shape = binary_work_shape(stored_dim as usize).map_err(forge_work_error)?;
                let transform_visits = checked_work_add(
                    checked_work_add(
                        checked_work_mul(
                            encode_calls,
                            shape.encode_transform_coefficient_visits,
                            "binary encode transform visits",
                        )?,
                        checked_work_mul(
                            decode_calls,
                            shape.decode_transform_coefficient_visits,
                            "binary decode transform visits",
                        )?,
                        "binary row transform visits",
                    )?,
                    checked_work_mul(
                        query_prepare_calls,
                        shape.query_prepare_transform_coefficient_visits,
                        "binary query transform visits",
                    )?,
                    "binary aggregate transform visits",
                )?;
                let auxiliary = checked_work_mul(
                    packed_score_calls,
                    shape.packed_score_coefficient_visits,
                    "binary packed score visits",
                )?;
                (
                    shape.geometry_physical_bytes,
                    shape.geometry_retained_entries,
                    transform_visits,
                    auxiliary,
                )
            }
            QuantPolicy::ScalarInt8 => (
                0,
                0,
                0,
                checked_work_mul(
                    checked_work_mul(3, packed_score_calls, "ScalarInt8 score passes")?,
                    stored,
                    "ScalarInt8 score coefficient work",
                )?,
            ),
            QuantPolicy::None | QuantPolicy::MxFp4 | QuantPolicy::Float8 => (
                0,
                0,
                0,
                checked_work_mul(packed_score_calls, stored, "linear codec packed score work")?,
            ),
            QuantPolicy::Pq { m, nbits } => {
                return Err(admission_error(format!(
                    "PQ codec is not implemented for work planning: m={m} nbits={nbits}"
                )));
            }
            QuantPolicy::ColbertResidual2Bit => {
                return Err(admission_error(
                    "ColbertResidual2Bit is not a dense compression candidate",
                ));
            }
        };
    let accounted_work_units = checked_work_sum(
        [
            retained_entry_and_sample_bound,
            transform_visits,
            auxiliary,
            pairwise_score_evaluations,
            registry_coefficient_evaluations,
        ],
        "candidate accounted work",
    )?;
    Ok(CompressionCandidateWorkObservation {
        slot_id,
        quant_policy,
        raw_dim,
        stored_dim,
        corpus_rows: rows,
        geometry_physical_bytes,
        codec_retained_entry_and_sample_bound: retained_entry_and_sample_bound,
        encode_calls,
        decode_calls,
        query_prepare_calls,
        packed_score_calls,
        codec_transform_coefficient_visits: transform_visits,
        codec_auxiliary_work_units: auxiliary,
        pairwise_score_evaluations,
        registry_coefficient_evaluations,
        accounted_work_units,
    })
}

fn validate_codec_work_shape(policy: QuantPolicy, stored_dim: usize) -> Result<()> {
    match policy {
        QuantPolicy::TurboQuant {
            bits_per_channel_x2,
        }
        | QuantPolicy::TurboQuantHadamard {
            bits_per_channel_x2,
        } => {
            let level = turboquant_level(bits_per_channel_x2)?;
            if stored_dim > TURBOQUANT_MAX_DIM {
                return Err(forge_work_error(calyx_forge::ForgeError::QuantError {
                    op: "turboquant_new".to_string(),
                    level: level.to_string(),
                    detail: format!(
                        "dimension must be in 1..={TURBOQUANT_MAX_DIM}, got {stored_dim}"
                    ),
                    remediation:
                        "Use a supported TurboQuant dimension and re-commission the candidate"
                            .to_string(),
                }));
            }
            // Preserve Forge's public construction-domain refusal identity for
            // unsupported D before admission planning; the immediately
            // following minimum-work derivation performs the one planner call.
            Ok(())
        }
        QuantPolicy::Binary
        | QuantPolicy::None
        | QuantPolicy::ScalarInt8
        | QuantPolicy::MxFp4
        | QuantPolicy::Float8 => Ok(()),
        QuantPolicy::Pq { m, nbits } => Err(admission_error(format!(
            "PQ codec is not implemented for work planning: m={m} nbits={nbits}"
        ))),
        QuantPolicy::ColbertResidual2Bit => Err(admission_error(
            "ColbertResidual2Bit is not a dense compression candidate",
        )),
    }
}

fn aggregate_candidate_work<'a>(
    entries: impl IntoIterator<Item = &'a CompressionCandidateWorkObservation>,
) -> Result<WorkAggregates> {
    let mut aggregates = WorkAggregates {
        candidate_slots: 0,
        peak_codec_geometry_bytes: 0,
        retained_entry_and_sample_bound: 0,
        transform_visits: 0,
        auxiliary: 0,
        pairwise: 0,
        registry_coefficients: 0,
        accounted: 0,
    };
    for entry in entries {
        aggregates.candidate_slots = aggregates
            .candidate_slots
            .checked_add(1)
            .ok_or_else(|| admission_error("candidate work cardinality exceeds u64"))?;
        aggregates.peak_codec_geometry_bytes = aggregates
            .peak_codec_geometry_bytes
            .max(entry.geometry_physical_bytes);
        aggregates.retained_entry_and_sample_bound = checked_work_add(
            aggregates.retained_entry_and_sample_bound,
            entry.codec_retained_entry_and_sample_bound,
            "aggregate codec retained-entry/sample bound",
        )?;
        aggregates.transform_visits = checked_work_add(
            aggregates.transform_visits,
            entry.codec_transform_coefficient_visits,
            "aggregate transform visits",
        )?;
        aggregates.auxiliary = checked_work_add(
            aggregates.auxiliary,
            entry.codec_auxiliary_work_units,
            "aggregate codec auxiliary work",
        )?;
        aggregates.pairwise = checked_work_add(
            aggregates.pairwise,
            entry.pairwise_score_evaluations,
            "aggregate pairwise scores",
        )?;
        aggregates.registry_coefficients = checked_work_add(
            aggregates.registry_coefficients,
            entry.registry_coefficient_evaluations,
            "aggregate Registry coefficients",
        )?;
        aggregates.accounted = checked_work_add(
            aggregates.accounted,
            entry.accounted_work_units,
            "aggregate accounted work",
        )?;
    }
    Ok(aggregates)
}

fn apply_v3_aggregate_work(
    work: &mut CompressionWorkObservation,
    entries: &[CompressionCandidateWorkObservation],
    aggregates: &WorkAggregates,
) -> Result<()> {
    work.work_model = WORK_MODEL.to_string();
    work.candidate_slots = aggregates.candidate_slots;
    work.candidate_work = entries.to_vec();
    work.peak_codec_geometry_bytes = aggregates.peak_codec_geometry_bytes;
    work.aggregate_codec_retained_entry_and_sample_bound =
        aggregates.retained_entry_and_sample_bound;
    work.aggregate_codec_transform_coefficient_visits = aggregates.transform_visits;
    work.aggregate_codec_auxiliary_work_units = aggregates.auxiliary;
    work.aggregate_pairwise_score_evaluations = aggregates.pairwise;
    work.aggregate_registry_coefficient_evaluations = aggregates.registry_coefficients;
    work.total_accounted_work_units = aggregates.accounted;
    Ok(())
}

fn validate_candidate_work_entries(
    entries: &[CompressionCandidateWorkObservation],
    request: &CompressionCandidateEvaluationRequest,
) -> Result<()> {
    if entries.is_empty() {
        return Err(admission_error(
            "compression candidate work vector is empty",
        ));
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].slot_id >= pair[1].slot_id)
    {
        return Err(admission_error(
            "compression candidate work vector is not in strict slot-id order",
        ));
    }
    let query_count = u64::try_from(request.queries.len())
        .map_err(|_| admission_error("held-out query count exceeds u64"))?;
    let lifecycle_query_runs = u64::from(request.warmup_runs)
        .checked_add(u64::from(request.measured_runs))
        .and_then(|runs| runs.checked_add(1))
        .ok_or_else(|| admission_error("candidate query-run count overflow"))?;
    let first = entries
        .first()
        .ok_or_else(|| admission_error("compression candidate work vector is empty"))?;
    for entry in entries {
        if entry.corpus_rows != first.corpus_rows || entry.raw_dim != first.raw_dim {
            return Err(admission_error(
                "compression candidate work vector does not share one canonical raw corpus shape",
            ));
        }
        let expected = derive_candidate_work_observation(
            entry.slot_id,
            entry.quant_policy,
            entry.raw_dim,
            entry.stored_dim,
            u32::try_from(entry.corpus_rows)
                .map_err(|_| admission_error("candidate work corpus rows exceed u32"))?,
            query_count,
            lifecycle_query_runs,
        )?;
        if &expected != entry {
            return Err(admission_error(format!(
                "compression candidate work arithmetic is inconsistent for slot {}",
                entry.slot_id
            )));
        }
    }
    Ok(())
}

fn validate_v3_work_observation(
    work: &CompressionWorkObservation,
    request: &CompressionCandidateEvaluationRequest,
) -> Result<WorkAggregates> {
    validate_candidate_evaluation_request_shape(request)?;
    if work.work_model != WORK_MODEL {
        return Err(admission_error(format!(
            "compression work model is {}; expected {WORK_MODEL}",
            work.work_model
        )));
    }
    validate_candidate_work_entries(&work.candidate_work, request)?;
    let aggregates = aggregate_candidate_work(&work.candidate_work)?;
    if work.candidate_slots != aggregates.candidate_slots
        || work.peak_codec_geometry_bytes != aggregates.peak_codec_geometry_bytes
        || work.aggregate_codec_retained_entry_and_sample_bound
            != aggregates.retained_entry_and_sample_bound
        || work.aggregate_codec_transform_coefficient_visits != aggregates.transform_visits
        || work.aggregate_codec_auxiliary_work_units != aggregates.auxiliary
        || work.aggregate_pairwise_score_evaluations != aggregates.pairwise
        || work.aggregate_registry_coefficient_evaluations != aggregates.registry_coefficients
        || work.total_accounted_work_units != aggregates.accounted
    {
        return Err(admission_error(
            "compression aggregate work fields do not equal the canonical candidate vector",
        ));
    }
    validate_v3_aggregate_limits(&aggregates, &request.work_limits)?;
    Ok(aggregates)
}

fn validate_planned_work_for_generation(
    work: &CompressionWorkObservation,
    generation: &CompressedGenerationIdentity,
    slot: &Slot,
    request: &CompressionAdmissionRequest,
    live_codec_geometry_physical_bytes: u64,
) -> Result<()> {
    let candidate_request = CompressionCandidateEvaluationRequest {
        requested_backend: request.requested_backend,
        queries: request.queries.clone(),
        k: request.k,
        warmup_runs: request.warmup_runs,
        measured_runs: request.measured_runs,
        work_limits: request.work_limits.clone(),
        gates: request.gates.clone(),
    };
    validate_v3_work_observation(work, &candidate_request)?;
    let current = work
        .candidate_work
        .iter()
        .find(|candidate| candidate.slot_id == slot.slot_id.get())
        .ok_or_else(|| {
            admission_error(format!(
                "compression work vector omits active candidate slot {}",
                slot.slot_id.get()
            ))
        })?;
    if current.quant_policy != slot.quant
        || current.raw_dim != generation.raw_dim
        || current.stored_dim != generation.stored_dim
        || current.corpus_rows != u64::from(generation.row_count)
    {
        return Err(admission_error(
            "compression work vector does not bind the active manifested generation",
        ));
    }
    if current.geometry_physical_bytes != live_codec_geometry_physical_bytes {
        return Err(admission_error(format!(
            "live codec geometry physical-byte readback differs from the allocation-free v3 plan: slot={} planned={} live={live_codec_geometry_physical_bytes}",
            slot.slot_id.get(),
            current.geometry_physical_bytes,
        )));
    }
    let expected_legacy = derive_and_validate_work(generation, request)?;
    if !legacy_work_fields_equal(work, &expected_legacy) {
        return Err(admission_error(
            "compression local evaluation work does not match the active generation",
        ));
    }
    Ok(())
}

fn validate_v3_work_limits(limits: &CompressionAdmissionWorkLimits) -> Result<()> {
    for (field, value) in [
        ("maximum_corpus_rows", limits.maximum_corpus_rows),
        ("maximum_held_out_queries", limits.maximum_held_out_queries),
        (
            "maximum_total_packed_searches",
            limits.maximum_total_packed_searches,
        ),
        (
            "maximum_pairwise_score_evaluations",
            limits.maximum_pairwise_score_evaluations,
        ),
        (
            "maximum_coefficient_evaluations",
            limits.maximum_coefficient_evaluations,
        ),
        ("maximum_candidate_slots", limits.maximum_candidate_slots),
        (
            "maximum_peak_codec_geometry_bytes",
            limits.maximum_peak_codec_geometry_bytes,
        ),
        (
            "maximum_aggregate_codec_retained_entry_and_sample_bound",
            limits.maximum_aggregate_codec_retained_entry_and_sample_bound,
        ),
        (
            "maximum_aggregate_codec_transform_coefficient_visits",
            limits.maximum_aggregate_codec_transform_coefficient_visits,
        ),
        (
            "maximum_aggregate_pairwise_score_evaluations",
            limits.maximum_aggregate_pairwise_score_evaluations,
        ),
        (
            "maximum_total_accounted_work_units",
            limits.maximum_total_accounted_work_units,
        ),
    ] {
        if value == 0 {
            return Err(admission_error(format!(
                "compression admission v3 pre-execution work limit {field} must be nonzero"
            )));
        }
    }
    Ok(())
}

fn has_v3_work_limits(limits: &CompressionAdmissionWorkLimits) -> bool {
    limits.maximum_candidate_slots != 0
        || limits.maximum_peak_codec_geometry_bytes != 0
        || limits.maximum_aggregate_codec_retained_entry_and_sample_bound != 0
        || limits.maximum_aggregate_codec_transform_coefficient_visits != 0
        || limits.maximum_aggregate_pairwise_score_evaluations != 0
        || limits.maximum_total_accounted_work_units != 0
}

const fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

fn validate_v3_aggregate_limits(
    aggregates: &WorkAggregates,
    limits: &CompressionAdmissionWorkLimits,
) -> Result<()> {
    if aggregates.candidate_slots > limits.maximum_candidate_slots
        || aggregates.peak_codec_geometry_bytes > limits.maximum_peak_codec_geometry_bytes
        || aggregates.retained_entry_and_sample_bound
            > limits.maximum_aggregate_codec_retained_entry_and_sample_bound
        || aggregates.transform_visits > limits.maximum_aggregate_codec_transform_coefficient_visits
        || aggregates.pairwise > limits.maximum_aggregate_pairwise_score_evaluations
        || aggregates.accounted > limits.maximum_total_accounted_work_units
    {
        return Err(admission_error(format!(
            "compression admission aggregate work exceeds declared pre-execution limits: candidate_slots={}/{} peak_codec_geometry_bytes={}/{} aggregate_codec_retained_entry_and_sample_bound={}/{} aggregate_codec_transform_coefficient_visits={}/{} aggregate_codec_auxiliary_work_units={} aggregate_pairwise_score_evaluations={}/{} aggregate_registry_coefficient_evaluations={} total_accounted_work_units={}/{}",
            aggregates.candidate_slots,
            limits.maximum_candidate_slots,
            aggregates.peak_codec_geometry_bytes,
            limits.maximum_peak_codec_geometry_bytes,
            aggregates.retained_entry_and_sample_bound,
            limits.maximum_aggregate_codec_retained_entry_and_sample_bound,
            aggregates.transform_visits,
            limits.maximum_aggregate_codec_transform_coefficient_visits,
            aggregates.auxiliary,
            aggregates.pairwise,
            limits.maximum_aggregate_pairwise_score_evaluations,
            aggregates.registry_coefficients,
            aggregates.accounted,
            limits.maximum_total_accounted_work_units,
        )));
    }
    Ok(())
}

fn validate_v3_minimum_aggregate_limits(
    minimum: &WorkAggregates,
    limits: &CompressionAdmissionWorkLimits,
) -> Result<()> {
    if minimum.candidate_slots > limits.maximum_candidate_slots
        || minimum.peak_codec_geometry_bytes > limits.maximum_peak_codec_geometry_bytes
        || minimum.retained_entry_and_sample_bound
            > limits.maximum_aggregate_codec_retained_entry_and_sample_bound
        || minimum.transform_visits > limits.maximum_aggregate_codec_transform_coefficient_visits
        || minimum.pairwise > limits.maximum_aggregate_pairwise_score_evaluations
        || minimum.accounted > limits.maximum_total_accounted_work_units
    {
        return Err(admission_error(format!(
            "compression admission work is impossible at the minimum one-row corpus before source scan: candidate_slots={}/{} peak_codec_geometry_bytes={}/{} aggregate_codec_retained_entry_and_sample_bound={}/{} minimum_aggregate_codec_transform_coefficient_visits={}/{} minimum_aggregate_pairwise_score_evaluations={}/{} minimum_total_accounted_work_units={}/{}",
            minimum.candidate_slots,
            limits.maximum_candidate_slots,
            minimum.peak_codec_geometry_bytes,
            limits.maximum_peak_codec_geometry_bytes,
            minimum.retained_entry_and_sample_bound,
            limits.maximum_aggregate_codec_retained_entry_and_sample_bound,
            minimum.transform_visits,
            limits.maximum_aggregate_codec_transform_coefficient_visits,
            minimum.pairwise,
            limits.maximum_aggregate_pairwise_score_evaluations,
            minimum.accounted,
            limits.maximum_total_accounted_work_units,
        )));
    }
    Ok(())
}

fn legacy_work_fields_equal(
    left: &CompressionWorkObservation,
    right: &CompressionWorkObservation,
) -> bool {
    left.corpus_rows == right.corpus_rows
        && left.held_out_queries == right.held_out_queries
        && left.warmup_packed_searches == right.warmup_packed_searches
        && left.measured_packed_searches == right.measured_packed_searches
        && left.exact_truth_pairwise_scores == right.exact_truth_pairwise_scores
        && left.packed_pairwise_scores == right.packed_pairwise_scores
        && left.reconstruction_rows == right.reconstruction_rows
        && left.coefficient_evaluations == right.coefficient_evaluations
}

fn turboquant_level(bits_per_channel_x2: u8) -> Result<QuantLevel> {
    match bits_per_channel_x2 {
        5 => Ok(QuantLevel::Bits2p5),
        7 => Ok(QuantLevel::Bits3p5),
        other => Err(admission_error(format!(
            "unsupported TurboQuant bits_per_channel_x2 {other}; expected 5 or 7"
        ))),
    }
}

fn checked_work_add(left: u64, right: u64, field: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| admission_error(format!("{field} overflow")))
}

fn checked_work_mul(left: u64, right: u64, field: &str) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(|| admission_error(format!("{field} overflow")))
}

fn checked_work_sum<const N: usize>(values: [u64; N], field: &str) -> Result<u64> {
    values
        .into_iter()
        .try_fold(0_u64, |total, value| checked_work_add(total, value, field))
}

fn forge_work_error(error: calyx_forge::ForgeError) -> calyx_core::CalyxError {
    calyx_core::CalyxError {
        code: error.code(),
        message: error.to_string(),
        remediation: super::COMPRESSION_REMEDIATION,
    }
}

/// Selects exactly one admitted candidate from separately persisted candidate
/// slots. Candidate receipts are re-opened from Aster, cohort invariants are
/// compared exactly, and the winner uses rational physical bits per original
/// source value. The selected receipt is persisted and read back before any
/// current pointer moves; the complete source set is then independently read
/// and recomputed a second time before winner publication. V3 replay publishes
/// only the exact full cohort vector persisted by a common commission. Each
/// pass streams one receipt at a time, retaining only the current winner's full
/// receipt plus fixed identity/selection records; the first pass drops before
/// the independent second pass and the second drops before pointer publication
/// (#1064 PC-29/35).
pub(crate) fn select_compression_candidate<'a, C, F>(
    vault: &AsterVault<C>,
    candidates: &[CompressionCandidateReference],
    mut resolve_lens: F,
) -> Result<CompressionAdmissionReadback>
where
    C: Clock,
    F: FnMut(&Slot) -> Result<&'a LensSpec>,
{
    let first_read = load_candidate_set(vault, candidates, &mut resolve_lens)?;
    let LoadedCandidateSet {
        references: validated_references,
        selection,
        winner_reference,
        winner_receipt,
    } = first_read;
    let winner_slot = winner_reference.slot.clone();
    let winner_lens = resolve_lens(&winner_slot)?;
    let mut selected_receipt = winner_receipt;
    selected_receipt.candidate_selection = Some(selection.clone());

    let mut prior_current = BTreeMap::new();
    let prior_pointer_lease = vault.retain_latest_snapshot();
    let before_seq = prior_pointer_lease.seq();
    for candidate in &validated_references {
        prior_current.insert(
            candidate.slot.slot_id.get(),
            read_pointer_digest(
                vault,
                &candidate.slot,
                before_seq,
                &compression_admission_pointer_key(candidate.slot.slot_id),
                "current-admission",
            )?,
        );
        prior_pointer_lease.record_progress();
    }
    if vault.latest_seq() != before_seq {
        return Err(admission_error(
            "compression candidate current-pointer sequence changed during pre-selection readback",
        ));
    }
    drop(prior_pointer_lease);

    let selection_readback =
        persist_evaluation_receipt(vault, &winner_slot, winner_lens, selected_receipt)?;
    let selected_sha256 = decode_hex_32(
        &selection_readback.receipt_sha256,
        "selected admission receipt SHA-256",
    )?;
    let post_receipt_pointer_lease = vault.retain_latest_snapshot();
    let post_receipt_seq = post_receipt_pointer_lease.seq();
    for candidate in &validated_references {
        let observed = read_pointer_digest(
            vault,
            &candidate.slot,
            post_receipt_seq,
            &compression_admission_pointer_key(candidate.slot.slot_id),
            "current-admission",
        )?;
        if observed
            != prior_current
                .get(&candidate.slot.slot_id.get())
                .copied()
                .flatten()
        {
            return Err(admission_error(format!(
                "candidate-selection receipt publication changed slot {} current pointer before independent candidate-set readback",
                candidate.slot.slot_id.get()
            )));
        }
        post_receipt_pointer_lease.record_progress();
    }
    if vault.latest_seq() != post_receipt_seq {
        return Err(admission_error(
            "compression candidate current-pointer sequence changed during post-receipt readback",
        ));
    }
    drop(post_receipt_pointer_lease);

    let second_read = load_candidate_set(vault, &validated_references, &mut resolve_lens)?;
    if second_read.selection != selection
        || second_read.winner_reference.slot != winner_slot
        || second_read.winner_reference.receipt_sha256 != winner_reference.receipt_sha256
        || selection_readback.receipt.candidate_selection.as_ref() != Some(&selection)
    {
        return Err(admission_error(
            "persisted compression candidate selection differs from independent source-receipt recomputation",
        ));
    }
    drop(second_read);

    publish_selected_receipt(
        vault,
        &winner_slot,
        winner_lens,
        selected_sha256,
        &selection_readback.receipt,
        selection_readback.receipt_commit_seq,
        selection_readback.receipt_ledger,
        &validated_references,
        &prior_current,
    )
}

fn load_candidate_set<'a, C, F>(
    vault: &AsterVault<C>,
    candidates: &[CompressionCandidateReference],
    resolve_lens: &mut F,
) -> Result<LoadedCandidateSet>
where
    C: Clock,
    F: FnMut(&Slot) -> Result<&'a LensSpec>,
{
    const SLOT_ID_DOMAIN_CARDINALITY: usize = u16::MAX as usize + 1;
    if candidates.len() < 2 || candidates.len() > SLOT_ID_DOMAIN_CARDINALITY {
        return Err(admission_error(
            "compression candidate selection requires between two and 65,536 separately persisted candidate slots; single-candidate publication is not selection and cardinality cannot exceed the SlotId domain",
        ));
    }
    let mut unique_slot_ids = BTreeSet::new();
    if candidates
        .iter()
        .any(|candidate| !unique_slot_ids.insert(candidate.slot.slot_id.get()))
    {
        return Err(admission_error(
            "compression candidate selection requires unique separate slot ids",
        ));
    }
    let mut canonical = candidates.to_vec();
    canonical.sort_by(|left, right| {
        left.slot
            .slot_id
            .get()
            .cmp(&right.slot.slot_id.get())
            .then_with(|| left.slot.slot_key.key().cmp(right.slot.slot_key.key()))
            .then_with(|| left.receipt_sha256.cmp(&right.receipt_sha256))
    });
    let snapshot_lease = vault.retain_latest_snapshot();
    let snapshot = snapshot_lease.seq();
    let mut cohort: Option<CandidateCohortIdentity> = None;
    let mut entries = Vec::with_capacity(canonical.len());
    let mut retained_winner: Option<(
        usize,
        CompressionCandidateReference,
        CompressionAdmissionReceipt,
    )> = None;
    for reference in &canonical {
        let receipt = read_receipt_at(vault, &reference.slot, snapshot, reference.receipt_sha256)?;
        if receipt.schema != COMPRESSION_ADMISSION_SCHEMA || receipt.work.work_model != WORK_MODEL {
            return Err(admission_error(format!(
                "candidate slot {} receipt {} uses legacy admission work and cannot enter v3 selection; re-evaluate every candidate under {}",
                reference.slot.slot_id.get(),
                hex(&reference.receipt_sha256),
                COMPRESSION_ADMISSION_SCHEMA
            )));
        }
        if receipt.candidate_selection.is_some() {
            return Err(admission_error(format!(
                "slot {} receipt {} is already a selection receipt and cannot recursively enter a candidate set",
                reference.slot.slot_id.get(),
                hex(&reference.receipt_sha256)
            )));
        }
        let generation = generation_identity_without_codec_at(
            vault,
            &reference.slot,
            resolve_lens(&reference.slot)?,
            snapshot,
        )?;
        validate_active_generation_at(vault, &receipt, &reference.slot, &generation, snapshot)?;
        let identity = CandidateCohortIdentity::from_receipt(&receipt)?;
        if let Some(expected) = &cohort {
            if &identity != expected {
                return Err(admission_error(format!(
                    "compression candidate slot {} does not share the exact source/raw shape/corpus/query-digest/truth/metric/k/backend/protocol/work-limit/gate cohort",
                    receipt.slot_id
                )));
            }
        } else {
            validate_candidate_roster(&canonical, &receipt)?;
            cohort = Some(identity);
        }

        let entry = candidate_selection_entry(reference, &receipt);
        let index = entries.len();
        let becomes_winner = if entry.verdict == CompressionAdmissionVerdict::Admitted {
            match retained_winner.as_ref() {
                Some((prior, _, _)) => candidate_entry_precedes(&entry, &entries[*prior])?,
                None => true,
            }
        } else {
            false
        };
        if becomes_winner {
            retained_winner = Some((index, reference.clone(), receipt));
        }
        entries.push(entry);
        snapshot_lease.record_progress();
    }
    snapshot_lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(admission_error(
            "compression candidate-set vault sequence changed during immutable replay",
        ));
    }
    let (selection, winner_index) = build_candidate_selection(entries)?;
    let (retained_index, winner_reference, winner_receipt) = retained_winner.ok_or_else(|| {
        admission_error("compression candidate set contains no gate-admitted candidate")
    })?;
    if retained_index != winner_index {
        return Err(admission_error(
            "streamed compression winner differs from canonical candidate-set selection",
        ));
    }
    Ok(LoadedCandidateSet {
        references: canonical,
        selection,
        winner_reference,
        winner_receipt,
    })
}

fn validate_candidate_roster(
    references: &[CompressionCandidateReference],
    receipt: &CompressionAdmissionReceipt,
) -> Result<()> {
    if receipt.work.candidate_work.len() != references.len() {
        return Err(admission_error(format!(
            "compression candidate references do not contain the complete v3 work roster: references={} roster={}",
            references.len(),
            receipt.work.candidate_work.len()
        )));
    }
    for (reference, planned) in references.iter().zip(&receipt.work.candidate_work) {
        let raw_dim = match reference.slot.shape {
            SlotShape::Dense(dim) => dim,
            _ => {
                return Err(admission_error(format!(
                    "compression candidate slot {} is not dense",
                    reference.slot.slot_id.get()
                )));
            }
        };
        if reference.slot.slot_id.get() != planned.slot_id
            || reference.slot.quant != planned.quant_policy
            || raw_dim != planned.raw_dim
        {
            return Err(admission_error(format!(
                "compression candidate references do not exactly match v3 work roster entry for slot {}",
                reference.slot.slot_id.get()
            )));
        }
    }
    Ok(())
}

fn candidate_selection_entry(
    reference: &CompressionCandidateReference,
    receipt: &CompressionAdmissionReceipt,
) -> CompressionCandidateSelectionEntry {
    CompressionCandidateSelectionEntry {
        slot_id: receipt.slot_id,
        slot_key: receipt.slot_key.clone(),
        receipt_sha256: hex(&reference.receipt_sha256),
        generation_seq: receipt.generation_seq,
        codec: receipt.codec,
        level: receipt.level.clone(),
        verdict: receipt.verdict,
        total_physical_bytes: receipt.total_physical_bytes,
        logical_values: receipt.logical_values,
        effective_bits_per_value: receipt.effective_bits_per_value,
        build_elapsed_ns: receipt.build.elapsed_ns,
    }
}

fn build_candidate_selection(
    entries: Vec<CompressionCandidateSelectionEntry>,
) -> Result<(CompressionCandidateSelectionReceipt, usize)> {
    let winner_index = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.verdict == CompressionAdmissionVerdict::Admitted)
        .try_fold(None, |winner: Option<usize>, (index, entry)| {
            let Some(prior) = winner else {
                return Ok::<_, calyx_core::CalyxError>(Some(index));
            };
            if candidate_entry_precedes(entry, &entries[prior])? {
                Ok(Some(index))
            } else {
                Ok(Some(prior))
            }
        })?
        .ok_or_else(|| {
            admission_error("compression candidate set contains no gate-admitted candidate")
        })?;
    let candidate_set_sha256 = candidate_set_digest(&entries)?;
    let winner_slot_id = entries[winner_index].slot_id;
    let winner_receipt_sha256 = entries[winner_index].receipt_sha256.clone();
    Ok((
        CompressionCandidateSelectionReceipt {
            schema: COMPRESSION_CANDIDATE_SELECTION_SCHEMA.to_string(),
            protocol: SELECTION_PROTOCOL.to_string(),
            candidate_set_sha256: hex(&candidate_set_sha256),
            candidates: entries,
            winner_slot_id,
            winner_receipt_sha256,
            ordering: "minimum exact total_physical_bytes*8/logical_source_values; ties by codec rank, level bytes, slot id, receipt SHA-256".to_string(),
        },
        winner_index,
    ))
}

fn candidate_entry_precedes(
    left: &CompressionCandidateSelectionEntry,
    right: &CompressionCandidateSelectionEntry,
) -> Result<bool> {
    let left_bits = u128::from(left.total_physical_bytes)
        .checked_mul(8)
        .and_then(|value| value.checked_mul(u128::from(right.logical_values)))
        .ok_or_else(|| admission_error("candidate physical-ratio comparison overflow"))?;
    let right_bits = u128::from(right.total_physical_bytes)
        .checked_mul(8)
        .and_then(|value| value.checked_mul(u128::from(left.logical_values)))
        .ok_or_else(|| admission_error("candidate physical-ratio comparison overflow"))?;
    if left_bits != right_bits {
        return Ok(left_bits < right_bits);
    }
    Ok(candidate_codec_rank(left.codec)
        .cmp(&candidate_codec_rank(right.codec))
        .then_with(|| left.level.as_bytes().cmp(right.level.as_bytes()))
        .then_with(|| left.slot_id.cmp(&right.slot_id))
        .then_with(|| left.receipt_sha256.cmp(&right.receipt_sha256))
        .is_lt())
}

fn candidate_codec_rank(codec: StoredSlotCodec) -> u8 {
    match codec {
        StoredSlotCodec::TurboQuantBits2p5 => 0,
        StoredSlotCodec::TurboQuantBits3p5 => 1,
        StoredSlotCodec::Binary => 2,
        StoredSlotCodec::MxFp4 => 3,
        StoredSlotCodec::ScalarInt8 => 4,
        StoredSlotCodec::MxFp8 => 5,
        StoredSlotCodec::RawF32 => 6,
    }
}

fn candidate_set_digest(entries: &[CompressionCandidateSelectionEntry]) -> Result<[u8; 32]> {
    let canonical = serde_json::to_vec(entries)
        .map_err(|error| admission_error(format!("encode candidate set: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-candidate-set-v1");
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn publish_selected_receipt<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    receipt_sha256: [u8; 32],
    expected_receipt: &CompressionAdmissionReceipt,
    receipt_commit_seq: Option<Seq>,
    receipt_ledger: Option<LedgerRef>,
    candidates: &[CompressionCandidateReference],
    prior_current: &BTreeMap<u16, Option<[u8; 32]>>,
) -> Result<CompressionAdmissionReadback> {
    if expected_receipt.verdict != CompressionAdmissionVerdict::Admitted
        || expected_receipt.candidate_selection.is_none()
    {
        return Err(admission_error(
            "only an admitted full candidate-set selection receipt can become current",
        ));
    }
    let pre_publication_lease = vault.retain_latest_snapshot();
    let snapshot = pre_publication_lease.seq();
    let receipt = read_receipt_at(vault, slot, snapshot, receipt_sha256)?;
    pre_publication_lease.record_progress();
    if &receipt != expected_receipt {
        return Err(admission_error(
            "selected receipt changed between independent readback and publication",
        ));
    }
    let generation = generation_identity_without_codec_at(vault, slot, lens, snapshot)?;
    validate_active_generation_at(vault, &receipt, slot, &generation, snapshot)?;
    pre_publication_lease.record_progress();
    let pointer_key = compression_admission_pointer_key(slot.slot_id);
    let current_pointer =
        read_pointer_digest(vault, slot, snapshot, &pointer_key, "current-admission")?;
    pre_publication_lease.record_progress();
    if current_pointer == Some(receipt_sha256) {
        if vault.latest_seq() != snapshot {
            return Err(admission_error(
                "selected admission pointer sequence changed during idempotent publication readback",
            ));
        }
        return Ok(CompressionAdmissionReadback {
            receipt_sha256: hex(&receipt_sha256),
            receipt,
            receipt_commit_seq,
            receipt_ledger,
            pointer_commit_seq: None,
            pointer_ledger: None,
            current: true,
            active_generation_current: true,
            trust: "verified_idempotent_selected_admission_readback".to_string(),
        });
    }
    if vault.latest_seq() != snapshot {
        return Err(admission_error(
            "selected admission source sequence changed before pointer publication",
        ));
    }
    drop(pre_publication_lease);

    let (pointer_seq, pointer_ledger) = vault.write_cf_batch_with_ledger_entry_if_seq(
        snapshot,
        [(
            ColumnFamily::Compression,
            pointer_key.clone(),
            receipt_sha256.to_vec(),
        )],
        EntryKind::Admission,
        admission_subject(slot),
        admission_ledger_payload(
            slot,
            receipt_sha256,
            &receipt.schema,
            "publish",
            CompressionAdmissionVerdict::Admitted,
        )?,
        ActorId::Service("calyx-registry-compression-admission".to_string()),
    )?;
    vault.flush_with_report()?;
    let publication_readback_lease = vault.retain_snapshot_at(pointer_seq);
    let inventory = vault.physical_commit_inventory(
        pointer_seq,
        &[
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    publication_readback_lease.record_progress();
    let pointer = vault
        .read_cf_at(pointer_seq, ColumnFamily::Compression, &pointer_key)?
        .ok_or_else(|| admission_error("selected admission pointer is absent after publication"))?;
    if pointer.as_slice() != receipt_sha256.as_slice() {
        return Err(admission_error(
            "selected admission pointer physical readback differs from selection receipt hash",
        ));
    }
    publication_readback_lease.record_progress();
    for candidate in candidates {
        if candidate.slot.slot_id == slot.slot_id {
            continue;
        }
        let observed = read_pointer_digest(
            vault,
            &candidate.slot,
            pointer_seq,
            &compression_admission_pointer_key(candidate.slot.slot_id),
            "current-admission",
        )?;
        if observed
            != prior_current
                .get(&candidate.slot.slot_id.get())
                .copied()
                .flatten()
        {
            return Err(admission_error(format!(
                "winner publication changed non-winning slot {} current pointer",
                candidate.slot.slot_id.get()
            )));
        }
        publication_readback_lease.record_progress();
    }
    let final_receipt = read_receipt_at(vault, slot, pointer_seq, receipt_sha256)?;
    validate_active_generation_at(vault, &final_receipt, slot, &generation, pointer_seq)?;
    publication_readback_lease.record_progress();
    if vault.latest_seq() != pointer_seq {
        return Err(admission_error(
            "selected admission pointer sequence changed during physical publication readback",
        ));
    }
    Ok(CompressionAdmissionReadback {
        receipt_sha256: hex(&receipt_sha256),
        receipt: final_receipt,
        receipt_commit_seq,
        receipt_ledger,
        pointer_commit_seq: Some(pointer_seq),
        pointer_ledger: Some(pointer_ledger),
        current: true,
        active_generation_current: true,
        trust: format!(
            "verified_selected_pointer_physical_bytes={};candidate_set_recomputed=true",
            inventory.total_physical_bytes
        ),
    })
}

fn persist_evaluation_receipt<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    receipt: CompressionAdmissionReceipt,
) -> Result<CompressionAdmissionReadback> {
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| admission_error(format!("encode admission receipt: {error}")))?;
    let receipt_sha256: [u8; 32] = Sha256::digest(&receipt_bytes).into();
    let receipt_key = compression_admission_receipt_key(slot.slot_id, receipt_sha256);
    let pre_receipt_lease = vault.retain_latest_snapshot();
    let expected_seq = pre_receipt_lease.seq();
    let active_generation = generation_identity_without_codec_at(vault, slot, lens, expected_seq)?;
    validate_active_generation_at(vault, &receipt, slot, &active_generation, expected_seq)?;
    pre_receipt_lease.record_progress();
    if let Some(existing) =
        vault.read_cf_at(expected_seq, ColumnFamily::Compression, &receipt_key)?
    {
        pre_receipt_lease.record_progress();
        let existing_receipt = decode_receipt(slot, receipt_sha256, &existing)?;
        if existing != receipt_bytes || existing_receipt != receipt {
            return Err(admission_error(format!(
                "immutable compression admission receipt {} already exists with different canonical bytes",
                hex(&receipt_sha256)
            )));
        }
        let latest = read_pointer_digest(
            vault,
            slot,
            expected_seq,
            &compression_admission_evaluation_pointer_key(slot.slot_id),
            "latest-evaluation",
        )?;
        pre_receipt_lease.record_progress();
        if latest != Some(receipt_sha256) {
            return Err(admission_error(format!(
                "immutable compression admission receipt {} exists but is not the latest evaluation; refusing ambiguous replay",
                hex(&receipt_sha256)
            )));
        }
        let current = read_pointer_digest(
            vault,
            slot,
            expected_seq,
            &compression_admission_pointer_key(slot.slot_id),
            "current-admission",
        )? == Some(receipt_sha256);
        pre_receipt_lease.record_progress();
        if vault.latest_seq() != expected_seq {
            return Err(admission_error(
                "compression evaluation sequence changed during idempotent receipt readback",
            ));
        }
        return Ok(CompressionAdmissionReadback {
            receipt_sha256: hex(&receipt_sha256),
            receipt: existing_receipt,
            receipt_commit_seq: None,
            receipt_ledger: None,
            pointer_commit_seq: None,
            pointer_ledger: None,
            current,
            active_generation_current: true,
            trust: "verified_idempotent_immutable_evaluation_readback".to_string(),
        });
    }
    let prior_admission_pointer = vault.read_cf_at(
        expected_seq,
        ColumnFamily::Compression,
        &compression_admission_pointer_key(slot.slot_id),
    )?;
    pre_receipt_lease.record_progress();
    if vault.latest_seq() != expected_seq {
        return Err(admission_error(
            "compression evaluation source sequence changed before receipt publication",
        ));
    }
    drop(pre_receipt_lease);
    let evaluation_pointer_key = compression_admission_evaluation_pointer_key(slot.slot_id);
    let (receipt_seq, receipt_ledger) = vault.write_cf_batch_with_ledger_entry_if_seq(
        expected_seq,
        [
            (
                ColumnFamily::Compression,
                receipt_key.clone(),
                receipt_bytes.clone(),
            ),
            (
                ColumnFamily::Compression,
                evaluation_pointer_key.clone(),
                receipt_sha256.to_vec(),
            ),
        ],
        EntryKind::Admission,
        admission_subject(slot),
        admission_ledger_payload(
            slot,
            receipt_sha256,
            &receipt.schema,
            "evaluation",
            receipt.verdict,
        )?,
        ActorId::Service("calyx-registry-compression-admission".to_string()),
    )?;
    vault.flush_with_report()?;
    let receipt_readback_lease = vault.retain_snapshot_at(receipt_seq);
    let receipt_inventory = vault.physical_commit_inventory(
        receipt_seq,
        &[
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    receipt_readback_lease.record_progress();
    let observed = vault
        .read_cf_at(receipt_seq, ColumnFamily::Compression, &receipt_key)?
        .ok_or_else(|| admission_error("admission receipt was absent after its commit"))?;
    let readback_receipt = decode_receipt(slot, receipt_sha256, &observed)?;
    if observed != receipt_bytes || readback_receipt != receipt {
        return Err(admission_error(
            "admission receipt physical readback differs from the staged receipt",
        ));
    }
    receipt_readback_lease.record_progress();
    validate_active_generation_at(
        vault,
        &readback_receipt,
        slot,
        &active_generation,
        receipt_seq,
    )?;
    receipt_readback_lease.record_progress();
    let evaluation_pointer = vault
        .read_cf_at(
            receipt_seq,
            ColumnFamily::Compression,
            &evaluation_pointer_key,
        )?
        .ok_or_else(|| admission_error("latest-evaluation pointer was absent after publication"))?;
    if evaluation_pointer.as_slice() != receipt_sha256.as_slice() {
        return Err(admission_error(
            "latest-evaluation pointer physical readback differs from receipt hash",
        ));
    }
    receipt_readback_lease.record_progress();

    let after_pointer = vault.read_cf_at(
        receipt_seq,
        ColumnFamily::Compression,
        &compression_admission_pointer_key(slot.slot_id),
    )?;
    if after_pointer != prior_admission_pointer {
        return Err(admission_error(
            "candidate evaluation changed the current admission pointer before candidate selection",
        ));
    }
    receipt_readback_lease.record_progress();
    if vault.latest_seq() != receipt_seq {
        return Err(admission_error(
            "compression evaluation sequence changed during receipt physical readback",
        ));
    }
    Ok(CompressionAdmissionReadback {
        receipt_sha256: hex(&receipt_sha256),
        receipt: readback_receipt,
        receipt_commit_seq: Some(receipt_seq),
        receipt_ledger: Some(receipt_ledger),
        pointer_commit_seq: None,
        pointer_ledger: None,
        current: false,
        active_generation_current: true,
        trust: format!(
            "verified_candidate_evaluation_physical_bytes={};current_pointer_unchanged=true",
            receipt_inventory.total_physical_bytes
        ),
    })
}

fn derive_and_validate_work(
    generation: &CompressedGenerationIdentity,
    request: &CompressionAdmissionRequest,
) -> Result<CompressionWorkObservation> {
    derive_and_validate_work_shape(
        generation.row_count,
        generation.raw_dim,
        generation.stored_dim,
        request,
    )
}

fn derive_and_validate_work_shape(
    row_count: u32,
    raw_dim: u32,
    stored_dim: u32,
    request: &CompressionAdmissionRequest,
) -> Result<CompressionWorkObservation> {
    let held_out_queries = u64::try_from(request.queries.len())
        .map_err(|_| admission_error("held-out query count exceeds u64"))?;
    derive_and_validate_work_counts(
        row_count,
        raw_dim,
        stored_dim,
        held_out_queries,
        request.warmup_runs,
        request.measured_runs,
        &request.work_limits,
    )
}

fn derive_and_validate_work_counts(
    row_count: u32,
    raw_dim: u32,
    stored_dim: u32,
    held_out_queries: u64,
    warmup_runs: u32,
    measured_runs: u32,
    limits: &CompressionAdmissionWorkLimits,
) -> Result<CompressionWorkObservation> {
    let corpus_rows = u64::from(row_count);
    let warmup_packed_searches = u64::from(warmup_runs)
        .checked_mul(held_out_queries)
        .ok_or_else(|| admission_error("warmup packed-search count overflow"))?;
    let measured_packed_searches = u64::from(measured_runs)
        .checked_mul(held_out_queries)
        .ok_or_else(|| admission_error("measured packed-search count overflow"))?;
    let total_packed_searches = warmup_packed_searches
        .checked_add(measured_packed_searches)
        .ok_or_else(|| admission_error("total packed-search count overflow"))?;
    let exact_truth_pairwise_scores = corpus_rows
        .checked_mul(held_out_queries)
        .ok_or_else(|| admission_error("exact-truth pairwise-score count overflow"))?;
    let packed_pairwise_scores = corpus_rows
        .checked_mul(total_packed_searches)
        .ok_or_else(|| admission_error("packed pairwise-score count overflow"))?;
    let total_pairwise_scores = exact_truth_pairwise_scores
        .checked_add(packed_pairwise_scores)
        .and_then(|value| value.checked_add(corpus_rows))
        .ok_or_else(|| admission_error("total pairwise-score count overflow"))?;
    let coefficient_evaluations = exact_truth_pairwise_scores
        .checked_mul(u64::from(raw_dim))
        .and_then(|value| {
            packed_pairwise_scores
                .checked_mul(u64::from(stored_dim))
                .and_then(|packed| value.checked_add(packed))
        })
        .and_then(|value| {
            corpus_rows
                .checked_mul(u64::from(raw_dim) + u64::from(stored_dim))
                .and_then(|reconstruction| value.checked_add(reconstruction))
        })
        .ok_or_else(|| admission_error("coefficient-evaluation count overflow"))?;
    if corpus_rows > limits.maximum_corpus_rows
        || held_out_queries > limits.maximum_held_out_queries
        || total_packed_searches > limits.maximum_total_packed_searches
        || total_pairwise_scores > limits.maximum_pairwise_score_evaluations
        || coefficient_evaluations > limits.maximum_coefficient_evaluations
    {
        return Err(admission_error(format!(
            "compression admission work exceeds declared pre-execution limits: rows={corpus_rows}/{} queries={held_out_queries}/{} packed_searches={total_packed_searches}/{} pairwise_scores={total_pairwise_scores}/{} coefficient_evaluations={coefficient_evaluations}/{}",
            limits.maximum_corpus_rows,
            limits.maximum_held_out_queries,
            limits.maximum_total_packed_searches,
            limits.maximum_pairwise_score_evaluations,
            limits.maximum_coefficient_evaluations
        )));
    }
    Ok(CompressionWorkObservation {
        corpus_rows,
        held_out_queries,
        warmup_packed_searches,
        measured_packed_searches,
        exact_truth_pairwise_scores,
        packed_pairwise_scores,
        reconstruction_rows: corpus_rows,
        coefficient_evaluations,
        work_model: String::new(),
        candidate_slots: 0,
        candidate_work: Vec::new(),
        peak_codec_geometry_bytes: 0,
        aggregate_codec_retained_entry_and_sample_bound: 0,
        aggregate_codec_transform_coefficient_visits: 0,
        aggregate_codec_auxiliary_work_units: 0,
        aggregate_pairwise_score_evaluations: 0,
        aggregate_registry_coefficient_evaluations: 0,
        total_accounted_work_units: 0,
    })
}

fn validate_request(slot: &Slot, request: &CompressionAdmissionRequest) -> Result<()> {
    validate_request_with_work_model(slot, request, true)
}

fn validate_request_with_work_model(
    slot: &Slot,
    request: &CompressionAdmissionRequest,
    require_v3_limits: bool,
) -> Result<()> {
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(admission_error(
            "physical compression admission requires a dense slot",
        ));
    };
    if request.generation_seq == 0
        || request.queries.is_empty()
        || request.k == 0
        || request.warmup_runs == 0
        || request.measured_runs < 3
    {
        return Err(admission_error(
            "generation_seq, held-out queries, k, and warmup_runs must be nonzero and measured_runs must be at least three",
        ));
    }
    if require_v3_limits {
        validate_v3_work_limits(&request.work_limits)?;
    } else if request.work_limits.maximum_corpus_rows == 0
        || request.work_limits.maximum_held_out_queries == 0
        || request.work_limits.maximum_total_packed_searches == 0
        || request.work_limits.maximum_pairwise_score_evaluations == 0
        || request.work_limits.maximum_coefficient_evaluations == 0
    {
        return Err(admission_error(
            "legacy compression admission pre-execution work limits must all be nonzero",
        ));
    }
    for query in &request.queries {
        if query.values.len() != raw_dim as usize
            || query.values.iter().any(|value| !value.is_finite())
            || query.values.iter().all(|value| *value == 0.0)
        {
            return Err(admission_error(format!(
                "held-out query {} must contain exactly {raw_dim} finite coefficients with nonzero norm",
                query.cx_id
            )));
        }
    }
    validate_gates(&request.gates)
}

fn validate_candidate_evaluation_request_shape(
    request: &CompressionCandidateEvaluationRequest,
) -> Result<BTreeSet<CxId>> {
    if request.queries.is_empty()
        || request.k == 0
        || request.warmup_runs == 0
        || request.measured_runs < 3
    {
        return Err(admission_error(
            "held-out queries, k, and warmup_runs must be nonzero and measured_runs must be at least three",
        ));
    }
    validate_v3_work_limits(&request.work_limits)?;
    let query_count = u64::try_from(request.queries.len())
        .map_err(|_| admission_error("held-out query count exceeds u64"))?;
    if query_count > request.work_limits.maximum_held_out_queries {
        return Err(admission_error(format!(
            "held-out queries exceed declared pre-execution limit: held_out_queries={query_count}/{}",
            request.work_limits.maximum_held_out_queries
        )));
    }
    let lifecycle_runs = u64::from(request.warmup_runs)
        .checked_add(u64::from(request.measured_runs))
        .and_then(|runs| runs.checked_add(1))
        .ok_or_else(|| admission_error("candidate lifecycle packed-search run count overflow"))?;
    let lifecycle_packed_searches = lifecycle_runs
        .checked_mul(query_count)
        .ok_or_else(|| admission_error("candidate lifecycle packed-search count overflow"))?;
    if lifecycle_packed_searches > request.work_limits.maximum_total_packed_searches {
        return Err(admission_error(format!(
            "candidate lifecycle packed searches exceed declared pre-execution limit: total_packed_searches={lifecycle_packed_searches}/{}",
            request.work_limits.maximum_total_packed_searches
        )));
    }
    if u64::from(request.k) > request.work_limits.maximum_corpus_rows {
        return Err(admission_error(format!(
            "candidate k exceeds the declared maximum corpus cardinality: k={}/{}",
            request.k, request.work_limits.maximum_corpus_rows
        )));
    }
    if request.requested_backend != BackendKind::Cpu {
        return Err(admission_error(format!(
            "compression candidate requested backend {} but no real device provider is registered",
            request.requested_backend
        )));
    }
    let mut identities = BTreeSet::new();
    for query in &request.queries {
        if !identities.insert(query.cx_id) {
            return Err(admission_error(
                "held-out query identities contain a duplicate CxId",
            ));
        }
    }
    validate_gates(&request.gates)?;
    Ok(identities)
}

fn preflight_compression_candidate_operation_inner(
    candidate_count: usize,
    mut candidate_slot_ids: impl Iterator<Item = u16>,
    request: &CompressionCandidateEvaluationRequest,
) -> Result<BTreeSet<CxId>> {
    if candidate_count == 0 {
        return Err(admission_error(
            "compression candidate preflight requires at least one registered slot id",
        ));
    }
    validate_v3_work_limits(&request.work_limits)?;
    let candidate_count = u64::try_from(candidate_count)
        .map_err(|_| admission_error("compression candidate count exceeds u64"))?;
    if candidate_count > request.work_limits.maximum_candidate_slots {
        return Err(admission_error(format!(
            "compression candidate slots exceed declared pre-execution limit: candidate_slots={candidate_count}/{}",
            request.work_limits.maximum_candidate_slots
        )));
    }
    let mut unique_slot_ids = BTreeSet::new();
    if candidate_slot_ids.any(|slot_id| !unique_slot_ids.insert(slot_id)) {
        return Err(admission_error(
            "compression candidate slot ids must be unique",
        ));
    }
    validate_candidate_evaluation_request_shape(request)
}

fn validate_candidate_evaluation_request_for_slot(
    slot: &Slot,
    request: &CompressionCandidateEvaluationRequest,
) -> Result<()> {
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(admission_error(
            "physical compression admission requires a dense slot",
        ));
    };
    for query in &request.queries {
        if query.values.len() != raw_dim as usize
            || query.values.iter().any(|value| !value.is_finite())
            || query.values.iter().all(|value| *value == 0.0)
        {
            return Err(admission_error(format!(
                "held-out query {} must contain exactly {raw_dim} finite coefficients with nonzero norm",
                query.cx_id
            )));
        }
    }
    Ok(())
}

fn validate_gates(gates: &CompressionAdmissionGates) -> Result<()> {
    if !gates.minimum_recall_at_k.is_finite()
        || !(0.0..=1.0).contains(&gates.minimum_recall_at_k)
        || !gates.maximum_mean_cosine_error.is_finite()
        || gates.maximum_mean_cosine_error < 0.0
        || !gates.maximum_cosine_error.is_finite()
        || gates.maximum_cosine_error < gates.maximum_mean_cosine_error
        || gates.maximum_p99_latency_ns == 0
        || gates.maximum_total_physical_bytes == 0
        || gates.maximum_working_set_bytes == 0
        || gates.maximum_materialized_primary_bytes_per_query == 0
    {
        return Err(admission_error(
            "compression admission gates are malformed or non-positive",
        ));
    }
    Ok(())
}

fn validate_query_identities(queries: &[CompressionQuery]) -> Result<()> {
    if queries
        .windows(2)
        .any(|pair| pair[0].cx_id == pair[1].cx_id)
    {
        return Err(admission_error(
            "held-out query identities contain a duplicate CxId",
        ));
    }
    Ok(())
}

fn load_raw_corpus<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    snapshot: Seq,
    generation: &CompressedGenerationIdentity,
    snapshot_lease: &RetainedSnapshot<'_>,
) -> Result<RawCorpus> {
    let expected_rows = usize::try_from(generation.row_count)
        .map_err(|_| admission_error("raw truth row count exceeds usize"))?;
    let range = KeyRange {
        start: Vec::new(),
        end: None,
    };
    let mut after_key: Option<Vec<u8>> = None;
    let mut persisted = Vec::with_capacity(expected_rows);
    loop {
        let remaining = expected_rows.saturating_sub(persisted.len());
        let page_limit = remaining.saturating_add(1).min(PREFLIGHT_PAGE_ROWS);
        let page = vault.scan_cf_range_page_at(
            snapshot,
            ColumnFamily::slot_raw(slot.slot_id),
            &range,
            after_key.as_deref(),
            page_limit,
        )?;
        snapshot_lease.record_progress();
        if page.is_empty() {
            break;
        }
        let next_after = page
            .last()
            .map(|(key, _)| key.clone())
            .ok_or_else(|| admission_error("nonempty raw-truth page has no final key"))?;
        if after_key
            .as_ref()
            .is_some_and(|previous| previous >= &next_after)
        {
            return Err(admission_error(
                "raw-truth page did not advance in strict key order",
            ));
        }
        persisted.extend(page);
        if persisted.len() > expected_rows {
            return Err(admission_error(format!(
                "raw truth corpus exceeds manifested row count: observed_at_least={} manifested={expected_rows}",
                persisted.len()
            )));
        }
        after_key = Some(next_after);
    }
    if persisted.is_empty() {
        return Err(admission_error("raw truth corpus is empty"));
    }
    if persisted.len() != generation.row_count as usize {
        return Err(admission_error(format!(
            "raw truth corpus row count {} differs from manifested generation row count {}",
            persisted.len(),
            generation.row_count
        )));
    }
    let codec_context_id = decode_hex_32(
        &generation.codec_context_sha256,
        "generation codec-context SHA-256",
    )?;
    let observed_raw_root = raw_generation_root(
        &codec_context_id,
        generation.row_count,
        persisted
            .iter()
            .map(|(key, bytes)| Ok((cx_id_from_key(key)?, bytes.as_slice())))
            .collect::<Result<Vec<_>>>()?,
    )?;
    let expected_raw_root = decode_hex_32(
        &generation.raw_generation_sha256,
        "generation raw-root SHA-256",
    )?;
    if observed_raw_root != expected_raw_root {
        return Err(admission_error(format!(
            "raw truth corpus root {} differs from manifested raw generation root {}",
            hex(&observed_raw_root),
            hex(&expected_raw_root)
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-source-values-v1");
    let mut rows = Vec::with_capacity(persisted.len());
    let mut encoded_value_bytes = 0_u64;
    for (key, bytes) in persisted {
        let cx_id = cx_id_from_key(&key)?;
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(&key);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        encoded_value_bytes = encoded_value_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| admission_error("raw truth encoded byte total overflow"))?;
        let vector = encode::decode_slot_vector(&bytes)?;
        let SlotVector::Dense { dim, data } = vector else {
            return Err(admission_error(format!(
                "raw truth row {cx_id} is not dense"
            )));
        };
        if dim != generation.raw_dim {
            return Err(admission_error(format!(
                "raw truth row {cx_id} dimension {dim} differs from generation dimension {}",
                generation.raw_dim
            )));
        }
        if let Some(index) = data.iter().position(|value| !value.is_finite()) {
            return Err(admission_error(format!(
                "raw truth row {cx_id} contains a non-finite coefficient at index {index}"
            )));
        }
        rows.push((cx_id, data));
        snapshot_lease.record_progress();
    }
    Ok(RawCorpus {
        rows,
        source_sha256: hasher.finalize().into(),
        encoded_value_bytes,
    })
}

struct ExactTruthHeapEntry(CompressionScoredHit);

impl PartialEq for ExactTruthHeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.score.to_bits() == other.0.score.to_bits() && self.0.cx_id == other.0.cx_id
    }
}

impl Eq for ExactTruthHeapEntry {}

impl PartialOrd for ExactTruthHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExactTruthHeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap keeps the least desirable retained hit at the root:
        // lower score is worse, then larger CxId is worse.
        other
            .0
            .score
            .total_cmp(&self.0.score)
            .then_with(|| self.0.cx_id.as_bytes().cmp(other.0.cx_id.as_bytes()))
    }
}

fn exact_truth(
    corpus: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
    snapshot_lease: &RetainedSnapshot<'_>,
) -> Result<Vec<Vec<CompressionScoredHit>>> {
    if k > corpus.len() {
        return Err(admission_error(format!(
            "requested k={k} exceeds corpus rows {}",
            corpus.len()
        )));
    }
    let mut truth = Vec::with_capacity(queries.len());
    for query in queries {
        let mut retained = BinaryHeap::with_capacity(k);
        for (row_index, (cx_id, values)) in corpus.iter().enumerate() {
            let candidate = ExactTruthHeapEntry(CompressionScoredHit {
                cx_id: *cx_id,
                score: cosine(&query.values, values)?,
            });
            if retained.len() < k {
                retained.push(candidate);
            } else if retained
                .peek()
                .is_some_and(|least_desirable| candidate < *least_desirable)
            {
                let mut least_desirable = retained
                    .peek_mut()
                    .ok_or_else(|| admission_error("exact-truth heap unexpectedly empty"))?;
                *least_desirable = candidate;
            }
            if row_index % PREFLIGHT_PAGE_ROWS == 0 {
                snapshot_lease.record_progress();
            }
        }
        let mut hits = retained
            .into_iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.cx_id.as_bytes().cmp(right.cx_id.as_bytes()))
        });
        truth.push(hits);
        snapshot_lease.record_progress();
    }
    Ok(truth)
}

fn build_query_observations(
    queries: &[CompressionQuery],
    exact: Vec<Vec<CompressionScoredHit>>,
    packed: Vec<Option<Vec<CompressedSlotHit>>>,
    samples: Vec<Vec<u64>>,
    k: usize,
) -> Result<Vec<CompressionQueryObservation>> {
    queries
        .iter()
        .zip(exact)
        .zip(packed)
        .zip(samples)
        .map(|(((query, exact_top_k), packed), latency_samples_ns)| {
            let packed_top_k = packed.ok_or_else(|| {
                admission_error(format!("query {} produced no packed result", query.cx_id))
            })?;
            if exact_top_k.len() != k || packed_top_k.len() != k {
                return Err(admission_error(format!(
                    "query {} expected exactly {k} truth/packed hits, got {}/{}",
                    query.cx_id,
                    exact_top_k.len(),
                    packed_top_k.len()
                )));
            }
            let truth_ids = exact_top_k
                .iter()
                .map(|hit| hit.cx_id)
                .collect::<BTreeSet<_>>();
            let matched = packed_top_k
                .iter()
                .filter(|hit| truth_ids.contains(&hit.cx_id))
                .count();
            Ok(CompressionQueryObservation {
                query_cx_id: query.cx_id,
                exact_top_k,
                packed_top_k,
                recall_at_k: matched as f64 / k as f64,
                latency_samples_ns,
            })
        })
        .collect()
}

fn reconstruction_summary(
    observations: &[CompressionReconstructionEvidence],
) -> Result<(f64, f64)> {
    if observations.is_empty() {
        return Err(admission_error(
            "reconstruction produced no row observations",
        ));
    }
    let sum = observations.iter().try_fold(0.0_f64, |sum, observation| {
        if !observation.cosine_error.is_finite() || observation.cosine_error < 0.0 {
            return Err(admission_error(format!(
                "row {} has invalid reconstruction error {}",
                observation.cx_id, observation.cosine_error
            )));
        }
        Ok(sum + observation.cosine_error)
    })?;
    let max = observations
        .iter()
        .map(|observation| observation.cosine_error)
        .reduce(f64::max)
        .ok_or_else(|| admission_error("reconstruction maximum is absent"))?;
    Ok((sum / observations.len() as f64, max))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_gates(
    gates: &CompressionAdmissionGates,
    recall: f64,
    mean_error: f64,
    max_error: f64,
    p99: u64,
    physical_bytes: u64,
    working_set_bytes: u64,
    materialized_primary_bytes: u64,
    working_set_gate: &str,
) -> Vec<CompressionGateObservation> {
    vec![
        ratio_gate(
            "minimum_recall_at_k",
            CompressionGateComparison::AtLeast,
            recall,
            gates.minimum_recall_at_k,
            recall >= gates.minimum_recall_at_k,
        ),
        ratio_gate(
            "maximum_mean_cosine_error",
            CompressionGateComparison::AtMost,
            mean_error,
            gates.maximum_mean_cosine_error,
            mean_error <= gates.maximum_mean_cosine_error,
        ),
        ratio_gate(
            "maximum_cosine_error",
            CompressionGateComparison::AtMost,
            max_error,
            gates.maximum_cosine_error,
            max_error <= gates.maximum_cosine_error,
        ),
        integer_gate("maximum_p99_latency_ns", p99, gates.maximum_p99_latency_ns),
        integer_gate(
            "maximum_total_physical_bytes",
            physical_bytes,
            gates.maximum_total_physical_bytes,
        ),
        integer_gate(
            working_set_gate,
            working_set_bytes,
            gates.maximum_working_set_bytes,
        ),
        integer_gate(
            "maximum_materialized_primary_bytes_per_query",
            materialized_primary_bytes,
            gates.maximum_materialized_primary_bytes_per_query,
        ),
    ]
}

fn ratio_gate(
    gate: &str,
    comparison: CompressionGateComparison,
    observed: f64,
    threshold: f64,
    passed: bool,
) -> CompressionGateObservation {
    CompressionGateObservation {
        gate: gate.to_string(),
        comparison,
        observed: format!("{observed:.17}"),
        threshold: format!("{threshold:.17}"),
        passed,
    }
}

fn integer_gate(gate: &str, observed: u64, threshold: u64) -> CompressionGateObservation {
    CompressionGateObservation {
        gate: gate.to_string(),
        comparison: CompressionGateComparison::AtMost,
        observed: observed.to_string(),
        threshold: threshold.to_string(),
        passed: observed <= threshold,
    }
}

fn validate_generation_inventory(slot: &Slot, inventory: &PhysicalCommitInventory) -> Result<()> {
    let mut primary = BTreeSet::new();
    let mut raw = BTreeSet::new();
    let mut proofs = BTreeSet::new();
    let mut manifests = 0_usize;
    let mut lifecycles = 0_usize;
    let mut ledgers = 0_usize;
    let mut time_indexes = 0_usize;
    let mut invalidated_evaluation_pointers = 0_usize;
    let mut invalidated_admission_pointers = 0_usize;
    for row in &inventory.rows {
        if row.tombstoned {
            let invalidated_slot = if row.cf == ColumnFamily::Compression {
                parse_compression_admission_evaluation_pointer_key(&row.key)
                    .map(|slot_id| (slot_id, true))
                    .or_else(|| {
                        parse_compression_admission_pointer_key(&row.key)
                            .map(|slot_id| (slot_id, false))
                    })
            } else {
                None
            };
            let Some((invalidated_slot, evaluation)) = invalidated_slot else {
                return Err(admission_error(format!(
                    "generation inventory row {} in {} is unexpectedly tombstoned",
                    row.ordinal,
                    row.cf.name()
                )));
            };
            if invalidated_slot != slot.slot_id {
                return Err(admission_error(
                    "generation inventory invalidates an admission pointer for another slot",
                ));
            }
            if evaluation {
                invalidated_evaluation_pointers += 1;
            } else {
                invalidated_admission_pointers += 1;
            }
            continue;
        }
        match row.cf {
            cf if cf == ColumnFamily::slot(slot.slot_id) => {
                primary.insert(cx_id_from_key(&row.key)?);
            }
            cf if cf == ColumnFamily::slot_raw(slot.slot_id) => {
                raw.insert(cx_id_from_key(&row.key)?);
            }
            ColumnFamily::Compression => {
                if row.key == compression_manifest_key(slot.slot_id) {
                    manifests += 1;
                } else if let Some((proof_slot, cx_id)) =
                    parse_compression_membership_proof_key(&row.key)
                {
                    if proof_slot != slot.slot_id {
                        return Err(admission_error(
                            "generation inventory contains a proof for another slot",
                        ));
                    }
                    proofs.insert(cx_id);
                } else if let Some((lifecycle_slot, _)) = parse_compression_lifecycle_key(&row.key)
                {
                    if lifecycle_slot != slot.slot_id {
                        return Err(admission_error(
                            "generation inventory contains a lifecycle row for another slot",
                        ));
                    }
                    lifecycles += 1;
                } else {
                    return Err(admission_error(format!(
                        "generation inventory contains an unexpected Compression key of {} bytes",
                        row.key.len()
                    )));
                }
            }
            ColumnFamily::Ledger => ledgers += 1,
            ColumnFamily::TimeIndex => time_indexes += 1,
            _ => {
                return Err(admission_error(format!(
                    "generation inventory contains unexpected CF {}",
                    row.cf.name()
                )));
            }
        }
    }
    if primary.is_empty()
        || primary != raw
        || primary != proofs
        || manifests != 1
        || lifecycles != 1
        || ledgers == 0
        || time_indexes != 1
        || invalidated_evaluation_pointers > 1
        || invalidated_admission_pointers > 1
    {
        return Err(admission_error(format!(
            "generation inventory is incomplete: primary={} raw={} proofs={} manifests={manifests} lifecycles={lifecycles} ledgers={ledgers} time_indexes={time_indexes}",
            primary.len(),
            raw.len(),
            proofs.len()
        )));
    }
    Ok(())
}

fn physical_components(inventory: &PhysicalCommitInventory) -> Vec<CompressionPhysicalComponent> {
    inventory
        .components
        .iter()
        .map(|component| CompressionPhysicalComponent {
            role: match &component.role {
                PhysicalCommitComponentRole::WalRecord => "wal_record".to_string(),
                PhysicalCommitComponentRole::DurableSst {
                    cf,
                    sst_index,
                    entries,
                } => format!(
                    "durable_sst:cf={}:index={sst_index}:entries={entries}",
                    cf.name()
                ),
                PhysicalCommitComponentRole::CurrentPointer => "current_pointer".to_string(),
                PhysicalCommitComponentRole::ImmutableManifest { manifest_seq } => {
                    format!("immutable_manifest:seq={manifest_seq}")
                }
                PhysicalCommitComponentRole::ManifestMirror { manifest_seq } => {
                    format!("manifest_mirror:seq={manifest_seq}")
                }
                PhysicalCommitComponentRole::RouterHandoff { manifest_seq } => {
                    format!("router_handoff:seq={manifest_seq}")
                }
            },
            container: component.container.name().to_string(),
            relative_path: component.relative_path.clone(),
            offset: component.offset,
            length: component.length,
            sha256: component.sha256_hex(),
        })
        .collect()
}

fn read_pointer_digest<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    snapshot: Seq,
    key: &[u8],
    kind: &str,
) -> Result<Option<[u8; 32]>> {
    let Some(pointer) = vault.read_cf_at(snapshot, ColumnFamily::Compression, key)? else {
        return Ok(None);
    };
    let digest: [u8; 32] = pointer.as_slice().try_into().map_err(|_| {
        admission_error(format!(
            "compression {kind} pointer for slot {} has {} bytes, expected 32",
            slot.slot_id.get(),
            pointer.len()
        ))
    })?;
    Ok(Some(digest))
}

fn read_receipt_at<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    snapshot: Seq,
    receipt_sha256: [u8; 32],
) -> Result<CompressionAdmissionReceipt> {
    let bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_admission_receipt_key(slot.slot_id, receipt_sha256),
        )?
        .ok_or_else(|| {
            admission_error(format!(
                "compression admission receipt {} for slot {} is missing",
                hex(&receipt_sha256),
                slot.slot_id.get()
            ))
        })?;
    decode_receipt(slot, receipt_sha256, &bytes)
}

fn validate_active_generation_at<C: Clock>(
    vault: &AsterVault<C>,
    receipt: &CompressionAdmissionReceipt,
    slot: &Slot,
    generation: &CompressedGenerationIdentity,
    snapshot: Seq,
) -> Result<()> {
    if !receipt_binds_active_generation_at(vault, receipt, slot, generation, snapshot)? {
        return Err(admission_error(format!(
            "compression admission receipt for slot {} does not bind the active manifested generation and its exact visible manifest row version",
            slot.slot_id.get(),
        )));
    }
    Ok(())
}

fn validate_pointer_bound_generation(
    receipt: &CompressionAdmissionReceipt,
    slot: &Slot,
    generation: &CompressedGenerationIdentity,
) -> Result<()> {
    // Aster atomically tombstones both admission pointer families on every
    // manifest mutation, so a live pointer supplies the freshness fact that a
    // latest-only handle cannot recover from historical MVCC row versions.
    if !receipt_binds_generation_content(receipt, slot, generation) {
        return Err(admission_error(format!(
            "compression admission pointer for slot {} does not bind the active manifested generation content identity",
            slot.slot_id.get(),
        )));
    }
    Ok(())
}

fn receipt_binds_active_generation_at<C: Clock>(
    vault: &AsterVault<C>,
    receipt: &CompressionAdmissionReceipt,
    slot: &Slot,
    generation: &CompressedGenerationIdentity,
    snapshot: Seq,
) -> Result<bool> {
    // Hash-addressed and mutation-eligible receipts do not inherit pointer
    // freshness: bind the content and the exact visible manifest row version.
    if !receipt_binds_generation_content(receipt, slot, generation) {
        return Ok(false);
    }
    Ok(vault.seq_for_key_at(
        snapshot,
        ColumnFamily::Compression,
        &compression_manifest_key(slot.slot_id),
    )? == Some(receipt.generation_seq))
}

fn receipt_binds_generation_content(
    receipt: &CompressionAdmissionReceipt,
    slot: &Slot,
    generation: &CompressedGenerationIdentity,
) -> bool {
    !(receipt.slot_id != slot.slot_id.get()
        || receipt.slot_key != slot.slot_key.key()
        || receipt.codec != generation.codec
        || receipt.level != generation.level
        || receipt.raw_dim != generation.raw_dim
        || receipt.stored_dim != generation.stored_dim
        || receipt.corpus_rows != generation.row_count
        || receipt.codec_context_sha256 != generation.codec_context_sha256
        || receipt.generation_sha256 != generation.generation_sha256
        || receipt.raw_generation_sha256 != generation.raw_generation_sha256
        || receipt.membership_sha256 != generation.membership_sha256)
}

fn validate_receipt(slot: &Slot, receipt: &CompressionAdmissionReceipt) -> Result<()> {
    let legacy = receipt.schema == LEGACY_COMPRESSION_ADMISSION_SCHEMA;
    let expected_build_protocol = if legacy {
        LEGACY_BUILD_PROTOCOL
    } else {
        BUILD_PROTOCOL
    };
    let build_sequence_valid = if legacy {
        receipt.build.source_seq < receipt.build.generation_seq
    } else {
        receipt.build.source_seq.checked_add(1) == Some(receipt.build.generation_seq)
    };
    if (!legacy && receipt.schema != COMPRESSION_ADMISSION_SCHEMA)
        || receipt.slot_id != slot.slot_id.get()
        || receipt.slot_key != slot.slot_key.key()
        || receipt.manifest_seq == 0
        || !receipt.query_ids_disjoint
        || receipt.metric != "cosine"
        || receipt.requested_backend != BackendKind::Cpu
        || receipt.observed_backend != BackendKind::Cpu
        || receipt.device_identity.trim().is_empty()
        || receipt.kernel_identity != PACKED_KERNEL_ID
        || receipt.build.protocol != expected_build_protocol
        || receipt.build.generation_seq != receipt.generation_seq
        || !build_sequence_valid
        || receipt.build.elapsed_ns == 0
        || receipt.placement.requested_backend != receipt.requested_backend
        || receipt.placement.observed_backend != receipt.observed_backend
        || receipt.placement.device_identity != receipt.device_identity
        || receipt.placement.kernel_identity != receipt.kernel_identity
        || receipt.placement.vram
            != (CompressionVramObservation::NotApplicable {
                reason: CPU_VRAM_REASON.to_string(),
            })
    {
        return Err(admission_error(
            "compression admission receipt has invalid schema, slot, generation, metric, or execution identity",
        ));
    }
    for (field, value) in [
        (
            "codec_context_sha256",
            receipt.codec_context_sha256.as_str(),
        ),
        ("generation_sha256", receipt.generation_sha256.as_str()),
        (
            "raw_generation_sha256",
            receipt.raw_generation_sha256.as_str(),
        ),
        ("membership_sha256", receipt.membership_sha256.as_str()),
        (
            "source_values_sha256",
            receipt.source_values_sha256.as_str(),
        ),
        ("query_values_sha256", receipt.query_values_sha256.as_str()),
        (
            "exact_ground_truth_sha256",
            receipt.exact_ground_truth_sha256.as_str(),
        ),
    ] {
        decode_hex_32(value, field)?;
    }

    let request = CompressionAdmissionRequest {
        generation_seq: receipt.generation_seq,
        requested_backend: receipt.requested_backend,
        queries: receipt.held_out_queries.clone(),
        k: receipt.k,
        warmup_runs: receipt.warmup_runs,
        measured_runs: receipt.measured_runs,
        work_limits: receipt.work_limits.clone(),
        gates: receipt.gates.clone(),
    };
    validate_request_with_work_model(slot, &request, !legacy)?;
    let generation = CompressedGenerationIdentity {
        slot_id: receipt.slot_id,
        codec: receipt.codec,
        level: receipt.level.clone(),
        raw_dim: receipt.raw_dim,
        stored_dim: receipt.stored_dim,
        row_count: receipt.corpus_rows,
        codec_context_sha256: receipt.codec_context_sha256.clone(),
        generation_sha256: receipt.generation_sha256.clone(),
        raw_generation_sha256: receipt.raw_generation_sha256.clone(),
        membership_sha256: receipt.membership_sha256.clone(),
        assay_attestation_sha256: None,
    };
    let expected_work = derive_and_validate_work(&generation, &request)?;
    if legacy {
        if receipt.work != expected_work || has_v3_work_limits(&receipt.work_limits) {
            return Err(admission_error(
                "legacy compression admission receipt contains non-canonical v3 work fields",
            ));
        }
    } else {
        if !legacy_work_fields_equal(&receipt.work, &expected_work) {
            return Err(admission_error(
                "compression admission receipt local work arithmetic is inconsistent",
            ));
        }
        let candidate_request = CompressionCandidateEvaluationRequest {
            requested_backend: request.requested_backend,
            queries: request.queries.clone(),
            k: request.k,
            warmup_runs: request.warmup_runs,
            measured_runs: request.measured_runs,
            work_limits: request.work_limits.clone(),
            gates: request.gates.clone(),
        };
        validate_v3_work_observation(&receipt.work, &candidate_request)?;
        let current = receipt
            .work
            .candidate_work
            .iter()
            .find(|candidate| candidate.slot_id == receipt.slot_id)
            .ok_or_else(|| admission_error("v3 receipt work omits its own candidate slot"))?;
        if current.quant_policy != slot.quant
            || current.raw_dim != receipt.raw_dim
            || current.stored_dim != receipt.stored_dim
            || current.corpus_rows != u64::from(receipt.corpus_rows)
        {
            return Err(admission_error(
                "v3 receipt work does not bind its own candidate generation",
            ));
        }
    }
    let mut canonical_queries = receipt.held_out_queries.clone();
    canonical_queries.sort_by(|left, right| left.cx_id.as_bytes().cmp(right.cx_id.as_bytes()));
    validate_query_identities(&canonical_queries)?;
    if canonical_queries != receipt.held_out_queries
        || query_digest(&receipt.held_out_queries)
            != decode_hex_32(&receipt.query_values_sha256, "query_values_sha256")?
    {
        return Err(admission_error(
            "compression admission receipt held-out queries are not canonical or do not match their digest",
        ));
    }

    let expected_logical_values = u64::from(receipt.corpus_rows)
        .checked_mul(u64::from(receipt.raw_dim))
        .ok_or_else(|| admission_error("receipt logical value count overflow"))?;
    if receipt.logical_values != expected_logical_values || receipt.logical_values == 0 {
        return Err(admission_error(
            "compression admission receipt logical value count is inconsistent",
        ));
    }
    validate_physical_components(receipt)?;
    let expected_rate = receipt
        .total_physical_bytes
        .checked_mul(8)
        .ok_or_else(|| admission_error("receipt physical bit count overflow"))?
        as f64
        / receipt.logical_values as f64;
    if receipt.effective_bits_per_value.to_bits() != expected_rate.to_bits()
        || receipt.primary_value_bytes == 0
        || receipt.primary_value_bytes > receipt.total_physical_bytes
    {
        return Err(admission_error(
            "compression admission receipt physical rate or primary byte count is inconsistent",
        ));
    }

    validate_query_observations(receipt)?;
    if truth_digest(&receipt.queries)
        != decode_hex_32(
            &receipt.exact_ground_truth_sha256,
            "exact_ground_truth_sha256",
        )?
    {
        return Err(admission_error(
            "compression admission receipt exact-ground-truth digest is inconsistent",
        ));
    }
    let (mean_error, max_error) = reconstruction_summary(&receipt.reconstruction)?;
    if receipt.reconstruction.len() != receipt.corpus_rows as usize
        || receipt
            .reconstruction
            .windows(2)
            .any(|pair| pair[0].cx_id.as_bytes() >= pair[1].cx_id.as_bytes())
        || receipt.mean_reconstruction_cosine_error.to_bits() != mean_error.to_bits()
        || receipt.max_reconstruction_cosine_error.to_bits() != max_error.to_bits()
    {
        return Err(admission_error(
            "compression admission receipt reconstruction evidence is incomplete or inconsistent",
        ));
    }

    let mut samples = receipt
        .queries
        .iter()
        .flat_map(|query| query.latency_samples_ns.iter().copied())
        .collect::<Vec<_>>();
    samples.sort_unstable();
    let p50 = percentile(&samples, 50)?;
    let p95 = percentile(&samples, 95)?;
    let p99 = percentile(&samples, 99)?;
    let median_seconds = p50 as f64 / 1_000_000_000.0;
    let vectors_per_second = f64::from(receipt.corpus_rows) / median_seconds;
    let bytes_per_second = receipt.primary_value_bytes as f64 / median_seconds;
    if receipt.latency_p50_ns != p50
        || receipt.latency_p95_ns != p95
        || receipt.latency_p99_ns != p99
        || receipt.vectors_per_second.to_bits() != vectors_per_second.to_bits()
        || receipt.bytes_per_second.to_bits() != bytes_per_second.to_bits()
    {
        return Err(admission_error(
            "compression admission receipt latency or throughput arithmetic is inconsistent",
        ));
    }
    let total_packed_searches = receipt
        .work
        .warmup_packed_searches
        .checked_add(receipt.work.measured_packed_searches)
        .ok_or_else(|| admission_error("receipt packed-search count overflow"))?;
    let expected_exact_scored = receipt
        .work
        .held_out_queries
        .checked_mul(receipt.work.corpus_rows)
        .ok_or_else(|| admission_error("receipt exact-truth scored-row count overflow"))?;
    let expected_packed_hits = total_packed_searches
        .checked_mul(u64::from(receipt.k))
        .ok_or_else(|| admission_error("receipt packed-hit count overflow"))?;
    let expected_retained_hits = receipt
        .work
        .held_out_queries
        .checked_mul(u64::from(receipt.k))
        .ok_or_else(|| admission_error("receipt retained packed-hit count overflow"))?;
    if receipt.allocations.scope != ALLOCATION_SCOPE
        || receipt.allocations.physical_inventory_row_records == 0
        || receipt.allocations.physical_inventory_component_records
            != receipt.physical_components.len() as u64
        || receipt.allocations.raw_truth_column_buffers != 1
        || receipt.allocations.raw_truth_vector_buffers != u64::from(receipt.corpus_rows)
        || receipt.allocations.raw_truth_rows != u64::from(receipt.corpus_rows)
        || receipt.allocations.raw_truth_encoded_bytes == 0
        || receipt.allocations.reconstruction_result_buffers != 1
        || receipt.allocations.reconstruction_rows != u64::from(receipt.corpus_rows)
        || receipt.allocations.exact_truth_result_buffers != receipt.work.held_out_queries
        || receipt.allocations.exact_truth_scored_rows != expected_exact_scored
        || receipt.allocations.packed_search_calls != total_packed_searches
        || receipt.allocations.packed_result_buffers_returned != total_packed_searches
        || receipt.allocations.packed_hits_returned != expected_packed_hits
        || receipt.allocations.retained_packed_result_buffers != receipt.work.held_out_queries
        || receipt.allocations.retained_packed_hits != expected_retained_hits
        || receipt.allocations.latency_sample_buffers != receipt.work.held_out_queries
        || receipt.allocations.latency_samples != receipt.work.measured_packed_searches
        || receipt
            .allocations
            .materialized_primary_rows_per_packed_search
            != u64::from(receipt.corpus_rows)
        || receipt
            .allocations
            .materialized_primary_bytes_per_packed_search
            != receipt.primary_value_bytes
    {
        return Err(admission_error(
            "compression admission receipt materialization observations are inconsistent",
        ));
    }
    let minimum_recall = receipt
        .queries
        .iter()
        .map(|query| query.recall_at_k)
        .reduce(f64::min)
        .ok_or_else(|| admission_error("receipt has no recall observations"))?;
    let expected_gates = evaluate_gates(
        &receipt.gates,
        minimum_recall,
        mean_error,
        max_error,
        p99,
        receipt.total_physical_bytes,
        receipt.resources.working_set_bytes_after,
        receipt.primary_value_bytes,
        if legacy {
            LEGACY_WORKING_SET_GATE
        } else {
            WORKING_SET_AFTER_MEASURED_SEARCH_GATE
        },
    );
    let expected_verdict = if expected_gates.iter().all(|gate| gate.passed) {
        CompressionAdmissionVerdict::Admitted
    } else {
        CompressionAdmissionVerdict::Refused
    };
    if receipt.gate_observations != expected_gates || receipt.verdict != expected_verdict {
        return Err(admission_error(
            "compression admission receipt gates or verdict are inconsistent",
        ));
    }
    if let Some(selection) = &receipt.candidate_selection {
        validate_selection_receipt(receipt, selection)?;
    }
    Ok(())
}

fn validate_selection_receipt(
    receipt: &CompressionAdmissionReceipt,
    selection: &CompressionCandidateSelectionReceipt,
) -> Result<()> {
    if selection.schema != COMPRESSION_CANDIDATE_SELECTION_SCHEMA
        || selection.protocol != SELECTION_PROTOCOL
        || selection.candidates.len() < 2
        || receipt.verdict != CompressionAdmissionVerdict::Admitted
    {
        return Err(admission_error(
            "compression candidate selection receipt has invalid schema, protocol, cardinality, or verdict",
        ));
    }
    let mut canonical = selection.candidates.clone();
    canonical.sort_by(|left, right| {
        left.slot_id
            .cmp(&right.slot_id)
            .then_with(|| left.slot_key.cmp(&right.slot_key))
            .then_with(|| left.receipt_sha256.cmp(&right.receipt_sha256))
    });
    if canonical != selection.candidates
        || canonical
            .windows(2)
            .any(|pair| pair[0].slot_id == pair[1].slot_id)
        || canonical.iter().any(|entry| {
            entry.logical_values == 0
                || entry.total_physical_bytes == 0
                || entry.build_elapsed_ns == 0
                || decode_hex_32(&entry.receipt_sha256, "candidate receipt SHA-256").is_err()
                || !selection_entry_rate_valid(entry)
        })
    {
        return Err(admission_error(
            "compression candidate selection entries are not unique canonical exact summaries",
        ));
    }
    let expected_digest = candidate_set_digest(&selection.candidates)?;
    if decode_hex_32(&selection.candidate_set_sha256, "candidate-set SHA-256")? != expected_digest {
        return Err(admission_error(
            "compression candidate selection set digest is inconsistent",
        ));
    }
    let winner_index = selection
        .candidates
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.verdict == CompressionAdmissionVerdict::Admitted)
        .try_fold(None, |winner: Option<usize>, (index, entry)| {
            let Some(prior) = winner else {
                return Ok::<_, calyx_core::CalyxError>(Some(index));
            };
            if candidate_entry_precedes(entry, &selection.candidates[prior])? {
                Ok(Some(index))
            } else {
                Ok(Some(prior))
            }
        })?
        .ok_or_else(|| admission_error("selection receipt has no admitted candidate"))?;
    let winner = &selection.candidates[winner_index];
    if selection.winner_slot_id != winner.slot_id
        || selection.winner_receipt_sha256 != winner.receipt_sha256
        || receipt.slot_id != winner.slot_id
        || receipt.slot_key != winner.slot_key
        || receipt.generation_seq != winner.generation_seq
        || receipt.codec != winner.codec
        || receipt.level != winner.level
        || receipt.total_physical_bytes != winner.total_physical_bytes
        || receipt.logical_values != winner.logical_values
        || receipt.effective_bits_per_value.to_bits() != winner.effective_bits_per_value.to_bits()
        || receipt.build.elapsed_ns != winner.build_elapsed_ns
    {
        return Err(admission_error(
            "compression candidate selection winner does not match the selected admission receipt",
        ));
    }
    Ok(())
}

fn selection_entry_rate_valid(entry: &CompressionCandidateSelectionEntry) -> bool {
    entry
        .total_physical_bytes
        .checked_mul(8)
        .map(|bits| {
            entry.effective_bits_per_value.to_bits()
                == (bits as f64 / entry.logical_values as f64).to_bits()
        })
        .unwrap_or(false)
}

fn validate_physical_components(receipt: &CompressionAdmissionReceipt) -> Result<()> {
    if receipt.physical_components.is_empty() {
        return Err(admission_error(
            "compression admission receipt has no physical components",
        ));
    }
    let mut canonical = receipt.physical_components.clone();
    canonical.sort_by(|left, right| {
        physical_component_identity(left).cmp(&physical_component_identity(right))
    });
    if canonical != receipt.physical_components
        || canonical.windows(2).any(|pair| {
            physical_component_identity(&pair[0]) == physical_component_identity(&pair[1])
        })
    {
        return Err(admission_error(
            "compression admission physical components are not in unique canonical order",
        ));
    }
    let mut total = 0_u64;
    let mut ranges = BTreeMap::<(String, String), Vec<(u64, u64)>>::new();
    for component in &receipt.physical_components {
        if component.role.trim().is_empty()
            || component.container.trim().is_empty()
            || component.relative_path.trim().is_empty()
            || component.length == 0
        {
            return Err(admission_error(
                "compression admission physical component has an empty identity or byte range",
            ));
        }
        decode_hex_32(&component.sha256, "physical component SHA-256")?;
        let end = component
            .offset
            .checked_add(component.length)
            .ok_or_else(|| admission_error("physical component byte range overflow"))?;
        ranges
            .entry((component.container.clone(), component.relative_path.clone()))
            .or_default()
            .push((component.offset, end));
        total = total
            .checked_add(component.length)
            .ok_or_else(|| admission_error("physical component total overflow"))?;
    }
    for ((container, path), ranges) in &mut ranges {
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            return Err(admission_error(format!(
                "compression admission physical components overlap in {container}/{path}"
            )));
        }
    }
    if total != receipt.total_physical_bytes {
        return Err(admission_error(format!(
            "compression admission physical component total {total} differs from receipt total {}",
            receipt.total_physical_bytes
        )));
    }
    Ok(())
}

fn physical_component_identity(component: &CompressionPhysicalComponent) -> String {
    format!(
        "{}/{}@{}+{}",
        component.container, component.relative_path, component.offset, component.length
    )
}

fn validate_query_observations(receipt: &CompressionAdmissionReceipt) -> Result<()> {
    if receipt.queries.len() != receipt.held_out_queries.len() {
        return Err(admission_error(
            "compression admission query observation count differs from held-out inputs",
        ));
    }
    for (input, observation) in receipt.held_out_queries.iter().zip(&receipt.queries) {
        if observation.query_cx_id != input.cx_id
            || observation.exact_top_k.len() != receipt.k as usize
            || observation.packed_top_k.len() != receipt.k as usize
            || observation.latency_samples_ns.len() != receipt.measured_runs as usize
            || observation.latency_samples_ns.contains(&0)
        {
            return Err(admission_error(format!(
                "compression admission query observation for {} has inconsistent identity, hit count, or samples",
                input.cx_id
            )));
        }
        let exact_ids = observation
            .exact_top_k
            .iter()
            .map(|hit| hit.cx_id)
            .collect::<BTreeSet<_>>();
        let packed_ids = observation
            .packed_top_k
            .iter()
            .map(|hit| hit.cx_id)
            .collect::<BTreeSet<_>>();
        if exact_ids.len() != observation.exact_top_k.len()
            || packed_ids.len() != observation.packed_top_k.len()
            || observation
                .exact_top_k
                .iter()
                .any(|hit| !hit.score.is_finite())
            || observation
                .packed_top_k
                .iter()
                .any(|hit| !hit.score.is_finite())
        {
            return Err(admission_error(format!(
                "compression admission query observation for {} has duplicate or non-finite hits",
                input.cx_id
            )));
        }
        let matched = packed_ids.intersection(&exact_ids).count();
        let recall = matched as f64 / receipt.k as f64;
        if observation.recall_at_k.to_bits() != recall.to_bits() {
            return Err(admission_error(format!(
                "compression admission query observation for {} has inconsistent recall",
                input.cx_id
            )));
        }
    }
    Ok(())
}

fn decode_receipt(
    slot: &Slot,
    expected_sha256: [u8; 32],
    bytes: &[u8],
) -> Result<CompressionAdmissionReceipt> {
    let observed: [u8; 32] = Sha256::digest(bytes).into();
    if observed != expected_sha256 {
        return Err(admission_error(format!(
            "compression admission receipt SHA-256 mismatch: key={} value={}",
            hex(&expected_sha256),
            hex(&observed)
        )));
    }
    let receipt: CompressionAdmissionReceipt = serde_json::from_slice(bytes)
        .map_err(|error| admission_error(format!("decode admission receipt: {error}")))?;
    if (receipt.schema != COMPRESSION_ADMISSION_SCHEMA
        && receipt.schema != LEGACY_COMPRESSION_ADMISSION_SCHEMA)
        || receipt.slot_id != slot.slot_id.get()
    {
        return Err(admission_error(
            "compression admission receipt schema/slot identity mismatch",
        ));
    }
    let canonical = serde_json::to_vec(&receipt)
        .map_err(|error| admission_error(format!("re-encode admission receipt: {error}")))?;
    if canonical != bytes {
        return Err(admission_error(
            "compression admission receipt is not canonical JSON for its schema",
        ));
    }
    validate_receipt(slot, &receipt)?;
    Ok(receipt)
}

fn admission_subject(slot: &Slot) -> SubjectId {
    SubjectId::Query(format!("compression-admission:slot:{}", slot.slot_id.get()).into_bytes())
}

fn admission_ledger_payload(
    slot: &Slot,
    receipt_sha256: [u8; 32],
    schema: &str,
    phase: &str,
    verdict: CompressionAdmissionVerdict,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "marker": schema,
        "slot_id": slot.slot_id.get(),
        "receipt_sha256": hex(&receipt_sha256),
        "phase": phase,
        "verdict": verdict,
    }))
    .map_err(|error| admission_error(format!("encode admission ledger payload: {error}")))
}

fn query_digest(queries: &[CompressionQuery]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-query-values-v1");
    for query in queries {
        hasher.update(query.cx_id.as_bytes());
        hasher.update((query.values.len() as u64).to_be_bytes());
        for value in &query.values {
            hasher.update(value.to_bits().to_be_bytes());
        }
    }
    hasher.finalize().into()
}

fn truth_digest(observations: &[CompressionQueryObservation]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-exact-truth-v1");
    for observation in observations {
        hasher.update(observation.query_cx_id.as_bytes());
        hasher.update((observation.exact_top_k.len() as u64).to_be_bytes());
        for hit in &observation.exact_top_k {
            hasher.update(hit.cx_id.as_bytes());
            hasher.update(hit.score.to_bits().to_be_bytes());
        }
    }
    hasher.finalize().into()
}

fn percentile(samples: &[u64], percentile: usize) -> Result<u64> {
    if samples.is_empty() || !(1..=100).contains(&percentile) {
        return Err(admission_error(
            "latency percentile input is empty or invalid",
        ));
    }
    let index = samples
        .len()
        .checked_mul(percentile)
        .ok_or_else(|| admission_error("latency percentile index overflow"))?
        .div_ceil(100)
        .saturating_sub(1);
    Ok(samples[index])
}

fn cosine(left: &[f32], right: &[f32]) -> Result<f64> {
    if left.len() != right.len() || left.is_empty() {
        return Err(admission_error("cosine vectors have incompatible geometry"));
    }
    let mut dot = 0.0_f64;
    let mut left_norm = 0.0_f64;
    let mut right_norm = 0.0_f64;
    for (left, right) in left.iter().zip(right) {
        let left = f64::from(*left);
        let right = f64::from(*right);
        dot += left * right;
        left_norm += left * left;
        right_norm += right * right;
    }
    if left_norm <= 0.0 || right_norm <= 0.0 {
        return Err(admission_error(
            "cosine is undefined for a zero-norm vector",
        ));
    }
    let score = (dot / (left_norm.sqrt() * right_norm.sqrt())).clamp(-1.0, 1.0);
    if !score.is_finite() {
        return Err(admission_error("cosine score is non-finite"));
    }
    Ok(score)
}

fn cx_id_from_key(key: &[u8]) -> Result<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        admission_error(format!(
            "slot row key must be a 16-byte CxId, got {} bytes",
            key.len()
        ))
    })?;
    Ok(CxId::from_bytes(bytes))
}

fn cpu_device_identity() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        format!(
            "os={};arch={};avx2={};avx512f={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("avx512f")
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        format!(
            "os={};arch={}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(admission_error(format!(
            "{field} must be exactly 64 hexadecimal characters"
        )));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| admission_error(format!("{field} contains invalid UTF-8")))?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| admission_error(format!("{field} contains invalid hexadecimal")))?;
    }
    if hex(&bytes) != value {
        return Err(admission_error(format!(
            "{field} must use canonical lowercase hexadecimal"
        )));
    }
    Ok(bytes)
}

fn admission_error(message: impl Into<String>) -> calyx_core::CalyxError {
    compression_error(CALYX_COMPRESSION_ADMISSION_REFUSED, message)
}
