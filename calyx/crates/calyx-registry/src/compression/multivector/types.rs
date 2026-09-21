use calyx_core::{CxId, LedgerRef, QuantPolicy, Seq};
use serde::{Deserialize, Serialize};

use super::{CALYX_MULTIVECTOR_PACK_INVALID, multivector_error};

/// The one commissioned multi-vector storage representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiVectorStorageCodec {
    /// ColBERTv2 centroid code plus a two-bit residual per component.
    ColbertResidual2BitV1,
}

impl MultiVectorStorageCodec {
    /// Stable catalog/ledger label.
    pub const fn catalog_label(self) -> &'static str {
        match self {
            Self::ColbertResidual2BitV1 => "colbert_residual_2bit_v1",
        }
    }
}

/// Explicit, persisted training and admission bounds for one generation.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiVectorCompressionConfig {
    /// Maximum tokens allowed in any document or query.
    pub max_tokens: u32,
    /// Maximum token-vector dimension admitted by this generation.
    pub max_token_dim: u32,
    /// Number of corpus-trained centroids.
    pub centroid_count: u32,
    /// Deterministic Lloyd refinement iterations.
    pub kmeans_iterations: u32,
    /// Maximum admitted absolute MaxSim score error.
    pub max_score_error: f32,
}

impl MultiVectorCompressionConfig {
    pub(super) fn validate(self, token_dim: u32) -> calyx_core::Result<()> {
        if token_dim == 0 || !token_dim.is_multiple_of(4) {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!(
                    "two-bit residual packing requires positive token_dim divisible by four, got {token_dim}"
                ),
            ));
        }
        if self.max_tokens == 0 {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                "max_tokens must be greater than zero",
            ));
        }
        if self.max_token_dim == 0
            || !self.max_token_dim.is_multiple_of(4)
            || token_dim > self.max_token_dim
        {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!(
                    "token_dim {token_dim} exceeds or is incompatible with declared max_token_dim {}",
                    self.max_token_dim
                ),
            ));
        }
        if self.centroid_count == 0 {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                "centroid_count must be greater than zero",
            ));
        }
        if self.kmeans_iterations == 0 {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                "kmeans_iterations must be greater than zero",
            ));
        }
        if !self.max_score_error.is_finite() || self.max_score_error < 0.0 {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!(
                    "max_score_error must be finite and non-negative, got {}",
                    self.max_score_error
                ),
            ));
        }
        Ok(())
    }
}

/// One exact raw-F32 document token matrix.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultiVectorCompressionRow {
    pub cx_id: CxId,
    pub tokens: Vec<Vec<f32>>,
}

/// One independently identified raw-F32 admission query.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultiVectorCompressionQuery {
    pub cx_id: CxId,
    pub tokens: Vec<Vec<f32>>,
}

/// One persisted row returned in a generation report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PackedMultiVectorRow {
    pub cx_id: CxId,
    pub token_count: u32,
    pub raw_bytes: Vec<u8>,
    pub packed_bytes: Vec<u8>,
}

/// Complete byte accounting for one committed generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedMultiVectorBytes {
    pub raw_sidecar_value_bytes: usize,
    pub packed_row_value_bytes: usize,
    pub row_header_bytes: usize,
    pub centroid_code_bytes: usize,
    pub residual_bytes: usize,
    pub row_checksum_bytes: usize,
    pub codebook_bytes: usize,
    pub manifest_value_bytes: usize,
    pub lifecycle_value_bytes: usize,
    pub ledger_value_bytes: usize,
    pub key_bytes: usize,
    /// Values and keys accounted above. Storage-engine/WAL framing is measured
    /// from the durable vault directory during FSV, never estimated here.
    pub accounted_bytes: usize,
}

/// Measured result of an admitted packed generation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultiVectorCompressionReport {
    pub slot_id: u16,
    pub slot_key: String,
    pub requested_quant: QuantPolicy,
    pub stored_codec: MultiVectorStorageCodec,
    pub config: MultiVectorCompressionConfig,
    pub generation_rows: u32,
    pub total_tokens: u64,
    pub admission_queries: u32,
    pub admission_k: u32,
    pub recall_at_k_raw: f32,
    pub recall_at_k_packed: f32,
    pub recall_drop: f32,
    pub max_abs_score_error: f32,
    pub mean_abs_score_error: f32,
    pub exact_ranking_root_sha256: [u8; 32],
    pub packed_ranking_root_sha256: [u8; 32],
    pub scoring_backend: String,
    pub bytes: PackedMultiVectorBytes,
    pub rows: Vec<PackedMultiVectorRow>,
    pub generation_manifest_bytes: Vec<u8>,
    pub snapshot: Option<Seq>,
    pub ledger: Option<LedgerRef>,
}

/// One direct packed-search hit.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PackedMultiVectorHit {
    pub cx_id: CxId,
    pub score: f32,
}

/// Caller-owned bounded scratch for direct packed MaxSim.
#[derive(Clone, Debug, Default)]
pub struct PackedMaxSimScratch {
    pub(super) decoded_token: Vec<f32>,
    pub(super) maxima: Vec<f32>,
    pub(super) normalized_query: Vec<f32>,
    pub(super) query_tokens: usize,
}

impl PackedMaxSimScratch {
    /// Currently allocated scratch bytes (capacities, not logical lengths).
    pub fn allocated_bytes(&self) -> usize {
        (self.decoded_token.capacity() + self.maxima.capacity() + self.normalized_query.capacity())
            * std::mem::size_of::<f32>()
    }
}
