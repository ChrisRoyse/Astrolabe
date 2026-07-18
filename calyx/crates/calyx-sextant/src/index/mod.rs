//! Per-slot index trait and implementations.

use calyx_core::{CxId, Result, SlotId, SlotShape, SlotVector};
use serde::{Deserialize, Serialize};

pub mod autotune;
pub mod bm25;
pub mod cuvs_bruteforce;
pub mod diskann;
pub mod distance;
pub mod dual;
pub mod funnel;
pub mod hnsw;
pub mod inverted;
pub mod multi;
pub mod partitioned;
pub mod quant_config;
pub mod spann;
#[doc(hidden)]
pub mod testutil;
pub mod tokenizer;
pub mod vecfile;

pub use autotune::{
    BwPostcutoffAnnealRegistry, BwPostcutoffConfig, BwPostcutoffTuner, TuneDirection,
    TunerAdjustment, TunerAdjustmentKind, TunerConfig, TunerLedgerEntry, TunerObservation,
    TunerRange, TunerWarning, register_with_anneal,
};
pub use cuvs_bruteforce::{CuvsBruteForceTopK, cuvs_bruteforce_topk};
pub use diskann::{
    ConcatCrossTermDiskAnn, ConcatCrossTermHit, ConcatCrossTermKey, DISKANN_GENERATION_MAGIC,
    DISKANN_GENERATION_VERSION, Direction, DirectionalBoost, DiskAnnBuildBackend,
    DiskAnnBuildParams, DiskAnnBuildProgress, DiskAnnGeneration, DiskAnnGraphReader, DiskAnnHeader,
    DiskAnnMetric, DiskAnnNodeRef, DiskAnnPqBuildParams, DiskAnnPqIndex, DiskAnnPqSearchBuild,
    DiskAnnRawIndex, DiskAnnSearch, DiskAnnSearchParams, DiskAnnVectorEncoding, DualDiskAnnSearch,
    TokenDiskAnnMaxSim, build_diskann_graph, build_diskann_graph_with_backend,
    build_diskann_graph_with_backend_and_progress, build_dual, build_dual_with_search,
    dual_graph_path, node_block_size, open_diskann_graph, open_dual,
};
pub use distance::{cosine_distance, dot, kernel_backend, l2_normalize, l2_sq};
pub use dual::{DualIndex, DualSide};
pub use funnel::{
    FUNNEL_MIN_VAULT_SIZE, FinalCxSearch, FunnelHit, FunnelParams, FunnelPath, KernelFirstSearch,
    KernelRegion, KernelRegionAnn, KernelRegionId, LocalCxId, RegionCandidate, RegionId,
    RegionPartitions,
};
pub use hnsw::{
    HNSW_ACTIVE_POINTER_MAGIC, HNSW_ACTIVE_POINTER_VERSION, HNSW_ARTIFACT_MAGIC,
    HNSW_ARTIFACT_VERSION, HNSW_MAX_DIM, HnswActivePointer, HnswArtifactActivator,
    HnswArtifactExpectation, HnswArtifactMetadata, HnswArtifactReceipt, HnswIndex,
};
pub use inverted::InvertedIndex;
pub use multi::MaxSimIndex;
pub use partitioned::{
    DEFAULT_FINAL_ASSIGNMENT_PROBE, FbinSource, I8BinSource, PartitionBuildParams,
    PartitionDistanceMetric, PartitionedManifest, PartitionedManifestDbReadback, PartitionedSearch,
    PartitionedSearchOptions, PartitionedSearchReadback, RegionMeta, SyntheticSource, VectorSource,
    VectorSourceIdentity, build_partitioned_vault, build_partitioned_vault_from_source,
    build_partitioned_vault_from_source_with_backend,
    build_partitioned_vault_from_source_with_backend_and_metric,
    build_partitioned_vault_with_backend, gen_row, partitioned_manifest_db_exists,
    partitioned_manifest_db_readback,
};
pub use quant_config::{
    PackedQuery, PackedVector, QuantConfig, QuantKind, SEXTANT_QUANT_LAYOUT_VERSION, score_packed,
};
pub use spann::{
    PostingListReader, PostingListWriter, PostingMember, SPANN_ACTIVE_MAGIC, SPANN_CENTROID_MAGIC,
    SPANN_MANIFEST_MAGIC, SPANN_POSTING_FORMAT_VERSION, SPANN_POSTING_SEGMENT_MAGIC,
    SPANN_STATE_SEGMENT_MAGIC, SpannCentroidIndex, SpannDistanceMetric, SpannIndexIdentity,
    SpannPostingLimits, SpannPostingPhysicalStats, SpannPostingWriteReceipt, SpannSearch,
    build_centroids, decode_posting_block, encode_posting_block,
};
pub use testutil::{SyntheticVault, build_synthetic_vault, synthetic_dense_rows};
pub use vecfile::{
    DenseVectorFile, FbinVectors, FbinWriter, I8BIN_MAGIC, I8BinVectors, I8BinWriter, I32BinMatrix,
    VEC_HEADER_LEN, VEC_MAGIC, VEC_MAGIC_LEGACY_V1, VECTOR_FILE_MAX_DIM, VectorFileFormat,
    VectorFileIdentity,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexSearchHit {
    pub cx_id: CxId,
    pub score: f32,
    pub rank: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStats {
    pub slot: SlotId,
    pub shape: SlotShape,
    pub len: usize,
    pub built_at_seq: u64,
    pub base_seq: u64,
    pub kind: &'static str,
}

pub trait SextantIndex: Send + Sync {
    fn slot(&self) -> SlotId;
    fn shape(&self) -> SlotShape;
    fn insert(&mut self, cx_id: CxId, vector: SlotVector, seq: u64) -> Result<()>;
    fn search(
        &self,
        query: &SlotVector,
        k: usize,
        ef: Option<usize>,
    ) -> Result<Vec<IndexSearchHit>>;
    fn rebuild(&mut self) -> Result<()>;
    fn vector(&self, cx_id: CxId) -> Option<SlotVector>;
    fn set_base_seq(&mut self, seq: u64);
    fn stats(&self) -> IndexStats;
    fn insert_text(&mut self, _cx_id: CxId, _text: &str, _seq: u64) -> Result<()> {
        Err(crate::error::sextant_error(
            crate::error::CALYX_SEXTANT_VECTOR_SHAPE,
            "index does not accept text",
        ))
    }

    fn search_text(&self, _text: &str, _k: usize) -> Result<Vec<IndexSearchHit>> {
        Err(crate::error::sextant_error(
            crate::error::CALYX_SEXTANT_VECTOR_SHAPE,
            "index does not search text",
        ))
    }

    fn candidate_text(&self, _cx_id: CxId) -> Option<String> {
        None
    }
}

pub fn ranked(scored: Vec<(CxId, f32)>) -> Vec<IndexSearchHit> {
    scored
        .into_iter()
        .enumerate()
        .map(|(idx, (cx_id, score))| IndexSearchHit {
            cx_id,
            score,
            rank: idx + 1,
        })
        .collect()
}
