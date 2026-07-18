//! Durable SPANN posting generations: bounded canonical payloads in immutable
//! zstd segments, atomically committed by an authenticated active manifest.

mod codec;
mod config;
mod format;
mod lease;
mod manifest;
mod store;

pub(super) use format::publish_synced_file_atomic;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use calyx_core::{CxId, Result, SlotId, SlotShape, SlotVector, SparseEntry};

use super::centroids::SpannCentroidIndex;
use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_DIM_MISMATCH, CALYX_INDEX_INVALID_PARAMS, CALYX_INDEX_IO,
    CALYX_SEXTANT_INDEX_EMPTY, CALYX_SEXTANT_VECTOR_SHAPE, sextant_error,
};
use crate::index::distance::l2_sq;
use crate::index::{IndexSearchHit, IndexStats, SextantIndex, ranked};
pub use codec::{decode_posting_block, encode_posting_block};
pub use config::{
    SPANN_ACTIVE_MAGIC, SPANN_MANIFEST_MAGIC, SPANN_POSTING_FORMAT_VERSION,
    SPANN_POSTING_SEGMENT_MAGIC, SPANN_STATE_SEGMENT_MAGIC, SpannDistanceMetric,
    SpannIndexIdentity, SpannPostingLimits,
};
use store::PostingStore;
pub use store::{SpannPostingPhysicalStats, SpannPostingWriteReceipt};

/// One member of a SPANN posting list: its stable local id plus the sparse
/// vector used for query-dependent squared-L2 ranking.
#[derive(Clone, Debug, PartialEq)]
pub struct PostingMember {
    pub cx_id: u32,
    pub vector: Vec<(u32, f32)>,
}

impl PostingMember {
    pub fn new(cx_id: u32, vector: Vec<(u32, f32)>) -> Self {
        Self { cx_id, vector }
    }
}

/// Low-level durable writer using the same generation store as `SpannSearch`.
#[derive(Debug)]
pub struct PostingListWriter {
    store: PostingStore,
}

/// Low-level durable reader. It validates the complete declared generation on
/// open and caches materialized postings under the sealed registry budget.
#[derive(Debug)]
pub struct PostingListReader {
    store: PostingStore,
}

#[derive(Debug)]
pub struct SpannSearch {
    slot: SlotId,
    dim: u32,
    centroids: SpannCentroidIndex,
    store: PostingStore,
    default_n_probe: usize,
    boundary_epsilon: f32,
    max_replication: usize,
    base_seq: u64,
}

impl PostingListWriter {
    pub fn create_or_open(
        slot: SlotId,
        centroids: &SpannCentroidIndex,
        dir: impl Into<PathBuf>,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        let identity = SpannIndexIdentity::from_centroids(slot, centroids)?;
        Ok(Self {
            store: PostingStore::create_or_open(dir.into(), identity, limits)?,
        })
    }

    pub fn upsert(
        &mut self,
        cx_id: CxId,
        vector: Vec<(u32, f32)>,
        memberships: Vec<u32>,
        seq: u64,
    ) -> Result<SpannPostingWriteReceipt> {
        self.store.upsert(cx_id, vector, memberships, seq)
    }

    pub fn compact(&mut self) -> Result<SpannPostingWriteReceipt> {
        self.store.compact_all()
    }

    pub fn physical_stats(&self) -> Result<SpannPostingPhysicalStats> {
        self.store.physical_stats()
    }
}

impl PostingListReader {
    pub fn open(
        slot: SlotId,
        centroids: &SpannCentroidIndex,
        dir: impl Into<PathBuf>,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        let identity = SpannIndexIdentity::from_centroids(slot, centroids)?;
        Ok(Self {
            store: PostingStore::open_existing(dir.into(), identity, limits)?,
        })
    }

    pub fn read_list(&self, centroid_id: u32) -> Result<Vec<PostingMember>> {
        self.store
            .read_lists(std::iter::once(centroid_id))?
            .into_iter()
            .next()
            .map(|(_, members)| members.as_ref().clone())
            .ok_or_else(|| corrupt(format!("centroid {centroid_id} was not read")))
    }

    pub fn read_lists(
        &self,
        centroid_ids: impl IntoIterator<Item = u32>,
    ) -> Result<Vec<(u32, Vec<PostingMember>)>> {
        Ok(self
            .store
            .read_lists(centroid_ids)?
            .into_iter()
            .map(|(centroid, members)| (centroid, members.as_ref().clone()))
            .collect())
    }

    pub fn physical_stats(&self) -> Result<SpannPostingPhysicalStats> {
        self.store.physical_stats()
    }
}

impl SpannSearch {
    pub fn new(
        slot: SlotId,
        centroids: SpannCentroidIndex,
        posting_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::new_with_limits(
            slot,
            centroids,
            posting_dir,
            SpannPostingLimits::production(),
        )
    }

    pub fn new_with_limits(
        slot: SlotId,
        centroids: SpannCentroidIndex,
        posting_dir: impl Into<PathBuf>,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        let posting_dir = posting_dir.into();
        let identity = SpannIndexIdentity::from_centroids(slot, &centroids)?;
        let store = PostingStore::create_or_open(posting_dir, identity, limits)?;
        Ok(Self::from_store(slot, centroids, store))
    }

    pub fn open(
        slot: SlotId,
        centroid_dir: impl AsRef<Path>,
        posting_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::open_with_limits(
            slot,
            centroid_dir,
            posting_dir,
            SpannPostingLimits::production(),
        )
    }

    pub fn open_with_limits(
        slot: SlotId,
        centroid_dir: impl AsRef<Path>,
        posting_dir: impl Into<PathBuf>,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        let centroids =
            SpannCentroidIndex::open_with_max_bytes(centroid_dir, limits.max_centroid_file_bytes)?;
        let identity = SpannIndexIdentity::from_centroids(slot, &centroids)?;
        let store = PostingStore::open_existing(posting_dir.into(), identity, limits)?;
        Ok(Self::from_store(slot, centroids, store))
    }

    fn from_store(slot: SlotId, centroids: SpannCentroidIndex, store: PostingStore) -> Self {
        let boundary_epsilon = f32::from_bits(store.limits().boundary_epsilon_bits);
        let max_replication = usize::from(store.limits().max_replication);
        Self {
            slot,
            dim: centroids.dim(),
            centroids,
            base_seq: store.base_seq(),
            store,
            default_n_probe: 8,
            boundary_epsilon,
            max_replication,
        }
    }

    pub fn with_default_n_probe(mut self, n_probe: usize) -> Result<Self> {
        if n_probe == 0 {
            return Err(invalid("default n_probe must be positive"));
        }
        self.default_n_probe = n_probe;
        Ok(self)
    }

    pub fn with_boundary_duplication(
        mut self,
        epsilon: f32,
        max_replication: usize,
    ) -> Result<Self> {
        if !epsilon.is_finite() || epsilon < 0.0 || max_replication == 0 {
            return Err(invalid(format!(
                "boundary epsilon {epsilon} and max replication {max_replication} must be finite/nonnegative and positive"
            )));
        }
        if epsilon.to_bits() != self.store.limits().boundary_epsilon_bits
            || max_replication != usize::from(self.store.limits().max_replication)
        {
            return Err(invalid(
                "boundary routing is sealed in SpannPostingLimits; create/open with the intended registry values",
            ));
        }
        self.boundary_epsilon = epsilon;
        self.max_replication = max_replication;
        Ok(self)
    }

    /// Probes a validated batch of postings once and ranks their union by the
    /// same squared-L2 metric used for training and routing.
    pub fn search(&self, query: &[f32], k: usize, n_probe: usize) -> Result<Vec<(u32, f32)>> {
        if k == 0 {
            return Ok(Vec::new());
        }
        if self.centroids.centroid_count() == 0 {
            return Err(sextant_error(
                CALYX_SEXTANT_INDEX_EMPTY,
                "spann search requires at least one centroid",
            ));
        }
        if n_probe == 0 {
            return Err(invalid("spann search n_probe must be positive"));
        }
        validate_query(self.dim, query)?;
        let centroid_ids = self
            .centroids
            .nearest_centroids_raw_l2_graph(query, n_probe)?;
        let expected = n_probe.min(self.centroids.centroid_count());
        if centroid_ids.len() != expected {
            return Err(corrupt(format!(
                "squared-L2 centroid router returned {} routes, expected {expected}",
                centroid_ids.len()
            )));
        }
        let query_norm_sq: f32 = query.iter().map(|value| value * value).sum();
        if !query_norm_sq.is_finite() {
            return Err(invalid("query norm is non-finite"));
        }
        let lists = self.store.read_lists(centroid_ids)?;
        let mut best = BTreeMap::<u32, f32>::new();
        for (_, members) in lists {
            for member in members.iter() {
                let mut dot = 0.0_f32;
                let mut member_norm_sq = 0.0_f32;
                for (idx, val) in &member.vector {
                    let qi = *query.get(*idx as usize).ok_or_else(|| {
                        corrupt(format!(
                            "posting member dimension {idx} outside query dim {}",
                            query.len()
                        ))
                    })?;
                    dot += qi * val;
                    member_norm_sq += val * val;
                }
                let distance = query_norm_sq - 2.0 * dot + member_norm_sq;
                if !distance.is_finite() {
                    return Err(corrupt(format!(
                        "non-finite squared-L2 score for local id {}",
                        member.cx_id
                    )));
                }
                let similarity = -distance.max(0.0);
                best.entry(member.cx_id)
                    .and_modify(|existing| *existing = existing.max(similarity))
                    .or_insert(similarity);
            }
        }
        let mut hits = best.into_iter().collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        hits.truncate(k);
        Ok(hits)
    }

    pub fn posting_dir(&self) -> &Path {
        self.store.dir()
    }

    pub fn centroids(&self) -> &SpannCentroidIndex {
        &self.centroids
    }

    pub fn physical_stats(&self) -> Result<SpannPostingPhysicalStats> {
        self.store.physical_stats()
    }

    pub fn last_write(&self) -> Option<&SpannPostingWriteReceipt> {
        self.store.last_write()
    }

    pub fn verify_storage(&self) -> Result<()> {
        self.store.verify_all_postings()
    }
}

impl SextantIndex for SpannSearch {
    fn slot(&self) -> SlotId {
        self.slot
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Sparse(self.dim)
    }

    fn insert(&mut self, cx_id: CxId, vector: SlotVector, seq: u64) -> Result<()> {
        if self.centroids.centroid_count() == 0 {
            return Err(sextant_error(
                CALYX_SEXTANT_INDEX_EMPTY,
                "spann insert requires at least one centroid",
            ));
        }
        let dense = dense_sparse(self.dim, &vector)?;
        let sparse = sparse_pairs(&vector)?;
        let memberships = boundary_centroids(
            &self.centroids,
            &dense,
            self.boundary_epsilon,
            self.max_replication,
        )?;
        self.store.upsert(cx_id, sparse, memberships, seq)?;
        self.base_seq = self.base_seq.max(seq);
        Ok(())
    }

    fn search(
        &self,
        query: &SlotVector,
        k: usize,
        ef: Option<usize>,
    ) -> Result<Vec<IndexSearchHit>> {
        let dense = dense_sparse(self.dim, query)?;
        let n_probe = ef.unwrap_or(self.default_n_probe);
        let mut hits = Vec::new();
        for (local, score) in SpannSearch::search(self, &dense, k, n_probe)? {
            hits.push((self.store.cx_for_local(local)?, score));
        }
        Ok(ranked(hits))
    }

    fn rebuild(&mut self) -> Result<()> {
        self.store.compact_all()?;
        Ok(())
    }

    fn vector(&self, cx_id: CxId) -> Option<SlotVector> {
        self.store
            .record_for_cx(cx_id)
            .map(|record| SlotVector::Sparse {
                dim: self.dim,
                entries: record
                    .vector
                    .iter()
                    .map(|(idx, val)| SparseEntry {
                        idx: *idx,
                        val: *val,
                    })
                    .collect(),
            })
    }

    fn set_base_seq(&mut self, seq: u64) {
        self.base_seq = seq;
    }

    fn stats(&self) -> IndexStats {
        IndexStats {
            slot: self.slot,
            shape: self.shape(),
            len: self.store.len(),
            built_at_seq: self.store.built_at_seq(),
            base_seq: self.base_seq,
            kind: "SPANN",
        }
    }
}

fn dense_sparse(dim: u32, vector: &SlotVector) -> Result<Vec<f32>> {
    vector.validate_schema()?;
    let SlotVector::Sparse { dim: vdim, entries } = vector else {
        return Err(sextant_error(
            CALYX_SEXTANT_VECTOR_SHAPE,
            "spann requires sparse vectors",
        ));
    };
    if *vdim != dim {
        return Err(sextant_error(
            CALYX_INDEX_DIM_MISMATCH,
            format!("sparse dim {vdim} expected {dim}"),
        ));
    }
    let mut dense = vec![0.0_f32; dim as usize];
    for entry in entries {
        dense[entry.idx as usize] = entry.val;
    }
    Ok(dense)
}

fn sparse_pairs(vector: &SlotVector) -> Result<Vec<(u32, f32)>> {
    let SlotVector::Sparse { entries, .. } = vector else {
        return Err(sextant_error(
            CALYX_SEXTANT_VECTOR_SHAPE,
            "spann requires sparse vectors",
        ));
    };
    let mut pairs = entries
        .iter()
        .map(|entry| (entry.idx, entry.val))
        .collect::<Vec<_>>();
    pairs.sort_by_key(|(idx, _)| *idx);
    Ok(pairs)
}

fn validate_query(dim: u32, query: &[f32]) -> Result<()> {
    if query.len() != dim as usize {
        return Err(sextant_error(
            CALYX_INDEX_DIM_MISMATCH,
            format!("query dim {} expected {dim}", query.len()),
        ));
    }
    if query.iter().any(|value| !value.is_finite()) {
        return Err(invalid("query has non-finite component"));
    }
    Ok(())
}

fn boundary_centroids(
    centroids: &SpannCentroidIndex,
    vector: &[f32],
    epsilon: f32,
    max_replication: usize,
) -> Result<Vec<u32>> {
    if centroids.centroid_count() == 0 || vector.len() != centroids.dim() as usize {
        return Err(invalid(
            "boundary routing requires non-empty matching centroids",
        ));
    }
    if !epsilon.is_finite() || epsilon < 0.0 || max_replication == 0 {
        return Err(invalid("boundary routing parameters are invalid"));
    }
    let mut scored = centroids
        .centroids()
        .iter()
        .enumerate()
        .map(|(idx, centroid)| (idx as u32, l2_sq(centroid, vector)))
        .collect::<Vec<_>>();
    if scored.iter().any(|(_, distance)| !distance.is_finite()) {
        return Err(invalid("boundary squared-L2 distance is non-finite"));
    }
    scored.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let nearest = scored[0].1;
    let threshold = nearest * (1.0 + epsilon);
    if !threshold.is_finite() {
        return Err(invalid("boundary threshold is non-finite"));
    }
    let mut selected = scored
        .iter()
        .copied()
        .filter(|(_, distance)| *distance <= threshold)
        .take(max_replication)
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(corrupt("boundary router selected no centroid"));
    }
    selected.sort_unstable();
    Ok(selected)
}

fn invalid(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_INVALID_PARAMS,
        format!("spann postings: {detail}"),
    )
}

fn corrupt(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_CORRUPT,
        format!("spann posting generation corrupt: {detail}"),
    )
}

fn io(stage: &str, error: std::io::Error) -> calyx_core::CalyxError {
    sextant_error(CALYX_INDEX_IO, format!("spann postings {stage}: {error}"))
}
