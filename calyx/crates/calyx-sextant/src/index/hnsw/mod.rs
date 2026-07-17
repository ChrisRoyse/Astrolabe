//! Deterministic in-RAM dense HNSW-style index.

mod activation;
mod artifact;
mod graph;
mod scored;

pub use activation::{
    HNSW_ACTIVE_POINTER_MAGIC, HNSW_ACTIVE_POINTER_VERSION, HnswActivePointer,
    HnswArtifactActivator,
};
pub use artifact::{
    HNSW_ARTIFACT_MAGIC, HNSW_ARTIFACT_VERSION, HnswArtifactExpectation, HnswArtifactMetadata,
    HnswArtifactReceipt,
};

/// Largest dense dimension accepted by the in-memory and persisted HNSW
/// contract. This matches Calyx's frozen vector/quantization ceiling and keeps
/// artifact size arithmetic and per-query scratch bounded.
pub const HNSW_MAX_DIM: u32 = 4_096;

use std::collections::HashMap;

use calyx_aster::gc::{AnnIndexGraph, AnnTombstoneStats};
use calyx_core::{CxId, Result, SlotId, SlotShape, SlotVector};

use super::quant_config::{PackedQuery, PackedVector, score_packed};
use super::{IndexSearchHit, IndexStats, QuantConfig, SextantIndex, ranked};
use crate::error::{
    CALYX_SEXTANT_DIM_MISMATCH, CALYX_SEXTANT_EF_TOO_SMALL, CALYX_SEXTANT_INDEX_EMPTY,
    CALYX_SEXTANT_VECTOR_SHAPE, sextant_error,
};
use crate::util::{dense, top_k};

#[derive(Clone, Debug)]
struct Row {
    cx_id: CxId,
    /// Physically packed per-row storage: the configured quantizer changes
    /// these bytes and the scoring kernel (layout v1, see `quant_config`).
    stored: PackedVector,
    seq: u64,
    level: u8,
    neighbors: Vec<usize>,
    deleted: bool,
}

#[derive(Clone, Debug)]
pub struct HnswIndex {
    slot: SlotId,
    dim: u32,
    seed: u64,
    max_neighbors: usize,
    rows: Vec<Row>,
    positions: HashMap<CxId, usize>,
    fingerprints: HashMap<[u8; 32], Vec<usize>>,
    entry_point: Option<usize>,
    quant: QuantConfig,
    built_at_seq: u64,
    base_seq: u64,
}

impl HnswIndex {
    pub fn new(slot: SlotId, dim: u32, seed: u64) -> Self {
        Self {
            slot,
            dim,
            seed,
            max_neighbors: 32,
            rows: Vec::new(),
            positions: HashMap::new(),
            fingerprints: HashMap::new(),
            entry_point: None,
            quant: QuantConfig::none(),
            built_at_seq: 0,
            base_seq: 0,
        }
    }

    pub fn with_quant(mut self, quant: QuantConfig) -> Self {
        self.quant = quant;
        self
    }

    fn validate_configuration(&self) -> Result<()> {
        self.quant.validate()?;
        if self.dim == 0 || self.dim > HNSW_MAX_DIM {
            return Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                format!(
                    "hnsw dimension {} is outside the supported range 1..={HNSW_MAX_DIM}",
                    self.dim
                ),
            ));
        }
        Ok(())
    }

    pub fn neighbor_counts(&self) -> Vec<usize> {
        self.rows.iter().map(|row| row.neighbors.len()).collect()
    }

    pub fn total_nodes(&self) -> usize {
        self.rows.len()
    }

    pub fn live_len(&self) -> usize {
        self.rows.iter().filter(|row| !row.deleted).count()
    }

    pub fn tombstone_count(&self) -> usize {
        self.rows.iter().filter(|row| row.deleted).count()
    }

    pub fn tombstone_ratio(&self) -> f64 {
        if self.rows.is_empty() {
            0.0
        } else {
            self.tombstone_count() as f64 / self.rows.len() as f64
        }
    }

    pub fn mark_deleted(&mut self, cx_id: CxId, seq: u64) -> Result<bool> {
        let Some(&index) = self.positions.get(&cx_id) else {
            return Ok(false);
        };
        if self.rows[index].deleted {
            self.base_seq = self.base_seq.max(seq);
            return Ok(false);
        }
        self.remove_fingerprint(index);
        self.rows[index].deleted = true;
        self.rows[index].seq = seq;
        self.base_seq = self.base_seq.max(seq);
        Ok(true)
    }

    pub fn purge_tombstones(&mut self) -> Result<usize> {
        let before = self.rows.len();
        self.rows.retain(|row| !row.deleted);
        self.rebuild_lookup_maps();
        self.rebuild()?;
        Ok(before - self.rows.len())
    }

    pub fn clone_without_tombstones(&self) -> Result<Self> {
        let mut clone = self.clone();
        clone.purge_tombstones()?;
        Ok(clone)
    }

    pub fn layer_histogram(&self) -> Vec<usize> {
        let max = self.rows.iter().map(|row| row.level).max().unwrap_or(0) as usize;
        let mut hist = vec![0; max + 1];
        for row in &self.rows {
            hist[row.level as usize] += 1;
        }
        hist
    }

    pub fn brute_force(&self, query: &[f32], k: usize) -> Vec<(CxId, f32)> {
        let prepared = self.quant.prepare_query(query);
        top_k(
            self.rows
                .iter()
                .enumerate()
                .filter(|(_, row)| !row.deleted)
                .map(|(idx, row)| (row.cx_id, self.score_row(&prepared, idx)))
                .collect(),
            k,
        )
    }

    /// Total packed vector payload bytes physically held by this index.
    pub fn physical_vector_bytes(&self) -> usize {
        self.rows
            .iter()
            .map(|row| row.stored.physical_bytes())
            .sum()
    }

    /// The quantization policy this index physically stores and scores with.
    pub fn quant_config(&self) -> &QuantConfig {
        &self.quant
    }

    /// Scores one prepared query against one packed row directly.
    ///
    /// The query is always prepared by this index's own `QuantConfig` and row
    /// dimensions are validated at insert, so a pairing failure here is an
    /// internal invariant violation, not a caller state.
    pub(super) fn score_row(&self, query: &PackedQuery, idx: usize) -> f32 {
        match score_packed(query, &self.rows[idx].stored) {
            Ok(score) => score,
            Err(error) => unreachable!(
                "packed scoring invariant violated inside HnswIndex: {}",
                error.message
            ),
        }
    }

    /// Builds the construction-time query for an already-inserted row from its
    /// packed representation (no raw vector is retained).
    pub(super) fn construction_query(&self, index: usize) -> PackedQuery {
        match &self.rows[index].stored {
            PackedVector::F32 { values } => self.quant.prepare_query(values),
            PackedVector::Scalar8 { .. } => {
                let approx = self.rows[index].stored.approx_f32();
                self.quant.prepare_query(&approx)
            }
            PackedVector::Binary { bits, dim } => PackedQuery::Binary {
                bits: bits.clone(),
                dim: *dim,
            },
        }
    }

    pub fn recall_at(&self, queries: &[Vec<f32>], k: usize, ef: usize) -> f32 {
        if queries.is_empty() {
            return 1.0;
        }
        let mut total = 0.0;
        for query in queries {
            let exact: Vec<_> = self
                .brute_force(query, k)
                .into_iter()
                .map(|x| x.0)
                .collect();
            let got: Vec<_> = self
                .search(
                    &SlotVector::Dense {
                        dim: self.dim,
                        data: query.clone(),
                    },
                    k,
                    Some(ef),
                )
                .unwrap()
                .into_iter()
                .map(|x| x.cx_id)
                .collect();
            let overlap = got.iter().filter(|cx| exact.contains(cx)).count();
            total += overlap as f32 / k.max(1) as f32;
        }
        total / queries.len() as f32
    }

    fn level_for(&self, cx_id: CxId, ordinal: usize) -> u8 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(cx_id.as_bytes());
        hasher.update(&self.seed.to_be_bytes());
        hasher.update(&(ordinal as u64).to_be_bytes());
        let byte = hasher.finalize().as_bytes()[0];
        byte.trailing_zeros().min(6) as u8
    }

    fn checked_query<'a>(&self, query: &'a SlotVector) -> Result<&'a [f32]> {
        self.validate_configuration()?;
        let values = dense(query)?;
        if values.len() != self.dim as usize {
            return Err(sextant_error(
                CALYX_SEXTANT_DIM_MISMATCH,
                format!("query dim {} expected {}", values.len(), self.dim),
            ));
        }
        if values.iter().any(|value| !value.is_finite()) {
            return Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                "hnsw query contains a non-finite coordinate",
            ));
        }
        Ok(values)
    }

    fn exact_vector_hits(
        &self,
        packed_query: &PackedVector,
        prepared: &PackedQuery,
    ) -> Vec<(CxId, f32)> {
        let identity = packed_query.identity_bytes();
        self.fingerprints
            .get(&packed_fingerprint(packed_query))
            .into_iter()
            .flat_map(|indices| indices.iter())
            .filter(|idx| {
                self.rows
                    .get(**idx)
                    .is_some_and(|row| !row.deleted && row.stored.identity_bytes() == identity)
            })
            .map(|idx| (self.rows[*idx].cx_id, self.score_row(prepared, *idx)))
            .collect()
    }

    fn index_fingerprint(&mut self, index: usize) {
        let fingerprint = packed_fingerprint(&self.rows[index].stored);
        self.fingerprints
            .entry(fingerprint)
            .or_default()
            .push(index);
    }

    fn remove_fingerprint(&mut self, index: usize) {
        let fingerprint = packed_fingerprint(&self.rows[index].stored);
        if let Some(indices) = self.fingerprints.get_mut(&fingerprint) {
            indices.retain(|idx| *idx != index);
            if indices.is_empty() {
                self.fingerprints.remove(&fingerprint);
            }
        }
    }

    fn rebuild_lookup_maps(&mut self) {
        self.positions.clear();
        self.fingerprints.clear();
        for idx in 0..self.rows.len() {
            self.positions.insert(self.rows[idx].cx_id, idx);
            self.index_fingerprint(idx);
        }
    }
}

impl SextantIndex for HnswIndex {
    fn slot(&self) -> SlotId {
        self.slot
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(self.dim)
    }

    fn insert(&mut self, cx_id: CxId, vector: SlotVector, seq: u64) -> Result<()> {
        self.validate_configuration()?;
        let values = dense(&vector)?;
        if values.len() != self.dim as usize {
            return Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                format!("dim {} expected {}", values.len(), self.dim),
            ));
        }
        if values.iter().any(|value| !value.is_finite()) {
            return Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                "hnsw insert contains a non-finite coordinate",
            ));
        }
        self.quant.lock_after_first_insert();
        let packed = self.quant.pack(values);
        if let Some(&index) = self.positions.get(&cx_id) {
            self.remove_fingerprint(index);
            self.rows[index].stored = packed;
            self.rows[index].seq = seq;
            self.rows[index].deleted = false;
            self.index_fingerprint(index);
            self.base_seq = self.base_seq.max(seq);
            self.rebuild()?;
            return Ok(());
        }
        let index = self.rows.len();
        let level = self.level_for(cx_id, index);
        self.rows.push(Row {
            cx_id,
            stored: packed,
            seq,
            level,
            neighbors: Vec::new(),
            deleted: false,
        });
        self.positions.insert(cx_id, index);
        self.index_fingerprint(index);
        self.connect_new_row(index);
        self.refresh_entry_after_insert(index);
        self.built_at_seq = self.built_at_seq.max(seq);
        self.base_seq = self.base_seq.max(seq);
        Ok(())
    }

    fn search(
        &self,
        query: &SlotVector,
        k: usize,
        ef: Option<usize>,
    ) -> Result<Vec<IndexSearchHit>> {
        if self.rows.is_empty() {
            return Err(sextant_error(
                CALYX_SEXTANT_INDEX_EMPTY,
                "hnsw search requested on an empty index",
            ));
        }
        if k == 0 {
            return Err(sextant_error(
                CALYX_SEXTANT_EF_TOO_SMALL,
                "hnsw search requires k > 0",
            ));
        }
        let live_len = self.live_len();
        if live_len == 0 {
            return Err(sextant_error(
                CALYX_SEXTANT_INDEX_EMPTY,
                "hnsw search requested on an empty index",
            ));
        }
        let raw_query = self.checked_query(query)?;
        let prepared = self.quant.prepare_query(raw_query);
        let packed_query = self.quant.pack(raw_query);
        let needed = k.min(live_len);
        let ef = ef
            .unwrap_or_else(|| needed.max(self.max_neighbors * 2))
            .min(self.rows.len());
        if ef < needed {
            return Err(sextant_error(
                CALYX_SEXTANT_EF_TOO_SMALL,
                format!("ef {ef} below requested result count {needed}"),
            ));
        }
        let entry = self.entry_point().ok_or_else(|| {
            sextant_error(
                CALYX_SEXTANT_INDEX_EMPTY,
                "hnsw search requested on an empty index",
            )
        })?;
        let start = self.greedy_descent(&prepared, entry);
        let results = self.beam_search(&prepared, start, ef);
        let mut merged = HashMap::<CxId, f32>::new();
        for (cx_id, score) in results
            .into_iter()
            .chain(self.exact_vector_hits(&packed_query, &prepared))
        {
            merged
                .entry(cx_id)
                .and_modify(|existing| *existing = existing.max(score))
                .or_insert(score);
        }
        let mut results = top_k(merged.into_iter().collect(), k);
        results.truncate(k);
        Ok(ranked(results))
    }

    fn rebuild(&mut self) -> Result<()> {
        for row in &mut self.rows {
            row.neighbors.clear();
        }
        self.entry_point = None;
        for idx in 0..self.rows.len() {
            self.connect_new_row(idx);
            self.refresh_entry_after_insert(idx);
        }
        self.built_at_seq = self.base_seq;
        Ok(())
    }

    fn vector(&self, cx_id: CxId) -> Option<SlotVector> {
        // Reconstruction from the packed representation: exact for
        // QuantKind::None, the labeled representable approximation otherwise.
        self.positions.get(&cx_id).and_then(|&index| {
            (!self.rows[index].deleted).then(|| SlotVector::Dense {
                dim: self.dim,
                data: self.rows[index].stored.approx_f32(),
            })
        })
    }

    fn set_base_seq(&mut self, seq: u64) {
        self.base_seq = seq;
    }

    fn stats(&self) -> IndexStats {
        IndexStats {
            slot: self.slot,
            shape: self.shape(),
            len: self.live_len(),
            built_at_seq: self.built_at_seq,
            base_seq: self.base_seq,
            kind: "hnsw",
        }
    }
}

impl AnnIndexGraph for HnswIndex {
    fn ann_index_id(&self) -> String {
        format!("slot_{}", self.slot.get())
    }

    fn ann_tombstone_stats(&self) -> AnnTombstoneStats {
        let tombstoned_nodes = self.tombstone_count();
        AnnTombstoneStats {
            index_id: self.ann_index_id(),
            total_nodes: self.total_nodes(),
            tombstoned_nodes,
            live_nodes: self.live_len(),
        }
    }

    fn rebuild_without_tombstones(&self) -> Result<Self> {
        self.clone_without_tombstones()
    }
}

fn packed_fingerprint(packed: &PackedVector) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let identity = packed.identity_bytes();
    hasher.update(&(identity.len() as u64).to_le_bytes());
    hasher.update(&identity);
    *hasher.finalize().as_bytes()
}
