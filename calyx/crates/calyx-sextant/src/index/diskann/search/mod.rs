//! DiskANN beam search and raw-f32 rescore (PH68 T02).

mod construct;
mod helpers;
mod pq_support;
mod scratch;
mod storage;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use calyx_core::{CxId, Result, SlotId, SlotShape, SlotVector};

use super::build::{DiskAnnBuildBackend, DiskAnnBuildParams};
use super::generation::DiskAnnGeneration;
use super::graph::{DiskAnnGraphReader, DiskAnnMetric, DiskAnnVectorRef};
use super::pq::{DiskAnnPqBinding, DiskAnnPqBuildParams, DiskAnnPqIndex};
use super::raw::DiskAnnRawIndex;
use crate::error::{CALYX_INDEX_DIM_MISMATCH, CALYX_INDEX_IO, sextant_error};
use crate::index::distance::{cosine_distance, l2_normalize};
use crate::index::{IndexSearchHit, IndexStats, SextantIndex, ranked};
use crate::util::dense;

use helpers::{
    Candidate, DiskAnnDistanceMode, dense_rows, distance, invalid, io, prefetch_node, sorted,
};
pub use pq_support::DiskAnnPqSearchBuild;
use storage::build_search_generation_with_backend;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskAnnSearchParams {
    pub beamwidth: usize,
    pub ef_search: usize,
    pub rescore_k: usize,
    pub rescore_from_raw: bool,
}

impl Default for DiskAnnSearchParams {
    fn default() -> Self {
        Self {
            beamwidth: 32,
            ef_search: 64,
            rescore_k: 64,
            rescore_from_raw: true,
        }
    }
}

/// Graphs at or below this on-disk size fit comfortably in the OS page cache, so
/// per-node `posix_fadvise` prefetch is net-negative (syscall overhead with no
/// readahead benefit). Above it, prefetch helps amortize cold-SSD latency.
const PREFETCH_MIN_GRAPH_BYTES: u64 = 256 * 1024 * 1024;

pub(super) fn prefetch_file_for_graph(
    path: &Path,
    reader: &DiskAnnGraphReader,
) -> Result<Option<File>> {
    let graph_bytes = reader.node_count() * reader.node_block_size() as u64;
    if graph_bytes <= PREFETCH_MIN_GRAPH_BYTES {
        return Ok(None);
    }
    File::open(path)
        .map(Some)
        .map_err(|e| io("open graph for prefetch", e))
}

#[derive(Clone, Copy)]
pub(super) struct SearchBuildSidecars {
    pub(super) write_default_raw_sidecar: bool,
    pub(super) pq: Option<DiskAnnPqBuildParams>,
    pub(super) backend: DiskAnnBuildBackend,
}

#[derive(Debug)]
pub struct DiskAnnSearch {
    slot: SlotId,
    dim: u32,
    graph_path: PathBuf,
    generation: Option<DiskAnnGeneration>,
    raw: Option<DiskAnnRawIndex>,
    pq: Option<DiskAnnPqIndex>,
    reader: Option<DiskAnnGraphReader>,
    graph_file: Option<File>,
    distance_mode: DiskAnnDistanceMode,
    ids: Vec<CxId>,
    positions: HashMap<CxId, u32>,
    build_params: DiskAnnBuildParams,
    build_backend: DiskAnnBuildBackend,
    default_search: DiskAnnSearchParams,
    built_at_seq: u64,
    base_seq: u64,
}

impl DiskAnnSearch {
    pub fn search_ids(
        &self,
        query: &[f32],
        k: usize,
        params: &DiskAnnSearchParams,
    ) -> Result<Vec<(u32, f32)>> {
        scratch::search_ids(self, query, k, params)
    }

    fn graph_query<'a>(&self, query: &'a [f32]) -> Cow<'a, [f32]> {
        match self.distance_mode {
            DiskAnnDistanceMode::UnitL2 => Cow::Owned(l2_normalize(query)),
            DiskAnnDistanceMode::RawL2 => Cow::Borrowed(query),
        }
    }

    fn validate_query(&self, query: &[f32]) -> Result<()> {
        if query.len() != self.dim as usize {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                format!("query dim {} expected {}", query.len(), self.dim),
            ));
        }
        if query.iter().any(|v| !v.is_finite()) {
            return Err(invalid("query vector has non-finite component"));
        }
        Ok(())
    }

    fn rescore_from_raw(&self, query: &[f32], hits: &[(u32, f32)]) -> Result<Vec<(u32, f32)>> {
        let Some(raw) = &self.raw else {
            return Ok(hits.to_vec());
        };
        let mut rescored = Vec::with_capacity(hits.len());
        for &(id, _) in hits {
            rescored.push((
                id,
                raw_rescore_distance(query, raw.vector(id)?, self.distance_mode),
            ));
        }
        Ok(sorted(rescored))
    }

    fn prefetch(
        &self,
        candidates: &[Candidate],
        beamwidth: usize,
        reader: &DiskAnnGraphReader,
    ) -> Result<()> {
        let Some(file) = &self.graph_file else {
            return Ok(());
        };
        // `posix_fadvise(WILLNEED)` is a syscall per candidate per beam step. It
        // only pays off for graphs large enough that cold-SSD readahead matters;
        // on a graph that already fits the page cache (e.g. a partitioned region
        // graph) it is pure overhead — thousands of no-op syscalls per query that
        // dominate latency. Skip prefetch for resident-sized graphs.
        let graph_bytes = reader.node_count() * reader.node_block_size() as u64;
        if graph_bytes <= PREFETCH_MIN_GRAPH_BYTES {
            return Ok(());
        }
        for candidate in candidates.iter().take(beamwidth) {
            prefetch_node(
                file,
                reader.node_block_offset(candidate.id)?,
                reader.node_block_size(),
            );
        }
        Ok(())
    }

    fn vectors_from_graph(&self) -> Result<Vec<Vec<f32>>> {
        let Some(reader) = &self.reader else {
            return Ok(Vec::new());
        };
        (0..reader.node_count() as u32)
            .map(|id| {
                let node = reader.read_node(id)?;
                match node.vector {
                    DiskAnnVectorRef::F32(values) => Ok(values.to_vec()),
                    DiskAnnVectorRef::I8 { .. } => Err(sextant_error(
                        CALYX_INDEX_IO,
                        "directional DiskANN rebuild requires its exact raw component; lossy i8 reconstruction is forbidden",
                    )),
                }
            })
            .collect()
    }

    fn vectors_for_rebuild(&self) -> Result<Vec<Vec<f32>>> {
        let Some(raw) = &self.raw else {
            return self.vectors_from_graph();
        };
        (0..self.ids.len() as u32)
            .map(|id| raw.vector(id).map(<[f32]>::to_vec))
            .collect()
    }

    pub fn generation(&self) -> Option<&DiskAnnGeneration> {
        self.generation.as_ref()
    }

    pub fn physical_bytes(&self) -> u64 {
        self.generation
            .as_ref()
            .map_or(0, DiskAnnGeneration::physical_bytes)
    }

    fn install_generation(&mut self, generation: DiskAnnGeneration) -> Result<()> {
        let reader = DiskAnnGraphReader::open_physical(generation.graph_path())?;
        if reader.header().dim != self.dim || reader.header().node_count as usize != self.ids.len()
        {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                "rebuilt DiskANN generation shape disagrees with the in-memory identity map",
            ));
        }
        let raw = generation
            .raw_path()
            .map(|path| {
                DiskAnnRawIndex::read(
                    path,
                    generation.source_hash(),
                    generation.graph_hash(),
                    generation.metric(),
                    self.dim as usize,
                    self.ids.len(),
                )
            })
            .transpose()?;
        let pq = generation
            .pq_path()
            .map(|path| {
                DiskAnnPqIndex::read_bound(
                    path,
                    DiskAnnPqBinding {
                        source_hash: generation.source_hash(),
                        graph_hash: generation.graph_hash(),
                        metric: generation.metric(),
                        dim: self.dim as usize,
                        node_count: self.ids.len(),
                    },
                    generation.pq_code_bits().ok_or_else(|| {
                        sextant_error(
                            CALYX_INDEX_IO,
                            "PQ path exists without a declared code width",
                        )
                    })?,
                )
            })
            .transpose()?;
        let distance_mode = match generation.metric() {
            DiskAnnMetric::UnitL2 => DiskAnnDistanceMode::UnitL2,
            DiskAnnMetric::RawL2 => DiskAnnDistanceMode::RawL2,
        };
        let graph_file = prefetch_file_for_graph(generation.graph_path(), &reader)?;
        self.reader = Some(reader);
        self.graph_file = graph_file;
        self.raw = raw;
        self.pq = pq;
        self.distance_mode = distance_mode;
        self.generation = Some(generation);
        Ok(())
    }
}

fn raw_rescore_distance(query: &[f32], raw: &[f32], mode: DiskAnnDistanceMode) -> f32 {
    match mode {
        DiskAnnDistanceMode::UnitL2 => cosine_distance(query, raw),
        _ => distance(query, raw, mode),
    }
}

impl SextantIndex for DiskAnnSearch {
    fn slot(&self) -> SlotId {
        self.slot
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(self.dim)
    }

    fn insert(&mut self, cx_id: CxId, vector: SlotVector, seq: u64) -> Result<()> {
        let values = dense(&vector)?;
        self.validate_query(values)?;
        let mut vectors = self.vectors_for_rebuild()?;
        if let Some(&id) = self.positions.get(&cx_id) {
            vectors[id as usize] = values.to_vec();
        } else {
            let id = u32::try_from(self.ids.len())
                .map_err(|_| invalid("diskann graph exceeds u32 node id space"))?;
            self.positions.insert(cx_id, id);
            self.ids.push(cx_id);
            vectors.push(values.to_vec());
        }
        let rows: Vec<_> = self.ids.iter().copied().zip(vectors).collect();
        let dense_rows = dense_rows(&rows, self.dim as usize)?;
        let pq_params = self.pq.as_ref().map(DiskAnnPqIndex::build_params);
        let generation = build_search_generation_with_backend(
            &self.graph_path,
            &dense_rows,
            self.build_params,
            None,
            self.raw.is_some(),
            pq_params,
            self.build_backend,
            self.distance_mode,
            |_| Ok(()),
        )?;
        self.install_generation(generation)?;
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
        let query = dense(query)?;
        let mut params = self.default_search;
        if let Some(ef) = ef {
            params.ef_search = ef;
        }
        let scored = self
            .search_ids(query, k, &params)?
            .into_iter()
            .map(|(id, dist)| (self.ids[id as usize], 1.0 - dist))
            .collect();
        Ok(ranked(scored))
    }

    fn rebuild(&mut self) -> Result<()> {
        let vectors = self.vectors_for_rebuild()?;
        if vectors.is_empty() {
            return Ok(());
        }
        let rows: Vec<_> = self.ids.iter().copied().zip(vectors).collect();
        let dense_rows = dense_rows(&rows, self.dim as usize)?;
        let pq_params = self.pq.as_ref().map(DiskAnnPqIndex::build_params);
        let generation = build_search_generation_with_backend(
            &self.graph_path,
            &dense_rows,
            self.build_params,
            None,
            self.raw.is_some(),
            pq_params,
            self.build_backend,
            self.distance_mode,
            |_| Ok(()),
        )?;
        self.install_generation(generation)?;
        Ok(())
    }

    fn vector(&self, cx_id: CxId) -> Option<SlotVector> {
        let id = *self.positions.get(&cx_id)?;
        if let Some(raw) = &self.raw
            && let Ok(vector) = raw.vector(id)
        {
            return Some(SlotVector::Dense {
                dim: self.dim,
                data: vector.to_vec(),
            });
        }
        let reader = self.reader.as_ref()?;
        let DiskAnnVectorRef::F32(vector) = reader.read_node(id).ok()?.vector else {
            return None;
        };
        Some(SlotVector::Dense {
            dim: self.dim,
            data: vector.to_vec(),
        })
    }

    fn set_base_seq(&mut self, seq: u64) {
        self.base_seq = seq;
    }

    fn stats(&self) -> IndexStats {
        IndexStats {
            slot: self.slot,
            shape: self.shape(),
            len: self.ids.len(),
            built_at_seq: self.built_at_seq,
            base_seq: self.base_seq,
            kind: "DiskANN",
        }
    }
}
