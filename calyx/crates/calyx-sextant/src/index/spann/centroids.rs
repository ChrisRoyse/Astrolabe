//! SPANN centroid state persisted as `centroids.spn`.

mod codec;
mod raw_l2_graph;

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use calyx_core::{CxId, Result, SlotId, SlotVector};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

use super::posting::publish_synced_file_atomic;
use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_DIM_MISMATCH, CALYX_INDEX_INVALID_PARAMS, CALYX_INDEX_IO,
    sextant_error,
};
use crate::index::distance::l2_sq;
use crate::index::{HnswIndex, SextantIndex};
use codec::{decode_centroids, write_header};
use raw_l2_graph::RawL2CentroidGraph;

pub const SPANN_CENTROID_MAGIC: [u8; 8] = *b"CLXSP001";
const FORMAT_VERSION: u32 = 1;
const KMEANS_ITERS: usize = 12;
const RAW_L2_GRAPH_EF_FLOOR: usize = 128;
const CENTROID_SLOT: SlotId = SlotId::new(u16::MAX - 1);
const DEFAULT_MAX_CENTROID_FILE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct SpannCentroidIndex {
    dim: u32,
    centroids: Vec<Vec<f32>>,
    posting_list_offsets: Vec<u64>,
    assignments: Vec<(u32, u32)>,
    hnsw: HnswIndex,
    centroid_lookup: BTreeMap<CxId, u32>,
    raw_l2_graph: RawL2CentroidGraph,
}

impl SpannCentroidIndex {
    pub fn empty(dim: u32) -> Self {
        Self::from_parts(dim, Vec::new(), Vec::new(), Vec::new())
            .expect("empty centroid index is valid")
    }

    pub fn from_parts(
        dim: u32,
        centroids: Vec<Vec<f32>>,
        posting_list_offsets: Vec<u64>,
        assignments: Vec<(u32, u32)>,
    ) -> Result<Self> {
        validate_centroids(dim, &centroids)?;
        let mut offsets = posting_list_offsets;
        if offsets.is_empty() {
            offsets = (0..centroids.len() as u64).collect();
        }
        if offsets.len() != centroids.len() {
            return Err(invalid(format!(
                "posting offset count {} != centroid count {}",
                offsets.len(),
                centroids.len()
            )));
        }
        for &(_, centroid_id) in &assignments {
            if centroid_id as usize >= centroids.len() {
                return Err(invalid(format!(
                    "assignment references centroid {centroid_id} but count is {}",
                    centroids.len()
                )));
            }
        }
        let (hnsw, lookup) = build_hnsw(dim, &centroids)?;
        let raw_l2_graph = RawL2CentroidGraph::build(&centroids);
        Ok(Self {
            dim,
            centroids,
            posting_list_offsets: offsets,
            assignments,
            hnsw,
            centroid_lookup: lookup,
            raw_l2_graph,
        })
    }

    pub fn dim(&self) -> u32 {
        self.dim
    }

    pub fn centroid_count(&self) -> usize {
        self.centroids.len()
    }

    pub fn centroids(&self) -> &[Vec<f32>] {
        &self.centroids
    }

    pub fn posting_list_offsets(&self) -> &[u64] {
        &self.posting_list_offsets
    }

    pub fn assignments(&self) -> &[(u32, u32)] {
        &self.assignments
    }

    /// Canonical identity of the centroid geometry and persisted assignment
    /// contract. Posting generations seal this value so lists can never be
    /// opened against a different trained router.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"calyx-spann-centroids-v1");
        hasher.update(&self.dim.to_le_bytes());
        hasher.update(&(self.centroids.len() as u64).to_le_bytes());
        for centroid in &self.centroids {
            for value in centroid {
                hasher.update(&value.to_bits().to_le_bytes());
            }
        }
        hasher.update(&(self.posting_list_offsets.len() as u64).to_le_bytes());
        for offset in &self.posting_list_offsets {
            hasher.update(&offset.to_le_bytes());
        }
        hasher.update(&(self.assignments.len() as u64).to_le_bytes());
        for (vector_id, centroid_id) in &self.assignments {
            hasher.update(&vector_id.to_le_bytes());
            hasher.update(&centroid_id.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    pub fn assignment(&self, vector_id: u32) -> Option<u32> {
        self.assignments
            .iter()
            .find_map(|(id, centroid)| (*id == vector_id).then_some(*centroid))
    }

    pub fn assign(&self, vector: &[f32]) -> Result<u32> {
        self.nearest_centroids_exact_l2(vector, 1)?
            .into_iter()
            .next()
            .ok_or_else(|| corrupt("exact squared-L2 centroid routing returned no region"))
    }

    /// Approximate nearest-centroid assignment via the HNSW routing layer —
    /// O(log R) instead of `assign`'s O(R) linear scan. The partitioned
    /// billion-scale builder grows the centroid count R with N, so an exact scan
    /// makes the assignment phase O(N*R*dim) ~ quadratic in N; routing through the
    /// HNSW keeps it O(N*log R*dim). Any routing error or incomplete result is
    /// returned to the caller; assignment never substitutes another route.
    pub fn assign_hnsw(&self, vector: &[f32]) -> Result<u32> {
        self.nearest_centroids(vector, 1)?
            .first()
            .copied()
            .ok_or_else(|| corrupt("HNSW centroid routing returned no region"))
    }

    /// Approximate raw-L2 nearest-centroid assignment through the metric-aware
    /// centroid graph. This avoids the cosine-only HNSW route while keeping the
    /// assignment phase sublinear in the final centroid count.
    pub fn assign_raw_l2_graph(&self, vector: &[f32]) -> Result<u32> {
        self.nearest_centroids_raw_l2_graph(vector, 1)?
            .first()
            .copied()
            .ok_or_else(|| corrupt("raw squared-L2 centroid routing returned no region"))
    }

    pub fn nearest_centroids(&self, query: &[f32], n_probe: usize) -> Result<Vec<u32>> {
        let k = self.validate_route_request(query, n_probe)?;
        let query = SlotVector::Dense {
            dim: self.dim,
            data: query.to_vec(),
        };
        let hits = self.hnsw.search(&query, k, Some(k.max(64)))?;
        let mut routes = Vec::with_capacity(hits.len());
        for hit in hits {
            routes.push(*self.centroid_lookup.get(&hit.cx_id).ok_or_else(|| {
                corrupt(format!(
                    "HNSW centroid route references unknown CxId {}",
                    hit.cx_id
                ))
            })?);
        }
        if routes.len() != k {
            return Err(corrupt(format!(
                "HNSW centroid router returned {} routes, expected {k}",
                routes.len()
            )));
        }
        Ok(routes)
    }

    pub fn nearest_centroids_exact_l2(&self, query: &[f32], n_probe: usize) -> Result<Vec<u32>> {
        let k = self.validate_route_request(query, n_probe)?;
        let mut scored: Vec<(u32, f32)> = self
            .centroids
            .iter()
            .enumerate()
            .map(|(idx, centroid)| (idx as u32, l2_sq(centroid, query)))
            .collect();
        scored.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        Ok(scored.into_iter().take(k).map(|(idx, _)| idx).collect())
    }

    pub fn nearest_centroids_raw_l2_graph(
        &self,
        query: &[f32],
        n_probe: usize,
    ) -> Result<Vec<u32>> {
        self.validate_route_request(query, n_probe)?;
        let ef = n_probe.saturating_mul(4).max(RAW_L2_GRAPH_EF_FLOOR);
        self.raw_l2_graph
            .search(&self.centroids, query, n_probe, ef)
    }

    fn validate_route_request(&self, query: &[f32], n_probe: usize) -> Result<usize> {
        if self.centroids.is_empty() {
            return Err(invalid("centroid routing requires a non-empty index"));
        }
        if n_probe == 0 {
            return Err(invalid("centroid routing n_probe must be positive"));
        }
        if query.len() != self.dim as usize {
            return Err(invalid(format!(
                "centroid routing query dim {} != {}",
                query.len(),
                self.dim
            )));
        }
        if query.iter().any(|value| !value.is_finite()) {
            return Err(invalid("centroid routing query contains non-finite values"));
        }
        Ok(n_probe.min(self.centroids.len()))
    }

    pub fn save(&self, slot_sparse_dir: impl AsRef<Path>) -> Result<()> {
        self.save_to_path(slot_sparse_dir.as_ref().join("centroids.spn"))
    }

    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| io("create centroid dir", e))?;
        }
        let tmp = tmp_path(path);
        let file = File::create(&tmp).map_err(|e| io("create centroid tmp", e))?;
        let mut out = BufWriter::new(file);
        write_header(&mut out, self)?;
        for centroid in &self.centroids {
            for value in centroid {
                out.write_all(&value.to_le_bytes())
                    .map_err(|e| io("write centroid f32", e))?;
            }
        }
        for offset in &self.posting_list_offsets {
            out.write_all(&offset.to_le_bytes())
                .map_err(|e| io("write posting offset", e))?;
        }
        for (vector_id, centroid_id) in &self.assignments {
            out.write_all(&vector_id.to_le_bytes())
                .map_err(|e| io("write assignment id", e))?;
            out.write_all(&centroid_id.to_le_bytes())
                .map_err(|e| io("write assignment centroid", e))?;
        }
        let file = out
            .into_inner()
            .map_err(|e| io("flush centroid tmp", e.into_error()))?;
        file.sync_all().map_err(|e| io("fsync centroid tmp", e))?;
        drop(file);
        let expected_hash = self.content_hash();
        let staged = Self::open_from_path_with_max_bytes(&tmp, DEFAULT_MAX_CENTROID_FILE_BYTES)?;
        if staged.content_hash() != expected_hash {
            return Err(corrupt(format!(
                "staged centroid readback {} changed content identity",
                tmp.display()
            )));
        }
        publish_synced_file_atomic(&tmp, path, path.exists())?;
        let published = Self::open_from_path_with_max_bytes(path, DEFAULT_MAX_CENTROID_FILE_BYTES)?;
        if published.content_hash() != expected_hash {
            return Err(corrupt(format!(
                "published centroid readback {} changed content identity",
                path.display()
            )));
        }
        Ok(())
    }

    pub fn open(slot_sparse_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_max_bytes(slot_sparse_dir, DEFAULT_MAX_CENTROID_FILE_BYTES)
    }

    pub fn open_with_max_bytes(
        slot_sparse_dir: impl AsRef<Path>,
        max_file_bytes: u64,
    ) -> Result<Self> {
        Self::open_from_path_with_max_bytes(
            slot_sparse_dir.as_ref().join("centroids.spn"),
            max_file_bytes,
        )
    }

    pub fn open_from_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_from_path_with_max_bytes(path, DEFAULT_MAX_CENTROID_FILE_BYTES)
    }

    pub fn open_from_path_with_max_bytes(
        path: impl AsRef<Path>,
        max_file_bytes: u64,
    ) -> Result<Self> {
        let path = path.as_ref();
        if max_file_bytes < 40 {
            return Err(invalid(format!(
                "centroid file registry limit {max_file_bytes} is below the 40-byte header"
            )));
        }
        let mut file = File::open(path).map_err(|e| io("open centroids", e))?;
        let file_len = file.metadata().map_err(|e| io("stat centroids", e))?.len();
        if file_len > max_file_bytes {
            return Err(corrupt(format!(
                "centroid file {} length {file_len} exceeds registry limit {max_file_bytes}",
                path.display()
            )));
        }
        let len =
            usize::try_from(file_len).map_err(|_| corrupt("centroid file length exceeds usize"))?;
        let mut bytes = vec![0_u8; len];
        file.read_exact(&mut bytes)
            .map_err(|e| io("read centroids", e))?;
        decode_centroids(&bytes)
    }
}

pub fn build_centroids(
    vectors: &[(u32, Vec<f32>)],
    n_clusters: usize,
    seed: u64,
) -> SpannCentroidIndex {
    try_build_centroids(vectors, n_clusters, seed).expect("valid SPANN centroid input")
}

pub fn try_build_centroids(
    vectors: &[(u32, Vec<f32>)],
    n_clusters: usize,
    seed: u64,
) -> Result<SpannCentroidIndex> {
    if vectors.is_empty() {
        return Ok(SpannCentroidIndex::empty(0));
    }
    let dim = vectors[0].1.len();
    validate_rows(vectors, dim)?;
    let k = effective_cluster_count(vectors.len(), n_clusters);
    let mut centroids = kmeans_pp(vectors, k, seed);
    for _ in 0..KMEANS_ITERS {
        // Assignment step is O(N*k*dim) and the hot loop — compute the nearest
        // centroid for every vector in parallel, then accumulate sums serially in
        // index order (so the float reduction stays deterministic / unchanged).
        let assignments: Vec<u32> = vectors
            .par_iter()
            .map(|(_, vector)| nearest_by_l2(&centroids, vector).expect("k > 0"))
            .collect();
        let mut sums = vec![vec![0.0_f32; dim]; k];
        let mut counts = vec![0_usize; k];
        for ((_, vector), &cid) in vectors.iter().zip(&assignments) {
            counts[cid as usize] += 1;
            for (sum, value) in sums[cid as usize].iter_mut().zip(vector) {
                *sum += *value;
            }
        }
        for cid in 0..k {
            if counts[cid] == 0 {
                centroids[cid] = farthest_vector(vectors, &centroids).clone();
            } else {
                let inv = 1.0 / counts[cid] as f32;
                for value in &mut sums[cid] {
                    *value *= inv;
                }
                centroids[cid] = sums[cid].clone();
            }
        }
    }
    let assignments = vectors
        .par_iter()
        .map(|(id, vector)| (*id, nearest_by_l2(&centroids, vector).expect("k > 0")))
        .collect();
    SpannCentroidIndex::from_parts(dim as u32, centroids, (0..k as u64).collect(), assignments)
}

pub fn default_cluster_count(vector_count: usize) -> usize {
    ((vector_count as f64).sqrt() as usize).max(1)
}

fn effective_cluster_count(vector_count: usize, requested: usize) -> usize {
    let wanted = if requested == 0 {
        default_cluster_count(vector_count)
    } else {
        requested
    };
    wanted.min(vector_count)
}

fn kmeans_pp(vectors: &[(u32, Vec<f32>)], k: usize, seed: u64) -> Vec<Vec<f32>> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let first = vectors[rng.gen_range(0..vectors.len())].1.clone();
    // Canonical kmeans++ with a cached D^2 array: `min_dist[i]` is the squared
    // distance from vector i to its NEAREST chosen centroid so far. Adding a
    // centroid updates the cache in O(N*dim) instead of re-scanning the whole
    // centroid set (the old code was O(N*k^2*dim) — the billion-scale build wall).
    // The cache equals `nearest_distance_sq(&centroids, v)` at every step, so the
    // RNG draws and chosen centroids are bit-identical to the naive version.
    let mut min_dist: Vec<f32> = vectors
        .par_iter()
        .map(|(_, vector)| l2_sq(&first, vector))
        .collect();
    let mut centroids = vec![first];
    while centroids.len() < k {
        let total: f32 = min_dist.iter().sum();
        if total <= f32::EPSILON {
            // Degenerate: every remaining point coincides with a centroid. Mirror
            // the naive fallback exactly, then refresh the cache against the new
            // centroid set (rare path — correctness over speed).
            let before = centroids.len();
            for (_, vector) in vectors {
                if !centroids.contains(vector) {
                    centroids.push(vector.clone());
                    break;
                }
            }
            if centroids.len() < k {
                centroids.push(vectors[centroids.len() % vectors.len()].1.clone());
            }
            if centroids.len() != before {
                let cset = &centroids;
                min_dist = vectors
                    .par_iter()
                    .map(|(_, vector)| nearest_distance_sq(cset, vector))
                    .collect();
            }
            continue;
        }
        let mut cut = rng.gen_range(0.0..total);
        let mut chosen = vectors.len() - 1;
        for (idx, distance) in min_dist.iter().enumerate() {
            cut -= *distance;
            if cut <= 0.0 {
                chosen = idx;
                break;
            }
        }
        let new_centroid = vectors[chosen].1.clone();
        // Fold the new centroid into the cached nearest-distance array in parallel.
        min_dist
            .par_iter_mut()
            .zip(vectors.par_iter())
            .for_each(|(md, (_, vector))| {
                let d = l2_sq(&new_centroid, vector);
                if d < *md {
                    *md = d;
                }
            });
        centroids.push(new_centroid);
    }
    centroids
}

fn farthest_vector<'a>(vectors: &'a [(u32, Vec<f32>)], centroids: &[Vec<f32>]) -> &'a Vec<f32> {
    vectors
        .iter()
        .max_by(|(_, a), (_, b)| {
            nearest_distance_sq(centroids, a).total_cmp(&nearest_distance_sq(centroids, b))
        })
        .map(|(_, vector)| vector)
        .expect("non-empty vectors")
}

fn nearest_by_l2(centroids: &[Vec<f32>], vector: &[f32]) -> Option<u32> {
    centroids
        .iter()
        .enumerate()
        .min_by(|(a_idx, a), (b_idx, b)| {
            l2_sq(a, vector)
                .total_cmp(&l2_sq(b, vector))
                .then_with(|| a_idx.cmp(b_idx))
        })
        .map(|(idx, _)| idx as u32)
}

fn nearest_distance_sq(centroids: &[Vec<f32>], vector: &[f32]) -> f32 {
    centroids
        .iter()
        .map(|centroid| l2_sq(centroid, vector))
        .min_by(f32::total_cmp)
        .unwrap_or(0.0)
}

fn build_hnsw(dim: u32, centroids: &[Vec<f32>]) -> Result<(HnswIndex, BTreeMap<CxId, u32>)> {
    let mut hnsw = HnswIndex::new(CENTROID_SLOT, dim, 0x5A17_570A);
    let mut lookup = BTreeMap::new();
    for (idx, vector) in centroids.iter().enumerate() {
        let id = centroid_cx_id(idx as u32);
        hnsw.insert(
            id,
            SlotVector::Dense {
                dim,
                data: vector.clone(),
            },
            idx as u64,
        )?;
        lookup.insert(id, idx as u32);
    }
    Ok((hnsw, lookup))
}

fn centroid_cx_id(id: u32) -> CxId {
    let mut bytes = [0_u8; 16];
    bytes[0..8].copy_from_slice(b"CLXSPANN");
    bytes[12..16].copy_from_slice(&id.to_be_bytes());
    CxId::from_bytes(bytes)
}

fn validate_rows(vectors: &[(u32, Vec<f32>)], dim: usize) -> Result<()> {
    for (id, vector) in vectors {
        if vector.len() != dim {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                format!("vector {id} dim {} expected {dim}", vector.len()),
            ));
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(invalid(format!("vector {id} has non-finite component")));
        }
    }
    Ok(())
}

fn validate_centroids(dim: u32, centroids: &[Vec<f32>]) -> Result<()> {
    for (idx, centroid) in centroids.iter().enumerate() {
        if centroid.len() != dim as usize {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                format!("centroid {idx} dim {} expected {dim}", centroid.len()),
            ));
        }
        if centroid.iter().any(|value| !value.is_finite()) {
            return Err(invalid(format!("centroid {idx} has non-finite component")));
        }
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn invalid(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_INVALID_PARAMS,
        format!("spann centroids: {detail}"),
    )
}

fn corrupt(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_CORRUPT,
        format!("spann centroids corrupt: {detail}"),
    )
}

fn io(stage: &str, error: std::io::Error) -> calyx_core::CalyxError {
    sextant_error(CALYX_INDEX_IO, format!("spann centroids {stage}: {error}"))
}
