//! Integrity-bound Product Quantization for DiskANN navigation.
//!
//! The format declares 4- or 8-bit codes, binds graph/source/metric/training
//! identity, seals the codebook and whole payload, eagerly validates every
//! code, and performs asymmetric query-to-code distance via one reusable LUT.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

use calyx_core::Result;
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

use super::graph::DiskAnnMetric;
use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_DIM_MISMATCH, CALYX_INDEX_INVALID_PARAMS, CALYX_INDEX_IO,
    sextant_error,
};

const PQ_MAGIC: [u8; 8] = *b"CLXPQ002";
const PQ_VERSION: u16 = 2;
const HEADER_BYTES: usize = 192;
const SEAL_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskAnnPqBuildParams {
    pub subvectors: usize,
    pub centroids: usize,
    pub iterations: usize,
    pub code_bits: u8,
}

impl Default for DiskAnnPqBuildParams {
    fn default() -> Self {
        Self {
            subvectors: 16,
            centroids: 256,
            iterations: 8,
            code_bits: 8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DiskAnnPqBinding {
    pub source_hash: [u8; 32],
    pub graph_hash: [u8; 32],
    pub metric: DiskAnnMetric,
    pub dim: usize,
    pub node_count: usize,
}

#[derive(Clone, Debug)]
pub struct DiskAnnPqIndex {
    dim: usize,
    node_count: usize,
    subvectors: usize,
    centroids: usize,
    subdim: usize,
    iterations: usize,
    code_bits: u8,
    source_hash: [u8; 32],
    graph_hash: [u8; 32],
    training_seed: [u8; 32],
    codebook: Vec<f32>,
    codes: Vec<u8>,
}

#[derive(Debug)]
pub struct DiskAnnPqQuery<'a> {
    lut: Vec<f32>,
    subvectors: usize,
    centroids: usize,
    code_bits: u8,
    codes: &'a [u8],
    node_count: usize,
}

impl DiskAnnPqIndex {
    pub(super) fn build_bound(
        rows: &[(u32, Vec<f32>)],
        params: DiskAnnPqBuildParams,
        binding: DiskAnnPqBinding,
    ) -> Result<Self> {
        validate_rows(rows, params, binding)?;
        let dim = rows[0].1.len();
        let node_count = rows.len();
        let subdim = dim / params.subvectors;
        let training_seed = training_seed(binding, params);
        let mut codebook = Vec::with_capacity(params.subvectors * params.centroids * subdim);
        for subvector in 0..params.subvectors {
            train_subspace(
                rows,
                subvector * subdim,
                subdim,
                params.centroids,
                params.iterations,
                training_seed,
                subvector,
                &mut codebook,
            );
        }
        let code_count = node_count
            .checked_mul(params.subvectors)
            .ok_or_else(|| invalid("PQ code count overflow"))?;
        let code_bytes = packed_code_bytes(code_count, params.code_bits)?;
        let mut index = Self {
            dim,
            node_count,
            subvectors: params.subvectors,
            centroids: params.centroids,
            subdim,
            iterations: params.iterations,
            code_bits: params.code_bits,
            source_hash: binding.source_hash,
            graph_hash: binding.graph_hash,
            training_seed,
            codebook,
            codes: vec![0; code_bytes],
        };
        index.encode_rows(rows)?;
        Ok(index)
    }

    pub(super) fn read_bound(
        path: &Path,
        binding: DiskAnnPqBinding,
        expected_code_bits: u8,
    ) -> Result<Self> {
        let mut file = File::open(path).map_err(|error| io("open PQ component", error))?;
        let file_len = usize::try_from(
            file.metadata()
                .map_err(|error| io("stat PQ component", error))?
                .len(),
        )
        .map_err(|_| corrupt("PQ component length exceeds usize"))?;
        if file_len < HEADER_BYTES + SEAL_BYTES {
            return Err(corrupt(format!("PQ component is only {file_len} bytes")));
        }
        let mut header = [0_u8; HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|error| io("read PQ header", error))?;
        let parsed = ParsedHeader::decode(&header)?;
        parsed.validate_binding(binding, expected_code_bits)?;
        let codebook_floats = parsed.codebook_floats()?;
        let codebook_bytes = codebook_floats
            .checked_mul(4)
            .ok_or_else(|| corrupt("PQ codebook byte size overflow"))?;
        let code_count = parsed
            .node_count
            .checked_mul(parsed.subvectors)
            .ok_or_else(|| corrupt("PQ code count overflow"))?;
        let codes_bytes = packed_code_bytes(code_count, parsed.code_bits)
            .map_err(|_| corrupt("PQ header declares an unsupported code width"))?;
        if parsed.codebook_bytes != codebook_bytes
            || parsed.codes_bytes != codes_bytes
            || file_len != HEADER_BYTES + codebook_bytes + codes_bytes + SEAL_BYTES
        {
            return Err(corrupt(format!(
                "PQ component physical layout mismatch: file={file_len} codebook={}/{codebook_bytes} codes={}/{codes_bytes}",
                parsed.codebook_bytes, parsed.codes_bytes
            )));
        }
        let mut bytes = Vec::with_capacity(file_len);
        bytes.extend_from_slice(&header);
        file.read_to_end(&mut bytes)
            .map_err(|error| io("read PQ payload", error))?;
        let seal_at = bytes.len() - SEAL_BYTES;
        let computed = blake3::hash(&bytes[..seal_at]);
        if computed.as_bytes() != &bytes[seal_at..] {
            return Err(corrupt(format!(
                "PQ component seal mismatch: computed {}",
                computed.to_hex()
            )));
        }
        let codebook_start = HEADER_BYTES;
        let codes_start = codebook_start + codebook_bytes;
        let actual_codebook_hash = blake3::hash(&bytes[codebook_start..codes_start]);
        if actual_codebook_hash.as_bytes() != &parsed.codebook_hash {
            return Err(corrupt(format!(
                "PQ codebook hash mismatch: computed {}",
                actual_codebook_hash.to_hex()
            )));
        }
        let mut codebook = Vec::with_capacity(codebook_floats);
        for chunk in bytes[codebook_start..codes_start].chunks_exact(4) {
            let value = f32::from_le_bytes(chunk.try_into().expect("4B"));
            if !value.is_finite() {
                return Err(corrupt("PQ codebook contains non-finite centroid"));
            }
            codebook.push(value);
        }
        let index = Self {
            dim: parsed.dim,
            node_count: parsed.node_count,
            subvectors: parsed.subvectors,
            centroids: parsed.centroids,
            subdim: parsed.subdim,
            iterations: parsed.iterations,
            code_bits: parsed.code_bits,
            source_hash: parsed.source_hash,
            graph_hash: parsed.graph_hash,
            training_seed: parsed.training_seed,
            codebook,
            codes: bytes[codes_start..seal_at].to_vec(),
        };
        index.validate_all_codes()?;
        Ok(index)
    }

    pub(super) fn write_staged(&self, path: &Path, metric: DiskAnnMetric) -> Result<()> {
        let codebook_bytes = self
            .codebook
            .len()
            .checked_mul(4)
            .ok_or_else(|| invalid("PQ codebook byte size overflow"))?;
        let mut encoded_codebook = Vec::with_capacity(codebook_bytes);
        for value in &self.codebook {
            encoded_codebook.extend_from_slice(&value.to_le_bytes());
        }
        let codebook_hash = blake3::hash(&encoded_codebook);
        let mut header = [0_u8; HEADER_BYTES];
        header[0..8].copy_from_slice(&PQ_MAGIC);
        header[8..10].copy_from_slice(&PQ_VERSION.to_le_bytes());
        header[10] = self.code_bits;
        header[11] = metric as u8;
        header[12..16].copy_from_slice(&(self.dim as u32).to_le_bytes());
        header[16..24].copy_from_slice(&(self.node_count as u64).to_le_bytes());
        header[24..28].copy_from_slice(&(self.subvectors as u32).to_le_bytes());
        header[28..32].copy_from_slice(&(self.centroids as u32).to_le_bytes());
        header[32..36].copy_from_slice(&(self.subdim as u32).to_le_bytes());
        header[36..40].copy_from_slice(&(self.iterations as u32).to_le_bytes());
        header[40..72].copy_from_slice(&self.source_hash);
        header[72..104].copy_from_slice(&self.graph_hash);
        header[104..136].copy_from_slice(&self.training_seed);
        header[136..168].copy_from_slice(codebook_hash.as_bytes());
        header[168..176].copy_from_slice(&(codebook_bytes as u64).to_le_bytes());
        header[176..184].copy_from_slice(&(self.codes.len() as u64).to_le_bytes());
        let mut file =
            File::create(path).map_err(|error| io("create staged PQ component", error))?;
        let mut hasher = blake3::Hasher::new();
        for part in [&header[..], &encoded_codebook, &self.codes] {
            file.write_all(part)
                .map_err(|error| io("write PQ component", error))?;
            hasher.update(part);
        }
        file.write_all(hasher.finalize().as_bytes())
            .map_err(|error| io("write PQ seal", error))?;
        file.sync_all()
            .map_err(|error| io("fsync PQ component", error))
    }

    pub fn query<'a>(&'a self, query: &[f32]) -> Result<DiskAnnPqQuery<'a>> {
        if query.len() != self.dim {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                format!("PQ query dim {} expected {}", query.len(), self.dim),
            ));
        }
        if query.iter().any(|value| !value.is_finite()) {
            return Err(invalid("PQ query contains non-finite component"));
        }
        let mut lut = vec![0.0; self.subvectors * self.centroids];
        for subvector in 0..self.subvectors {
            let offset = subvector * self.subdim;
            let query_subvector = &query[offset..offset + self.subdim];
            for centroid in 0..self.centroids {
                lut[subvector * self.centroids + centroid] =
                    l2_sq(query_subvector, self.centroid(subvector, centroid));
            }
        }
        Ok(DiskAnnPqQuery {
            lut,
            subvectors: self.subvectors,
            centroids: self.centroids,
            code_bits: self.code_bits,
            codes: &self.codes,
            node_count: self.node_count,
        })
    }

    pub fn ram_bytes(&self) -> usize {
        self.codes.len() + self.codebook.len() * size_of::<f32>()
    }

    pub fn node_count(&self) -> usize {
        self.node_count
    }

    pub fn subvectors(&self) -> usize {
        self.subvectors
    }

    pub fn centroids(&self) -> usize {
        self.centroids
    }

    pub fn code_bits(&self) -> u8 {
        self.code_bits
    }

    pub fn build_params(&self) -> DiskAnnPqBuildParams {
        DiskAnnPqBuildParams {
            subvectors: self.subvectors,
            centroids: self.centroids,
            iterations: self.iterations,
            code_bits: self.code_bits,
        }
    }

    fn encode_rows(&mut self, rows: &[(u32, Vec<f32>)]) -> Result<()> {
        for (row, (id, vector)) in rows.iter().enumerate() {
            if *id as usize != row {
                return Err(invalid(format!("PQ row id {id} expected dense id {row}")));
            }
            for subvector in 0..self.subvectors {
                let offset = subvector * self.subdim;
                let code = self.nearest(subvector, &vector[offset..offset + self.subdim]);
                set_code(
                    &mut self.codes,
                    row * self.subvectors + subvector,
                    self.code_bits,
                    code,
                )?;
            }
        }
        Ok(())
    }

    fn nearest(&self, subvector: usize, values: &[f32]) -> usize {
        nearest_in_codebook(
            values,
            self.centroid_block(subvector),
            self.centroids,
            self.subdim,
        )
    }

    fn centroid_block(&self, subvector: usize) -> &[f32] {
        let at = subvector * self.centroids * self.subdim;
        &self.codebook[at..at + self.centroids * self.subdim]
    }

    fn centroid(&self, subvector: usize, centroid: usize) -> &[f32] {
        let at = (subvector * self.centroids + centroid) * self.subdim;
        &self.codebook[at..at + self.subdim]
    }

    fn validate_all_codes(&self) -> Result<()> {
        let code_count = self
            .node_count
            .checked_mul(self.subvectors)
            .ok_or_else(|| corrupt("PQ code count overflow"))?;
        for at in 0..code_count {
            let code = code_at(&self.codes, at, self.code_bits)?;
            if code >= self.centroids {
                return Err(corrupt(format!(
                    "PQ code {code} at {at} >= {}",
                    self.centroids
                )));
            }
        }
        if self.code_bits == 4
            && code_count % 2 == 1
            && self.codes.last().is_some_and(|byte| byte & 0xf0 != 0)
        {
            return Err(corrupt("PQ final high nibble padding is noncanonical"));
        }
        Ok(())
    }
}

impl DiskAnnPqQuery<'_> {
    pub fn distance_l2(&self, id: u32) -> Result<f32> {
        let row = id as usize;
        if row >= self.node_count {
            return Err(invalid(format!("PQ node {id} outside {}", self.node_count)));
        }
        let code_offset = row
            .checked_mul(self.subvectors)
            .ok_or_else(|| invalid("PQ code offset overflow"))?;
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: feature detection proves AVX2 support. Code and LUT
            // bounds are validated eagerly and rechecked by code_at.
            return unsafe { self.distance_l2_avx2(code_offset) };
        }
        self.distance_l2_scalar(code_offset)
    }

    fn distance_l2_scalar(&self, code_offset: usize) -> Result<f32> {
        let mut sum = 0.0;
        for subvector in 0..self.subvectors {
            let code = code_at(self.codes, code_offset + subvector, self.code_bits)?;
            sum += self.lut[subvector * self.centroids + code];
        }
        Ok(sum)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn distance_l2_avx2(&self, code_offset: usize) -> Result<f32> {
        use std::arch::x86_64::*;

        unsafe {
            let mut acc = _mm256_setzero_ps();
            let vectorized = self.subvectors / 8 * 8;
            let mut subvector = 0_usize;
            while subvector < vectorized {
                let mut indices = [0_i32; 8];
                for lane in 0..8 {
                    let code = code_at(self.codes, code_offset + subvector + lane, self.code_bits)?;
                    indices[lane] = i32::try_from((subvector + lane) * self.centroids + code)
                        .map_err(|_| invalid("PQ LUT index exceeds i32 gather space"))?;
                }
                let offsets = _mm256_loadu_si256(indices.as_ptr().cast());
                let values = _mm256_i32gather_ps::<4>(self.lut.as_ptr(), offsets);
                acc = _mm256_add_ps(acc, values);
                subvector += 8;
            }
            let mut lanes = [0.0_f32; 8];
            _mm256_storeu_ps(lanes.as_mut_ptr(), acc);
            let mut sum = lanes.into_iter().sum::<f32>();
            for tail in subvector..self.subvectors {
                let code = code_at(self.codes, code_offset + tail, self.code_bits)?;
                sum += self.lut[tail * self.centroids + code];
            }
            Ok(sum)
        }
    }
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    code_bits: u8,
    metric: DiskAnnMetric,
    dim: usize,
    node_count: usize,
    subvectors: usize,
    centroids: usize,
    subdim: usize,
    iterations: usize,
    source_hash: [u8; 32],
    graph_hash: [u8; 32],
    training_seed: [u8; 32],
    codebook_hash: [u8; 32],
    codebook_bytes: usize,
    codes_bytes: usize,
}

impl ParsedHeader {
    fn decode(bytes: &[u8; HEADER_BYTES]) -> Result<Self> {
        if bytes[0..8] != PQ_MAGIC {
            return Err(corrupt("PQ component magic mismatch"));
        }
        let version = le_u16(bytes, 8);
        if version != PQ_VERSION {
            return Err(corrupt(format!("PQ component version {version}")));
        }
        let metric = match bytes[11] {
            1 => DiskAnnMetric::UnitL2,
            2 => DiskAnnMetric::RawL2,
            other => return Err(corrupt(format!("PQ metric tag {other}"))),
        };
        if bytes[184..].iter().any(|byte| *byte != 0) {
            return Err(corrupt("PQ reserved bytes are noncanonical"));
        }
        let parsed = Self {
            code_bits: bytes[10],
            metric,
            dim: le_u32(bytes, 12) as usize,
            node_count: usize::try_from(le_u64(bytes, 16))
                .map_err(|_| corrupt("PQ node_count exceeds usize"))?,
            subvectors: le_u32(bytes, 24) as usize,
            centroids: le_u32(bytes, 28) as usize,
            subdim: le_u32(bytes, 32) as usize,
            iterations: le_u32(bytes, 36) as usize,
            source_hash: bytes[40..72].try_into().expect("32B"),
            graph_hash: bytes[72..104].try_into().expect("32B"),
            training_seed: bytes[104..136].try_into().expect("32B"),
            codebook_hash: bytes[136..168].try_into().expect("32B"),
            codebook_bytes: usize::try_from(le_u64(bytes, 168))
                .map_err(|_| corrupt("PQ codebook length exceeds usize"))?,
            codes_bytes: usize::try_from(le_u64(bytes, 176))
                .map_err(|_| corrupt("PQ codes length exceeds usize"))?,
        };
        validate_header(
            parsed.dim,
            parsed.node_count,
            parsed.subvectors,
            parsed.centroids,
            parsed.subdim,
            parsed.iterations,
            parsed.code_bits,
        )?;
        Ok(parsed)
    }

    fn validate_binding(&self, binding: DiskAnnPqBinding, expected_code_bits: u8) -> Result<()> {
        if self.metric != binding.metric
            || self.source_hash != binding.source_hash
            || self.graph_hash != binding.graph_hash
            || self.dim != binding.dim
            || self.node_count != binding.node_count
            || self.code_bits != expected_code_bits
        {
            return Err(corrupt(
                "PQ graph/source/metric/dimension/count/code-width binding mismatch",
            ));
        }
        let expected_seed = training_seed(
            binding,
            DiskAnnPqBuildParams {
                subvectors: self.subvectors,
                centroids: self.centroids,
                iterations: self.iterations,
                code_bits: self.code_bits,
            },
        );
        if self.training_seed != expected_seed {
            return Err(corrupt("PQ deterministic training seed mismatch"));
        }
        Ok(())
    }

    fn codebook_floats(&self) -> Result<usize> {
        self.subvectors
            .checked_mul(self.centroids)
            .and_then(|value| value.checked_mul(self.subdim))
            .ok_or_else(|| corrupt("PQ codebook size overflow"))
    }
}

fn validate_rows(
    rows: &[(u32, Vec<f32>)],
    params: DiskAnnPqBuildParams,
    binding: DiskAnnPqBinding,
) -> Result<()> {
    if rows.is_empty() {
        return Err(invalid("PQ requires at least one row"));
    }
    let dim = rows[0].1.len();
    if dim != binding.dim || rows.len() != binding.node_count {
        return Err(invalid("PQ rows disagree with the bound graph shape"));
    }
    validate_header(
        dim,
        rows.len(),
        params.subvectors,
        params.centroids,
        dim.checked_div(params.subvectors.max(1)).unwrap_or(0),
        params.iterations,
        params.code_bits,
    )
    .map_err(|error| invalid(error.message))?;
    if params.centroids > rows.len() {
        return Err(invalid(format!(
            "PQ centroids {} exceed training rows {}; gather more rows or reduce centroids",
            params.centroids,
            rows.len()
        )));
    }
    for (expected, (id, vector)) in rows.iter().enumerate() {
        if *id as usize != expected {
            return Err(invalid(format!(
                "PQ row id {id} expected dense id {expected}"
            )));
        }
        if vector.len() != dim {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                format!("PQ vector {id} dim {} expected {dim}", vector.len()),
            ));
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(invalid(format!("PQ vector {id} contains non-finite value")));
        }
    }
    Ok(())
}

fn validate_header(
    dim: usize,
    node_count: usize,
    subvectors: usize,
    centroids: usize,
    subdim: usize,
    iterations: usize,
    code_bits: u8,
) -> Result<()> {
    if dim == 0
        || node_count == 0
        || subvectors == 0
        || centroids == 0
        || subdim == 0
        || iterations == 0
    {
        return Err(corrupt("PQ header contains zero field"));
    }
    let max_centroids = match code_bits {
        4 => 16,
        8 => 256,
        other => return Err(corrupt(format!("PQ code width {other}; expected 4 or 8"))),
    };
    if centroids > max_centroids {
        return Err(corrupt(format!(
            "PQ centroids {centroids} exceed {code_bits}-bit code space {max_centroids}"
        )));
    }
    if subvectors.checked_mul(subdim) != Some(dim) {
        return Err(corrupt(format!(
            "PQ subvectors {subvectors} * subdim {subdim} != dim {dim}"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn train_subspace(
    rows: &[(u32, Vec<f32>)],
    offset: usize,
    subdim: usize,
    centroids: usize,
    iterations: usize,
    base_seed: [u8; 32],
    subvector: usize,
    out: &mut Vec<f32>,
) {
    let n = rows.len();
    let start = out.len();
    let mut seed_hasher = blake3::Hasher::new();
    seed_hasher.update(b"calyx/diskann/pq/kmeans++/v1\0");
    seed_hasher.update(&base_seed);
    seed_hasher.update(&(subvector as u64).to_le_bytes());
    let mut rng = ChaCha8Rng::from_seed(*seed_hasher.finalize().as_bytes());
    let first = rng.gen_range(0..n);
    out.extend_from_slice(&rows[first].1[offset..offset + subdim]);
    let mut min_distances = vec![f64::INFINITY; n];
    for centroid in 1..centroids {
        let newest = &out[start + (centroid - 1) * subdim..start + centroid * subdim];
        let mut total = 0.0_f64;
        for (row, (_, vector)) in rows.iter().enumerate() {
            let distance = f64::from(l2_sq(&vector[offset..offset + subdim], newest));
            min_distances[row] = min_distances[row].min(distance);
            total += min_distances[row];
        }
        let selected = if total > 0.0 && total.is_finite() {
            let mut threshold = rng.r#gen::<f64>() * total;
            let mut chosen = n - 1;
            for (row, distance) in min_distances.iter().copied().enumerate() {
                threshold -= distance;
                if threshold <= 0.0 {
                    chosen = row;
                    break;
                }
            }
            chosen
        } else {
            centroid % n
        };
        out.extend_from_slice(&rows[selected].1[offset..offset + subdim]);
    }
    let mut sums = vec![0.0_f64; centroids * subdim];
    let mut counts = vec![0_usize; centroids];
    let mut assignments = vec![0_usize; n];
    for _ in 0..iterations {
        sums.fill(0.0);
        counts.fill(0);
        for (row, (_, vector)) in rows.iter().enumerate() {
            let values = &vector[offset..offset + subdim];
            let nearest = nearest_in_codebook(values, &out[start..], centroids, subdim);
            assignments[row] = nearest;
            counts[nearest] += 1;
            let sum_at = nearest * subdim;
            for axis in 0..subdim {
                sums[sum_at + axis] += f64::from(values[axis]);
            }
        }
        for centroid in 0..centroids {
            let dst_at = start + centroid * subdim;
            if counts[centroid] == 0 {
                let farthest = rows
                    .iter()
                    .enumerate()
                    .max_by(|(left, (_, left_vector)), (right, (_, right_vector))| {
                        let left_center = assignments[*left];
                        let right_center = assignments[*right];
                        let left_distance = l2_sq(
                            &left_vector[offset..offset + subdim],
                            &out[start + left_center * subdim..start + (left_center + 1) * subdim],
                        );
                        let right_distance = l2_sq(
                            &right_vector[offset..offset + subdim],
                            &out[start + right_center * subdim
                                ..start + (right_center + 1) * subdim],
                        );
                        left_distance
                            .total_cmp(&right_distance)
                            .then_with(|| right.cmp(left))
                    })
                    .map_or(centroid % n, |(row, _)| row);
                out[dst_at..dst_at + subdim]
                    .copy_from_slice(&rows[farthest].1[offset..offset + subdim]);
                continue;
            }
            let sum_at = centroid * subdim;
            for axis in 0..subdim {
                out[dst_at + axis] = (sums[sum_at + axis] / counts[centroid] as f64) as f32;
            }
        }
    }
}

fn nearest_in_codebook(values: &[f32], codebook: &[f32], centroids: usize, subdim: usize) -> usize {
    (0..centroids)
        .min_by(|&left, &right| {
            let left_center = &codebook[left * subdim..(left + 1) * subdim];
            let right_center = &codebook[right * subdim..(right + 1) * subdim];
            l2_sq(values, left_center)
                .total_cmp(&l2_sq(values, right_center))
                .then_with(|| left.cmp(&right))
        })
        .unwrap_or(0)
}

fn training_seed(binding: DiskAnnPqBinding, params: DiskAnnPqBuildParams) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx/diskann/pq/training/v2\0");
    hasher.update(&binding.source_hash);
    hasher.update(&binding.graph_hash);
    hasher.update(&[binding.metric as u8, params.code_bits]);
    hasher.update(&(binding.dim as u32).to_le_bytes());
    hasher.update(&(binding.node_count as u64).to_le_bytes());
    hasher.update(&(params.subvectors as u32).to_le_bytes());
    hasher.update(&(params.centroids as u32).to_le_bytes());
    hasher.update(&(params.iterations as u32).to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn packed_code_bytes(code_count: usize, code_bits: u8) -> Result<usize> {
    match code_bits {
        4 => Ok(code_count.div_ceil(2)),
        8 => Ok(code_count),
        other => Err(invalid(format!("PQ code width {other}; expected 4 or 8"))),
    }
}

fn set_code(codes: &mut [u8], at: usize, code_bits: u8, code: usize) -> Result<()> {
    match code_bits {
        4 if code < 16 => {
            let byte = codes
                .get_mut(at / 2)
                .ok_or_else(|| invalid("PQ packed code offset out of range"))?;
            if at % 2 == 0 {
                *byte = (*byte & 0xf0) | code as u8;
            } else {
                *byte = (*byte & 0x0f) | ((code as u8) << 4);
            }
            Ok(())
        }
        8 if code < 256 => {
            *codes
                .get_mut(at)
                .ok_or_else(|| invalid("PQ code offset out of range"))? = code as u8;
            Ok(())
        }
        _ => Err(invalid(format!(
            "PQ code {code} does not fit {code_bits} bits"
        ))),
    }
}

fn code_at(codes: &[u8], at: usize, code_bits: u8) -> Result<usize> {
    match code_bits {
        4 => {
            let byte = *codes
                .get(at / 2)
                .ok_or_else(|| corrupt("PQ packed code offset out of range"))?;
            Ok(usize::from(if at % 2 == 0 {
                byte & 0x0f
            } else {
                byte >> 4
            }))
        }
        8 => codes
            .get(at)
            .copied()
            .map(usize::from)
            .ok_or_else(|| corrupt("PQ code offset out of range")),
        other => Err(corrupt(format!("PQ code width {other}"))),
    }
}

fn l2_sq(left: &[f32], right: &[f32]) -> f32 {
    left.iter()
        .zip(right)
        .map(|(left, right)| {
            let delta = left - right;
            delta * delta
        })
        .sum()
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2B"))
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4B"))
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8B"))
}

fn invalid(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_INVALID_PARAMS,
        format!("diskann PQ invalid: {detail}"),
    )
}

fn corrupt(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(CALYX_INDEX_CORRUPT, format!("diskann PQ corrupt: {detail}"))
}

fn io(stage: &str, error: std::io::Error) -> calyx_core::CalyxError {
    sextant_error(CALYX_INDEX_IO, format!("diskann PQ {stage}: {error}"))
}
