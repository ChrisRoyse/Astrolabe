//! DiskANN on-disk graph format: header, compact node blocks, writer,
//! mmap reader (PH68 T01). Construction lives in [`super::build`].
//!
//! Layout: one page-aligned header block (`CLXDA001`), then one fixed-size
//! block per node holding `[vector payload | neighbor_count: u32 | neighbors:
//! [u32; m_max] zero-padded]` so a single offset calculation fetches a node's
//! full search state. v4 payloads are either f32 or signed-int8 directional
//! codes with a cached norm, and the whole component is sealed. Node `id` lives at byte offset
//! `HEADER + id * node_block_size`.
//!
//! Server-only: embedded vaults keep the in-RAM HNSW from PH23.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use calyx_core::Result;
use memmap2::Mmap;

use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_INVALID_PARAMS, CALYX_INDEX_IO, sextant_error,
};

/// File magic at offset 0 of every `graph.cda`.
pub const DISKANN_MAGIC: [u8; 8] = *b"CLXDA001";
/// Integrity-bound graph format. Older graph-only formats are deliberately
/// refused: they do not carry metric/source identity, cached directional
/// norms, canonical padding, or a whole-file seal and must be rebuilt.
pub const DISKANN_FORMAT_VERSION: u32 = 4;
/// The header remains one 4 KiB page for mmap/old-reader stability.
pub const DISKANN_BLOCK_ALIGN: usize = 4096;
/// Node records are cache-line aligned instead of page padded.
pub const DISKANN_NODE_ALIGN: usize = 64;
/// Upper bound on vector dimensionality accepted by the format.
pub const DISKANN_MAX_DIM: usize = 8192;
/// Upper bound on `m_max` (graph out-degree capacity) accepted by the format.
pub const DISKANN_MAX_M: usize = 512;
/// BLAKE3 seal appended to every physical graph.
pub const DISKANN_GRAPH_SEAL_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DiskAnnMetric {
    UnitL2 = 1,
    RawL2 = 2,
}

impl DiskAnnMetric {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::UnitL2),
            2 => Ok(Self::RawL2),
            other => Err(corrupt(format!("unsupported metric tag {other}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DiskAnnVectorEncoding {
    DirectionalI8 = 1,
    F32 = 2,
}

impl DiskAnnVectorEncoding {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::DirectionalI8),
            2 => Ok(Self::F32),
            other => Err(corrupt(format!("unsupported vector encoding tag {other}"))),
        }
    }
}

/// Size in bytes of one node block: vector + count + padded neighbor list,
/// rounded up to the compact node alignment.
pub const fn node_block_size(dim: usize, m_max: usize) -> usize {
    compact_i8_node_block_size(dim, m_max)
}

const fn compact_f32_node_block_size(dim: usize, m_max: usize) -> usize {
    (dim * 4 + 4 + m_max * 4).div_ceil(DISKANN_NODE_ALIGN) * DISKANN_NODE_ALIGN
}

const fn compact_i8_node_block_size(dim: usize, m_max: usize) -> usize {
    (i8_payload_len(dim) + 4 + m_max * 4).div_ceil(DISKANN_NODE_ALIGN) * DISKANN_NODE_ALIGN
}

const fn i8_payload_len(dim: usize) -> usize {
    // Four-byte align the signed codes, then persist the exact code-domain
    // norm once. Search never recomputes it per candidate.
    dim.div_ceil(4) * 4 + 4
}

const fn node_block_size_for_header(header: &DiskAnnHeader) -> usize {
    match header.vector_encoding {
        DiskAnnVectorEncoding::F32 => {
            compact_f32_node_block_size(header.dim as usize, header.m_max as usize)
        }
        DiskAnnVectorEncoding::DirectionalI8 => {
            compact_i8_node_block_size(header.dim as usize, header.m_max as usize)
        }
    }
}

fn corrupt(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_CORRUPT,
        format!("diskann graph corrupt: {detail}"),
    )
}

pub(super) fn invalid(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_INVALID_PARAMS,
        format!("diskann invalid params: {detail}"),
    )
}

fn io_err(stage: &str, error: std::io::Error) -> calyx_core::CalyxError {
    sextant_error(CALYX_INDEX_IO, format!("diskann {stage}: {error}"))
}

/// Fixed header written as the first `DISKANN_BLOCK_ALIGN` block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskAnnHeader {
    pub format_version: u32,
    pub dim: u32,
    pub m_max: u32,
    pub max_degree: u32,
    pub entry_point_id: u32,
    pub node_count: u64,
    pub metric: DiskAnnMetric,
    pub vector_encoding: DiskAnnVectorEncoding,
    pub code_bits: u8,
    pub source_hash: [u8; 32],
}

impl DiskAnnHeader {
    fn encode(&self) -> [u8; DISKANN_BLOCK_ALIGN] {
        let mut block = [0_u8; DISKANN_BLOCK_ALIGN];
        block[0..8].copy_from_slice(&DISKANN_MAGIC);
        block[8..12].copy_from_slice(&self.format_version.to_le_bytes());
        block[12..16].copy_from_slice(&self.dim.to_le_bytes());
        block[16..20].copy_from_slice(&self.m_max.to_le_bytes());
        block[20..24].copy_from_slice(&self.max_degree.to_le_bytes());
        block[24..28].copy_from_slice(&self.entry_point_id.to_le_bytes());
        block[28..36].copy_from_slice(&self.node_count.to_le_bytes());
        block[36] = self.metric as u8;
        block[37] = self.vector_encoding as u8;
        block[38] = self.code_bits;
        block[40..72].copy_from_slice(&self.source_hash);
        block
    }

    fn decode(block: &[u8]) -> Result<Self> {
        if block.len() < 36 {
            return Err(corrupt("header block shorter than 36 bytes"));
        }
        if block[0..8] != DISKANN_MAGIC {
            return Err(corrupt(format!("bad magic {:02x?}", &block[0..8])));
        }
        let le_u32 = |at: usize| u32::from_le_bytes(block[at..at + 4].try_into().expect("4B"));
        let header = Self {
            format_version: le_u32(8),
            dim: le_u32(12),
            m_max: le_u32(16),
            max_degree: le_u32(20),
            entry_point_id: le_u32(24),
            node_count: u64::from_le_bytes(block[28..36].try_into().expect("8B")),
            metric: DiskAnnMetric::decode(block[36])?,
            vector_encoding: DiskAnnVectorEncoding::decode(block[37])?,
            code_bits: block[38],
            source_hash: block[40..72].try_into().expect("32B"),
        };
        if header.format_version != DISKANN_FORMAT_VERSION {
            return Err(corrupt(format!(
                "format_version {} is not integrity-bound v{DISKANN_FORMAT_VERSION}; rebuild the graph",
                header.format_version
            )));
        }
        if header.dim == 0 || header.dim as usize > DISKANN_MAX_DIM {
            return Err(corrupt(format!(
                "dim {} out of 1..={DISKANN_MAX_DIM}",
                header.dim
            )));
        }
        if header.m_max == 0 || header.m_max as usize > DISKANN_MAX_M {
            return Err(corrupt(format!(
                "m_max {} out of 1..={DISKANN_MAX_M}",
                header.m_max
            )));
        }
        if header.max_degree > header.m_max {
            return Err(corrupt(format!("max_degree {} > m_max", header.max_degree)));
        }
        if header.node_count == 0 {
            return Err(corrupt("node_count is zero"));
        }
        if header.node_count > u64::from(u32::MAX) {
            return Err(corrupt(format!(
                "node_count {} exceeds the u32 node-id contract",
                header.node_count
            )));
        }
        if u64::from(header.entry_point_id) >= header.node_count {
            return Err(corrupt(format!(
                "entry_point_id {} >= node_count",
                header.entry_point_id
            )));
        }
        match (header.metric, header.vector_encoding, header.code_bits) {
            (DiskAnnMetric::UnitL2, DiskAnnVectorEncoding::DirectionalI8, 8)
            | (DiskAnnMetric::RawL2, DiskAnnVectorEncoding::F32, 32) => {}
            tuple => {
                return Err(corrupt(format!(
                    "unsupported metric/encoding/code_bits contract {tuple:?}"
                )));
            }
        }
        if header.source_hash == [0; 32] {
            return Err(corrupt("source hash is all-zero"));
        }
        if block[39] != 0 || block[72..].iter().any(|byte| *byte != 0) {
            return Err(corrupt("header reserved bytes are noncanonical"));
        }
        Ok(header)
    }
}

/// Sequential page-aligned writer. Stages into `<final>.tmp` in the same
/// directory (same filesystem — no `EXDEV`) and publishes atomically on
/// `finish()`; a crash never leaves a partial `graph.cda` behind.
pub(super) struct DiskAnnGraphWriter {
    out: Option<BufWriter<File>>,
    tmp_path: PathBuf,
    final_path: PathBuf,
    header: DiskAnnHeader,
    block: usize,
    next_id: u32,
    hasher: blake3::Hasher,
}

impl DiskAnnGraphWriter {
    pub(super) fn create(path: &Path, header: DiskAnnHeader) -> Result<Self> {
        // Re-validate through the same gate readers use: a header we would
        // refuse to read back must never be written.
        DiskAnnHeader::decode(&header.encode())?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| io_err("create index dir", e))?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp_path = PathBuf::from(tmp);
        let file = File::create(&tmp_path).map_err(|e| io_err("create tmp graph file", e))?;
        let mut out = BufWriter::new(file);
        let header_bytes = header.encode();
        out.write_all(&header_bytes)
            .map_err(|e| io_err("write header block", e))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&header_bytes);
        Ok(Self {
            out: Some(out),
            tmp_path,
            final_path: path.to_path_buf(),
            header,
            block: node_block_size_for_header(&header),
            next_id: 0,
            hasher,
        })
    }

    pub(super) fn write_node(&mut self, id: u32, vector: &[f32], neighbors: &[u32]) -> Result<()> {
        if id != self.next_id {
            return Err(invalid(format!(
                "node id {id} out of order (expected {})",
                self.next_id
            )));
        }
        if u64::from(id) >= self.header.node_count {
            return Err(invalid(format!(
                "node id {id} >= node_count {}",
                self.header.node_count
            )));
        }
        if vector.len() != self.header.dim as usize {
            return Err(invalid(format!("node {id} vector len {}", vector.len())));
        }
        if vector.iter().any(|v| !v.is_finite()) {
            return Err(invalid(format!(
                "node {id} vector has non-finite component"
            )));
        }
        if neighbors.len() > self.header.m_max as usize {
            return Err(invalid(format!(
                "node {id} degree {} > m_max",
                neighbors.len()
            )));
        }
        let mut unique = BTreeSet::new();
        for &n in neighbors {
            if u64::from(n) >= self.header.node_count || n == id {
                return Err(invalid(format!("node {id} has invalid neighbor id {n}")));
            }
            if !unique.insert(n) {
                return Err(invalid(format!("node {id} repeats neighbor id {n}")));
            }
        }
        let out = self
            .out
            .as_mut()
            .ok_or_else(|| invalid("writer already finished"))?;
        let mut block = vec![0_u8; self.block];
        let payload_len = write_vector_payload(&mut block, &self.header, vector)?;
        let count = u32::try_from(neighbors.len()).expect("<= m_max <= 512");
        block[payload_len..payload_len + 4].copy_from_slice(&count.to_le_bytes());
        for (index, n) in neighbors.iter().enumerate() {
            let at = payload_len + 4 + index * 4;
            block[at..at + 4].copy_from_slice(&n.to_le_bytes());
        }
        out.write_all(&block)
            .map_err(|e| io_err("write node block", e))?;
        self.hasher.update(&block);
        self.next_id += 1;
        Ok(())
    }

    /// Flush + fsync the staged file, then atomically rename it into place.
    pub(super) fn finish(mut self) -> Result<()> {
        if u64::from(self.next_id) != self.header.node_count {
            return Err(invalid(format!(
                "finish after {} nodes; header promised {}",
                self.next_id, self.header.node_count
            )));
        }
        let mut out = self
            .out
            .take()
            .ok_or_else(|| invalid("writer already finished"))?;
        out.write_all(self.hasher.finalize().as_bytes())
            .map_err(|e| io_err("write graph seal", e))?;
        let file = out
            .into_inner()
            .map_err(|e| io_err("flush graph", e.into_error()))?;
        file.sync_all().map_err(|e| io_err("fsync graph", e))?;
        drop(file);
        fs::rename(&self.tmp_path, &self.final_path)
            .map_err(|e| io_err("publish graph (rename tmp)", e))
    }
}

impl Drop for DiskAnnGraphWriter {
    fn drop(&mut self) {
        if self.out.is_some() {
            self.out = None; // close handle before unlink (Windows)
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

fn write_vector_payload(out: &mut [u8], header: &DiskAnnHeader, vector: &[f32]) -> Result<usize> {
    match header.vector_encoding {
        DiskAnnVectorEncoding::F32 => {
            for (index, value) in vector.iter().enumerate() {
                let at = index * 4;
                out[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            Ok(vector.len() * 4)
        }
        DiskAnnVectorEncoding::DirectionalI8 => {
            let source_norm = vector
                .iter()
                .map(|value| f64::from(*value) * f64::from(*value))
                .sum::<f64>()
                .sqrt();
            if !source_norm.is_finite() || (source_norm - 1.0).abs() > 1.0e-4 {
                return Err(invalid(format!(
                    "directional graph requires unit vectors; observed norm {source_norm:.9}"
                )));
            }
            let row = quantize_direction_i8(vector);
            for (dst, value) in out[..row.len()].iter_mut().zip(&row) {
                *dst = *value as u8;
            }
            let codes_padded = vector.len().div_ceil(4) * 4;
            let norm = row
                .iter()
                .map(|value| f64::from(*value) * f64::from(*value))
                .sum::<f64>()
                .sqrt() as f32;
            if !norm.is_finite() || norm <= 0.0 {
                return Err(invalid(
                    "directional quantization produced invalid code norm",
                ));
            }
            out[codes_padded..codes_padded + 4].copy_from_slice(&norm.to_le_bytes());
            let payload = i8_payload_len(vector.len());
            Ok(payload)
        }
    }
}

fn quantize_direction_i8(vector: &[f32]) -> Vec<i8> {
    let max_abs = vector
        .iter()
        .map(|value| value.abs())
        .fold(0.0_f32, f32::max);
    if max_abs == 0.0 {
        return vec![0; vector.len()];
    }
    let scale = 127.0 / max_abs;
    vector
        .iter()
        .map(|value| (value * scale).round().clamp(-127.0, 127.0) as i8)
        .collect()
}

/// Zero-copy view of one node inside the mapped graph file.
#[derive(Debug)]
pub struct DiskAnnNodeRef<'a> {
    pub vector: DiskAnnVectorRef<'a>,
    pub neighbors: &'a [u32],
}

#[derive(Clone, Copy, Debug)]
pub enum DiskAnnVectorRef<'a> {
    F32(&'a [f32]),
    I8 { codes: &'a [i8], norm: f32 },
}

impl DiskAnnVectorRef<'_> {
    pub fn to_vec(self) -> Vec<f32> {
        match self {
            Self::F32(values) => values.to_vec(),
            Self::I8 { codes, .. } => codes
                .iter()
                .map(|value| f32::from(*value))
                .collect::<Vec<_>>(),
        }
    }
}

/// mmap-backed reader. The file is published atomically by the writer and
/// never mutated afterwards; the map is read-only.
#[derive(Debug)]
pub struct DiskAnnGraphReader {
    mmap: Mmap,
    header: DiskAnnHeader,
    block: usize,
}

impl DiskAnnGraphReader {
    pub fn open(path: &Path) -> Result<Self> {
        let generation = super::generation::DiskAnnGeneration::open(path)?;
        Self::open_physical(generation.graph_path())
    }

    pub(super) fn open_physical(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(|e| io_err("open graph file", e))?;
        let len = file
            .metadata()
            .map_err(|e| io_err("stat graph file", e))?
            .len();
        if len < DISKANN_BLOCK_ALIGN as u64 {
            return Err(corrupt(format!(
                "file is {len} B, smaller than one header block"
            )));
        }
        let mut header_block = [0_u8; DISKANN_BLOCK_ALIGN];
        file.read_exact(&mut header_block)
            .map_err(|error| io_err("read graph header", error))?;
        let header = DiskAnnHeader::decode(&header_block)?;
        let block = node_block_size_for_header(&header);
        let body_bytes = header
            .node_count
            .checked_mul(block as u64)
            .ok_or_else(|| corrupt("graph body size overflow"))?;
        let expected = (DISKANN_BLOCK_ALIGN as u64)
            .checked_add(body_bytes)
            .and_then(|value| value.checked_add(DISKANN_GRAPH_SEAL_BYTES as u64))
            .ok_or_else(|| corrupt("graph file size overflow"))?;
        if len != expected {
            return Err(corrupt(format!(
                "file len {len} != expected {expected} ({} x {block} B node blocks)",
                header.node_count
            )));
        }
        // SAFETY: the validated header bounds the exact mapping length; active
        // generation components are immutable and content-addressed.
        let mmap = unsafe { Mmap::map(&file).map_err(|e| io_err("mmap graph file", e))? };
        let sealed_at = mmap.len() - DISKANN_GRAPH_SEAL_BYTES;
        let actual = blake3::hash(&mmap[..sealed_at]);
        if actual.as_bytes() != &mmap[sealed_at..] {
            return Err(corrupt(format!(
                "whole-file BLAKE3 mismatch: computed {}",
                actual.to_hex()
            )));
        }
        let reader = Self {
            mmap,
            header,
            block,
        };
        reader.validate_all_nodes()?;
        Ok(reader)
    }

    pub fn header(&self) -> &DiskAnnHeader {
        &self.header
    }

    pub fn node_count(&self) -> u64 {
        self.header.node_count
    }

    pub fn node_block_size(&self) -> usize {
        self.block
    }

    pub fn node_block_offset(&self, id: u32) -> Result<u64> {
        if u64::from(id) >= self.header.node_count {
            return Err(invalid(format!(
                "node id {id} >= node_count {}",
                self.header.node_count
            )));
        }
        Ok((DISKANN_BLOCK_ALIGN + id as usize * self.block) as u64)
    }

    pub fn read_node(&self, id: u32) -> Result<DiskAnnNodeRef<'_>> {
        self.read_node_inner(id, false)
    }

    fn read_node_inner(&self, id: u32, validate_contents: bool) -> Result<DiskAnnNodeRef<'_>> {
        if u64::from(id) >= self.header.node_count {
            return Err(invalid(format!(
                "node id {id} >= node_count {}",
                self.header.node_count
            )));
        }
        let dim = self.header.dim as usize;
        let start = DISKANN_BLOCK_ALIGN + id as usize * self.block;
        let bytes = &self.mmap[start..start + self.block];
        let (vector, count_at) = match self.header.vector_encoding {
            DiskAnnVectorEncoding::F32 => {
                let vector = cast_le_slice::<f32>(&bytes[..dim * 4], "vector")?;
                if validate_contents && vector.iter().any(|value| !value.is_finite()) {
                    return Err(corrupt(format!("node {id} has non-finite f32 vector")));
                }
                (DiskAnnVectorRef::F32(vector), dim * 4)
            }
            DiskAnnVectorEncoding::DirectionalI8 => {
                let codes = cast_le_slice::<i8>(&bytes[..dim], "i8 vector")?;
                let codes_padded = dim.div_ceil(4) * 4;
                if validate_contents && bytes[dim..codes_padded].iter().any(|byte| *byte != 0) {
                    return Err(corrupt(format!("node {id} has noncanonical i8 padding")));
                }
                let norm = f32::from_le_bytes(
                    bytes[codes_padded..codes_padded + 4]
                        .try_into()
                        .expect("4B"),
                );
                if !norm.is_finite() || norm <= 0.0 {
                    return Err(corrupt(format!("node {id} has invalid cached i8 norm")));
                }
                if validate_contents {
                    let computed = codes
                        .iter()
                        .map(|value| f64::from(*value) * f64::from(*value))
                        .sum::<f64>()
                        .sqrt() as f32;
                    if (computed - norm).abs() > 1.0e-3 {
                        return Err(corrupt(format!(
                            "node {id} cached i8 norm {norm} != computed {computed}"
                        )));
                    }
                }
                (DiskAnnVectorRef::I8 { codes, norm }, i8_payload_len(dim))
            }
        };
        let count =
            u32::from_le_bytes(bytes[count_at..count_at + 4].try_into().expect("4B")) as usize;
        if count > self.header.m_max as usize {
            return Err(corrupt(format!("node {id} neighbor_count {count} > m_max")));
        }
        let nb_at = count_at + 4;
        let neighbors = cast_le_slice::<u32>(&bytes[nb_at..nb_at + count * 4], "neighbors")?;
        if validate_contents {
            let mut unique = BTreeSet::new();
            for neighbor in neighbors {
                if u64::from(*neighbor) >= self.header.node_count || *neighbor == id {
                    return Err(corrupt(format!(
                        "node {id} has invalid neighbor {neighbor}"
                    )));
                }
                if !unique.insert(*neighbor) {
                    return Err(corrupt(format!("node {id} repeats neighbor {neighbor}")));
                }
            }
            let used = nb_at + count * 4;
            if bytes[used..].iter().any(|byte| *byte != 0) {
                return Err(corrupt(format!("node {id} has noncanonical block padding")));
            }
        }
        Ok(DiskAnnNodeRef { vector, neighbors })
    }

    fn validate_all_nodes(&self) -> Result<()> {
        let mut observed_max_degree = 0_u32;
        for id in 0..self.header.node_count as u32 {
            let node = self.read_node_inner(id, true)?;
            observed_max_degree = observed_max_degree.max(node.neighbors.len() as u32);
        }
        if observed_max_degree != self.header.max_degree {
            return Err(corrupt(format!(
                "header max_degree {} != observed {observed_max_degree}",
                self.header.max_degree
            )));
        }
        Ok(())
    }
}

/// Reinterpret little-endian on-disk bytes as `&[T]` without copying. Fails
/// closed (`CALYX_INDEX_CORRUPT`) if the region is misaligned rather than
/// panicking; blocks are 4 KiB-aligned within a page-aligned map, so a
/// misalignment can only mean a corrupt/foreign file.
fn cast_le_slice<'a, T>(bytes: &'a [u8], what: &str) -> Result<&'a [T]> {
    debug_assert_eq!(bytes.len() % size_of::<T>(), 0);
    if bytes.as_ptr().align_offset(align_of::<T>()) != 0 {
        return Err(corrupt(format!(
            "{what} region misaligned for zero-copy read"
        )));
    }
    // SAFETY: alignment checked above; length is an exact multiple of the
    // element size; f32/u32 accept any bit pattern; lifetime tied to the map.
    Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len() / size_of::<T>()) })
}

/// Open an existing `graph.cda` for zero-copy reads.
pub fn open_diskann_graph(path: &Path) -> Result<DiskAnnGraphReader> {
    DiskAnnGraphReader::open(path)
}
