//! Contiguous, sealed raw-vector refinement component for one DiskANN generation.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

use calyx_core::Result;
use memmap2::Mmap;

use super::graph::DiskAnnMetric;
use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_INVALID_PARAMS, CALYX_INDEX_IO, sextant_error,
};

const RAW_MAGIC: [u8; 8] = *b"CLXDAR01";
const RAW_VERSION: u16 = 1;
const HEADER_BYTES: usize = 128;
const SEAL_BYTES: usize = 32;

#[derive(Debug)]
pub struct DiskAnnRawIndex {
    mmap: Mmap,
    dim: usize,
    node_count: usize,
    source_hash: [u8; 32],
}

impl DiskAnnRawIndex {
    pub(super) fn write_staged(
        path: &Path,
        rows: &[(u32, Vec<f32>)],
        graph_source_hash: [u8; 32],
        graph_hash: [u8; 32],
        metric: DiskAnnMetric,
    ) -> Result<()> {
        validate_rows(rows)?;
        let dim = rows[0].1.len();
        let node_count = rows.len();
        let payload_bytes = node_count
            .checked_mul(dim)
            .and_then(|values| values.checked_mul(4))
            .ok_or_else(|| invalid("raw payload size overflow"))?;
        let source_hash = raw_source_hash(rows);
        let mut header = [0_u8; HEADER_BYTES];
        header[0..8].copy_from_slice(&RAW_MAGIC);
        header[8..10].copy_from_slice(&RAW_VERSION.to_le_bytes());
        header[10] = metric as u8;
        header[12..16].copy_from_slice(&(dim as u32).to_le_bytes());
        header[16..24].copy_from_slice(&(node_count as u64).to_le_bytes());
        header[24..56].copy_from_slice(&graph_source_hash);
        header[56..88].copy_from_slice(&graph_hash);
        header[88..120].copy_from_slice(&source_hash);
        header[120..128].copy_from_slice(&(payload_bytes as u64).to_le_bytes());
        let mut file =
            File::create(path).map_err(|error| io("create staged raw component", error))?;
        let mut hasher = blake3::Hasher::new();
        file.write_all(&header)
            .map_err(|error| io("write raw header", error))?;
        hasher.update(&header);
        for (_, vector) in rows {
            for value in vector {
                let bytes = value.to_le_bytes();
                file.write_all(&bytes)
                    .map_err(|error| io("write raw vector", error))?;
                hasher.update(&bytes);
            }
        }
        file.write_all(hasher.finalize().as_bytes())
            .map_err(|error| io("write raw seal", error))?;
        file.sync_all()
            .map_err(|error| io("fsync raw component", error))
    }

    pub(super) fn read(
        path: &Path,
        expected_graph_source_hash: [u8; 32],
        expected_graph_hash: [u8; 32],
        expected_metric: DiskAnnMetric,
        expected_dim: usize,
        expected_node_count: usize,
    ) -> Result<Self> {
        let mut file = File::open(path).map_err(|error| io("open raw component", error))?;
        let len = file
            .metadata()
            .map_err(|error| io("stat raw component", error))?
            .len();
        if len < (HEADER_BYTES + SEAL_BYTES) as u64 {
            return Err(corrupt(format!("raw component is only {len} bytes")));
        }
        let mut header = [0_u8; HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|error| io("read raw header", error))?;
        if header[0..8] != RAW_MAGIC {
            return Err(corrupt("raw component magic mismatch"));
        }
        let version = u16::from_le_bytes(header[8..10].try_into().expect("2B"));
        if version != RAW_VERSION {
            return Err(corrupt(format!("raw component version {version}")));
        }
        let metric = match header[10] {
            1 => DiskAnnMetric::UnitL2,
            2 => DiskAnnMetric::RawL2,
            other => return Err(corrupt(format!("raw component metric tag {other}"))),
        };
        if header[11] != 0 {
            return Err(corrupt("raw component reserved bytes are noncanonical"));
        }
        let dim = le_u32(&header, 12) as usize;
        let node_count = usize::try_from(le_u64(&header, 16))
            .map_err(|_| corrupt("raw node_count exceeds usize"))?;
        let graph_source_hash: [u8; 32] = header[24..56].try_into().expect("32B");
        let graph_hash: [u8; 32] = header[56..88].try_into().expect("32B");
        let source_hash: [u8; 32] = header[88..120].try_into().expect("32B");
        let payload_bytes = usize::try_from(le_u64(&header, 120))
            .map_err(|_| corrupt("raw payload length exceeds usize"))?;
        let expected_payload = node_count
            .checked_mul(dim)
            .and_then(|values| values.checked_mul(4))
            .ok_or_else(|| corrupt("raw payload size overflow"))?;
        if dim != expected_dim
            || node_count != expected_node_count
            || graph_source_hash != expected_graph_source_hash
            || graph_hash != expected_graph_hash
            || metric != expected_metric
            || payload_bytes != expected_payload
            || len != (HEADER_BYTES + payload_bytes + SEAL_BYTES) as u64
        {
            return Err(corrupt(format!(
                "raw component contract mismatch: metric={metric:?}/{expected_metric:?} dim={dim}/{expected_dim} nodes={node_count}/{expected_node_count} payload={payload_bytes}/{expected_payload}"
            )));
        }
        // SAFETY: the fixed header and expected graph binding established the
        // exact mapping length before any virtual address space was reserved.
        let mmap = unsafe { Mmap::map(&file).map_err(|error| io("mmap raw component", error))? };
        let seal_at = mmap.len() - SEAL_BYTES;
        let computed = blake3::hash(&mmap[..seal_at]);
        if computed.as_bytes() != &mmap[seal_at..] {
            return Err(corrupt(format!(
                "raw component seal mismatch: computed {}",
                computed.to_hex()
            )));
        }
        let index = Self {
            mmap,
            dim,
            node_count,
            source_hash,
        };
        index.validate_all()?;
        Ok(index)
    }

    pub fn vector(&self, id: u32) -> Result<&[f32]> {
        let id = id as usize;
        if id >= self.node_count {
            return Err(invalid(format!(
                "raw node {id} outside {}",
                self.node_count
            )));
        }
        let at = HEADER_BYTES + id * self.dim * 4;
        let bytes = &self.mmap[at..at + self.dim * 4];
        if bytes.as_ptr().align_offset(align_of::<f32>()) != 0 {
            return Err(corrupt("raw vector is not f32-aligned"));
        }
        // SAFETY: alignment and exact byte length are checked; f32 accepts all
        // bit patterns, and open eagerly rejected non-finite values.
        Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), self.dim) })
    }

    pub fn source_hash(&self) -> [u8; 32] {
        self.source_hash
    }

    pub fn ram_bytes(&self) -> usize {
        self.mmap.len()
    }

    fn validate_all(&self) -> Result<()> {
        for id in 0..self.node_count as u32 {
            if self.vector(id)?.iter().any(|value| !value.is_finite()) {
                return Err(corrupt(format!("raw vector {id} contains non-finite f32")));
            }
        }
        Ok(())
    }
}

pub(super) fn raw_source_hash(rows: &[(u32, Vec<f32>)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx/diskann/raw-source/v1\0");
    hasher.update(&(rows.len() as u64).to_le_bytes());
    hasher.update(&(rows.first().map_or(0, |(_, vector)| vector.len()) as u32).to_le_bytes());
    for (id, vector) in rows {
        hasher.update(&id.to_le_bytes());
        for value in vector {
            hasher.update(&value.to_bits().to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn validate_rows(rows: &[(u32, Vec<f32>)]) -> Result<()> {
    let Some((_, first)) = rows.first() else {
        return Err(invalid("raw refinement requires at least one row"));
    };
    if first.is_empty() {
        return Err(invalid("raw refinement dimension must be positive"));
    }
    for (expected, (id, vector)) in rows.iter().enumerate() {
        if *id as usize != expected || vector.len() != first.len() {
            return Err(invalid(format!(
                "raw row {id} is not dense or has dimension {} instead of {}",
                vector.len(),
                first.len()
            )));
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(invalid(format!("raw row {id} contains non-finite f32")));
        }
    }
    Ok(())
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
        format!("diskann raw invalid: {detail}"),
    )
}

fn corrupt(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_CORRUPT,
        format!("diskann raw corrupt: {detail}"),
    )
}

fn io(stage: &str, error: std::io::Error) -> calyx_core::CalyxError {
    sextant_error(CALYX_INDEX_IO, format!("diskann raw {stage}: {error}"))
}
