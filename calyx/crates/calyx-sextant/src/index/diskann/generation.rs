//! Atomic DiskANN generation publication.
//!
//! The caller-visible `graph.cda` path is a small active-generation pointer.
//! It is published last and names immutable, content-addressed graph/raw/PQ
//! components in the same directory. Readers validate the pointer seal,
//! generation root, exact component lengths and BLAKE3 digests before any
//! candidate is served. A partial build is therefore unreachable, while a
//! missing or mixed component fails closed instead of changing the search
//! contract.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use calyx_core::Result;

use super::graph::{DiskAnnGraphReader, DiskAnnMetric};
use crate::error::{CALYX_INDEX_CORRUPT, CALYX_INDEX_IO, sextant_error};

pub const DISKANN_GENERATION_MAGIC: [u8; 8] = *b"CLXDAG01";
pub const DISKANN_GENERATION_VERSION: u16 = 1;
const FIXED_HEADER_BYTES: usize = 224;
const SEAL_BYTES: usize = 32;
const MAX_COMPONENT_NAME_BYTES: usize = 255;
const FLAG_RAW: u8 = 1;
const FLAG_PQ: u8 = 2;

#[derive(Clone, Debug)]
pub struct DiskAnnGeneration {
    logical_path: PathBuf,
    graph_path: PathBuf,
    raw_path: Option<PathBuf>,
    pq_path: Option<PathBuf>,
    generation_id: [u8; 32],
    source_hash: [u8; 32],
    graph_hash: [u8; 32],
    raw_hash: [u8; 32],
    pq_hash: [u8; 32],
    graph_bytes: u64,
    raw_bytes: u64,
    pq_bytes: u64,
    pointer_bytes: u64,
    node_count: u64,
    dim: u32,
    m_max: u32,
    metric: DiskAnnMetric,
    pq_code_bits: u8,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct StagedComponents<'a> {
    pub graph: &'a Path,
    pub raw: Option<&'a Path>,
    pub pq: Option<&'a Path>,
    pub pq_code_bits: u8,
}

impl DiskAnnGeneration {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(|error| io("open active generation", error))?;
        let len = usize::try_from(
            file.metadata()
                .map_err(|error| io("stat active generation", error))?
                .len(),
        )
        .map_err(|_| corrupt("active generation length exceeds usize"))?;
        let maximum = FIXED_HEADER_BYTES + 3 * MAX_COMPONENT_NAME_BYTES + SEAL_BYTES;
        if !(FIXED_HEADER_BYTES + SEAL_BYTES..=maximum).contains(&len) {
            return Err(corrupt(format!(
                "active generation {} length {len} is outside {}..={maximum}",
                path.display(),
                FIXED_HEADER_BYTES + SEAL_BYTES
            )));
        }
        let mut bytes = vec![0_u8; len];
        file.read_exact(&mut bytes)
            .map_err(|error| io("read active generation", error))?;
        let decoded = decode_manifest(path, &bytes)?;
        decoded.validate_components()?;
        Ok(decoded)
    }

    pub fn graph_path(&self) -> &Path {
        &self.graph_path
    }

    pub fn raw_path(&self) -> Option<&Path> {
        self.raw_path.as_deref()
    }

    pub fn pq_path(&self) -> Option<&Path> {
        self.pq_path.as_deref()
    }

    pub fn generation_id(&self) -> [u8; 32] {
        self.generation_id
    }

    pub fn source_hash(&self) -> [u8; 32] {
        self.source_hash
    }

    pub fn graph_hash(&self) -> [u8; 32] {
        self.graph_hash
    }

    pub fn raw_hash(&self) -> Option<[u8; 32]> {
        self.raw_path.as_ref().map(|_| self.raw_hash)
    }

    pub fn pq_hash(&self) -> Option<[u8; 32]> {
        self.pq_path.as_ref().map(|_| self.pq_hash)
    }

    pub fn node_count(&self) -> u64 {
        self.node_count
    }

    pub fn dim(&self) -> u32 {
        self.dim
    }

    pub fn metric(&self) -> DiskAnnMetric {
        self.metric
    }

    pub fn pq_code_bits(&self) -> Option<u8> {
        (self.pq_path.is_some()).then_some(self.pq_code_bits)
    }

    pub fn physical_bytes(&self) -> u64 {
        self.graph_bytes + self.raw_bytes + self.pq_bytes + self.pointer_bytes()
    }

    pub fn graph_bytes(&self) -> u64 {
        self.graph_bytes
    }

    pub fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }

    pub fn pq_bytes(&self) -> u64 {
        self.pq_bytes
    }

    pub fn pointer_bytes(&self) -> u64 {
        self.pointer_bytes
    }

    fn validate_components(&self) -> Result<()> {
        validate_component("graph", &self.graph_path, self.graph_bytes, self.graph_hash)?;
        match (&self.raw_path, self.raw_bytes) {
            (Some(path), bytes) if bytes > 0 => {
                validate_component("raw", path, bytes, self.raw_hash)?
            }
            (None, 0) => {}
            _ => return Err(corrupt("raw component presence/length mismatch")),
        }
        match (&self.pq_path, self.pq_bytes) {
            (Some(path), bytes) if bytes > 0 => {
                validate_component("pq", path, bytes, self.pq_hash)?
            }
            (None, 0) => {}
            _ => return Err(corrupt("pq component presence/length mismatch")),
        }
        let reader = DiskAnnGraphReader::open_physical(&self.graph_path)?;
        let header = reader.header();
        if header.source_hash != self.source_hash
            || header.metric != self.metric
            || header.node_count != self.node_count
            || header.dim != self.dim
            || header.m_max != self.m_max
        {
            return Err(corrupt(
                "active generation metadata disagrees with the sealed graph header",
            ));
        }
        Ok(())
    }
}

pub(super) fn publish(
    logical_path: &Path,
    components: StagedComponents<'_>,
) -> Result<DiskAnnGeneration> {
    let reader = DiskAnnGraphReader::open_physical(components.graph)?;
    let header = *reader.header();
    drop(reader);
    let graph_bytes = file_len(components.graph, "graph")?;
    let graph_hash = hash_file(components.graph)?;
    let (raw_bytes, raw_hash) = component_identity(components.raw, "raw")?;
    let (pq_bytes, pq_hash) = component_identity(components.pq, "pq")?;
    if components.pq.is_some() != matches!(components.pq_code_bits, 4 | 8) {
        return Err(corrupt(
            "PQ presence requires declared 4-bit or 8-bit codes, and absence requires zero",
        ));
    }
    let generation_id = generation_root(
        header.metric,
        header.source_hash,
        graph_hash,
        raw_hash,
        pq_hash,
        graph_bytes,
        raw_bytes,
        pq_bytes,
        header.node_count,
        header.dim,
        header.m_max,
        components.pq_code_bits,
    );
    let graph_path = publish_component(logical_path, components.graph, "graph", graph_hash)?;
    let raw_path = components
        .raw
        .map(|path| publish_component(logical_path, path, "raw", raw_hash))
        .transpose()?;
    let pq_path = components
        .pq
        .map(|path| publish_component(logical_path, path, "pq", pq_hash))
        .transpose()?;
    let generation = DiskAnnGeneration {
        logical_path: logical_path.to_path_buf(),
        graph_path,
        raw_path,
        pq_path,
        generation_id,
        source_hash: header.source_hash,
        graph_hash,
        raw_hash,
        pq_hash,
        graph_bytes,
        raw_bytes,
        pq_bytes,
        pointer_bytes: 0,
        node_count: header.node_count,
        dim: header.dim,
        m_max: header.m_max,
        metric: header.metric,
        pq_code_bits: components.pq_code_bits,
    };
    let encoded = encode_manifest(&generation)?;
    publish_active_pointer(logical_path, &encoded)?;
    DiskAnnGeneration::open(logical_path)
}

pub(super) fn stage_path(logical_path: &Path, label: &str) -> PathBuf {
    let mut name = logical_path
        .file_name()
        .unwrap_or_else(|| OsStr::new("graph.cda"))
        .to_os_string();
    name.push(format!(".stage-{}-{label}", std::process::id()));
    logical_path.with_file_name(name)
}

fn component_identity(path: Option<&Path>, label: &str) -> Result<(u64, [u8; 32])> {
    match path {
        Some(path) => Ok((file_len(path, label)?, hash_file(path)?)),
        None => Ok((0, [0; 32])),
    }
}

fn publish_component(
    logical_path: &Path,
    staged: &Path,
    label: &str,
    digest: [u8; 32],
) -> Result<PathBuf> {
    let parent = logical_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| io("create generation directory", error))?;
    let stem = logical_path
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("graph");
    let extension = match label {
        "graph" => "cda",
        "raw" => "raw",
        "pq" => "pq",
        _ => "bin",
    };
    let final_path = parent.join(format!(
        "{stem}.{}.{}.{extension}",
        hex(&digest[..12]),
        label
    ));
    if final_path.is_file() {
        if hash_file(&final_path)? != digest
            || file_len(&final_path, label)? != file_len(staged, label)?
        {
            return Err(corrupt(format!(
                "immutable {label} destination {} exists with different bytes",
                final_path.display()
            )));
        }
        fs::remove_file(staged).map_err(|error| io("remove duplicate staged component", error))?;
        return Ok(final_path);
    }
    move_file_write_through(staged, &final_path, false)?;
    Ok(final_path)
}

fn encode_manifest(generation: &DiskAnnGeneration) -> Result<Vec<u8>> {
    let graph = component_name(&generation.logical_path, &generation.graph_path)?;
    let raw = generation
        .raw_path
        .as_deref()
        .map(|path| component_name(&generation.logical_path, path))
        .transpose()?
        .unwrap_or_default();
    let pq = generation
        .pq_path
        .as_deref()
        .map(|path| component_name(&generation.logical_path, path))
        .transpose()?
        .unwrap_or_default();
    let mut bytes = vec![0_u8; FIXED_HEADER_BYTES];
    bytes[0..8].copy_from_slice(&DISKANN_GENERATION_MAGIC);
    bytes[8..10].copy_from_slice(&DISKANN_GENERATION_VERSION.to_le_bytes());
    bytes[10] = generation.metric as u8;
    bytes[11] = (generation.raw_path.is_some() as u8) * FLAG_RAW
        | (generation.pq_path.is_some() as u8) * FLAG_PQ;
    bytes[12] = generation.pq_code_bits;
    bytes[16..20].copy_from_slice(&generation.dim.to_le_bytes());
    bytes[20..24].copy_from_slice(&generation.m_max.to_le_bytes());
    bytes[24..32].copy_from_slice(&generation.node_count.to_le_bytes());
    bytes[32..64].copy_from_slice(&generation.generation_id);
    bytes[64..96].copy_from_slice(&generation.source_hash);
    bytes[96..128].copy_from_slice(&generation.graph_hash);
    bytes[128..160].copy_from_slice(&generation.raw_hash);
    bytes[160..192].copy_from_slice(&generation.pq_hash);
    bytes[192..200].copy_from_slice(&generation.graph_bytes.to_le_bytes());
    bytes[200..208].copy_from_slice(&generation.raw_bytes.to_le_bytes());
    bytes[208..216].copy_from_slice(&generation.pq_bytes.to_le_bytes());
    bytes[216..218].copy_from_slice(&(graph.len() as u16).to_le_bytes());
    bytes[218..220].copy_from_slice(&(raw.len() as u16).to_le_bytes());
    bytes[220..222].copy_from_slice(&(pq.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&graph);
    bytes.extend_from_slice(&raw);
    bytes.extend_from_slice(&pq);
    let seal = blake3::hash(&bytes);
    bytes.extend_from_slice(seal.as_bytes());
    Ok(bytes)
}

fn decode_manifest(logical_path: &Path, bytes: &[u8]) -> Result<DiskAnnGeneration> {
    if bytes.len() < FIXED_HEADER_BYTES + SEAL_BYTES {
        return Err(corrupt(format!(
            "active generation {} is {} bytes, shorter than the header and seal",
            logical_path.display(),
            bytes.len()
        )));
    }
    if bytes[0..8] != DISKANN_GENERATION_MAGIC {
        return Err(corrupt(format!(
            "{} is not an atomic DiskANN generation pointer; rebuild the legacy graph",
            logical_path.display()
        )));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("2B"));
    if version != DISKANN_GENERATION_VERSION {
        return Err(corrupt(format!("active generation version {version}")));
    }
    let seal_at = bytes.len() - SEAL_BYTES;
    let computed = blake3::hash(&bytes[..seal_at]);
    if computed.as_bytes() != &bytes[seal_at..] {
        return Err(corrupt(format!(
            "active generation seal mismatch; computed {}",
            computed.to_hex()
        )));
    }
    if bytes[13..16].iter().any(|byte| *byte != 0)
        || bytes[222..FIXED_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(corrupt("active generation reserved bytes are noncanonical"));
    }
    let metric = match bytes[10] {
        1 => DiskAnnMetric::UnitL2,
        2 => DiskAnnMetric::RawL2,
        other => return Err(corrupt(format!("active generation metric tag {other}"))),
    };
    let flags = bytes[11];
    if flags & !(FLAG_RAW | FLAG_PQ) != 0 {
        return Err(corrupt(format!("active generation flags {flags:#x}")));
    }
    let pq_code_bits = bytes[12];
    if flags & FLAG_PQ != 0 {
        if !matches!(pq_code_bits, 4 | 8) {
            return Err(corrupt(format!(
                "active generation PQ code width {pq_code_bits}"
            )));
        }
    } else if pq_code_bits != 0 {
        return Err(corrupt(
            "active generation declares PQ code width without PQ",
        ));
    }
    let graph_len = le_u16(bytes, 216) as usize;
    let raw_len = le_u16(bytes, 218) as usize;
    let pq_len = le_u16(bytes, 220) as usize;
    let names_len = graph_len
        .checked_add(raw_len)
        .and_then(|value| value.checked_add(pq_len))
        .ok_or_else(|| corrupt("active generation path length overflow"))?;
    if graph_len == 0
        || graph_len > MAX_COMPONENT_NAME_BYTES
        || raw_len > MAX_COMPONENT_NAME_BYTES
        || pq_len > MAX_COMPONENT_NAME_BYTES
        || FIXED_HEADER_BYTES + names_len != seal_at
    {
        return Err(corrupt(
            "active generation component path lengths are invalid",
        ));
    }
    let mut at = FIXED_HEADER_BYTES;
    let graph_name = component_path(bytes, &mut at, graph_len)?;
    let raw_name = component_path(bytes, &mut at, raw_len)?;
    let pq_name = component_path(bytes, &mut at, pq_len)?;
    let parent = logical_path.parent().unwrap_or_else(|| Path::new("."));
    let graph_path = parent.join(graph_name);
    let raw_path = (flags & FLAG_RAW != 0).then(|| parent.join(raw_name));
    let pq_path = (flags & FLAG_PQ != 0).then(|| parent.join(pq_name));
    if (flags & FLAG_RAW != 0) != (raw_len > 0) || (flags & FLAG_PQ != 0) != (pq_len > 0) {
        return Err(corrupt(
            "active generation flags disagree with component paths",
        ));
    }
    let generation = DiskAnnGeneration {
        logical_path: logical_path.to_path_buf(),
        graph_path,
        raw_path,
        pq_path,
        generation_id: bytes[32..64].try_into().expect("32B"),
        source_hash: bytes[64..96].try_into().expect("32B"),
        graph_hash: bytes[96..128].try_into().expect("32B"),
        raw_hash: bytes[128..160].try_into().expect("32B"),
        pq_hash: bytes[160..192].try_into().expect("32B"),
        graph_bytes: le_u64(bytes, 192),
        raw_bytes: le_u64(bytes, 200),
        pq_bytes: le_u64(bytes, 208),
        pointer_bytes: bytes.len() as u64,
        node_count: le_u64(bytes, 24),
        dim: le_u32(bytes, 16),
        m_max: le_u32(bytes, 20),
        metric,
        pq_code_bits,
    };
    let expected_root = generation_root(
        generation.metric,
        generation.source_hash,
        generation.graph_hash,
        generation.raw_hash,
        generation.pq_hash,
        generation.graph_bytes,
        generation.raw_bytes,
        generation.pq_bytes,
        generation.node_count,
        generation.dim,
        generation.m_max,
        generation.pq_code_bits,
    );
    if generation.generation_id != expected_root {
        return Err(corrupt(format!(
            "active generation root {} != computed {}",
            hex(&generation.generation_id),
            hex(&expected_root)
        )));
    }
    Ok(generation)
}

#[allow(clippy::too_many_arguments)]
fn generation_root(
    metric: DiskAnnMetric,
    source_hash: [u8; 32],
    graph_hash: [u8; 32],
    raw_hash: [u8; 32],
    pq_hash: [u8; 32],
    graph_bytes: u64,
    raw_bytes: u64,
    pq_bytes: u64,
    node_count: u64,
    dim: u32,
    m_max: u32,
    pq_code_bits: u8,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx/diskann/active-generation/v1\0");
    hasher.update(&[metric as u8, pq_code_bits]);
    hasher.update(&source_hash);
    hasher.update(&graph_hash);
    hasher.update(&raw_hash);
    hasher.update(&pq_hash);
    hasher.update(&graph_bytes.to_le_bytes());
    hasher.update(&raw_bytes.to_le_bytes());
    hasher.update(&pq_bytes.to_le_bytes());
    hasher.update(&node_count.to_le_bytes());
    hasher.update(&dim.to_le_bytes());
    hasher.update(&m_max.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn validate_component(
    label: &str,
    path: &Path,
    expected_bytes: u64,
    expected_hash: [u8; 32],
) -> Result<()> {
    let actual_bytes = file_len(path, label)?;
    if actual_bytes != expected_bytes {
        return Err(corrupt(format!(
            "{label} component {} length {actual_bytes} != active generation {expected_bytes}",
            path.display()
        )));
    }
    let actual_hash = hash_file(path)?;
    if actual_hash != expected_hash {
        return Err(corrupt(format!(
            "{label} component {} BLAKE3 {} != active generation {}",
            path.display(),
            hex(&actual_hash),
            hex(&expected_hash)
        )));
    }
    Ok(())
}

fn file_len(path: &Path, label: &str) -> Result<u64> {
    let len = fs::metadata(path)
        .map_err(|error| io(&format!("stat {label} component"), error))?
        .len();
    if len == 0 {
        return Err(corrupt(format!(
            "{label} component {} is empty",
            path.display()
        )));
    }
    Ok(len)
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).map_err(|error| io("open component for hashing", error))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io("read component for hashing", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn component_hash(path: &Path) -> Result<[u8; 32]> {
    hash_file(path)
}

fn component_name(logical: &Path, component: &Path) -> Result<Vec<u8>> {
    if component.parent() != logical.parent() {
        return Err(corrupt(
            "generation component is outside the active pointer directory",
        ));
    }
    let name = component
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| corrupt("generation component name is not UTF-8"))?;
    if name.len() > MAX_COMPONENT_NAME_BYTES {
        return Err(corrupt("generation component name exceeds 255 bytes"));
    }
    Ok(name.as_bytes().to_vec())
}

fn component_path(bytes: &[u8], at: &mut usize, len: usize) -> Result<PathBuf> {
    let raw = std::str::from_utf8(&bytes[*at..*at + len])
        .map_err(|_| corrupt("generation component name is not UTF-8"))?;
    *at += len;
    let path = Path::new(raw);
    let mut components = path.components();
    if len == 0 {
        return Ok(PathBuf::new());
    }
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(path.to_path_buf()),
        _ => Err(corrupt(format!("unsafe generation component path {raw:?}"))),
    }
}

fn publish_active_pointer(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| io("create active pointer parent", error))?;
    }
    let temp = stage_path(path, "pointer");
    let mut file = File::create(&temp).map_err(|error| io("create active pointer temp", error))?;
    file.write_all(bytes)
        .map_err(|error| io("write active pointer temp", error))?;
    file.sync_all()
        .map_err(|error| io("fsync active pointer temp", error))?;
    drop(file);
    move_file_write_through(&temp, path, true)
}

#[cfg(windows)]
fn move_file_write_through(source: &Path, target: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain alive for the
    // call; MoveFileExW retains neither pointer.
    if unsafe { MoveFileExW(source_wide.as_ptr(), target_wide.as_ptr(), flags) } == 0 {
        return Err(io(
            "publish generation with MoveFileExW",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_file_write_through(source: &Path, target: &Path, replace: bool) -> Result<()> {
    if !replace && target.exists() {
        return Err(corrupt(format!(
            "immutable target {} already exists",
            target.display()
        )));
    }
    fs::rename(source, target).map_err(|error| io("publish generation component", error))
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn corrupt(detail: impl std::fmt::Display) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_CORRUPT,
        format!("diskann generation corrupt: {detail}"),
    )
}

fn io(stage: &str, error: std::io::Error) -> calyx_core::CalyxError {
    sextant_error(
        CALYX_INDEX_IO,
        format!("diskann generation {stage}: {error}"),
    )
}
