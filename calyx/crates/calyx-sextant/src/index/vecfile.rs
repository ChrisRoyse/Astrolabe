//! Flat on-disk vector files of REAL embeddings — the source of truth for
//! partitioned-vault build and search. No vectors are ever synthesised: the builder
//! and bench read genuine embeddings produced by the real embedder from a real
//! corpus.
//!
//! # `CLXVEC02` (`.fbin`) — exact bit-preserving F32 source of truth
//!
//! Layout (little-endian):
//! `magic "CLXVEC02" (8 B) | u32 dim | u64 count | u64 payload_len | payload
//! blake3 digest (32 B) | f32[count*dim] row-major`.
//!
//! Every finite payload bit is preserved exactly as written; the writer refuses
//! non-finite coefficients and the reader independently re-verifies the payload
//! digest and finiteness at open, so a `.fbin` accepted for build/search is
//! authenticated byte-for-byte against its declared header identity.
//!
//! # `CLXI8B02` (`.i8bin`) — per-row-scaled symmetric int8
//!
//! Layout (little-endian):
//! `magic "CLXI8B02" (8 B) | u32 dim | u64 count | u64 payload_len | payload
//! blake3 digest (32 B)` then per row: `f32 scale | i8[dim] codes`.
//!
//! `scale` is the dequantization multiplier (`value ≈ code * scale`), derived by
//! the writer as `max_abs / 127`, so magnitude information is preserved per row
//! instead of being discarded. Canonical rows never contain the encoder-impossible
//! `-128` code and always contain at least one `±127` extremum; the reader refuses
//! non-canonical rows fail-closed.
//!
//! Legacy `CLXVEC01` and headerless BigANN `.i8bin` files are refused fail-closed
//! with structured remediation — they are ambiguous (lossy writer / no integrity
//! binding) and are never silently reinterpreted.

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use calyx_core::Result;
use memmap2::Mmap;

use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_IO, CALYX_INDEX_LEGACY_FORMAT, CALYX_INDEX_NONCANONICAL_I8,
    CALYX_INDEX_NONFINITE, CALYX_INDEX_PAYLOAD_DIGEST, sextant_error,
};

/// Current authenticated `.fbin` magic (format v2).
pub const VEC_MAGIC: [u8; 8] = *b"CLXVEC02";
/// Legacy lossy `.fbin` magic — refused fail-closed.
pub const VEC_MAGIC_LEGACY_V1: [u8; 8] = *b"CLXVEC01";
/// Current authenticated `.i8bin` magic (format v2).
pub const I8BIN_MAGIC: [u8; 8] = *b"CLXI8B02";

/// Shared v2 header: magic(8) + dim(4) + count(8) + payload_len(8) + digest(32).
pub const VEC_HEADER_LEN: usize = 60;
const DIGEST_OFFSET: u64 = 28;

#[derive(Debug)]
pub enum DenseVectorFile {
    Fbin(FbinVectors),
    I8Bin(I8BinVectors),
}

impl DenseVectorFile {
    pub fn open(path: &Path) -> Result<Self> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("fbin") => Ok(Self::Fbin(FbinVectors::open(path)?)),
            Some("i8bin") => Ok(Self::I8Bin(I8BinVectors::open(path)?)),
            _ => Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("unsupported vector file extension for {}", path.display()),
            )),
        }
    }

    pub fn dim(&self) -> usize {
        match self {
            Self::Fbin(file) => file.dim(),
            Self::I8Bin(file) => file.dim(),
        }
    }

    pub fn count(&self) -> u64 {
        match self {
            Self::Fbin(file) => file.count(),
            Self::I8Bin(file) => file.count(),
        }
    }

    /// Verified blake3 digest of the payload bytes (source identity).
    pub fn payload_blake3(&self) -> [u8; 32] {
        match self {
            Self::Fbin(file) => file.payload_blake3(),
            Self::I8Bin(file) => file.payload_blake3(),
        }
    }

    pub fn row_f32(&self, idx: u64) -> Vec<f32> {
        match self {
            Self::Fbin(file) => file.row(idx).to_vec(),
            Self::I8Bin(file) => file.row_f32_normalized(idx),
        }
    }

    pub fn row_f32_raw(&self, idx: u64) -> Vec<f32> {
        match self {
            Self::Fbin(file) => file.row(idx).to_vec(),
            Self::I8Bin(file) => file.row_f32_raw(idx),
        }
    }
}

struct VerifiedHeader {
    dim: usize,
    count: u64,
    payload_len: usize,
    digest: [u8; 32],
}

/// Opens, maps, and authenticates a v2 vector file: magic/version dispatch,
/// checked size arithmetic, exact length, and payload digest verification.
fn open_verified(
    path: &Path,
    expected_magic: &[u8; 8],
    kind: &str,
    row_stride_for_dim: impl Fn(u64) -> Option<u64>,
) -> Result<(Mmap, VerifiedHeader)> {
    let file = File::open(path).map_err(|e| {
        sextant_error(
            CALYX_INDEX_IO,
            format!("open {kind} {}: {e}", path.display()),
        )
    })?;
    let len = file
        .metadata()
        .map_err(|e| sextant_error(CALYX_INDEX_IO, format!("stat {kind}: {e}")))?
        .len();
    if len < 8 {
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} is {len} B, smaller than any vector-file magic",
                path.display()
            ),
        ));
    }
    // SAFETY: read-only map of a file written atomically by the exporter and not
    // mutated in place while open.
    let mmap = unsafe {
        Mmap::map(&file).map_err(|e| sextant_error(CALYX_INDEX_IO, format!("mmap {kind}: {e}")))?
    };
    // Magic dispatch runs before the size gate so a legacy file of any length
    // is named as legacy, never lumped into generic corruption.
    if mmap[0..8] != expected_magic[..] {
        if mmap[0..8] == VEC_MAGIC_LEGACY_V1 {
            return Err(sextant_error(
                CALYX_INDEX_LEGACY_FORMAT,
                format!(
                    "{kind} {} carries legacy magic CLXVEC01 (lossy 0.001-rounded writer, \
                     no payload digest); refusing to guess its contents",
                    path.display()
                ),
            ));
        }
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} bad magic {:02x?}, expected {:02x?}",
                path.display(),
                &mmap[0..8],
                expected_magic
            ),
        ));
    }
    if len < VEC_HEADER_LEN as u64 {
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} is {len} B, smaller than the {VEC_HEADER_LEN} B v2 header",
                path.display()
            ),
        ));
    }
    let dim = u32::from_le_bytes(mmap[8..12].try_into().expect("4B")) as u64;
    let count = u64::from_le_bytes(mmap[12..20].try_into().expect("8B"));
    let payload_len = u64::from_le_bytes(mmap[20..28].try_into().expect("8B"));
    let digest: [u8; 32] = mmap[28..60].try_into().expect("32B");
    if dim == 0 {
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!("{kind} {} dim is zero", path.display()),
        ));
    }
    let row_stride = row_stride_for_dim(dim).ok_or_else(|| {
        sextant_error(
            CALYX_INDEX_CORRUPT,
            format!("{kind} {} row stride overflows u64 (dim {dim})", path.display()),
        )
    })?;
    let expected_payload = count.checked_mul(row_stride).ok_or_else(|| {
        sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} payload size overflows u64 (count {count} x stride {row_stride})",
                path.display()
            ),
        )
    })?;
    if expected_payload != payload_len {
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} declared payload_len {payload_len} != count {count} x stride \
                 {row_stride} = {expected_payload}",
                path.display()
            ),
        ));
    }
    let expected_total = (VEC_HEADER_LEN as u64)
        .checked_add(payload_len)
        .ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{kind} {} total size overflows u64", path.display()),
            )
        })?;
    if len != expected_total {
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} len {len} != expected {expected_total} (header {VEC_HEADER_LEN} + \
                 payload {payload_len})",
                path.display()
            ),
        ));
    }
    let payload_len_usize = usize::try_from(payload_len).map_err(|_| {
        sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} payload {payload_len} B exceeds this platform's address space",
                path.display()
            ),
        )
    })?;
    let observed = blake3::hash(&mmap[VEC_HEADER_LEN..VEC_HEADER_LEN + payload_len_usize]);
    if *observed.as_bytes() != digest {
        return Err(sextant_error(
            CALYX_INDEX_PAYLOAD_DIGEST,
            format!(
                "{kind} {} payload digest mismatch: header {} != observed {}",
                path.display(),
                hex32(&digest),
                observed.to_hex()
            ),
        ));
    }
    let dim_usize = usize::try_from(dim).map_err(|_| {
        sextant_error(
            CALYX_INDEX_CORRUPT,
            format!("{kind} {} dim {dim} exceeds usize", path.display()),
        )
    })?;
    Ok((
        mmap,
        VerifiedHeader {
            dim: dim_usize,
            count,
            payload_len: payload_len_usize,
            digest,
        },
    ))
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// mmap-backed reader over an authenticated `CLXVEC02` `.fbin` of real
/// embeddings. Reads are zero-copy slices into the mapping, so build/search
/// never materialise the whole file in heap. `open` verifies the payload digest
/// and refuses non-finite payloads, so every served row is bit-exact source
/// truth.
#[derive(Debug)]
pub struct FbinVectors {
    mmap: Mmap,
    dim: usize,
    count: u64,
    digest: [u8; 32],
}

impl FbinVectors {
    pub fn open(path: &Path) -> Result<Self> {
        let (mmap, header) =
            open_verified(path, &VEC_MAGIC, "vecfile", |dim| dim.checked_mul(4))?;
        // The f32 region begins at byte 60; mmap base is page-aligned and 60 % 4 == 0,
        // so the region is 4-byte aligned for zero-copy f32 reads.
        if !(mmap.as_ptr() as usize + VEC_HEADER_LEN).is_multiple_of(std::mem::align_of::<f32>()) {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                "vecfile f32 region misaligned for zero-copy read",
            ));
        }
        // Authenticated exact source truth must be finite: refuse NaN/Inf payloads.
        let payload = &mmap[VEC_HEADER_LEN..VEC_HEADER_LEN + header.payload_len];
        for (value_idx, chunk) in payload.chunks_exact(4).enumerate() {
            let value = f32::from_le_bytes(chunk.try_into().expect("4B"));
            if !value.is_finite() {
                return Err(sextant_error(
                    CALYX_INDEX_NONFINITE,
                    format!(
                        "vecfile {} contains non-finite value {value} at flat index {value_idx} \
                         (row {}, col {})",
                        path.display(),
                        value_idx / header.dim,
                        value_idx % header.dim
                    ),
                ));
            }
        }
        Ok(Self {
            mmap,
            dim: header.dim,
            count: header.count,
            digest: header.digest,
        })
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Verified blake3 digest of the payload bytes (source identity for
    /// downstream build/measurement manifests).
    pub fn payload_blake3(&self) -> [u8; 32] {
        self.digest
    }

    /// Zero-copy view of row `idx`'s embedding. The hot-path variant: bounds are
    /// still checked (open proved the payload region exact, so only `idx` can be
    /// wrong) and an out-of-range index panics with the structured message from
    /// [`Self::try_row`]; fallible callers use `try_row` directly.
    pub fn row(&self, idx: u64) -> &[f32] {
        self.try_row(idx)
            .unwrap_or_else(|error| panic!("{error:?}"))
    }

    /// Bounds-checked row read (fail closed instead of panicking).
    pub fn try_row(&self, idx: u64) -> Result<&[f32]> {
        if idx >= self.count {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("vecfile row {idx} >= count {}", self.count),
            ));
        }
        // idx < count and count*dim*4 fits usize (proven at open), so this
        // arithmetic cannot overflow.
        let start = VEC_HEADER_LEN + (idx as usize) * self.dim * 4;
        let bytes = &self.mmap[start..start + self.dim * 4];
        // SAFETY: alignment checked in `open`; length is an exact multiple of 4; f32
        // accepts any bit pattern; lifetime tied to the map.
        Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<f32>(), self.dim) })
    }
}

/// mmap-backed reader for authenticated `CLXI8B02` per-row-scaled signed-int8
/// vectors. `open` verifies the payload digest and per-row canonical form
/// (finite positive scale, no `-128` code, `±127` extremum present).
#[derive(Debug)]
pub struct I8BinVectors {
    mmap: Mmap,
    dim: usize,
    count: u64,
    digest: [u8; 32],
}

impl I8BinVectors {
    pub fn open(path: &Path) -> Result<Self> {
        let (mmap, header) = open_verified(path, &I8BIN_MAGIC, "i8bin", |dim| {
            dim.checked_add(4)
        })?;
        let stride = header.dim + 4;
        for row in 0..header.count {
            let start = VEC_HEADER_LEN + (row as usize) * stride;
            let scale =
                f32::from_le_bytes(mmap[start..start + 4].try_into().expect("4B"));
            if !scale.is_finite() || scale <= 0.0 {
                return Err(sextant_error(
                    CALYX_INDEX_NONCANONICAL_I8,
                    format!(
                        "i8bin {} row {row} scale {scale} is not finite and positive",
                        path.display()
                    ),
                ));
            }
            let codes = &mmap[start + 4..start + stride];
            let mut max_abs_code = 0_u8;
            for (col, code) in codes.iter().enumerate() {
                let code = *code as i8;
                if code == i8::MIN {
                    return Err(sextant_error(
                        CALYX_INDEX_NONCANONICAL_I8,
                        format!(
                            "i8bin {} row {row} col {col} carries encoder-impossible code -128",
                            path.display()
                        ),
                    ));
                }
                max_abs_code = max_abs_code.max(code.unsigned_abs());
            }
            if max_abs_code != 127 {
                return Err(sextant_error(
                    CALYX_INDEX_NONCANONICAL_I8,
                    format!(
                        "i8bin {} row {row} max |code| {max_abs_code} != 127; canonical rows \
                         are scaled to a ±127 extremum",
                        path.display()
                    ),
                ));
            }
        }
        Ok(Self {
            mmap,
            dim: header.dim,
            count: header.count,
            digest: header.digest,
        })
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Verified blake3 digest of the payload bytes (source identity for
    /// downstream build/measurement manifests).
    pub fn payload_blake3(&self) -> [u8; 32] {
        self.digest
    }

    fn row_start(&self, idx: u64) -> usize {
        assert!(
            idx < self.count,
            "i8bin row {idx} >= count {} (callers must pre-validate via count())",
            self.count
        );
        // idx < count and count*(dim+4) fits usize (proven at open).
        VEC_HEADER_LEN + (idx as usize) * (self.dim + 4)
    }

    /// Per-row dequantization multiplier (`value ≈ code * scale`).
    pub fn row_scale(&self, idx: u64) -> f32 {
        let start = self.row_start(idx);
        f32::from_le_bytes(self.mmap[start..start + 4].try_into().expect("4B"))
    }

    pub fn row_i8(&self, idx: u64) -> &[i8] {
        let start = self.row_start(idx) + 4;
        let bytes = &self.mmap[start..start + self.dim];
        // SAFETY: i8 has alignment 1 and accepts every byte pattern.
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<i8>(), self.dim) }
    }

    pub fn row_f32_normalized(&self, idx: u64) -> Vec<f32> {
        let mut out = self
            .row_i8(idx)
            .iter()
            .map(|value| f32::from(*value))
            .collect::<Vec<_>>();
        let norm = out.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > 0.0 {
            for value in &mut out {
                *value /= norm;
            }
        }
        out
    }

    /// Dequantized row with the per-row scale applied, reconstructing the source
    /// magnitudes within the quantization bound instead of discarding them.
    pub fn row_f32_raw(&self, idx: u64) -> Vec<f32> {
        let scale = self.row_scale(idx);
        self.row_i8(idx)
            .iter()
            .map(|value| f32::from(*value) * scale)
            .collect()
    }
}

struct VecWriterInner {
    file: BufWriter<File>,
    path: PathBuf,
    dim: usize,
    declared_count: u64,
    written: u64,
    hasher: blake3::Hasher,
}

impl VecWriterInner {
    fn create(
        path: &Path,
        magic: &[u8; 8],
        kind: &str,
        dim: usize,
        count: u64,
        row_stride_for_dim: impl Fn(u64) -> Option<u64>,
    ) -> Result<Self> {
        let dim_u32 = u32::try_from(dim).map_err(|_| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{kind} dim {dim} exceeds the u32 header field"),
            )
        })?;
        if dim == 0 {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{kind} dim must be non-zero"),
            ));
        }
        let row_stride = row_stride_for_dim(dim_u32 as u64).ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{kind} row stride overflows u64 (dim {dim})"),
            )
        })?;
        let payload_len = count.checked_mul(row_stride).ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{kind} payload size overflows u64 (count {count} x stride {row_stride})"),
            )
        })?;
        let mut file = BufWriter::new(File::create(path).map_err(|e| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("create {kind} {}: {e}", path.display()),
            )
        })?);
        let io = |e: std::io::Error| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("write {kind} header {}: {e}", path.display()),
            )
        };
        file.write_all(magic).map_err(io)?;
        file.write_all(&dim_u32.to_le_bytes()).map_err(io)?;
        file.write_all(&count.to_le_bytes()).map_err(io)?;
        file.write_all(&payload_len.to_le_bytes()).map_err(io)?;
        file.write_all(&[0_u8; 32]).map_err(io)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            dim,
            declared_count: count,
            written: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    fn write_payload(&mut self, bytes: &[u8]) -> Result<()> {
        self.hasher.update(bytes);
        self.file.write_all(bytes).map_err(|e| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("write row to {}: {e}", self.path.display()),
            )
        })?;
        self.written += 1;
        Ok(())
    }

    fn flush_sync(&mut self) -> Result<()> {
        self.file.flush().map_err(|e| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("flush {}: {e}", self.path.display()),
            )
        })?;
        self.file.get_ref().sync_all().map_err(|e| {
            sextant_error(CALYX_INDEX_IO, format!("sync {}: {e}", self.path.display()))
        })
    }

    fn finalize(mut self) -> Result<[u8; 32]> {
        if self.written != self.declared_count {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} declared {} rows but {} were written; refusing to seal a partial file",
                    self.path.display(),
                    self.declared_count,
                    self.written
                ),
            ));
        }
        let digest = *self.hasher.finalize().as_bytes();
        let io = |e: std::io::Error| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("seal digest of {}: {e}", self.path.display()),
            )
        };
        self.file.seek(SeekFrom::Start(DIGEST_OFFSET)).map_err(io)?;
        self.file.write_all(&digest).map_err(io)?;
        self.file.flush().map_err(io)?;
        self.file.get_ref().sync_all().map_err(io)?;
        Ok(digest)
    }
}

/// Streaming writer for the authenticated `CLXVEC02` `.fbin` format. Rows are
/// written bit-exactly (no rounding of any kind); non-finite coefficients are
/// refused fail-closed. `finalize` seals the header payload digest.
pub struct FbinWriter {
    inner: VecWriterInner,
    row_bytes: Vec<u8>,
}

impl FbinWriter {
    pub fn create(path: &Path, dim: usize, count: u64) -> Result<Self> {
        let inner =
            VecWriterInner::create(path, &VEC_MAGIC, "vecfile", dim, count, |dim| {
                dim.checked_mul(4)
            })?;
        Ok(Self {
            row_bytes: Vec::with_capacity(dim * 4),
            inner,
        })
    }

    pub fn write_row(&mut self, row: &[f32]) -> Result<()> {
        if row.len() != self.inner.dim {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "vecfile row {} has dim {} != declared {}",
                    self.inner.written,
                    row.len(),
                    self.inner.dim
                ),
            ));
        }
        self.row_bytes.clear();
        for (col, value) in row.iter().enumerate() {
            if !value.is_finite() {
                return Err(sextant_error(
                    CALYX_INDEX_NONFINITE,
                    format!(
                        "vecfile row {} col {col} value {value} is not finite; the exact F32 \
                         source of truth refuses NaN/Inf",
                        self.inner.written
                    ),
                ));
            }
            self.row_bytes.extend_from_slice(&value.to_le_bytes());
        }
        let row_bytes = std::mem::take(&mut self.row_bytes);
        let result = self.inner.write_payload(&row_bytes);
        self.row_bytes = row_bytes;
        result
    }

    pub fn flush_sync(&mut self) -> Result<()> {
        self.inner.flush_sync()
    }

    /// Seals the payload digest into the header and returns it.
    pub fn finalize(self) -> Result<[u8; 32]> {
        self.inner.finalize()
    }
}

/// Streaming writer for the authenticated `CLXI8B02` `.i8bin` format with a
/// preserved per-row dequantization scale. Zero and non-finite rows are refused
/// fail-closed; codes are canonical symmetric int8 (`-127..=127` with a `±127`
/// extremum).
pub struct I8BinWriter {
    inner: VecWriterInner,
    row_bytes: Vec<u8>,
}

impl I8BinWriter {
    pub fn create(path: &Path, dim: usize, count: u64) -> Result<Self> {
        let inner = VecWriterInner::create(path, &I8BIN_MAGIC, "i8bin", dim, count, |dim| {
            dim.checked_add(4)
        })?;
        Ok(Self {
            row_bytes: Vec::with_capacity(dim + 4),
            inner,
        })
    }

    pub fn write_row(&mut self, row: &[f32]) -> Result<()> {
        if row.len() != self.inner.dim {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "i8bin row {} has dim {} != declared {}",
                    self.inner.written,
                    row.len(),
                    self.inner.dim
                ),
            ));
        }
        let mut max_abs = 0.0_f32;
        for (col, value) in row.iter().enumerate() {
            if !value.is_finite() {
                return Err(sextant_error(
                    CALYX_INDEX_NONFINITE,
                    format!(
                        "i8bin row {} col {col} value {value} is not finite",
                        self.inner.written
                    ),
                ));
            }
            max_abs = max_abs.max(value.abs());
        }
        if max_abs == 0.0 {
            return Err(sextant_error(
                CALYX_INDEX_NONCANONICAL_I8,
                format!(
                    "i8bin row {} is all-zero; a directional int8 row requires a non-zero \
                     direction",
                    self.inner.written
                ),
            ));
        }
        let scale = max_abs / 127.0;
        if !scale.is_finite() || scale <= 0.0 {
            return Err(sextant_error(
                CALYX_INDEX_NONCANONICAL_I8,
                format!(
                    "i8bin row {} produced non-finite/non-positive scale {scale} from max_abs \
                     {max_abs}",
                    self.inner.written
                ),
            ));
        }
        self.row_bytes.clear();
        self.row_bytes.extend_from_slice(&scale.to_le_bytes());
        let mut max_abs_code = 0_u8;
        for value in row {
            let code = (value / scale).round().clamp(-127.0, 127.0) as i8;
            max_abs_code = max_abs_code.max(code.unsigned_abs());
            self.row_bytes.push(code as u8);
        }
        if max_abs_code != 127 {
            return Err(sextant_error(
                CALYX_INDEX_NONCANONICAL_I8,
                format!(
                    "i8bin row {} quantized without a ±127 extremum (max |code| {max_abs_code}); \
                     canonical per-row scaling must map max |value| to ±127",
                    self.inner.written
                ),
            ));
        }
        let row_bytes = std::mem::take(&mut self.row_bytes);
        let result = self.inner.write_payload(&row_bytes);
        self.row_bytes = row_bytes;
        result
    }

    pub fn flush_sync(&mut self) -> Result<()> {
        self.inner.flush_sync()
    }

    /// Seals the payload digest into the header and returns it.
    pub fn finalize(self) -> Result<[u8; 32]> {
        self.inner.finalize()
    }
}

const I32BIN_HEADER_LEN: usize = 8;

#[derive(Debug)]
pub struct I32BinMatrix {
    mmap: Mmap,
    width: usize,
    count: u64,
}

impl I32BinMatrix {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|e| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("open i32bin {}: {e}", path.display()),
            )
        })?;
        let len = file
            .metadata()
            .map_err(|e| sextant_error(CALYX_INDEX_IO, format!("stat i32bin: {e}")))?
            .len();
        if len < I32BIN_HEADER_LEN as u64 {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("i32bin {} is {len} B, smaller than header", path.display()),
            ));
        }
        // SAFETY: read-only map of an immutable dataset file.
        let mmap = unsafe {
            Mmap::map(&file)
                .map_err(|e| sextant_error(CALYX_INDEX_IO, format!("mmap i32bin: {e}")))?
        };
        let count = u32::from_le_bytes(mmap[0..4].try_into().expect("4B")) as u64;
        let width = u32::from_le_bytes(mmap[4..8].try_into().expect("4B")) as usize;
        if width == 0 {
            return Err(sextant_error(CALYX_INDEX_CORRUPT, "i32bin width is zero"));
        }
        let body = count
            .checked_mul(width as u64)
            .and_then(|cells| cells.checked_mul(4))
            .ok_or_else(|| {
                sextant_error(
                    CALYX_INDEX_CORRUPT,
                    format!(
                        "i32bin {} body size overflows u64 (count {count} x width {width})",
                        path.display()
                    ),
                )
            })?;
        let expect = (I32BIN_HEADER_LEN as u64).checked_add(body).ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("i32bin {} total size overflows u64", path.display()),
            )
        })?;
        if len != expect {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "i32bin {} len {len} != expected {expect} (count {count} x width {width} x 4 + {I32BIN_HEADER_LEN})",
                    path.display()
                ),
            ));
        }
        usize::try_from(body).map_err(|_| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "i32bin {} body {body} B exceeds this platform's address space",
                    path.display()
                ),
            )
        })?;
        Ok(Self { mmap, width, count })
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn row(&self, idx: u64) -> Vec<i32> {
        assert!(
            idx < self.count,
            "i32bin row {idx} >= count {} (callers must pre-validate via count())",
            self.count
        );
        let start = I32BIN_HEADER_LEN + (idx as usize) * self.width * 4;
        self.mmap[start..start + self.width * 4]
            .chunks_exact(4)
            .map(|chunk| i32::from_le_bytes(chunk.try_into().expect("4B")))
            .collect()
    }
}
