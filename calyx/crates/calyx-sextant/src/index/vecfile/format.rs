use std::fs::File;
use std::path::Path;

use calyx_core::Result;
use memmap2::Mmap;

use super::{VEC_HEADER_LEN, VEC_MAGIC_LEGACY_V1, VECTOR_FILE_MAX_DIM};
use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_IO, CALYX_INDEX_LEGACY_FORMAT, CALYX_INDEX_PAYLOAD_DIGEST,
    sextant_error,
};

const SOURCE_IDENTITY_DOMAIN: &[u8] = b"calyx/vector-file/source-identity/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorFileFormat {
    ExactF32,
    SymmetricInt8,
}

impl VectorFileFormat {
    pub const fn manifest_name(self) -> &'static str {
        match self {
            Self::ExactF32 => "CLXVEC02",
            Self::SymmetricInt8 => "CLXI8B02",
        }
    }

    pub const fn magic(self) -> [u8; 8] {
        match self {
            Self::ExactF32 => *b"CLXVEC02",
            Self::SymmetricInt8 => *b"CLXI8B02",
        }
    }

    pub const fn storage_contract(self) -> &'static str {
        match self {
            Self::ExactF32 => "clxvec02-exact-f32-bit-preserving-blake3-authenticated",
            Self::SymmetricInt8 => "clxi8b02-per-row-scale-symmetric-int8-blake3-authenticated",
        }
    }

    pub const fn kind(self) -> &'static str {
        match self {
            Self::ExactF32 => "vecfile",
            Self::SymmetricInt8 => "i8bin",
        }
    }

    pub const fn row_stride(self, dim: u64) -> Option<u64> {
        match self {
            Self::ExactF32 => dim.checked_mul(4),
            Self::SymmetricInt8 => dim.checked_add(4),
        }
    }
}

/// Complete identity of an authenticated vector-file source. `payload_blake3`
/// seals the exact row bytes; `source_blake3` additionally binds the format,
/// dimension, row count, and payload length so the same bytes cannot be
/// silently reinterpreted under a different shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VectorFileIdentity {
    pub format: VectorFileFormat,
    pub dim: u32,
    pub count: u64,
    pub payload_len: u64,
    pub payload_blake3: [u8; 32],
    pub source_blake3: [u8; 32],
}

pub(super) struct VerifiedHeader {
    pub dim: usize,
    pub count: u64,
    pub payload_len: usize,
    pub identity: VectorFileIdentity,
}

pub(super) fn source_blake3(
    format: VectorFileFormat,
    dim: u32,
    count: u64,
    payload_len: u64,
    payload_blake3: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_IDENTITY_DOMAIN);
    hasher.update(&format.magic());
    hasher.update(&dim.to_le_bytes());
    hasher.update(&count.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(payload_blake3);
    *hasher.finalize().as_bytes()
}

/// Opens, maps, and authenticates a v2 vector file: magic/version dispatch,
/// configured shape bound, checked size arithmetic, exact length, and payload
/// digest verification.
pub(super) fn open_verified(
    path: &Path,
    format: VectorFileFormat,
) -> Result<(Mmap, VerifiedHeader)> {
    let kind = format.kind();
    let expected_magic = format.magic();
    let file = File::open(path).map_err(|error| {
        sextant_error(
            CALYX_INDEX_IO,
            format!("open {kind} {}: {error}", path.display()),
        )
    })?;
    let len = file
        .metadata()
        .map_err(|error| sextant_error(CALYX_INDEX_IO, format!("stat {kind}: {error}")))?
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
    // SAFETY: accepted vector files are immutable, no-replace publications.
    // Writers stage and validate complete bytes before the one-way rename, so
    // the mapped destination is never mutated in place.
    let mmap = unsafe {
        Mmap::map(&file)
            .map_err(|error| sextant_error(CALYX_INDEX_IO, format!("mmap {kind}: {error}")))?
    };
    if mmap[0..8] != expected_magic {
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
    let dim = u32::from_le_bytes(mmap[8..12].try_into().expect("4B"));
    let count = u64::from_le_bytes(mmap[12..20].try_into().expect("8B"));
    let payload_len = u64::from_le_bytes(mmap[20..28].try_into().expect("8B"));
    let payload_blake3: [u8; 32] = mmap[28..60].try_into().expect("32B");
    if dim == 0 || dim as usize > VECTOR_FILE_MAX_DIM {
        return Err(sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} dim {dim} is outside the configured range 1..={VECTOR_FILE_MAX_DIM}",
                path.display()
            ),
        ));
    }
    let row_stride = format.row_stride(u64::from(dim)).ok_or_else(|| {
        sextant_error(
            CALYX_INDEX_CORRUPT,
            format!(
                "{kind} {} row stride overflows u64 (dim {dim})",
                path.display()
            ),
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
    if observed.as_bytes() != &payload_blake3 {
        return Err(sextant_error(
            CALYX_INDEX_PAYLOAD_DIGEST,
            format!(
                "{kind} {} payload digest mismatch: header {} != observed {}",
                path.display(),
                hex32(&payload_blake3),
                observed.to_hex()
            ),
        ));
    }
    let identity = VectorFileIdentity {
        format,
        dim,
        count,
        payload_len,
        payload_blake3,
        source_blake3: source_blake3(format, dim, count, payload_len, &payload_blake3),
    };
    Ok((
        mmap,
        VerifiedHeader {
            dim: dim as usize,
            count,
            payload_len: payload_len_usize,
            identity,
        },
    ))
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
