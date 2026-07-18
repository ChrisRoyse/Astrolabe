//! Slot-vector wire codec: the dense/absent/sparse/multi tag dispatch plus the
//! canonical sparse encoding (tag 4 delta-varint / tag 5 dense-selected) and its
//! LEB128 varint helpers.

use super::put_string;
use crate::vault::cursor::Cursor;
use calyx_core::{AbsentReason, CalyxError, Result, SlotVector, SparseEntry};

pub fn encode_slot_vector(vector: &SlotVector) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match vector {
        SlotVector::Dense { dim, data } => {
            if *dim as usize != data.len() {
                return Err(CalyxError::aster_corrupt_shard(
                    "dense slot dim does not match data length",
                ));
            }
            out.push(0);
            out.extend_from_slice(&dim.to_be_bytes());
            for value in data {
                out.extend_from_slice(&value.to_bits().to_be_bytes());
            }
        }
        SlotVector::Absent { reason } => {
            out.push(1);
            encode_absent_reason(reason, &mut out)?;
        }
        SlotVector::Sparse { dim, entries } => {
            encode_sparse_canonical(*dim, entries, &mut out)?;
        }
        SlotVector::Multi { token_dim, tokens } => {
            out.push(3);
            out.extend_from_slice(&token_dim.to_be_bytes());
            out.extend_from_slice(&(tokens.len() as u32).to_be_bytes());
            for token in tokens {
                if token.len() != *token_dim as usize {
                    return Err(CalyxError::aster_corrupt_shard(
                        "multi slot token dim does not match token length",
                    ));
                }
                for value in token {
                    out.extend_from_slice(&value.to_bits().to_be_bytes());
                }
            }
        }
    }
    Ok(out)
}

pub fn decode_slot_vector(bytes: &[u8]) -> Result<SlotVector> {
    let mut cursor = Cursor::new(bytes);
    match cursor.u8()? {
        0 => {
            let dim = cursor.u32()?;
            let mut data = Vec::with_capacity(dim as usize);
            for _ in 0..dim {
                data.push(f32::from_bits(cursor.u32()?));
            }
            Ok(SlotVector::Dense { dim, data })
        }
        1 => Ok(SlotVector::Absent {
            reason: decode_absent_reason(&mut cursor)?,
        }),
        2 => Err(CalyxError {
            code: "CALYX_ASTER_SPARSE_LEGACY",
            message: "sparse slot vector uses legacy tag 2 (fixed u32+f32 pairs with no \
                      canonical ordering/bounds contract); refusing to guess its contents"
                .to_string(),
            remediation: "re-ingest the constellation so sparse slots are persisted in the \
                          canonical delta-varint (tag 4) or dense-selected (tag 5) form",
        }),
        3 => {
            let token_dim = cursor.u32()?;
            let n = cursor.u32()? as usize;
            let mut tokens = Vec::with_capacity(n);
            for _ in 0..n {
                let mut token = Vec::with_capacity(token_dim as usize);
                for _ in 0..token_dim {
                    token.push(f32::from_bits(cursor.u32()?));
                }
                tokens.push(token);
            }
            Ok(SlotVector::Multi { token_dim, tokens })
        }
        4 => decode_sparse_varint(&mut cursor),
        5 => decode_sparse_dense_selected(&mut cursor),
        tag => Err(CalyxError::aster_corrupt_shard(format!(
            "unknown slot vector tag {tag}"
        ))),
    }
}

/// Value dtype declared inside canonical sparse encodings. Only f32 exists
/// today; the byte is explicit so future dtypes are versioned, never guessed.
const SPARSE_VALUE_DTYPE_F32: u8 = 1;

/// Validates the canonical sparse row contract: strictly increasing indices
/// bounded by `dim`, finite values, and no explicit ±0.0 entries (a canonical
/// sparse vector never stores zeros — implicit coordinates are zero).
fn validate_sparse_canonical(dim: u32, entries: &[SparseEntry]) -> Result<()> {
    let mut previous: Option<u32> = None;
    for entry in entries {
        if entry.idx >= dim {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry index {} is outside ambient dim {dim}",
                entry.idx
            )));
        }
        if let Some(previous) = previous
            && previous >= entry.idx
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry indices are not strictly increasing: {previous} then {}",
                entry.idx
            )));
        }
        if !entry.val.is_finite() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry index {} value {} is not finite",
                entry.idx, entry.val
            )));
        }
        if entry.val == 0.0 {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry index {} stores explicit ±0.0; canonical sparse rows omit zero \
                 coordinates",
                entry.idx
            )));
        }
        previous = Some(entry.idx);
    }
    Ok(())
}

/// Encodes a sparse slot vector canonically, selecting the physically smaller
/// of the delta-varint sparse form (tag 4) and the dense form (tag 5) from the
/// actual encoded byte counts. The selected representation is persisted
/// explicitly via its tag — readback always reconstructs the identical
/// `SlotVector::Sparse`.
fn encode_sparse_canonical(dim: u32, entries: &[SparseEntry], out: &mut Vec<u8>) -> Result<()> {
    validate_sparse_canonical(dim, entries)?;
    // Tag 4 candidate: dim + dtype + varint n + delta-varint indices + f32 values.
    let mut sparse = Vec::with_capacity(16 + entries.len() * 6);
    sparse.push(4);
    sparse.extend_from_slice(&dim.to_be_bytes());
    sparse.push(SPARSE_VALUE_DTYPE_F32);
    let count = u32::try_from(entries.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("sparse entry count exceeds u32"))?;
    put_varint(&mut sparse, count);
    let mut previous: Option<u32> = None;
    for entry in entries {
        let delta = match previous {
            None => entry.idx,
            // Strictly increasing (validated above), so the gap is >= 1.
            Some(previous) => entry.idx - previous,
        };
        put_varint(&mut sparse, delta);
        previous = Some(entry.idx);
    }
    for entry in entries {
        sparse.extend_from_slice(&entry.val.to_bits().to_be_bytes());
    }
    // Tag 5 candidate: dim + full f32 lattice (indices implicit).
    let dense_len = 1_usize + 4 + (dim as usize) * 4;
    if sparse.len() <= dense_len {
        out.extend_from_slice(&sparse);
        return Ok(());
    }
    out.push(5);
    out.extend_from_slice(&dim.to_be_bytes());
    let mut lattice = vec![0_u32; dim as usize];
    for entry in entries {
        lattice[entry.idx as usize] = entry.val.to_bits();
    }
    for bits in lattice {
        out.extend_from_slice(&bits.to_be_bytes());
    }
    Ok(())
}

fn decode_sparse_varint(cursor: &mut Cursor<'_>) -> Result<SlotVector> {
    let dim = cursor.u32()?;
    let dtype = cursor.u8()?;
    if dtype != SPARSE_VALUE_DTYPE_F32 {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "unknown sparse value dtype {dtype}"
        )));
    }
    let count = read_varint(cursor)? as usize;
    let mut indices = Vec::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let delta = read_varint(cursor)?;
        let idx = match previous {
            None => delta,
            Some(previous) => {
                if delta == 0 {
                    return Err(CalyxError::aster_corrupt_shard(
                        "sparse delta 0 would repeat an index; indices must be strictly \
                         increasing",
                    ));
                }
                previous.checked_add(delta).ok_or_else(|| {
                    CalyxError::aster_corrupt_shard("sparse index delta overflows u32")
                })?
            }
        };
        if idx >= dim {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse index {idx} is outside ambient dim {dim}"
            )));
        }
        indices.push(idx);
        previous = Some(idx);
    }
    let mut entries = Vec::with_capacity(count);
    for idx in indices {
        let val = f32::from_bits(cursor.u32()?);
        if !val.is_finite() || val == 0.0 {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse index {idx} decodes non-canonical value {val}"
            )));
        }
        entries.push(SparseEntry { idx, val });
    }
    Ok(SlotVector::Sparse { dim, entries })
}

fn decode_sparse_dense_selected(cursor: &mut Cursor<'_>) -> Result<SlotVector> {
    let dim = cursor.u32()?;
    let mut entries = Vec::new();
    for idx in 0..dim {
        let bits = cursor.u32()?;
        if bits == 0 {
            continue;
        }
        let val = f32::from_bits(bits);
        if !val.is_finite() || val == 0.0 {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse-selected-dense index {idx} decodes non-canonical value {val}"
            )));
        }
        entries.push(SparseEntry { idx, val });
    }
    Ok(SlotVector::Sparse { dim, entries })
}

/// Unsigned LEB128.
fn put_varint(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_varint(cursor: &mut Cursor<'_>) -> Result<u32> {
    let mut value: u32 = 0;
    let mut shift = 0_u32;
    loop {
        let byte = cursor.u8()?;
        let chunk = u32::from(byte & 0x7f);
        if shift >= 32 || (shift == 28 && chunk > 0x0f) {
            return Err(CalyxError::aster_corrupt_shard("varint exceeds u32 range"));
        }
        value |= chunk << shift;
        if byte & 0x80 == 0 {
            // Canonical LEB128: no trailing zero continuation groups.
            if byte == 0 && shift != 0 {
                return Err(CalyxError::aster_corrupt_shard(
                    "non-canonical varint with redundant trailing zero group",
                ));
            }
            return Ok(value);
        }
        shift += 7;
    }
}

fn encode_absent_reason(reason: &AbsentReason, out: &mut Vec<u8>) -> Result<()> {
    match reason {
        AbsentReason::NotApplicable => out.push(0),
        AbsentReason::Redacted => out.push(1),
        AbsentReason::LensUnavailable => out.push(2),
        AbsentReason::Deferred => out.push(3),
        AbsentReason::LensInactive => out.push(4),
        AbsentReason::Error(value) => {
            out.push(5);
            put_string(out, value)?;
        }
    }
    Ok(())
}

fn decode_absent_reason(cursor: &mut Cursor<'_>) -> Result<AbsentReason> {
    Ok(match cursor.u8()? {
        0 => AbsentReason::NotApplicable,
        1 => AbsentReason::Redacted,
        2 => AbsentReason::LensUnavailable,
        3 => AbsentReason::Deferred,
        4 => AbsentReason::LensInactive,
        5 => AbsentReason::Error(cursor.string()?),
        tag => {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "unknown absent tag {tag}"
            )));
        }
    })
}
