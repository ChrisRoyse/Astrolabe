use calyx_core::{CxId, Result};

use super::config::SpannPostingLimits;
use super::{PostingMember, corrupt, invalid};

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PostingMutation {
    pub cx_id: u32,
    pub vector: Option<Vec<(u32, f32)>>,
}

impl PostingMutation {
    pub(super) fn upsert(member: PostingMember) -> Self {
        Self {
            cx_id: member.cx_id,
            vector: Some(member.vector),
        }
    }

    pub(super) const fn delete(cx_id: u32) -> Self {
        Self {
            cx_id,
            vector: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct StoredRecord {
    pub local_id: u32,
    pub cx_id: CxId,
    pub vector: Vec<(u32, f32)>,
    pub memberships: Vec<u32>,
    pub seq: u64,
}

/// Canonical uncompressed posting payload used inside a sealed v3 segment.
/// This compatibility helper does not create a durable file; production paths
/// use the versioned segment envelope in `format`.
pub fn encode_posting_block(entries: &[PostingMember]) -> Result<Vec<u8>> {
    let limits = SpannPostingLimits::production();
    let operations = entries
        .iter()
        .cloned()
        .map(PostingMutation::upsert)
        .collect::<Vec<_>>();
    encode_posting_mutations(&operations, u32::MAX, &limits)
}

/// Decodes a compatibility payload under the production registry bounds.
pub fn decode_posting_block(raw: &[u8]) -> Result<Vec<PostingMember>> {
    let limits = SpannPostingLimits::production();
    decode_posting_mutations(raw, u32::MAX, &limits)?
        .into_iter()
        .map(|mutation| {
            let vector = mutation
                .vector
                .ok_or_else(|| corrupt("compatibility posting payload contains a tombstone"))?;
            Ok(PostingMember {
                cx_id: mutation.cx_id,
                vector,
            })
        })
        .collect()
}

pub(super) fn encode_posting_mutations(
    operations: &[PostingMutation],
    dim: u32,
    limits: &SpannPostingLimits,
) -> Result<Vec<u8>> {
    limits.validate()?;
    let count = u32::try_from(operations.len())
        .map_err(|_| invalid("posting operation count exceeds u32"))?;
    if count > limits.max_members_per_segment {
        return Err(invalid(format!(
            "posting operation count {count} exceeds registry limit {}",
            limits.max_members_per_segment
        )));
    }
    let mut previous = 0_u32;
    let mut encoded_len = 4_usize;
    for (ordinal, operation) in operations.iter().enumerate() {
        if ordinal > 0 && operation.cx_id <= previous {
            return Err(invalid("posting cx_ids must be strictly ascending"));
        }
        encoded_len = checked_add(encoded_len, varint_len(operation.cx_id - previous))?;
        encoded_len = checked_add(encoded_len, 1)?;
        if let Some(vector) = &operation.vector {
            validate_sparse_vector(vector, dim, limits)?;
            encoded_len = checked_add(encoded_len, varint_len(vector.len() as u32))?;
            let mut previous_idx = 0_u32;
            for (index, (idx, _)) in vector.iter().enumerate() {
                let delta = if index == 0 {
                    *idx
                } else {
                    *idx - previous_idx
                };
                encoded_len = checked_add(encoded_len, varint_len(delta))?;
                encoded_len = checked_add(encoded_len, 4)?;
                previous_idx = *idx;
            }
        }
        previous = operation.cx_id;
    }
    ensure_decoded_limit(encoded_len, limits)?;
    let mut raw = Vec::with_capacity(encoded_len);
    raw.extend_from_slice(&count.to_le_bytes());
    previous = 0;
    for operation in operations {
        write_varint(operation.cx_id - previous, &mut raw);
        match &operation.vector {
            Some(vector) => {
                raw.push(1);
                write_varint(vector.len() as u32, &mut raw);
                let mut previous_idx = 0_u32;
                for (ordinal, (idx, val)) in vector.iter().enumerate() {
                    let delta = if ordinal == 0 {
                        *idx
                    } else {
                        *idx - previous_idx
                    };
                    write_varint(delta, &mut raw);
                    raw.extend_from_slice(&val.to_bits().to_le_bytes());
                    previous_idx = *idx;
                }
            }
            None => raw.push(2),
        }
        previous = operation.cx_id;
    }
    debug_assert_eq!(raw.len(), encoded_len);
    Ok(raw)
}

pub(super) fn decode_posting_mutations(
    raw: &[u8],
    dim: u32,
    limits: &SpannPostingLimits,
) -> Result<Vec<PostingMutation>> {
    limits.validate()?;
    ensure_decoded_limit(raw.len(), limits)?;
    if raw.len() < 4 {
        return Err(corrupt(format!("raw posting payload is {} B", raw.len())));
    }
    let count = u32::from_le_bytes(raw[0..4].try_into().expect("4B"));
    if count > limits.max_members_per_segment {
        return Err(corrupt(format!(
            "posting count {count} exceeds registry limit {}",
            limits.max_members_per_segment
        )));
    }
    if usize::try_from(count).unwrap_or(usize::MAX) > raw.len().saturating_sub(4) / 2 {
        return Err(corrupt(format!(
            "posting count {count} cannot fit in {} remaining bytes",
            raw.len() - 4
        )));
    }
    let mut cursor = 4;
    let mut previous = 0_u32;
    let mut operations = Vec::with_capacity(count as usize);
    for ordinal in 0..count {
        let delta = read_canonical_varint(raw, &mut cursor)?;
        if ordinal > 0 && delta == 0 {
            return Err(corrupt("duplicate posting cx_id (zero delta)"));
        }
        let cx_id = previous
            .checked_add(delta)
            .ok_or_else(|| corrupt("posting cx_id delta overflow"))?;
        let tag = take_byte(raw, &mut cursor, "posting operation tag")?;
        let vector = match tag {
            1 => Some(decode_sparse_vector(raw, &mut cursor, dim, limits)?),
            2 => None,
            _ => return Err(corrupt(format!("unknown posting operation tag {tag}"))),
        };
        operations.push(PostingMutation { cx_id, vector });
        previous = cx_id;
    }
    if cursor != raw.len() {
        return Err(corrupt(format!(
            "{} trailing posting payload bytes",
            raw.len() - cursor
        )));
    }
    Ok(operations)
}

pub(super) fn encode_state_records(
    records: &[StoredRecord],
    dim: u32,
    centroid_count: u32,
    limits: &SpannPostingLimits,
) -> Result<Vec<u8>> {
    limits.validate()?;
    let count =
        u32::try_from(records.len()).map_err(|_| invalid("state record count exceeds u32"))?;
    if count > limits.max_members_per_segment {
        return Err(invalid(format!(
            "state record count {count} exceeds registry limit {}",
            limits.max_members_per_segment
        )));
    }
    let mut previous = 0_u32;
    let mut encoded_len = 4_usize;
    for (ordinal, record) in records.iter().enumerate() {
        if ordinal > 0 && record.local_id <= previous {
            return Err(invalid("state local ids must be strictly ascending"));
        }
        validate_sparse_vector(&record.vector, dim, limits)?;
        validate_memberships(&record.memberships, centroid_count)?;
        encoded_len = checked_add(encoded_len, varint_len(record.local_id - previous))?;
        encoded_len = checked_add(encoded_len, 16 + 8)?;
        encoded_len = checked_add(encoded_len, varint_len(record.memberships.len() as u32))?;
        let mut previous_centroid = 0_u32;
        for (index, centroid) in record.memberships.iter().enumerate() {
            let delta = if index == 0 {
                *centroid
            } else {
                *centroid - previous_centroid
            };
            encoded_len = checked_add(encoded_len, varint_len(delta))?;
            previous_centroid = *centroid;
        }
        encoded_len = checked_add(encoded_len, varint_len(record.vector.len() as u32))?;
        let mut previous_idx = 0_u32;
        for (index, (idx, _)) in record.vector.iter().enumerate() {
            let delta = if index == 0 {
                *idx
            } else {
                *idx - previous_idx
            };
            encoded_len = checked_add(encoded_len, varint_len(delta))?;
            encoded_len = checked_add(encoded_len, 4)?;
            previous_idx = *idx;
        }
        previous = record.local_id;
    }
    ensure_decoded_limit(encoded_len, limits)?;
    let mut raw = Vec::with_capacity(encoded_len);
    raw.extend_from_slice(&count.to_le_bytes());
    previous = 0;
    for record in records {
        write_varint(record.local_id - previous, &mut raw);
        raw.extend_from_slice(record.cx_id.as_bytes());
        raw.extend_from_slice(&record.seq.to_le_bytes());
        write_varint(record.memberships.len() as u32, &mut raw);
        let mut previous_centroid = 0_u32;
        for (ordinal, centroid) in record.memberships.iter().enumerate() {
            let delta = if ordinal == 0 {
                *centroid
            } else {
                *centroid - previous_centroid
            };
            write_varint(delta, &mut raw);
            previous_centroid = *centroid;
        }
        write_varint(record.vector.len() as u32, &mut raw);
        let mut previous_idx = 0_u32;
        for (ordinal, (idx, val)) in record.vector.iter().enumerate() {
            let delta = if ordinal == 0 {
                *idx
            } else {
                *idx - previous_idx
            };
            write_varint(delta, &mut raw);
            raw.extend_from_slice(&val.to_bits().to_le_bytes());
            previous_idx = *idx;
        }
        previous = record.local_id;
    }
    debug_assert_eq!(raw.len(), encoded_len);
    Ok(raw)
}

pub(super) fn decode_state_records(
    raw: &[u8],
    dim: u32,
    centroid_count: u32,
    limits: &SpannPostingLimits,
) -> Result<Vec<StoredRecord>> {
    ensure_decoded_limit(raw.len(), limits)?;
    if raw.len() < 4 {
        return Err(corrupt(format!("raw state payload is {} B", raw.len())));
    }
    let count = u32::from_le_bytes(raw[0..4].try_into().expect("4B"));
    if count > limits.max_members_per_segment {
        return Err(corrupt(format!(
            "state count {count} exceeds registry limit {}",
            limits.max_members_per_segment
        )));
    }
    if usize::try_from(count).unwrap_or(usize::MAX) > raw.len().saturating_sub(4) / 26 {
        return Err(corrupt(format!(
            "state count {count} cannot fit in {} remaining bytes",
            raw.len() - 4
        )));
    }
    let mut cursor = 4;
    let mut previous = 0_u32;
    let mut records = Vec::with_capacity(count as usize);
    for ordinal in 0..count {
        let delta = read_canonical_varint(raw, &mut cursor)?;
        if ordinal > 0 && delta == 0 {
            return Err(corrupt("duplicate state local id (zero delta)"));
        }
        let local_id = previous
            .checked_add(delta)
            .ok_or_else(|| corrupt("state local id delta overflow"))?;
        let cx_id = CxId::from_bytes(take_array::<16>(raw, &mut cursor, "state CxId")?);
        let seq = u64::from_le_bytes(take_array::<8>(raw, &mut cursor, "state sequence")?);
        let membership_count = read_canonical_varint(raw, &mut cursor)?;
        if membership_count == 0 || membership_count > centroid_count {
            return Err(corrupt(format!(
                "state {local_id} membership count {membership_count} outside 1..={centroid_count}"
            )));
        }
        if membership_count as usize > raw.len().saturating_sub(cursor) {
            return Err(corrupt(format!(
                "state {local_id} membership count {membership_count} exceeds remaining bytes"
            )));
        }
        let mut memberships = Vec::with_capacity(membership_count as usize);
        let mut previous_centroid = 0_u32;
        for index in 0..membership_count {
            let delta = read_canonical_varint(raw, &mut cursor)?;
            if index > 0 && delta == 0 {
                return Err(corrupt(format!(
                    "state {local_id} has duplicate centroid membership"
                )));
            }
            let centroid = previous_centroid
                .checked_add(delta)
                .ok_or_else(|| corrupt("state centroid delta overflow"))?;
            if centroid >= centroid_count {
                return Err(corrupt(format!(
                    "state {local_id} centroid {centroid} outside count {centroid_count}"
                )));
            }
            memberships.push(centroid);
            previous_centroid = centroid;
        }
        let vector = decode_sparse_vector(raw, &mut cursor, dim, limits)?;
        records.push(StoredRecord {
            local_id,
            cx_id,
            vector,
            memberships,
            seq,
        });
        previous = local_id;
    }
    if cursor != raw.len() {
        return Err(corrupt(format!(
            "{} trailing state payload bytes",
            raw.len() - cursor
        )));
    }
    Ok(records)
}

fn decode_sparse_vector(
    raw: &[u8],
    cursor: &mut usize,
    dim: u32,
    limits: &SpannPostingLimits,
) -> Result<Vec<(u32, f32)>> {
    let nnz = read_canonical_varint(raw, cursor)?;
    if nnz > limits.max_nnz_per_member {
        return Err(corrupt(format!(
            "sparse nnz {nnz} exceeds registry limit {}",
            limits.max_nnz_per_member
        )));
    }
    let minimum = usize::try_from(nnz)
        .ok()
        .and_then(|count| count.checked_mul(5))
        .ok_or_else(|| corrupt("sparse minimum byte count overflow"))?;
    if minimum > raw.len().saturating_sub(*cursor) {
        return Err(corrupt(format!(
            "sparse nnz {nnz} needs at least {minimum} bytes but {} remain",
            raw.len().saturating_sub(*cursor)
        )));
    }
    let mut vector = Vec::with_capacity(nnz as usize);
    let mut previous_idx = 0_u32;
    for ordinal in 0..nnz {
        let delta = read_canonical_varint(raw, cursor)?;
        if ordinal > 0 && delta == 0 {
            return Err(corrupt("duplicate sparse dimension (zero delta)"));
        }
        let idx = previous_idx
            .checked_add(delta)
            .ok_or_else(|| corrupt("sparse dimension delta overflow"))?;
        if idx >= dim {
            return Err(corrupt(format!(
                "sparse dimension {idx} outside declared dim {dim}"
            )));
        }
        let val = f32::from_bits(u32::from_le_bytes(take_array::<4>(
            raw,
            cursor,
            "sparse value",
        )?));
        if !val.is_finite() {
            return Err(corrupt(format!(
                "sparse dimension {idx} has non-finite value"
            )));
        }
        vector.push((idx, val));
        previous_idx = idx;
    }
    Ok(vector)
}

pub(super) fn validate_sparse_vector(
    vector: &[(u32, f32)],
    dim: u32,
    limits: &SpannPostingLimits,
) -> Result<()> {
    let nnz = u32::try_from(vector.len()).map_err(|_| invalid("sparse nnz exceeds u32"))?;
    if nnz > limits.max_nnz_per_member {
        return Err(invalid(format!(
            "sparse nnz {nnz} exceeds registry limit {}",
            limits.max_nnz_per_member
        )));
    }
    let mut previous = None;
    for (idx, val) in vector {
        if *idx >= dim {
            return Err(invalid(format!(
                "sparse dimension {idx} outside declared dim {dim}"
            )));
        }
        if previous.is_some_and(|last| *idx <= last) {
            return Err(invalid("sparse dimensions must be strictly ascending"));
        }
        if !val.is_finite() {
            return Err(invalid(format!(
                "sparse dimension {idx} has non-finite value"
            )));
        }
        previous = Some(*idx);
    }
    Ok(())
}

fn validate_memberships(memberships: &[u32], centroid_count: u32) -> Result<()> {
    if memberships.is_empty() {
        return Err(invalid(
            "stored record requires at least one centroid membership",
        ));
    }
    let mut previous = None;
    for centroid in memberships {
        if *centroid >= centroid_count {
            return Err(invalid(format!(
                "centroid membership {centroid} outside count {centroid_count}"
            )));
        }
        if previous.is_some_and(|last| *centroid <= last) {
            return Err(invalid("centroid memberships must be strictly ascending"));
        }
        previous = Some(*centroid);
    }
    Ok(())
}

fn write_varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_canonical_varint(raw: &[u8], cursor: &mut usize) -> Result<u32> {
    let start = *cursor;
    let mut value = 0_u32;
    let mut shift = 0_u32;
    loop {
        let byte = take_byte(raw, cursor, "posting varint")?;
        if shift == 28 && byte > 0x0f {
            return Err(corrupt("posting varint exceeds u32"));
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let used = *cursor - start;
            if used != varint_len(value) {
                return Err(corrupt(format!(
                    "noncanonical posting varint for {value}: {used} bytes"
                )));
            }
            return Ok(value);
        }
        shift += 7;
        if shift > 28 {
            return Err(corrupt("posting varint exceeds u32"));
        }
    }
}

const fn varint_len(mut value: u32) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn take_byte(raw: &[u8], cursor: &mut usize, label: &str) -> Result<u8> {
    let byte = *raw
        .get(*cursor)
        .ok_or_else(|| corrupt(format!("truncated {label}")))?;
    *cursor += 1;
    Ok(byte)
}

fn take_array<const N: usize>(raw: &[u8], cursor: &mut usize, label: &str) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| corrupt(format!("{label} offset overflow")))?;
    let bytes = raw
        .get(*cursor..end)
        .ok_or_else(|| corrupt(format!("truncated {label}")))?;
    *cursor = end;
    Ok(bytes.try_into().expect("exact length"))
}

fn checked_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| invalid("posting encoded length overflow"))
}

fn ensure_decoded_limit(len: usize, limits: &SpannPostingLimits) -> Result<()> {
    let len = u64::try_from(len).map_err(|_| invalid("posting length exceeds u64"))?;
    if len > limits.max_decoded_segment_bytes {
        return Err(invalid(format!(
            "decoded posting length {len} exceeds registry limit {}",
            limits.max_decoded_segment_bytes
        )));
    }
    Ok(())
}
