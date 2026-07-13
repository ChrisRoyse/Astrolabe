//! WAL record framing.
//!
//! Two on-disk record kinds share this file:
//!
//! * **Standalone** (`MAGIC` = `CXW1`, 20-byte header) — one record *is* one
//!   whole atomic commit. This is the original v1 layout and is written
//!   byte-for-byte unchanged for any commit whose encoded payload fits in a
//!   single record chunk, so every WAL written before multi-record framing
//!   replays identically.
//! * **Group member** (`MAGIC_GROUP` = `CXW2`, 28-byte header) — one chunk of
//!   an atomic commit that is too large for a single record. A commit larger
//!   than [`CHUNK_TARGET_BYTES`] is split, at byte boundaries, into
//!   `member_count` chunk records carrying `member_index` `0..member_count`.
//!   Replay applies the group only when every member is present (all-or-nothing);
//!   an incomplete trailing group at EOF is a torn tail and is truncated exactly
//!   like a torn single record. See [`decode_logical_at`].
//!
//! The two kinds are distinguished by the leading magic, so a reader accepts
//! both and old single-record WALs need no migration.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

pub(super) const MAGIC: u32 = u32::from_le_bytes(*b"CXW1");
pub(super) const MAGIC_GROUP: u32 = u32::from_le_bytes(*b"CXW2");
pub(super) const HEADER_LEN: usize = 20;
pub(super) const GROUP_HEADER_LEN: usize = 28;
pub(super) const MAX_RECORD_BYTES: u32 = 64 * 1024 * 1024;
/// Soft target size for one WAL record chunk when framing a commit that does
/// not fit in a single record. Kept strictly below [`MAX_RECORD_BYTES`] so the
/// per-record header can never tip an individual chunk over the hard cap, and
/// large enough that a 500k-edge first-index commit frames into a handful of
/// records rather than thousands. This is a physical framing parameter in the
/// same family as [`MAX_RECORD_BYTES`], not a measured threshold.
pub(super) const CHUNK_TARGET_BYTES: u32 = 32 * 1024 * 1024;

/// Which on-disk record layout a header/record uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordKind {
    /// A whole atomic commit in one record (`CXW1`).
    Standalone,
    /// One chunk of a multi-record atomic commit (`CXW2`).
    GroupMember { index: u32, count: u32 },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DecodeStatus {
    Complete(DecodedRecord),
    Eof,
    Torn { offset: u64, message: String },
}

/// Result of reassembling one *logical* commit (a standalone record, or a
/// complete group) starting at a byte offset.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LogicalStatus {
    Complete(DecodedRecord),
    Eof,
    Torn { offset: u64, message: String },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum HeaderStatus {
    Complete(RecordHeader),
    Eof,
    Torn { offset: u64, message: String },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RecordHeader {
    pub seq: u64,
    pub len: u32,
    pub kind: RecordKind,
    pub expected_crc: u32,
    pub start_offset: u64,
    /// Offset of the first payload byte (`start_offset + header width`).
    pub payload_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct DecodedRecord {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub kind: RecordKind,
    pub start_offset: u64,
    pub end_offset: u64,
}

/// Encodes a standalone (`CXW1`) commit record. Layout unchanged from v1.
pub(super) fn encode(seq: u64, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_RECORD_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("WAL payload exceeds max record size {MAX_RECORD_BYTES}"),
        ));
    }

    let len = payload.len() as u32;
    let crc = standalone_crc(seq, len, payload);
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(&MAGIC.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Encodes one chunk record (`CXW2`) of a multi-record atomic commit.
pub(super) fn encode_group_member(
    seq: u64,
    member_index: u32,
    member_count: u32,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_RECORD_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("WAL payload exceeds max record size {MAX_RECORD_BYTES}"),
        ));
    }

    let len = payload.len() as u32;
    let crc = group_crc(seq, member_index, member_count, len, payload);
    let mut bytes = Vec::with_capacity(GROUP_HEADER_LEN + payload.len());
    bytes.extend_from_slice(&MAGIC_GROUP.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&member_index.to_le_bytes());
    bytes.extend_from_slice(&member_count.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Decodes one *physical* record (standalone or a single group member) at
/// `offset`. Group reassembly is done by [`decode_logical_at`].
pub(super) fn decode_at(file: &mut File, offset: u64) -> io::Result<DecodeStatus> {
    let header = match read_header_at(file, offset)? {
        HeaderStatus::Complete(header) => header,
        HeaderStatus::Eof => return Ok(DecodeStatus::Eof),
        HeaderStatus::Torn { offset, message } => {
            return Ok(DecodeStatus::Torn { offset, message });
        }
    };
    file.seek(SeekFrom::Start(header.payload_offset))?;
    let mut payload = vec![0u8; header.len as usize];
    if let Err(error) = file.read_exact(&mut payload) {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(DecodeStatus::Torn {
                offset,
                message: format!(
                    "partial WAL payload for seq {}: wanted {} bytes",
                    header.seq, header.len
                ),
            });
        }
        return Err(error);
    }

    let actual_crc = record_crc(&header, &payload);
    if actual_crc != header.expected_crc {
        return Ok(DecodeStatus::Torn {
            offset,
            message: format!(
                "crc mismatch for seq {}: expected {:08x}, got {actual_crc:08x}",
                header.seq, header.expected_crc
            ),
        });
    }

    Ok(DecodeStatus::Complete(DecodedRecord {
        seq: header.seq,
        payload,
        kind: header.kind,
        start_offset: offset,
        end_offset: header.end_offset,
    }))
}

/// Decodes one *logical* commit at `offset`: a standalone record verbatim, or a
/// complete group reassembled from its member chunks into one payload.
///
/// A complete group returns a [`DecodedRecord`] whose `seq` is the single commit
/// seq shared by every member, whose `payload` is the byte concatenation of
/// every member chunk (identical to the pre-split payload), and whose
/// `start_offset` / `end_offset` span the whole group. An incomplete group at
/// EOF, or any member framing inconsistency, is reported as `Torn` at the
/// group's start offset so the caller discards the entire partial group
/// (all-or-nothing).
pub(super) fn decode_logical_at(file: &mut File, offset: u64) -> io::Result<LogicalStatus> {
    let first = match decode_at(file, offset)? {
        DecodeStatus::Complete(record) => record,
        DecodeStatus::Eof => return Ok(LogicalStatus::Eof),
        DecodeStatus::Torn { offset, message } => {
            return Ok(LogicalStatus::Torn { offset, message });
        }
    };

    let count = match first.kind {
        RecordKind::Standalone => return Ok(LogicalStatus::Complete(first)),
        RecordKind::GroupMember { index: 0, count } if count >= 1 => count,
        RecordKind::GroupMember { index, count } => {
            return Ok(LogicalStatus::Torn {
                offset: first.start_offset,
                message: format!(
                    "WAL logical record at byte {} starts at group member {index}/{count} \
                     instead of member 0",
                    first.start_offset
                ),
            });
        }
    };

    let group_start = first.start_offset;
    let commit_seq = first.seq;
    let mut payload = first.payload;
    let mut final_end = first.end_offset;
    let mut next_offset = first.end_offset;
    let mut expected_index = 1u32;
    while expected_index < count {
        match decode_at(file, next_offset)? {
            DecodeStatus::Complete(member) => match member.kind {
                // Every member of one atomic commit shares the commit seq; a
                // differing seq, count, or out-of-order index is torn framing.
                RecordKind::GroupMember {
                    index: member_index,
                    count: member_count,
                } if member_count == count
                    && member_index == expected_index
                    && member.seq == commit_seq =>
                {
                    payload.extend_from_slice(&member.payload);
                    final_end = member.end_offset;
                    next_offset = member.end_offset;
                    expected_index += 1;
                }
                other_kind => {
                    return Ok(LogicalStatus::Torn {
                        offset: group_start,
                        message: format!(
                            "WAL group starting at byte {group_start} (seq {commit_seq}) expected \
                             member {expected_index}/{count} but found seq {} {other_kind:?}",
                            member.seq
                        ),
                    });
                }
            },
            DecodeStatus::Eof => {
                return Ok(LogicalStatus::Torn {
                    offset: group_start,
                    message: format!(
                        "incomplete WAL group starting at byte {group_start}: reached EOF with \
                         {expected_index}/{count} members"
                    ),
                });
            }
            DecodeStatus::Torn { message, .. } => {
                return Ok(LogicalStatus::Torn {
                    offset: group_start,
                    message: format!(
                        "incomplete WAL group starting at byte {group_start} after \
                         {expected_index}/{count} members: {message}"
                    ),
                });
            }
        }
    }

    Ok(LogicalStatus::Complete(DecodedRecord {
        seq: commit_seq,
        payload,
        kind: RecordKind::Standalone,
        start_offset: group_start,
        end_offset: final_end,
    }))
}

pub(super) fn read_header_at(file: &mut File, offset: u64) -> io::Result<HeaderStatus> {
    file.seek(SeekFrom::Start(offset))?;
    let mut magic_bytes = [0u8; 4];
    let read = file.read(&mut magic_bytes)?;
    if read == 0 {
        return Ok(HeaderStatus::Eof);
    }
    if read < 4 {
        return Ok(HeaderStatus::Torn {
            offset,
            message: format!("partial WAL header: {read}/4 magic bytes"),
        });
    }
    let magic = u32::from_le_bytes(magic_bytes);
    match magic {
        MAGIC => read_standalone_header(file, offset),
        MAGIC_GROUP => read_group_header(file, offset),
        _ => Ok(HeaderStatus::Torn {
            offset,
            message: format!("bad WAL magic 0x{magic:08x}"),
        }),
    }
}

fn read_standalone_header(file: &mut File, offset: u64) -> io::Result<HeaderStatus> {
    let mut tail = [0u8; HEADER_LEN - 4];
    let read = file.read(&mut tail)?;
    if read < tail.len() {
        return Ok(HeaderStatus::Torn {
            offset,
            message: format!("partial WAL header: {}/{HEADER_LEN} bytes", read + 4),
        });
    }
    let seq = u64::from_le_bytes(tail[0..8].try_into().expect("seq width"));
    let len = u32::from_le_bytes(tail[8..12].try_into().expect("len width"));
    let expected_crc = u32::from_le_bytes(tail[12..16].try_into().expect("crc width"));
    if len > MAX_RECORD_BYTES {
        return Ok(HeaderStatus::Torn {
            offset,
            message: format!("record length {len} exceeds max {MAX_RECORD_BYTES}"),
        });
    }
    let payload_offset = offset + HEADER_LEN as u64;
    Ok(HeaderStatus::Complete(RecordHeader {
        seq,
        len,
        kind: RecordKind::Standalone,
        expected_crc,
        start_offset: offset,
        payload_offset,
        end_offset: payload_offset + len as u64,
    }))
}

fn read_group_header(file: &mut File, offset: u64) -> io::Result<HeaderStatus> {
    let mut tail = [0u8; GROUP_HEADER_LEN - 4];
    let read = file.read(&mut tail)?;
    if read < tail.len() {
        return Ok(HeaderStatus::Torn {
            offset,
            message: format!(
                "partial WAL group header: {}/{GROUP_HEADER_LEN} bytes",
                read + 4
            ),
        });
    }
    let seq = u64::from_le_bytes(tail[0..8].try_into().expect("seq width"));
    let member_index = u32::from_le_bytes(tail[8..12].try_into().expect("member index width"));
    let member_count = u32::from_le_bytes(tail[12..16].try_into().expect("member count width"));
    let len = u32::from_le_bytes(tail[16..20].try_into().expect("len width"));
    let expected_crc = u32::from_le_bytes(tail[20..24].try_into().expect("crc width"));
    if len > MAX_RECORD_BYTES {
        return Ok(HeaderStatus::Torn {
            offset,
            message: format!("record length {len} exceeds max {MAX_RECORD_BYTES}"),
        });
    }
    if member_count == 0 || member_index >= member_count {
        return Ok(HeaderStatus::Torn {
            offset,
            message: format!("invalid WAL group framing: member {member_index}/{member_count}"),
        });
    }
    let payload_offset = offset + GROUP_HEADER_LEN as u64;
    Ok(HeaderStatus::Complete(RecordHeader {
        seq,
        len,
        kind: RecordKind::GroupMember {
            index: member_index,
            count: member_count,
        },
        expected_crc,
        start_offset: offset,
        payload_offset,
        end_offset: payload_offset + len as u64,
    }))
}

fn record_crc(header: &RecordHeader, payload: &[u8]) -> u32 {
    match header.kind {
        RecordKind::Standalone => standalone_crc(header.seq, header.len, payload),
        RecordKind::GroupMember { index, count } => {
            group_crc(header.seq, index, count, header.len, payload)
        }
    }
}

fn standalone_crc(seq: u64, len: u32, payload: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&seq.to_le_bytes());
    hasher.update(&len.to_le_bytes());
    hasher.update(payload);
    hasher.finalize()
}

fn group_crc(seq: u64, member_index: u32, member_count: u32, len: u32, payload: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&seq.to_le_bytes());
    hasher.update(&member_index.to_le_bytes());
    hasher.update(&member_count.to_le_bytes());
    hasher.update(&len.to_le_bytes());
    hasher.update(payload);
    hasher.finalize()
}
