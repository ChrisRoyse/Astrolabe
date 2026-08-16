use std::fs::OpenOptions;
use std::path::Path;

use calyx_core::{CalyxError, CalyxErrorCode, Result};

use super::record::{HeaderStatus, LogicalStatus, RecordKind};
use super::{ReplayRecord, TornTail, record, segment, storage_error};

/// Reads and validates one logical WAL commit by exact segment and byte range.
///
/// For a commit framed as a multi-record group, `seq` is the single commit seq
/// shared by every member and `start_offset`/`end_offset` span the whole group
/// — exactly the coordinates a group-aware replay recorded — and the
/// reassembled payload is returned.
pub(crate) fn read_record_at(
    segment_path: impl AsRef<Path>,
    seq: u64,
    start_offset: u64,
    end_offset: u64,
) -> Result<ReplayRecord> {
    let path = segment_path.as_ref();
    let dir = path
        .parent()
        .ok_or_else(|| CalyxError::disk_pressure("WAL segment path has no parent"))?;
    let _lock = crate::file_lock::FileLockGuard::acquire(&dir.join(".append.lock"))?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| storage_error("open WAL segment for point read", error))?;
    match record::decode_logical_at(&mut file, start_offset)
        .map_err(|error| storage_error("decode WAL record", error))?
    {
        LogicalStatus::Complete(decoded) => {
            if decoded.seq != seq
                || decoded.start_offset != start_offset
                || decoded.end_offset != end_offset
            {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "WAL record {} decoded as seq {} range {}..{} instead of seq {seq} range {start_offset}..{end_offset}",
                    path.display(),
                    decoded.seq,
                    decoded.start_offset,
                    decoded.end_offset
                )));
            }
            Ok(ReplayRecord {
                seq: decoded.seq,
                payload: decoded.payload,
                segment_path: path.to_path_buf(),
                start_offset: decoded.start_offset,
                end_offset: decoded.end_offset,
            })
        }
        LogicalStatus::Eof => Err(CalyxError::aster_corrupt_shard(format!(
            "WAL record {seq} at {}:{}..{} is beyond EOF",
            path.display(),
            start_offset,
            end_offset
        ))),
        LogicalStatus::Torn { offset, message } => Err(TornTail {
            segment_path: path.to_path_buf(),
            offset,
            code: CalyxErrorCode::AsterTornWal.code(),
            message,
        }
        .error()),
    }
}

/// Locates and reads one exact retained logical commit by sequence.
///
/// Canonical segment names are enumerated in order. Every physical framing
/// header through `seq` is validated, including skipped multi-record group
/// membership, without reading its payload. Only the requested standalone
/// record or complete group is decoded and CRC-validated. A recycled segment,
/// a sequence gap that advances beyond `seq`, duplicate/non-increasing framing,
/// or a torn group therefore refuses instead of being reclassified as an
/// absent payload.
pub(crate) fn read_record_by_seq(dir: impl AsRef<Path>, seq: u64) -> Result<ReplayRecord> {
    if seq == 0 {
        return Err(CalyxError::aster_corrupt_shard(
            "WAL exact-record sequence must be nonzero",
        ));
    }
    let dir = dir.as_ref();
    let _lock =
        crate::file_lock::FileLockGuard::acquire_shared_existing(&dir.join(".append.lock"))?;
    let segments = segment::list_segments(dir)?;
    if segments.is_empty() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "WAL seq {seq} requested from empty directory {}",
            dir.display()
        )));
    }

    let mut last_logical_seq = None;
    for (_, path) in segments {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|error| storage_error("open WAL segment for exact-record lookup", error))?;
        let file_len = file
            .metadata()
            .map_err(|error| storage_error("stat WAL segment for exact-record lookup", error))?
            .len();
        let mut offset = 0u64;
        let mut pending_group: Option<(u64, u32, u32)> = None;
        loop {
            let header = match record::read_header_at(&mut file, offset)
                .map_err(|error| storage_error("decode WAL exact-record header", error))?
            {
                HeaderStatus::Complete(header) => header,
                HeaderStatus::Eof if pending_group.is_some() => {
                    return Err(TornTail {
                        segment_path: path.clone(),
                        offset,
                        code: CalyxErrorCode::AsterTornWal.code(),
                        message: format!(
                            "incomplete WAL group before requested seq {seq}: reached EOF with pending framing {pending_group:?}"
                        ),
                    }
                    .error());
                }
                HeaderStatus::Eof => break,
                HeaderStatus::Torn { offset, message } => {
                    return Err(TornTail {
                        segment_path: path.clone(),
                        offset,
                        code: CalyxErrorCode::AsterTornWal.code(),
                        message,
                    }
                    .error());
                }
            };
            if header.end_offset > file_len {
                return Err(TornTail {
                    segment_path: path.clone(),
                    offset,
                    code: CalyxErrorCode::AsterTornWal.code(),
                    message: format!(
                        "WAL header for seq {} declares end {} beyond file length {file_len}",
                        header.seq, header.end_offset
                    ),
                }
                .error());
            }

            match (pending_group, header.kind) {
                (None, RecordKind::Standalone) => {
                    require_increasing_seq(&path, last_logical_seq, header.seq, offset)?;
                    if header.seq == seq {
                        return decode_requested_record(&mut file, &path, seq, offset);
                    }
                    if header.seq > seq {
                        return Err(sequence_absent_before(&path, seq, header.seq));
                    }
                    last_logical_seq = Some(header.seq);
                }
                (None, RecordKind::GroupMember { index: 0, count }) => {
                    require_increasing_seq(&path, last_logical_seq, header.seq, offset)?;
                    if header.seq == seq {
                        return decode_requested_record(&mut file, &path, seq, offset);
                    }
                    if header.seq > seq {
                        return Err(sequence_absent_before(&path, seq, header.seq));
                    }
                    if count == 1 {
                        last_logical_seq = Some(header.seq);
                    } else {
                        pending_group = Some((header.seq, 1, count));
                    }
                }
                (
                    Some((group_seq, next_index, count)),
                    RecordKind::GroupMember {
                        index,
                        count: found,
                    },
                ) if header.seq == group_seq && index == next_index && found == count => {
                    if next_index + 1 == count {
                        pending_group = None;
                        last_logical_seq = Some(group_seq);
                    } else {
                        pending_group = Some((group_seq, next_index + 1, count));
                    }
                }
                (pending, kind) => {
                    return Err(TornTail {
                        segment_path: path.clone(),
                        offset,
                        code: CalyxErrorCode::AsterTornWal.code(),
                        message: format!(
                            "invalid logical group framing during exact-record lookup: pending {pending:?}, found seq {} {kind:?}",
                            header.seq
                        ),
                    }
                    .error());
                }
            }
            offset = header.end_offset;
        }
    }

    Err(CalyxError::aster_corrupt_shard(format!(
        "WAL seq {seq} is absent from the retained canonical segment set in {} (the record may have been recycled or compacted away)",
        dir.display()
    )))
}

/// Reads the named logical commit only when it is the exact physical WAL tip.
///
/// Segment enumeration validates canonical names and continuity. Only the
/// final segment is opened: earlier payloads and headers cannot contain the
/// tip, while rotation guarantees the latest append lives in the final
/// segment. Headers before `seq` in that bounded segment are walked without
/// decoding payloads; the named standalone record or complete group is then
/// decoded with CRC validation and must end exactly at EOF.
pub(crate) fn read_tip_record(dir: impl AsRef<Path>, seq: u64) -> Result<ReplayRecord> {
    let dir = dir.as_ref();
    let _lock =
        crate::file_lock::FileLockGuard::acquire_shared_existing(&dir.join(".append.lock"))?;
    let segments = segment::list_segments(dir)?;
    let (_, path) = segments.last().ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!(
            "WAL tip seq {seq} requested from empty directory {}",
            dir.display()
        ))
    })?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| storage_error("open WAL tip segment", error))?;
    let file_len = file
        .metadata()
        .map_err(|error| storage_error("stat WAL tip segment", error))?
        .len();
    let mut offset = 0u64;
    let mut last_logical_seq = None;
    let mut pending_group: Option<(u64, u32, u32)> = None;
    loop {
        let header = match record::read_header_at(&mut file, offset)
            .map_err(|error| storage_error("decode WAL tip header", error))?
        {
            HeaderStatus::Complete(header) => header,
            HeaderStatus::Eof if pending_group.is_some() => {
                return Err(TornTail {
                    segment_path: path.clone(),
                    offset,
                    code: CalyxErrorCode::AsterTornWal.code(),
                    message: format!(
                        "incomplete WAL group before requested tip seq {seq}: reached EOF with pending framing {pending_group:?}"
                    ),
                }
                .error());
            }
            HeaderStatus::Eof => {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "WAL tip seq {seq} is absent from final segment {}",
                    path.display()
                )));
            }
            HeaderStatus::Torn { offset, message } => {
                return Err(TornTail {
                    segment_path: path.clone(),
                    offset,
                    code: CalyxErrorCode::AsterTornWal.code(),
                    message,
                }
                .error());
            }
        };
        if header.end_offset > file_len {
            return Err(TornTail {
                segment_path: path.clone(),
                offset,
                code: CalyxErrorCode::AsterTornWal.code(),
                message: format!(
                    "WAL header for seq {} declares end {} beyond file length {file_len}",
                    header.seq, header.end_offset
                ),
            }
            .error());
        }

        match (pending_group, header.kind) {
            (None, RecordKind::Standalone) => {
                require_increasing_seq(path, last_logical_seq, header.seq, offset)?;
                last_logical_seq = Some(header.seq);
            }
            (None, RecordKind::GroupMember { index: 0, count }) => {
                require_increasing_seq(path, last_logical_seq, header.seq, offset)?;
                if count > 1 {
                    pending_group = Some((header.seq, 1, count));
                } else {
                    last_logical_seq = Some(header.seq);
                }
            }
            (
                Some((group_seq, next_index, count)),
                RecordKind::GroupMember {
                    index,
                    count: found,
                },
            ) if header.seq == group_seq && index == next_index && found == count => {
                if next_index + 1 == count {
                    pending_group = None;
                    last_logical_seq = Some(group_seq);
                } else {
                    pending_group = Some((group_seq, next_index + 1, count));
                }
            }
            (pending, kind) => {
                return Err(TornTail {
                    segment_path: path.clone(),
                    offset,
                    code: CalyxErrorCode::AsterTornWal.code(),
                    message: format!(
                        "invalid logical group framing before WAL tip: pending {pending:?}, found seq {} {kind:?}",
                        header.seq
                    ),
                }
                .error());
            }
        }

        if header.seq == seq {
            match record::decode_logical_at(&mut file, offset)
                .map_err(|error| storage_error("decode WAL tip record", error))?
            {
                LogicalStatus::Complete(decoded) => {
                    if decoded.seq != seq || decoded.end_offset != file_len {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "WAL seq {seq} decoded at {}..{} but final segment {} ends at {file_len}; the named commit is not the exact physical tip",
                            decoded.start_offset,
                            decoded.end_offset,
                            path.display()
                        )));
                    }
                    return Ok(ReplayRecord {
                        seq: decoded.seq,
                        payload: decoded.payload,
                        segment_path: path.clone(),
                        start_offset: decoded.start_offset,
                        end_offset: decoded.end_offset,
                    });
                }
                LogicalStatus::Eof => {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "WAL tip seq {seq} at {}:{offset} is beyond EOF",
                        path.display()
                    )));
                }
                LogicalStatus::Torn { offset, message } => {
                    return Err(TornTail {
                        segment_path: path.clone(),
                        offset,
                        code: CalyxErrorCode::AsterTornWal.code(),
                        message,
                    }
                    .error());
                }
            }
        }
        if header.seq > seq {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "WAL final segment {} advanced to seq {} before requested tip seq {seq}",
                path.display(),
                header.seq
            )));
        }
        offset = header.end_offset;
    }
}

fn decode_requested_record(
    file: &mut std::fs::File,
    path: &Path,
    seq: u64,
    offset: u64,
) -> Result<ReplayRecord> {
    match record::decode_logical_at(file, offset)
        .map_err(|error| storage_error("decode requested WAL record", error))?
    {
        LogicalStatus::Complete(decoded) => {
            if decoded.seq != seq || decoded.start_offset != offset {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "WAL exact-record lookup requested seq {seq} at {}:{offset}, decoded seq {} range {}..{}",
                    path.display(),
                    decoded.seq,
                    decoded.start_offset,
                    decoded.end_offset
                )));
            }
            Ok(ReplayRecord {
                seq: decoded.seq,
                payload: decoded.payload,
                segment_path: path.to_path_buf(),
                start_offset: decoded.start_offset,
                end_offset: decoded.end_offset,
            })
        }
        LogicalStatus::Eof => Err(CalyxError::aster_corrupt_shard(format!(
            "WAL seq {seq} at {}:{offset} is beyond EOF",
            path.display()
        ))),
        LogicalStatus::Torn { offset, message } => Err(TornTail {
            segment_path: path.to_path_buf(),
            offset,
            code: CalyxErrorCode::AsterTornWal.code(),
            message,
        }
        .error()),
    }
}

fn sequence_absent_before(path: &Path, requested: u64, observed: u64) -> CalyxError {
    CalyxError::aster_corrupt_shard(format!(
        "WAL segment {} advanced to seq {observed} before requested seq {requested}; the exact retained record is absent",
        path.display()
    ))
}

fn require_increasing_seq(
    path: &Path,
    previous: Option<u64>,
    observed: u64,
    offset: u64,
) -> Result<()> {
    if previous.is_none_or(|previous| observed > previous) {
        return Ok(());
    }
    Err(CalyxError::aster_corrupt_shard(format!(
        "WAL logical sequence is not strictly increasing in {} at byte {offset}: previous {}, observed {observed}",
        path.display(),
        previous.expect("non-increasing branch requires a previous seq")
    )))
}
