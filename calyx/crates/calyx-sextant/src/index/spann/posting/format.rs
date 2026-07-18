use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::Result;

use super::codec::{
    PostingMutation, StoredRecord, decode_posting_mutations, decode_state_records,
    encode_posting_mutations, encode_state_records,
};
use super::config::{
    SPANN_POSTING_FORMAT_VERSION, SPANN_POSTING_SEGMENT_MAGIC, SPANN_STATE_SEGMENT_MAGIC,
    SpannIndexIdentity, SpannPostingLimits,
};
use super::{corrupt, io};

const SEGMENT_HEADER_BYTES: usize = 232;
const SEGMENT_SEAL_OFFSET: usize = 200;
const CODEC_ZSTD: u8 = 1;
const FLAG_ZSTD_CHECKSUM: u8 = 1;
const STATE_CENTROID_ID: u32 = u32::MAX;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SegmentKind {
    Posting = 1,
    State = 2,
}

impl SegmentKind {
    pub(super) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Posting),
            2 => Ok(Self::State),
            _ => Err(corrupt(format!("unknown SPANN segment kind {tag}"))),
        }
    }

    const fn magic(self) -> [u8; 8] {
        match self {
            Self::Posting => SPANN_POSTING_SEGMENT_MAGIC,
            Self::State => SPANN_STATE_SEGMENT_MAGIC,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SegmentDescriptor {
    pub kind: SegmentKind,
    pub centroid_id: u32,
    pub generation: u64,
    pub record_count: u32,
    pub min_local_id: u32,
    pub max_local_id: u32,
    pub file_len: u64,
    pub decoded_len: u64,
    pub compressed_len: u64,
    pub file_hash: [u8; 32],
    pub file_name: String,
}

#[derive(Debug)]
pub(super) struct StagedSegment {
    pub descriptor: SegmentDescriptor,
    bytes: Vec<u8>,
}

pub(super) enum DecodedSegment {
    Posting(Vec<PostingMutation>),
    State(Vec<StoredRecord>),
}

pub(super) fn build_posting_segment(
    identity: &SpannIndexIdentity,
    centroid_id: u32,
    generation: u64,
    operations: &[PostingMutation],
    limits: &SpannPostingLimits,
) -> Result<StagedSegment> {
    if centroid_id >= identity.centroid_count {
        return Err(corrupt(format!(
            "posting centroid {centroid_id} outside count {}",
            identity.centroid_count
        )));
    }
    let raw = encode_posting_mutations(operations, identity.dim, limits)?;
    let (min_local_id, max_local_id) = id_range(operations.iter().map(|op| op.cx_id));
    build_segment(
        SegmentKind::Posting,
        identity,
        centroid_id,
        generation,
        operations.len(),
        min_local_id,
        max_local_id,
        raw,
        limits,
    )
}

pub(super) fn build_state_segment(
    identity: &SpannIndexIdentity,
    generation: u64,
    records: &[StoredRecord],
    limits: &SpannPostingLimits,
) -> Result<StagedSegment> {
    let raw = encode_state_records(records, identity.dim, identity.centroid_count, limits)?;
    let (min_local_id, max_local_id) = id_range(records.iter().map(|record| record.local_id));
    build_segment(
        SegmentKind::State,
        identity,
        STATE_CENTROID_ID,
        generation,
        records.len(),
        min_local_id,
        max_local_id,
        raw,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_segment(
    kind: SegmentKind,
    identity: &SpannIndexIdentity,
    centroid_id: u32,
    generation: u64,
    record_count: usize,
    min_local_id: u32,
    max_local_id: u32,
    raw: Vec<u8>,
    limits: &SpannPostingLimits,
) -> Result<StagedSegment> {
    limits.validate()?;
    let record_count =
        u32::try_from(record_count).map_err(|_| corrupt("segment record count exceeds u32"))?;
    let decoded_len =
        u64::try_from(raw.len()).map_err(|_| corrupt("decoded segment length exceeds u64"))?;
    if decoded_len > limits.max_decoded_segment_bytes {
        return Err(corrupt(format!(
            "decoded segment length {decoded_len} exceeds registry limit {}",
            limits.max_decoded_segment_bytes
        )));
    }
    let compressed = compress(&raw, limits)?;
    let compressed_len = u64::try_from(compressed.len())
        .map_err(|_| corrupt("compressed segment length exceeds u64"))?;
    if compressed_len > limits.max_compressed_segment_bytes {
        return Err(corrupt(format!(
            "compressed segment length {compressed_len} exceeds registry limit {}",
            limits.max_compressed_segment_bytes
        )));
    }
    let decoded_hash = *blake3::hash(&raw).as_bytes();
    let limits_hash = limits_hash(limits);
    let mut bytes = vec![0_u8; SEGMENT_HEADER_BYTES];
    bytes[0..8].copy_from_slice(&kind.magic());
    bytes[8..10].copy_from_slice(&SPANN_POSTING_FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(SEGMENT_HEADER_BYTES as u16).to_le_bytes());
    bytes[12] = kind as u8;
    bytes[13] = identity.metric.tag();
    bytes[14] = CODEC_ZSTD;
    bytes[15] = FLAG_ZSTD_CHECKSUM;
    bytes[16..48].copy_from_slice(&identity.index_id);
    bytes[48..80].copy_from_slice(&identity.centroid_hash);
    bytes[80..88].copy_from_slice(&generation.to_le_bytes());
    bytes[88..92].copy_from_slice(&centroid_id.to_le_bytes());
    bytes[92..96].copy_from_slice(&identity.dim.to_le_bytes());
    bytes[96..100].copy_from_slice(&identity.centroid_count.to_le_bytes());
    bytes[100..104].copy_from_slice(&record_count.to_le_bytes());
    bytes[104..108].copy_from_slice(&min_local_id.to_le_bytes());
    bytes[108..112].copy_from_slice(&max_local_id.to_le_bytes());
    bytes[112..116].copy_from_slice(&limits.zstd_level.to_le_bytes());
    bytes[116..120].copy_from_slice(&limits.zstd_window_log_max.to_le_bytes());
    bytes[120..128].copy_from_slice(&decoded_len.to_le_bytes());
    bytes[128..136].copy_from_slice(&compressed_len.to_le_bytes());
    bytes[136..168].copy_from_slice(&decoded_hash);
    bytes[168..200].copy_from_slice(&limits_hash);
    let mut seal = blake3::Hasher::new();
    seal.update(&bytes[..SEGMENT_SEAL_OFFSET]);
    seal.update(&compressed);
    bytes[SEGMENT_SEAL_OFFSET..SEGMENT_HEADER_BYTES].copy_from_slice(seal.finalize().as_bytes());
    bytes.extend_from_slice(&compressed);
    let file_hash = *blake3::hash(&bytes).as_bytes();
    let prefix = hex_prefix(&file_hash, 64);
    let stem = match kind {
        SegmentKind::Posting => format!("p{centroid_id:08x}"),
        SegmentKind::State => "state".to_string(),
    };
    let file_name = format!("{stem}-g{generation:016x}-{prefix}.spz");
    let file_len = u64::try_from(bytes.len()).map_err(|_| corrupt("segment length exceeds u64"))?;
    Ok(StagedSegment {
        descriptor: SegmentDescriptor {
            kind,
            centroid_id,
            generation,
            record_count,
            min_local_id,
            max_local_id,
            file_len,
            decoded_len,
            compressed_len,
            file_hash,
            file_name,
        },
        bytes,
    })
}

pub(super) fn publish_segment(
    dir: &Path,
    staged: StagedSegment,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<SegmentDescriptor> {
    fs::create_dir_all(dir).map_err(|error| io("create posting directory", error))?;
    let final_path = safe_component_path(dir, &staged.descriptor.file_name)?;
    if final_path.exists() {
        return Err(corrupt(format!(
            "immutable segment target already exists: {}",
            final_path.display()
        )));
    }
    let temp_path = unique_temp_path(&final_path)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| io("create segment temp", error))?;
        file.write_all(&staged.bytes)
            .map_err(|error| io("write segment temp", error))?;
        file.sync_all()
            .map_err(|error| io("fsync segment temp", error))?;
        drop(file);
        let readback = read_exact_file(&temp_path, staged.descriptor.file_len, limits)?;
        if blake3::hash(&readback).as_bytes() != &staged.descriptor.file_hash {
            return Err(corrupt(format!(
                "staged segment hash mismatch for {}",
                temp_path.display()
            )));
        }
        decode_segment_bytes(&readback, &staged.descriptor, identity, limits)?;
        publish_synced_file_atomic(&temp_path, &final_path, false)?;
        let final_readback = read_exact_file(&final_path, staged.descriptor.file_len, limits)?;
        if blake3::hash(&final_readback).as_bytes() != &staged.descriptor.file_hash {
            return Err(corrupt(format!(
                "published segment hash mismatch for {}",
                final_path.display()
            )));
        }
        Ok(staged.descriptor)
    })();
    if result.is_err() && temp_path.exists() {
        if let Err(error) = fs::remove_file(&temp_path) {
            tracing::error!(
                path = %temp_path.display(),
                %error,
                "failed to remove uncommitted SPANN segment temp"
            );
        }
    }
    result
}

pub(super) fn read_segment(
    dir: &Path,
    descriptor: &SegmentDescriptor,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<DecodedSegment> {
    let path = safe_component_path(dir, &descriptor.file_name)?;
    let bytes = read_exact_file(&path, descriptor.file_len, limits)?;
    if blake3::hash(&bytes).as_bytes() != &descriptor.file_hash {
        return Err(corrupt(format!(
            "segment {} checksum mismatch",
            path.display()
        )));
    }
    decode_segment_bytes(&bytes, descriptor, identity, limits)
}

fn decode_segment_bytes(
    bytes: &[u8],
    descriptor: &SegmentDescriptor,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<DecodedSegment> {
    let payload = validate_envelope(bytes, descriptor, identity, limits)?;
    let raw = decompress(payload, descriptor.decoded_len, limits)?;
    if blake3::hash(&raw).as_bytes() != &bytes[136..168] {
        return Err(corrupt(format!(
            "segment {} decoded checksum mismatch",
            descriptor.file_name
        )));
    }
    let decoded = match descriptor.kind {
        SegmentKind::Posting => {
            DecodedSegment::Posting(decode_posting_mutations(&raw, identity.dim, limits)?)
        }
        SegmentKind::State => DecodedSegment::State(decode_state_records(
            &raw,
            identity.dim,
            identity.centroid_count,
            limits,
        )?),
    };
    let actual_count = match &decoded {
        DecodedSegment::Posting(records) => records.len(),
        DecodedSegment::State(records) => records.len(),
    };
    if actual_count != descriptor.record_count as usize {
        return Err(corrupt(format!(
            "segment {} decoded {} records but declares {}",
            descriptor.file_name, actual_count, descriptor.record_count
        )));
    }
    Ok(decoded)
}

fn validate_envelope<'a>(
    bytes: &'a [u8],
    descriptor: &SegmentDescriptor,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<&'a [u8]> {
    if bytes.len() < SEGMENT_HEADER_BYTES {
        return Err(corrupt(format!(
            "segment {} is {} B, below header size {SEGMENT_HEADER_BYTES}",
            descriptor.file_name,
            bytes.len()
        )));
    }
    if bytes[0..8] != descriptor.kind.magic() {
        return Err(corrupt(format!(
            "segment {} has wrong magic",
            descriptor.file_name
        )));
    }
    let version = le_u16(bytes, 8);
    let header_len = le_u16(bytes, 10) as usize;
    if version != SPANN_POSTING_FORMAT_VERSION || header_len != SEGMENT_HEADER_BYTES {
        return Err(corrupt(format!(
            "segment {} version/header {version}/{header_len}",
            descriptor.file_name
        )));
    }
    if SegmentKind::from_tag(bytes[12])? != descriptor.kind
        || bytes[13] != identity.metric.tag()
        || bytes[14] != CODEC_ZSTD
        || bytes[15] != FLAG_ZSTD_CHECKSUM
        || bytes[16..48] != identity.index_id
        || bytes[48..80] != identity.centroid_hash
        || le_u64(bytes, 80) != descriptor.generation
        || le_u32(bytes, 88) != descriptor.centroid_id
        || le_u32(bytes, 92) != identity.dim
        || le_u32(bytes, 96) != identity.centroid_count
        || le_u32(bytes, 100) != descriptor.record_count
        || le_u32(bytes, 104) != descriptor.min_local_id
        || le_u32(bytes, 108) != descriptor.max_local_id
        || le_i32(bytes, 112) != limits.zstd_level
        || le_u32(bytes, 116) != limits.zstd_window_log_max
        || le_u64(bytes, 120) != descriptor.decoded_len
        || le_u64(bytes, 128) != descriptor.compressed_len
        || bytes[168..200] != limits_hash(limits)
    {
        return Err(corrupt(format!(
            "segment {} header disagrees with manifest/registry identity",
            descriptor.file_name
        )));
    }
    let payload = &bytes[SEGMENT_HEADER_BYTES..];
    if payload.len() as u64 != descriptor.compressed_len {
        return Err(corrupt(format!(
            "segment {} compressed length {} != {}",
            descriptor.file_name,
            payload.len(),
            descriptor.compressed_len
        )));
    }
    let mut seal = blake3::Hasher::new();
    seal.update(&bytes[..SEGMENT_SEAL_OFFSET]);
    seal.update(payload);
    if seal.finalize().as_bytes() != &bytes[SEGMENT_SEAL_OFFSET..SEGMENT_HEADER_BYTES] {
        return Err(corrupt(format!(
            "segment {} envelope seal mismatch",
            descriptor.file_name
        )));
    }
    Ok(payload)
}

fn compress(raw: &[u8], limits: &SpannPostingLimits) -> Result<Vec<u8>> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), limits.zstd_level)
        .map_err(|error| io("create zstd encoder", error))?;
    encoder
        .include_checksum(true)
        .map_err(|error| io("enable zstd checksum", error))?;
    encoder
        .set_pledged_src_size(Some(raw.len() as u64))
        .map_err(|error| io("declare zstd content size", error))?;
    encoder
        .write_all(raw)
        .map_err(|error| io("compress zstd segment", error))?;
    encoder
        .finish()
        .map_err(|error| io("finish zstd segment", error))
}

fn decompress(payload: &[u8], decoded_len: u64, limits: &SpannPostingLimits) -> Result<Vec<u8>> {
    if decoded_len > limits.max_decoded_segment_bytes {
        return Err(corrupt(format!(
            "declared decoded length {decoded_len} exceeds registry limit {}",
            limits.max_decoded_segment_bytes
        )));
    }
    let frame_len = zstd::zstd_safe::find_frame_compressed_size(payload).map_err(|code| {
        corrupt(format!(
            "invalid zstd frame: {}",
            zstd::zstd_safe::get_error_name(code)
        ))
    })?;
    if frame_len != payload.len() {
        return Err(corrupt(format!(
            "zstd frame length {frame_len} != payload length {}; concatenated/trailing frames are forbidden",
            payload.len()
        )));
    }
    let content_size = zstd::zstd_safe::get_frame_content_size(payload)
        .map_err(|error| corrupt(format!("invalid zstd content-size header: {error:?}")))?
        .ok_or_else(|| corrupt("zstd frame omits required content size"))?;
    if content_size != decoded_len {
        return Err(corrupt(format!(
            "zstd content size {content_size} != declared decoded length {decoded_len}"
        )));
    }
    let expected =
        usize::try_from(decoded_len).map_err(|_| corrupt("decoded length exceeds usize"))?;
    let mut decoder = zstd::stream::Decoder::new(Cursor::new(payload))
        .map_err(|error| io("create bounded zstd decoder", error))?;
    decoder
        .window_log_max(limits.zstd_window_log_max)
        .map_err(|error| io("set zstd decoder window bound", error))?;
    let take = decoded_len
        .checked_add(1)
        .ok_or_else(|| corrupt("decoded length + 1 overflow"))?;
    let mut raw = Vec::with_capacity(expected);
    decoder
        .take(take)
        .read_to_end(&mut raw)
        .map_err(|error| corrupt(format!("zstd decode failed: {error}")))?;
    if raw.len() != expected {
        return Err(corrupt(format!(
            "zstd decoded {} bytes, expected {expected}",
            raw.len()
        )));
    }
    Ok(raw)
}

fn read_exact_file(path: &Path, expected_len: u64, limits: &SpannPostingLimits) -> Result<Vec<u8>> {
    let maximum = (SEGMENT_HEADER_BYTES as u64)
        .checked_add(limits.max_compressed_segment_bytes)
        .ok_or_else(|| corrupt("maximum segment file length overflow"))?;
    if expected_len < SEGMENT_HEADER_BYTES as u64 || expected_len > maximum {
        return Err(corrupt(format!(
            "declared segment length {expected_len} outside {}..={maximum} for {}",
            SEGMENT_HEADER_BYTES,
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|error| io("open declared segment", error))?;
    let actual = file
        .metadata()
        .map_err(|error| io("stat declared segment", error))?
        .len();
    if actual != expected_len {
        return Err(corrupt(format!(
            "declared segment {} length {actual} != manifest {expected_len}",
            path.display()
        )));
    }
    let len = usize::try_from(actual).map_err(|_| corrupt("segment length exceeds usize"))?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes)
        .map_err(|error| io("read declared segment", error))?;
    Ok(bytes)
}

pub(super) fn safe_component_path(dir: &Path, file_name: &str) -> Result<PathBuf> {
    let path = Path::new(file_name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if !file_name.is_empty() && file_name.len() <= 255 => {
            Ok(dir.join(path))
        }
        _ => Err(corrupt(format!(
            "unsafe SPANN component name {file_name:?}"
        ))),
    }
}

fn unique_temp_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| corrupt(format!("segment path {} has no file name", path.display())))?;
    let mut temp = OsString::from(".");
    temp.push(name);
    temp.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(path.with_file_name(temp))
}

pub(crate) fn publish_synced_file_atomic(
    source: &Path,
    target: &Path,
    replace: bool,
) -> Result<()> {
    publish_synced_file_atomic_impl(source, target, replace)
}

#[cfg(windows)]
fn publish_synced_file_atomic_impl(source: &Path, target: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileRenameInfoEx, SYNCHRONIZE, SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
    };

    if target.file_name().is_none() {
        return Err(corrupt(format!(
            "SPANN publication target {} has no file name",
            target.display()
        )));
    }
    // `canonicalize` produces a Win32 verbatim (`\\?\`) path. That prefix is
    // a Win32 parser instruction, not part of the native rename filename, and
    // FileRenameInfoEx can persist bytes beyond the intended component when it
    // is embedded in FILE_RENAME_INFO. Supply an ordinary absolute DOS path.
    let absolute_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io("resolve SPANN publication working directory", error))?
            .join(target)
    };
    let target_wide = absolute_target
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let file_name_bytes = target_wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| corrupt("SPANN publication target length overflow"))?;
    let file_name_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let buffer_len = file_name_offset
        .checked_add(file_name_bytes)
        .ok_or_else(|| corrupt("SPANN rename buffer length overflow"))?;
    let buffer_len_u32 = u32::try_from(buffer_len)
        .map_err(|_| corrupt("SPANN rename buffer exceeds the Windows u32 limit"))?;
    let word_size = std::mem::size_of::<usize>();
    let word_count = buffer_len
        .checked_add(word_size - 1)
        .ok_or_else(|| corrupt("SPANN rename buffer alignment overflow"))?
        / word_size;
    let mut buffer = vec![0_usize; word_count];
    let rename_info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut flags = 0_u32;
    if replace {
        flags |= FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
    }
    // SAFETY: `buffer` is pointer-aligned and large enough for the fixed
    // FILE_RENAME_INFO prefix plus every UTF-16 code unit copied below.
    unsafe {
        std::ptr::write(rename_info, FILE_RENAME_INFO::default());
        (*rename_info).Anonymous.Flags = flags;
        (*rename_info).RootDirectory = std::ptr::null_mut();
        (*rename_info).FileNameLength = u32::try_from(file_name_bytes)
            .map_err(|_| corrupt("SPANN publication target exceeds the Windows u32 limit"))?;
        std::ptr::copy_nonoverlapping(
            target_wide.as_ptr(),
            std::ptr::addr_of_mut!((*rename_info).FileName).cast::<u16>(),
            target_wide.len(),
        );
    }

    let source_file = OpenOptions::new()
        .read(true)
        .access_mode(DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(source)
        .map_err(|error| io("open staged SPANN component for atomic publication", error))?;
    // SAFETY: the source handle is live and DELETE-capable; `buffer` remains
    // live and contains an initialized variable-length FILE_RENAME_INFO.
    if unsafe {
        SetFileInformationByHandle(
            source_file.as_raw_handle(),
            FileRenameInfoEx,
            buffer.as_ptr().cast(),
            buffer_len_u32,
        )
    } == 0
    {
        return Err(io(
            &format!(
                "atomically publish SPANN component {} -> {} with FileRenameInfoEx",
                source.display(),
                target.display()
            ),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn publish_synced_file_atomic_impl(source: &Path, target: &Path, replace: bool) -> Result<()> {
    if !replace && target.exists() {
        return Err(corrupt(format!(
            "immutable SPANN target already exists: {}",
            target.display()
        )));
    }
    fs::rename(source, target).map_err(|error| io("publish SPANN component", error))
}

pub(super) fn limits_hash(limits: &SpannPostingLimits) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(64);
    limits.encode(&mut encoded);
    *blake3::hash(&encoded).as_bytes()
}

fn id_range(ids: impl Iterator<Item = u32>) -> (u32, u32) {
    let mut ids = ids;
    let Some(first) = ids.next() else {
        return (0, 0);
    };
    ids.fold((first, first), |(minimum, maximum), value| {
        (minimum.min(value), maximum.max(value))
    })
}

fn hex_prefix(bytes: &[u8], digits: usize) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .take(digits)
        .map(|nibble| char::from_digit(u32::from(nibble), 16).expect("hex nibble"))
        .collect()
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2B"))
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4B"))
}

fn le_i32(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().expect("4B"))
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8B"))
}
