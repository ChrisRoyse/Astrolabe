//! Immutable SSTable writer and mmap reader.

pub mod arrow;
mod bloom;
pub mod level;
mod page;

use crate::mmap_col::MmapColumn;
use bloom::BloomFilter;
use calyx_core::{CalyxError, Result};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC: &[u8; 4] = b"CXS1";
const LEGACY_VERSION: u32 = 1;
const VERSION: u32 = 2;
const HEADER_LEN: usize = 32;
const RECORD_HEADER_LEN: usize = 12;
const INDEX_ENTRY_FIXED_LEN: usize = 12;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Metadata returned after writing an SSTable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SstSummary {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: u64,
    pub index_offset: u64,
    pub bloom_offset: u64,
}

/// A key/value row read from an SSTable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SstEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A key-only SST row view used by latest-read scans that must respect
/// tombstones without cloning record values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SstKeyState {
    pub key: Vec<u8>,
    pub is_tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexEntry {
    key: Vec<u8>,
    offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SstLookupMetadata {
    index: Arc<Vec<IndexEntry>>,
    bloom: BloomFilter,
    file_len: usize,
    header_bytes: [u8; HEADER_LEN],
    #[cfg(windows)]
    file_generation: crate::mmap_col::MmapFileGeneration,
}

impl SstLookupMetadata {
    pub(crate) fn key_range(&self) -> Option<(&[u8], &[u8])> {
        Some((
            self.index.first()?.key.as_slice(),
            self.index.last()?.key.as_slice(),
        ))
    }
}

/// Memory-mapped SSTable reader.
#[derive(Debug)]
pub struct SstReader {
    column: MmapColumn,
    lookup: Arc<SstLookupMetadata>,
}

/// Byte range proven by a complete record decode and CRC check against one
/// retained immutable [`SstReader`] mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedSstValueRange {
    start: usize,
    end: usize,
}

impl ValidatedSstValueRange {
    pub(crate) const fn len(self) -> usize {
        self.end - self.start
    }
}

/// Writes a sorted immutable SSTable. The input iterator must already be ordered.
pub fn write_sst<'a>(
    path: impl AsRef<Path>,
    entries: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<SstSummary> {
    let path = path.as_ref();
    let entries: Vec<_> = entries
        .into_iter()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    ensure_sorted(&entries)?;

    let mut bytes = vec![0u8; HEADER_LEN];
    let mut index = Vec::with_capacity(entries.len());
    for (key, value) in &entries {
        let offset = bytes.len() as u64;
        write_record(&mut bytes, key, value)?;
        index.push(IndexEntry {
            key: key.clone(),
            offset,
        });
    }

    let index_offset = bytes.len() as u64;
    write_index(&mut bytes, &index);
    let bloom_offset = bytes.len() as u64;
    BloomFilter::from_keys(entries.iter().map(|(key, _)| key.as_slice())).encode(&mut bytes);
    let body_crc = section_crc(&bytes[HEADER_LEN..]);
    write_header(
        &mut bytes,
        entries.len() as u32,
        index_offset,
        bloom_offset,
        body_crc,
    );

    let mut tmp = SstTemp::new(path)?;
    {
        let mut file = File::create(tmp.path()).map_err(|error| {
            storage_error(&format!("create SST temp {}", tmp.path().display()), error)
        })?;
        file.write_all(&bytes).map_err(|error| {
            storage_error(&format!("write SST {}", tmp.path().display()), error)
        })?;
        file.sync_all().map_err(|error| {
            storage_error(&format!("fsync SST {}", tmp.path().display()), error)
        })?;
    }
    fs::rename(tmp.path(), path).map_err(|error| {
        storage_error(
            &format!("rename SST {} to {}", tmp.path().display(), path.display()),
            error,
        )
    })?;
    tmp.commit();
    sync_parent(path)?;

    Ok(SstSummary {
        path: path.to_path_buf(),
        entries: entries.len(),
        bytes: bytes.len() as u64,
        index_offset,
        bloom_offset,
    })
}

struct SstTemp {
    path: PathBuf,
    committed: bool,
}

impl SstTemp {
    fn new(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| CalyxError::disk_pressure("SST path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| CalyxError::disk_pressure("SST path has no file name"))?;
        let mut temp_name = OsString::from(name);
        temp_name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        Ok(Self {
            path: parent.join(temp_name),
            committed: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for SstTemp {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl SstReader {
    /// Opens an SSTable through mmap.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let column = MmapColumn::open(path.as_ref())?;
        let bytes = column.as_bytes();
        let header = read_header(bytes)?;
        let index = Arc::new(read_index(
            bytes,
            header.entries,
            header.index_offset,
            header.bloom_offset,
        )?);
        let bloom_bytes = bytes
            .get(header.bloom_offset as usize..)
            .ok_or_else(|| CalyxError::aster_corrupt_shard("SST bloom offset out of bounds"))?;
        let bloom = BloomFilter::decode(bloom_bytes)
            .ok_or_else(|| CalyxError::aster_corrupt_shard("invalid SST bloom filter"))?;
        let header_bytes = bytes[0..HEADER_LEN]
            .try_into()
            .expect("read_header established the exact SST header length");
        let lookup = Arc::new(SstLookupMetadata {
            index,
            bloom,
            file_len: bytes.len(),
            header_bytes,
            #[cfg(windows)]
            file_generation: column.file_generation(),
        });
        Ok(Self { column, lookup })
    }

    /// Opens an immutable SST generation using metadata produced by a prior
    /// full body validation. Exact generation, length, and header equality are
    /// checked before the shared index is trusted; individual record CRCs are
    /// still checked when values are read.
    pub(crate) fn open_with_lookup(
        path: impl AsRef<Path>,
        lookup: Arc<SstLookupMetadata>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let column = MmapColumn::open(path)?;
        let bytes = column.as_bytes();
        if bytes.len() != lookup.file_len {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "SST generation length changed for {}: validated {}, reopened {}",
                path.display(),
                lookup.file_len,
                bytes.len()
            )));
        }
        let reopened_header = bytes
            .get(0..HEADER_LEN)
            .ok_or_else(|| CalyxError::aster_corrupt_shard("SST header missing on reopen"))?;
        if reopened_header != lookup.header_bytes {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "SST generation header changed after validation for {}",
                path.display()
            )));
        }
        #[cfg(windows)]
        if column.file_generation() != lookup.file_generation {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "SST file identity changed after validation for {}: validated {:?}, reopened {:?}",
                path.display(),
                lookup.file_generation,
                column.file_generation()
            )));
        }
        Ok(Self { column, lookup })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.get_ref(key)?.map(<[u8]>::to_vec))
    }

    /// Reads one value as a borrow of this reader's immutable mapped SST.
    ///
    /// Ordered full-state verification uses this seam to hash and decode a row
    /// while the SST is open, without allocating a second value buffer per key.
    pub(crate) fn get_ref(&self, key: &[u8]) -> Result<Option<&[u8]>> {
        Ok(self
            .validated_value_range(key)?
            .map(|range| self.value_at_validated_range(range)))
    }

    /// Validates one indexed record completely and returns an immutable byte
    /// range that can be replayed after the whole multi-get read set has been
    /// validated. The range is meaningful only for this retained reader.
    pub(crate) fn validated_value_range(
        &self,
        key: &[u8],
    ) -> Result<Option<ValidatedSstValueRange>> {
        if !self.lookup.bloom.may_contain(key) {
            return Ok(None);
        }
        let Ok(position) = self
            .lookup
            .index
            .binary_search_by(|entry| entry.key.as_slice().cmp(key))
        else {
            return Ok(None);
        };
        let record = read_record_ref(self.column.as_bytes(), self.lookup.index[position].offset)?;
        let base = self.column.as_bytes().as_ptr() as usize;
        let start = (record.value.as_ptr() as usize)
            .checked_sub(base)
            .ok_or_else(|| CalyxError::aster_corrupt_shard("SST value precedes mapped bytes"))?;
        let end = start
            .checked_add(record.value.len())
            .ok_or_else(|| CalyxError::aster_corrupt_shard("SST validated value range overflow"))?;
        if end > self.column.as_bytes().len() {
            return Err(CalyxError::aster_corrupt_shard(
                "SST validated value range exceeds mapped bytes",
            ));
        }
        Ok(Some(ValidatedSstValueRange { start, end }))
    }

    /// Replays bytes from a range produced by [`Self::validated_value_range`].
    /// The reader's mmap is immutable for its lifetime, so a previously valid
    /// range cannot become invalid between preflight and callback publication.
    pub(crate) fn value_at_validated_range(&self, range: ValidatedSstValueRange) -> &[u8] {
        self.column
            .as_bytes()
            .get(range.start..range.end)
            .expect("validated SST value range remains valid for retained immutable mmap")
    }

    pub fn range(&self, start: &[u8], end: &[u8]) -> Result<Vec<SstEntry>> {
        let start_at = self
            .lookup
            .index
            .partition_point(|entry| entry.key.as_slice() < start);
        let mut rows = Vec::new();
        for entry in &self.lookup.index[start_at..] {
            if entry.key.as_slice() >= end {
                break;
            }
            rows.push(read_record(self.column.as_bytes(), entry.offset)?);
        }
        Ok(rows)
    }

    pub fn range_key_states(&self, start: &[u8], end: &[u8]) -> Result<Vec<SstKeyState>> {
        self.range_key_states_until(start, Some(end))
    }

    pub fn range_key_states_until(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<SstKeyState>> {
        let start_at = self
            .lookup
            .index
            .partition_point(|entry| entry.key.as_slice() < start);
        let mut rows = Vec::new();
        for entry in &self.lookup.index[start_at..] {
            if end.is_some_and(|end| entry.key.as_slice() >= end) {
                break;
            }
            let record = read_record_ref(self.column.as_bytes(), entry.offset)?;
            rows.push(SstKeyState {
                key: record.key.to_vec(),
                is_tombstone: crate::mvcc::is_tombstone_value(record.value),
            });
        }
        Ok(rows)
    }

    pub fn iter(&self) -> Result<Vec<SstEntry>> {
        self.lookup
            .index
            .iter()
            .map(|entry| read_record(self.column.as_bytes(), entry.offset))
            .collect()
    }

    /// Visits every row through the retained immutable mmap without cloning
    /// key/value bodies. Physical generation readback uses this to compare an
    /// SST to its decoded WAL batch with memory bounded by that WAL batch,
    /// rather than allocating a second copy of the checkpoint.
    pub(crate) fn visit_entries(
        &self,
        mut visit: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<usize> {
        for entry in self.lookup.index.iter() {
            let record = read_record_ref(self.column.as_bytes(), entry.offset)?;
            visit(record.key, record.value)?;
        }
        Ok(self.lookup.index.len())
    }

    pub fn bloom_may_contain(&self, key: &[u8]) -> bool {
        self.lookup.bloom.may_contain(key)
    }

    /// First and last key stored in this SST, or `None` for an empty file.
    pub fn key_range(&self) -> Option<(&[u8], &[u8])> {
        Some((
            self.lookup.index.first()?.key.as_slice(),
            self.lookup.index.last()?.key.as_slice(),
        ))
    }

    pub(crate) fn lookup_metadata(&self) -> Arc<SstLookupMetadata> {
        Arc::clone(&self.lookup)
    }
}

struct SstRecordRef<'a> {
    key: &'a [u8],
    value: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct Header {
    entries: u32,
    index_offset: u64,
    bloom_offset: u64,
}

fn ensure_sorted(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(CalyxError::aster_corrupt_shard(
            "SST entries must be strictly sorted by key",
        ));
    }
    Ok(())
}

fn write_record(out: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<()> {
    let key_len = u32::try_from(key.len())
        .map_err(|_| CalyxError::disk_pressure("SST key length exceeds u32"))?;
    let value_len = u32::try_from(value.len())
        .map_err(|_| CalyxError::disk_pressure("SST value length exceeds u32"))?;
    let crc = record_crc(key, value);
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(&value_len.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    Ok(())
}

fn read_record(bytes: &[u8], offset: u64) -> Result<SstEntry> {
    let record = read_record_ref(bytes, offset)?;
    Ok(SstEntry {
        key: record.key.to_vec(),
        value: record.value.to_vec(),
    })
}

fn read_record_ref(bytes: &[u8], offset: u64) -> Result<SstRecordRef<'_>> {
    let offset = offset as usize;
    let header = bytes
        .get(offset..offset + RECORD_HEADER_LEN)
        .ok_or_else(|| CalyxError::aster_corrupt_shard("SST record header out of bounds"))?;
    let key_len = u32::from_le_bytes(header[0..4].try_into().expect("key len")) as usize;
    let value_len = u32::from_le_bytes(header[4..8].try_into().expect("value len")) as usize;
    let expected_crc = u32::from_le_bytes(header[8..12].try_into().expect("record crc"));
    let key_start = offset + RECORD_HEADER_LEN;
    let value_start = key_start + key_len;
    let value_end = value_start + value_len;
    let key = bytes
        .get(key_start..value_start)
        .ok_or_else(|| CalyxError::aster_corrupt_shard("SST key out of bounds"))?;
    let value = bytes
        .get(value_start..value_end)
        .ok_or_else(|| CalyxError::aster_corrupt_shard("SST value out of bounds"))?;
    let actual_crc = record_crc(key, value);
    if actual_crc != expected_crc {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "SST record crc mismatch at {offset}: expected {expected_crc:08x}, got {actual_crc:08x}"
        )));
    }
    Ok(SstRecordRef { key, value })
}

fn write_index(out: &mut Vec<u8>, index: &[IndexEntry]) {
    for entry in index {
        out.extend_from_slice(&(entry.key.len() as u32).to_le_bytes());
        out.extend_from_slice(&entry.offset.to_le_bytes());
        out.extend_from_slice(&entry.key);
    }
}

fn read_index(
    bytes: &[u8],
    entries: u32,
    index_offset: u64,
    bloom_offset: u64,
) -> Result<Vec<IndexEntry>> {
    let mut offset = index_offset as usize;
    let end = bloom_offset as usize;
    let mut index = Vec::with_capacity(entries as usize);
    for _ in 0..entries {
        let fixed = bytes
            .get(offset..offset + INDEX_ENTRY_FIXED_LEN)
            .ok_or_else(|| CalyxError::aster_corrupt_shard("SST index entry out of bounds"))?;
        let key_len = u32::from_le_bytes(fixed[0..4].try_into().expect("index key len")) as usize;
        let record_offset = u64::from_le_bytes(fixed[4..12].try_into().expect("record offset"));
        offset += INDEX_ENTRY_FIXED_LEN;
        let key = bytes
            .get(offset..offset + key_len)
            .ok_or_else(|| CalyxError::aster_corrupt_shard("SST index key out of bounds"))?
            .to_vec();
        offset += key_len;
        index.push(IndexEntry {
            key,
            offset: record_offset,
        });
    }
    if offset != end {
        return Err(CalyxError::aster_corrupt_shard("SST index length mismatch"));
    }
    if index.windows(2).any(|pair| pair[0].key >= pair[1].key) {
        return Err(CalyxError::aster_corrupt_shard(
            "SST index keys must be strictly sorted",
        ));
    }
    Ok(index)
}

fn write_header(
    bytes: &mut [u8],
    entries: u32,
    index_offset: u64,
    bloom_offset: u64,
    body_crc: u32,
) {
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
    bytes[8..12].copy_from_slice(&entries.to_le_bytes());
    bytes[12..20].copy_from_slice(&index_offset.to_le_bytes());
    bytes[20..28].copy_from_slice(&bloom_offset.to_le_bytes());
    bytes[28..32].copy_from_slice(&body_crc.to_le_bytes());
}

fn read_header(bytes: &[u8]) -> Result<Header> {
    let header = bytes
        .get(0..HEADER_LEN)
        .ok_or_else(|| CalyxError::aster_corrupt_shard("SST header missing"))?;
    if &header[0..4] != MAGIC {
        return Err(CalyxError::aster_corrupt_shard("SST magic mismatch"));
    }
    let version = u32::from_le_bytes(header[4..8].try_into().expect("version"));
    if version != VERSION && version != LEGACY_VERSION {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "unsupported SST version {version}"
        )));
    }
    let entries = u32::from_le_bytes(header[8..12].try_into().expect("entries"));
    let index_offset = u64::from_le_bytes(header[12..20].try_into().expect("index offset"));
    let bloom_offset = u64::from_le_bytes(header[20..28].try_into().expect("bloom offset"));
    let len = bytes.len() as u64;
    if index_offset < HEADER_LEN as u64
        || index_offset > len
        || bloom_offset < index_offset
        || bloom_offset > len
    {
        return Err(CalyxError::aster_corrupt_shard(
            "SST header offsets out of bounds",
        ));
    }
    if version >= VERSION {
        let expected_crc = u32::from_le_bytes(header[28..32].try_into().expect("body crc"));
        let actual_crc = section_crc(
            bytes
                .get(HEADER_LEN..)
                .ok_or_else(|| CalyxError::aster_corrupt_shard("SST body missing"))?,
        );
        if actual_crc != expected_crc {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "SST body crc mismatch: expected {expected_crc:08x}, got {actual_crc:08x}"
            )));
        }
    }
    Ok(Header {
        entries,
        index_offset,
        bloom_offset,
    })
}

fn section_crc(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn record_crc(key: &[u8], value: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(key);
    hasher.update(value);
    hasher.finalize()
}

fn sync_parent(path: &Path) -> Result<()> {
    crate::fsync::sync_parent(path, "SST")
}

fn storage_error(context: &str, error: io::Error) -> CalyxError {
    CalyxError::disk_pressure(format!("{context}: {error}"))
}
