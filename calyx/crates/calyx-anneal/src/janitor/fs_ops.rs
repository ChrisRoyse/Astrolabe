use super::{CALYX_IO_ERROR, CALYX_JANITOR_ROTATION_ERROR, ROTATION_STREAM_CHUNK_BYTES};
use calyx_core::{CalyxError, Result, Ts};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IO_REMEDIATION: &str =
    "inspect janitor filesystem source of truth; preserve files until cleanup is safe";
const ROTATION_REMEDIATION: &str = "leave the source log in place; inspect the destination path and free disk space, \
     then let the next janitor tick re-attempt the verified rotation";

/// Monotonic sequence disambiguating rotation temp names within one process.
static ROTATION_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(super) enum CleanupKind {
    Log,
    Temp,
}

pub(super) fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir)
            .map_err(|error| io_error(format!("read {}: {error}", dir.display())))?
        {
            let entry = entry
                .map_err(|error| io_error(format!("read {} entry: {error}", dir.display())))?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|error| io_error(format!("stat {}: {error}", path.display())))?;
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
}

pub(super) fn immediate_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for entry in
        fs::read_dir(root).map_err(|error| io_error(format!("read {}: {error}", root.display())))?
    {
        let path = entry
            .map_err(|error| io_error(format!("read {} entry: {error}", root.display())))?
            .path();
        if path.is_dir() {
            dirs.push(path);
        }
    }
    Ok(dirs)
}

pub(super) fn temp_dirs(home: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for candidate in [home.join(".tmp"), home.join("data").join(".tmp")] {
        if candidate.is_dir() {
            dirs.push(candidate);
        }
    }
    for dir in immediate_dirs(home)? {
        let tmp = dir.join(".tmp");
        if tmp.is_dir() {
            dirs.push(tmp);
        }
        for child in immediate_dirs(&dir).unwrap_or_default() {
            let nested = child.join(".tmp");
            if nested.is_dir() {
                dirs.push(nested);
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    Ok(dirs)
}

pub(super) fn ensure_inside_dataset(dataset_root: &Path, path: &Path) -> Result<()> {
    let root = dataset_root
        .canonicalize()
        .map_err(|error| io_error(format!("canonicalize {}: {error}", dataset_root.display())))?;
    let actual = path
        .canonicalize()
        .map_err(|error| io_error(format!("canonicalize {}: {error}", path.display())))?;
    if !actual.starts_with(&root) {
        return Err(io_error(format!(
            "temp file {} escapes dataset {}",
            path.display(),
            dataset_root.display()
        )));
    }
    Ok(())
}

pub(super) fn dir_size(path: &Path) -> Result<u64> {
    collect_files(path)?
        .into_iter()
        .map(|file| file_len(&file))
        .sum()
}

pub(super) fn file_len(path: &Path) -> Result<u64> {
    fs::metadata(path)
        .map(|meta| meta.len())
        .map_err(|error| io_error(format!("stat {}: {error}", path.display())))
}

pub(super) fn age_ms(path: &Path, now: Ts) -> Result<u64> {
    Ok(now.saturating_sub(modified_ms(path)?))
}

pub(super) fn modified_ms(path: &Path) -> Result<u64> {
    let modified = fs::metadata(path)
        .map_err(|error| io_error(format!("stat {}: {error}", path.display())))?
        .modified()
        .map_err(|error| io_error(format!("modified {}: {error}", path.display())))?;
    system_time_ms(modified)
}

fn system_time_ms(time: SystemTime) -> Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map_err(|error| io_error(format!("mtime before epoch: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| io_error("mtime exceeds u64 milliseconds"))
}

pub(super) fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

pub(super) fn is_zst(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "zst")
}

pub(super) fn zst_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io_error(format!(
                "log path has no UTF-8 file name: {}",
                path.display()
            ))
        })?;
    Ok(path.with_file_name(format!("{name}.zst")))
}

pub(super) fn starts_with_canonical(child: &Path, parent: &Path) -> bool {
    parent
        .canonicalize()
        .map(|parent| child.starts_with(parent))
        .unwrap_or(false)
}

pub(super) fn hash_path(path: &Path) -> String {
    blake3::hash(path.to_string_lossy().as_bytes())
        .to_hex()
        .to_string()
}

pub(super) fn io_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_IO_ERROR,
        message: message.into(),
        remediation: IO_REMEDIATION,
    }
}

/// Structured, fail-closed error for a rotation that refuses to publish or delete.
/// `stage` names the rotation phase (`prepared`, `compressed`, `verify`, `published`).
pub(super) fn rotation_error(stage: &str, message: impl AsRef<str>) -> CalyxError {
    CalyxError {
        code: CALYX_JANITOR_ROTATION_ERROR,
        message: format!("[{stage}] {}", message.as_ref()),
        remediation: ROTATION_REMEDIATION,
    }
}

/// Lower-hex encoding of a digest for structured diagnostics.
pub(super) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// True when `path` is an in-flight or abandoned rotation temp file (`*.zst.tmp.*`).
/// Such files are never treated as rotatable source logs.
pub(super) fn is_rotation_temp(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".zst.tmp."))
}

/// Independently computed length and BLAKE3 digest of a byte stream.
#[derive(Clone, Copy)]
pub(super) struct StreamDigest {
    pub len: u64,
    pub hash: [u8; 32],
}

/// Identity of the source captured during compression plus the compressed size.
#[derive(Clone, Copy)]
pub(super) struct RotationStats {
    pub src_len: u64,
    pub src_hash: [u8; 32],
    pub compressed_len: u64,
}

/// A `Read` adapter that digests bytes as they flow through and enforces a
/// wall-clock deadline so a rotation cannot exceed its declared time budget.
struct DigestReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    len: u64,
    deadline: Option<Instant>,
}

impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline
            && Instant::now() >= deadline
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "rotation time budget exceeded",
            ));
        }
        let read = self.inner.read(buf)?;
        if read > 0 {
            self.hasher.update(&buf[..read]);
            self.len += read as u64;
        }
        Ok(read)
    }
}

/// A `Write` sink that digests decompressed bytes without ever materializing them.
struct DigestSink {
    hasher: blake3::Hasher,
    len: u64,
}

impl Write for DigestSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.len += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Stream a plaintext file through BLAKE3, returning its length and digest without
/// holding the whole file in memory.
pub(super) fn source_digest(path: &Path) -> Result<StreamDigest> {
    let file =
        File::open(path).map_err(|error| io_error(format!("open {}: {error}", path.display())))?;
    let mut reader = BufReader::with_capacity(ROTATION_STREAM_CHUNK_BYTES, file);
    let mut hasher = blake3::Hasher::new();
    let mut len = 0u64;
    let mut buf = vec![0u8; ROTATION_STREAM_CHUNK_BYTES];
    loop {
        let read = reader
            .read(&mut buf)
            .map_err(|error| io_error(format!("read {}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        len += read as u64;
    }
    Ok(StreamDigest {
        len,
        hash: *hasher.finalize().as_bytes(),
    })
}

/// Independently reopen and stream-decompress a zstd artifact, returning the exact
/// decoded length and BLAKE3 digest. Never materializes the decoded output.
pub(super) fn decode_digest(path: &Path) -> Result<StreamDigest> {
    let file = File::open(path)
        .map_err(|error| rotation_error("verify", format!("open {}: {error}", path.display())))?;
    let reader = BufReader::with_capacity(ROTATION_STREAM_CHUNK_BYTES, file);
    let mut sink = DigestSink {
        hasher: blake3::Hasher::new(),
        len: 0,
    };
    zstd::stream::copy_decode(reader, &mut sink).map_err(|error| {
        rotation_error("verify", format!("decompress {}: {error}", path.display()))
    })?;
    Ok(StreamDigest {
        len: sink.len,
        hash: *sink.hasher.finalize().as_bytes(),
    })
}

/// Compress `source` into a freshly created same-directory temp file, fsync it,
/// independently decode-verify it, publish it to `final_path` with create-only
/// rename semantics, then independently decode-verify the published bytes. Returns
/// the captured source identity. On ANY failure the temp file is removed, a
/// half-published final is removed, and the source is left completely untouched.
pub(super) fn verified_publish(
    source: &Path,
    final_path: &Path,
    time_budget: Duration,
) -> Result<RotationStats> {
    let temp = unique_temp_path(final_path)?;
    let temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            rotation_error(
                "prepared",
                format!("create temp {}: {error}", temp.display()),
            )
        })?;

    let stats = match compress_into(source, temp_file, time_budget) {
        Ok(stats) => stats,
        Err(error) => {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
    };

    // Independent decode of the temp file BEFORE it is ever published.
    if let Err(error) = verify_decode(&temp, &stats, source) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    // Publish with create-only rename: the caller has proven the destination is
    // absent, and on Windows `rename` refuses to clobber an existing target.
    if let Err(error) = fs::rename(&temp, final_path) {
        let _ = fs::remove_file(&temp);
        return Err(rotation_error(
            "published",
            format!(
                "publish {} -> {}: {error}",
                temp.display(),
                final_path.display()
            ),
        ));
    }
    // Best-effort directory fsync so the rename itself is durable.
    if let Some(parent) = final_path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    // Independent decode of the FINAL published bytes — the exact artifact that
    // will remain after the source is deleted.
    if let Err(error) = verify_decode(final_path, &stats, source) {
        let _ = fs::remove_file(final_path);
        return Err(error);
    }

    Ok(stats)
}

fn compress_into(source: &Path, temp_file: File, time_budget: Duration) -> Result<RotationStats> {
    let plain = File::open(source).map_err(|error| {
        rotation_error("compressed", format!("open {}: {error}", source.display()))
    })?;
    // A zero budget yields an immediate deadline (rotation refuses); a huge budget
    // that overflows `Instant` yields no deadline.
    let deadline = Instant::now().checked_add(time_budget);
    let mut reader = DigestReader {
        inner: BufReader::with_capacity(ROTATION_STREAM_CHUNK_BYTES, plain),
        hasher: blake3::Hasher::new(),
        len: 0,
        deadline,
    };
    let mut encoder = zstd::stream::Encoder::new(temp_file, 0)
        .map_err(|error| rotation_error("compressed", format!("init zstd encoder: {error}")))?;
    io::copy(&mut reader, &mut encoder).map_err(|error| {
        rotation_error(
            "compressed",
            format!("compress {}: {error}", source.display()),
        )
    })?;
    let temp_file = encoder
        .finish()
        .map_err(|error| rotation_error("compressed", format!("finalize zstd frame: {error}")))?;
    temp_file
        .sync_all()
        .map_err(|error| rotation_error("compressed", format!("fsync compressed temp: {error}")))?;
    let compressed_len = temp_file.metadata().map(|meta| meta.len()).unwrap_or(0);
    Ok(RotationStats {
        src_len: reader.len,
        src_hash: *reader.hasher.finalize().as_bytes(),
        compressed_len,
    })
}

fn verify_decode(compressed: &Path, stats: &RotationStats, source: &Path) -> Result<()> {
    let digest = decode_digest(compressed)?;
    if digest.len != stats.src_len || digest.hash != stats.src_hash {
        return Err(rotation_error(
            "verify",
            format!(
                "compressed {} does not decode to source {}: expected len {} hash {}, decoded len {} hash {}",
                compressed.display(),
                source.display(),
                stats.src_len,
                hex(&stats.src_hash),
                digest.len,
                hex(&digest.hash)
            ),
        ));
    }
    Ok(())
}

fn unique_temp_path(final_path: &Path) -> Result<PathBuf> {
    let name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            rotation_error(
                "prepared",
                format!(
                    "destination has no UTF-8 file name: {}",
                    final_path.display()
                ),
            )
        })?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let seq = ROTATION_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(final_path.with_file_name(format!("{name}.tmp.{pid}.{nanos}.{seq}")))
}
