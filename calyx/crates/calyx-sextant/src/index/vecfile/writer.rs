use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{CalyxError, Result};

use super::format::{VectorFileFormat, VectorFileIdentity, open_verified};
use super::{FbinVectors, I8BinVectors, VEC_HEADER_LEN, VECTOR_FILE_MAX_DIM};
use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_IO, CALYX_INDEX_NONCANONICAL_I8, CALYX_INDEX_NONFINITE,
    sextant_error,
};

const DIGEST_OFFSET: u64 = 28;
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct VecWriterInner {
    file: Option<BufWriter<File>>,
    target_path: PathBuf,
    stage_path: Option<PathBuf>,
    format: VectorFileFormat,
    dim: usize,
    declared_count: u64,
    payload_len: u64,
    written: u64,
    hasher: blake3::Hasher,
    poison: Option<CalyxError>,
}

impl VecWriterInner {
    fn create(
        target_path: &Path,
        format: VectorFileFormat,
        dim: usize,
        count: u64,
    ) -> Result<Self> {
        if dim == 0 || dim > VECTOR_FILE_MAX_DIM {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} dim {dim} is outside the configured range 1..={VECTOR_FILE_MAX_DIM}",
                    format.kind()
                ),
            ));
        }
        let dim_u32 = u32::try_from(dim).map_err(|_| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{} dim {dim} exceeds the u32 header field", format.kind()),
            )
        })?;
        let row_stride = format.row_stride(u64::from(dim_u32)).ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("{} row stride overflows u64 (dim {dim})", format.kind()),
            )
        })?;
        let payload_len = count.checked_mul(row_stride).ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} payload size overflows u64 (count {count} x stride {row_stride})",
                    format.kind()
                ),
            )
        })?;
        let total_len = (VEC_HEADER_LEN as u64)
            .checked_add(payload_len)
            .ok_or_else(|| {
                sextant_error(
                    CALYX_INDEX_CORRUPT,
                    format!("{} total file size overflows u64", format.kind()),
                )
            })?;
        usize::try_from(total_len).map_err(|_| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} total file size {total_len} exceeds this platform's address space",
                    format.kind()
                ),
            )
        })?;

        match fs::symlink_metadata(target_path) {
            Ok(_) => {
                return Err(sextant_error(
                    CALYX_INDEX_CORRUPT,
                    format!(
                        "refusing to overwrite immutable {} target {}",
                        format.kind(),
                        target_path.display()
                    ),
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(sextant_error(
                    CALYX_INDEX_IO,
                    format!(
                        "inspect {} target {} before create: {error}",
                        format.kind(),
                        target_path.display()
                    ),
                ));
            }
        }

        let (stage_path, stage_file) = create_stage(target_path, format.kind())?;
        let mut inner = Self {
            file: Some(BufWriter::new(stage_file)),
            target_path: target_path.to_path_buf(),
            stage_path: Some(stage_path),
            format,
            dim,
            declared_count: count,
            payload_len,
            written: 0,
            hasher: blake3::Hasher::new(),
            poison: None,
        };
        if let Err(error) = inner.write_header(dim_u32) {
            return Err(inner.poison(error));
        }
        Ok(inner)
    }

    fn write_header(&mut self, dim: u32) -> Result<()> {
        let magic = self.format.magic();
        let count = self.declared_count.to_le_bytes();
        let payload_len = self.payload_len.to_le_bytes();
        let file = self.file_mut()?;
        file.write_all(&magic)
            .and_then(|_| file.write_all(&dim.to_le_bytes()))
            .and_then(|_| file.write_all(&count))
            .and_then(|_| file.write_all(&payload_len))
            .and_then(|_| file.write_all(&[0_u8; 32]))
            .map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!(
                        "write {} staging header for {}: {error}",
                        self.format.kind(),
                        self.target_path.display()
                    ),
                )
            })
    }

    fn file_mut(&mut self) -> Result<&mut BufWriter<File>> {
        self.file.as_mut().ok_or_else(|| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} writer for {} has already been finalized",
                    self.format.kind(),
                    self.target_path.display()
                ),
            )
        })
    }

    fn fail(&mut self, code: &'static str, message: String) -> CalyxError {
        self.poison(sextant_error(code, message))
    }

    fn poison(&mut self, error: CalyxError) -> CalyxError {
        if self.poison.is_none() {
            tracing::error!(
                code = error.code,
                target = %self.target_path.display(),
                stage = %self.stage_path.as_deref().unwrap_or(Path::new("<none>")).display(),
                message = %error.message,
                "vector-file writer poisoned; destination remains unpublished"
            );
            self.poison = Some(error.clone());
        }
        self.poison.clone().expect("poison set")
    }

    fn check_writable(&self) -> Result<()> {
        if let Some(error) = &self.poison {
            return Err(error.clone());
        }
        if self.written >= self.declared_count {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} {} received row {} beyond declared count {}; destination remains unpublished",
                    self.format.kind(),
                    self.target_path.display(),
                    self.written,
                    self.declared_count
                ),
            ));
        }
        Ok(())
    }

    fn write_payload(&mut self, bytes: &[u8]) -> Result<()> {
        if let Err(error) = self.check_writable() {
            return Err(self.poison(error));
        }
        let stage = self.stage_path.clone().unwrap_or_default();
        if let Err(error) = self.file_mut()?.write_all(bytes).map_err(|error| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("write row to {}: {error}", stage.display()),
            )
        }) {
            return Err(self.poison(error));
        }
        self.hasher.update(bytes);
        self.written += 1;
        Ok(())
    }

    fn flush_sync(&mut self) -> Result<()> {
        if let Some(error) = &self.poison {
            return Err(error.clone());
        }
        let stage = self.stage_path.clone().unwrap_or_default();
        let result = (|| {
            let file = self.file_mut()?;
            file.flush().map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!("flush {}: {error}", stage.display()),
                )
            })?;
            file.get_ref().sync_all().map_err(|error| {
                sextant_error(CALYX_INDEX_IO, format!("sync {}: {error}", stage.display()))
            })
        })();
        if let Err(error) = result {
            return Err(self.poison(error));
        }
        Ok(())
    }

    fn finalize(mut self) -> Result<VectorFileIdentity> {
        if let Some(error) = &self.poison {
            return Err(error.clone());
        }
        if self.written != self.declared_count {
            let error = self.fail(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} declared {} rows but {} were written; refusing to publish partial target {}",
                    self.format.kind(),
                    self.declared_count,
                    self.written,
                    self.target_path.display()
                ),
            );
            return Err(error);
        }
        let digest = *self.hasher.finalize().as_bytes();
        let stage = self
            .stage_path
            .clone()
            .expect("stage exists before publish");
        let seal_result = (|| {
            let file = self.file_mut()?;
            file.flush().map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!("flush payload {}: {error}", stage.display()),
                )
            })?;
            file.seek(SeekFrom::Start(DIGEST_OFFSET)).map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!("seek digest {}: {error}", stage.display()),
                )
            })?;
            file.write_all(&digest).map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!("seal digest {}: {error}", stage.display()),
                )
            })?;
            file.flush().map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!("flush digest {}: {error}", stage.display()),
                )
            })?;
            file.get_ref().sync_all().map_err(|error| {
                sextant_error(
                    CALYX_INDEX_IO,
                    format!("sync sealed {}: {error}", stage.display()),
                )
            })
        })();
        if let Err(error) = seal_result {
            return Err(self.poison(error));
        }
        drop(self.file.take());

        let production_validation = match self.format {
            VectorFileFormat::ExactF32 => FbinVectors::open(&stage).map(|file| file.identity()),
            VectorFileFormat::SymmetricInt8 => {
                I8BinVectors::open(&stage).map(|file| file.identity())
            }
        };
        let identity = match production_validation {
            Ok(identity) => identity,
            Err(error) => return Err(self.poison(error)),
        };
        let (_, verified) = match open_verified(&stage, self.format) {
            Ok(verified) => verified,
            Err(error) => return Err(self.poison(error)),
        };
        if verified.identity != identity || identity.payload_blake3 != digest {
            let error = self.fail(
                CALYX_INDEX_CORRUPT,
                format!(
                    "{} staging identity changed during production-reader verification for {}",
                    self.format.kind(),
                    self.target_path.display()
                ),
            );
            return Err(error);
        }

        publish_no_replace(&stage, &self.target_path).map_err(|error| self.poison(error))?;
        self.stage_path = None;
        Ok(identity)
    }
}

impl Drop for VecWriterInner {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(stage) = self.stage_path.take()
            && let Err(error) = fs::remove_file(&stage)
            && error.kind() != ErrorKind::NotFound
        {
            tracing::error!(
                code = CALYX_INDEX_IO,
                stage = %stage.display(),
                target = %self.target_path.display(),
                error = %error,
                "failed to remove unpublished vector-file staging artifact"
            );
        }
    }
}

/// Streaming writer for authenticated, bit-preserving `CLXVEC02` files.
pub struct FbinWriter {
    inner: VecWriterInner,
    row_bytes: Vec<u8>,
}

impl FbinWriter {
    pub fn create(path: &Path, dim: usize, count: u64) -> Result<Self> {
        let inner = VecWriterInner::create(path, VectorFileFormat::ExactF32, dim, count)?;
        Ok(Self {
            row_bytes: Vec::with_capacity(dim * 4),
            inner,
        })
    }

    pub fn write_row(&mut self, row: &[f32]) -> Result<()> {
        if row.len() != self.inner.dim {
            let error = self.inner.fail(
                CALYX_INDEX_CORRUPT,
                format!(
                    "vecfile row {} has dim {} != declared {}",
                    self.inner.written,
                    row.len(),
                    self.inner.dim
                ),
            );
            return Err(error);
        }
        self.row_bytes.clear();
        for (col, value) in row.iter().enumerate() {
            if !value.is_finite() {
                let error = self.inner.fail(
                    CALYX_INDEX_NONFINITE,
                    format!(
                        "vecfile row {} col {col} value {value} is not finite; the exact F32 source of truth refuses NaN/Inf",
                        self.inner.written
                    ),
                );
                return Err(error);
            }
            self.row_bytes.extend_from_slice(&value.to_le_bytes());
        }
        let bytes = std::mem::take(&mut self.row_bytes);
        let result = self.inner.write_payload(&bytes);
        self.row_bytes = bytes;
        result
    }

    pub fn flush_sync(&mut self) -> Result<()> {
        self.inner.flush_sync()
    }

    /// Validates through the production reader, atomically publishes without
    /// replacement, and returns the complete authenticated source identity.
    pub fn finalize(self) -> Result<VectorFileIdentity> {
        self.inner.finalize()
    }
}

/// Streaming writer for authenticated, per-row-scale symmetric `CLXI8B02`.
pub struct I8BinWriter {
    inner: VecWriterInner,
    row_bytes: Vec<u8>,
}

impl I8BinWriter {
    pub fn create(path: &Path, dim: usize, count: u64) -> Result<Self> {
        let inner = VecWriterInner::create(path, VectorFileFormat::SymmetricInt8, dim, count)?;
        Ok(Self {
            row_bytes: Vec::with_capacity(dim + 4),
            inner,
        })
    }

    pub fn write_row(&mut self, row: &[f32]) -> Result<()> {
        if row.len() != self.inner.dim {
            let error = self.inner.fail(
                CALYX_INDEX_CORRUPT,
                format!(
                    "i8bin row {} has dim {} != declared {}",
                    self.inner.written,
                    row.len(),
                    self.inner.dim
                ),
            );
            return Err(error);
        }
        let mut max_abs = 0.0_f32;
        for (col, value) in row.iter().enumerate() {
            if !value.is_finite() {
                let error = self.inner.fail(
                    CALYX_INDEX_NONFINITE,
                    format!(
                        "i8bin row {} col {col} value {value} is not finite",
                        self.inner.written
                    ),
                );
                return Err(error);
            }
            max_abs = max_abs.max(value.abs());
        }
        if max_abs == 0.0 {
            let error = self.inner.fail(
                CALYX_INDEX_NONCANONICAL_I8,
                format!(
                    "i8bin row {} is all-zero; a directional int8 row requires a non-zero direction",
                    self.inner.written
                ),
            );
            return Err(error);
        }
        let scale = max_abs / 127.0;
        if !scale.is_finite() || scale <= 0.0 {
            let error = self.inner.fail(
                CALYX_INDEX_NONCANONICAL_I8,
                format!(
                    "i8bin row {} produced non-finite/non-positive scale {scale} from max_abs {max_abs}",
                    self.inner.written
                ),
            );
            return Err(error);
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
            let error = self.inner.fail(
                CALYX_INDEX_NONCANONICAL_I8,
                format!(
                    "i8bin row {} quantized without a ±127 extremum (max |code| {max_abs_code})",
                    self.inner.written
                ),
            );
            return Err(error);
        }
        let bytes = std::mem::take(&mut self.row_bytes);
        let result = self.inner.write_payload(&bytes);
        self.row_bytes = bytes;
        result
    }

    pub fn flush_sync(&mut self) -> Result<()> {
        self.inner.flush_sync()
    }

    pub fn finalize(self) -> Result<VectorFileIdentity> {
        self.inner.finalize()
    }
}

fn create_stage(target: &Path, kind: &str) -> Result<(PathBuf, File)> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = target.file_name().ok_or_else(|| {
        sextant_error(
            CALYX_INDEX_CORRUPT,
            format!("{kind} target {} has no file name", target.display()),
        )
    })?;
    for _ in 0..128 {
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut stage_name = OsString::from(".");
        stage_name.push(file_name);
        stage_name.push(format!(".calyx-stage-{}-{sequence}", std::process::id()));
        let stage = parent.join(stage_name);
        match OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&stage)
        {
            Ok(file) => return Ok((stage, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(sextant_error(
                    CALYX_INDEX_IO,
                    format!("create {kind} staging file {}: {error}", stage.display()),
                ));
            }
        }
    }
    Err(sextant_error(
        CALYX_INDEX_IO,
        format!(
            "could not allocate a unique {kind} staging file beside {} after 128 attempts",
            target.display()
        ),
    ))
}

#[cfg(windows)]
fn publish_no_replace(stage: &Path, target: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let stage_wide = stage
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain alive for the
    // call; MoveFileExW retains neither pointer. Omitting REPLACE_EXISTING makes
    // publication immutable even if another writer wins the race.
    if unsafe {
        MoveFileExW(
            stage_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(sextant_error(
            CALYX_INDEX_IO,
            format!(
                "atomically publish {} to immutable target {}: {}",
                stage.display(),
                target.display(),
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn publish_no_replace(stage: &Path, target: &Path) -> Result<()> {
    fs::hard_link(stage, target).map_err(|error| {
        sextant_error(
            CALYX_INDEX_IO,
            format!(
                "atomically publish {} to immutable target {}: {error}",
                stage.display(),
                target.display()
            ),
        )
    })?;
    fs::remove_file(stage).map_err(|error| {
        sextant_error(
            CALYX_INDEX_IO,
            format!("remove published staging link {}: {error}", stage.display()),
        )
    })
}
