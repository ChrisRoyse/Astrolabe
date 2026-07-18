//! Bounded, fail-closed exporter for authenticated static-lookup matrices.
//!
//! Rows are accepted one at a time in tokenizer-id order. The exporter keeps
//! only one encoded row plus the INT8 scale table in memory; it never
//! materializes the source matrix. A complete artifact is sealed and reopened
//! through the production mmap reader before an immutable destination name is
//! published.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{CalyxError, Result};
use half::f16;

use super::{
    DTYPE_F16, DTYPE_F32, DTYPE_I8, HEADER_LEN, MAGIC, StaticLookupDType, StaticLookupMatrix,
    read_tokenizer,
};

mod publish;

use publish::publish_immutable;

const DIGEST_OFFSET: u64 = 32;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
static TEMP_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// Physical identity returned after a CXLKUP2 artifact has been sealed,
/// production-reader verified, and durably published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticLookupArtifact {
    /// Immutable published artifact path.
    pub path: PathBuf,
    /// Vocabulary-bound row count.
    pub rows: u32,
    /// Values per row.
    pub dim: u32,
    /// Persisted value representation.
    pub dtype: StaticLookupDType,
    /// Exact bytes after the 64-byte header.
    pub body_len: u64,
    /// Header plus body bytes on disk.
    pub physical_bytes: u64,
    /// BLAKE3 seal over the exact body bytes.
    pub body_blake3: [u8; 32],
}

/// Streaming writer for the versioned CXLKUP2 static-lookup format.
///
/// `create` derives the exact row count from the real tokenizer. Callers then
/// provide one finite F32 source row per tokenizer id, in ascending id order.
/// INT8 uses a symmetric per-row scale and canonical `[-127, 127]` codes; F16
/// and F32 preserve their declared physical dtype. `finalize` refuses partial
/// files, seals the body digest, reopens the staged bytes with the production
/// mmap reader, and publishes the immutable destination without overwriting an
/// existing artifact.
pub struct StaticLookupWriter {
    file: Option<File>,
    target: PathBuf,
    temporary: PathBuf,
    rows: u32,
    dim: u32,
    dtype: StaticLookupDType,
    body_len: u64,
    written: u32,
    poisoned: bool,
    scales: Vec<u8>,
    row_bytes: Vec<u8>,
}

impl StaticLookupWriter {
    /// Creates a staged exporter bound to `tokenizer` and a new destination.
    pub fn create(
        target: impl AsRef<Path>,
        tokenizer: impl AsRef<Path>,
        dim: u32,
        dtype: StaticLookupDType,
    ) -> Result<Self> {
        let target = target.as_ref();
        let tokenizer_path = tokenizer.as_ref();
        if dim == 0 {
            return Err(export_invalid("static lookup export dim must be non-zero"));
        }
        if target.exists() {
            return Err(artifact_exists(target));
        }
        if target == tokenizer_path {
            return Err(export_invalid(format!(
                "static lookup output {} is also the tokenizer; frozen source artifacts must \
                 remain distinct",
                target.display()
            )));
        }

        let tokenizer = read_tokenizer(tokenizer_path)?;
        let rows = u32::try_from(tokenizer.get_vocab_size(true)).map_err(|_| {
            export_invalid(format!(
                "tokenizer {} vocabulary exceeds the CXLKUP2 u32 row field",
                tokenizer_path.display()
            ))
        })?;
        if rows == 0 {
            return Err(export_invalid(format!(
                "tokenizer {} has an empty vocabulary",
                tokenizer_path.display()
            )));
        }

        let cells = u64::from(rows)
            .checked_mul(u64::from(dim))
            .ok_or_else(|| export_invalid("static lookup cell count overflows u64"))?;
        let scale_table_len = match dtype {
            StaticLookupDType::Int8 => u64::from(rows)
                .checked_mul(4)
                .ok_or_else(|| export_invalid("static lookup scale table overflows u64"))?,
            StaticLookupDType::F16 | StaticLookupDType::F32 => 0,
        };
        let body_len = cells
            .checked_mul(dtype.width() as u64)
            .and_then(|bytes| bytes.checked_add(scale_table_len))
            .ok_or_else(|| export_invalid("static lookup body size overflows u64"))?;
        let physical_bytes = (HEADER_LEN as u64)
            .checked_add(body_len)
            .ok_or_else(|| export_invalid("static lookup artifact size overflows u64"))?;
        usize::try_from(physical_bytes).map_err(|_| {
            export_invalid(format!(
                "static lookup artifact {physical_bytes} B exceeds this process address space"
            ))
        })?;

        let parent = target.parent().filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)
                .map_err(|error| export_io("create output directory", target, error))?;
        }
        let temporary = temporary_path(target)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| export_io("create staging artifact", &temporary, error))?;

        let scale_capacity = usize::try_from(scale_table_len)
            .map_err(|_| export_invalid("static lookup scale table exceeds usize"))?;
        let row_capacity = (dim as usize)
            .checked_mul(dtype.width())
            .ok_or_else(|| export_invalid("static lookup row buffer size overflows usize"))?;
        let mut scales = Vec::new();
        scales.try_reserve_exact(scale_capacity).map_err(|error| {
            export_invalid(format!(
                "reserve {scale_capacity} B static lookup scale table failed: {error}"
            ))
        })?;
        let mut row_bytes = Vec::new();
        row_bytes.try_reserve_exact(row_capacity).map_err(|error| {
            export_invalid(format!(
                "reserve {row_capacity} B static lookup row buffer failed: {error}"
            ))
        })?;

        let mut writer = Self {
            file: Some(file),
            target: target.to_path_buf(),
            temporary,
            rows,
            dim,
            dtype,
            body_len,
            written: 0,
            poisoned: false,
            scales,
            row_bytes,
        };
        writer.initialize(physical_bytes, scale_table_len)?;
        Ok(writer)
    }

    /// Returns the tokenizer-derived row count.
    pub const fn rows(&self) -> u32 {
        self.rows
    }

    /// Returns the declared row dimension.
    pub const fn dim(&self) -> u32 {
        self.dim
    }

    /// Returns the declared persisted representation.
    pub const fn dtype(&self) -> StaticLookupDType {
        self.dtype
    }

    /// Returns the number of source rows accepted so far.
    pub const fn written_rows(&self) -> u32 {
        self.written
    }

    /// Encodes the next tokenizer-id-ordered finite F32 source row.
    pub fn write_row(&mut self, row: &[f32]) -> Result<()> {
        if self.poisoned {
            return Err(export_invalid(
                "static lookup exporter is poisoned after a partial I/O failure; discard it and export to a new path",
            ));
        }
        if self.written >= self.rows {
            return Err(export_invalid(format!(
                "static lookup export already received its declared {} tokenizer rows; row {} \
                 would be surplus",
                self.rows, self.written
            )));
        }
        if row.len() != self.dim as usize {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "static lookup export row {} has dim {} != declared {}",
                self.written,
                row.len(),
                self.dim
            )));
        }

        self.row_bytes.clear();
        match self.dtype {
            StaticLookupDType::Int8 => self.encode_int8(row)?,
            StaticLookupDType::F16 => self.encode_f16(row)?,
            StaticLookupDType::F32 => self.encode_f32(row)?,
        }
        let row_bytes = std::mem::take(&mut self.row_bytes);
        let write_result = self.file_mut()?.write_all(&row_bytes);
        self.row_bytes = row_bytes;
        if let Err(error) = write_result {
            self.poisoned = true;
            return Err(export_io("write matrix row", &self.temporary, error));
        }
        self.written += 1;
        Ok(())
    }

    /// Seals, independently reopens, and immutably publishes the artifact.
    pub fn finalize(mut self) -> Result<StaticLookupArtifact> {
        if self.poisoned {
            return Err(export_invalid(
                "static lookup exporter is poisoned after a partial I/O failure; refusing to seal ambiguous bytes",
            ));
        }
        if self.written != self.rows {
            return Err(export_invalid(format!(
                "static lookup export declared {} tokenizer rows but received {}; refusing to \
                 publish a partial artifact",
                self.rows, self.written
            )));
        }
        if self.dtype == StaticLookupDType::Int8 {
            let expected = self.rows as usize * 4;
            if self.scales.len() != expected {
                return Err(export_invalid(format!(
                    "static lookup scale table is {} B, expected {expected} B",
                    self.scales.len()
                )));
            }
            let scales = std::mem::take(&mut self.scales);
            let file = self.file_mut()?;
            file.seek(SeekFrom::Start(HEADER_LEN as u64))
                .and_then(|_| file.write_all(&scales))
                .map_err(|error| export_io("write scale table", &self.temporary, error))?;
        }

        let body_len = self.body_len;
        let temporary = self.temporary.clone();
        let file = self.file_mut()?;
        file.sync_all()
            .map_err(|error| export_io("sync unsealed artifact", &temporary, error))?;
        file.seek(SeekFrom::Start(HEADER_LEN as u64))
            .map_err(|error| export_io("seek artifact body", &temporary, error))?;
        let mut hasher = blake3::Hasher::new();
        let mut remaining = body_len;
        let mut buffer = [0_u8; HASH_BUFFER_BYTES];
        while remaining != 0 {
            let requested = usize::try_from(remaining.min(HASH_BUFFER_BYTES as u64))
                .expect("bounded hash read");
            file.read_exact(&mut buffer[..requested])
                .map_err(|error| export_io("hash artifact body", &temporary, error))?;
            hasher.update(&buffer[..requested]);
            remaining -= requested as u64;
        }
        let digest = *hasher.finalize().as_bytes();
        file.seek(SeekFrom::Start(DIGEST_OFFSET))
            .and_then(|_| file.write_all(&digest))
            .and_then(|_| file.sync_all())
            .map_err(|error| export_io("seal artifact", &temporary, error))?;
        drop(self.file.take());

        // The production mmap reader is the format authority. A staged file
        // that it cannot authenticate never receives the destination name.
        drop(StaticLookupMatrix::open(&self.temporary)?);
        if self.target.exists() {
            return Err(artifact_exists(&self.target));
        }
        let physical_bytes = (HEADER_LEN as u64)
            .checked_add(self.body_len)
            .ok_or_else(|| export_invalid("static lookup artifact size overflows u64"))?;
        publish_immutable(&self.temporary, &self.target)?;

        // Publication is the sole commit point. No fallible operation follows
        // it, so an Err can never ambiguously mean "the artifact was committed".
        Ok(StaticLookupArtifact {
            path: self.target.clone(),
            rows: self.rows,
            dim: self.dim,
            dtype: self.dtype,
            body_len: self.body_len,
            physical_bytes,
            body_blake3: digest,
        })
    }

    fn initialize(&mut self, physical_bytes: u64, scale_table_len: u64) -> Result<()> {
        let dtype = match self.dtype {
            StaticLookupDType::Int8 => DTYPE_I8,
            StaticLookupDType::F16 => DTYPE_F16,
            StaticLookupDType::F32 => DTYPE_F32,
        };
        let rows = self.rows.to_le_bytes();
        let dim = self.dim.to_le_bytes();
        let body_len = self.body_len.to_le_bytes();
        let temporary = self.temporary.clone();
        let file = self.file_mut()?;
        file.set_len(physical_bytes)
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(MAGIC))
            .and_then(|_| file.write_all(&rows))
            .and_then(|_| file.write_all(&dim))
            .and_then(|_| file.write_all(&[dtype, 0, 0, 0]))
            .and_then(|_| file.write_all(&rows))
            .and_then(|_| file.write_all(&body_len))
            .and_then(|_| file.write_all(&[0_u8; 32]))
            .and_then(|_| file.seek(SeekFrom::Start(HEADER_LEN as u64 + scale_table_len)))
            .map_err(|error| export_io("initialize staging artifact", &temporary, error))?;
        Ok(())
    }

    fn encode_int8(&mut self, row: &[f32]) -> Result<()> {
        let mut max_abs = 0.0_f32;
        for (column, value) in row.iter().copied().enumerate() {
            ensure_finite(self.written, column, value)?;
            max_abs = max_abs.max(value.abs());
        }
        if max_abs == 0.0 {
            return Err(CalyxError::lens_numerical_invariant(format!(
                "static lookup export row {} is all-zero; canonical symmetric INT8 requires a \
                 non-zero row with a ±127 extremum",
                self.written
            )));
        }
        let scale = max_abs / 127.0;
        if !scale.is_finite() || scale <= 0.0 {
            return Err(CalyxError::lens_numerical_invariant(format!(
                "static lookup export row {} produced invalid scale {scale} from max_abs \
                 {max_abs}",
                self.written
            )));
        }
        self.scales.extend_from_slice(&scale.to_le_bytes());
        let mut max_abs_code = 0_u8;
        for value in row {
            let code = (value / scale).round().clamp(-127.0, 127.0) as i8;
            max_abs_code = max_abs_code.max(code.unsigned_abs());
            self.row_bytes.push(code as u8);
        }
        if max_abs_code != 127 {
            return Err(CalyxError::lens_numerical_invariant(format!(
                "static lookup export row {} failed to produce a ±127 extremum",
                self.written
            )));
        }
        Ok(())
    }

    fn encode_f16(&mut self, row: &[f32]) -> Result<()> {
        for (column, value) in row.iter().copied().enumerate() {
            ensure_finite(self.written, column, value)?;
            let encoded = f16::from_f32(value);
            if !encoded.is_finite() {
                return Err(CalyxError::lens_numerical_invariant(format!(
                    "static lookup export row {} column {column} value {value} overflows F16; \
                     export this matrix as F32",
                    self.written
                )));
            }
            self.row_bytes
                .extend_from_slice(&encoded.to_bits().to_le_bytes());
        }
        Ok(())
    }

    fn encode_f32(&mut self, row: &[f32]) -> Result<()> {
        for (column, value) in row.iter().copied().enumerate() {
            ensure_finite(self.written, column, value)?;
            self.row_bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }

    fn file_mut(&mut self) -> Result<&mut File> {
        self.file.as_mut().ok_or_else(|| {
            export_invalid("static lookup exporter file handle is already finalized")
        })
    }
}

impl Drop for StaticLookupWriter {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Err(error) = fs::remove_file(&self.temporary)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::error!(
                code = "CALYX_LENS_ARTIFACT_STAGING_CLEANUP_FAILED",
                path = %self.temporary.display(),
                error = %error,
                remediation = "remove the named incomplete staging file after verifying no exporter owns it",
                "static lookup exporter could not remove incomplete staging bytes"
            );
        }
    }
}

fn ensure_finite(row: u32, column: usize, value: f32) -> Result<()> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(CalyxError::lens_numerical_invariant(format!(
            "static lookup export row {row} column {column} value {value} is not finite"
        )))
    }
}

fn temporary_path(target: &Path) -> Result<PathBuf> {
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| export_invalid("static lookup output requires a UTF-8 file name"))?;
    let ordinal = TEMP_ORDINAL.fetch_add(1, Ordering::Relaxed);
    Ok(target.with_file_name(format!(
        ".{name}.{}.{}.calyx-tmp",
        std::process::id(),
        ordinal
    )))
}

fn artifact_exists(path: &Path) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_ARTIFACT_EXISTS",
        message: format!(
            "static lookup artifact {} already exists; frozen artifacts are immutable",
            path.display()
        ),
        remediation: "export to a new content/version-specific path and commission a new frozen lens id",
    }
}

fn export_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_ARTIFACT_INVALID",
        message: message.into(),
        remediation: "fix the tokenizer, dimensions, dtype, or source rows and export a new CXLKUP2 artifact",
    }
}

fn export_io(action: &str, path: &Path, error: std::io::Error) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_ARTIFACT_IO",
        message: format!("{action} {} failed: {error}", path.display()),
        remediation: "verify the destination is writable, local, on the same filesystem as its staging file, and has sufficient space; preserve the error and retry to a new path",
    }
}
