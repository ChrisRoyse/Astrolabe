//! Authenticated CXLKUP2 mmap parsing and canonical row validation.

use std::fs::File;
use std::path::Path;

use calyx_core::{CalyxError, Result};
use memmap2::Mmap;

use super::backend::{self, StaticLookupBackend};
use super::{
    DTYPE_F16, DTYPE_F32, DTYPE_I8, HEADER_LEN, MAGIC, MAGIC_LEGACY_V1, StaticLookupDType,
    config_invalid,
};

#[derive(Debug)]
pub(super) struct StaticLookupMatrix {
    mmap: Mmap,
    pub(super) rows: u32,
    pub(super) dim: u32,
    pub(super) dtype: StaticLookupDType,
    pub(super) backend: StaticLookupBackend,
    /// Byte offset where value codes begin (after the int8 per-row scale table).
    codes_offset: usize,
}

impl StaticLookupMatrix {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|err| {
            CalyxError::lens_unreachable(format!(
                "open static lookup matrix {} failed: {err}",
                path.display()
            ))
        })?;
        let mmap = unsafe {
            Mmap::map(&file).map_err(|err| {
                CalyxError::lens_unreachable(format!(
                    "mmap static lookup matrix {} failed: {err}",
                    path.display()
                ))
            })?
        };
        if mmap.len() < HEADER_LEN {
            return Err(config_invalid(format!(
                "static lookup matrix {} is {} B, smaller than the {HEADER_LEN} B v2 header",
                path.display(),
                mmap.len()
            )));
        }
        if &mmap[..8] != MAGIC {
            if &mmap[..8] == MAGIC_LEGACY_V1 {
                return Err(legacy_matrix_refused(path));
            }
            return Err(config_invalid(format!(
                "static lookup matrix {} has invalid magic {:02x?}",
                path.display(),
                &mmap[..8]
            )));
        }
        let rows = read_u32(&mmap[8..12]);
        let dim = read_u32(&mmap[12..16]);
        if rows == 0 || dim == 0 {
            return Err(CalyxError::lens_dim_mismatch(
                "static lookup matrix rows and dim must be non-zero",
            ));
        }
        let dtype = match mmap[16] {
            DTYPE_I8 => StaticLookupDType::Int8,
            DTYPE_F16 => StaticLookupDType::F16,
            DTYPE_F32 => StaticLookupDType::F32,
            other => {
                return Err(config_invalid(format!(
                    "unsupported static lookup dtype {other}"
                )));
            }
        };
        if mmap[17..20] != [0, 0, 0] {
            return Err(config_invalid(
                "static lookup matrix header pad bytes must be zero",
            ));
        }
        let vocab_size = read_u32(&mmap[20..24]);
        if vocab_size != rows {
            return Err(config_invalid(format!(
                "static lookup matrix declares vocab_size {vocab_size} != rows {rows}; the \
                 vocabulary identity must be bound one-to-one to matrix rows"
            )));
        }
        let declared_body_len = u64::from_le_bytes(mmap[24..32].try_into().expect("body len"));
        let digest: [u8; 32] = mmap[32..64].try_into().expect("digest");
        let cells = (rows as u64).checked_mul(dim as u64).ok_or_else(|| {
            CalyxError::lens_dim_mismatch("static lookup matrix cell count overflows u64")
        })?;
        let scale_table_len = match dtype {
            StaticLookupDType::Int8 => (rows as u64).checked_mul(4).ok_or_else(|| {
                CalyxError::lens_dim_mismatch("static lookup scale table overflows u64")
            })?,
            StaticLookupDType::F16 | StaticLookupDType::F32 => 0,
        };
        let body_len = cells
            .checked_mul(dtype.width() as u64)
            .and_then(|values| values.checked_add(scale_table_len))
            .ok_or_else(|| {
                CalyxError::lens_dim_mismatch("static lookup matrix body size overflows u64")
            })?;
        if body_len != declared_body_len {
            return Err(config_invalid(format!(
                "static lookup matrix declared body_len {declared_body_len} != computed \
                 {body_len} (rows {rows} x dim {dim} dtype {})",
                dtype.as_str()
            )));
        }
        let expected_total = (HEADER_LEN as u64).checked_add(body_len).ok_or_else(|| {
            CalyxError::lens_dim_mismatch("static lookup matrix total size overflows u64")
        })?;
        if mmap.len() as u64 != expected_total {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "static lookup matrix byte length {} != expected {expected_total}",
                mmap.len()
            )));
        }
        let body_len_usize = usize::try_from(body_len).map_err(|_| {
            CalyxError::lens_dim_mismatch(
                "static lookup matrix body exceeds this platform's address space",
            )
        })?;
        let observed = blake3::hash(&mmap[HEADER_LEN..HEADER_LEN + body_len_usize]);
        if *observed.as_bytes() != digest {
            return Err(CalyxError {
                code: "CALYX_LENS_MATRIX_DIGEST_MISMATCH",
                message: format!(
                    "static lookup matrix {} body does not match its sealed blake3 digest \
                     (observed {})",
                    path.display(),
                    observed.to_hex()
                ),
                remediation: "regenerate the matrix from its source embeddings; never trust the corrupt copy",
            });
        }
        let codes_offset = HEADER_LEN + scale_table_len as usize;
        let matrix = Self {
            mmap,
            rows,
            dim,
            dtype,
            backend: backend::detect(dtype),
            codes_offset,
        };
        matrix.verify_body(path)?;
        Ok(matrix)
    }

    /// Validates every persisted cell once at load: int8 scales are finite and
    /// positive with canonical codes; f16/f32 values are finite.
    fn verify_body(&self, path: &Path) -> Result<()> {
        match self.dtype {
            StaticLookupDType::Int8 => {
                for row in 0..self.rows {
                    let scale = self.row_scale(row);
                    if !scale.is_finite() || scale <= 0.0 {
                        return Err(CalyxError::lens_numerical_invariant(format!(
                            "static lookup matrix {} row {row} scale {scale} is not finite and \
                             positive",
                            path.display()
                        )));
                    }
                    let start = self.codes_offset + row as usize * self.dim as usize;
                    let codes = &self.mmap[start..start + self.dim as usize];
                    let mut max_abs_code = 0_u8;
                    for (column, raw) in codes.iter().copied().enumerate() {
                        let code = raw as i8;
                        if code == i8::MIN {
                            return Err(CalyxError::lens_numerical_invariant(format!(
                                "static lookup matrix {} row {row} column {column} carries \
                                 encoder-impossible int8 code -128",
                                path.display()
                            )));
                        }
                        max_abs_code = max_abs_code.max(code.unsigned_abs());
                    }
                    if max_abs_code != 127 {
                        return Err(CalyxError::lens_numerical_invariant(format!(
                            "static lookup matrix {} row {row} max |code| {max_abs_code} != \
                             127; canonical per-row quantization must use its full range",
                            path.display()
                        )));
                    }
                }
            }
            StaticLookupDType::F16 => {
                for (cell, chunk) in self.mmap[self.codes_offset..].chunks_exact(2).enumerate() {
                    let value = backend::f16_to_f32(u16::from_le_bytes([chunk[0], chunk[1]]));
                    if !value.is_finite() {
                        return Err(CalyxError::lens_numerical_invariant(format!(
                            "static lookup matrix {} contains non-finite f16 value at cell {cell}",
                            path.display()
                        )));
                    }
                }
            }
            StaticLookupDType::F32 => {
                for (cell, chunk) in self.mmap[self.codes_offset..].chunks_exact(4).enumerate() {
                    let value = f32::from_le_bytes(chunk.try_into().expect("4B"));
                    if !value.is_finite() {
                        return Err(CalyxError::lens_numerical_invariant(format!(
                            "static lookup matrix {} contains non-finite f32 value at cell {cell}",
                            path.display()
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Per-row dequantization multiplier for the int8 dtype.
    fn row_scale(&self, row: u32) -> f32 {
        let pos = HEADER_LEN + row as usize * 4;
        f32::from_le_bytes(self.mmap[pos..pos + 4].try_into().expect("scale bytes"))
    }

    pub(super) fn add_row(&self, row: u32, out: &mut [f32]) -> Result<()> {
        if row >= self.rows {
            return Err(CalyxError {
                code: "CALYX_LENS_TOKEN_ID_OUT_OF_RANGE",
                message: format!(
                    "token id {row} is outside the bound vocabulary of {} rows; the tokenizer \
                     and matrix identities have drifted apart",
                    self.rows
                ),
                remediation: "recommission the static lookup lens with a tokenizer whose \
                              vocabulary matches the matrix vocab_size binding",
            });
        }
        let dim = self.dim as usize;
        if out.len() != dim {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "static lookup output dim {} != matrix dim {dim}",
                out.len()
            )));
        }
        let start = self.codes_offset + row as usize * dim * self.dtype.width();
        match self.dtype {
            StaticLookupDType::Int8 => {
                let scale = self.row_scale(row);
                backend::add_i8(out, &self.mmap[start..start + dim], scale, self.backend);
            }
            StaticLookupDType::F16 => {
                backend::add_f16(out, &self.mmap[start..start + dim * 2], self.backend);
            }
            StaticLookupDType::F32 => {
                backend::add_f32(out, &self.mmap[start..start + dim * 4], self.backend);
            }
        }
        Ok(())
    }
}

fn legacy_matrix_refused(path: &Path) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_MATRIX_LEGACY",
        message: format!(
            "static lookup matrix {} carries legacy magic CXLKUP1 (single global scale, no \
             vocabulary binding, no body digest); refusing to guess its contents",
            path.display()
        ),
        remediation: "re-export the matrix in the CXLKUP2 format (per-row int8 scales, \
                      vocab_size binding, sealed blake3 body digest)",
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("u32 header bytes"))
}
