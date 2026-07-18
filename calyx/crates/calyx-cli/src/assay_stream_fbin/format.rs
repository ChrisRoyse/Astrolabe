use std::path::Path;

use calyx_sextant::index::{FbinWriter, I8BinWriter};
use serde::Serialize;

use crate::error::{CliError, CliResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct VectorFileSeal {
    pub(crate) payload_blake3: String,
    pub(crate) source_blake3: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) enum VectorFormat {
    #[serde(rename = "fbin")]
    #[default]
    Fbin,
    #[serde(rename = "i8bin")]
    I8Bin,
}

impl VectorFormat {
    pub(crate) fn parse(value: &str) -> CliResult<Self> {
        match value {
            "fbin" => Ok(Self::Fbin),
            "i8bin" => Ok(Self::I8Bin),
            other => Err(CliError::usage(format!(
                "--vector-format must be fbin or i8bin, got {other}"
            ))),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Fbin => "fbin",
            Self::I8Bin => "i8bin",
        }
    }

    pub(crate) fn dir_name(self) -> &'static str {
        match self {
            Self::Fbin => "fbin",
            Self::I8Bin => "i8bin",
        }
    }

    pub(crate) fn extension(self) -> &'static str {
        self.as_str()
    }

    pub(crate) fn storage_contract(self) -> &'static str {
        match self {
            Self::Fbin => "clxvec02-exact-f32-bit-preserving-blake3-authenticated",
            Self::I8Bin => "clxi8b02-per-row-scale-symmetric-int8-blake3-authenticated",
        }
    }
}

/// Streaming sink for one authenticated v2 vector file. Rows are written
/// bit-exactly (fbin) or with a preserved per-row dequantization scale (i8bin);
/// non-finite rows are refused fail-closed by the underlying writers and
/// `finalize` seals the blake3 payload digest into the header.
pub(crate) enum VectorFileSink {
    Fbin(FbinWriter),
    I8Bin(I8BinWriter),
}

impl VectorFileSink {
    pub(crate) fn create(
        path: &Path,
        format: VectorFormat,
        dim: usize,
        count: usize,
    ) -> CliResult<Self> {
        let count = u64::try_from(count)
            .map_err(|_| CliError::usage("vector file row count exceeds u64"))?;
        match format {
            VectorFormat::Fbin => Ok(Self::Fbin(
                FbinWriter::create(path, dim, count).map_err(CliError::Calyx)?,
            )),
            VectorFormat::I8Bin => Ok(Self::I8Bin(
                I8BinWriter::create(path, dim, count).map_err(CliError::Calyx)?,
            )),
        }
    }

    pub(crate) fn write_row(&mut self, row: &[f32]) -> CliResult {
        match self {
            Self::Fbin(writer) => writer.write_row(row).map_err(CliError::Calyx),
            Self::I8Bin(writer) => writer.write_row(row).map_err(CliError::Calyx),
        }
    }

    pub(crate) fn flush_sync(&mut self) -> CliResult {
        match self {
            Self::Fbin(writer) => writer.flush_sync().map_err(CliError::Calyx),
            Self::I8Bin(writer) => writer.flush_sync().map_err(CliError::Calyx),
        }
    }

    /// Validates and atomically publishes the vector file, returning both its
    /// exact payload digest and its shape-bound canonical source identity.
    pub(crate) fn finalize(self) -> CliResult<VectorFileSeal> {
        let identity = match self {
            Self::Fbin(writer) => writer.finalize().map_err(CliError::Calyx)?,
            Self::I8Bin(writer) => writer.finalize().map_err(CliError::Calyx)?,
        };
        Ok(VectorFileSeal {
            payload_blake3: hex32(&identity.payload_blake3),
            source_blake3: hex32(&identity.source_blake3),
        })
    }
}

fn hex32(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
