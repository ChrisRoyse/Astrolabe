use std::fs::File;
use std::path::Path;

use calyx_core::Result;
use memmap2::Mmap;

use crate::error::{CALYX_INDEX_CORRUPT, CALYX_INDEX_IO, sextant_error};

const I32BIN_HEADER_LEN: usize = 8;

#[derive(Debug)]
pub struct I32BinMatrix {
    mmap: Mmap,
    width: usize,
    count: u64,
}

impl I32BinMatrix {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|error| {
            sextant_error(
                CALYX_INDEX_IO,
                format!("open i32bin {}: {error}", path.display()),
            )
        })?;
        let len = file
            .metadata()
            .map_err(|error| sextant_error(CALYX_INDEX_IO, format!("stat i32bin: {error}")))?
            .len();
        if len < I32BIN_HEADER_LEN as u64 {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("i32bin {} is {len} B, smaller than header", path.display()),
            ));
        }
        // SAFETY: callers treat benchmark truth files as immutable for the
        // lifetime of this read-only mapping.
        let mmap = unsafe {
            Mmap::map(&file)
                .map_err(|error| sextant_error(CALYX_INDEX_IO, format!("mmap i32bin: {error}")))?
        };
        let count = u64::from(u32::from_le_bytes(mmap[0..4].try_into().expect("4B")));
        let width = u32::from_le_bytes(mmap[4..8].try_into().expect("4B")) as usize;
        if width == 0 {
            return Err(sextant_error(CALYX_INDEX_CORRUPT, "i32bin width is zero"));
        }
        let body = count
            .checked_mul(width as u64)
            .and_then(|cells| cells.checked_mul(4))
            .ok_or_else(|| {
                sextant_error(
                    CALYX_INDEX_CORRUPT,
                    format!(
                        "i32bin {} body size overflows u64 (count {count} x width {width})",
                        path.display()
                    ),
                )
            })?;
        let expected = (I32BIN_HEADER_LEN as u64)
            .checked_add(body)
            .ok_or_else(|| {
                sextant_error(
                    CALYX_INDEX_CORRUPT,
                    format!("i32bin {} total size overflows u64", path.display()),
                )
            })?;
        if len != expected {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "i32bin {} len {len} != expected {expected} (count {count} x width {width} x 4 + {I32BIN_HEADER_LEN})",
                    path.display()
                ),
            ));
        }
        usize::try_from(body).map_err(|_| {
            sextant_error(
                CALYX_INDEX_CORRUPT,
                format!(
                    "i32bin {} body {body} B exceeds this platform's address space",
                    path.display()
                ),
            )
        })?;
        Ok(Self { mmap, width, count })
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn row(&self, idx: u64) -> Vec<i32> {
        self.try_row(idx)
            .unwrap_or_else(|error| panic!("{error:?}"))
    }

    pub fn try_row(&self, idx: u64) -> Result<Vec<i32>> {
        if idx >= self.count {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("i32bin row {idx} >= count {}", self.count),
            ));
        }
        let start = I32BIN_HEADER_LEN + (idx as usize) * self.width * 4;
        Ok(self.mmap[start..start + self.width * 4]
            .chunks_exact(4)
            .map(|chunk| i32::from_le_bytes(chunk.try_into().expect("4B")))
            .collect())
    }
}
