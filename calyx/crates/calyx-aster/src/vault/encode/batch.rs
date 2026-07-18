//! The WAL write-batch codec: a `CXLWAL2`-framed sequence of (column family,
//! key, value) rows.

use super::put_bytes;
use crate::cf::ColumnFamily;
use crate::vault::cf_codec::{decode_cf_v2, encode_cf_v2};
use crate::vault::cursor::Cursor;
use calyx_core::{CalyxError, Result};

const WRITE_BATCH_MAGIC_V2: &[u8; 8] = b"CXLWAL2\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRow {
    pub cf: ColumnFamily,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub fn encode_write_batch(rows: &[WriteRow]) -> Result<Vec<u8>> {
    let count = u32::try_from(rows.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("write batch row count exceeds u32"))?;
    let mut out = Vec::new();
    out.extend_from_slice(WRITE_BATCH_MAGIC_V2);
    out.extend_from_slice(&count.to_be_bytes());
    for row in rows {
        encode_cf_v2(row.cf, &mut out);
        put_bytes(&mut out, &row.key)?;
        put_bytes(&mut out, &row.value)?;
    }
    Ok(out)
}

pub fn decode_write_batch(bytes: &[u8]) -> Result<Vec<WriteRow>> {
    if bytes.len() < WRITE_BATCH_MAGIC_V2.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "WAL write batch is {} bytes, smaller than the {}-byte CXLWAL2 header",
            bytes.len(),
            WRITE_BATCH_MAGIC_V2.len()
        )));
    }
    if !bytes.starts_with(WRITE_BATCH_MAGIC_V2) {
        return Err(CalyxError {
            code: "CALYX_ASTER_WAL_PAYLOAD_LEGACY",
            message: "WAL write batch has no CXLWAL2 header; the legacy one-byte column-family tag truncated u16 slot ids and overlapped raw/quantized slot families"
                .to_string(),
            remediation: "restore this pre-CXLWAL2 vault with a format-specific migration that knows every original slot id/family, or re-ingest it from its provenanced source; never reinterpret ambiguous committed state",
        });
    }
    let payload = &bytes[WRITE_BATCH_MAGIC_V2.len()..];
    let mut cursor = Cursor::new(payload);
    let count = cursor.u32()? as usize;
    let minimum_row_bytes = 11;
    if count > cursor.remaining() / minimum_row_bytes {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "write batch declares {count} rows but {} remaining bytes cannot hold that many canonical rows",
            cursor.remaining()
        )));
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(count).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!(
            "reserve {count} decoded write rows failed: {error}"
        ))
    })?;
    for _ in 0..count {
        rows.push(WriteRow {
            cf: decode_cf_v2(&mut cursor)?,
            key: cursor.bytes_prefixed()?.to_vec(),
            value: cursor.bytes_prefixed()?.to_vec(),
        });
    }
    if cursor.remaining() != 0 {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "write batch has {} trailing bytes after its declared rows",
            cursor.remaining()
        )));
    }
    Ok(rows)
}
