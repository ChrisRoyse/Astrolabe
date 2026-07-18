//! Aster vault on-disk encodings, split into focused codec submodules: the
//! constellation [`header`], the slot-vector [`vector`] codec, the Base row
//! ([`base`]), and the WAL write [`batch`]. The two shared length-prefixed
//! primitives (`put_string`/`put_bytes`) live here so every submodule reuses one
//! definition.

use calyx_core::{CalyxError, Result};

mod base;
mod batch;
mod header;
mod vector;

pub use super::anchor_codec::{decode_anchor, encode_anchor};
pub use base::{
    BaseRecord, CALYX_ASTER_BASE_SLOT_HASH_VIOLATION, ConstellationBaseIdentity,
    decode_constellation_base, decode_constellation_base_identity, encode_constellation_base,
};
pub use batch::{WriteRow, decode_write_batch, encode_write_batch};
pub use header::{
    ConstellationHeader, HEADER_LEN, decode_header, encode_header, same_constellation_identity,
};
pub use vector::{decode_slot_vector, encode_slot_vector};

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    put_bytes(out, value.as_bytes())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("encoded field too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
