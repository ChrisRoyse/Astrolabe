use calyx_core::{Result, Seq};
use sha2::{Digest, Sha256};

use super::{CALYX_MULTIVECTOR_PACK_INVALID, multivector_error};

pub(super) const DIGEST_BYTES: usize = 32;
pub(super) const CODEC_TAG_RESIDUAL_2BIT: u8 = 1;
pub(super) const METRIC_TAG_COSINE_MAXSIM: u8 = 1;
pub(super) const DTYPE_TAG_F32: u8 = 1;
pub(super) const RESIDUAL_BITS: u8 = 2;
pub(super) const CENTROID_CODE_BYTES: u8 = 4;
pub(super) const CUTOFF_COUNT: usize = 3;
pub(super) const WEIGHT_COUNT: usize = 4;

pub(super) fn append_digest(bytes: &mut Vec<u8>, domain: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes.as_slice());
    bytes.extend_from_slice(&hasher.finalize());
}

pub(super) fn require_digest(bytes: &[u8], domain: &[u8], label: &str) -> Result<()> {
    let body_len = bytes
        .len()
        .checked_sub(DIGEST_BYTES)
        .ok_or_else(|| invalid(format!("{label} has no checksum trailer")))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&bytes[..body_len]);
    if hasher.finalize().as_slice() != &bytes[body_len..] {
        return Err(invalid(format!("{label} SHA-256 checksum mismatch")));
    }
    Ok(())
}

pub(super) fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(slice_array(bytes, at)?))
}

pub(super) fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(slice_array(bytes, at)?))
}

pub(super) fn read_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(slice_array(bytes, at)?))
}

pub(super) fn read_seq(bytes: &[u8], at: usize) -> Result<Seq> {
    read_u64(bytes, at)
}

pub(super) fn read_f32(bytes: &[u8], at: usize) -> Result<f32> {
    let value = f32::from_bits(read_u32(bytes, at)?);
    if !value.is_finite() {
        return Err(invalid(format!("non-finite f32 at byte offset {at}")));
    }
    Ok(value)
}

pub(super) fn array_16(bytes: &[u8], at: usize) -> Result<[u8; 16]> {
    slice_array(bytes, at)
}

pub(super) fn array_32(bytes: &[u8], at: usize) -> Result<[u8; 32]> {
    slice_array(bytes, at)
}

fn slice_array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    let end = at
        .checked_add(N)
        .ok_or_else(|| invalid(format!("field byte offset {at} overflows usize")))?;
    bytes
        .get(at..end)
        .ok_or_else(|| invalid(format!("field at byte offset {at} exceeds record length")))?
        .try_into()
        .map_err(|_| invalid(format!("field at byte offset {at} has wrong width")))
}

pub(super) fn require_tag(actual: u8, expected: u8, field: &str) -> Result<()> {
    if actual != expected {
        return Err(invalid(format!(
            "{field} tag {actual} != expected {expected}"
        )));
    }
    Ok(())
}

pub(super) fn require_u16(bytes: &[u8], at: usize, expected: u16, field: &str) -> Result<()> {
    let actual = read_u16(bytes, at)?;
    if actual != expected {
        return Err(invalid(format!("{field} {actual} != expected {expected}")));
    }
    Ok(())
}

pub(super) fn require_u32(bytes: &[u8], at: usize, expected: u32, field: &str) -> Result<()> {
    let actual = read_u32(bytes, at)?;
    if actual != expected {
        return Err(invalid(format!("{field} {actual} != expected {expected}")));
    }
    Ok(())
}

pub(super) fn require_u64(bytes: &[u8], at: usize, expected: u64, field: &str) -> Result<()> {
    let actual = read_u64(bytes, at)?;
    if actual != expected {
        return Err(invalid(format!("{field} {actual} != expected {expected}")));
    }
    Ok(())
}

pub(super) fn as_u32(value: usize, field: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| invalid(format!("{field} exceeds u32")))
}

pub(super) fn sorted_finite(values: &[f32]) -> bool {
    values.iter().all(|value| value.is_finite()) && values.windows(2).all(|pair| pair[0] <= pair[1])
}

pub(super) fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    multivector_error(CALYX_MULTIVECTOR_PACK_INVALID, message)
}
