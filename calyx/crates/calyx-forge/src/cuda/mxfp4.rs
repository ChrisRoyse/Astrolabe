use crate::cpu::check_finite;
use crate::{ForgeError, Result};
use wide::f32x8;

pub const MXFP4_BLOCK_SIZE: usize = 32;
pub const MXFP4_PACKED_BYTES: usize = MXFP4_BLOCK_SIZE / 2;
pub const MXFP4_BLOCK_BYTES: usize = MXFP4_PACKED_BYTES + 1;
pub const MXFP4_MAX_DIM: usize = 1 << 20;

const E8M0_EXP_BIAS: i32 = 127;
const E8M0_NAN: u8 = 0xff;
const FP4_MAX_POWER_EXP: i32 = 2; // 4.0 is the largest power of two in E2M1.
const FP4_MAX_FINITE: f32 = 6.0;
const MXFP4_REMEDIATION: &str = "Re-encode finite values as OCP MXFP4 E2M1 blocks of 32 with canonical E8M0 scales, RNE element conversion, and zero padding";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MxFp4Block {
    pub codes: [u8; MXFP4_PACKED_BYTES],
    pub scale_e8m0: u8,
}

pub fn encode_mxfp4_block(block: &[f32; MXFP4_BLOCK_SIZE]) -> Result<MxFp4Block> {
    check_finite(block, "mxfp4_encode_block")?;
    let abs_max = block
        .iter()
        .map(|value| value.abs())
        .fold(0.0_f32, f32::max);
    let scale_e8m0 = canonical_scale_byte(abs_max, FP4_MAX_POWER_EXP);
    let scale = decode_e8m0(scale_e8m0)?;
    let mut codes = [0; MXFP4_PACKED_BYTES];
    for (idx, value) in block.iter().enumerate() {
        let code = encode_e2m1(*value / scale);
        set_nibble(&mut codes, idx, code);
    }
    Ok(MxFp4Block { codes, scale_e8m0 })
}

pub fn decode_mxfp4_block(block: &MxFp4Block) -> Result<[f32; MXFP4_BLOCK_SIZE]> {
    validate_mxfp4_block(block, MXFP4_BLOCK_SIZE, false)?;
    let mut decoded = [0.0; MXFP4_BLOCK_SIZE];
    let scale = decode_e8m0(block.scale_e8m0)?;
    for (idx, slot) in decoded.iter_mut().enumerate() {
        *slot = decode_e2m1(nibble_at(&block.codes, idx)) * scale;
    }
    Ok(decoded)
}

pub fn encode_mxfp4(vec: &[f32]) -> Result<Vec<MxFp4Block>> {
    check_finite(vec, "mxfp4_encode")?;
    validate_dim(vec.len(), "mxfp4_encode")?;
    let mut out = Vec::with_capacity(vec.len().div_ceil(MXFP4_BLOCK_SIZE));
    for chunk in vec.chunks(MXFP4_BLOCK_SIZE) {
        let mut block = [0.0; MXFP4_BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);
        out.push(encode_mxfp4_block(&block)?);
    }
    Ok(out)
}

pub fn decode_mxfp4(blocks: &[MxFp4Block], original_dim: usize) -> Result<Vec<f32>> {
    validate_mxfp4_blocks(blocks, original_dim)?;
    let mut decoded = Vec::with_capacity(original_dim);
    for (block_index, block) in blocks.iter().enumerate() {
        let valid = valid_lanes(original_dim, block_index);
        let scale = decode_e8m0(block.scale_e8m0)?;
        for lane in 0..valid {
            decoded.push(decode_e2m1(nibble_at(&block.codes, lane)) * scale);
        }
    }
    Ok(decoded)
}

/// Computes raw-query dot and candidate squared norm directly from packed OCP blocks.
///
/// This is the CPU reference/search path. It never materializes a candidate-wide F32 vector.
pub fn dot_norm_mxfp4(
    query: &[f32],
    blocks: &[MxFp4Block],
    original_dim: usize,
) -> Result<(f32, f64)> {
    if query.len() != original_dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![original_dim],
            got: vec![query.len()],
            remediation: MXFP4_REMEDIATION.to_string(),
        });
    }
    check_finite(query, "mxfp4_dot_query")?;
    validate_mxfp4_blocks(blocks, original_dim)?;

    let mut dot = 0.0_f32;
    let mut norm_sq = 0.0_f64;
    let mut coordinate = 0;
    for (block_index, block) in blocks.iter().enumerate() {
        let valid = valid_lanes(original_dim, block_index);
        let scale = decode_e8m0(block.scale_e8m0)?;
        let mut lane = 0;
        while lane + 8 <= valid {
            let mut values = [0.0_f32; 8];
            let mut query_values = [0.0_f32; 8];
            for offset in 0..8 {
                values[offset] = decode_e2m1(nibble_at(&block.codes, lane + offset)) * scale;
                query_values[offset] = query[coordinate + offset];
                norm_sq += f64::from(values[offset]) * f64::from(values[offset]);
            }
            dot += (f32x8::from(query_values) * f32x8::from(values)).reduce_add();
            lane += 8;
            coordinate += 8;
        }
        while lane < valid {
            let value = decode_e2m1(nibble_at(&block.codes, lane)) * scale;
            dot = query[coordinate].mul_add(value, dot);
            norm_sq += f64::from(value) * f64::from(value);
            coordinate += 1;
            lane += 1;
        }
    }
    if !dot.is_finite() || !norm_sq.is_finite() {
        return Err(quant_error(
            "mxfp4_dot",
            "packed dot or norm was non-finite",
        ));
    }
    Ok((dot, norm_sq))
}

pub fn validate_mxfp4_blocks(blocks: &[MxFp4Block], original_dim: usize) -> Result<()> {
    validate_dim(original_dim, "mxfp4_validate")?;
    let expected = original_dim.div_ceil(MXFP4_BLOCK_SIZE);
    if blocks.len() != expected {
        return Err(quant_error(
            "mxfp4_validate",
            format!(
                "block count mismatch: expected {expected} for dim {original_dim}, got {}",
                blocks.len()
            ),
        ));
    }
    for (index, block) in blocks.iter().enumerate() {
        let valid = valid_lanes(original_dim, index);
        validate_mxfp4_block(block, valid, index + 1 == blocks.len())?;
    }
    Ok(())
}

pub fn decode_e8m0(scale_e8m0: u8) -> Result<f32> {
    if scale_e8m0 == E8M0_NAN {
        return Err(quant_error(
            "mxfp_decode_scale",
            "E8M0 0xff is NaN and cannot appear in a finite Calyx MX payload",
        ));
    }
    Ok(2.0_f32.powi(i32::from(scale_e8m0) - E8M0_EXP_BIAS))
}

pub fn decode_e2m1(code: u8) -> f32 {
    let magnitude = match code & 0x07 {
        0 => 0.0,
        1 => 0.5,
        2 => 1.0,
        3 => 1.5,
        4 => 2.0,
        5 => 3.0,
        6 => 4.0,
        7 => 6.0,
        _ => unreachable!(),
    };
    if code & 0x08 == 0 {
        magnitude
    } else {
        -magnitude
    }
}

pub(crate) fn canonical_scale_byte(abs_max: f32, element_max_power_exp: i32) -> u8 {
    if abs_max == 0.0 {
        return 0;
    }
    let exponent = floor_log2_positive(abs_max) - element_max_power_exp;
    (exponent.clamp(-127, 127) + E8M0_EXP_BIAS) as u8
}

fn encode_e2m1(value: f32) -> u8 {
    if value == 0.0 {
        return 0;
    }
    let sign = if value.is_sign_negative() { 0x08 } else { 0 };
    let magnitude = value.abs();
    if magnitude >= FP4_MAX_FINITE {
        return sign | 7;
    }
    const VALUES: [f32; 8] = [0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0];
    let mut upper = 1;
    while VALUES[upper] < magnitude {
        upper += 1;
    }
    let lower = upper - 1;
    let lower_error = magnitude - VALUES[lower];
    let upper_error = VALUES[upper] - magnitude;
    let chosen = if lower_error < upper_error {
        lower
    } else if upper_error < lower_error {
        upper
    } else if lower.is_multiple_of(2) {
        lower
    } else {
        upper
    };
    sign | chosen as u8
}

pub(crate) fn validate_mxfp4_block(
    block: &MxFp4Block,
    valid: usize,
    final_block: bool,
) -> Result<()> {
    let scale = decode_e8m0(block.scale_e8m0)?;
    let mut any_nonzero = false;
    for lane in 0..MXFP4_BLOCK_SIZE {
        let code = nibble_at(&block.codes, lane);
        if code == 0x08 {
            return Err(quant_error(
                "mxfp4_validate",
                format!("negative-zero E2M1 code at lane {lane} is noncanonical"),
            ));
        }
        if lane >= valid && code != 0 {
            return Err(quant_error(
                "mxfp4_validate",
                format!(
                    "noncanonical final-block padding at lane {lane}: expected +0 code 0 got {code}"
                ),
            ));
        }
        if !(decode_e2m1(code) * scale).is_finite() {
            return Err(quant_error(
                "mxfp4_validate",
                format!(
                    "E2M1 code {code} with E8M0 scale 0x{:02x} overflows the finite F32 execution domain at lane {lane}",
                    block.scale_e8m0
                ),
            ));
        }
        any_nonzero |= code != 0;
    }
    if !any_nonzero && block.scale_e8m0 != 0 {
        return Err(quant_error(
            "mxfp4_validate",
            "all-zero E2M1 block requires canonical E8M0 scale byte 0",
        ));
    }
    if !final_block && valid != MXFP4_BLOCK_SIZE {
        return Err(quant_error(
            "mxfp4_validate",
            "only the final MXFP4 block may be partial",
        ));
    }
    Ok(())
}

fn validate_dim(dim: usize, op: &str) -> Result<()> {
    if (1..=MXFP4_MAX_DIM).contains(&dim) {
        return Ok(());
    }
    Err(quant_error(
        op,
        format!("dimension must be in 1..={MXFP4_MAX_DIM}, got {dim}"),
    ))
}

fn valid_lanes(dim: usize, block_index: usize) -> usize {
    (dim - block_index * MXFP4_BLOCK_SIZE).min(MXFP4_BLOCK_SIZE)
}

fn floor_log2_positive(value: f32) -> i32 {
    debug_assert!(value.is_finite() && value > 0.0);
    let bits = value.to_bits();
    let encoded_exp = ((bits >> 23) & 0xff) as i32;
    if encoded_exp != 0 {
        return encoded_exp - 127;
    }
    let fraction = bits & 0x7f_ffff;
    (31 - fraction.leading_zeros()) as i32 - 149
}

fn set_nibble(codes: &mut [u8; MXFP4_PACKED_BYTES], idx: usize, code: u8) {
    if idx.is_multiple_of(2) {
        codes[idx / 2] |= code & 0x0f;
    } else {
        codes[idx / 2] |= (code & 0x0f) << 4;
    }
}

pub fn nibble_at(codes: &[u8; MXFP4_PACKED_BYTES], idx: usize) -> u8 {
    let byte = codes[idx / 2];
    if idx.is_multiple_of(2) {
        byte & 0x0f
    } else {
        byte >> 4
    }
}

fn quant_error(op: &str, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: "OcpMxFp4E2M1".to_string(),
        detail: detail.into(),
        remediation: MXFP4_REMEDIATION.to_string(),
    }
}
