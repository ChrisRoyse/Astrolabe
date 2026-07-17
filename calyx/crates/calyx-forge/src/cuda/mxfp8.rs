use crate::cpu::check_finite;
use crate::mxfp4::{canonical_scale_byte, decode_e8m0};
use crate::{ForgeError, Result};
use wide::f32x8;

pub const MXFP8_BLOCK_SIZE: usize = 32;
pub const MXFP8_BLOCK_BYTES: usize = MXFP8_BLOCK_SIZE + 1;
pub const MXFP8_MAX_DIM: usize = 1 << 20;

const E4M3_MAX_POWER_EXP: i32 = 8; // 256.0 is the largest power of two in E4M3.
const E4M3_MAX_FINITE: f32 = 448.0;
const E4M3_NAN_MAGNITUDE: u8 = 0x7f;
const MXFP8_REMEDIATION: &str = "Re-encode finite values as OCP MXFP8 E4M3 blocks of 32 with canonical E8M0 scales, RNE element conversion, and zero padding";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MxFp8Block {
    pub codes: [u8; MXFP8_BLOCK_SIZE],
    pub scale_e8m0: u8,
}

pub fn encode_mxfp8_block(block: &[f32; MXFP8_BLOCK_SIZE]) -> Result<MxFp8Block> {
    check_finite(block, "mxfp8_encode_block")?;
    let abs_max = block
        .iter()
        .map(|value| value.abs())
        .fold(0.0_f32, f32::max);
    let scale_e8m0 = canonical_scale_byte(abs_max, E4M3_MAX_POWER_EXP);
    let scale = decode_e8m0(scale_e8m0)?;
    let mut codes = [0; MXFP8_BLOCK_SIZE];
    for (slot, value) in codes.iter_mut().zip(block.iter()) {
        *slot = encode_e4m3(*value / scale);
    }
    Ok(MxFp8Block { codes, scale_e8m0 })
}

pub fn decode_mxfp8_block(block: &MxFp8Block) -> Result<[f32; MXFP8_BLOCK_SIZE]> {
    validate_mxfp8_block(block, MXFP8_BLOCK_SIZE, false)?;
    let scale = decode_e8m0(block.scale_e8m0)?;
    let mut decoded = [0.0; MXFP8_BLOCK_SIZE];
    for (slot, code) in decoded.iter_mut().zip(block.codes.iter()) {
        *slot = decode_e4m3(*code)? * scale;
    }
    Ok(decoded)
}

pub fn encode_mxfp8(vec: &[f32]) -> Result<Vec<MxFp8Block>> {
    check_finite(vec, "mxfp8_encode")?;
    validate_dim(vec.len(), "mxfp8_encode")?;
    let mut out = Vec::with_capacity(vec.len().div_ceil(MXFP8_BLOCK_SIZE));
    for chunk in vec.chunks(MXFP8_BLOCK_SIZE) {
        let mut block = [0.0; MXFP8_BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);
        out.push(encode_mxfp8_block(&block)?);
    }
    Ok(out)
}

pub fn decode_mxfp8(blocks: &[MxFp8Block], original_dim: usize) -> Result<Vec<f32>> {
    validate_mxfp8_blocks(blocks, original_dim)?;
    let mut decoded = Vec::with_capacity(original_dim);
    for (block_index, block) in blocks.iter().enumerate() {
        let valid = valid_lanes(original_dim, block_index);
        let scale = decode_e8m0(block.scale_e8m0)?;
        for code in &block.codes[..valid] {
            decoded.push(decode_e4m3(*code)? * scale);
        }
    }
    Ok(decoded)
}

/// Computes raw-query dot and candidate squared norm directly from packed OCP blocks.
pub fn dot_norm_mxfp8(
    query: &[f32],
    blocks: &[MxFp8Block],
    original_dim: usize,
) -> Result<(f32, f64)> {
    if query.len() != original_dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![original_dim],
            got: vec![query.len()],
            remediation: MXFP8_REMEDIATION.to_string(),
        });
    }
    check_finite(query, "mxfp8_dot_query")?;
    validate_mxfp8_blocks(blocks, original_dim)?;

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
                values[offset] = decode_e4m3(block.codes[lane + offset])? * scale;
                query_values[offset] = query[coordinate + offset];
                norm_sq += f64::from(values[offset]) * f64::from(values[offset]);
            }
            dot += (f32x8::from(query_values) * f32x8::from(values)).reduce_add();
            lane += 8;
            coordinate += 8;
        }
        while lane < valid {
            let value = decode_e4m3(block.codes[lane])? * scale;
            dot = query[coordinate].mul_add(value, dot);
            norm_sq += f64::from(value) * f64::from(value);
            coordinate += 1;
            lane += 1;
        }
    }
    if !dot.is_finite() || !norm_sq.is_finite() {
        return Err(quant_error(
            "mxfp8_dot",
            "packed dot or norm was non-finite",
        ));
    }
    Ok((dot, norm_sq))
}

pub fn validate_mxfp8_blocks(blocks: &[MxFp8Block], original_dim: usize) -> Result<()> {
    validate_dim(original_dim, "mxfp8_validate")?;
    let expected = original_dim.div_ceil(MXFP8_BLOCK_SIZE);
    if blocks.len() != expected {
        return Err(quant_error(
            "mxfp8_validate",
            format!(
                "block count mismatch: expected {expected} for dim {original_dim}, got {}",
                blocks.len()
            ),
        ));
    }
    for (index, block) in blocks.iter().enumerate() {
        let valid = valid_lanes(original_dim, index);
        validate_mxfp8_block(block, valid, index + 1 == blocks.len())?;
    }
    Ok(())
}

pub fn decode_e4m3(code: u8) -> Result<f32> {
    if code & 0x7f == E4M3_NAN_MAGNITUDE {
        return Err(quant_error(
            "mxfp8_decode_element",
            format!("E4M3 code 0x{code:02x} is reserved NaN"),
        ));
    }
    let sign = if code & 0x80 == 0 { 1.0 } else { -1.0 };
    let exponent = (code >> 3) & 0x0f;
    let mantissa = code & 0x07;
    let magnitude = if exponent == 0 {
        (f32::from(mantissa) / 8.0) * 2.0_f32.powi(-6)
    } else {
        (1.0 + f32::from(mantissa) / 8.0) * 2.0_f32.powi(i32::from(exponent) - 7)
    };
    Ok(sign * magnitude)
}

fn encode_e4m3(value: f32) -> u8 {
    if value == 0.0 {
        return 0;
    }
    let sign = if value.is_sign_negative() { 0x80 } else { 0 };
    let magnitude = value.abs();
    if magnitude >= E4M3_MAX_FINITE {
        return sign | 0x7e;
    }

    // Positive finite E4M3 codes 0..=126 are monotonically ordered. Locate the
    // nearest pair in O(log 127), then apply IEEE roundTiesToEven at an exact tie.
    let mut low = 0_u8;
    let mut high = 0x7e_u8;
    while low < high {
        let mid = low + (high - low) / 2;
        let decoded = decode_positive_e4m3(mid);
        if decoded < magnitude {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    let upper = low;
    if upper == 0 {
        return sign;
    }
    let lower = upper - 1;
    let lower_error = magnitude - decode_positive_e4m3(lower);
    let upper_error = decode_positive_e4m3(upper) - magnitude;
    let chosen = if lower_error < upper_error {
        lower
    } else if upper_error < lower_error {
        upper
    } else if lower.is_multiple_of(2) {
        lower
    } else {
        upper
    };
    sign | chosen
}

fn decode_positive_e4m3(code: u8) -> f32 {
    debug_assert!(code <= 0x7e);
    let exponent = (code >> 3) & 0x0f;
    let mantissa = code & 0x07;
    if exponent == 0 {
        (f32::from(mantissa) / 8.0) * 2.0_f32.powi(-6)
    } else {
        (1.0 + f32::from(mantissa) / 8.0) * 2.0_f32.powi(i32::from(exponent) - 7)
    }
}

pub(crate) fn validate_mxfp8_block(
    block: &MxFp8Block,
    valid: usize,
    final_block: bool,
) -> Result<()> {
    let scale = decode_e8m0(block.scale_e8m0)?;
    let mut any_nonzero = false;
    for (lane, code) in block.codes.iter().enumerate() {
        if code & 0x7f == E4M3_NAN_MAGNITUDE {
            return Err(quant_error(
                "mxfp8_validate",
                format!("reserved E4M3 NaN code 0x{code:02x} at lane {lane}"),
            ));
        }
        if *code == 0x80 {
            return Err(quant_error(
                "mxfp8_validate",
                format!("negative-zero E4M3 code at lane {lane} is noncanonical"),
            ));
        }
        if lane >= valid && *code != 0 {
            return Err(quant_error(
                "mxfp8_validate",
                format!(
                    "noncanonical final-block padding at lane {lane}: expected +0 code 0 got 0x{code:02x}"
                ),
            ));
        }
        if !(decode_e4m3(*code)? * scale).is_finite() {
            return Err(quant_error(
                "mxfp8_validate",
                format!(
                    "E4M3 code 0x{code:02x} with E8M0 scale 0x{:02x} overflows the finite F32 execution domain at lane {lane}",
                    block.scale_e8m0
                ),
            ));
        }
        any_nonzero |= *code != 0;
    }
    if !any_nonzero && block.scale_e8m0 != 0 {
        return Err(quant_error(
            "mxfp8_validate",
            "all-zero E4M3 block requires canonical E8M0 scale byte 0",
        ));
    }
    if !final_block && valid != MXFP8_BLOCK_SIZE {
        return Err(quant_error(
            "mxfp8_validate",
            "only the final MXFP8 block may be partial",
        ));
    }
    Ok(())
}

fn validate_dim(dim: usize, op: &str) -> Result<()> {
    if (1..=MXFP8_MAX_DIM).contains(&dim) {
        return Ok(());
    }
    Err(quant_error(
        op,
        format!("dimension must be in 1..={MXFP8_MAX_DIM}, got {dim}"),
    ))
}

fn valid_lanes(dim: usize, block_index: usize) -> usize {
    (dim - block_index * MXFP8_BLOCK_SIZE).min(MXFP8_BLOCK_SIZE)
}

fn quant_error(op: &str, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: "OcpMxFp8E4M3".to_string(),
        detail: detail.into(),
        remediation: MXFP8_REMEDIATION.to_string(),
    }
}
