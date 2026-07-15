use crate::Result;
use crate::cpu::check_finite;

pub const MXFP4_BLOCK_SIZE: usize = 32;
pub const MXFP4_PACKED_BYTES: usize = MXFP4_BLOCK_SIZE / 2;
const MXFP4_EXP_BIAS: i32 = 127;
const MXFP4_MAX_SIGNED_CODE: i8 = 7;
const MXFP4_ZERO_CODE: u8 = 7;
const MXFP4_NAN_CODE: u8 = 15;

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
    let scale_e8m0 = scale_byte(abs_max);
    let scale = e8m0_scale(scale_e8m0);
    let mut codes = [0; MXFP4_PACKED_BYTES];
    for (idx, value) in block.iter().enumerate() {
        let code = quantize_code(*value, scale);
        if idx.is_multiple_of(2) {
            codes[idx / 2] |= code;
        } else {
            codes[idx / 2] |= code << 4;
        }
    }
    Ok(MxFp4Block { codes, scale_e8m0 })
}

pub fn decode_mxfp4_block(block: &MxFp4Block) -> [f32; MXFP4_BLOCK_SIZE] {
    let mut decoded = [0.0; MXFP4_BLOCK_SIZE];
    let scale = e8m0_scale(block.scale_e8m0);
    for (idx, slot) in decoded.iter_mut().enumerate() {
        *slot = decode_code(nibble_at(&block.codes, idx), scale);
    }
    decoded
}

pub fn encode_mxfp4(vec: &[f32]) -> Result<Vec<MxFp4Block>> {
    check_finite(vec, "mxfp4_encode")?;
    if vec.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(vec.len().div_ceil(MXFP4_BLOCK_SIZE));
    for chunk in vec.chunks(MXFP4_BLOCK_SIZE) {
        let mut block = [0.0; MXFP4_BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);
        out.push(encode_mxfp4_block(&block)?);
    }
    Ok(out)
}

pub fn decode_mxfp4(blocks: &[MxFp4Block], original_dim: usize) -> Vec<f32> {
    let mut decoded = Vec::with_capacity(blocks.len() * MXFP4_BLOCK_SIZE);
    for block in blocks {
        decoded.extend_from_slice(&decode_mxfp4_block(block));
    }
    decoded.truncate(original_dim);
    decoded
}

pub fn e8m0_scale(scale_e8m0: u8) -> f32 {
    2.0_f32.powi(i32::from(scale_e8m0) - MXFP4_EXP_BIAS)
}

fn scale_byte(abs_max: f32) -> u8 {
    if abs_max == 0.0 {
        return 0;
    }
    let exponent = (abs_max.log2().floor() as i32).clamp(-127, 127);
    (exponent + MXFP4_EXP_BIAS) as u8
}

fn quantize_code(value: f32, scale: f32) -> u8 {
    if value == 0.0 {
        return MXFP4_ZERO_CODE;
    }
    let mut signed =
        ((value / scale).clamp(-1.0, 1.0) * f32::from(MXFP4_MAX_SIGNED_CODE)).round() as i8;
    if signed == 0 {
        signed = if value.is_sign_positive() { 1 } else { -1 };
    }
    (signed + MXFP4_ZERO_CODE as i8) as u8
}

fn decode_code(code: u8, scale: f32) -> f32 {
    if code == MXFP4_NAN_CODE {
        return 0.0;
    }
    let signed = code.clamp(0, 14) as i8 - MXFP4_ZERO_CODE as i8;
    f32::from(signed) * scale / f32::from(MXFP4_MAX_SIGNED_CODE)
}

fn nibble_at(codes: &[u8; MXFP4_PACKED_BYTES], idx: usize) -> u8 {
    let byte = codes[idx / 2];
    if idx.is_multiple_of(2) {
        byte & 0x0f
    } else {
        byte >> 4
    }
}
