use wide::f32x8;

use crate::{
    ForgeError, MXFP4_BLOCK_SIZE, MXFP4_MAX_DIM, MXFP8_BLOCK_SIZE, MXFP8_MAX_DIM, MxFp4Block,
    MxFp8Block, Result, decode_e2m1, decode_e4m3, decode_e8m0, nibble_at, validate_mxfp4_blocks,
    validate_mxfp8_blocks,
};

const CPU_MX_GEMM_MAX_MATRIX_ELEMENTS: usize = 1 << 28;
const CPU_MX_REMEDIATION: &str = "Supply finite canonical OCP MX K-axis blocks for row-major A and column-major B, with non-empty dimensions inside the format limits; do not materialize whole F32 operands or silently switch backends";

/// Multiplies packed OCP MXFP4 matrices directly on the CPU.
///
/// A is M row-vectors and B is N column-vectors, each stored as consecutive
/// 32-value K-axis blocks. The inner loop decodes only eight register lanes at
/// a time and uses the native `f32x8` SIMD path; no operand-wide F32 buffer is
/// allocated. Output is column-major MxN.
pub fn gemm_mxfp4_packed(
    a_blocks: &[MxFp4Block],
    b_blocks: &[MxFp4Block],
    m: usize,
    k: usize,
    n: usize,
    out: &mut [f32],
) -> Result<()> {
    let k_blocks = validate_geometry("OcpMxFp4E2M1Ue8M0", m, k, n, out.len(), MXFP4_MAX_DIM)?;
    validate_fp4_matrix(a_blocks, m, k, k_blocks, "A")?;
    validate_fp4_matrix(b_blocks, n, k, k_blocks, "B")?;
    for col in 0..n {
        let b = &b_blocks[col * k_blocks..(col + 1) * k_blocks];
        for row in 0..m {
            let a = &a_blocks[row * k_blocks..(row + 1) * k_blocks];
            out[col * m + row] = dot_fp4_blocks(a, b, k)?;
        }
    }
    Ok(())
}

/// Direct packed OCP MXFP8 E4M3 CPU GEMM with the same K-axis contract.
pub fn gemm_mxfp8_packed(
    a_blocks: &[MxFp8Block],
    b_blocks: &[MxFp8Block],
    m: usize,
    k: usize,
    n: usize,
    out: &mut [f32],
) -> Result<()> {
    let k_blocks = validate_geometry("OcpMxFp8E4M3Ue8M0", m, k, n, out.len(), MXFP8_MAX_DIM)?;
    validate_fp8_matrix(a_blocks, m, k, k_blocks, "A")?;
    validate_fp8_matrix(b_blocks, n, k, k_blocks, "B")?;
    for col in 0..n {
        let b = &b_blocks[col * k_blocks..(col + 1) * k_blocks];
        for row in 0..m {
            let a = &a_blocks[row * k_blocks..(row + 1) * k_blocks];
            out[col * m + row] = dot_fp8_blocks(a, b, k)?;
        }
    }
    Ok(())
}

fn dot_fp4_blocks(a: &[MxFp4Block], b: &[MxFp4Block], k: usize) -> Result<f32> {
    let mut dot = 0.0_f32;
    for block in 0..a.len() {
        let scale_a = decode_e8m0(a[block].scale_e8m0)?;
        let scale_b = decode_e8m0(b[block].scale_e8m0)?;
        let valid = (k - block * MXFP4_BLOCK_SIZE).min(MXFP4_BLOCK_SIZE);
        let mut lane = 0;
        while lane + 8 <= valid {
            let mut values_a = [0.0_f32; 8];
            let mut values_b = [0.0_f32; 8];
            for offset in 0..8 {
                values_a[offset] = decode_e2m1(nibble_at(&a[block].codes, lane + offset)) * scale_a;
                values_b[offset] = decode_e2m1(nibble_at(&b[block].codes, lane + offset)) * scale_b;
            }
            dot += (f32x8::from(values_a) * f32x8::from(values_b)).reduce_add();
            lane += 8;
        }
        while lane < valid {
            let left = decode_e2m1(nibble_at(&a[block].codes, lane)) * scale_a;
            let right = decode_e2m1(nibble_at(&b[block].codes, lane)) * scale_b;
            dot = left.mul_add(right, dot);
            lane += 1;
        }
    }
    ensure_finite_dot("OcpMxFp4E2M1Ue8M0", dot)
}

fn dot_fp8_blocks(a: &[MxFp8Block], b: &[MxFp8Block], k: usize) -> Result<f32> {
    let mut dot = 0.0_f32;
    for block in 0..a.len() {
        let scale_a = decode_e8m0(a[block].scale_e8m0)?;
        let scale_b = decode_e8m0(b[block].scale_e8m0)?;
        let valid = (k - block * MXFP8_BLOCK_SIZE).min(MXFP8_BLOCK_SIZE);
        let mut lane = 0;
        while lane + 8 <= valid {
            let mut values_a = [0.0_f32; 8];
            let mut values_b = [0.0_f32; 8];
            for offset in 0..8 {
                values_a[offset] = decode_e4m3(a[block].codes[lane + offset])? * scale_a;
                values_b[offset] = decode_e4m3(b[block].codes[lane + offset])? * scale_b;
            }
            dot += (f32x8::from(values_a) * f32x8::from(values_b)).reduce_add();
            lane += 8;
        }
        while lane < valid {
            let left = decode_e4m3(a[block].codes[lane])? * scale_a;
            let right = decode_e4m3(b[block].codes[lane])? * scale_b;
            dot = left.mul_add(right, dot);
            lane += 1;
        }
    }
    ensure_finite_dot("OcpMxFp8E4M3Ue8M0", dot)
}

fn validate_fp4_matrix(
    blocks: &[MxFp4Block],
    vectors: usize,
    k: usize,
    k_blocks: usize,
    side: &'static str,
) -> Result<()> {
    validate_block_count("OcpMxFp4E2M1Ue8M0", blocks.len(), vectors, k_blocks, side)?;
    for vector in 0..vectors {
        validate_mxfp4_blocks(&blocks[vector * k_blocks..(vector + 1) * k_blocks], k).map_err(
            |error| {
                mx_error(
                    "OcpMxFp4E2M1Ue8M0",
                    format!("{side} vector {vector} is invalid: {error}"),
                )
            },
        )?;
    }
    Ok(())
}

fn validate_fp8_matrix(
    blocks: &[MxFp8Block],
    vectors: usize,
    k: usize,
    k_blocks: usize,
    side: &'static str,
) -> Result<()> {
    validate_block_count("OcpMxFp8E4M3Ue8M0", blocks.len(), vectors, k_blocks, side)?;
    for vector in 0..vectors {
        validate_mxfp8_blocks(&blocks[vector * k_blocks..(vector + 1) * k_blocks], k).map_err(
            |error| {
                mx_error(
                    "OcpMxFp8E4M3Ue8M0",
                    format!("{side} vector {vector} is invalid: {error}"),
                )
            },
        )?;
    }
    Ok(())
}

fn validate_geometry(
    element: &'static str,
    m: usize,
    k: usize,
    n: usize,
    out_len: usize,
    max_dim: usize,
) -> Result<usize> {
    if m == 0 || k == 0 || n == 0 || m > max_dim || k > max_dim || n > max_dim {
        return Err(mx_error(
            element,
            format!("shape [{m},{k},{n}] must be non-empty with every dimension <= {max_dim}"),
        ));
    }
    let a_elements = m
        .checked_mul(k)
        .ok_or_else(|| mx_error(element, "A shape overflow"))?;
    let b_elements = k
        .checked_mul(n)
        .ok_or_else(|| mx_error(element, "B shape overflow"))?;
    let output_elements = m
        .checked_mul(n)
        .ok_or_else(|| mx_error(element, "output shape overflow"))?;
    if a_elements > CPU_MX_GEMM_MAX_MATRIX_ELEMENTS
        || b_elements > CPU_MX_GEMM_MAX_MATRIX_ELEMENTS
        || output_elements > CPU_MX_GEMM_MAX_MATRIX_ELEMENTS
    {
        return Err(mx_error(
            element,
            format!(
                "shape [{m},{k},{n}] exceeds the configured {CPU_MX_GEMM_MAX_MATRIX_ELEMENTS}-element matrix limit"
            ),
        ));
    }
    if out_len != output_elements {
        return Err(mx_error(
            element,
            format!("output length mismatch: expected {output_elements}, got {out_len}"),
        ));
    }
    Ok(k.div_ceil(32))
}

fn validate_block_count(
    element: &'static str,
    actual: usize,
    vectors: usize,
    k_blocks: usize,
    side: &'static str,
) -> Result<()> {
    let expected = vectors
        .checked_mul(k_blocks)
        .ok_or_else(|| mx_error(element, format!("{side} block count overflow")))?;
    if actual == expected {
        Ok(())
    } else {
        Err(mx_error(
            element,
            format!("{side} K-axis block count mismatch: expected {expected}, got {actual}"),
        ))
    }
}

fn ensure_finite_dot(element: &'static str, dot: f32) -> Result<f32> {
    if dot.is_finite() {
        Ok(dot)
    } else {
        Err(ForgeError::NumericalInvariant {
            op: format!("cpu_packed_gemm dtype={element}"),
            detail: "packed SIMD accumulation produced a non-finite output".to_string(),
            remediation: CPU_MX_REMEDIATION.to_string(),
        })
    }
}

fn mx_error(element: &'static str, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: "cpu_packed_gemm backend=cpu".to_string(),
        level: element.to_string(),
        detail: detail.into(),
        remediation: CPU_MX_REMEDIATION.to_string(),
    }
}
