use cudarc::driver::CudaSlice;

use super::mxfp_path::{
    MxPackedGemmEvidence, PackedPlanStorage, check_block_count, packed_shape_error,
    validate_geometry,
};
use crate::mxfp8::validate_mxfp8_block;
use crate::{CudaContext, MXFP8_BLOCK_SIZE, MxFp8Block, Result, encode_mxfp8};

const ELEMENT: &str = "OcpMxFp8E4M3Ue8M0";
const KERNEL: &str = "gemm_mxfp8_e4m3_fp32_accum_kernel";

/// A reusable resident OCP MXFP8 E4M3 GEMM plan for native sm_120 MMA.
pub struct MxFp8GemmPlan {
    inner: PackedPlanStorage,
}

impl MxFp8GemmPlan {
    pub fn upload(
        ctx: &CudaContext,
        a_blocks: &[MxFp8Block],
        b_blocks: &[MxFp8Block],
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<Self> {
        let k_blocks = validate_mxfp8_matrix_blocks(a_blocks, b_blocks, m, k, n)?;
        let (a_codes, a_scales) = flatten_blocks(a_blocks);
        let (b_codes, b_scales) = flatten_blocks(b_blocks);
        Ok(Self {
            inner: PackedPlanStorage::upload(
                ctx, ELEMENT, KERNEL, m, k, n, k_blocks, &a_codes, &a_scales, &b_codes, &b_scales,
            )?,
        })
    }

    pub fn execute(&mut self, ctx: &CudaContext, out: &mut CudaSlice<f32>) -> Result<()> {
        self.inner.execute(ctx, out)
    }

    pub fn evidence(&self) -> MxPackedGemmEvidence {
        self.inner.evidence()
    }
}

pub fn pack_mxfp8_a_row_major(values: &[f32], m: usize, k: usize) -> Result<Vec<MxFp8Block>> {
    pack_k_axis(values, m, k, "A row-major")
}

pub fn pack_mxfp8_b_column_major(values: &[f32], k: usize, n: usize) -> Result<Vec<MxFp8Block>> {
    pack_k_axis(values, n, k, "B column-major")
}

/// One-shot native MXFP8 dispatch. Use [`MxFp8GemmPlan`] for repeated GEMMs.
pub fn gemm_mxfp8_fp32_accum(
    ctx: &CudaContext,
    a_blocks: &[MxFp8Block],
    b_blocks: &[MxFp8Block],
    m: usize,
    k: usize,
    n: usize,
    out: &mut CudaSlice<f32>,
) -> Result<()> {
    let mut plan = MxFp8GemmPlan::upload(ctx, a_blocks, b_blocks, m, k, n)?;
    plan.execute(ctx, out)
}

fn validate_mxfp8_matrix_blocks(
    a_blocks: &[MxFp8Block],
    b_blocks: &[MxFp8Block],
    m: usize,
    k: usize,
    n: usize,
) -> Result<usize> {
    let k_blocks = validate_geometry(ELEMENT, m, k, n)?;
    let expected_a = m
        .checked_mul(k_blocks)
        .ok_or_else(|| packed_shape_error(ELEMENT, [m, k, n], "A block count overflow"))?;
    let expected_b = n
        .checked_mul(k_blocks)
        .ok_or_else(|| packed_shape_error(ELEMENT, [m, k, n], "B block count overflow"))?;
    check_block_count(ELEMENT, [m, k, n], "A", a_blocks.len(), expected_a)?;
    check_block_count(ELEMENT, [m, k, n], "B", b_blocks.len(), expected_b)?;
    validate_vectors(a_blocks, m, k, k_blocks, "A")?;
    validate_vectors(b_blocks, n, k, k_blocks, "B")?;
    Ok(k_blocks)
}

fn validate_vectors(
    blocks: &[MxFp8Block],
    vectors: usize,
    k: usize,
    k_blocks: usize,
    side: &'static str,
) -> Result<()> {
    for vector in 0..vectors {
        for block in 0..k_blocks {
            let valid = (k - block * MXFP8_BLOCK_SIZE).min(MXFP8_BLOCK_SIZE);
            validate_mxfp8_block(
                &blocks[vector * k_blocks + block],
                valid,
                block + 1 == k_blocks,
            )
            .map_err(|error| {
                packed_shape_error(
                    ELEMENT,
                    [vectors, k, 0],
                    format!("{side} vector {vector} block {block} is not canonical: {error}"),
                )
            })?;
        }
    }
    Ok(())
}

fn pack_k_axis(
    values: &[f32],
    vectors: usize,
    k: usize,
    side: &'static str,
) -> Result<Vec<MxFp8Block>> {
    if vectors == 0 || k == 0 {
        return Err(packed_shape_error(
            ELEMENT,
            [vectors, k, 0],
            format!("{side} dimensions must be non-empty"),
        ));
    }
    let expected = vectors.checked_mul(k).ok_or_else(|| {
        packed_shape_error(ELEMENT, [vectors, k, 0], format!("{side} length overflow"))
    })?;
    if values.len() != expected {
        return Err(packed_shape_error(
            ELEMENT,
            [vectors, k, 0],
            format!(
                "{side} length mismatch: expected {expected}, got {}",
                values.len()
            ),
        ));
    }
    let mut blocks = Vec::with_capacity(vectors * k.div_ceil(MXFP8_BLOCK_SIZE));
    for vector in values.chunks_exact(k) {
        blocks.extend(encode_mxfp8(vector)?);
    }
    Ok(blocks)
}

fn flatten_blocks(blocks: &[MxFp8Block]) -> (Vec<u8>, Vec<u8>) {
    let mut codes = Vec::with_capacity(blocks.len() * MXFP8_BLOCK_SIZE);
    let mut scales = Vec::with_capacity(blocks.len());
    for block in blocks {
        codes.extend_from_slice(&block.codes);
        scales.push(block.scale_e8m0);
    }
    (codes, scales)
}
