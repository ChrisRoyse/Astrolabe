use cudarc::driver::CudaSlice;

use super::mxfp_path::{
    MxPackedGemmEvidence, PackedPlanStorage, check_block_count, packed_shape_error,
    validate_geometry,
};
use crate::mxfp4::validate_mxfp4_block;
use crate::{CudaContext, MXFP4_BLOCK_SIZE, MXFP4_PACKED_BYTES, MxFp4Block, Result, encode_mxfp4};

const ELEMENT: &str = "OcpMxFp4E2M1Ue8M0";
const KERNEL: &str = "gemm_mxfp4_e2m1_fp32_accum_kernel";

/// A reusable packed OCP MXFP4 GEMM plan.
///
/// The plan owns resident device buffers for row-major A, column-major B, and
/// their K-axis UE8M0 scales. Repeated executions reuse those buffers and the
/// cached sm_120 CUBIN/function; operands are never decoded to F32.
pub struct MxFp4GemmPlan {
    inner: PackedPlanStorage,
}

impl MxFp4GemmPlan {
    pub fn upload(
        ctx: &CudaContext,
        a_blocks: &[MxFp4Block],
        b_blocks: &[MxFp4Block],
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<Self> {
        let k_blocks = validate_mxfp4_matrix_blocks(a_blocks, b_blocks, m, k, n)?;
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

/// Packs a row-major MxK F32 matrix into OCP MXFP4 K-axis blocks.
pub fn pack_mxfp4_a_row_major(values: &[f32], m: usize, k: usize) -> Result<Vec<MxFp4Block>> {
    pack_k_axis(values, m, k, "A row-major")
}

/// Packs a column-major KxN F32 matrix into OCP MXFP4 K-axis blocks.
///
/// Each B column is contiguous, so this has the same physical vector layout as
/// A's rows while preserving the TN contract required by native SM120 MMA.
pub fn pack_mxfp4_b_column_major(values: &[f32], k: usize, n: usize) -> Result<Vec<MxFp4Block>> {
    pack_k_axis(values, n, k, "B column-major")
}

/// One-shot native MXFP4 dispatch. Use [`MxFp4GemmPlan`] for repeated GEMMs.
pub fn gemm_mxfp4_fp32_accum(
    ctx: &CudaContext,
    a_blocks: &[MxFp4Block],
    b_blocks: &[MxFp4Block],
    m: usize,
    k: usize,
    n: usize,
    out: &mut CudaSlice<f32>,
) -> Result<()> {
    let mut plan = MxFp4GemmPlan::upload(ctx, a_blocks, b_blocks, m, k, n)?;
    plan.execute(ctx, out)
}

fn validate_mxfp4_matrix_blocks(
    a_blocks: &[MxFp4Block],
    b_blocks: &[MxFp4Block],
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
    blocks: &[MxFp4Block],
    vectors: usize,
    k: usize,
    k_blocks: usize,
    side: &'static str,
) -> Result<()> {
    for vector in 0..vectors {
        for block in 0..k_blocks {
            let valid = (k - block * MXFP4_BLOCK_SIZE).min(MXFP4_BLOCK_SIZE);
            validate_mxfp4_block(
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
) -> Result<Vec<MxFp4Block>> {
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
    let mut blocks = Vec::with_capacity(vectors * k.div_ceil(MXFP4_BLOCK_SIZE));
    for vector in values.chunks_exact(k) {
        blocks.extend(encode_mxfp4(vector)?);
    }
    Ok(blocks)
}

fn flatten_blocks(blocks: &[MxFp4Block]) -> (Vec<u8>, Vec<u8>) {
    let mut codes = Vec::with_capacity(blocks.len() * MXFP4_PACKED_BYTES);
    let mut scales = Vec::with_capacity(blocks.len());
    for block in blocks {
        codes.extend_from_slice(&block.codes);
        scales.push(block.scale_e8m0);
    }
    (codes, scales)
}
