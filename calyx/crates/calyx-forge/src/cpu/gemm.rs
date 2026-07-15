use wide::{f32x8, f32x16};

use crate::Result;
use crate::cpu::guard::{check_finite, check_shape_2d};

pub const TILE_M: usize = 64;
pub const TILE_K: usize = 64;

pub fn gemm_f32(a: &[f32], b: &[f32], m: usize, k: usize, n: usize, out: &mut [f32]) -> Result<()> {
    validate_gemm_inputs(a, b, m, k, n, out)?;
    out.fill(0.0);
    if m == 0 || n == 0 {
        return Ok(());
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return gemm_tiled_f32x16(a, b, m, k, n, out);
        }
    }

    gemm_tiled_f32x8(a, b, m, k, n, out)
}

fn validate_gemm_inputs(
    a: &[f32],
    b: &[f32],
    m: usize,
    k: usize,
    n: usize,
    out: &[f32],
) -> Result<()> {
    check_shape_2d(a, m, k, "gemm A")?;
    check_shape_2d(b, k, n, "gemm B")?;
    check_shape_2d(out, m, n, "gemm output")?;
    check_finite(a, "cpu.gemm")?;
    check_finite(b, "cpu.gemm")?;
    Ok(())
}

fn gemm_tiled_f32x16(
    a: &[f32],
    b: &[f32],
    m: usize,
    k: usize,
    n: usize,
    out: &mut [f32],
) -> Result<()> {
    for col_tile in 0..n {
        for row_tile in (0..m).step_by(TILE_M) {
            let row_end = (row_tile + TILE_M).min(m);
            for row in row_tile..row_end {
                out[col_major(row, col_tile, m)] = dot_f32x16(a, b, row, col_tile, m, k);
            }
        }
    }
    Ok(())
}

fn gemm_tiled_f32x8(
    a: &[f32],
    b: &[f32],
    m: usize,
    k: usize,
    n: usize,
    out: &mut [f32],
) -> Result<()> {
    for col_tile in 0..n {
        for row_tile in (0..m).step_by(TILE_M) {
            let row_end = (row_tile + TILE_M).min(m);
            for row in row_tile..row_end {
                out[col_major(row, col_tile, m)] = dot_f32x8(a, b, row, col_tile, m, k);
            }
        }
    }
    Ok(())
}

fn dot_f32x16(a: &[f32], b: &[f32], row: usize, col: usize, m: usize, k: usize) -> f32 {
    let mut sum = 0.0;
    let mut depth_tile = 0;
    while depth_tile < k {
        let depth_end = (depth_tile + TILE_K).min(k);
        let mut depth = depth_tile;
        while depth + 16 <= depth_end {
            let mut a_lane = [0.0; 16];
            let mut b_lane = [0.0; 16];
            for lane in 0..16 {
                let d = depth + lane;
                a_lane[lane] = a[col_major(row, d, m)];
                b_lane[lane] = b[col_major(d, col, k)];
            }
            // DETERMINISM: keep the AVX512 lane multiply, then reduce as two
            // explicit f32x8-compatible subtotals. A full f32x16 tree reduction
            // drifts from cuBLAS in near-zero cancellation cells.
            let products = (f32x16::from(a_lane) * f32x16::from(b_lane)).to_array();
            for lane_chunk in products.chunks_exact(8) {
                let mut subtotal = 0.0;
                for product in lane_chunk {
                    subtotal += *product;
                }
                sum += subtotal;
            }
            depth += 16;
        }
        while depth < depth_end {
            sum += a[col_major(row, depth, m)] * b[col_major(depth, col, k)];
            depth += 1;
        }
        depth_tile += TILE_K;
    }
    sum
}

fn dot_f32x8(a: &[f32], b: &[f32], row: usize, col: usize, m: usize, k: usize) -> f32 {
    let mut sum = 0.0;
    let mut depth_tile = 0;
    while depth_tile < k {
        let depth_end = (depth_tile + TILE_K).min(k);
        let mut depth = depth_tile;
        while depth + 8 <= depth_end {
            let mut a_lane = [0.0; 8];
            let mut b_lane = [0.0; 8];
            for lane in 0..8 {
                let d = depth + lane;
                a_lane[lane] = a[col_major(row, d, m)];
                b_lane[lane] = b[col_major(d, col, k)];
            }
            sum += (f32x8::from(a_lane) * f32x8::from(b_lane)).reduce_add();
            depth += 8;
        }
        while depth < depth_end {
            sum += a[col_major(row, depth, m)] * b[col_major(depth, col, k)];
            depth += 1;
        }
        depth_tile += TILE_K;
    }
    sum
}

fn col_major(row: usize, col: usize, rows: usize) -> usize {
    col * rows + row
}
