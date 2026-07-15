use wide::f32x16;

use crate::Result;
use crate::cpu::guard::{check_finite, check_norm_positive, check_shape_2d};

pub fn cosine_batch(query: &[f32], candidates: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
    validate_batch("cosine_batch", query, candidates, dim, out)?;
    if out.is_empty() {
        return Ok(());
    }

    let query_norm = sum_squares(query).sqrt();
    check_norm_positive(query_norm, "cosine_batch", 0)?;

    for (row, score) in out.iter_mut().enumerate() {
        let candidate = candidate_row(candidates, dim, row);
        let (dot, candidate_norm_sq) = dot_and_norm(query, candidate);
        let candidate_norm = candidate_norm_sq.sqrt();
        check_norm_positive(candidate_norm, "cosine_batch", row)?;
        *score = dot / (query_norm * candidate_norm);
    }
    Ok(())
}

pub fn dot_batch(query: &[f32], candidates: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
    validate_batch("dot_batch", query, candidates, dim, out)?;
    for (row, score) in out.iter_mut().enumerate() {
        *score = dot(query, candidate_row(candidates, dim, row));
    }
    Ok(())
}

pub fn l2_batch(query: &[f32], candidates: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
    validate_batch("l2_batch", query, candidates, dim, out)?;
    for (row, score) in out.iter_mut().enumerate() {
        *score = l2_squared(query, candidate_row(candidates, dim, row));
    }
    Ok(())
}

fn validate_batch(
    op: &'static str,
    query: &[f32],
    candidates: &[f32],
    dim: usize,
    out: &[f32],
) -> Result<()> {
    check_shape_2d(query, 1, dim, "distance query")?;
    check_shape_2d(candidates, out.len(), dim, "distance candidates")?;
    check_finite(query, op)?;
    check_finite(candidates, op)?;
    Ok(())
}

fn candidate_row(candidates: &[f32], dim: usize, row: usize) -> &[f32] {
    let start = row * dim;
    &candidates[start..start + dim]
}

fn sum_squares(values: &[f32]) -> f32 {
    let mut sum = 0.0;
    let mut offset = 0;
    while offset + 16 <= values.len() {
        let chunk = load16(values, offset);
        // DETERMINISM: f32x16 chunks are reduced in ascending input-offset
        // order; each chunk contributes exactly one reduce_add() subtotal.
        sum += (chunk * chunk).reduce_add();
        offset += 16;
    }
    while offset < values.len() {
        sum += values[offset] * values[offset];
        offset += 1;
    }
    sum
}

fn dot(query: &[f32], candidate: &[f32]) -> f32 {
    let mut sum = 0.0;
    let mut offset = 0;
    while offset + 16 <= query.len() {
        sum += (load16(query, offset) * load16(candidate, offset)).reduce_add();
        offset += 16;
    }
    while offset < query.len() {
        sum += query[offset] * candidate[offset];
        offset += 1;
    }
    sum
}

fn dot_and_norm(query: &[f32], candidate: &[f32]) -> (f32, f32) {
    let mut dot_sum = 0.0;
    let mut norm_sum = 0.0;
    let mut offset = 0;
    while offset + 16 <= query.len() {
        let q = load16(query, offset);
        let c = load16(candidate, offset);
        dot_sum += (q * c).reduce_add();
        norm_sum += (c * c).reduce_add();
        offset += 16;
    }
    while offset < query.len() {
        dot_sum += query[offset] * candidate[offset];
        norm_sum += candidate[offset] * candidate[offset];
        offset += 1;
    }
    (dot_sum, norm_sum)
}

fn l2_squared(query: &[f32], candidate: &[f32]) -> f32 {
    let mut sum = 0.0;
    let mut offset = 0;
    while offset + 16 <= query.len() {
        let diff = load16(query, offset) - load16(candidate, offset);
        sum += (diff * diff).reduce_add();
        offset += 16;
    }
    while offset < query.len() {
        let diff = query[offset] - candidate[offset];
        sum += diff * diff;
        offset += 1;
    }
    sum
}

fn load16(values: &[f32], offset: usize) -> f32x16 {
    let mut lanes = [0.0; 16];
    lanes.copy_from_slice(&values[offset..offset + 16]);
    f32x16::from(lanes)
}
