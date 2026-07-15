use wide::f32x16;

use crate::cpu::guard::{check_finite, check_norm_positive, check_shape_2d};
use crate::{ForgeError, Result};

pub fn normalize_f32(vecs: &mut [f32], dim: usize) -> Result<()> {
    if dim == 0 {
        if vecs.is_empty() {
            return Ok(());
        }
        return Err(ForgeError::ShapeMismatch {
            expected: vec![0],
            got: vec![vecs.len()],
            remediation: "dim=0 is valid only for an empty matrix".to_string(),
        });
    }
    if !vecs.len().is_multiple_of(dim) {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![dim],
            got: vec![vecs.len()],
            remediation: "normalize input length must be an integer number of rows".to_string(),
        });
    }
    let rows = vecs.len() / dim;
    check_shape_2d(vecs, rows, dim, "normalize input")?;
    check_finite(vecs, "normalize")?;

    for row in 0..rows {
        let start = row * dim;
        let end = start + dim;
        let norm_sq = sum_squares(&vecs[start..end]);
        let norm = norm_sq.sqrt();
        check_norm_positive(norm, "normalize", row)?;
        scale_row(&mut vecs[start..end], 1.0 / norm);
    }
    Ok(())
}

fn sum_squares(values: &[f32]) -> f32 {
    let mut sum = 0.0;
    let mut offset = 0;
    while offset + 16 <= values.len() {
        let chunk = load16(values, offset);
        // DETERMINISM: row elements are consumed in ascending offset order; each
        // f32x16 chunk contributes one reduce_add() subtotal before scalar tail.
        sum += (chunk * chunk).reduce_add();
        offset += 16;
    }
    while offset < values.len() {
        sum += values[offset] * values[offset];
        offset += 1;
    }
    sum
}

fn scale_row(values: &mut [f32], scale: f32) {
    let scale_vec = f32x16::splat(scale);
    let mut offset = 0;
    while offset + 16 <= values.len() {
        let scaled = load16(values, offset) * scale_vec;
        values[offset..offset + 16].copy_from_slice(&scaled.to_array());
        offset += 16;
    }
    while offset < values.len() {
        values[offset] *= scale;
        offset += 1;
    }
}

fn load16(values: &[f32], offset: usize) -> f32x16 {
    let mut lanes = [0.0; 16];
    lanes.copy_from_slice(&values[offset..offset + 16]);
    f32x16::from(lanes)
}
