use crate::{ForgeError, Result};

const NUMERICAL_REMEDIATION: &str =
    "Ensure all input vectors are normalized finite f32; check upstream embedding model output";

pub fn check_finite(slice: &[f32], op: &str) -> Result<()> {
    for (index, value) in slice.iter().enumerate() {
        if !value.is_finite() {
            return Err(ForgeError::NumericalInvariant {
                op: op.to_string(),
                detail: format!("non-finite f32 at index {index}: {value}"),
                remediation: NUMERICAL_REMEDIATION.to_string(),
            });
        }
    }
    Ok(())
}

pub fn check_norm_positive(norm: f32, op: &str, row: usize) -> Result<()> {
    if norm > 0.0 && norm.is_finite() {
        return Ok(());
    }
    Err(ForgeError::NumericalInvariant {
        op: op.to_string(),
        detail: format!("zero or non-finite norm at row {row}"),
        remediation: NUMERICAL_REMEDIATION.to_string(),
    })
}

pub fn check_shape_2d(slice: &[f32], rows: usize, cols: usize, name: &str) -> Result<()> {
    let expected_len = rows
        .checked_mul(cols)
        .ok_or_else(|| ForgeError::ShapeMismatch {
            expected: vec![rows, cols],
            got: vec![slice.len()],
            remediation: format!("{name} shape overflows usize"),
        })?;
    if slice.len() == expected_len {
        return Ok(());
    }
    Err(ForgeError::ShapeMismatch {
        expected: vec![rows, cols],
        got: vec![slice.len()],
        remediation: format!("{name} length does not match rows*cols"),
    })
}
