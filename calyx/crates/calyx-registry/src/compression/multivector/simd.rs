use calyx_core::Result;

use super::{CALYX_MULTIVECTOR_PACK_INVALID, multivector_error};

/// Runtime label persisted in reports and exposed for FSV inspection.
pub const fn packed_maxsim_backend() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64-sse2"
    } else {
        "unsupported"
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) fn dot(left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!(
                "SIMD dot operands have different lengths {} and {}",
                left.len(),
                right.len()
            ),
        ));
    }
    // SAFETY: x86_64 guarantees SSE2. `_mm_loadu_ps` accepts unaligned
    // pointers, the loop stays inside both equal-length slices, and the scalar
    // tail covers the remainder.
    Ok(unsafe { dot_sse2(left, right) })
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn dot(_left: &[f32], _right: &[f32]) -> Result<f32> {
    Err(multivector_error(
        CALYX_MULTIVECTOR_PACK_INVALID,
        "direct packed MaxSim requires the commissioned x86_64 SSE2 backend on the current Windows target",
    ))
}

pub(super) fn normalize(values: &mut [f32]) -> Result<()> {
    let norm_sq = dot(values, values)?;
    if !norm_sq.is_finite() || norm_sq <= 0.0 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!("token has invalid squared L2 norm {norm_sq}"),
        ));
    }
    let inverse = norm_sq.sqrt().recip();
    for value in values {
        *value *= inverse;
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn dot_sse2(left: &[f32], right: &[f32]) -> f32 {
    use std::arch::x86_64::{
        __m128, _mm_add_ps, _mm_loadu_ps, _mm_mul_ps, _mm_setzero_ps, _mm_storeu_ps,
    };

    let mut sum: __m128 = _mm_setzero_ps();
    let chunks = left.len() / 4;
    for index in 0..chunks {
        let offset = index * 4;
        // SAFETY: `offset + 4 <= len` by the `chunks` bound.
        let a = unsafe { _mm_loadu_ps(left.as_ptr().add(offset)) };
        // SAFETY: the slices have equal lengths and the same bound applies.
        let b = unsafe { _mm_loadu_ps(right.as_ptr().add(offset)) };
        sum = _mm_add_ps(sum, _mm_mul_ps(a, b));
    }
    let mut lanes = [0.0_f32; 4];
    // SAFETY: `lanes` has exactly four writable f32 values.
    unsafe { _mm_storeu_ps(lanes.as_mut_ptr(), sum) };
    let mut total = lanes.into_iter().sum::<f32>();
    for index in chunks * 4..left.len() {
        total += left[index] * right[index];
    }
    total
}
