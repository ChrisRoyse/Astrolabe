//! CPU backends for accumulating rows directly from the static-lookup mmap.

use super::StaticLookupDType;

/// Active row-accumulation backend selected once when the mmap is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticLookupBackend {
    /// AVX2 for INT8/F32, and AVX2 + F16C for F16.
    Avx2,
    /// Portable finite-value implementation used when the required CPU feature
    /// set is not present.
    Scalar,
}

impl StaticLookupBackend {
    /// Stable execution-attestation token for this backend.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avx2 => "avx2",
            Self::Scalar => "scalar",
        }
    }
}

pub(super) fn detect(dtype: StaticLookupDType) -> StaticLookupBackend {
    #[cfg(target_arch = "x86_64")]
    {
        let avx2 = std::arch::is_x86_feature_detected!("avx2");
        let dtype_supported =
            dtype != StaticLookupDType::F16 || std::arch::is_x86_feature_detected!("f16c");
        if avx2 && dtype_supported {
            return StaticLookupBackend::Avx2;
        }
    }
    StaticLookupBackend::Scalar
}

pub(super) fn add_i8(out: &mut [f32], codes: &[u8], scale: f32, backend: StaticLookupBackend) {
    #[cfg(target_arch = "x86_64")]
    if backend == StaticLookupBackend::Avx2 {
        // SAFETY: backend selection proved AVX2 support; slices are equal length
        // and the implementation uses unaligned, bounds-checked chunk loads.
        unsafe { add_i8_avx2(out, codes, scale) };
        return;
    }
    for (dst, raw) in out.iter_mut().zip(codes) {
        *dst += (*raw as i8) as f32 * scale;
    }
}

pub(super) fn add_f16(out: &mut [f32], bytes: &[u8], backend: StaticLookupBackend) {
    #[cfg(target_arch = "x86_64")]
    if backend == StaticLookupBackend::Avx2 {
        // SAFETY: backend selection proved AVX2+F16C support; the function uses
        // unaligned loads and consumes exactly two bytes per output value.
        unsafe { add_f16_avx2(out, bytes) };
        return;
    }
    for (dst, chunk) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *dst += f16_to_f32(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
}

pub(super) fn add_f32(out: &mut [f32], bytes: &[u8], backend: StaticLookupBackend) {
    #[cfg(target_arch = "x86_64")]
    if backend == StaticLookupBackend::Avx2 {
        // SAFETY: backend selection proved AVX2 support; the function uses
        // unaligned loads and consumes exactly four bytes per output value.
        unsafe { add_f32_avx2(out, bytes) };
        return;
    }
    for (dst, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *dst += f32::from_le_bytes(chunk.try_into().expect("f32 row bytes"));
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn add_i8_avx2(out: &mut [f32], codes: &[u8], scale: f32) {
    use std::arch::x86_64::{
        __m128i, _mm_loadl_epi64, _mm256_add_ps, _mm256_cvtepi8_epi32, _mm256_cvtepi32_ps,
        _mm256_loadu_ps, _mm256_mul_ps, _mm256_set1_ps, _mm256_storeu_ps,
    };

    let mut index = 0;
    let scale8 = _mm256_set1_ps(scale);
    while index + 8 <= out.len() {
        // SAFETY: the loop bounds prove eight source and destination elements.
        unsafe {
            let packed = _mm_loadl_epi64(codes.as_ptr().add(index).cast::<__m128i>());
            let values = _mm256_mul_ps(_mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(packed)), scale8);
            let previous = _mm256_loadu_ps(out.as_ptr().add(index));
            _mm256_storeu_ps(out.as_mut_ptr().add(index), _mm256_add_ps(previous, values));
        }
        index += 8;
    }
    for (dst, raw) in out[index..].iter_mut().zip(&codes[index..]) {
        *dst += (*raw as i8) as f32 * scale;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,f16c")]
unsafe fn add_f16_avx2(out: &mut [f32], bytes: &[u8]) {
    use std::arch::x86_64::{
        __m128i, _mm_loadu_si128, _mm256_add_ps, _mm256_cvtph_ps, _mm256_loadu_ps, _mm256_storeu_ps,
    };

    let mut index = 0;
    while index + 8 <= out.len() {
        // SAFETY: the loop bounds prove sixteen source bytes and eight outputs.
        unsafe {
            let packed = _mm_loadu_si128(bytes.as_ptr().add(index * 2).cast::<__m128i>());
            let values = _mm256_cvtph_ps(packed);
            let previous = _mm256_loadu_ps(out.as_ptr().add(index));
            _mm256_storeu_ps(out.as_mut_ptr().add(index), _mm256_add_ps(previous, values));
        }
        index += 8;
    }
    for (dst, chunk) in out[index..]
        .iter_mut()
        .zip(bytes[index * 2..].chunks_exact(2))
    {
        *dst += f16_to_f32(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn add_f32_avx2(out: &mut [f32], bytes: &[u8]) {
    use std::arch::x86_64::{_mm256_add_ps, _mm256_loadu_ps, _mm256_storeu_ps};

    let mut index = 0;
    while index + 8 <= out.len() {
        // SAFETY: the loop bounds prove 32 source bytes and eight outputs.
        unsafe {
            let values = _mm256_loadu_ps(bytes.as_ptr().add(index * 4).cast::<f32>());
            let previous = _mm256_loadu_ps(out.as_ptr().add(index));
            _mm256_storeu_ps(out.as_mut_ptr().add(index), _mm256_add_ps(previous, values));
        }
        index += 8;
    }
    for (dst, chunk) in out[index..]
        .iter_mut()
        .zip(bytes[index * 4..].chunks_exact(4))
    {
        *dst += f32::from_le_bytes(chunk.try_into().expect("f32 row bytes"));
    }
}

pub(super) fn f16_to_f32(bits: u16) -> f32 {
    let sign = ((bits & 0x8000) as u32) << 16;
    let exp = (bits >> 10) & 0x1f;
    let frac = (bits & 0x03ff) as u32;
    let value = match exp {
        0 if frac == 0 => sign,
        0 => {
            let mut mant = frac;
            let mut exponent = -14_i32;
            while mant & 0x0400 == 0 {
                mant <<= 1;
                exponent -= 1;
            }
            mant &= 0x03ff;
            sign | (((exponent + 127) as u32) << 23) | (mant << 13)
        }
        0x1f => sign | 0x7f80_0000 | (frac << 13),
        _ => sign | (((exp as u32) + 112) << 23) | (frac << 13),
    };
    f32::from_bits(value)
}
