//! Deterministic, platform-independent `f32` transcendental math.
//!
//! The deterministic encoders (S2/S3/S5/S8/S9/S10/S11) route feature values
//! through natural-log and exponential functions and then freeze their outputs
//! as byte-exact hex goldens; content addresses derive from those bytes. Rust
//! std's [`f32::ln`], [`f32::ln_1p`] and [`f32::exp`] have
//! *implementation-defined precision* (they may lower to the platform libm or a
//! hardware intrinsic), so their least-significant bits can differ by an ULP
//! across platforms and toolchains. A same-process determinism probe cannot see
//! that divergence, so it would surface only as cross-platform golden failures.
//!
//! These functions are the single math source for those encoders. They are the
//! MUSL/FreeBSD `logf`/`log1pf`/`expf` routines ported verbatim from the
//! `rust-lang/libm` crate (MIT licensed). They use only IEEE-754 `+ - * /` and
//! bit reinterpretation — all correctly-rounded and deterministic on every
//! conforming platform — so their results are bit-identical everywhere.
//!
//! The routines are ported verbatim; the upstream constants (documented to more
//! decimal digits than an `f32` holds, but rounding to the intended bits) and
//! expressions (e.g. `x - x` to mint a sign-preserving `NaN`) are kept as-is for
//! auditability against the reference source, so the relevant clippy lints are
//! allowed here.
#![allow(clippy::excessive_precision, clippy::eq_op, clippy::needless_late_init)]

use std::hint::black_box;

/// Natural logarithm of `x` — deterministic replacement for [`f32::ln`].
#[inline]
pub(crate) fn ln(x: f32) -> f32 {
    logf(x)
}

/// Natural logarithm of `1 + x` — deterministic replacement for
/// [`f32::ln_1p`].
#[inline]
pub(crate) fn ln_1p(x: f32) -> f32 {
    log1pf(x)
}

/// Base-*e* exponential — deterministic replacement for [`f32::exp`].
#[inline]
pub(crate) fn exp(x: f32) -> f32 {
    expf(x)
}

/* origin: FreeBSD /usr/src/lib/msun/src/e_logf.c (via rust-lang/libm) */
const LOGF_LN2_HI: f32 = 6.9313812256e-01;
const LOGF_LN2_LO: f32 = 9.0580006145e-06;
const LOGF_LG1: f32 = 0.66666662693;
const LOGF_LG2: f32 = 0.40000972152;
const LOGF_LG3: f32 = 0.28498786688;
const LOGF_LG4: f32 = 0.24279078841;

fn logf(mut x: f32) -> f32 {
    let x1p25 = f32::from_bits(0x4c000000); // 2^25

    let mut ix = x.to_bits();
    let mut k = 0i32;

    if (ix < 0x00800000) || ((ix >> 31) != 0) {
        // x < 2**-126
        if ix << 1 == 0 {
            return -1. / (x * x); // log(+-0) = -inf
        }
        if (ix >> 31) != 0 {
            return (x - x) / 0.; // log(-#) = NaN
        }
        // subnormal number, scale up x
        k -= 25;
        x *= x1p25;
        ix = x.to_bits();
    } else if ix >= 0x7f800000 {
        return x;
    } else if ix == 0x3f800000 {
        return 0.;
    }

    // reduce x into [sqrt(2)/2, sqrt(2)]
    ix += 0x3f800000 - 0x3f3504f3;
    k += ((ix >> 23) as i32) - 0x7f;
    ix = (ix & 0x007fffff) + 0x3f3504f3;
    x = f32::from_bits(ix);

    let f = x - 1.;
    let s = f / (2. + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LOGF_LG2 + w * LOGF_LG4);
    let t2 = z * (LOGF_LG1 + w * LOGF_LG3);
    let r = t2 + t1;
    let hfsq = 0.5 * f * f;
    let dk = k as f32;
    s * (hfsq + r) + dk * LOGF_LN2_LO - hfsq + f + dk * LOGF_LN2_HI
}

/* origin: FreeBSD /usr/src/lib/msun/src/s_log1pf.c (via rust-lang/libm) */
fn log1pf(x: f32) -> f32 {
    // Shares the LOGF_* polynomial constants above.
    let mut ui: u32 = x.to_bits();
    let hfsq: f32;
    let mut f: f32 = 0.;
    let mut c: f32 = 0.;
    let s: f32;
    let z: f32;
    let r: f32;
    let w: f32;
    let t1: f32;
    let t2: f32;
    let dk: f32;
    let ix: u32;
    let mut iu: u32;
    let mut k: i32;

    ix = ui;
    k = 1;
    if ix < 0x3ed413d0 || (ix >> 31) > 0 {
        // 1 + x < sqrt(2)+
        if ix >= 0xbf800000 {
            // x <= -1.0
            if x == -1. {
                return x / 0.0; // log1p(-1) = +inf
            }
            return (x - x) / 0.0; // log1p(x < -1) = NaN
        }
        if ix << 1 < 0x33800000 << 1 {
            // |x| < 2**-24
            if (ix & 0x7f800000) == 0 {
                // underflow if subnormal
                black_box(x * x);
            }
            return x;
        }
        if ix <= 0xbe95f619 {
            // sqrt(2)/2- <= 1+x < sqrt(2)+
            k = 0;
            c = 0.;
            f = x;
        }
    } else if ix >= 0x7f800000 {
        return x;
    }
    if k > 0 {
        ui = (1. + x).to_bits();
        iu = ui;
        iu += 0x3f800000 - 0x3f3504f3;
        k = (iu >> 23) as i32 - 0x7f;
        // correction term ~ log(1+x)-log(u), avoid underflow in c/u
        if k < 25 {
            c = if k >= 2 {
                1. - (f32::from_bits(ui) - x)
            } else {
                x - (f32::from_bits(ui) - 1.)
            };
            c /= f32::from_bits(ui);
        } else {
            c = 0.;
        }
        // reduce u into [sqrt(2)/2, sqrt(2)]
        iu = (iu & 0x007fffff) + 0x3f3504f3;
        ui = iu;
        f = f32::from_bits(ui) - 1.;
    }
    s = f / (2.0 + f);
    z = s * s;
    w = z * z;
    t1 = w * (LOGF_LG2 + w * LOGF_LG4);
    t2 = z * (LOGF_LG1 + w * LOGF_LG3);
    r = t2 + t1;
    hfsq = 0.5 * f * f;
    dk = k as f32;
    s * (hfsq + r) + (dk * LOGF_LN2_LO + c) - hfsq + f + dk * LOGF_LN2_HI
}

/* origin: FreeBSD /usr/src/lib/msun/src/e_expf.c (via rust-lang/libm) */
const EXPF_HALF: [f32; 2] = [0.5, -0.5];
const EXPF_LN2_HI: f32 = 6.9314575195e-01;
const EXPF_LN2_LO: f32 = 1.4286067653e-06;
const EXPF_INV_LN2: f32 = 1.4426950216e+00;
const EXPF_P1: f32 = 1.6666625440e-1;
const EXPF_P2: f32 = -2.7667332906e-3;

fn expf(mut x: f32) -> f32 {
    let x1p127 = f32::from_bits(0x7f000000); // 2^127
    let x1p_126 = f32::from_bits(0x800000); // 2^-126
    let mut hx = x.to_bits();
    let sign = (hx >> 31) as i32; // sign bit of x
    let signb: bool = sign != 0;
    hx &= 0x7fffffff; // high word of |x|

    // special cases
    if hx >= 0x42aeac50 {
        // if |x| >= -87.33655f or NaN
        if hx > 0x7f800000 {
            // NaN
            return x;
        }
        if (hx >= 0x42b17218) && (!signb) {
            // x >= 88.722839f -> overflow
            x *= x1p127;
            return x;
        }
        if signb {
            // underflow
            black_box(-x1p_126 / x);
            if hx >= 0x42cff1b5 {
                // x <= -103.972084f
                return 0.;
            }
        }
    }

    // argument reduction
    let k: i32;
    let hi: f32;
    let lo: f32;
    if hx > 0x3eb17218 {
        // if |x| > 0.5 ln2
        if hx > 0x3f851592 {
            // if |x| > 1.5 ln2
            k = (EXPF_INV_LN2 * x + EXPF_HALF[sign as usize]) as i32;
        } else {
            k = 1 - sign - sign;
        }
        let kf = k as f32;
        hi = x - kf * EXPF_LN2_HI; // k*ln2hi is exact here
        lo = kf * EXPF_LN2_LO;
        x = hi - lo;
    } else if hx > 0x39000000 {
        // |x| > 2**-14
        k = 0;
        hi = x;
        lo = 0.;
    } else {
        // raise inexact
        black_box(x1p127 + x);
        return 1. + x;
    }

    // x is now in primary range
    let xx = x * x;
    let c = x - xx * (EXPF_P1 + xx * EXPF_P2);
    let y = 1. + (x * c / (2. - c) - lo + hi);
    if k == 0 { y } else { scalbnf(y, k) }
}

/* origin: MUSL scalbnf */
fn scalbnf(mut x: f32, mut n: i32) -> f32 {
    let x1p127 = f32::from_bits(0x7f000000); // 2^127
    let x1p_126 = f32::from_bits(0x00800000); // 2^-126
    let x1p24 = f32::from_bits(0x4b800000); // 2^24
    if n > 127 {
        x *= x1p127;
        n -= 127;
        if n > 127 {
            x *= x1p127;
            n -= 127;
            if n > 127 {
                n = 127;
            }
        }
    } else if n < -126 {
        x *= x1p_126 * x1p24;
        n += 126 - 24;
        if n < -126 {
            x *= x1p_126 * x1p24;
            n += 126 - 24;
            if n < -126 {
                n = -126;
            }
        }
    }
    x * f32::from_bits(((0x7f + n) as u32) << 23)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f32, b: f32, tol: f32) -> bool {
        (a - b).abs() <= tol * (1.0 + a.abs().max(b.abs()))
    }

    #[test]
    fn matches_known_mathematical_values() {
        assert_eq!(ln(1.0), 0.0);
        assert_eq!(ln_1p(0.0), 0.0);
        assert_eq!(exp(0.0), 1.0);
        assert!(close(ln(std::f32::consts::E), 1.0, 1e-6));
        assert!(close(exp(1.0), std::f32::consts::E, 1e-6));
        assert!(close(ln_1p(1.0), std::f32::consts::LN_2, 1e-6));
        assert!(close(exp(-1.0), 1.0 / std::f32::consts::E, 1e-6));
    }

    #[test]
    fn tracks_std_within_a_few_ulps_across_the_encoder_input_range() {
        // Proves the port is a correct log/exp (not merely deterministic
        // garbage): it agrees with std to a tight tolerance over the value
        // ranges the encoders feed it. The point of the module is that std is
        // NOT the frozen source, but a correct port must still be numerically
        // faithful.
        for i in 0..=2000u32 {
            let v = i as f32 * 0.5; // 0 .. 1000
            assert!(
                close(ln_1p(v), v.ln_1p(), 4e-6),
                "ln_1p diverged at {v}: det={} std={}",
                ln_1p(v),
                v.ln_1p()
            );
            let d = i as f32 * 0.1; // exp domain used by recency decay
            let arg = -std::f32::consts::LN_2 * d / 30.0;
            assert!(close(exp(arg), arg.exp(), 4e-6), "exp diverged at {arg}");
            let w = 1.0 + i as f32; // ln domain used by positive_day_log
            assert!(close(ln(w), w.ln(), 4e-6), "ln diverged at {w}");
        }
    }

    #[test]
    fn is_bit_stable_for_frozen_encoder_arguments() {
        // Byte-exact anchors: if the port is ever altered, these break. They
        // are the frozen bit patterns the encoder goldens depend on.
        // ln(2) == ln_1p(1) == 0x3f317218; exp(1) == 0x402df854.
        assert_eq!(ln_1p(1.0).to_bits(), 0x3f31_7218);
        assert_eq!(ln(2.0).to_bits(), 0x3f31_7218);
        assert_eq!(exp(1.0).to_bits(), 0x402d_f854);
    }
}
