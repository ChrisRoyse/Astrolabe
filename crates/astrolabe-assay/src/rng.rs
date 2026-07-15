//! Deterministic, worker-count-invariant pseudo-random stream and the
//! continuous samplers the KSG measurement chain needs.
//!
//! Every stochastic step in this crate (random projection, bootstrap resampling,
//! small-sample posterior draws) must be a pure function of its seed so a card
//! reproduces bit-for-bit regardless of how many workers built it. A stateful
//! global PRNG cannot promise that: its stream depends on how many threads pulled
//! from it and in what order. Instead this module is a **counter-based PRF**: the
//! next value is `blake3(seed_key || counter)`, so the k-th draw is a pure
//! function of `(seed, k)` and never of scheduling. The samplers (uniform,
//! standard normal, gamma) are the standard closed-form transforms of that
//! uniform stream, so they inherit the same determinism.

/// Domain-separation tag framed into every RNG preimage so an assay draw stream
/// can never collide with another blake3 use of the same seed.
pub const ASSAY_RNG_TAG: &str = "astro-assay-rng-v1";

/// A deterministic counter-based pseudo-random stream keyed by a 32-byte seed.
///
/// The stream is a pure function of `(key, counter)`: `next_u64` hashes the key
/// and the current counter, then advances the counter. Cloning the stream and
/// pulling the same number of values yields identical draws, and two streams with
/// the same seed are identical no matter what thread built them.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    key: [u8; 32],
    counter: u64,
}

impl DeterministicRng {
    /// Seeds a stream from a `u64` seed by hashing it (with the domain tag) into
    /// the 32-byte key. Distinct `u64` seeds give independent streams.
    pub fn from_u64(seed: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ASSAY_RNG_TAG.as_bytes());
        hasher.update(&seed.to_le_bytes());
        Self {
            key: *hasher.finalize().as_bytes(),
            counter: 0,
        }
    }

    /// Seeds a stream from a `u64` seed and an arbitrary byte-label so several
    /// independent streams (projection, bootstrap, posterior) can be derived from
    /// one card seed without sharing a stream.
    pub fn from_u64_labeled(seed: u64, label: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ASSAY_RNG_TAG.as_bytes());
        hasher.update(&seed.to_le_bytes());
        hasher.update(&(label.len() as u64).to_le_bytes());
        hasher.update(label.as_bytes());
        Self {
            key: *hasher.finalize().as_bytes(),
            counter: 0,
        }
    }

    /// Returns the next 64-bit value in the stream and advances the counter.
    pub fn next_u64(&mut self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.key);
        hasher.update(&self.counter.to_le_bytes());
        let bytes = hasher.finalize();
        let block = bytes.as_bytes();
        self.counter = self.counter.wrapping_add(1);
        let mut out = [0u8; 8];
        out.copy_from_slice(&block[..8]);
        u64::from_le_bytes(out)
    }

    /// Returns the next uniform value in the half-open interval `[0, 1)`.
    ///
    /// Uses the top 53 bits of a 64-bit draw scaled by `2^-53`, the standard
    /// full-mantissa construction of a uniform double, so the result is never
    /// exactly `1.0`.
    pub fn next_f64(&mut self) -> f64 {
        const SCALE: f64 = 1.0 / ((1u64 << 53) as f64);
        ((self.next_u64() >> 11) as f64) * SCALE
    }

    /// Returns the next uniform value in the open interval `(0, 1)`.
    ///
    /// Some transforms (Box–Muller's logarithm, gamma's boost) diverge at exactly
    /// zero, so this variant rejects a zero draw and takes the next one.
    pub fn next_open_unit(&mut self) -> f64 {
        loop {
            let u = self.next_f64();
            if u > 0.0 {
                return u;
            }
        }
    }

    /// Returns the next draw from the standard normal distribution `N(0, 1)` by
    /// the Box–Muller transform. Each call consumes two uniforms and returns one
    /// of the pair (the second is discarded so the stream position stays a simple
    /// function of the draw index).
    pub fn next_standard_normal(&mut self) -> f64 {
        let u1 = self.next_open_unit();
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Returns the next draw from `Gamma(shape, 1)` (unit rate) using the
    /// Marsaglia–Tsang method, with the standard `shape < 1` boost.
    ///
    /// Marsaglia–Tsang is exact for `shape >= 1`; for `shape < 1` it draws a
    /// `Gamma(shape + 1, 1)` variate and multiplies by `U^(1/shape)`, which is the
    /// published correction. `shape` must be finite and strictly positive.
    pub fn next_gamma(&mut self, shape: f64) -> f64 {
        debug_assert!(shape.is_finite() && shape > 0.0, "gamma shape must be > 0");
        if shape < 1.0 {
            let g = self.next_gamma(shape + 1.0);
            let u = self.next_open_unit();
            return g * u.powf(1.0 / shape);
        }
        let d = shape - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();
        loop {
            let x = self.next_standard_normal();
            let v = (1.0 + c * x).powi(3);
            if v <= 0.0 {
                continue;
            }
            let u = self.next_open_unit();
            let x2 = x * x;
            if u < 1.0 - 0.0331 * x2 * x2 {
                return d * v;
            }
            if u.ln() < 0.5 * x2 + d * (1.0 - v + v.ln()) {
                return d * v;
            }
        }
    }

    /// Draws a Dirichlet vector with the given per-component concentrations by
    /// normalizing independent unit-rate gamma draws (the standard construction).
    /// Every concentration must be finite and strictly positive.
    pub fn next_dirichlet(&mut self, concentrations: &[f64]) -> Vec<f64> {
        let mut draws: Vec<f64> = concentrations.iter().map(|&a| self.next_gamma(a)).collect();
        let sum: f64 = draws.iter().sum();
        if sum > 0.0 {
            for value in &mut draws {
                *value /= sum;
            }
        } else {
            // Degenerate underflow: fall back to the uniform simplex point so the
            // result is always a valid probability vector rather than NaNs.
            let uniform = 1.0 / draws.len() as f64;
            draws.fill(uniform);
        }
        draws
    }
}
