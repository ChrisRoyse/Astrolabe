//! Deterministic random projection that pre-reduces high-dimensional embedding
//! slots before the KSG estimator sees them (08 §1, blueprint `projection.rs`).
//!
//! KSG is a k-nearest-neighbour estimator, and nearest-neighbour distances lose
//! all contrast in high dimensions (the concentration-of-distances effect), so a
//! 768-d embedding slot is projected to a small target dimension first. The
//! Johnson–Lindenstrauss lemma guarantees a random linear map into
//! `O(log n)` dimensions preserves pairwise distances up to a small distortion,
//! which is exactly what a distance-based MI estimator needs. The target
//! dimension is `round(factor · log2(n))` (blueprint: `≈ 2·log2(n)`), and the
//! projection matrix is drawn from a seeded [`DeterministicRng`] so the reduced
//! coordinates — and therefore the MI estimate — reproduce bit-for-bit.

use crate::rng::DeterministicRng;

/// Label that seeds the projection's own RNG stream, independent of the
/// bootstrap and posterior streams derived from the same card seed.
pub const PROJECTION_RNG_LABEL: &str = "random-projection";

/// Computes the JL target dimension `round(factor_permille/1000 · log2(n))`,
/// clamped to `[1, source_dim]`.
///
/// `n` is the sample count and `source_dim` the embedding width. The factor is
/// carried in permille so it stays a declared integer knob (`≈ 2.0` → `2000`).
/// A target that would exceed the source dimension is pointless (the projection
/// would not reduce anything), so it clamps down to `source_dim`; a target below
/// one is illegal, so it clamps up to one.
pub fn target_dimension(n: usize, source_dim: usize, factor_permille: u64) -> usize {
    if source_dim == 0 {
        return 0;
    }
    if n < 2 {
        return 1.min(source_dim);
    }
    let log2n = (n as f64).log2();
    let raw = (factor_permille as f64 / 1000.0) * log2n;
    let rounded = raw.round() as i64;
    (rounded.max(1) as usize).min(source_dim)
}

/// Projects each `source_dim`-vector in `vectors` onto `target_dim` axes using a
/// seeded Gaussian random matrix, scaled by `1/sqrt(target_dim)` (the standard
/// JL normalization so squared distances are preserved in expectation).
///
/// The matrix is generated in a fixed row-major order from the seeded RNG, so the
/// projection is a pure function of `(seed, source_dim, target_dim)` and the
/// input. Every input vector must have width `source_dim`. When `target_dim`
/// already equals `source_dim` the vectors are returned unchanged (no projection
/// is needed).
pub fn random_projection(
    vectors: &[Vec<f64>],
    source_dim: usize,
    target_dim: usize,
    seed: u64,
) -> Vec<Vec<f64>> {
    if target_dim >= source_dim {
        return vectors.to_vec();
    }
    if target_dim == 0 {
        return vec![Vec::new(); vectors.len()];
    }
    // Draw the projection matrix once, deterministically: matrix[t][s].
    let mut rng = DeterministicRng::from_u64_labeled(seed, PROJECTION_RNG_LABEL);
    let scale = 1.0 / (target_dim as f64).sqrt();
    let mut matrix = vec![0.0_f64; target_dim * source_dim];
    for cell in &mut matrix {
        *cell = rng.next_standard_normal() * scale;
    }
    vectors
        .iter()
        .map(|v| {
            debug_assert_eq!(v.len(), source_dim);
            let mut out = vec![0.0_f64; target_dim];
            for (t, out_t) in out.iter_mut().enumerate() {
                let row = &matrix[t * source_dim..(t + 1) * source_dim];
                let mut acc = 0.0;
                for (w, x) in row.iter().zip(v.iter()) {
                    acc += w * x;
                }
                *out_t = acc;
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    #[test]
    fn target_dimension_follows_two_log2_n() {
        // factor 2.0, n = 1024 -> 2 * 10 = 20.
        assert_eq!(target_dimension(1024, 768, 2000), 20);
        // Clamps down to the source dimension.
        assert_eq!(target_dimension(1_000_000_000, 8, 2000), 8);
        // Clamps up to one for tiny n.
        assert_eq!(target_dimension(1, 768, 2000), 1);
    }

    #[test]
    fn projection_is_deterministic_for_a_seed() {
        let mut rng = DeterministicRng::from_u64(1);
        let vectors: Vec<Vec<f64>> = (0..50)
            .map(|_| (0..64).map(|_| rng.next_standard_normal()).collect())
            .collect();
        let a = random_projection(&vectors, 64, 8, 999);
        let b = random_projection(&vectors, 64, 8, 999);
        assert_eq!(a, b);
        assert_eq!(a[0].len(), 8);
        // A different seed gives a different projection.
        let c = random_projection(&vectors, 64, 8, 1000);
        assert_ne!(a, c);
    }

    #[test]
    fn projection_approximately_preserves_pairwise_distances() {
        // JL: a Gaussian projection preserves squared distances in expectation.
        let mut rng = DeterministicRng::from_u64_labeled(5, "jl-data");
        let source_dim = 200;
        let vectors: Vec<Vec<f64>> = (0..40)
            .map(|_| {
                (0..source_dim)
                    .map(|_| rng.next_standard_normal())
                    .collect()
            })
            .collect();
        let target_dim = 64;
        let projected = random_projection(&vectors, source_dim, target_dim, 7);
        // Average ratio of projected to original squared distance should be ~1.
        let mut ratios = Vec::new();
        for i in 0..vectors.len() {
            for j in (i + 1)..vectors.len() {
                let orig: f64 = vectors[i]
                    .iter()
                    .zip(&vectors[j])
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum();
                let proj: f64 = projected[i]
                    .iter()
                    .zip(&projected[j])
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum();
                if orig > 0.0 {
                    ratios.push(proj / orig);
                }
            }
        }
        let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
        assert!((mean - 1.0).abs() < 0.1, "mean distance ratio={mean}");
    }
}
