use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use crate::quant::rotation::domain_seed;
use crate::quant::{RotationSeed, SeedId};
use crate::{ForgeError, Result};

/// Frozen identity of the arbitrary-dimension structured Hadamard transform.
pub(crate) const STRUCTURED_HADAMARD_VERSION: u8 = 1;
const MIXING_ROUNDS: usize = 2;

#[derive(Clone)]
struct HadamardRound {
    /// Destination-to-source permutation. This representation makes the
    /// inverse an exact scatter without storing a second permutation.
    permutation: Vec<u32>,
    signs: Vec<u8>,
}

/// Bit-exact, arbitrary-dimension randomized Hadamard transform.
///
/// Each round applies a frozen Rademacher phase, a deterministic permutation,
/// then normalized FWHT blocks following the binary decomposition of `dim`.
/// Every block is orthogonal; two independently generated rounds mix values
/// across the power-of-two block boundary while retaining an exact inverse.
/// Setup uses only SHA-256, ChaCha8, integer operations, and frozen IEEE-754
/// constants: it is independent of platform `libm`.
pub(crate) struct StructuredHadamard {
    dim: usize,
    seed_id: SeedId,
    transform_id: SeedId,
    rounds: Vec<HadamardRound>,
}

impl StructuredHadamard {
    pub(crate) fn new(seed: &RotationSeed, domain: &[u8]) -> Result<Self> {
        seed.validate()?;
        let mut rng = ChaCha8Rng::from_seed(domain_seed(domain, &seed.id, seed.dim));
        let mut rounds = Vec::new();
        rounds.try_reserve_exact(MIXING_ROUNDS).map_err(|error| {
            transform_error(format!("cannot allocate Hadamard rounds: {error}"))
        })?;
        for _ in 0..MIXING_ROUNDS {
            let mut permutation = (0..seed.dim)
                .map(|index| {
                    u32::try_from(index)
                        .map_err(|_| transform_error("Hadamard permutation index exceeds u32"))
                })
                .collect::<Result<Vec<_>>>()?;
            for index in (1..seed.dim).rev() {
                let swap = uniform_below(&mut rng, index + 1);
                permutation.swap(index, swap);
            }
            let mut signs = vec![0_u8; seed.dim.div_ceil(8)];
            for index in 0..seed.dim {
                if rng.next_u32() & 1 != 0 {
                    signs[index / 8] |= 1 << (index % 8);
                }
            }
            rounds.push(HadamardRound { permutation, signs });
        }

        let transform_id = transform_id(domain, seed, &rounds);
        Ok(Self {
            dim: seed.dim,
            seed_id: seed.id,
            transform_id,
            rounds,
        })
    }

    pub(crate) fn apply(&self, values: &mut [f32]) -> Result<()> {
        self.validate(values, "apply")?;
        let mut scratch = vec![0.0_f32; self.dim];
        for round in &self.rounds {
            for (destination, source) in round.permutation.iter().enumerate() {
                let source = *source as usize;
                scratch[destination] = values[source] * sign_at(&round.signs, destination);
            }
            apply_block_fwht(&mut scratch);
            values.copy_from_slice(&scratch);
        }
        validate_output(values, "apply")
    }

    pub(crate) fn apply_inverse(&self, values: &mut [f32]) -> Result<()> {
        self.validate(values, "apply_inverse")?;
        let mut scratch = vec![0.0_f32; self.dim];
        for round in self.rounds.iter().rev() {
            scratch.copy_from_slice(values);
            apply_block_fwht(&mut scratch);
            for (destination, source) in round.permutation.iter().enumerate() {
                values[*source as usize] =
                    scratch[destination] * sign_at(&round.signs, destination);
            }
        }
        validate_output(values, "apply_inverse")
    }

    pub(crate) fn seed_id(&self) -> SeedId {
        self.seed_id
    }

    pub(crate) fn dim(&self) -> usize {
        self.dim
    }

    pub(crate) fn transform_id(&self) -> SeedId {
        self.transform_id
    }

    pub(crate) fn physical_bytes(&self) -> usize {
        self.rounds
            .iter()
            .map(|round| round.permutation.len() * std::mem::size_of::<u32>() + round.signs.len())
            .sum()
    }

    fn validate(&self, values: &[f32], op: &str) -> Result<()> {
        if values.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![values.len()],
                remediation: "Use the exact structured TurboQuant dimension".to_string(),
            });
        }
        if let Some(index) = values.iter().position(|value| !value.is_finite()) {
            return Err(transform_error(format!(
                "structured Hadamard {op} input is non-finite at index {index}"
            )));
        }
        Ok(())
    }
}

fn uniform_below(rng: &mut ChaCha8Rng, bound: usize) -> usize {
    let bound = bound as u64;
    let zone = u64::MAX - u64::MAX % bound;
    loop {
        let candidate = rng.next_u64();
        if candidate < zone {
            return (candidate % bound) as usize;
        }
    }
}

fn transform_id(domain: &[u8], seed: &RotationSeed, rounds: &[HadamardRound]) -> SeedId {
    let mut hasher = Sha256::new();
    hasher.update(b"calyx/turboquant/structured-hadamard/geometry/v1\0");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update([STRUCTURED_HADAMARD_VERSION, MIXING_ROUNDS as u8]);
    hasher.update((seed.dim as u64).to_le_bytes());
    hasher.update(seed.id);
    for round in rounds {
        hasher.update((round.permutation.len() as u64).to_le_bytes());
        for source in &round.permutation {
            hasher.update(source.to_le_bytes());
        }
        hasher.update((round.signs.len() as u64).to_le_bytes());
        hasher.update(&round.signs);
    }
    hasher.finalize().into()
}

fn apply_block_fwht(values: &mut [f32]) {
    let mut offset = 0_usize;
    let mut remaining = values.len();
    while remaining != 0 {
        let block_len = largest_power_of_two(remaining);
        fwht_normalized(&mut values[offset..offset + block_len]);
        offset += block_len;
        remaining -= block_len;
    }
}

fn largest_power_of_two(value: usize) -> usize {
    1_usize << (usize::BITS - 1 - value.leading_zeros())
}

fn fwht_normalized(values: &mut [f32]) {
    let mut width = 1_usize;
    while width < values.len() {
        let stride = width * 2;
        for base in (0..values.len()).step_by(stride) {
            for lane in 0..width {
                let left = values[base + lane];
                let right = values[base + lane + width];
                values[base + lane] = left + right;
                values[base + lane + width] = left - right;
            }
        }
        width = stride;
    }
    let scale = inverse_sqrt_power_of_two(values.len());
    for value in values {
        *value *= scale;
    }
}

fn inverse_sqrt_power_of_two(value: usize) -> f32 {
    let exponent = value.trailing_zeros() as i32;
    let power = f32::from_bits(((127 - exponent / 2) as u32) << 23);
    if exponent & 1 == 0 {
        power
    } else {
        // Canonical nearest-f32 representation of 1/sqrt(2).
        power * f32::from_bits(0x3f35_04f3)
    }
}

fn sign_at(signs: &[u8], index: usize) -> f32 {
    if signs[index / 8] & (1 << (index % 8)) == 0 {
        -1.0
    } else {
        1.0
    }
}

fn validate_output(values: &[f32], op: &str) -> Result<()> {
    if let Some(index) = values.iter().position(|value| !value.is_finite()) {
        return Err(transform_error(format!(
            "structured Hadamard {op} output is non-finite at index {index}"
        )));
    }
    Ok(())
}

fn transform_error(detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: "structured_hadamard".to_string(),
        level: "geometry_v1".to_string(),
        detail: detail.into(),
        remediation: "Use a current, finite structured TurboQuant vector and its exact frozen seed"
            .to_string(),
    }
}
