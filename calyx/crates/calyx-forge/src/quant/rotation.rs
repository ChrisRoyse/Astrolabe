use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::quant::SeedId;
use crate::{ForgeError, Result};

pub const CURRENT_SEED_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RotationSeed {
    #[serde(with = "seed_id_hex_serde")]
    pub id: SeedId,
    pub version: u8,
    pub dim: usize,
    pub diagonal: Vec<f32>,
}

impl RotationSeed {
    pub fn verify_current_version(&self) -> Result<()> {
        if self.version == CURRENT_SEED_VERSION {
            return Ok(());
        }
        Err(ForgeError::SeedVersionMismatch {
            expected: CURRENT_SEED_VERSION,
            got: self.version,
        })
    }
}

pub fn new_seed(dim: usize, entropy: &[u8]) -> RotationSeed {
    let rng_seed = sha256_entropy_dim(entropy, dim);
    let mut rng = ChaCha8Rng::from_seed(rng_seed);
    let diagonal: Vec<f32> = (0..dim)
        .map(|_| if rng.r#gen::<bool>() { 1.0 } else { -1.0 })
        .collect();
    let id = content_id(&diagonal, CURRENT_SEED_VERSION, dim);
    RotationSeed {
        id,
        version: CURRENT_SEED_VERSION,
        dim,
        diagonal,
    }
}

pub fn apply_rotation(seed: &RotationSeed, vec: &mut [f32]) {
    assert_eq!(
        vec.len(),
        seed.dim,
        "dimension mismatch: expected {} got {}",
        seed.dim,
        vec.len()
    );
    apply_block_hadamard(vec);
    for (value, sign) in vec.iter_mut().zip(seed.diagonal.iter()) {
        *value *= *sign;
    }
}

pub fn apply_inverse_rotation(seed: &RotationSeed, vec: &mut [f32]) {
    assert_eq!(
        vec.len(),
        seed.dim,
        "dimension mismatch: expected {} got {}",
        seed.dim,
        vec.len()
    );
    for (value, sign) in vec.iter_mut().zip(seed.diagonal.iter()) {
        *value *= *sign;
    }
    apply_block_hadamard(vec);
}

pub fn apply_rotation_batch(seed: &RotationSeed, vecs: &mut [f32], n: usize) {
    let expected = n
        .checked_mul(seed.dim)
        .expect("batch dimension mismatch: n * dim overflow");
    assert_eq!(
        vecs.len(),
        expected,
        "batch dimension mismatch: expected {} got {}",
        expected,
        vecs.len()
    );
    for row in vecs.chunks_exact_mut(seed.dim) {
        apply_rotation(seed, row);
    }
}

pub fn seed_id_hex(id: &SeedId) -> String {
    let mut hex = String::with_capacity(id.len() * 2);
    for byte in id {
        hex.push(nibble_hex(byte >> 4));
        hex.push(nibble_hex(byte & 0x0f));
    }
    hex
}

fn sha256_entropy_dim(entropy: &[u8], dim: usize) -> SeedId {
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.update((dim as u64).to_le_bytes());
    hasher.finalize().into()
}

fn content_id(diagonal: &[f32], version: u8, dim: usize) -> SeedId {
    let mut hasher = Sha256::new();
    for sign in diagonal {
        hasher.update(sign.to_le_bytes());
    }
    hasher.update([version]);
    hasher.update((dim as u64).to_le_bytes());
    hasher.finalize().into()
}

fn apply_block_hadamard(vec: &mut [f32]) {
    let mut offset = 0;
    while offset < vec.len() {
        let block_len = largest_power_of_two_at_most(vec.len() - offset);
        hadamard_power_of_two(&mut vec[offset..offset + block_len]);
        offset += block_len;
    }
}

fn hadamard_power_of_two(block: &mut [f32]) {
    let mut width = 1;
    while width < block.len() {
        let step = width * 2;
        for base in (0..block.len()).step_by(step) {
            for idx in 0..width {
                let left = block[base + idx];
                let right = block[base + idx + width];
                block[base + idx] = left + right;
                block[base + idx + width] = left - right;
            }
        }
        width = step;
    }
    let scale = 1.0 / (block.len() as f32).sqrt();
    for value in block {
        *value *= scale;
    }
}

fn largest_power_of_two_at_most(value: usize) -> usize {
    1usize << (usize::BITS - 1 - value.leading_zeros())
}

fn nibble_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble is masked"),
    }
}

fn decode_hex_seed_id(text: &str) -> std::result::Result<SeedId, String> {
    if text.len() != 64 {
        return Err(format!("seed id hex length must be 64, got {}", text.len()));
    }
    let mut id = [0u8; 32];
    for (idx, slot) in id.iter_mut().enumerate() {
        let hi = hex_value(text.as_bytes()[idx * 2])?;
        let lo = hex_value(text.as_bytes()[idx * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(id)
}

fn hex_value(byte: u8) -> std::result::Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid seed id hex byte: {byte}")),
    }
}

mod seed_id_hex_serde {
    use super::*;

    pub fn serialize<S>(id: &SeedId, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&seed_id_hex(id))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<SeedId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        decode_hex_seed_id(&text).map_err(serde::de::Error::custom)
    }
}
