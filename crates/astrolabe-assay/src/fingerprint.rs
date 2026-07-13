//! Input fingerprints: the cache key that makes invalidation exact.
//!
//! A sampled result is valid exactly as long as *every* input that determined
//! it is unchanged. The [`InputFingerprint`] is a blake3 hash over a canonical
//! preimage of all of them — seed, sample size, panel version, the shard set,
//! and the full population content — so any change to any of them yields a
//! different key and the old cache entry can no longer be found. There is no
//! partial or fuzzy match: a panel bump, a shard set change, or a single
//! subject's content byte flip all move the key, which is what keys the
//! invalidation scan.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::population::Population;

/// Domain-separation tag framed into every fingerprint preimage.
pub const ASSAY_FINGERPRINT_TAG: &str = "astro-assay-fingerprint-v1";

/// A 32-byte content-addressed key over every input that determines a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InputFingerprint([u8; 32]);

impl InputFingerprint {
    /// Computes the fingerprint over the full input tuple.
    ///
    /// `shards` need not be sorted or deduplicated: they are canonicalized here
    /// so shard order and duplicates never affect the key. The population is
    /// already canonically ordered by construction.
    pub fn compute(
        population: &Population,
        seed: u64,
        sample_size: u64,
        panel_version: u32,
        shards: &[String],
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ASSAY_FINGERPRINT_TAG.as_bytes());
        hasher.update(&seed.to_le_bytes());
        hasher.update(&sample_size.to_le_bytes());
        hasher.update(&panel_version.to_le_bytes());

        let mut shards: Vec<&String> = shards.iter().collect();
        shards.sort();
        shards.dedup();
        hasher.update(&(shards.len() as u64).to_le_bytes());
        for shard in shards {
            hasher.update(&(shard.len() as u64).to_le_bytes());
            hasher.update(shard.as_bytes());
        }

        hasher.update(&(population.len() as u64).to_le_bytes());
        for subject in population.subjects() {
            hasher.update(subject.series_id.as_bytes());
            hasher.update(&(subject.stratum.len() as u64).to_le_bytes());
            hasher.update(subject.stratum.as_bytes());
            hasher.update(&subject.content_fingerprint);
        }
        Self(*hasher.finalize().as_bytes())
    }

    /// Raw fingerprint bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering, used as the on-disk store key.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
        }
        out
    }
}

impl fmt::Display for InputFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::population::AssaySubject;
    use astrolabe_domain::SeriesId;

    fn subj(byte: u8, stratum: &str, content: u8) -> AssaySubject {
        AssaySubject::new(SeriesId::from_bytes([byte; 16]), stratum, [content; 32]).unwrap()
    }

    fn pop() -> Population {
        Population::new([subj(1, "function", 10), subj(2, "class", 20)]).unwrap()
    }

    #[test]
    fn fingerprint_is_stable_and_hex_is_64_chars() {
        let fp = InputFingerprint::compute(&pop(), 7, 100, 3, &["shard-a".into()]);
        let again = InputFingerprint::compute(&pop(), 7, 100, 3, &["shard-a".into()]);
        assert_eq!(fp, again);
        assert_eq!(fp.to_hex().len(), 64);
    }

    #[test]
    fn shard_order_and_duplicates_do_not_change_the_key() {
        let a = InputFingerprint::compute(&pop(), 7, 100, 3, &["a".into(), "b".into()]);
        let b = InputFingerprint::compute(&pop(), 7, 100, 3, &["b".into(), "a".into(), "a".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn panel_bump_shard_change_and_content_flip_each_move_the_key() {
        let base = InputFingerprint::compute(&pop(), 7, 100, 3, &["a".into()]);
        let panel = InputFingerprint::compute(&pop(), 7, 100, 4, &["a".into()]);
        let shard = InputFingerprint::compute(&pop(), 7, 100, 3, &["a".into(), "b".into()]);
        let flipped = Population::new([subj(1, "function", 11), subj(2, "class", 20)]).unwrap();
        let content = InputFingerprint::compute(&flipped, 7, 100, 3, &["a".into()]);
        assert_ne!(base, panel);
        assert_ne!(base, shard);
        assert_ne!(base, content);
    }
}
