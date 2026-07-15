//! Deterministic, seeded stratified sampling.
//!
//! # Why this is deterministic and worker-count invariant
//!
//! The sampler never uses a stateful PRNG whose stream depends on how many
//! threads pulled from it, and it never depends on the order subjects arrive.
//! Instead every subject is assigned a *priority key* that is a pure hash of
//! `(seed, series_id)`; the selected subjects in a stratum are simply the ones
//! with the smallest priority keys. Selecting the k smallest keys is a set
//! operation — it gives the identical result no matter how the population was
//! partitioned across workers or in what order the keys were computed. This is
//! the hash-based reproducible-sampling pattern (compute a keyed hash per
//! element and take the k extremal keys per stratum) rather than a shuffle.
//!
//! # Why the proportions are exact and hand-computable
//!
//! Seats are apportioned across strata by the **largest-remainder (Hamilton)**
//! method in pure integer arithmetic: each stratum gets
//! `floor(sample_size * n_s / N)` base seats, and the leftover seats go to the
//! strata with the largest fractional remainders, ties broken by stratum label
//! ascending. No floating point is involved, so a reviewer can reproduce the
//! allocation exactly by hand.

use astrolabe_domain::SeriesId;
use serde::{Deserialize, Serialize};

use crate::fingerprint::InputFingerprint;
use crate::population::Population;

/// Domain-separation tag framed into every priority-key preimage.
pub const ASSAY_PRIORITY_TAG: &str = "astro-assay-priority-v1";

/// Per-stratum apportionment: how many seats a stratum received, and its size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StratumAllocation {
    /// Stratum label.
    pub stratum: String,
    /// Number of subjects in this stratum in the population.
    pub population: usize,
    /// Number of sample seats apportioned to this stratum.
    pub allocated: usize,
}

/// One subject selected into the sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedSubject {
    /// Stratum the subject was selected from.
    pub stratum: String,
    /// Stable identity of the selected subject.
    pub series_id: SeriesId,
    /// Zero-based rank within the stratum, ascending by priority key.
    pub rank_in_stratum: usize,
    /// Lowercase-hex priority key that determined selection order.
    pub priority: String,
}

/// The full, serializable result of one sampling pass.
///
/// Serialized field-by-field in declaration order over deterministically
/// ordered vectors, so `serde_json::to_vec` is byte-identical for identical
/// inputs. That byte-identity is the determinism evidence read back in FSV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleResult {
    /// Cache key: the fingerprint of every input that produced this result.
    pub fingerprint: InputFingerprint,
    /// Seed used for the priority keys.
    pub seed: u64,
    /// Requested sample size (before clamping to the population size).
    pub requested_sample_size: u64,
    /// Effective sample size after clamping to the population size.
    pub effective_sample_size: usize,
    /// Panel version that scoped the sample.
    pub panel_version: u32,
    /// Canonicalized shard set that scoped the sample.
    pub shards: Vec<String>,
    /// Per-stratum apportionment, in ascending stratum order.
    pub allocations: Vec<StratumAllocation>,
    /// Selected subjects, ordered by `(stratum, rank_in_stratum)`.
    pub rows: Vec<SelectedSubject>,
}

/// A subject that has been scored with its priority key.
///
/// This is the unit the cooperative lane produces one tick at a time and the
/// unit [`finalize_keyed`] consumes; the one-shot [`stratified_sample`] builds
/// the identical vector in a single pass. Because the finalizer is shared, the
/// cooperative and one-shot paths return byte-identical results.
#[derive(Debug, Clone)]
pub struct KeyedSubject {
    /// Stratum label of the scored subject.
    pub stratum: String,
    /// Identity of the scored subject.
    pub series_id: SeriesId,
    /// The subject's priority key under the seed.
    pub key: [u8; 32],
}

/// Computes the priority key for a subject under a seed.
pub fn priority_key(seed: u64, series_id: &SeriesId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_PRIORITY_TAG.as_bytes());
    hasher.update(&seed.to_le_bytes());
    hasher.update(series_id.as_bytes());
    *hasher.finalize().as_bytes()
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// Largest-remainder (Hamilton) apportionment of `sample_size` seats across
/// strata whose sizes are `sizes`, in the same order as `sizes`.
///
/// Returns one seat count per input stratum. The sum of the returned counts
/// equals `min(sample_size, total)` and no stratum ever receives more seats
/// than its size.
pub fn largest_remainder_apportionment(sizes: &[usize], sample_size: u64) -> Vec<usize> {
    let total: u128 = sizes.iter().map(|&n| n as u128).sum();
    if total == 0 {
        return vec![0; sizes.len()];
    }
    let target = (sample_size as u128).min(total);

    let mut base = Vec::with_capacity(sizes.len());
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(sizes.len());
    let mut assigned: u128 = 0;
    for (index, &n) in sizes.iter().enumerate() {
        let numerator = target * n as u128;
        let quotient = numerator / total;
        let remainder = numerator % total;
        base.push(quotient as usize);
        assigned += quotient;
        remainders.push((remainder, index));
    }

    let mut leftover = target - assigned;
    // Largest remainder first; tie broken by stratum index ascending (the strata
    // are already in ascending-label order, so this is a stable label tie-break).
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for &(_, index) in &remainders {
        if leftover == 0 {
            break;
        }
        // A base seat count can never already equal the stratum size while a
        // leftover remains (that requires target >= total, i.e. no leftover),
        // so +1 stays within the stratum size.
        base[index] += 1;
        leftover -= 1;
    }
    base
}

/// Runs one deterministic stratified sampling pass over `population`.
pub fn stratified_sample(
    population: &Population,
    seed: u64,
    sample_size: u64,
    panel_version: u32,
    shards: &[String],
) -> SampleResult {
    let keyed: Vec<KeyedSubject> = population
        .subjects()
        .iter()
        .map(|subject| KeyedSubject {
            stratum: subject.stratum.clone(),
            series_id: subject.series_id,
            key: priority_key(seed, &subject.series_id),
        })
        .collect();
    let fingerprint =
        InputFingerprint::compute(population, seed, sample_size, panel_version, shards);
    finalize_keyed(keyed, fingerprint, seed, sample_size, panel_version, shards)
}

/// Selects the stratified sample from already-scored subjects.
///
/// This is the single selection core shared by the one-shot sampler and the
/// cooperative lane. It sorts the scored subjects into canonical order, so it is
/// independent of the order they were scored in (whether one pass or many
/// cooperative ticks), then apportions seats and selects the smallest keys per
/// stratum.
pub fn finalize_keyed(
    mut keyed: Vec<KeyedSubject>,
    fingerprint: InputFingerprint,
    seed: u64,
    sample_size: u64,
    panel_version: u32,
    shards: &[String],
) -> SampleResult {
    let mut canonical_shards: Vec<String> = shards.to_vec();
    canonical_shards.sort();
    canonical_shards.dedup();

    // Canonical order: by stratum, then ascending priority key, then identity.
    keyed.sort_by(|a, b| {
        a.stratum
            .cmp(&b.stratum)
            .then_with(|| a.key.cmp(&b.key))
            .then_with(|| a.series_id.as_bytes().cmp(b.series_id.as_bytes()))
    });

    // Group by stratum, preserving ascending-label order.
    let mut strata_sizes: Vec<(String, usize)> = Vec::new();
    for subject in &keyed {
        match strata_sizes.last_mut() {
            Some((label, count)) if *label == subject.stratum => *count += 1,
            _ => strata_sizes.push((subject.stratum.clone(), 1)),
        }
    }
    let sizes: Vec<usize> = strata_sizes.iter().map(|(_, n)| *n).collect();
    let seats = largest_remainder_apportionment(&sizes, sample_size);

    let mut allocations = Vec::with_capacity(strata_sizes.len());
    let mut rows = Vec::new();
    let mut effective_sample_size = 0usize;
    let mut offset = 0usize;
    for ((stratum, size), &allocated) in strata_sizes.iter().zip(seats.iter()) {
        allocations.push(StratumAllocation {
            stratum: stratum.clone(),
            population: *size,
            allocated,
        });
        effective_sample_size += allocated;
        for rank in 0..allocated {
            let subject = &keyed[offset + rank];
            rows.push(SelectedSubject {
                stratum: stratum.clone(),
                series_id: subject.series_id,
                rank_in_stratum: rank,
                priority: hex32(&subject.key),
            });
        }
        offset += size;
    }

    SampleResult {
        fingerprint,
        seed,
        requested_sample_size: sample_size,
        effective_sample_size,
        panel_version,
        shards: canonical_shards,
        allocations,
        rows,
    }
}
