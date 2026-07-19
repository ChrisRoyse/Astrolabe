use std::collections::BTreeSet;

use calyx_aster::vault::encode;
use calyx_core::{Result, Slot, SlotVector};
use sha2::{Digest, Sha256};

use super::codec::invalid;
use super::row_format::PendingPackedRow;
use super::simd;
use super::{MultiVectorCompressionConfig, MultiVectorCompressionRow};
use crate::spec::LensSpec;

const CODEC_CONTEXT_DOMAIN: &[u8] = b"calyx-colbert-residual-context-v1";

pub(super) fn normalized_corpus(rows: &[MultiVectorCompressionRow]) -> Result<Vec<Vec<f32>>> {
    let mut tokens = Vec::new();
    for row in rows {
        for token in &row.tokens {
            let mut normalized = token.clone();
            simd::normalize(&mut normalized)?;
            tokens.push(normalized);
        }
    }
    Ok(tokens)
}

pub(super) fn require_distinct_centroids(tokens: &[Vec<f32>], required: u32) -> Result<()> {
    let distinct = tokens
        .iter()
        .map(|token| {
            token
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>()
        .len();
    if distinct < required as usize {
        return Err(invalid(format!(
            "centroid_count {required} requires at least that many distinct normalized tokens, found {distinct}"
        )));
    }
    Ok(())
}

pub(super) fn train_centroids(
    tokens: &[Vec<f32>],
    dim: usize,
    count: usize,
    iterations: u32,
) -> Result<Vec<f32>> {
    let capacity = count
        .checked_mul(dim)
        .ok_or_else(|| invalid("centroid codebook capacity overflow"))?;
    let mut centroids = Vec::with_capacity(capacity);
    centroids.extend_from_slice(&tokens[0]);
    while centroids.len() / dim < count {
        let mut chosen = None;
        let mut chosen_similarity = f32::INFINITY;
        for (index, token) in tokens.iter().enumerate() {
            let mut best = f32::NEG_INFINITY;
            for centroid in centroids.chunks_exact(dim) {
                best = best.max(simd::dot(token, centroid)?);
            }
            if best < chosen_similarity {
                chosen_similarity = best;
                chosen = Some(index);
            }
        }
        centroids.extend_from_slice(&tokens[chosen.ok_or_else(|| invalid("no centroid seed"))?]);
    }
    let mut assignments = vec![0_usize; tokens.len()];
    for _ in 0..iterations {
        for (token_index, token) in tokens.iter().enumerate() {
            assignments[token_index] = nearest_centroid(token, &centroids, dim)?;
        }
        let mut sums = vec![0.0_f32; capacity];
        let mut counts = vec![0_u64; count];
        for (token, centroid) in tokens.iter().zip(&assignments) {
            counts[*centroid] += 1;
            for axis in 0..dim {
                sums[*centroid * dim + axis] += token[axis];
            }
        }
        for centroid in 0..count {
            if counts[centroid] == 0 {
                return Err(invalid(format!(
                    "deterministic centroid {centroid} became empty; reduce centroid_count"
                )));
            }
            simd::normalize(&mut sums[centroid * dim..(centroid + 1) * dim])?;
        }
        centroids = sums;
    }
    Ok(centroids)
}

pub(super) fn nearest_centroid(token: &[f32], centroids: &[f32], dim: usize) -> Result<usize> {
    let mut best_index = 0;
    let mut best_score = f32::NEG_INFINITY;
    for (index, centroid) in centroids.chunks_exact(dim).enumerate() {
        let score = simd::dot(token, centroid)?;
        if score > best_score {
            best_score = score;
            best_index = index;
        }
    }
    Ok(best_index)
}

pub(super) fn train_residual_buckets(
    tokens: &[Vec<f32>],
    centroids: &[f32],
    dim: usize,
) -> Result<([f32; 3], [f32; 4])> {
    let capacity = tokens
        .len()
        .checked_mul(dim)
        .ok_or_else(|| invalid("residual training capacity overflow"))?;
    let mut residuals = Vec::with_capacity(capacity);
    for token in tokens {
        let centroid = nearest_centroid(token, centroids, dim)?;
        for axis in 0..dim {
            residuals.push(token[axis] - centroids[centroid * dim + axis]);
        }
    }
    residuals.sort_by(f32::total_cmp);
    let cutoffs = [
        quantile(&residuals, 0.25),
        quantile(&residuals, 0.50),
        quantile(&residuals, 0.75),
    ];
    let weights = [
        quantile(&residuals, 0.125),
        quantile(&residuals, 0.375),
        quantile(&residuals, 0.625),
        quantile(&residuals, 0.875),
    ];
    Ok((cutoffs, weights))
}

fn quantile(sorted: &[f32], probability: f64) -> f32 {
    let position = probability * (sorted.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        return sorted[lower];
    }
    let fraction = (position - lower as f64) as f32;
    sorted[lower] + (sorted[upper] - sorted[lower]) * fraction
}

pub(super) fn pack_rows(
    rows: &[MultiVectorCompressionRow],
    token_dim: u32,
    config: MultiVectorCompressionConfig,
    centroids: &[f32],
    cutoffs: [f32; 3],
) -> Result<Vec<PendingPackedRow>> {
    let dim = token_dim as usize;
    let mut pending = Vec::with_capacity(rows.len());
    for row in rows {
        let token_count =
            u32::try_from(row.tokens.len()).map_err(|_| invalid("token count exceeds u32"))?;
        let code_capacity = row
            .tokens
            .len()
            .checked_mul(4)
            .ok_or_else(|| invalid("centroid code capacity overflow"))?;
        let residual_capacity = row
            .tokens
            .len()
            .checked_mul(dim / 4)
            .ok_or_else(|| invalid("packed residual capacity overflow"))?;
        let mut codes = Vec::with_capacity(code_capacity);
        let mut residuals = Vec::with_capacity(residual_capacity);
        for token in &row.tokens {
            let mut normalized = token.clone();
            simd::normalize(&mut normalized)?;
            let centroid = nearest_centroid(&normalized, centroids, dim)?;
            let centroid_code =
                u32::try_from(centroid).map_err(|_| invalid("centroid code exceeds u32"))?;
            codes.extend_from_slice(&centroid_code.to_be_bytes());
            for axes in (0..dim).step_by(4) {
                let mut packed = 0_u8;
                for lane in 0..4 {
                    let residual =
                        normalized[axes + lane] - centroids[centroid * dim + axes + lane];
                    packed |= bucket_index(residual, cutoffs) << (6 - lane * 2);
                }
                residuals.push(packed);
            }
        }
        let mut payload = codes;
        payload.extend_from_slice(&residuals);
        let raw_bytes = encode::encode_slot_vector(&SlotVector::Multi {
            token_dim,
            tokens: row.tokens.clone(),
        })?;
        if token_count > config.max_tokens {
            return Err(invalid("row exceeded max_tokens after validation"));
        }
        pending.push(PendingPackedRow {
            cx_id: row.cx_id,
            token_count,
            raw_bytes,
            payload,
        });
    }
    Ok(pending)
}

fn bucket_index(value: f32, cutoffs: [f32; 3]) -> u8 {
    if value <= cutoffs[0] {
        0
    } else if value <= cutoffs[1] {
        1
    } else if value <= cutoffs[2] {
        2
    } else {
        3
    }
}

pub(super) fn codec_context_id(
    slot: &Slot,
    lens: &LensSpec,
    config: MultiVectorCompressionConfig,
    centroids: &[f32],
    cutoffs: [f32; 3],
    weights: [f32; 4],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CODEC_CONTEXT_DOMAIN);
    hasher.update(slot.slot_id.get().to_be_bytes());
    hasher.update((slot.slot_key.key().len() as u64).to_be_bytes());
    hasher.update(slot.slot_key.key().as_bytes());
    hasher.update(lens.lens_id().as_bytes());
    hasher.update(config.max_tokens.to_be_bytes());
    hasher.update(config.max_token_dim.to_be_bytes());
    hasher.update(config.centroid_count.to_be_bytes());
    hasher.update(config.kmeans_iterations.to_be_bytes());
    hasher.update(config.max_score_error.to_bits().to_be_bytes());
    for value in centroids {
        hasher.update(value.to_bits().to_be_bytes());
    }
    for value in cutoffs {
        hasher.update(value.to_bits().to_be_bytes());
    }
    for value in weights {
        hasher.update(value.to_bits().to_be_bytes());
    }
    hasher.finalize().into()
}
