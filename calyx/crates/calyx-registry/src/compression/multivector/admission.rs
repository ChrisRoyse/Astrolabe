use std::collections::{BTreeMap, BTreeSet};

use calyx_core::{CxId, Result};
use sha2::{Digest, Sha256};

use super::codec::{invalid, prepare_maxsim_query, score_prepared_maxsim};
use super::simd;
use super::{
    MultiVectorCompressionQuery, MultiVectorCompressionRow, PackedMaxSimScratch,
    PackedMultiVectorManifest, PackedMultiVectorRow, parse_packed_multivector_row,
};

const RANKING_ROOT_DOMAIN: &[u8] = b"calyx-colbert-residual-ranking-v1";

pub(super) struct Admission {
    pub recall_at_k: f32,
    pub max_abs_score_error: f32,
    pub mean_abs_score_error: f32,
    pub exact_ranking_root: [u8; 32],
    pub packed_ranking_root: [u8; 32],
}

pub(super) fn measure_admission(
    queries: &[MultiVectorCompressionQuery],
    raw_rows: &[MultiVectorCompressionRow],
    packed_rows: &[PackedMultiVectorRow],
    manifest: &PackedMultiVectorManifest,
    k: usize,
) -> Result<Admission> {
    let raw_map: BTreeMap<CxId, &MultiVectorCompressionRow> =
        raw_rows.iter().map(|row| (row.cx_id, row)).collect();
    let mut scratch = PackedMaxSimScratch::default();
    let mut exact_rankings = Vec::with_capacity(queries.len());
    let mut packed_rankings = Vec::with_capacity(queries.len());
    let mut error_sum = 0.0_f64;
    let mut error_count = 0_u64;
    let mut max_error = 0.0_f32;
    let mut recall_sum = 0.0_f64;
    let mut exact_maxima = Vec::new();
    let mut normalized_document = Vec::new();
    for query in queries {
        prepare_maxsim_query(&query.tokens, manifest, &mut scratch)?;
        let mut exact_scores = Vec::with_capacity(raw_rows.len());
        let mut packed_scores = Vec::with_capacity(raw_rows.len());
        for packed in packed_rows {
            let raw = raw_map
                .get(&packed.cx_id)
                .ok_or_else(|| invalid("packed admission row has no exact source"))?;
            let exact = exact_maxsim(
                &scratch.normalized_query,
                scratch.query_tokens,
                &raw.tokens,
                manifest.token_dim as usize,
                &mut exact_maxima,
                &mut normalized_document,
            )?;
            let parsed =
                parse_packed_multivector_row(&packed.packed_bytes, manifest, packed.cx_id)?;
            let approximate = score_prepared_maxsim(&parsed, manifest, &mut scratch)?;
            let error = (exact - approximate).abs();
            max_error = max_error.max(error);
            error_sum += f64::from(error);
            error_count += 1;
            exact_scores.push((packed.cx_id, exact));
            packed_scores.push((packed.cx_id, approximate));
        }
        sort_scores(&mut exact_scores);
        sort_scores(&mut packed_scores);
        let exact_top: BTreeSet<CxId> = exact_scores
            .iter()
            .take(k)
            .map(|(cx_id, _)| *cx_id)
            .collect();
        let packed_top: BTreeSet<CxId> = packed_scores
            .iter()
            .take(k)
            .map(|(cx_id, _)| *cx_id)
            .collect();
        recall_sum += exact_top.intersection(&packed_top).count() as f64 / k as f64;
        exact_rankings.push((query.cx_id, exact_scores));
        packed_rankings.push((query.cx_id, packed_scores));
    }
    Ok(Admission {
        recall_at_k: (recall_sum / queries.len() as f64) as f32,
        max_abs_score_error: max_error,
        mean_abs_score_error: (error_sum / error_count as f64) as f32,
        exact_ranking_root: ranking_root(b"exact", &exact_rankings),
        packed_ranking_root: ranking_root(b"packed", &packed_rankings),
    })
}

fn exact_maxsim(
    normalized_query: &[f32],
    query_tokens: usize,
    document: &[Vec<f32>],
    dim: usize,
    maxima: &mut Vec<f32>,
    normalized_document: &mut Vec<f32>,
) -> Result<f32> {
    maxima.clear();
    maxima.resize(query_tokens, f32::NEG_INFINITY);
    for document_token in document {
        normalized_document.clear();
        normalized_document.extend_from_slice(document_token);
        simd::normalize(normalized_document)?;
        for (query_index, query_token) in normalized_query.chunks_exact(dim).enumerate() {
            let score = simd::dot(query_token, normalized_document)?;
            if score > maxima[query_index] {
                maxima[query_index] = score;
            }
        }
    }
    Ok(maxima.iter().sum())
}

fn sort_scores(scores: &mut [(CxId, f32)]) {
    scores.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
}

fn ranking_root(label: &[u8], rankings: &[(CxId, Vec<(CxId, f32)>)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RANKING_ROOT_DOMAIN);
    hasher.update(label);
    hasher.update((rankings.len() as u64).to_be_bytes());
    for (query, ranking) in rankings {
        hasher.update(query.as_bytes());
        hasher.update((ranking.len() as u64).to_be_bytes());
        for (cx_id, score) in ranking {
            hasher.update(cx_id.as_bytes());
            hasher.update(score.to_bits().to_be_bytes());
        }
    }
    hasher.finalize().into()
}
