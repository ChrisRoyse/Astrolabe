use calyx_core::{CalyxError, CxId, Result, Slot, SlotShape};

use super::codec::{CodecContext, EncodedRow, parse_stored_slot};
use super::{
    CALYX_VECTOR_COMPRESSION_EMPTY, CALYX_VECTOR_COMPRESSION_INVALID, SlotCompressionReport,
    compression_error,
};
use crate::spec::LensSpec;

pub(super) fn validate_batch(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[Vec<f32>],
    k: usize,
) -> Result<()> {
    if rows.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "cannot compress an empty slot batch",
        ));
    }
    if k == 0 {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "recall@k requires k > 0",
        ));
    }
    if k > rows.len() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!("recall@k requested k={k} for only {} rows", rows.len()),
        ));
    }
    if queries.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "recall admission requires an explicit non-empty query set distinct from the stored-row iterator",
        ));
    }
    if !lens.recall_delta.is_finite() || !(0.0..=1.0).contains(&lens.recall_delta) {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "lens recall_delta must be finite and within [0,1], got {}",
                lens.recall_delta
            ),
        ));
    }
    let SlotShape::Dense(dim) = slot.shape else {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "slot compression currently requires dense slots",
        ));
    };
    if lens.output != slot.shape {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "lens output {:?} does not match slot shape {:?}",
            lens.output, slot.shape
        )));
    }
    let mut ids = std::collections::BTreeSet::new();
    for (cx_id, row) in rows {
        if !ids.insert(*cx_id) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!("duplicate compressed row id {cx_id}"),
            ));
        }
        validate_dense(row, dim)?;
    }
    for query in queries {
        validate_dense(query, dim)?;
    }
    Ok(())
}

pub fn matryoshka_truncate_renormalize(raw: &[f32], truncate_dim: u32) -> Result<Vec<f32>> {
    let dim = truncate_dim as usize;
    if dim == 0 || dim > raw.len() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "truncate_dim {truncate_dim} invalid for vector dim {}",
                raw.len()
            ),
        ));
    }
    let mut out = raw[..dim].to_vec();
    normalize_unit(&mut out)?;
    Ok(out)
}

pub(super) fn prepare_dense(raw: &[f32], truncate_dim: Option<u32>) -> Result<Vec<f32>> {
    if let Some(dim) = truncate_dim {
        matryoshka_truncate_renormalize(raw, dim)
    } else {
        Ok(raw.to_vec())
    }
}

pub(super) fn recall_at_k(
    rows: &[(CxId, Vec<f32>)],
    queries: &[Vec<f32>],
    encoded: &[EncodedRow],
    codec: &CodecContext,
    k: usize,
    truncate_dim: Option<u32>,
) -> Result<f32> {
    let mut total = 0.0;
    for query in queries {
        let exact = top_k(query, rows.iter().map(|(id, raw)| (*id, raw.as_slice())), k)?;
        let prepared_query = prepare_dense(query, truncate_dim)?;
        let prepared_query = codec.prepare_query(&prepared_query)?;
        let approx = top_k_persisted(codec, &prepared_query, encoded, k)?;
        let overlap = approx.iter().filter(|id| exact.contains(id)).count();
        total += overlap as f32 / k as f32;
    }
    Ok(total / queries.len() as f32)
}

pub(super) fn recall_drop(report: &SlotCompressionReport) -> f32 {
    report.recall_at_k_raw - report.recall_at_k_compressed
}

fn top_k<'a>(
    query: &[f32],
    candidates: impl Iterator<Item = (CxId, &'a [f32])>,
    k: usize,
) -> Result<Vec<CxId>> {
    let mut scored = candidates
        .map(|(id, candidate)| cosine(query, candidate).map(|score| (id, score)))
        .collect::<Result<Vec<_>>>()?;
    scored.sort_by(|(left_id, left), (right_id, right)| {
        right
            .total_cmp(left)
            .then_with(|| left_id.to_bytes().cmp(&right_id.to_bytes()))
    });
    Ok(scored.into_iter().take(k).map(|(id, _)| id).collect())
}

fn top_k_persisted(
    codec: &CodecContext,
    query: &super::codec::PreparedSlotQuery,
    candidates: &[EncodedRow],
    k: usize,
) -> Result<Vec<CxId>> {
    let mut best: Vec<(CxId, f32)> = Vec::with_capacity(k);
    for row in candidates {
        let parsed = parse_stored_slot(&row.stored_bytes)?;
        let score = codec.score_parsed(query, &parsed)?;
        if !score.is_finite() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!("persisted packed scorer returned non-finite score for {}", row.cx_id),
            ));
        }
        retain_top_k(&mut best, (row.cx_id, score), k);
    }
    best.sort_by(compare_score);
    Ok(best.into_iter().map(|(id, _)| id).collect())
}

fn retain_top_k(best: &mut Vec<(CxId, f32)>, hit: (CxId, f32), k: usize) {
    if best.len() < k {
        best.push(hit);
        return;
    }
    let Some((worst_index, worst)) = best
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| compare_score(left, right))
    else {
        return;
    };
    if compare_score(&hit, worst).is_lt() {
        best[worst_index] = hit;
    }
}

fn compare_score(left: &(CxId, f32), right: &(CxId, f32)) -> std::cmp::Ordering {
    right
        .1
        .total_cmp(&left.1)
        .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
}

fn validate_dense(values: &[f32], dim: u32) -> Result<()> {
    if values.len() != dim as usize {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "slot vector dim {} does not match slot shape {dim}",
            values.len()
        )));
    }
    if let Some(idx) = values.iter().position(|value| !value.is_finite()) {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!("non-finite coefficient at index {idx}"),
        ));
    }
    Ok(())
}

fn normalize_unit(values: &mut [f32]) -> Result<()> {
    if let Some(idx) = values.iter().position(|value| !value.is_finite()) {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!("non-finite coefficient at index {idx}"),
        ));
    }
    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    if !norm.is_finite() || norm <= f32::EPSILON {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "cannot normalize zero or non-finite Matryoshka prefix",
        ));
    }
    for value in values {
        *value /= norm;
    }
    Ok(())
}

fn cosine(left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "cosine dim {} != {}",
            left.len(),
            right.len()
        )));
    }
    let mut dot = 0.0;
    let mut lhs_norm = 0.0;
    let mut rhs_norm = 0.0;
    for (lhs, rhs) in left.iter().zip(right) {
        dot += lhs * rhs;
        lhs_norm += lhs * lhs;
        rhs_norm += rhs * rhs;
    }
    if lhs_norm <= f32::EPSILON || rhs_norm <= f32::EPSILON {
        return Ok(0.0);
    }
    Ok(dot / (lhs_norm.sqrt() * rhs_norm.sqrt()))
}
