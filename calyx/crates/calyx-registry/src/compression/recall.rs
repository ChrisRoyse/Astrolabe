use calyx_core::{CalyxError, CxId, Result, Slot, SlotShape};
use std::collections::BinaryHeap;

use super::codec::{CodecContext, EncodedRow, parse_stored_slot};
use super::{
    CALYX_VECTOR_COMPRESSION_EMPTY, CALYX_VECTOR_COMPRESSION_INVALID, CompressionQuery,
    SlotCompressionReport, compression_error,
};
use crate::spec::LensSpec;

pub(super) fn validate_batch(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
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
    if k >= rows.len() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "recall@k requires k smaller than the corpus so compression can change membership; requested k={k} for {} rows",
                rows.len()
            ),
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
    let effective_dim = lens.truncate_dim.unwrap_or(dim);
    if effective_dim == 0 || effective_dim > dim {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "recall admission effective dimension {effective_dim} is invalid for raw dimension {dim}"
            ),
        ));
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
    let row_ids = rows
        .iter()
        .map(|(cx_id, _)| *cx_id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut query_ids = std::collections::BTreeSet::new();
    for (query_index, query) in queries.iter().enumerate() {
        if row_ids.contains(&query.cx_id) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "recall query id {} is also a stored-row id; use a disjoint independently produced query corpus",
                    query.cx_id
                ),
            ));
        }
        if !query_ids.insert(query.cx_id) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!("duplicate recall query id {}", query.cx_id),
            ));
        }
        validate_dense(&query.values, dim)?;
        let effective_query = &query.values[..effective_dim as usize];
        if let Some((row_id, _)) = rows
            .iter()
            .find(|(_, row)| same_positive_ray(effective_query, &row[..effective_dim as usize]))
        {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "recall query {} lies on the same positive ray as stored row {row_id} in effective dimension {effective_dim}; use an independently produced directionally distinct query corpus",
                    query.cx_id
                ),
            ));
        }
        if let Some(previous) = queries[..query_index].iter().find(|previous| {
            same_positive_ray(effective_query, &previous.values[..effective_dim as usize])
        }) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "recall query {} duplicates the positive ray of prior query {} in effective dimension {effective_dim}; repeated/scaled queries cannot weight admission",
                    query.cx_id, previous.cx_id
                ),
            ));
        }
        validate_query_discrimination(&query.values, rows, k)?;
    }
    Ok(())
}

fn same_positive_ray(left: &[f32], right: &[f32]) -> bool {
    let Some(pivot) = left
        .iter()
        .zip(right)
        .position(|(&left, &right)| left != 0.0 || right != 0.0)
    else {
        return true;
    };
    let left_pivot = left[pivot];
    let right_pivot = right[pivot];
    if left_pivot == 0.0
        || right_pivot == 0.0
        || left_pivot.is_sign_negative() != right_pivot.is_sign_negative()
    {
        return false;
    }
    left.iter().zip(right).all(|(&left, &right)| {
        f64::from(left) * f64::from(right_pivot) == f64::from(right) * f64::from(left_pivot)
    })
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
    queries: &[CompressionQuery],
    encoded: &[EncodedRow],
    codec: &CodecContext,
    k: usize,
    truncate_dim: Option<u32>,
) -> Result<f32> {
    let mut total = 0.0;
    for query in queries {
        let exact = top_k(
            &query.values,
            rows.iter().map(|(id, raw)| (*id, raw.as_slice())),
            k,
        )?;
        let prepared_query = prepare_dense(&query.values, truncate_dim)?;
        let prepared_query = codec.prepare_query(&prepared_query)?;
        let approx = top_k_persisted(codec, &prepared_query, encoded, k)?;
        let overlap = approx.iter().filter(|id| exact.contains(id)).count();
        total += overlap as f32 / k as f32;
    }
    Ok(total / queries.len() as f32)
}

pub(super) fn recall_drop(report: &SlotCompressionReport) -> f32 {
    report.recall_drop
}

fn top_k<'a>(
    query: &[f32],
    candidates: impl Iterator<Item = (CxId, &'a [f32])>,
    k: usize,
) -> Result<Vec<CxId>> {
    let mut scored = BinaryHeap::with_capacity(k);
    for (id, candidate) in candidates {
        retain_top_k(&mut scored, (id, cosine(query, candidate)?), k);
    }
    let mut scored = scored.into_vec();
    scored.sort();
    Ok(scored.into_iter().map(|hit| hit.0.0).collect())
}

fn top_k_persisted(
    codec: &CodecContext,
    query: &super::codec::PreparedSlotQuery,
    candidates: &[EncodedRow],
    k: usize,
) -> Result<Vec<CxId>> {
    let boundary_size = k.checked_add(1).ok_or_else(|| {
        compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "compressed recall boundary size overflow",
        )
    })?;
    let mut best = BinaryHeap::with_capacity(boundary_size);
    for row in candidates {
        let parsed = parse_stored_slot(&row.stored_bytes)?;
        let score = codec.score_parsed(query, &parsed)?;
        if !score.is_finite() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "persisted packed scorer returned non-finite score for {}",
                    row.cx_id
                ),
            ));
        }
        retain_top_k(&mut best, (row.cx_id, score), boundary_size);
    }
    let mut best = best.into_vec();
    best.sort();
    if best.len() <= k {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "compressed recall scorer produced only {} ranked candidates for k={k}",
                best.len()
            ),
        ));
    }
    if best[k - 1].0.1.total_cmp(&best[k].0.1).is_eq() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "compressed recall score is tied at the k={k} membership boundary; use a corpus and operating point with discriminating persisted scores"
            ),
        ));
    }
    best.truncate(k);
    Ok(best.into_iter().map(|hit| hit.0.0).collect())
}

struct HeapScore((CxId, f32));

impl PartialEq for HeapScore {
    fn eq(&self, other: &Self) -> bool {
        compare_score(&self.0, &other.0).is_eq()
    }
}

impl Eq for HeapScore {}

impl PartialOrd for HeapScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        compare_score(&self.0, &other.0)
    }
}

fn retain_top_k(best: &mut BinaryHeap<HeapScore>, hit: (CxId, f32), k: usize) {
    if best.len() < k {
        best.push(HeapScore(hit));
        return;
    }
    let Some(worst) = best.peek() else {
        return;
    };
    if compare_score(&hit, &worst.0).is_lt() {
        best.pop();
        best.push(HeapScore(hit));
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

fn validate_query_discrimination(query: &[f32], rows: &[(CxId, Vec<f32>)], k: usize) -> Result<()> {
    let squared_norm = query.iter().try_fold(0.0_f64, |sum, value| {
        let next = sum + f64::from(*value) * f64::from(*value);
        next.is_finite().then_some(next)
    });
    if squared_norm.is_none_or(|norm| norm == 0.0) {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "recall admission query must have a finite non-zero norm",
        ));
    }
    let mut scores = rows
        .iter()
        .map(|(cx_id, row)| cosine(query, row).map(|score| (*cx_id, score)))
        .collect::<Result<Vec<_>>>()?;
    scores.sort_by(|(left_id, left), (right_id, right)| {
        right
            .total_cmp(left)
            .then_with(|| left_id.as_bytes().cmp(right_id.as_bytes()))
    });
    if scores[k - 1].1.total_cmp(&scores[k].1).is_eq() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "recall query has a tied exact score at the k={k} membership boundary; use a discriminating query corpus"
            ),
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
    let squared_norm = values.iter().try_fold(0.0_f64, |sum, value| {
        let next = sum + f64::from(*value) * f64::from(*value);
        next.is_finite().then_some(next)
    });
    let norm = squared_norm
        .ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "Matryoshka prefix norm overflowed",
            )
        })?
        .sqrt();
    if norm == 0.0 {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "cannot normalize a zero Matryoshka prefix",
        ));
    }
    for value in values {
        let normalized = f64::from(*value) / norm;
        if !normalized.is_finite() || normalized.abs() > f64::from(f32::MAX) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "normalized Matryoshka coefficient is not finite f32",
            ));
        }
        *value = normalized as f32;
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
    let mut dot = 0.0_f64;
    let mut lhs_norm = 0.0_f64;
    let mut rhs_norm = 0.0_f64;
    for (lhs, rhs) in left.iter().zip(right) {
        dot += f64::from(*lhs) * f64::from(*rhs);
        lhs_norm += f64::from(*lhs) * f64::from(*lhs);
        rhs_norm += f64::from(*rhs) * f64::from(*rhs);
        if !dot.is_finite() || !lhs_norm.is_finite() || !rhs_norm.is_finite() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "cosine accumulation overflowed",
            ));
        }
    }
    if lhs_norm == 0.0 || rhs_norm == 0.0 {
        return Ok(0.0);
    }
    let score = dot / (lhs_norm.sqrt() * rhs_norm.sqrt());
    if !score.is_finite() || score.abs() > f64::from(f32::MAX) {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "cosine score is not a finite f32",
        ));
    }
    Ok(score as f32)
}
