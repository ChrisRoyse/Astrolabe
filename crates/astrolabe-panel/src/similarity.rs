//! Cosine similarity + trusted-region centroid over measured panel slot vectors.
//!
//! These primitives back the guard `guard_calibrate` **auto** path (#326): instead
//! of consuming operator-supplied per-slot cosine populations, the guard measures
//! sources through the real panel/lens stack, builds a trusted-region centroid per
//! slot from the in-distribution (good) measurements, and scores every good/bad
//! case as its cosine distance to that centroid. Those cosine populations feed the
//! existing split-conformal `conformal_tau` machinery unchanged.
//!
//! Cosine is scale-invariant, so the centroid is the plain arithmetic mean of the
//! measured payloads (no renormalization). An [`SlotVector::Absent`] carries no
//! direction: it is *skipped* by the centroid (never treated as a zero vector — a
//! zero vector would silently bias the mean, standing invariant #3) and yields
//! `Ok(None)` from [`slot_vector_cosine`] so the caller counts the gap rather than
//! inventing a score. A shape/dim mismatch is a fail-closed error — never a silent
//! zero — because comparing incompatible slots is a contract violation, not a miss.

use calyx_core::{SlotVector, SparseEntry};

use crate::{PanelError, PanelResult};

/// Error code: two slot vectors compared/aggregated under different shapes or dims.
pub const ASTRO_PANEL_COSINE_SHAPE_MISMATCH: &str = "ASTRO_PANEL_COSINE_SHAPE_MISMATCH";
/// Error code: a slot vector shape unsupported by the cosine/centroid primitives
/// (the guard slots are all Dense or Sparse; `Multi` late-interaction tokens are
/// not a single direction and are refused rather than silently flattened).
pub const ASTRO_PANEL_COSINE_UNSUPPORTED_SHAPE: &str = "ASTRO_PANEL_COSINE_UNSUPPORTED_SHAPE";

/// Cosine similarity in `[-1, 1]` between two measured slot vectors of identical
/// shape and dimension.
///
/// Returns `Ok(None)` when either vector is [`SlotVector::Absent`] (no direction to
/// compare) or has zero L2 norm (a genuinely empty measurement, e.g. an all-zero
/// sparse surface — undefined cosine). Fails closed on a shape or dim mismatch, and
/// on the unsupported `Multi` shape.
pub fn slot_vector_cosine(a: &SlotVector, b: &SlotVector) -> PanelResult<Option<f32>> {
    match (a, b) {
        (SlotVector::Absent { .. }, _) | (_, SlotVector::Absent { .. }) => Ok(None),
        (SlotVector::Dense { dim: da, data: xa }, SlotVector::Dense { dim: db, data: xb }) => {
            if da != db {
                return Err(shape_mismatch(format!(
                    "dense cosine dim mismatch: {da} vs {db}"
                )));
            }
            Ok(dense_cosine(xa, xb))
        }
        (
            SlotVector::Sparse {
                dim: da,
                entries: ea,
            },
            SlotVector::Sparse {
                dim: db,
                entries: eb,
            },
        ) => {
            if da != db {
                return Err(shape_mismatch(format!(
                    "sparse cosine dim mismatch: {da} vs {db}"
                )));
            }
            Ok(sparse_cosine(ea, eb))
        }
        (SlotVector::Multi { .. }, _) | (_, SlotVector::Multi { .. }) => Err(unsupported_shape()),
        _ => Err(shape_mismatch(
            "cosine requires both operands to share a shape (dense/dense or sparse/sparse)"
                .to_string(),
        )),
    }
}

/// Builds the trusted-region centroid (arithmetic mean direction) over a set of
/// measured slot vectors of identical shape.
///
/// [`SlotVector::Absent`] entries are skipped (not counted, not zero-filled). The
/// mean is over the *measured* vectors only. Returns `Ok(None)` when no measured
/// vector is present (no trusted region can be formed). Fails closed on a shape/dim
/// mismatch among the measured vectors, and on the unsupported `Multi` shape.
pub fn slot_centroid(vectors: &[&SlotVector]) -> PanelResult<Option<SlotVector>> {
    // First measured vector fixes the expected shape.
    let mut measured = vectors.iter().copied().filter(|vector| !vector.is_absent());
    let Some(first) = measured.next() else {
        return Ok(None);
    };
    match first {
        SlotVector::Dense { dim, data } => {
            let dim = *dim;
            let mut acc = vec![0.0f64; data.len()];
            let mut count = 0u64;
            for vector in vectors.iter().copied().filter(|v| !v.is_absent()) {
                let SlotVector::Dense {
                    dim: d,
                    data: values,
                } = vector
                else {
                    return Err(shape_mismatch(
                        "centroid mixes dense with a non-dense measured vector".to_string(),
                    ));
                };
                if *d != dim || values.len() != acc.len() {
                    return Err(shape_mismatch(format!(
                        "centroid dense dim mismatch: expected {dim} ({} values), got {d} ({} values)",
                        acc.len(),
                        values.len()
                    )));
                }
                for (slot, value) in acc.iter_mut().zip(values) {
                    *slot += f64::from(*value);
                }
                count += 1;
            }
            let inv = 1.0 / count as f64;
            let data = acc.into_iter().map(|sum| (sum * inv) as f32).collect();
            Ok(Some(SlotVector::Dense { dim, data }))
        }
        SlotVector::Sparse { dim, .. } => {
            let dim = *dim;
            let mut sums: std::collections::BTreeMap<u32, f64> = std::collections::BTreeMap::new();
            let mut count = 0u64;
            for vector in vectors.iter().copied().filter(|v| !v.is_absent()) {
                let SlotVector::Sparse { dim: d, entries } = vector else {
                    return Err(shape_mismatch(
                        "centroid mixes sparse with a non-sparse measured vector".to_string(),
                    ));
                };
                if *d != dim {
                    return Err(shape_mismatch(format!(
                        "centroid sparse dim mismatch: expected {dim}, got {d}"
                    )));
                }
                for entry in entries {
                    *sums.entry(entry.idx).or_insert(0.0) += f64::from(entry.val);
                }
                count += 1;
            }
            let inv = 1.0 / count as f64;
            let entries = sums
                .into_iter()
                .map(|(idx, sum)| SparseEntry {
                    idx,
                    val: (sum * inv) as f32,
                })
                .collect();
            Ok(Some(SlotVector::Sparse { dim, entries }))
        }
        SlotVector::Multi { .. } => Err(unsupported_shape()),
        SlotVector::Absent { .. } => unreachable!("filtered above"),
    }
}

fn dense_cosine(a: &[f32], b: &[f32]) -> Option<f32> {
    let mut dot = 0.0f64;
    let mut na = 0.0f64;
    let mut nb = 0.0f64;
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    normalize(dot, na, nb)
}

fn sparse_cosine(a: &[SparseEntry], b: &[SparseEntry]) -> Option<f32> {
    use std::collections::BTreeMap;
    let map_a: BTreeMap<u32, f64> = a.iter().map(|e| (e.idx, f64::from(e.val))).collect();
    let mut dot = 0.0f64;
    let mut nb = 0.0f64;
    for entry in b {
        let y = f64::from(entry.val);
        nb += y * y;
        if let Some(x) = map_a.get(&entry.idx) {
            dot += x * y;
        }
    }
    let na: f64 = map_a.values().map(|x| x * x).sum();
    normalize(dot, na, nb)
}

fn normalize(dot: f64, na: f64, nb: f64) -> Option<f32> {
    if na <= 0.0 || nb <= 0.0 {
        return None;
    }
    let cos = dot / (na.sqrt() * nb.sqrt());
    // Clamp the tiny floating-point overshoot past +-1 so downstream conformal
    // math always sees a valid cosine.
    Some(cos.clamp(-1.0, 1.0) as f32)
}

fn shape_mismatch(message: String) -> PanelError {
    PanelError::new(
        ASTRO_PANEL_COSINE_SHAPE_MISMATCH,
        message,
        "Compare only slot vectors of the same slot (identical shape and dim).",
    )
}

fn unsupported_shape() -> PanelError {
    PanelError::new(
        ASTRO_PANEL_COSINE_UNSUPPORTED_SHAPE,
        "cosine/centroid over a Multi (late-interaction token) slot is unsupported",
        "Score guard slots, which are all Dense or Sparse; do not pass the S22 token_multi slot.",
    )
}
