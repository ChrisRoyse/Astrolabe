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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PanelInput, encode_slot};
    use astrolabe_domain::SymbolLabel;
    use calyx_core::{AbsentReason, SlotId};

    fn dense(values: &[f32]) -> SlotVector {
        SlotVector::Dense {
            dim: values.len() as u32,
            data: values.to_vec(),
        }
    }

    fn sparse(dim: u32, entries: &[(u32, f32)]) -> SlotVector {
        SlotVector::Sparse {
            dim,
            entries: entries
                .iter()
                .map(|(idx, val)| SparseEntry {
                    idx: *idx,
                    val: *val,
                })
                .collect(),
        }
    }

    #[test]
    fn identical_dense_vectors_are_cosine_one() {
        let v = dense(&[1.0, 2.0, 3.0]);
        let cos = slot_vector_cosine(&v, &v).unwrap().unwrap();
        assert!((cos - 1.0).abs() < 1e-6, "cos {cos}");
    }

    #[test]
    fn orthogonal_dense_vectors_are_cosine_zero() {
        let a = dense(&[1.0, 0.0]);
        let b = dense(&[0.0, 1.0]);
        let cos = slot_vector_cosine(&a, &b).unwrap().unwrap();
        assert!(cos.abs() < 1e-6, "cos {cos}");
    }

    #[test]
    fn opposite_dense_vectors_are_cosine_minus_one() {
        let a = dense(&[1.0, 1.0]);
        let b = dense(&[-1.0, -1.0]);
        let cos = slot_vector_cosine(&a, &b).unwrap().unwrap();
        assert!((cos + 1.0).abs() < 1e-6, "cos {cos}");
    }

    #[test]
    fn sparse_cosine_uses_only_matching_indices() {
        // a . b = 2*4 (idx 1) = 8; |a|=sqrt(1+4)=sqrt5; |b|=sqrt(16+9)=5.
        let a = sparse(65_536, &[(0, 1.0), (1, 2.0)]);
        let b = sparse(65_536, &[(1, 4.0), (2, 3.0)]);
        let cos = slot_vector_cosine(&a, &b).unwrap().unwrap();
        let expected = 8.0f32 / (5.0f32.sqrt() * 5.0);
        assert!(
            (cos - expected).abs() < 1e-6,
            "cos {cos} expected {expected}"
        );
    }

    #[test]
    fn absent_operand_yields_none_not_zero() {
        let a = dense(&[1.0, 2.0]);
        let absent = SlotVector::Absent {
            reason: AbsentReason::NotApplicable,
        };
        assert!(slot_vector_cosine(&a, &absent).unwrap().is_none());
        assert!(slot_vector_cosine(&absent, &a).unwrap().is_none());
    }

    #[test]
    fn zero_norm_yields_none() {
        let a = dense(&[0.0, 0.0]);
        let b = dense(&[1.0, 1.0]);
        assert!(slot_vector_cosine(&a, &b).unwrap().is_none());
    }

    #[test]
    fn dim_mismatch_fails_closed() {
        let a = dense(&[1.0, 2.0]);
        let b = dense(&[1.0, 2.0, 3.0]);
        let err = slot_vector_cosine(&a, &b).unwrap_err();
        assert_eq!(err.code(), ASTRO_PANEL_COSINE_SHAPE_MISMATCH);
    }

    #[test]
    fn shape_mismatch_dense_vs_sparse_fails_closed() {
        let a = dense(&[1.0, 2.0]);
        let b = sparse(2, &[(0, 1.0)]);
        let err = slot_vector_cosine(&a, &b).unwrap_err();
        assert_eq!(err.code(), ASTRO_PANEL_COSINE_SHAPE_MISMATCH);
    }

    #[test]
    fn dense_centroid_is_arithmetic_mean_and_skips_absent() {
        let a = dense(&[1.0, 3.0]);
        let b = dense(&[3.0, 1.0]);
        let absent = SlotVector::Absent {
            reason: AbsentReason::LensUnavailable,
        };
        let centroid = slot_centroid(&[&a, &absent, &b]).unwrap().unwrap();
        // Absent is not zero-filled: mean is over the two measured vectors => [2,2].
        assert_eq!(centroid.as_dense().unwrap(), &[2.0, 2.0]);
    }

    #[test]
    fn empty_or_all_absent_centroid_is_none() {
        assert!(slot_centroid(&[]).unwrap().is_none());
        let absent = SlotVector::Absent {
            reason: AbsentReason::NotApplicable,
        };
        assert!(slot_centroid(&[&absent, &absent]).unwrap().is_none());
    }

    #[test]
    fn sparse_centroid_averages_over_measured_count() {
        let a = sparse(16, &[(1, 2.0), (3, 4.0)]);
        let b = sparse(16, &[(1, 4.0)]);
        let centroid = slot_centroid(&[&a, &b]).unwrap().unwrap();
        let SlotVector::Sparse { entries, .. } = centroid else {
            panic!("expected sparse centroid");
        };
        // idx1: (2+4)/2 = 3; idx3: (4+0)/2 = 2.
        let get = |idx: u32| entries.iter().find(|e| e.idx == idx).map(|e| e.val);
        assert_eq!(get(1), Some(3.0));
        assert_eq!(get(3), Some(2.0));
    }

    #[test]
    fn centroid_shape_mismatch_fails_closed() {
        let a = dense(&[1.0, 2.0]);
        let b = dense(&[1.0, 2.0, 3.0]);
        let err = slot_centroid(&[&a, &b]).unwrap_err();
        assert_eq!(err.code(), ASTRO_PANEL_COSINE_SHAPE_MISMATCH);
    }

    /// FSV over the *real* panel encoders: two structurally similar symbols and one
    /// structurally alien symbol, measured through the real S1 struct-trigram lens.
    /// The alien symbol must score a strictly lower cosine to the trusted (similar)
    /// centroid than an in-distribution symbol does — the exact good-vs-bad
    /// separation the guard auto path relies on.
    #[test]
    fn real_encoder_struct_trigram_cosine_separates_alien_from_trusted() {
        use crate::{ApiCall, ComplexityMetrics, EncoderLensInput, StructuralTrigram};

        let trigrams = |tris: &[(&str, &str, &str)]| -> Vec<StructuralTrigram> {
            tris.iter()
                .map(|(a, b, c)| StructuralTrigram {
                    a: (*a).to_string(),
                    b: (*b).to_string(),
                    c: (*c).to_string(),
                    weight: 1.0,
                })
                .collect()
        };
        let measure = |tris: Vec<StructuralTrigram>| -> SlotVector {
            let input = EncoderLensInput {
                struct_trigrams: Some(tris),
                ..empty_encoder_input()
            };
            encode_slot(SlotId::new(1), &input).expect("S1 struct trigram encodes")
        };

        // Two trusted symbols share most of their structural trigrams.
        let good_a = measure(trigrams(&[
            ("function_definition", "parameters", "identifier"),
            ("if_statement", "comparison_operator", "identifier"),
            ("return_statement", "binary_expression", "identifier"),
        ]));
        let good_b = measure(trigrams(&[
            ("function_definition", "parameters", "identifier"),
            ("if_statement", "comparison_operator", "identifier"),
            ("return_statement", "binary_expression", "number"),
        ]));
        // The alien symbol shares none of the trusted trigrams.
        let alien = measure(trigrams(&[
            ("class_definition", "block", "method"),
            ("for_statement", "call_expression", "argument_list"),
            ("try_statement", "except_clause", "raise_statement"),
        ]));

        let centroid = slot_centroid(&[&good_a, &good_b]).unwrap().unwrap();
        let good_cos = slot_vector_cosine(&good_a, &centroid).unwrap().unwrap();
        let alien_cos = slot_vector_cosine(&alien, &centroid).unwrap().unwrap();
        assert!(
            good_cos > alien_cos,
            "trusted cosine {good_cos} must exceed alien cosine {alien_cos}"
        );
        assert!(
            alien_cos < good_cos - 0.2,
            "alien symbol must be clearly separated: good {good_cos}, alien {alien_cos}"
        );

        // Keep the imports honest: the panel input builder and API-call type are
        // exercised so a future signature drift is caught by this FSV.
        let _ = PanelInput::fixture(SymbolLabel::Function);
        let _ = ApiCall {
            callee: "x".to_string(),
            call_count: 1.0,
            resolved: true,
        };
        let _ = ComplexityMetrics {
            cyclomatic: 1.0,
            cognitive: 1.0,
            loop_count: 0.0,
            loop_depth: 0.0,
            max_access_depth: 0.0,
            param_count: 0.0,
            body_lines: 1.0,
            body_tokens: 1.0,
        };
    }

    fn empty_encoder_input() -> crate::EncoderLensInput {
        crate::EncoderLensInput {
            ast_profile: None,
            struct_trigrams: None,
            complexity: None,
            api_calls: None,
            type_surface: None,
            decorators: None,
            identifiers: None,
            graph_position: None,
            path_hierarchy: None,
            churn_profile: None,
            recency: None,
            role_flags: None,
            lang_label: None,
            test_topology: None,
            error_surface: None,
            config_env_surface: None,
            route_surface: None,
            record_vec: None,
        }
    }
}
