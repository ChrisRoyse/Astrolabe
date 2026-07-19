use std::path::Path;

use calyx_core::{CalyxError, Result, SlotShape, SlotVector, SparseEntry};
use ort::value::{TensorElementType, ValueType};

use super::batch::TokenBatch;
use super::{config_invalid, validate_config};
use crate::frozen::NormPolicy;
use crate::runtime::common::normalize_unit;
use crate::runtime::onnx::PoolingPolicy;
use crate::runtime::onnx::io_binding::MaterializedF32Output;

#[derive(Clone, Copy, Debug)]
pub(super) enum CustomOutput {
    Dense {
        dim: u32,
        pooling: PoolingPolicy,
        norm_policy: NormPolicy,
    },
    Sparse {
        dim: u32,
    },
}

pub(super) struct CustomOutputContract {
    pub(super) name: String,
    pub(super) output: CustomOutput,
}

impl CustomOutput {
    pub(super) const fn dim(self) -> u32 {
        match self {
            Self::Dense { dim, .. } | Self::Sparse { dim } => dim,
        }
    }

    pub(super) const fn shape(self) -> SlotShape {
        match self {
            Self::Dense { dim, .. } => SlotShape::Dense(dim),
            Self::Sparse { dim } => SlotShape::Sparse(dim),
        }
    }
}

pub(super) fn output_from_session(
    session: &ort::session::Session,
    expected_shape: Option<SlotShape>,
    pooling: PoolingPolicy,
    norm_policy: NormPolicy,
) -> Result<CustomOutputContract> {
    let metadata = output_metadata(session)?;
    if !matches!(metadata.rank, 2 | 3) {
        return Err(CalyxError {
            code: "CALYX_ONNX_OUTPUT_CONTRACT_RANK_UNSUPPORTED",
            message: format!(
                "custom ONNX exact output {:?} has rank {}, but dense execution supports only [batch,dim] or [batch,sequence,dim]",
                metadata.name, metadata.rank
            ),
            remediation: "export a rank-2 or rank-3 Float32 output and recommission the frozen model before constructing a session",
        });
    }
    let output = if matches!(expected_shape, Some(SlotShape::Sparse(_))) {
        if metadata.rank != 2 {
            return Err(CalyxError {
                code: "CALYX_ONNX_OUTPUT_CONTRACT_RANK_UNSUPPORTED",
                message: format!(
                    "custom ONNX sparse exact output {:?} has rank {}, expected [batch,dim]",
                    metadata.name, metadata.rank
                ),
                remediation: "export one rank-2 Float32 sparse-logit output and recommission the frozen model",
            });
        }
        CustomOutput::Sparse { dim: metadata.dim }
    } else {
        CustomOutput::Dense {
            dim: metadata.dim,
            pooling,
            norm_policy,
        }
    };
    let shape = output.shape();
    if let Some(expected) = expected_shape
        && expected != shape
    {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX output shape {shape:?} != declared {expected:?}"
        )));
    }
    Ok(CustomOutputContract {
        name: metadata.name,
        output,
    })
}

pub(super) fn vectors_from_output(
    output_tensor: &MaterializedF32Output,
    batch: &TokenBatch,
    output: CustomOutput,
) -> Result<Vec<SlotVector>> {
    match output {
        CustomOutput::Dense {
            dim,
            pooling,
            norm_policy,
        } => dense_output_batch(
            &output_tensor.shape,
            &output_tensor.values,
            batch,
            pooling,
            dim,
            norm_policy,
        ),
        CustomOutput::Sparse { dim } => {
            sparse_output_batch(&output_tensor.shape, &output_tensor.values, batch, dim)
        }
    }
}

pub(in crate::runtime::onnx) fn pooling_from_config(path: &Path) -> Result<PoolingPolicy> {
    let value = validate_config(path)?;
    let Some(raw) = value
        .get("pooling")
        .or_else(|| value.get("pooling_policy"))
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(PoolingPolicy::Mean);
    };
    match raw {
        "mean" => Ok(PoolingPolicy::Mean),
        "cls" => Ok(PoolingPolicy::Cls),
        "last_token" | "last-token" => Ok(PoolingPolicy::LastToken),
        other => Err(config_invalid(format!("unsupported ONNX pooling {other}"))),
    }
}

fn dense_output_batch(
    shape: &[i64],
    values: &[f32],
    batch: &TokenBatch,
    policy: PoolingPolicy,
    dim: u32,
    norm_policy: NormPolicy,
) -> Result<Vec<SlotVector>> {
    pool_output_batch(shape, values, batch, policy, dim)?
        .into_iter()
        .map(|mut data| {
            apply_norm(norm_policy, &mut data)?;
            Ok(SlotVector::Dense { dim, data })
        })
        .collect()
}

fn pool_output_batch(
    shape: &[i64],
    values: &[f32],
    batch: &TokenBatch,
    policy: PoolingPolicy,
    dim: u32,
) -> Result<Vec<Vec<f32>>> {
    let dim = dim as usize;
    match shape {
        [actual_batch, actual_dim]
            if positive_usize(*actual_batch) == Some(batch.batch)
                && positive_usize(*actual_dim) == Some(dim) =>
        {
            dense_rows(values, batch.batch, dim)
        }
        [actual_batch, seq, actual_dim]
            if positive_usize(*actual_batch) == Some(batch.batch)
                && positive_usize(*seq) == Some(batch.seq)
                && positive_usize(*actual_dim) == Some(dim) =>
        {
            token_rows(values, batch, dim, policy)
        }
        _ => Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX output shape {shape:?} is incompatible with batch={} seq={} dim={dim}",
            batch.batch, batch.seq
        ))),
    }
}

fn sparse_output_batch(
    shape: &[i64],
    values: &[f32],
    batch: &TokenBatch,
    dim: u32,
) -> Result<Vec<SlotVector>> {
    let dim_usize = dim as usize;
    match shape {
        [actual_batch, actual_dim]
            if positive_usize(*actual_batch) == Some(batch.batch)
                && positive_usize(*actual_dim) == Some(dim_usize) => {}
        _ => {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "custom ONNX sparse output shape {shape:?} must be [batch={}, dim={dim_usize}]",
                batch.batch
            )));
        }
    }
    let expected = batch.batch * dim_usize;
    if values.len() != expected {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX sparse output has {} floats, expected {expected}",
            values.len()
        )));
    }
    values
        .chunks_exact(dim_usize)
        .map(|row| {
            Ok(SlotVector::Sparse {
                dim,
                entries: positive_sparse_entries(row)?,
            })
        })
        .collect()
}

fn positive_sparse_entries(values: &[f32]) -> Result<Vec<SparseEntry>> {
    let mut entries = Vec::new();
    for (idx, val) in values.iter().copied().enumerate() {
        if !val.is_finite() {
            return Err(CalyxError::lens_numerical_invariant(
                "custom ONNX sparse output emitted NaN or Inf",
            ));
        }
        if val > 0.0 {
            let idx = u32::try_from(idx)
                .map_err(|_| CalyxError::lens_dim_mismatch("sparse output index exceeds u32"))?;
            entries.push(SparseEntry { idx, val });
        }
    }
    Ok(entries)
}

struct OutputMetadata {
    name: String,
    rank: usize,
    dim: u32,
}

fn output_metadata(session: &ort::session::Session) -> Result<OutputMetadata> {
    let tensor_outputs = session
        .outputs()
        .iter()
        .filter(|out| matches!(out.dtype(), ValueType::Tensor { .. }))
        .collect::<Vec<_>>();
    let [output] = tensor_outputs.as_slice() else {
        return Err(CalyxError {
            code: "CALYX_ONNX_OUTPUT_CONTRACT_AMBIGUOUS",
            message: format!(
                "custom ONNX model must expose exactly one unambiguous tensor output, observed {} tensor outputs {:?}",
                tensor_outputs.len(),
                tensor_outputs
                    .iter()
                    .map(|output| output.name())
                    .collect::<Vec<_>>()
            ),
            remediation: "export one exact tensor output; durable explicit multi-output selection is unavailable until issue #610 is implemented, so no preferred-name fallback is permitted",
        });
    };
    if output.name().is_empty()
        || output.name().trim() != output.name()
        || output.name().chars().any(char::is_control)
    {
        return Err(CalyxError {
            code: "CALYX_ONNX_OUTPUT_CONTRACT_AMBIGUOUS",
            message: format!(
                "custom ONNX tensor output name {:?} is not a canonical nonblank control-free identity",
                output.name()
            ),
            remediation: "export one stable output name with no surrounding whitespace or control characters",
        });
    }
    let ValueType::Tensor { ty, shape, .. } = output.dtype() else {
        unreachable!("tensor_outputs contains only tensor metadata");
    };
    if *ty != TensorElementType::Float32 {
        return Err(CalyxError {
            code: "CALYX_ONNX_OUTPUT_CONTRACT_DTYPE_MISMATCH",
            message: format!(
                "custom ONNX exact output {:?} is {ty}, expected Float32; shape={shape:?}",
                output.name()
            ),
            remediation: "export the frozen authoritative output as Float32 and recommission the model before constructing a session",
        });
    }
    let Some(dim) = shape.last().copied().filter(|dim| *dim > 0) else {
        return Err(CalyxError {
            code: "CALYX_ONNX_OUTPUT_CONTRACT_SHAPE_MISMATCH",
            message: format!(
                "custom ONNX exact output {:?} has no positive static final dimension; observed shape={shape:?}",
                output.name()
            ),
            remediation: "export an output with a positive frozen embedding dimension and recommission the model",
        });
    };
    Ok(OutputMetadata {
        name: output.name().to_string(),
        rank: shape.len(),
        dim: u32::try_from(dim)
            .map_err(|_| CalyxError::lens_dim_mismatch("custom ONNX dim exceeds u32"))?,
    })
}

fn positive_usize(value: i64) -> Option<usize> {
    usize::try_from(value).ok().filter(|value| *value > 0)
}

fn pool_tokens(
    values: &[f32],
    seq: usize,
    dim: usize,
    mask: &[i64],
    policy: PoolingPolicy,
) -> Result<Vec<f32>> {
    if values.len() != seq * dim {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX token output has {} floats, expected {}",
            values.len(),
            seq * dim
        )));
    }
    match policy {
        PoolingPolicy::Cls => Ok(values[..dim].to_vec()),
        PoolingPolicy::LastToken => {
            let index = mask
                .iter()
                .take(seq)
                .rposition(|value| *value > 0)
                .unwrap_or(seq.saturating_sub(1));
            Ok(values[index * dim..(index + 1) * dim].to_vec())
        }
        PoolingPolicy::Mean => {
            let mut out = vec![0.0; dim];
            let mut count = 0usize;
            for token in 0..seq {
                if mask.get(token).copied().unwrap_or(1) <= 0 {
                    continue;
                }
                count += 1;
                for axis in 0..dim {
                    out[axis] += values[token * dim + axis];
                }
            }
            if count == 0 {
                return Err(CalyxError::lens_numerical_invariant(
                    "custom ONNX mean pooling saw no unmasked tokens",
                ));
            }
            for value in &mut out {
                *value /= count as f32;
            }
            Ok(out)
        }
    }
}

fn dense_rows(values: &[f32], batch: usize, dim: usize) -> Result<Vec<Vec<f32>>> {
    let expected = batch * dim;
    if values.len() != expected {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX dense output has {} floats, expected {expected}",
            values.len()
        )));
    }
    Ok(values
        .chunks_exact(dim)
        .map(|row| row.to_vec())
        .collect::<Vec<_>>())
}

fn token_rows(
    values: &[f32],
    batch: &TokenBatch,
    dim: usize,
    policy: PoolingPolicy,
) -> Result<Vec<Vec<f32>>> {
    let expected = batch.batch * batch.seq * dim;
    if values.len() != expected {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX token output has {} floats, expected {expected}",
            values.len()
        )));
    }
    let mut rows = Vec::with_capacity(batch.batch);
    for row in 0..batch.batch {
        let token_start = row * batch.seq * dim;
        let token_end = token_start + batch.seq * dim;
        let mask_start = row * batch.seq;
        let mask_end = mask_start + batch.seq;
        rows.push(pool_tokens(
            &values[token_start..token_end],
            batch.seq,
            dim,
            &batch.mask[mask_start..mask_end],
            policy,
        )?);
    }
    Ok(rows)
}

fn apply_norm(policy: NormPolicy, data: &mut [f32]) -> Result<()> {
    match policy {
        NormPolicy::L2 { .. } | NormPolicy::Unit { .. } => normalize_unit(data),
        NormPolicy::None | NormPolicy::Finite | NormPolicy::DeclaredByModel { .. } => {
            if data.iter().all(|value| value.is_finite()) {
                Ok(())
            } else {
                Err(CalyxError::lens_numerical_invariant(
                    "custom ONNX emitted NaN or Inf",
                ))
            }
        }
    }
}
