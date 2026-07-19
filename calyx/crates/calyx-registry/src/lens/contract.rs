use calyx_core::{CalyxError, QuantPolicy, Result, SlotShape};

use crate::frozen::FrozenLensContract;
use crate::spec::LensSpec;

pub(super) fn ensure_spec_declares_contract(
    contract: &FrozenLensContract,
    spec: &LensSpec,
) -> Result<()> {
    validate_quant_policy_for_shape(&spec.name, spec.output, spec.quant_default)?;
    let declared = spec.declared_contract();
    if declared == *contract {
        return Ok(());
    }
    Err(CalyxError::lens_frozen_violation(format!(
        "LensSpec {} declares frozen contract {}, but registry contract is {}",
        spec.name,
        declared.lens_id(),
        contract.lens_id()
    )))
}

/// Configuration-time storage-identity gate: a lens spec may only declare a
/// quantization policy its physical shape can actually persist. Dense-only
/// codecs are refused for sparse/multi shapes here — before any catalog or
/// registry mutation — instead of being advertised and failing at compression
/// time. Multi-vector residual storage is likewise refused for dense/sparse
/// shapes. `QuantPolicy::Pq` has no implemented persisted contract and is
/// refused for every shape at configuration time.
pub fn validate_quant_policy_for_shape(
    name: &str,
    shape: SlotShape,
    policy: QuantPolicy,
) -> Result<()> {
    if let QuantPolicy::Pq { m, nbits } = policy {
        return Err(CalyxError {
            code: "CALYX_LENS_QUANT_POLICY_UNIMPLEMENTED",
            message: format!(
                "lens {name} declares QuantPolicy::Pq {{ m: {m}, nbits: {nbits} }}, but no \
                 versioned persisted slot-PQ contract is implemented; the policy may not be \
                 advertised and fail later"
            ),
            remediation: "declare QuantPolicy::None or a supported TurboQuant/MxFp4/Float8/\
                          Binary policy for dense shapes",
        });
    }
    match shape {
        SlotShape::Dense(_) => match policy {
            QuantPolicy::ColbertResidual2Bit => Err(shape_policy_error(
                name,
                shape,
                policy,
                "ColBERT residual storage is defined only for multi-vector token matrices",
            )),
            _ => Ok(()),
        },
        SlotShape::Sparse(_) => match policy {
            QuantPolicy::None => Ok(()),
            other => Err(shape_policy_error(
                name,
                shape,
                other,
                "sparse storage has no commissioned compression codec and must remain exact",
            )),
        },
        SlotShape::Multi { token_dim } => match policy {
            QuantPolicy::None => Ok(()),
            QuantPolicy::ColbertResidual2Bit if token_dim > 0 && token_dim % 4 == 0 => Ok(()),
            QuantPolicy::ColbertResidual2Bit => Err(shape_policy_error(
                name,
                shape,
                policy,
                "two-bit residual packing requires a positive token dimension divisible by four",
            )),
            other => Err(shape_policy_error(
                name,
                shape,
                other,
                "multi-vector storage supports only exact rows or the separately versioned two-bit ColBERT residual codec",
            )),
        },
    }
}

fn shape_policy_error(
    name: &str,
    shape: SlotShape,
    policy: QuantPolicy,
    reason: &str,
) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_QUANT_POLICY_SHAPE_MISMATCH",
        message: format!("lens {name} declares {policy:?} for shape {shape:?}: {reason}"),
        remediation: "use a dense codec only with SlotShape::Dense, QuantPolicy::None with \
                      SlotShape::Sparse, and QuantPolicy::ColbertResidual2Bit (or explicit None) \
                      with a compatible SlotShape::Multi",
    }
}
