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
/// time. `QuantPolicy::Pq` has no implemented persisted contract and is refused
/// for every shape at configuration time.
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
        SlotShape::Dense(_) => Ok(()),
        SlotShape::Sparse(_) | SlotShape::Multi { .. } => match policy {
            QuantPolicy::None => Ok(()),
            other => Err(CalyxError {
                code: "CALYX_LENS_QUANT_POLICY_SHAPE_MISMATCH",
                message: format!(
                    "lens {name} declares dense-only quantization policy {other:?} for \
                     non-dense shape {shape:?}; sparse/multi slots persist exact canonical \
                     rows (QuantPolicy::None)"
                ),
                remediation: "declare QuantPolicy::None for sparse/multi shapes; dense-only \
                              codecs must be refused before catalog mutation, not at \
                              compression time",
            }),
        },
    }
}
