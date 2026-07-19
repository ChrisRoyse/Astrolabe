//! Truthful ColBERTv2 residual storage and direct packed MaxSim (issue #575).
//!
//! Multi-vector storage is deliberately separate from dense compression. Its
//! physical representation is centroid codes plus two-bit residuals, its
//! admission contract is measured against exact raw-F32 MaxSim, and its durable
//! generations use the same Aster manifest/lifecycle/Ledger state machine as
//! every other compressed slot without flattening a token matrix.

mod admission;
mod codec;
mod format;
mod generation;
mod generation_record;
mod index;
mod row_format;
mod simd;
mod training;
mod types;
mod wire;

use calyx_core::{CalyxError, QuantPolicy, Result, Slot, SlotShape};

use crate::spec::LensSpec;

pub use codec::packed_maxsim;
pub use format::{
    MULTIVECTOR_MANIFEST_MAGIC, MULTIVECTOR_MANIFEST_VERSION, PackedMultiVectorManifest,
    parse_packed_multivector_manifest,
};
pub use generation::{
    append_reseal_packed_multivector_rows, compress_streamed_multivector_column,
    erase_packed_multivector_rows, write_packed_multivector_generation,
};
pub use index::PackedMultiVectorIndex;
pub use row_format::{
    MULTIVECTOR_ROW_HEADER_BYTES, MULTIVECTOR_ROW_MAGIC, MULTIVECTOR_ROW_VERSION,
    ParsedPackedMultiVectorRow, parse_packed_multivector_row,
};
pub use simd::packed_maxsim_backend;
pub use types::{
    MultiVectorCompressionConfig, MultiVectorCompressionQuery, MultiVectorCompressionReport,
    MultiVectorCompressionRow, MultiVectorStorageCodec, PackedMaxSimScratch,
    PackedMultiVectorBytes, PackedMultiVectorHit, PackedMultiVectorRow,
};

/// Structured error code: a shape/policy has no packed multi-vector codec.
pub const CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED: &str = "CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED";
/// Structured error code: packed bytes or declared bounds are malformed.
pub const CALYX_MULTIVECTOR_PACK_INVALID: &str = "CALYX_MULTIVECTOR_PACK_INVALID";
/// Structured error code: persisted bytes do not match the frozen context.
pub const CALYX_MULTIVECTOR_CONTEXT_MISMATCH: &str = "CALYX_MULTIVECTOR_CONTEXT_MISMATCH";
/// Structured error code: exact-vs-packed admission failed.
pub const CALYX_MULTIVECTOR_ADMISSION_FAILED: &str = "CALYX_MULTIVECTOR_ADMISSION_FAILED";

const MULTIVECTOR_REMEDIATION: &str = "commission a compatible Multi slot with QuantPolicy::ColbertResidual2Bit, persist it through \
     the packed multi-vector generation API, and inspect the exact context/bound/checksum field; \
     dense codecs and raw-F32 scoring substitutes are never selected";

pub(super) fn multivector_error(code: &'static str, message: impl Into<String>) -> CalyxError {
    CalyxError {
        code,
        message: message.into(),
        remediation: MULTIVECTOR_REMEDIATION,
    }
}

/// Resolves the exact physical codec advertised by a shape/policy pair.
///
/// This is a pre-mutation authority: unsupported combinations fail before a
/// catalog or vault write. `QuantPolicy::None` remains a lawful exact Multi
/// policy, but it does not resolve to a packed codec.
pub fn resolve_multivector_storage(
    shape: SlotShape,
    policy: QuantPolicy,
) -> Result<MultiVectorStorageCodec> {
    match (shape, policy) {
        (SlotShape::Multi { token_dim }, QuantPolicy::ColbertResidual2Bit)
            if token_dim > 0 && token_dim % 4 == 0 =>
        {
            Ok(MultiVectorStorageCodec::ColbertResidual2BitV1)
        }
        (SlotShape::Multi { token_dim }, QuantPolicy::ColbertResidual2Bit) => {
            Err(multivector_error(
                CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
                format!(
                    "two-bit ColBERT residual storage requires a positive token_dim divisible by four, got {token_dim}"
                ),
            ))
        }
        (SlotShape::Multi { token_dim }, other) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "multi-vector slot (token_dim {token_dim}) declares {other:?}; packed storage requires the explicit QuantPolicy::ColbertResidual2Bit identity"
            ),
        )),
        (SlotShape::Dense(dim), other) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!("dense shape (dim {dim}, policy {other:?}) is not a multi-vector token matrix"),
        )),
        (SlotShape::Sparse(dim), other) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "sparse shape (ambient dim {dim}, policy {other:?}) has no packed multi-vector codec"
            ),
        )),
    }
}

/// Dense compression entry-point guard.
///
/// Non-dense slots and a Multi-only policy on a dense shape are refused before
/// source validation or mutation. This keeps the catalog, persisted format, and
/// executor from silently disagreeing.
pub fn reject_dense_codec_for_multivector(shape: SlotShape, requested: QuantPolicy) -> Result<()> {
    match (shape, requested) {
        (SlotShape::Dense(_), QuantPolicy::ColbertResidual2Bit) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            "a dense slot cannot execute the Multi-only ColbertResidual2Bit policy",
        )),
        (SlotShape::Dense(_), _) => Ok(()),
        (SlotShape::Multi { token_dim }, policy) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "multi-vector slot (token_dim {token_dim}, policy {policy:?}) cannot execute a dense codec; use the packed multi-vector generation API"
            ),
        )),
        (SlotShape::Sparse(dim), policy) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "sparse slot (ambient dim {dim}, policy {policy:?}) cannot execute a dense codec"
            ),
        )),
    }
}

pub(super) fn validate_multivector_context(slot: &Slot, lens: &LensSpec) -> Result<u32> {
    if slot.lens_id != lens.lens_id() {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "slot {} lens {} does not match registered lens {}",
                slot.slot_key.key(),
                slot.lens_id,
                lens.lens_id()
            ),
        ));
    }
    if slot.shape != lens.output {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "slot {} shape {:?} does not match registered lens shape {:?}",
                slot.slot_key.key(),
                slot.shape,
                lens.output
            ),
        ));
    }
    if slot.quant != lens.quant_default {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "slot {} policy {:?} does not match registered lens policy {:?}",
                slot.slot_key.key(),
                slot.quant,
                lens.quant_default
            ),
        ));
    }
    if lens.truncate_dim.is_some() {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            "multi-vector residual storage does not permit dense truncate_dim semantics",
        ));
    }
    resolve_multivector_storage(slot.shape, slot.quant)?;
    let SlotShape::Multi { token_dim } = slot.shape else {
        unreachable!("storage resolution accepted only Multi")
    };
    Ok(token_dim)
}
