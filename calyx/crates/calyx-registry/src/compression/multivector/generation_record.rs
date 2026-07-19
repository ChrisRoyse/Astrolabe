use calyx_aster::compression_lifecycle::{
    COMPRESSION_GENERATION_MARKER, GenerationLifecycleRecord, GenerationTransition,
};
use calyx_core::{CxId, Result, Seq, Slot};
use serde_json::json;

use super::{
    CALYX_MULTIVECTOR_PACK_INVALID, MultiVectorCompressionReport, PackedMultiVectorManifest,
    multivector_error,
};

pub(super) fn lifecycle_record(
    transition: GenerationTransition,
    slot: &Slot,
    prior_seq: Seq,
    manifest: &PackedMultiVectorManifest,
    affected: &[CxId],
) -> Result<GenerationLifecycleRecord> {
    GenerationLifecycleRecord::new(
        transition,
        slot.slot_id.get(),
        prior_seq,
        manifest.generation_rows,
        hex(&manifest.generation_root),
        hex(&manifest.raw_generation_root),
        affected.iter().map(|cx_id| hex(cx_id.as_bytes())).collect(),
    )
}

pub(super) fn ledger_payload(
    transition: GenerationTransition,
    manifest: &PackedMultiVectorManifest,
    affected: &[CxId],
) -> Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "marker": COMPRESSION_GENERATION_MARKER,
        "transition": transition.as_str(),
        "slot_id": manifest.slot_id,
        "codec": manifest.codec.catalog_label(),
        "rows": manifest.generation_rows,
        "total_tokens": manifest.total_tokens,
        "token_dim": manifest.token_dim,
        "max_tokens": manifest.config.max_tokens,
        "max_token_dim": manifest.config.max_token_dim,
        "centroid_count": manifest.config.centroid_count,
        "residual_bits": 2,
        "codec_context_id_sha256": hex(&manifest.codec_context_id),
        "generation_root_sha256": hex(&manifest.generation_root),
        "raw_generation_root_sha256": hex(&manifest.raw_generation_root),
        "exact_ranking_root_sha256": hex(&manifest.exact_ranking_root),
        "packed_ranking_root_sha256": hex(&manifest.packed_ranking_root),
        "max_abs_score_error": manifest.max_abs_score_error,
        "recall_at_k": manifest.recall_at_k,
        "affected_cx_ids": affected.iter().map(|cx_id| hex(cx_id.as_bytes())).collect::<Vec<_>>(),
    }))
    .map_err(|error| {
        invalid(format!(
            "Multi generation Ledger payload encoding failed: {error}"
        ))
    })
}

pub(super) fn finalize_byte_accounting(
    report: &mut MultiVectorCompressionReport,
    lifecycle_bytes: usize,
    ledger_bytes: usize,
) -> Result<()> {
    let rows = report.generation_rows as usize;
    report.bytes.lifecycle_value_bytes = lifecycle_bytes;
    report.bytes.ledger_value_bytes = ledger_bytes;
    report.bytes.key_bytes = rows
        .checked_mul(32)
        .and_then(|value| value.checked_add(2 + 11 + 8))
        .ok_or_else(|| invalid("Multi generation key-byte accounting overflow"))?;
    report.bytes.accounted_bytes = report
        .bytes
        .raw_sidecar_value_bytes
        .checked_add(report.bytes.packed_row_value_bytes)
        .and_then(|value| value.checked_add(report.bytes.manifest_value_bytes))
        .and_then(|value| value.checked_add(lifecycle_bytes))
        .and_then(|value| value.checked_add(ledger_bytes))
        .and_then(|value| value.checked_add(report.bytes.key_bytes))
        .ok_or_else(|| invalid("Multi generation total byte accounting overflow"))?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    multivector_error(CALYX_MULTIVECTOR_PACK_INVALID, message)
}
