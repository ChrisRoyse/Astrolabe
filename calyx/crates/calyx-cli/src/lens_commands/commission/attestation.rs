use std::path::Path;

use calyx_core::{CalyxError, Lens};
use calyx_registry::{
    CandleLens, FastembedQwen3Lens, LensForgeSourceTensorDtypeProfile, LensRuntime,
    lens_spec_from_manifest_path,
};
use serde::Serialize;
use serde_json::json;

use super::log::ConversionLog;
use crate::error::{CliError, CliResult};
use crate::lens_commands::support::hex_from_bytes;

#[derive(Serialize)]
pub(super) struct LocalExecutionAttestationReport {
    pub(super) executable_lens_id: String,
    pub(super) executable_corpus_hash: String,
    pub(super) loader_target_dtype: String,
    pub(super) observed_primary_activation_dtype: String,
    pub(super) observed_execution_device: String,
    pub(super) evidence_kind: String,
}

pub(super) fn attest_local_execution(
    manifest_path: &Path,
    expected_profile: Option<&LensForgeSourceTensorDtypeProfile>,
    log: &mut ConversionLog,
) -> CliResult<Option<LocalExecutionAttestationReport>> {
    let spec = lens_spec_from_manifest_path(manifest_path)?;
    let (profile, report) = match &spec.runtime {
        LensRuntime::CandleLocal { .. } => {
            let lens = CandleLens::from_lens_spec(&spec)?;
            let report = LocalExecutionAttestationReport {
                executable_lens_id: lens.id().to_string(),
                executable_corpus_hash: hex_from_bytes(&lens.contract().corpus_hash()),
                loader_target_dtype: lens.loader_target_dtype().to_string(),
                observed_primary_activation_dtype: lens
                    .observed_primary_activation_dtype()
                    .to_string(),
                observed_execution_device: lens.observed_execution_device().to_string(),
                evidence_kind: lens.dtype_attestation_evidence().to_string(),
            };
            (lens.source_tensor_dtype_profile().clone(), report)
        }
        LensRuntime::FastembedQwen3 { .. } => {
            let lens = FastembedQwen3Lens::from_lens_spec(&spec)?;
            let report = LocalExecutionAttestationReport {
                executable_lens_id: lens.id().to_string(),
                executable_corpus_hash: hex_from_bytes(&lens.contract().corpus_hash()),
                loader_target_dtype: lens.loader_target_dtype().to_string(),
                observed_primary_activation_dtype: lens
                    .observed_primary_activation_dtype()
                    .to_string(),
                observed_execution_device: lens.observed_execution_device().to_string(),
                evidence_kind: lens.dtype_attestation_evidence().to_string(),
            };
            (lens.source_tensor_dtype_profile().clone(), report)
        }
        _ => return Ok(None),
    };
    if Some(&profile) != expected_profile {
        return Err(CliError::from(CalyxError::lens_frozen_violation(
            "local execution source tensor dtype profile differs from the verified commission artifact profile",
        )));
    }
    log.event(json!({
        "event": "local_execution_attested",
        "declared_manifest_lens_id": spec.lens_id().to_string(),
        "executable_lens_id": &report.executable_lens_id,
        "executable_corpus_hash": &report.executable_corpus_hash,
        "source_tensor_dtype_profile": &profile,
        "loader_target_dtype": &report.loader_target_dtype,
        "observed_primary_activation_dtype": &report.observed_primary_activation_dtype,
        "observed_execution_device": &report.observed_execution_device,
        "dtype_attestation_evidence": &report.evidence_kind,
        "gemm_accumulation_dtype": "f32",
        "output_dtype": "f32",
    }))?;
    Ok(Some(report))
}
