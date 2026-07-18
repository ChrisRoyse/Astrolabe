use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Input, Modality, RuntimeExecutionAttestation};
use calyx_forge::PinnedCudaDeviceIdentity;
use calyx_registry::{
    CandleDevicePolicy, FrozenLensContract, LensForgeBatchPolicy, LensForgeManifest,
    LensForgeSourceTensorDtypeProfile, LensRuntime, LensSpec, OnnxInt8Attestation,
    lens_spec_from_manifest, parse_frozen_device_policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::support::{
    PreparedRuntimeLens, prepare_manifest_runtime, validate_vector_contract,
};
use crate::error::{CliError, CliResult};

const COMMISSION_PROBE: &str =
    "Calyx persisted-artifact mandatory full-forward commission attestation";
const RERANKER_COMMISSION_PROBE: &str =
    "Calyx persisted-artifact query\nCalyx persisted-artifact document";

/// Opaque proof that the exact final manifest is eligible for catalog storage.
///
/// The fields deliberately remain private. Catalog mutation accepts this type,
/// never a `LensSpec` or `PreparedRuntimeLens`, so callers cannot turn static
/// parsing or runtime construction into an admission claim.
pub(crate) struct AttestedCatalogAdmission {
    spec: LensSpec,
    manifest: PathBuf,
    manifest_sha256: String,
    execution_attestation: Option<LocalExecutionAttestationReport>,
    onnx_int8_attestation: Option<OnnxInt8Attestation>,
}

/// Commission-time receipt retaining the already loaded and executed runtime
/// across batch probing and the final manifest rewrite.
pub(crate) struct CatalogAdmissionDraft {
    initial_spec: LensSpec,
    initial_manifest: LensForgeManifest,
    initial_manifest_sha256: String,
    expected_profile: Option<LensForgeSourceTensorDtypeProfile>,
    expected_source_contract: Option<FrozenLensContract>,
    prepared: PreparedRuntimeLens,
    execution_report: Option<LocalExecutionAttestationReport>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct LocalExecutionAttestationReport {
    pub(crate) executable_lens_id: String,
    pub(crate) executable_corpus_hash: String,
    pub(crate) runtime: String,
    pub(crate) provider: String,
    pub(crate) loader_target_dtype: Option<String>,
    pub(crate) observed_primary_activation_dtype: Option<String>,
    pub(crate) observed_execution_device: String,
    pub(crate) evidence_kind: String,
    pub(crate) total_compute_nodes: Option<u64>,
    pub(crate) cpu_compute_nodes: Option<u64>,
}

impl LocalExecutionAttestationReport {
    pub(crate) fn same_execution_identity(&self, other: &Self) -> bool {
        self.executable_lens_id == other.executable_lens_id
            && self.executable_corpus_hash == other.executable_corpus_hash
            && self.runtime == other.runtime
            && self.provider == other.provider
            && self.loader_target_dtype == other.loader_target_dtype
            && self.observed_primary_activation_dtype == other.observed_primary_activation_dtype
            && self.observed_execution_device == other.observed_execution_device
            && self.evidence_kind == other.evidence_kind
            && self.total_compute_nodes == other.total_compute_nodes
            && self.cpu_compute_nodes == other.cpu_compute_nodes
    }
}

struct ManifestBinding {
    spec: LensSpec,
    manifest: LensForgeManifest,
    sha256: String,
}

impl AttestedCatalogAdmission {
    pub(super) fn into_parts(
        self,
    ) -> (
        LensSpec,
        PathBuf,
        String,
        Option<LocalExecutionAttestationReport>,
        Option<OnnxInt8Attestation>,
    ) {
        (
            self.spec,
            self.manifest,
            self.manifest_sha256,
            self.execution_attestation,
            self.onnx_int8_attestation,
        )
    }
}

impl CatalogAdmissionDraft {
    pub(crate) fn prepared(&self) -> &PreparedRuntimeLens {
        &self.prepared
    }

    pub(crate) fn execution_report(&self) -> Option<&LocalExecutionAttestationReport> {
        self.execution_report.as_ref()
    }

    /// Consume the runtime proof only after reparsing the exact final manifest
    /// bytes written by commission. No inference is repeated here.
    pub(crate) fn seal_final(
        self,
        manifest_path: &Path,
        expected_max_batch: Option<usize>,
        expected_batch_policy: &LensForgeBatchPolicy,
    ) -> CliResult<(
        AttestedCatalogAdmission,
        Option<LocalExecutionAttestationReport>,
    )> {
        let final_binding = read_manifest_binding(manifest_path)?;
        validate_source_profile(
            manifest_path,
            &final_binding.manifest,
            self.expected_profile.as_ref(),
        )?;

        let mut expected_manifest = self.initial_manifest.clone();
        expected_manifest.max_batch = expected_max_batch;
        expected_manifest.batch_policy = Some(expected_batch_policy.clone());
        if final_binding.manifest != expected_manifest {
            return Err(admission_error(
                "CALYX_LENS_CATALOG_FINAL_MANIFEST_DRIFT",
                format!(
                    "final manifest {} changed fields outside the exact commission-owned max_batch/batch_policy update (initial_sha256={} final_sha256={})",
                    manifest_path.display(),
                    self.initial_manifest_sha256,
                    final_binding.sha256
                ),
                "preserve the conversion log and artifacts, remove the unregistered manifest, and recommission without modifying frozen fields",
            ));
        }
        let mut expected_final = self.initial_spec.clone();
        expected_final.max_batch = expected_max_batch;
        if expected_final != final_binding.spec {
            return Err(admission_error(
                "CALYX_LENS_CATALOG_FINAL_MANIFEST_DRIFT",
                format!(
                    "final manifest {} changed fields other than the commission-owned max_batch/batch_policy metadata",
                    manifest_path.display()
                ),
                "preserve the conversion log and artifacts, remove the unregistered manifest, and recommission without modifying frozen fields",
            ));
        }
        validate_prepared_contract(&self.prepared, &final_binding.spec)?;
        if let Some(source_contract) = self.expected_source_contract.as_ref()
            && source_contract != &final_binding.spec.declared_contract()
        {
            return Err(admission_error(
                "CALYX_LENS_CATALOG_SOURCE_CONTRACT_DRIFT",
                format!(
                    "source-session lens {} does not match final manifest lens {}",
                    source_contract.lens_id(),
                    final_binding.spec.lens_id()
                ),
                "preserve source, executable, and final-manifest identities and recommission without rewriting frozen fields",
            ));
        }
        if requires_mandatory_local_attestation(&final_binding.spec.runtime)
            && self.execution_report.is_none()
        {
            return Err(missing_attestation(
                &final_binding.spec.runtime,
                &final_binding.spec.name,
            ));
        }
        if let Some(report) = self.execution_report.as_ref()
            && report.executable_lens_id != final_binding.spec.lens_id().to_string()
        {
            return Err(admission_error(
                "CALYX_LENS_CATALOG_EXECUTION_IDENTITY_DRIFT",
                format!(
                    "executed lens {} does not match final manifest lens {}",
                    report.executable_lens_id,
                    final_binding.spec.lens_id()
                ),
                "preserve both identities and recommission; never rewrite a frozen manifest after execution",
            ));
        }

        let report = self.execution_report;
        Ok((
            AttestedCatalogAdmission {
                spec: final_binding.spec,
                manifest: manifest_path.to_path_buf(),
                manifest_sha256: final_binding.sha256,
                execution_attestation: report.clone(),
                onnx_int8_attestation: final_binding.manifest.onnx_int8_attestation,
            },
            report,
        ))
    }
}

/// Start commission admission from the same prepared runtime that batch
/// preflight will use. FastEmbed commissions require the immutable source
/// session contract as a second, independent identity witness.
pub(crate) fn begin_commission_admission(
    manifest_path: &Path,
    prepared: PreparedRuntimeLens,
    expected_profile: Option<&LensForgeSourceTensorDtypeProfile>,
    expected_contract: Option<&FrozenLensContract>,
) -> CliResult<CatalogAdmissionDraft> {
    let binding = read_manifest_binding(manifest_path)?;
    begin_prepared_admission(
        manifest_path,
        binding,
        prepared,
        expected_profile,
        expected_contract,
        true,
    )
}

/// Verify a final manifest before any catalog lookup, idempotent return, or
/// write. Mandatory local runtimes are loaded from their persisted artifacts
/// and complete a real full forward here.
pub(crate) fn attest_manifest(manifest_path: PathBuf) -> CliResult<AttestedCatalogAdmission> {
    let initial = read_manifest_binding(&manifest_path)?;
    if !requires_mandatory_local_attestation(&initial.spec.runtime) {
        let final_binding = read_manifest_binding(&manifest_path)?;
        require_unchanged_binding(&manifest_path, &initial, &final_binding)?;
        return Ok(AttestedCatalogAdmission {
            spec: final_binding.spec,
            manifest: manifest_path,
            manifest_sha256: final_binding.sha256,
            execution_attestation: None,
            onnx_int8_attestation: final_binding.manifest.onnx_int8_attestation,
        });
    }

    let prepared = prepare_manifest_runtime(initial.spec.clone())?;
    if prepared.spec != initial.spec {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_PREPARED_SPEC_DRIFT",
            format!(
                "direct admission prepared runtime {} does not exactly match manifest {}",
                prepared.spec.name,
                manifest_path.display()
            ),
            "discard the prepared runtime and rerun admission from unchanged final manifest bytes",
        ));
    }
    validate_prepared_contract(&prepared, &initial.spec)?;
    validate_source_profile(
        &manifest_path,
        &initial.manifest,
        initial.manifest.source_tensor_dtype_profile.as_ref(),
    )?;
    let execution_report = execute_and_attest(&prepared)?;
    let final_binding = read_manifest_binding(&manifest_path)?;
    require_unchanged_binding(&manifest_path, &initial, &final_binding)?;
    validate_prepared_contract(&prepared, &final_binding.spec)?;
    if execution_report.executable_lens_id != final_binding.spec.lens_id().to_string() {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_IDENTITY_DRIFT",
            format!(
                "executed lens {} does not match final manifest lens {}",
                execution_report.executable_lens_id,
                final_binding.spec.lens_id()
            ),
            "preserve both identities and rerun admission; never rewrite a frozen manifest during execution",
        ));
    }
    Ok(AttestedCatalogAdmission {
        spec: final_binding.spec,
        manifest: manifest_path,
        manifest_sha256: final_binding.sha256,
        execution_attestation: Some(execution_report),
        onnx_int8_attestation: final_binding.manifest.onnx_int8_attestation,
    })
}

pub(crate) fn reparse_manifest_binding_with_onnx_int8_attestation(
    path: &Path,
) -> CliResult<(LensSpec, String, Option<OnnxInt8Attestation>)> {
    let binding = read_manifest_binding(path)?;
    Ok((
        binding.spec,
        binding.sha256,
        binding.manifest.onnx_int8_attestation,
    ))
}

pub(crate) fn reparse_manifest_binding(path: &Path) -> CliResult<(LensSpec, String)> {
    let binding = read_manifest_binding(path)?;
    Ok((binding.spec, binding.sha256))
}

fn begin_prepared_admission(
    manifest_path: &Path,
    binding: ManifestBinding,
    prepared: PreparedRuntimeLens,
    expected_profile: Option<&LensForgeSourceTensorDtypeProfile>,
    expected_contract: Option<&FrozenLensContract>,
    require_fastembed_source_contract: bool,
) -> CliResult<CatalogAdmissionDraft> {
    validate_source_profile(manifest_path, &binding.manifest, expected_profile)?;

    let mut expected_prepared = binding.spec.clone();
    expected_prepared.max_batch = prepared.spec.max_batch;
    if expected_prepared != prepared.spec {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_PREPARED_SPEC_DRIFT",
            format!(
                "prepared runtime {} does not match manifest {} outside the temporary batch ceiling",
                prepared.spec.name,
                manifest_path.display()
            ),
            "discard the prepared runtime and recommission from the unchanged persisted manifest",
        ));
    }
    validate_prepared_contract(&prepared, &binding.spec)?;

    if is_in_process_fastembed(&prepared.spec.runtime) {
        let expected = match expected_contract {
            Some(expected) => Some(expected),
            None if require_fastembed_source_contract => {
                return Err(admission_error(
                    "CALYX_FASTEMBED_COMMISSION_SOURCE_CONTRACT_MISSING",
                    format!(
                        "commission of {} lost the immutable source-session contract before persisted-artifact verification",
                        prepared.spec.name
                    ),
                    "recommission through the in-process FastEmbed path that carries its frozen source contract into persisted-artifact attestation",
                ));
            }
            None => None,
        };
        if let Some(expected) = expected
            && expected != &prepared.contract
        {
            return Err(CliError::from(CalyxError::lens_frozen_violation(format!(
                "exported FastEmbed artifacts declare lens {}, but the immutable source session committed lens {}",
                prepared.contract.lens_id(),
                expected.lens_id()
            ))));
        }
    }

    let execution_report = if requires_mandatory_local_attestation(&prepared.spec.runtime) {
        Some(execute_and_attest(&prepared)?)
    } else {
        None
    };
    Ok(CatalogAdmissionDraft {
        initial_spec: binding.spec,
        initial_manifest: binding.manifest,
        initial_manifest_sha256: binding.sha256,
        expected_profile: expected_profile.cloned(),
        expected_source_contract: expected_contract.cloned(),
        prepared,
        execution_report,
    })
}

fn require_unchanged_binding(
    manifest_path: &Path,
    initial: &ManifestBinding,
    current: &ManifestBinding,
) -> CliResult<()> {
    if initial.sha256 == current.sha256
        && initial.manifest == current.manifest
        && initial.spec == current.spec
    {
        return Ok(());
    }
    Err(admission_error(
        "CALYX_LENS_CATALOG_ADMISSION_STALE",
        format!(
            "manifest {} changed during runtime admission (initial_sha256={} current_sha256={})",
            manifest_path.display(),
            initial.sha256,
            current.sha256
        ),
        "preserve both manifest snapshots, discard the stale admission, and rerun against immutable final bytes",
    ))
}

fn execute_and_attest(
    prepared: &PreparedRuntimeLens,
) -> CliResult<LocalExecutionAttestationReport> {
    if !matches!(prepared.spec.modality, Modality::Text | Modality::Code) {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_ADMISSION_PROBE_UNSUPPORTED",
            format!(
                "mandatory local lens {} declares {:?}, but no real full-forward admission probe exists for that modality",
                prepared.spec.name, prepared.spec.modality
            ),
            "add a modality-native persisted-artifact probe before admitting this runtime",
        ));
    }
    let probe = Input::new(
        prepared.spec.modality,
        match &prepared.spec.runtime {
            LensRuntime::FastembedRerankerPlaced { .. } => RERANKER_COMMISSION_PROBE,
            _ => COMMISSION_PROBE,
        }
        .as_bytes()
        .to_vec(),
    );
    let vector = prepared.lens.measure(&probe)?;
    validate_vector_contract(
        &vector,
        prepared.contract.shape(),
        prepared.contract.norm_policy(),
    )?;
    let attestation = prepared
        .lens
        .execution_attestation()?
        .ok_or_else(|| missing_attestation(&prepared.spec.runtime, &prepared.spec.name))?;
    validate_attestation(&prepared.spec.runtime, &attestation)?;

    Ok(LocalExecutionAttestationReport {
        executable_lens_id: prepared.lens.id().to_string(),
        executable_corpus_hash: hex(&prepared.contract.corpus_hash()),
        runtime: attestation.runtime,
        provider: attestation.provider,
        loader_target_dtype: attestation.loader_dtype,
        observed_primary_activation_dtype: attestation.compute_dtype,
        observed_execution_device: attestation.device,
        // Persist the stable observation mechanism, not run-local profile
        // paths/hashes embedded after the first separator. Provider, physical
        // device, node counts, manifest digest, and lens/corpus identity carry
        // the authoritative execution binding.
        evidence_kind: attestation
            .evidence
            .split(';')
            .next()
            .unwrap_or_default()
            .to_string(),
        total_compute_nodes: attestation.total_compute_nodes,
        cpu_compute_nodes: attestation.cpu_compute_nodes,
    })
}

fn validate_prepared_contract(prepared: &PreparedRuntimeLens, spec: &LensSpec) -> CliResult<()> {
    let declared = spec.declared_contract();
    if prepared.contract != declared || prepared.lens.id() != declared.lens_id() {
        return Err(CliError::from(CalyxError::lens_frozen_violation(format!(
            "persisted runtime contract {} and executable lens {} do not match declared manifest contract {}",
            prepared.contract.lens_id(),
            prepared.lens.id(),
            declared.lens_id()
        ))));
    }
    Ok(())
}

fn validate_source_profile(
    manifest_path: &Path,
    manifest: &LensForgeManifest,
    expected: Option<&LensForgeSourceTensorDtypeProfile>,
) -> CliResult<()> {
    if manifest.source_tensor_dtype_profile.as_ref() != expected {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_SOURCE_PROFILE_DRIFT",
            format!(
                "manifest {} source tensor dtype profile differs from the verified commission artifact profile",
                manifest_path.display()
            ),
            "preserve the conversion log and recommission from the verified source artifacts",
        ));
    }
    Ok(())
}

fn validate_attestation(
    runtime: &LensRuntime,
    attestation: &RuntimeExecutionAttestation,
) -> CliResult<()> {
    for (field, value) in [
        ("runtime", attestation.runtime.as_str()),
        ("provider", attestation.provider.as_str()),
        ("device", attestation.device.as_str()),
        ("evidence", attestation.evidence.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(admission_error(
                "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                format!("persisted local execution attestation has an empty {field}"),
                "fix the runtime to emit complete observed execution evidence after a real full forward",
            ));
        }
    }

    let expected_runtime = match runtime {
        LensRuntime::CandleLocal { .. } => "candle-local",
        LensRuntime::FastembedQwen3 { .. } => "fastembed-qwen3",
        LensRuntime::Onnx { .. } => "onnx-custom",
        LensRuntime::OnnxColbert { .. } => "onnx-colbert",
        LensRuntime::FastembedDensePlaced { .. }
        | LensRuntime::FastembedSparsePlaced { .. }
        | LensRuntime::FastembedBgem3Placed { .. }
        | LensRuntime::FastembedRerankerPlaced { .. } => "onnx-fastembed-5.16.0-owned",
        _ => {
            return Err(admission_error(
                "CALYX_LENS_CATALOG_EXECUTION_RUNTIME_UNSUPPORTED",
                format!(
                    "runtime {runtime:?} entered mandatory local execution attestation without an exact executable-runtime identity contract"
                ),
                "define and observe the exact executable runtime identity before making this runtime mandatory for catalog admission",
            ));
        }
    };
    if attestation.runtime != expected_runtime {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_RUNTIME_MISMATCH",
            format!(
                "manifest runtime {runtime:?} requires executable runtime {expected_runtime}, observed {}",
                attestation.runtime
            ),
            "preserve the manifest and execution evidence, repair runtime construction, and rerun the real full forward; never register evidence from another executable runtime",
        ));
    }

    match runtime {
        LensRuntime::FastembedDensePlaced { execution, .. }
        | LensRuntime::FastembedSparsePlaced { execution, .. }
        | LensRuntime::FastembedBgem3Placed { execution, .. }
        | LensRuntime::FastembedRerankerPlaced { execution, .. } => {
            validate_onnx_fastembed_placement(execution, attestation)
        }
        LensRuntime::CandleLocal { device, dtype, .. }
        | LensRuntime::FastembedQwen3 { device, dtype, .. } => {
            validate_candle_placement(device, dtype, attestation)
        }
        LensRuntime::Onnx { .. } | LensRuntime::OnnxColbert { .. } => {
            validate_generic_onnx_cuda(attestation)
        }
        _ => Ok(()),
    }
}

fn validate_onnx_fastembed_placement(
    execution: &str,
    attestation: &RuntimeExecutionAttestation,
) -> CliResult<()> {
    let total = attestation.total_compute_nodes.ok_or_else(|| {
        admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
            "persisted FastEmbed execution attestation omitted total compute-node placement",
            "enable the committed-session and first-inference provider trace before catalog admission",
        )
    })?;
    let cpu = attestation.cpu_compute_nodes.ok_or_else(|| {
        admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
            "persisted FastEmbed execution attestation omitted CPU compute-node placement",
            "enable the committed-session and first-inference provider trace before catalog admission",
        )
    })?;
    if total == 0 || cpu > total {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
            format!("invalid FastEmbed provider placement total={total} cpu={cpu}"),
            "repair the runtime provider trace; do not register an unplaced graph",
        ));
    }

    let provider = attestation.provider.to_ascii_uppercase();
    match execution {
        "cuda_fail_loud" => {
            if cpu != 0 || !provider.contains("CUDA") || provider.contains("CPU") {
                return Err(placement_mismatch(format!(
                    "CUDA FastEmbed full-forward provider={} placed cpu_nodes={cpu}/{total}",
                    attestation.provider
                )));
            }
            attestation
                .device
                .parse::<PinnedCudaDeviceIdentity>()
                .map_err(|error| {
                    placement_mismatch(format!(
                        "CUDA FastEmbed attestation device {:?} is not a stable PCI+UUID identity: {error}",
                        attestation.device
                    ))
                })?;
        }
        "cpu_explicit" => {
            if cpu != total
                || !provider.contains("CPU")
                || provider.contains("CUDA")
                || attestation.device != "cpu"
            {
                return Err(placement_mismatch(format!(
                    "explicit-CPU FastEmbed full-forward provider={} device={} placed cpu_nodes={cpu}/{total}",
                    attestation.provider, attestation.device
                )));
            }
        }
        other => {
            return Err(admission_error(
                "CALYX_FASTEMBED_EXECUTION_IDENTITY_NONCANONICAL",
                format!("persisted FastEmbed execution policy {other:?} is noncanonical"),
                "recommission with cuda_fail_loud or cpu_explicit; never rewrite the frozen identity",
            ));
        }
    }
    Ok(())
}

fn validate_candle_placement(
    device: &str,
    dtype: &str,
    attestation: &RuntimeExecutionAttestation,
) -> CliResult<()> {
    let policy = parse_frozen_device_policy(device)?;
    let expected_device = policy.frozen_token();
    let expected_provider = if policy.is_gpu() {
        "candle_cuda"
    } else {
        "candle_cpu"
    };
    if attestation.device != expected_device || attestation.provider != expected_provider {
        return Err(placement_mismatch(format!(
            "Candle-family manifest requires provider={expected_provider} device={expected_device}, observed provider={} device={}",
            attestation.provider, attestation.device
        )));
    }
    if matches!(
        policy,
        CandleDevicePolicy::CudaFrozen { .. } | CandleDevicePolicy::CudaFailLoud { .. }
    ) {
        attestation
            .device
            .parse::<PinnedCudaDeviceIdentity>()
            .map_err(|error| {
                placement_mismatch(format!(
                    "Candle CUDA device {:?} is not a stable PCI+UUID identity: {error}",
                    attestation.device
                ))
            })?;
    }
    if attestation.loader_dtype.as_deref() != Some(dtype)
        || attestation.compute_dtype.as_deref() != Some(dtype)
    {
        return Err(admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_DTYPE_MISMATCH",
            format!(
                "Candle-family manifest requires dtype={dtype}, observed loader={:?} activation={:?}",
                attestation.loader_dtype, attestation.compute_dtype
            ),
            "recommission with artifacts and a runtime whose loader and primary activation match the frozen dtype",
        ));
    }
    Ok(())
}

fn validate_generic_onnx_cuda(attestation: &RuntimeExecutionAttestation) -> CliResult<()> {
    let total = attestation.total_compute_nodes.ok_or_else(|| {
        admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
            "local ONNX execution attestation omitted total compute-node placement",
            "enable first-real-inference provider placement tracing before catalog admission",
        )
    })?;
    let cpu = attestation.cpu_compute_nodes.ok_or_else(|| {
        admission_error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
            "local ONNX execution attestation omitted CPU compute-node placement",
            "enable first-real-inference provider placement tracing before catalog admission",
        )
    })?;
    let provider = attestation.provider.to_ascii_uppercase();
    if total == 0 || cpu != 0 || !provider.contains("CUDA") || provider.contains("CPU") {
        return Err(placement_mismatch(format!(
            "local ONNX full-forward provider={} placed cpu_nodes={cpu}/{total}",
            attestation.provider
        )));
    }
    attestation
        .device
        .parse::<PinnedCudaDeviceIdentity>()
        .map_err(|error| {
            placement_mismatch(format!(
                "local ONNX attestation device {:?} is not a stable PCI+UUID identity: {error}",
                attestation.device
            ))
        })?;
    Ok(())
}

pub(crate) fn requires_mandatory_local_attestation(runtime: &LensRuntime) -> bool {
    matches!(
        runtime,
        LensRuntime::CandleLocal { .. }
            | LensRuntime::Onnx { .. }
            | LensRuntime::OnnxColbert { .. }
            | LensRuntime::FastembedQwen3 { .. }
            | LensRuntime::FastembedDensePlaced { .. }
            | LensRuntime::FastembedSparsePlaced { .. }
            | LensRuntime::FastembedBgem3Placed { .. }
            | LensRuntime::FastembedRerankerPlaced { .. }
    )
}

fn is_in_process_fastembed(runtime: &LensRuntime) -> bool {
    matches!(
        runtime,
        LensRuntime::FastembedQwen3 { .. }
            | LensRuntime::FastembedDensePlaced { .. }
            | LensRuntime::FastembedSparsePlaced { .. }
            | LensRuntime::FastembedBgem3Placed { .. }
            | LensRuntime::FastembedRerankerPlaced { .. }
    )
}

fn read_manifest_binding(path: &Path) -> CliResult<ManifestBinding> {
    let bytes = std::fs::read(path).map_err(|error| {
        admission_error(
            "CALYX_LENS_CATALOG_MANIFEST_READ_FAILED",
            format!("read final manifest {} failed: {error}", path.display()),
            "restore the immutable commissioned manifest at this exact path and retry admission",
        )
    })?;
    let manifest: LensForgeManifest = serde_json::from_slice(&bytes).map_err(|error| {
        admission_error(
            "CALYX_LENS_CATALOG_MANIFEST_PARSE_FAILED",
            format!("parse final manifest {} failed: {error}", path.display()),
            "repair the manifest producer and recommission; do not hand-edit frozen JSON",
        )
    })?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let spec = lens_spec_from_manifest(&manifest, base)?;
    Ok(ManifestBinding {
        spec,
        manifest,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}

fn missing_attestation(runtime: &LensRuntime, name: &str) -> CliError {
    admission_error(
        "CALYX_LENS_CATALOG_EXECUTION_UNATTESTED",
        format!(
            "persisted local runtime {runtime:?} for lens {name} completed without usable runtime execution evidence"
        ),
        "fix the runtime so a real persisted-artifact full forward records provider, physical device, and node placement before catalog registration",
    )
}

fn placement_mismatch(message: impl Into<String>) -> CliError {
    admission_error(
        "CALYX_LENS_CATALOG_EXECUTION_PLACEMENT_MISMATCH",
        message,
        "preserve the execution evidence, repair provider/device selection, and rerun the full forward; never register or retry on another provider",
    )
}

fn admission_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    CliError::from(CalyxError {
        code,
        message: message.into(),
        remediation,
    })
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
