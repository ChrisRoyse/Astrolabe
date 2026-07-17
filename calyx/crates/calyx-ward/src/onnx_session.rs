//! Owned ONNX Runtime session policy and graph-placement attestation for Ward.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_char};
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use calyx_core::{CalyxError, LensId, RuntimeExecutionAttestation};
pub use calyx_onnx_runtime::OnnxCpuAuthorization as WardCpuAuthorization;
use calyx_onnx_runtime::{
    ImmutableDirectoryRoot, ImmutableFileIdentity, ImmutableFileSnapshot,
    OnnxCudaDeviceAttestation, OnnxCudaExecutionStream, OnnxRuntimePolicy,
};
use ort::ep::{self, ArenaExtendStrategy, ExecutionProviderDispatch};
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::{AsPointer, Error as OrtError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::WardError;

const GRAPH_ASSIGNMENT_CONFIG: &str = "session.record_ep_graph_assignment_info";
const CUDA_REMEDIATION: &str = "repair the pinned CUDA 13.3/ORT 1.26 runtime bundle or frozen model operator coverage; select a separately commissioned CPU LensId only when startup proved CALYX_CUDA_NO_DEVICE_ATTESTED, and never retry a failed CUDA session or inference on CPU";
const CPU_REMEDIATION: &str = "repair the pinned ORT runtime, CPU companion authorization, or frozen model/session contract before retrying";
const MAX_PROTO_RECURSION: usize = 64;
const MAX_PROFILE_TRACE_BYTES: u64 = 1024 * 1024 * 1024;
const ARTIFACT_SCHEMA: &str = "calyx-ward-onnx-artifact-contract-v1";
const EXECUTION_SCHEMA: &str = "calyx-ward-onnx-execution-attestation-v1";

/// Authorizes construction of separately commissioned CPU companion lenses
/// only when CUDA is genuinely absent before any Ward session is built.
pub fn authorize_cpu_companion() -> Result<WardCpuAuthorization, WardError> {
    calyx_onnx_runtime::authorize_cpu_companion().map_err(|error| {
        if error.code == "CALYX_ONNX_CPU_COMPANION_UNAUTHORIZED" {
            WardError::CpuCompanionUnauthorized {
                reason: error.to_string(),
            }
        } else {
            WardError::Runtime {
                reason: format!(
                    "shared ONNX startup execution decision failed with {}: {error}",
                    error.code
                ),
            }
        }
    })
}

/// One immutable artifact supplied to a Ward ONNX lens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WardOnnxArtifactEvidence {
    pub role: String,
    pub logical_name: String,
    pub source_path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

/// Frozen model/tokenizer/external-data contract derived from the same bytes
/// that are committed to ORT and `tokenizers`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WardOnnxArtifactContract {
    pub schema: String,
    pub provider_policy: String,
    pub execution_device: String,
    pub contract_sha256: String,
    pub frozen_operators: String,
    pub model: WardOnnxArtifactEvidence,
    pub external_data: Vec<WardOnnxArtifactEvidence>,
    pub tokenizer: Option<WardOnnxArtifactEvidence>,
}

/// Durable caller-facing handoff tying one LensId, its immutable artifacts,
/// and observed provider execution together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WardOnnxExecutionAttestation {
    pub schema: String,
    pub lens_id: LensId,
    pub artifacts: WardOnnxArtifactContract,
    pub runtime: RuntimeExecutionAttestation,
}

#[derive(Clone, Debug)]
enum Placement {
    Cuda(OnnxCudaDeviceAttestation),
    CpuExplicit,
}

impl Placement {
    const fn provider(&self) -> &'static str {
        match self {
            Self::Cuda(_) => crate::CUDA_ONNX_PROVIDER_POLICY,
            Self::CpuExplicit => crate::CPU_ONNX_PROVIDER_POLICY,
        }
    }

    fn device(&self) -> String {
        match self {
            Self::Cuda(device) => device.frozen_execution_device(),
            Self::CpuExplicit => "cpu".to_string(),
        }
    }

    const fn runtime_policy(&self) -> OnnxRuntimePolicy {
        match self {
            Self::Cuda(_) => OnnxRuntimePolicy::CudaFailLoud,
            Self::CpuExplicit => OnnxRuntimePolicy::CpuExplicit,
        }
    }

    fn runtime_ordinal(&self) -> Option<u32> {
        match self {
            Self::Cuda(device) => Some(device.ordinal),
            Self::CpuExplicit => None,
        }
    }

    const fn remediation(&self) -> &'static str {
        match self {
            Self::Cuda(_) => CUDA_REMEDIATION,
            Self::CpuExplicit => CPU_REMEDIATION,
        }
    }
}

pub(crate) struct WardOnnxArtifactBundle {
    contract: WardOnnxArtifactContract,
    model_bytes: Vec<u8>,
    external_data: Vec<(PathBuf, Vec<u8>)>,
    tokenizer_bytes: Option<Vec<u8>>,
    placement: Placement,
}

impl WardOnnxArtifactBundle {
    pub(crate) fn lens_weights_sha256(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        update_length_delimited(&mut hash, self.contract.schema.as_bytes());
        update_length_delimited(&mut hash, self.contract.contract_sha256.as_bytes());
        update_length_delimited(&mut hash, self.contract.provider_policy.as_bytes());
        update_length_delimited(&mut hash, self.contract.execution_device.as_bytes());
        hash.finalize().into()
    }

    pub(crate) fn tokenizer_bytes(&self) -> Result<&[u8], WardError> {
        self.tokenizer_bytes
            .as_deref()
            .ok_or_else(|| WardError::Runtime {
                reason: "Ward text lens artifact bundle has no tokenizer bytes".to_string(),
            })
    }

    pub(crate) fn error(
        &self,
        lens: &'static str,
        stage: &'static str,
        reason: impl ToString,
    ) -> WardError {
        SessionContext::new(lens, self).error(stage, reason)
    }
}

#[derive(Clone, Debug)]
struct SessionContext {
    lens: &'static str,
    model: PathBuf,
    model_sha256: String,
    frozen_operators: String,
    placement: Placement,
    profile_prefix: PathBuf,
    artifacts: WardOnnxArtifactContract,
}

impl SessionContext {
    fn new(lens: &'static str, bundle: &WardOnnxArtifactBundle) -> Self {
        Self {
            lens,
            model: bundle.contract.model.source_path.clone(),
            model_sha256: bundle.contract.model.sha256.clone(),
            frozen_operators: bundle.contract.frozen_operators.clone(),
            placement: bundle.placement.clone(),
            profile_prefix: profiling_file_path(lens),
            artifacts: bundle.contract.clone(),
        }
    }

    fn error(&self, stage: &'static str, reason: impl ToString) -> WardError {
        let reason = reason.to_string();
        eprintln!(
            "CALYX_WARD_ONNX phase=failure lens={} stage={} model={} model_sha256={} artifact_contract_sha256={} provider={} device={} frozen_operators={} external_data={} tokenizer={} reason={} remediation={}",
            self.lens,
            stage,
            self.model.display(),
            self.model_sha256,
            self.artifacts.contract_sha256,
            self.placement.provider(),
            self.placement.device(),
            self.frozen_operators,
            artifact_inventory_summary(&self.artifacts.external_data),
            self.artifacts
                .tokenizer
                .as_ref()
                .map_or_else(|| "none".to_string(), artifact_summary),
            reason,
            self.placement.remediation(),
        );
        WardError::Onnx {
            lens: self.lens,
            stage,
            model: self.model.clone(),
            model_sha256: self.model_sha256.clone(),
            artifact_contract_sha256: self.artifacts.contract_sha256.clone(),
            frozen_operators: self.frozen_operators.clone(),
            provider: self.placement.provider().to_string(),
            device: self.placement.device(),
            reason,
            remediation: self.placement.remediation(),
        }
    }
}

#[derive(Clone, Debug)]
struct ExternalDataReference {
    location: String,
    offset: u64,
    length: Option<u64>,
    checksum: Option<String>,
}

pub(crate) fn snapshot_cuda_artifacts(
    lens: &'static str,
    model_path: &Path,
    tokenizer_path: Option<&Path>,
) -> Result<WardOnnxArtifactBundle, WardError> {
    let requested = calyx_forge::configured_cuda_runtime_ordinal().map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "cuda_device_configuration",
            crate::CUDA_ONNX_PROVIDER_POLICY,
            "cuda:unresolved",
            error,
            CUDA_REMEDIATION,
        )
    })?;
    let selected =
        calyx_onnx_runtime::selected_cuda_device(OnnxRuntimePolicy::CudaFailLoud, Some(requested))
            .map_err(|error| {
                bootstrap_error(
                    lens,
                    model_path,
                    "pinned_runtime_initialization",
                    crate::CUDA_ONNX_PROVIDER_POLICY,
                    "cuda:unresolved",
                    error,
                    CUDA_REMEDIATION,
                )
            })?
            .ok_or_else(|| {
                bootstrap_error(
                    lens,
                    model_path,
                    "cuda_device_attestation",
                    crate::CUDA_ONNX_PROVIDER_POLICY,
                    "cuda:unresolved",
                    "CUDA policy returned no device attestation",
                    CUDA_REMEDIATION,
                )
            })?;
    snapshot_artifacts(lens, model_path, tokenizer_path, Placement::Cuda(selected))
}

pub(crate) fn snapshot_cpu_artifacts(
    lens: &'static str,
    model_path: &Path,
    tokenizer_path: Option<&Path>,
    authorization: &WardCpuAuthorization,
) -> Result<WardOnnxArtifactBundle, WardError> {
    if authorization.decision_code() != calyx_forge::CUDA_NO_DEVICE_ATTESTED_CODE {
        return Err(WardError::CpuCompanionUnauthorized {
            reason: format!(
                "CPU companion authorization does not record {}",
                calyx_forge::CUDA_NO_DEVICE_ATTESTED_CODE
            ),
        });
    }
    calyx_onnx_runtime::ensure_runtime(OnnxRuntimePolicy::CpuExplicit, None).map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "pinned_runtime_initialization",
            crate::CPU_ONNX_PROVIDER_POLICY,
            "cpu",
            format!(
                "authorized after {} at requested CUDA Runtime ordinal {}, but ORT core initialization failed: {error}",
                authorization.decision_code(),
                authorization.requested_runtime_ordinal()
            ),
            CPU_REMEDIATION,
        )
    })?;
    snapshot_artifacts(lens, model_path, tokenizer_path, Placement::CpuExplicit)
}

fn snapshot_artifacts(
    lens: &'static str,
    model_path: &Path,
    tokenizer_path: Option<&Path>,
    placement: Placement,
) -> Result<WardOnnxArtifactBundle, WardError> {
    let provider = placement.provider();
    let device = placement.device();
    let host_available = calyx_onnx_runtime::available_host_memory_bytes().map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "artifact_memory_budget",
            provider,
            &device,
            error,
            placement.remediation(),
        )
    })?;
    let mut remaining_budget = match &placement {
        Placement::Cuda(selected) => host_available.min(selected.total_vram_bytes),
        Placement::CpuExplicit => host_available,
    };
    let mut seen_identities = BTreeMap::<ImmutableFileIdentity, ArtifactIdentityClaim>::new();
    let model_parent = artifact_parent(model_path);
    let model_root =
        calyx_onnx_runtime::open_immutable_directory(model_parent).map_err(|error| {
            bootstrap_error(
                lens,
                model_path,
                "frozen_graph_root_snapshot",
                provider,
                &device,
                error,
                placement.remediation(),
            )
        })?;
    let model_snapshot = snapshot_artifact(
        "model",
        "model.onnx",
        model_path,
        Some(&model_root),
        &mut remaining_budget,
    )
    .map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "frozen_graph_snapshot",
            provider,
            &device,
            error,
            placement.remediation(),
        )
    })?;
    validate_direct_root(&model_snapshot, &model_root, "model").map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "frozen_graph_root_validation",
            provider,
            &device,
            error,
            placement.remediation(),
        )
    })?;
    register_artifact_identity(&mut seen_identities, &model_snapshot).map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "frozen_graph_identity",
            provider,
            &device,
            error,
            placement.remediation(),
        )
    })?;
    let FrozenArtifactSnapshot {
        evidence: model,
        bytes: model_bytes,
        ..
    } = model_snapshot;
    if model_bytes.is_empty() {
        return Err(bootstrap_error(
            lens,
            model_path,
            "frozen_graph_validation",
            provider,
            &device,
            "frozen ONNX graph is empty",
            placement.remediation(),
        ));
    }
    let frozen_operators = frozen_operator_inventory(&model_bytes).map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "frozen_graph_operator_inventory",
            provider,
            &device,
            error,
            placement.remediation(),
        )
    })?;
    let external_references = frozen_external_data_inventory(&model_bytes).map_err(|error| {
        bootstrap_error(
            lens,
            model_path,
            "frozen_graph_external_data_inventory",
            provider,
            &device,
            error,
            placement.remediation(),
        )
    })?;
    let mut external_data = Vec::new();
    let mut external_evidence = Vec::new();
    let mut seen_locations = BTreeMap::<String, (PathBuf, PathBuf, usize)>::new();
    for reference in external_references {
        let logical_path = validated_external_location(&reference.location).map_err(|error| {
            bootstrap_error(
                lens,
                model_path,
                "external_data_location_validation",
                provider,
                &device,
                error,
                placement.remediation(),
            )
        })?;
        let key = logical_path
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let (canonical_path, buffer_index) =
            if let Some((path, first_logical, index)) = seen_locations.get(&key) {
                if first_logical != &logical_path {
                    return Err(bootstrap_error(
                        lens,
                        model_path,
                        "external_data_location_alias",
                        provider,
                        &device,
                        format!(
                            "external_data locations {} and {} alias under Windows path semantics",
                            first_logical.display(),
                            logical_path.display(),
                        ),
                        placement.remediation(),
                    ));
                }
                (path.clone(), *index)
            } else {
                let source = model_root.final_path().join(&logical_path);
                let logical_name = logical_path.to_string_lossy().replace('\\', "/");
                let snapshot = snapshot_artifact(
                    "external_data",
                    &logical_name,
                    &source,
                    Some(&model_root),
                    &mut remaining_budget,
                )
                .map_err(|error| {
                    bootstrap_error(
                        lens,
                        model_path,
                        "external_data_snapshot",
                        provider,
                        &device,
                        error,
                        placement.remediation(),
                    )
                })?;
                register_artifact_identity(&mut seen_identities, &snapshot).map_err(|error| {
                    bootstrap_error(
                        lens,
                        model_path,
                        "external_data_identity_alias",
                        provider,
                        &device,
                        error,
                        placement.remediation(),
                    )
                })?;
                let FrozenArtifactSnapshot {
                    evidence, bytes, ..
                } = snapshot;
                let index = external_data.len();
                let canonical = evidence.source_path.clone();
                external_evidence.push(evidence);
                external_data.push((logical_path.clone(), bytes));
                seen_locations.insert(key, (canonical.clone(), logical_path.clone(), index));
                (canonical, index)
            };
        let bytes = &external_data[buffer_index].1;
        validate_external_range(&reference, bytes).map_err(|error| {
            bootstrap_error(
                lens,
                model_path,
                "external_data_range_validation",
                provider,
                &device,
                format!("{} (source={})", error, canonical_path.display()),
                placement.remediation(),
            )
        })?;
    }
    external_evidence.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    external_data.sort_by(|left, right| left.0.cmp(&right.0));

    let (tokenizer, tokenizer_bytes) = match tokenizer_path {
        Some(path) => {
            let tokenizer_root = calyx_onnx_runtime::open_immutable_directory(artifact_parent(
                path,
            ))
            .map_err(|error| {
                bootstrap_error(
                    lens,
                    model_path,
                    "tokenizer_root_snapshot",
                    provider,
                    &device,
                    error,
                    placement.remediation(),
                )
            })?;
            let snapshot = snapshot_artifact(
                "tokenizer",
                "tokenizer.json",
                path,
                Some(&tokenizer_root),
                &mut remaining_budget,
            )
            .map_err(|error| {
                bootstrap_error(
                    lens,
                    model_path,
                    "tokenizer_snapshot",
                    provider,
                    &device,
                    error,
                    placement.remediation(),
                )
            })?;
            validate_direct_root(&snapshot, &tokenizer_root, "tokenizer").map_err(|error| {
                bootstrap_error(
                    lens,
                    model_path,
                    "tokenizer_root_validation",
                    provider,
                    &device,
                    error,
                    placement.remediation(),
                )
            })?;
            register_artifact_identity(&mut seen_identities, &snapshot).map_err(|error| {
                bootstrap_error(
                    lens,
                    model_path,
                    "tokenizer_identity_alias",
                    provider,
                    &device,
                    error,
                    placement.remediation(),
                )
            })?;
            let FrozenArtifactSnapshot {
                evidence, bytes, ..
            } = snapshot;
            if bytes.is_empty() {
                return Err(bootstrap_error(
                    lens,
                    model_path,
                    "tokenizer_validation",
                    provider,
                    &device,
                    "tokenizer artifact is empty",
                    placement.remediation(),
                ));
            }
            (Some(evidence), Some(bytes))
        }
        None => (None, None),
    };

    let mut contract = WardOnnxArtifactContract {
        schema: ARTIFACT_SCHEMA.to_string(),
        provider_policy: provider.to_string(),
        execution_device: device,
        contract_sha256: String::new(),
        frozen_operators,
        model,
        external_data: external_evidence,
        tokenizer,
    };
    contract.contract_sha256 = artifact_contract_sha256(&contract);
    Ok(WardOnnxArtifactBundle {
        contract,
        model_bytes,
        external_data,
        tokenizer_bytes,
        placement,
    })
}

#[derive(Debug)]
struct FrozenArtifactSnapshot {
    evidence: WardOnnxArtifactEvidence,
    identity: ImmutableFileIdentity,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ArtifactIdentityClaim {
    role: String,
    logical_name: String,
    source_path: PathBuf,
}

fn artifact_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_direct_root(
    snapshot: &FrozenArtifactSnapshot,
    root: &ImmutableDirectoryRoot,
    role: &str,
) -> Result<(), String> {
    if snapshot.evidence.source_path.parent() != Some(root.final_path()) {
        return Err(format!(
            "{role} handle-final path {} is not a direct child of retained root {}",
            snapshot.evidence.source_path.display(),
            root.final_path().display(),
        ));
    }
    Ok(())
}

fn snapshot_artifact(
    role: &str,
    logical_name: &str,
    path: &Path,
    required_root: Option<&ImmutableDirectoryRoot>,
    remaining_budget: &mut u64,
) -> Result<FrozenArtifactSnapshot, CalyxError> {
    let ImmutableFileSnapshot {
        final_path,
        identity,
        bytes,
    } = calyx_onnx_runtime::snapshot_immutable_file(path, required_root, *remaining_budget)?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| CalyxError {
        code: "CALYX_WARD_ONNX_ARTIFACT_SIZE_OVERFLOW",
        message: format!("artifact {} byte length exceeds u64", final_path.display()),
        remediation: "commission a smaller artifact that fits the native process address space",
    })?;
    *remaining_budget = (*remaining_budget)
        .checked_sub(bytes_len)
        .ok_or_else(|| CalyxError {
            code: "CALYX_WARD_ONNX_ARTIFACT_BUDGET_UNDERFLOW",
            message: format!(
                "artifact {} consumed {bytes_len} bytes beyond the cumulative snapshot budget",
                final_path.display()
            ),
            remediation: "commission artifacts within the measured host-memory and CUDA-VRAM budget",
        })?;
    let evidence = WardOnnxArtifactEvidence {
        role: role.to_string(),
        logical_name: logical_name.to_string(),
        source_path: final_path,
        bytes: bytes_len,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    Ok(FrozenArtifactSnapshot {
        evidence,
        identity,
        bytes,
    })
}

fn register_artifact_identity(
    seen: &mut BTreeMap<ImmutableFileIdentity, ArtifactIdentityClaim>,
    snapshot: &FrozenArtifactSnapshot,
) -> Result<(), String> {
    let claim = ArtifactIdentityClaim {
        role: snapshot.evidence.role.clone(),
        logical_name: snapshot.evidence.logical_name.clone(),
        source_path: snapshot.evidence.source_path.clone(),
    };
    if let Some(previous) = seen.insert(snapshot.identity, claim) {
        return Err(format!(
            "artifact {}:{} at {} aliases {}:{} at {} through Windows file identity {:?}",
            snapshot.evidence.role,
            snapshot.evidence.logical_name,
            snapshot.evidence.source_path.display(),
            previous.role,
            previous.logical_name,
            previous.source_path.display(),
            snapshot.identity,
        ));
    }
    Ok(())
}

fn bootstrap_error(
    lens: &'static str,
    model: &Path,
    stage: &'static str,
    provider: &str,
    device: &str,
    reason: impl ToString,
    remediation: &'static str,
) -> WardError {
    let reason = reason.to_string();
    eprintln!(
        "CALYX_WARD_ONNX phase=failure lens={lens} stage={stage} model={} model_sha256=unavailable_before_immutable_snapshot artifact_contract_sha256=unavailable_before_immutable_snapshot provider={provider} device={device} frozen_operators=unavailable_before_immutable_snapshot reason={reason} remediation={remediation}",
        model.display(),
    );
    WardError::Onnx {
        lens,
        stage,
        model: model.to_path_buf(),
        model_sha256: "unavailable_before_immutable_snapshot".to_string(),
        artifact_contract_sha256: "unavailable_before_immutable_snapshot".to_string(),
        frozen_operators: "unavailable_before_immutable_snapshot".to_string(),
        provider: provider.to_string(),
        device: device.to_string(),
        reason,
        remediation,
    }
}

fn validated_external_location(location: &str) -> Result<PathBuf, String> {
    if location.trim().is_empty()
        || location.contains('\0')
        || location.starts_with('/')
        || location.contains('\\')
    {
        return Err(format!(
            "external_data location {location:?} must be non-empty relative POSIX text without NUL or backslash"
        ));
    }
    if location
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        return Err(format!(
            "external_data location {location:?} is not a canonical relative POSIX path"
        ));
    }
    let path = Path::new(location);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(format!(
                    "external_data location {location:?} is not a confined relative path"
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(format!(
            "external_data location {location:?} has no file component"
        ));
    }
    Ok(normalized)
}

fn validate_external_range(reference: &ExternalDataReference, buffer: &[u8]) -> Result<(), String> {
    let bytes =
        u64::try_from(buffer.len()).map_err(|_| "external data size exceeds u64".to_string())?;
    if reference.offset > bytes {
        return Err(format!(
            "external_data {} offset {} exceeds file size {bytes}",
            reference.location, reference.offset
        ));
    }
    if let Some(length) = reference.length {
        let end = reference
            .offset
            .checked_add(length)
            .ok_or_else(|| "external_data offset+length exceeds u64".to_string())?;
        if end > bytes {
            return Err(format!(
                "external_data {} range {}..{} exceeds file size {bytes}",
                reference.location, reference.offset, end
            ));
        }
    }
    if let Some(checksum) = &reference.checksum {
        let observed = format!("{:x}", sha1::Sha1::digest(buffer));
        if !checksum.eq_ignore_ascii_case(&observed) {
            return Err(format!(
                "external_data {} SHA1 mismatch; declared={} observed={observed}",
                reference.location, checksum
            ));
        }
    }
    Ok(())
}

fn artifact_contract_sha256(contract: &WardOnnxArtifactContract) -> String {
    let mut hash = Sha256::new();
    update_length_delimited(&mut hash, contract.schema.as_bytes());
    update_length_delimited(&mut hash, contract.provider_policy.as_bytes());
    update_length_delimited(&mut hash, contract.execution_device.as_bytes());
    update_length_delimited(&mut hash, contract.frozen_operators.as_bytes());
    update_artifact_digest(&mut hash, &contract.model);
    for artifact in &contract.external_data {
        update_artifact_digest(&mut hash, artifact);
    }
    if let Some(artifact) = &contract.tokenizer {
        update_artifact_digest(&mut hash, artifact);
    }
    format!("{:x}", hash.finalize())
}

fn update_artifact_digest(hash: &mut Sha256, artifact: &WardOnnxArtifactEvidence) {
    update_length_delimited(hash, artifact.role.as_bytes());
    update_length_delimited(hash, artifact.logical_name.as_bytes());
    update_length_delimited(hash, &artifact.bytes.to_be_bytes());
    update_length_delimited(hash, artifact.sha256.as_bytes());
}

fn update_length_delimited(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn artifact_summary(artifact: &WardOnnxArtifactEvidence) -> String {
    format!(
        "{}:{}:{}:{}",
        artifact.role, artifact.logical_name, artifact.bytes, artifact.sha256
    )
}

fn artifact_inventory_summary(artifacts: &[WardOnnxArtifactEvidence]) -> String {
    if artifacts.is_empty() {
        "none".to_string()
    } else {
        artifacts
            .iter()
            .map(artifact_summary)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Clone, Debug)]
struct GraphAssignment {
    total_nodes: u64,
    cpu_nodes: u64,
    cuda_nodes: u64,
    per_provider: String,
    per_provider_operators: String,
}

#[derive(Clone, Debug)]
enum ExecutionState {
    Pending,
    Attested(RuntimeExecutionAttestation),
    Failed(WardError),
}

/// Exact committed ORT session plus runtime placement evidence.
pub(crate) struct ManagedWardOnnxSession {
    // Declaration order is binding: ORT must drop before its user compute stream.
    session: Mutex<Session>,
    cuda_stream: Option<OnnxCudaExecutionStream>,
    profile_root: ImmutableDirectoryRoot,
    context: SessionContext,
    assignment: GraphAssignment,
    execution_state: Mutex<ExecutionState>,
}

impl ManagedWardOnnxSession {
    /// Accesses committed-session metadata. Productive inference must use
    /// [`Self::run_real_inference`] so the first run and profile finalization
    /// cannot race with another caller.
    pub(crate) fn inspect_session<T>(
        &self,
        action: impl FnOnce(&Session) -> Result<T, WardError>,
    ) -> Result<T, WardError> {
        let session = self.lock_session()?;
        action(&session)
    }

    /// Runs one real inference while holding the session through output host
    /// materialization and one-time profiling finalization. Callers return an
    /// owned, validated output from `action`; Ward never attests a borrowed or
    /// not-yet-materialized provider output.
    pub(crate) fn run_real_inference<T>(
        &self,
        action: impl FnOnce(&mut Session) -> Result<T, WardError>,
    ) -> Result<T, WardError> {
        let mut session = self.lock_session()?;
        self.ensure_usable()?;
        let output = match action(&mut session) {
            Ok(output) => output,
            Err(error) => {
                self.record_cuda_failure(error.clone())?;
                return Err(error);
            }
        };
        if let Err(error) = self.synchronize_and_attest_cuda() {
            self.record_cuda_failure(error.clone())?;
            return Err(error);
        }
        self.complete_first_inference(&mut session)?;
        Ok(output)
    }

    pub(crate) fn error(&self, stage: &'static str, reason: impl ToString) -> WardError {
        self.context.error(stage, reason)
    }

    pub(crate) const fn provider_policy(&self) -> &'static str {
        self.context.placement.provider()
    }

    /// Returns evidence only after this exact committed session completed a
    /// synchronous real inference, materialized its output on the host, and
    /// passed the independent ORT profiling readback.
    pub(crate) fn execution_attestation(
        &self,
    ) -> Result<Option<RuntimeExecutionAttestation>, WardError> {
        match &*self.lock_execution_state()? {
            ExecutionState::Pending => Ok(None),
            ExecutionState::Attested(attestation) => Ok(Some(attestation.clone())),
            ExecutionState::Failed(error) => Err(error.clone()),
        }
    }

    pub(crate) fn durable_execution_attestation(
        &self,
        lens_id: LensId,
    ) -> Result<Option<WardOnnxExecutionAttestation>, WardError> {
        self.execution_attestation().map(|attestation| {
            attestation.map(|runtime| WardOnnxExecutionAttestation {
                schema: EXECUTION_SCHEMA.to_string(),
                lens_id,
                artifacts: self.context.artifacts.clone(),
                runtime,
            })
        })
    }

    fn complete_first_inference(&self, session: &mut Session) -> Result<(), WardError> {
        let mut state = self.lock_execution_state()?;
        match &*state {
            ExecutionState::Attested(_) => return Ok(()),
            ExecutionState::Failed(error) => return Err(error.clone()),
            ExecutionState::Pending => {}
        }
        let result = self.profile_attestation(session);
        match result {
            Ok(attestation) => {
                eprintln!(
                    "CALYX_WARD_ONNX phase=first_real_inference_attested lens={} model={} model_sha256={} provider={} device={} total_nodes={} cpu_nodes={} evidence={}",
                    self.context.lens,
                    self.context.model.display(),
                    self.context.model_sha256,
                    attestation.provider,
                    attestation.device,
                    attestation.total_compute_nodes.unwrap_or(0),
                    attestation.cpu_compute_nodes.unwrap_or(0),
                    attestation.evidence,
                );
                *state = ExecutionState::Attested(attestation);
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "CALYX_WARD_ONNX phase=first_real_inference_attestation_failed lens={} code={} error={}",
                    self.context.lens,
                    error.code(),
                    error,
                );
                *state = ExecutionState::Failed(error.clone());
                Err(error)
            }
        }
    }

    fn profile_attestation(
        &self,
        session: &mut Session,
    ) -> Result<RuntimeExecutionAttestation, WardError> {
        // The caller materialized owned host output and synchronized the exact
        // retained stream before ending this one-shot profile.
        let trace_path = session
            .end_profiling()
            .map_err(|error| self.error("first_inference_end_profiling", error))?;
        self.validate_returned_profile_name(&trace_path)?;
        let profile_budget = calyx_onnx_runtime::available_host_memory_bytes()
            .map_err(|error| self.error("first_inference_profile_memory_budget", error))?
            .min(MAX_PROFILE_TRACE_BYTES);
        let trace = calyx_onnx_runtime::snapshot_immutable_file(
            Path::new(&trace_path),
            Some(&self.profile_root),
            profile_budget,
        )
        .map_err(|error| self.error("first_inference_profile_readback", error))?;
        self.validate_profile_snapshot(&trace_path, &trace, &self.profile_root)?;
        let trace_sha256 = format!("{:x}", Sha256::digest(&trace.bytes));
        let profile = parse_profile_assignment(&trace.bytes, &self.context.placement)
            .map_err(|error| self.error("first_inference_profile_parse", error))?;
        validate_profile_assignment(&self.context, &profile)?;
        let execution_device = self.observed_execution_device()?;
        Ok(RuntimeExecutionAttestation {
            runtime: format!("ward-onnx-{}", self.context.lens),
            provider: format!(
                "api24={};profile={}",
                self.assignment.per_provider, profile.per_provider
            ),
            device: execution_device.clone(),
            loader_dtype: None,
            compute_dtype: None,
            evidence: format!(
                "onnx_api24_committed_session+first_real_host_materialized_retained_stream_synchronized_inference_profile;model={};model_sha256={};artifact_contract_sha256={};provider_policy={};execution_device={};frozen_operators={};external_data={};tokenizer={};api24_total_nodes={};api24_cuda_nodes={};api24_cpu_nodes={};assigned_operators={};profile_total_nodes={};profile_cuda_nodes={};profile_cpu_nodes={};profile_operators={};profile_path={};profile_file_identity={}:{};profile_sha256={}",
                self.context.model.display(),
                self.context.model_sha256,
                self.context.artifacts.contract_sha256,
                self.context.placement.provider(),
                execution_device,
                self.context.frozen_operators,
                artifact_inventory_summary(&self.context.artifacts.external_data),
                self.context
                    .artifacts
                    .tokenizer
                    .as_ref()
                    .map_or_else(|| "none".to_string(), artifact_summary),
                self.assignment.total_nodes,
                self.assignment.cuda_nodes,
                self.assignment.cpu_nodes,
                self.assignment.per_provider_operators,
                profile.total_nodes,
                profile.cuda_nodes,
                profile.cpu_nodes,
                profile.per_provider_operators,
                trace.final_path.display(),
                trace.identity.volume_serial_number,
                trace.identity.file_index,
                trace_sha256,
            ),
            total_compute_nodes: Some(self.assignment.total_nodes),
            cpu_compute_nodes: Some(self.assignment.cpu_nodes),
        })
    }

    fn validate_returned_profile_name(&self, trace_path: &str) -> Result<(), WardError> {
        let expected_name = self
            .context
            .profile_prefix
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.error(
                    "first_inference_profile_path_validation",
                    "profiling prefix has no UTF-8 file name",
                )
            })?;
        let observed_name = Path::new(trace_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.error(
                    "first_inference_profile_path_validation",
                    format!("returned profiling path {trace_path} has no UTF-8 file name"),
                )
            })?;
        if !observed_name.starts_with(expected_name) {
            return Err(self.error(
                "first_inference_profile_path_validation",
                format!(
                    "ORT returned unexpected profile name {trace_path}; expected prefix {}",
                    self.context.profile_prefix.display()
                ),
            ));
        }
        Ok(())
    }

    fn validate_profile_snapshot(
        &self,
        returned_path: &str,
        snapshot: &ImmutableFileSnapshot,
        root: &ImmutableDirectoryRoot,
    ) -> Result<(), WardError> {
        let expected_name = self
            .context
            .profile_prefix
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.error(
                    "first_inference_profile_path_validation",
                    "profiling prefix has no UTF-8 file name",
                )
            })?;
        let observed_name = snapshot
            .final_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.error(
                    "first_inference_profile_path_validation",
                    format!(
                        "handle-final profiling path {} has no UTF-8 file name",
                        snapshot.final_path.display()
                    ),
                )
            })?;
        if snapshot.final_path.parent() != Some(root.final_path())
            || !observed_name.starts_with(expected_name)
        {
            return Err(self.error(
                "first_inference_profile_path_validation",
                format!(
                    "ORT returned profile {returned_path}, but its opened handle resolved to {} outside direct root {} or without prefix {expected_name}",
                    snapshot.final_path.display(),
                    root.final_path().display(),
                ),
            ));
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), WardError> {
        match &*self.lock_execution_state()? {
            ExecutionState::Failed(error) => Err(error.clone()),
            ExecutionState::Pending | ExecutionState::Attested(_) => Ok(()),
        }
    }

    fn record_cuda_failure(&self, error: WardError) -> Result<(), WardError> {
        if !matches!(&self.context.placement, Placement::Cuda(_)) {
            return Ok(());
        }
        let mut state = self.lock_execution_state()?;
        *state = ExecutionState::Failed(error);
        Ok(())
    }

    fn synchronize_and_attest_cuda(&self) -> Result<(), WardError> {
        match (&self.context.placement, &self.cuda_stream) {
            (Placement::Cuda(expected), Some(stream)) => {
                if !expected.same_stable_device(stream.device()) {
                    return Err(self.error(
                        "cuda_stream_identity",
                        format!(
                            "retained stream device {} differs from session device {}",
                            stream.device().frozen_execution_device(),
                            expected.frozen_execution_device(),
                        ),
                    ));
                }
                stream
                    .synchronize_and_attest()
                    .map_err(|error| self.error("cuda_stream_post_inference_attestation", error))
            }
            (Placement::Cuda(_), None) => Err(self.error(
                "cuda_stream_missing",
                "CUDA session has no retained physical-device-bound execution stream",
            )),
            (Placement::CpuExplicit, None) => Ok(()),
            (Placement::CpuExplicit, Some(_)) => Err(self.error(
                "cpu_stream_contract",
                "CPU-explicit session unexpectedly retained a CUDA execution stream",
            )),
        }
    }

    fn observed_execution_device(&self) -> Result<String, WardError> {
        match (&self.context.placement, &self.cuda_stream) {
            (Placement::Cuda(expected), Some(stream))
                if expected.same_stable_device(stream.device()) =>
            {
                Ok(stream.device().frozen_execution_device())
            }
            (Placement::Cuda(expected), Some(stream)) => Err(self.error(
                "cuda_stream_identity",
                format!(
                    "retained stream device {} differs from session device {}",
                    stream.device().frozen_execution_device(),
                    expected.frozen_execution_device(),
                ),
            )),
            (Placement::Cuda(_), None) => Err(self.error(
                "cuda_stream_missing",
                "CUDA session has no retained physical-device-bound execution stream",
            )),
            (Placement::CpuExplicit, None) => Ok("cpu".to_string()),
            (Placement::CpuExplicit, Some(_)) => Err(self.error(
                "cpu_stream_contract",
                "CPU-explicit session unexpectedly retained a CUDA execution stream",
            )),
        }
    }

    fn lock_session(&self) -> Result<MutexGuard<'_, Session>, WardError> {
        self.session
            .lock()
            .map_err(|_| self.error("session_lock", "ORT session mutex poisoned"))
    }

    fn lock_execution_state(&self) -> Result<MutexGuard<'_, ExecutionState>, WardError> {
        self.execution_state.lock().map_err(|_| {
            self.error(
                "execution_attestation_state",
                "execution-attestation mutex poisoned",
            )
        })
    }
}

/// Builds a Ward session from an immutable snapshot. CUDA graph construction
/// or inference is never retried through the CPU companion path.
pub(crate) fn build_session(
    lens: &'static str,
    bundle: WardOnnxArtifactBundle,
) -> Result<ManagedWardOnnxSession, WardError> {
    let context = SessionContext::new(lens, &bundle);
    calyx_onnx_runtime::ensure_runtime(
        context.placement.runtime_policy(),
        context.placement.runtime_ordinal(),
    )
    .map_err(|error| context.error("pinned_runtime_validation", error))?;
    let profile_root =
        calyx_onnx_runtime::open_immutable_directory(artifact_parent(&context.profile_prefix))
            .map_err(|error| context.error("first_inference_profile_root", error))?;
    let cuda_stream = match &context.placement {
        Placement::Cuda(device) => Some(
            calyx_onnx_runtime::create_cuda_execution_stream(device)
                .map_err(|error| context.error("cuda_stream_construction", error))?,
        ),
        Placement::CpuExplicit => None,
    };
    let compute_stream = cuda_stream
        .as_ref()
        .map(OnnxCudaExecutionStream::stream_ptr)
        .transpose()
        .map_err(|error| context.error("cuda_stream_pointer_attestation", error))?;

    let mut builder = Session::builder()
        .map_err(|error| context.error("session_builder", error))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|error| context.error("graph_optimization", error))?
        .with_execution_providers(execution_providers(&context, compute_stream)?)
        .map_err(|error| context.error("provider_registration", error))?;
    if matches!(&context.placement, Placement::Cuda(_)) {
        builder = builder
            .with_disable_cpu_fallback()
            .map_err(|error| context.error("disable_cpu_fallback", error))?;
    }
    builder = builder
        .with_config_entry(GRAPH_ASSIGNMENT_CONFIG, "1")
        .map_err(|error| context.error("graph_assignment_recording", error))?
        .with_profiling(&context.profile_prefix)
        .map_err(|error| context.error("first_inference_profiling_enable", error))?;

    let WardOnnxArtifactBundle {
        model_bytes,
        external_data,
        ..
    } = bundle;
    for (logical_name, bytes) in external_data {
        builder = builder
            .with_external_initializer_file_in_memory(logical_name, Cow::Owned(bytes))
            .map_err(|error| context.error("external_data_commit", error))?;
    }

    let session = builder
        .commit_from_memory(&model_bytes)
        .map_err(|error| context.error("model_memory_commit", error))?;
    if let Some(stream) = &cuda_stream {
        stream
            .synchronize_and_attest()
            .map_err(|error| context.error("cuda_stream_post_constructor_attestation", error))?;
    }
    let assignment = read_graph_assignment(&session)
        .map_err(|error| context.error("api24_graph_assignment_readback", error))?;
    validate_graph_assignment(&context, &assignment)?;
    let execution_device = cuda_stream.as_ref().map_or_else(
        || "cpu".to_string(),
        |stream| stream.device().frozen_execution_device(),
    );
    eprintln!(
        "CALYX_WARD_ONNX phase=api24_graph_assignment lens={} model={} model_sha256={} artifact_contract_sha256={} provider={} device={} total_nodes={} cuda_nodes={} cpu_nodes={} providers={} assigned_operators={} frozen_operators={} external_data={} tokenizer={}",
        context.lens,
        context.model.display(),
        context.model_sha256,
        context.artifacts.contract_sha256,
        context.placement.provider(),
        execution_device,
        assignment.total_nodes,
        assignment.cuda_nodes,
        assignment.cpu_nodes,
        assignment.per_provider,
        assignment.per_provider_operators,
        context.frozen_operators,
        artifact_inventory_summary(&context.artifacts.external_data),
        context
            .artifacts
            .tokenizer
            .as_ref()
            .map_or_else(|| "none".to_string(), artifact_summary),
    );

    Ok(ManagedWardOnnxSession {
        session: Mutex::new(session),
        cuda_stream,
        profile_root,
        context,
        assignment,
        execution_state: Mutex::new(ExecutionState::Pending),
    })
}

fn execution_providers(
    context: &SessionContext,
    compute_stream: Option<*mut ()>,
) -> Result<Vec<ExecutionProviderDispatch>, WardError> {
    match &context.placement {
        Placement::Cuda(device) => {
            let stream = compute_stream.ok_or_else(|| {
                context.error(
                    "cuda_stream_missing",
                    "CUDA provider construction has no retained execution-stream pointer",
                )
            })?;
            let device_id = i32::try_from(device.ordinal).map_err(|_| {
                context.error(
                    "cuda_device_ordinal",
                    format!(
                        "attested CUDA Runtime ordinal {} exceeds ORT's i32 ABI",
                        device.ordinal
                    ),
                )
            })?;
            let cuda = ep::CUDA::default()
                .with_device_id(device_id)
                .with_arena_extend_strategy(ArenaExtendStrategy::SameAsRequested);
            // The returned owner is stored after `session`, so it outlives ORT.
            let cuda = unsafe { cuda.with_compute_stream(stream) };
            Ok(vec![cuda.build().error_on_failure()])
        }
        Placement::CpuExplicit if compute_stream.is_none() => {
            Ok(vec![ep::CPU::default().build().error_on_failure()])
        }
        Placement::CpuExplicit => Err(context.error(
            "cpu_stream_contract",
            "CPU-explicit provider construction received a CUDA execution stream",
        )),
    }
}

fn read_graph_assignment(session: &Session) -> Result<GraphAssignment, OrtError> {
    let mut subgraphs = ptr::null();
    let mut subgraph_count = 0usize;
    // ORT owns every returned assignment object for the session lifetime; this
    // function only reads them while `session` is borrowed.
    status_result(unsafe {
        (ort::api().Session_GetEpGraphAssignmentInfo)(
            session.ptr(),
            &mut subgraphs,
            &mut subgraph_count,
        )
    })?;
    if subgraph_count > 0 && subgraphs.is_null() {
        return Err(OrtError::new(
            "Session_GetEpGraphAssignmentInfo returned a null subgraph array",
        ));
    }
    let subgraphs = if subgraph_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(subgraphs, subgraph_count) }
    };

    let mut counts = BTreeMap::<String, u64>::new();
    let mut operators = BTreeMap::<String, BTreeSet<String>>::new();
    for &subgraph in subgraphs {
        if subgraph.is_null() {
            return Err(OrtError::new(
                "Session_GetEpGraphAssignmentInfo returned a null subgraph",
            ));
        }
        let provider = assigned_string(|out| unsafe {
            (ort::api().EpAssignedSubgraph_GetEpName)(subgraph, out)
        })?;
        if provider.trim().is_empty() {
            return Err(OrtError::new(
                "EpAssignedSubgraph_GetEpName returned an empty provider",
            ));
        }
        let mut nodes = ptr::null();
        let mut node_count = 0usize;
        status_result(unsafe {
            (ort::api().EpAssignedSubgraph_GetNodes)(subgraph, &mut nodes, &mut node_count)
        })?;
        if node_count > 0 && nodes.is_null() {
            return Err(OrtError::new(
                "EpAssignedSubgraph_GetNodes returned a null node array",
            ));
        }
        let node_count_u64 = u64::try_from(node_count)
            .map_err(|_| OrtError::new("assigned ONNX node count exceeds u64"))?;
        let provider_count = counts.entry(provider.clone()).or_default();
        *provider_count = provider_count
            .checked_add(node_count_u64)
            .ok_or_else(|| OrtError::new("assigned ONNX provider node count exceeds u64"))?;
        let nodes = if node_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(nodes, node_count) }
        };
        for &node in nodes {
            if node.is_null() {
                return Err(OrtError::new(
                    "EpAssignedSubgraph_GetNodes returned a null node",
                ));
            }
            let operator = assigned_string(|out| unsafe {
                (ort::api().EpAssignedNode_GetOperatorType)(node, out)
            })?;
            if operator.trim().is_empty() {
                return Err(OrtError::new(
                    "EpAssignedNode_GetOperatorType returned an empty operator",
                ));
            }
            let domain =
                assigned_string(|out| unsafe { (ort::api().EpAssignedNode_GetDomain)(node, out) })?;
            let operator = if domain.trim().is_empty() {
                operator
            } else {
                format!("{domain}::{operator}")
            };
            operators
                .entry(provider.clone())
                .or_default()
                .insert(operator);
        }
    }

    assignment_from_counts(counts, operators)
}

fn assignment_from_counts(
    counts: BTreeMap<String, u64>,
    operators: BTreeMap<String, BTreeSet<String>>,
) -> Result<GraphAssignment, OrtError> {
    let total_nodes = checked_count_sum(counts.values().copied())?;
    let cpu_nodes = checked_count_sum(
        counts
            .iter()
            .filter(|(provider, _)| provider_name_is(provider, "CPU"))
            .map(|(_, count)| *count),
    )?;
    let cuda_nodes = checked_count_sum(
        counts
            .iter()
            .filter(|(provider, _)| provider_name_is(provider, "CUDA"))
            .map(|(_, count)| *count),
    )?;
    let per_provider = counts
        .iter()
        .map(|(provider, count)| format!("{provider}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    let per_provider_operators = operators
        .iter()
        .map(|(provider, names)| {
            format!(
                "{}:[{}]",
                provider,
                names.iter().cloned().collect::<Vec<_>>().join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    Ok(GraphAssignment {
        total_nodes,
        cpu_nodes,
        cuda_nodes,
        per_provider,
        per_provider_operators,
    })
}

fn checked_count_sum(counts: impl IntoIterator<Item = u64>) -> Result<u64, OrtError> {
    counts.into_iter().try_fold(0u64, |total, count| {
        total
            .checked_add(count)
            .ok_or_else(|| OrtError::new("ONNX placement node count exceeds u64"))
    })
}

fn validate_graph_assignment(
    context: &SessionContext,
    assignment: &GraphAssignment,
) -> Result<(), WardError> {
    validate_exact_placement(context, "api24_graph_assignment_validation", assignment)
}

fn validate_profile_assignment(
    context: &SessionContext,
    assignment: &GraphAssignment,
) -> Result<(), WardError> {
    validate_exact_placement(context, "first_inference_profile_validation", assignment)
}

fn validate_exact_placement(
    context: &SessionContext,
    stage: &'static str,
    assignment: &GraphAssignment,
) -> Result<(), WardError> {
    if assignment.total_nodes == 0 {
        return Err(context.error(stage, "placement evidence reported zero compute nodes"));
    }
    match &context.placement {
        Placement::Cuda(_)
            if assignment.cpu_nodes != 0 || assignment.cuda_nodes != assignment.total_nodes =>
        {
            Err(context.error(
                stage,
                format!(
                    "expected every compute node on CUDA, observed cuda={}/{} cpu={} providers={} operators={}",
                    assignment.cuda_nodes,
                    assignment.total_nodes,
                    assignment.cpu_nodes,
                    assignment.per_provider,
                    assignment.per_provider_operators,
                ),
            ))
        }
        Placement::CpuExplicit if assignment.cpu_nodes != assignment.total_nodes => {
            Err(context.error(
                stage,
                format!(
                    "expected every compute node on explicit CPU, observed cpu={}/{} providers={} operators={}",
                    assignment.cpu_nodes,
                    assignment.total_nodes,
                    assignment.per_provider,
                    assignment.per_provider_operators,
                ),
            ))
        }
        _ => Ok(()),
    }
}

fn parse_profile_assignment(
    bytes: &[u8],
    placement: &Placement,
) -> Result<GraphAssignment, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("ONNX profiling trace is not valid JSON: {error}"))?;
    let events = match &value {
        Value::Array(events) => events.as_slice(),
        Value::Object(map) => match map.get("traceEvents") {
            Some(Value::Array(events)) => events.as_slice(),
            _ => return Err("ONNX profiling trace object has no traceEvents array".to_string()),
        },
        _ => return Err("ONNX profiling trace is not an event array or traceEvents object".into()),
    };

    if events.is_empty() {
        return Err("ONNX profiling trace has no events".to_string());
    }

    let mut kernel_counts = BTreeMap::<String, u64>::new();
    let mut kernel_operators = BTreeMap::<String, BTreeSet<String>>::new();
    for (index, event) in events.iter().enumerate() {
        let event = event
            .as_object()
            .ok_or_else(|| format!("ONNX profile event {index} is not an object"))?;
        let Some(category) = event.get("cat") else {
            continue;
        };
        let category = category
            .as_str()
            .ok_or_else(|| format!("ONNX profile event {index} cat is not a string"))?;
        if category != "Node" {
            continue;
        }
        let name = event
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| format!("ONNX Node profile event {index} has no non-empty name"))?;
        let args = event
            .get("args")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("ONNX Node profile event {index} has no args object"))?;
        let provider = args
            .get("provider")
            .and_then(Value::as_str)
            .filter(|provider| !provider.trim().is_empty())
            .ok_or_else(|| {
                format!("ONNX Node profile event {index} ({name}) has no non-empty provider")
            })?;
        if matches!(placement, Placement::Cuda(_)) && provider_name_is(provider, "CPU") {
            return Err(format!(
                "CUDA profile contains CPU provider event {index} ({name}) provider={provider}"
            ));
        }
        if !name.ends_with("_kernel_time") {
            continue;
        }
        let operator = profile_operator(args)
            .map_err(|error| format!("ONNX kernel profile event {index} ({name}) {error}"))?;
        increment_profile_count(&mut kernel_counts, provider)?;
        kernel_operators
            .entry(provider.to_string())
            .or_default()
            .insert(operator);
    }
    if kernel_counts.is_empty() {
        return Err("ONNX profiling trace contains no recognized *_kernel_time events".to_string());
    }
    assignment_from_counts(kernel_counts, kernel_operators).map_err(|error| error.to_string())
}

fn profile_operator(args: &serde_json::Map<String, Value>) -> Result<String, String> {
    for key in ["op_name", "op_type", "operator"] {
        let Some(value) = args.get(key) else {
            continue;
        };
        let operator = value
            .as_str()
            .ok_or_else(|| format!("has non-string {key}"))?;
        if operator.trim().is_empty() {
            return Err(format!("has empty {key}"));
        }
        return Ok(operator.to_string());
    }
    Err("has no explicit operator identity".to_string())
}

fn increment_profile_count(
    counts: &mut BTreeMap<String, u64>,
    provider: &str,
) -> Result<(), String> {
    let count = counts.entry(provider.to_string()).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| "profile compute-node count exceeds u64".to_string())?;
    Ok(())
}

fn provider_name_is(provider: &str, expected: &str) -> bool {
    match expected {
        "CPU" => provider == "CPUExecutionProvider",
        "CUDA" => provider == "CUDAExecutionProvider",
        _ => false,
    }
}

fn assigned_string(
    call: impl FnOnce(*mut *const c_char) -> ort::sys::OrtStatusPtr,
) -> Result<String, OrtError> {
    let mut raw = ptr::null();
    status_result(call(&mut raw))?;
    if raw.is_null() {
        return Err(OrtError::new(
            "ONNX graph assignment returned a null string",
        ));
    }
    // API-24 documents this as an ORT-owned, NUL-terminated UTF-8 string.
    unsafe { CStr::from_ptr(raw) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| {
            OrtError::new(format!(
                "ONNX graph assignment string is not UTF-8: {error}"
            ))
        })
}

fn status_result(status: ort::sys::OrtStatusPtr) -> Result<(), OrtError> {
    // The ORT API transfers ownership of a non-null status to the caller.
    unsafe { OrtError::result_from_status(status) }
}

fn profiling_file_path(label: &str) -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let label = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    std::env::temp_dir().join(format!(
        "calyx_ward_onnx_profile_{}_{}_{sequence}",
        std::process::id(),
        label,
    ))
}

fn frozen_operator_inventory(bytes: &[u8]) -> Result<String, String> {
    let mut model = ProtoCursor::new(bytes);
    let mut graph_count = 0usize;
    let mut inventory = BTreeMap::<String, u64>::new();
    while let Some(field) = model.next_field()? {
        match field.number {
            7 => {
                graph_count = graph_count
                    .checked_add(1)
                    .ok_or_else(|| "ModelProto graph count exceeds usize".to_string())?;
                parse_graph_operators(field.bytes("ModelProto.graph")?, 0, &mut inventory)?;
            }
            20 => parse_training_info_operators(
                field.bytes("ModelProto.training_info")?,
                0,
                &mut inventory,
            )?,
            25 => {
                parse_function_operators(field.bytes("ModelProto.functions")?, 0, &mut inventory)?
            }
            _ => {}
        }
    }
    if graph_count != 1 {
        return Err(format!(
            "ModelProto contains {graph_count} graph fields; expected exactly one"
        ));
    }
    if inventory.is_empty() {
        return Err("frozen ONNX graph contains no operator nodes".to_string());
    }
    Ok(inventory
        .into_iter()
        .map(|(operator, count)| format!("{operator}:{count}"))
        .collect::<Vec<_>>()
        .join(","))
}

fn parse_graph_operators(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut graph = ProtoCursor::new(bytes);
    while let Some(field) = graph.next_field()? {
        if field.number == 1 {
            parse_node_operators(field.bytes("GraphProto.node")?, depth, inventory)?;
        }
    }
    Ok(())
}

fn parse_node_operators(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    let mut node = ProtoCursor::new(bytes);
    let mut operator = None;
    let mut domain = None;
    let mut attributes = Vec::new();
    while let Some(field) = node.next_field()? {
        match field.number {
            4 => operator = Some(field.string("NodeProto.op_type")?),
            5 => attributes.push(field.bytes("NodeProto.attribute")?),
            7 => domain = Some(field.string("NodeProto.domain")?),
            _ => {}
        }
    }
    let operator = operator
        .filter(|operator| !operator.is_empty())
        .ok_or_else(|| "ONNX NodeProto has no non-empty op_type".to_string())?;
    let key = domain
        .filter(|domain| !domain.is_empty())
        .map(|domain| format!("{domain}::{operator}"))
        .unwrap_or_else(|| operator.to_string());
    let count = inventory.entry(key).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| "ONNX operator count exceeds u64".to_string())?;
    for attribute in attributes {
        parse_attribute_operators(attribute, depth + 1, inventory)?;
    }
    Ok(())
}

fn parse_attribute_operators(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    let mut attribute = ProtoCursor::new(bytes);
    while let Some(field) = attribute.next_field()? {
        if field.number == 6 || field.number == 11 {
            parse_graph_operators(field.bytes("AttributeProto.graph")?, depth, inventory)?;
        }
    }
    Ok(())
}

fn parse_training_info_operators(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut training = ProtoCursor::new(bytes);
    while let Some(field) = training.next_field()? {
        if field.number == 1 || field.number == 2 {
            parse_graph_operators(
                field.bytes("TrainingInfoProto.graph")?,
                depth + 1,
                inventory,
            )?;
        }
    }
    Ok(())
}

fn parse_function_operators(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut function = ProtoCursor::new(bytes);
    while let Some(field) = function.next_field()? {
        match field.number {
            7 => parse_node_operators(field.bytes("FunctionProto.node")?, depth + 1, inventory)?,
            11 => parse_attribute_operators(
                field.bytes("FunctionProto.attribute_proto")?,
                depth + 1,
                inventory,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn frozen_external_data_inventory(bytes: &[u8]) -> Result<Vec<ExternalDataReference>, String> {
    let mut model = ProtoCursor::new(bytes);
    let mut graph_count = 0usize;
    let mut references = Vec::new();
    while let Some(field) = model.next_field()? {
        match field.number {
            7 => {
                graph_count = graph_count
                    .checked_add(1)
                    .ok_or_else(|| "ModelProto graph count exceeds usize".to_string())?;
                parse_graph_external_data(field.bytes("ModelProto.graph")?, 0, &mut references)?;
            }
            20 => parse_training_info_external_data(
                field.bytes("ModelProto.training_info")?,
                0,
                &mut references,
            )?,
            25 => parse_function_external_data(
                field.bytes("ModelProto.functions")?,
                0,
                &mut references,
            )?,
            _ => {}
        }
    }
    if graph_count != 1 {
        return Err(format!(
            "ModelProto contains {graph_count} graph fields; expected exactly one"
        ));
    }
    Ok(references)
}

fn parse_graph_external_data(
    bytes: &[u8],
    depth: usize,
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut graph = ProtoCursor::new(bytes);
    while let Some(field) = graph.next_field()? {
        match field.number {
            1 => parse_node_external_data(field.bytes("GraphProto.node")?, depth, references)?,
            5 => parse_tensor_external_data(field.bytes("GraphProto.initializer")?, references)?,
            15 => parse_sparse_tensor_external_data(
                field.bytes("GraphProto.sparse_initializer")?,
                references,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_node_external_data(
    bytes: &[u8],
    depth: usize,
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    let mut node = ProtoCursor::new(bytes);
    while let Some(field) = node.next_field()? {
        if field.number == 5 {
            parse_attribute_external_data(
                field.bytes("NodeProto.attribute")?,
                depth + 1,
                references,
            )?;
        }
    }
    Ok(())
}

fn parse_attribute_external_data(
    bytes: &[u8],
    depth: usize,
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut attribute = ProtoCursor::new(bytes);
    while let Some(field) = attribute.next_field()? {
        match field.number {
            5 | 10 => {
                parse_tensor_external_data(field.bytes("AttributeProto.tensor")?, references)?
            }
            6 | 11 => {
                parse_graph_external_data(field.bytes("AttributeProto.graph")?, depth, references)?
            }
            22 | 23 => parse_sparse_tensor_external_data(
                field.bytes("AttributeProto.sparse_tensor")?,
                references,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_sparse_tensor_external_data(
    bytes: &[u8],
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    let mut sparse = ProtoCursor::new(bytes);
    while let Some(field) = sparse.next_field()? {
        if field.number == 1 || field.number == 2 {
            parse_tensor_external_data(field.bytes("SparseTensorProto.tensor")?, references)?;
        }
    }
    Ok(())
}

fn parse_training_info_external_data(
    bytes: &[u8],
    depth: usize,
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut training = ProtoCursor::new(bytes);
    while let Some(field) = training.next_field()? {
        if field.number == 1 || field.number == 2 {
            parse_graph_external_data(
                field.bytes("TrainingInfoProto.graph")?,
                depth + 1,
                references,
            )?;
        }
    }
    Ok(())
}

fn parse_function_external_data(
    bytes: &[u8],
    depth: usize,
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    validate_proto_depth(depth)?;
    let mut function = ProtoCursor::new(bytes);
    while let Some(field) = function.next_field()? {
        match field.number {
            7 => {
                parse_node_external_data(field.bytes("FunctionProto.node")?, depth + 1, references)?
            }
            11 => parse_attribute_external_data(
                field.bytes("FunctionProto.attribute_proto")?,
                depth + 1,
                references,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_tensor_external_data(
    bytes: &[u8],
    references: &mut Vec<ExternalDataReference>,
) -> Result<(), String> {
    let mut tensor = ProtoCursor::new(bytes);
    let mut entries = BTreeMap::<String, String>::new();
    let mut data_location = 0u64;
    let mut data_location_seen = false;
    let mut inline_data_fields = BTreeSet::<u32>::new();
    while let Some(field) = tensor.next_field()? {
        match field.number {
            4 | 5 | 6 | 7 | 9 | 10 | 11 => {
                inline_data_fields.insert(field.number);
            }
            13 => {
                let (key, value) = parse_string_entry(field.bytes("TensorProto.external_data")?)?;
                if entries.insert(key.clone(), value).is_some() {
                    return Err(format!(
                        "TensorProto external_data contains duplicate key {key:?}"
                    ));
                }
            }
            14 => {
                if data_location_seen {
                    return Err("TensorProto contains duplicate data_location".to_string());
                }
                data_location_seen = true;
                data_location = field.varint("TensorProto.data_location")?;
            }
            _ => {}
        }
    }
    if data_location > 1 {
        return Err(format!(
            "TensorProto data_location {data_location} is not DEFAULT(0) or EXTERNAL(1)"
        ));
    }
    if entries.is_empty() && data_location == 0 {
        return Ok(());
    }
    if entries.is_empty() || data_location != 1 {
        return Err(
            "TensorProto external_data and EXTERNAL data_location are not both present".to_string(),
        );
    }
    if !inline_data_fields.is_empty() {
        return Err(format!(
            "external TensorProto also declares inline data field(s) {inline_data_fields:?}"
        ));
    }
    for key in entries.keys() {
        if !matches!(
            key.as_str(),
            "location" | "offset" | "length" | "checksum" | "basepath"
        ) {
            return Err(format!("unsupported TensorProto external_data key {key:?}"));
        }
    }
    if entries.contains_key("basepath") {
        return Err(
            "TensorProto external_data basepath is forbidden; location must be model-relative"
                .to_string(),
        );
    }
    let location = entries
        .remove("location")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "external TensorProto has no non-empty location".to_string())?;
    let offset = parse_external_u64(entries.remove("offset"), "offset")?.unwrap_or(0);
    let length = parse_external_u64(entries.remove("length"), "length")?;
    let checksum = entries
        .remove("checksum")
        .map(|checksum| {
            if checksum.len() != 40 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Err("external TensorProto checksum is not a 40-digit SHA1".to_string())
            } else {
                Ok(checksum.to_ascii_lowercase())
            }
        })
        .transpose()?;
    references.push(ExternalDataReference {
        location,
        offset,
        length,
        checksum,
    });
    Ok(())
}

fn parse_string_entry(bytes: &[u8]) -> Result<(String, String), String> {
    let mut entry = ProtoCursor::new(bytes);
    let mut key = None;
    let mut value = None;
    while let Some(field) = entry.next_field()? {
        match field.number {
            1 => key = Some(field.string("StringStringEntryProto.key")?.to_string()),
            2 => value = Some(field.string("StringStringEntryProto.value")?.to_string()),
            _ => {}
        }
    }
    let key = key
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(|| "external_data entry has no non-empty key".to_string())?;
    let value = value.ok_or_else(|| format!("external_data entry {key:?} has no value"))?;
    Ok((key, value))
}

fn parse_external_u64(raw: Option<String>, key: &str) -> Result<Option<u64>, String> {
    raw.map(|value| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!(
                "external_data {key} {value:?} is not an unsigned decimal integer"
            ));
        }
        value
            .parse::<u64>()
            .map_err(|error| format!("external_data {key} exceeds u64: {error}"))
    })
    .transpose()
}

fn validate_proto_depth(depth: usize) -> Result<(), String> {
    if depth > MAX_PROTO_RECURSION {
        Err(format!(
            "ONNX nested graph depth exceeds {MAX_PROTO_RECURSION}"
        ))
    } else {
        Ok(())
    }
}

struct ProtoField<'a> {
    number: u32,
    value: ProtoValue<'a>,
}

impl<'a> ProtoField<'a> {
    fn bytes(self, label: &str) -> Result<&'a [u8], String> {
        match self.value {
            ProtoValue::Bytes(bytes) => Ok(bytes),
            _ => Err(format!("{label} is not length-delimited")),
        }
    }

    fn string(self, label: &str) -> Result<&'a str, String> {
        std::str::from_utf8(self.bytes(label)?)
            .map_err(|error| format!("{label} is not UTF-8: {error}"))
    }

    fn varint(self, label: &str) -> Result<u64, String> {
        match self.value {
            ProtoValue::Varint(value) => Ok(value),
            _ => Err(format!("{label} is not a varint")),
        }
    }
}

enum ProtoValue<'a> {
    Varint(u64),
    Fixed,
    Bytes(&'a [u8]),
}

struct ProtoCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProtoCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next_field(&mut self) -> Result<Option<ProtoField<'a>>, String> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let number =
            u32::try_from(key >> 3).map_err(|_| "protobuf field number exceeds u32".to_string())?;
        if number == 0 {
            return Err("protobuf field number is zero".to_string());
        }
        let value = match key & 0x07 {
            0 => ProtoValue::Varint(self.varint()?),
            1 => {
                self.advance(8)?;
                ProtoValue::Fixed
            }
            2 => {
                let length = usize::try_from(self.varint()?)
                    .map_err(|_| "protobuf length exceeds usize".to_string())?;
                let start = self.offset;
                self.advance(length)?;
                ProtoValue::Bytes(&self.bytes[start..self.offset])
            }
            5 => {
                self.advance(4)?;
                ProtoValue::Fixed
            }
            wire => return Err(format!("unsupported protobuf wire type {wire}")),
        };
        Ok(Some(ProtoField { number, value }))
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| "truncated protobuf varint".to_string())?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err("protobuf varint exceeds u64".to_string());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("protobuf varint exceeds ten bytes".to_string())
    }

    fn advance(&mut self, length: usize) -> Result<(), String> {
        self.offset = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "protobuf field extends past end of input".to_string())?;
        Ok(())
    }
}
