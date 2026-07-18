#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CStr, OsStr, OsString, c_char};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HANDLE, HMODULE};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, GetFinalPathNameByHandleW,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    SetDefaultDllDirectories,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::OnnxRuntimePolicy;

const RUNTIME_ROOT_ENV: &str = "CALYX_CUDA13_RUNTIME_ROOT";
const LOCK_SCHEMA: &str = "astrolabe.windows-ort-cuda-runtime-lock.v3";
const RECEIPT_FILE: &str = "bundle.receipt.json";
const EXPECTED_LAYOUT: &str = "flat-bin-v1";
const EXPECTED_PLATFORM: &str = "windows-x86_64";
const EXPECTED_ROOT_PREFIX: &str = "ort-cuda13.3-windows-x86_64";
const EXPECTED_ORT_VERSION: &str = "1.27.1";
const EXPECTED_ORT_FILE_VERSION: &str = "1.27.20260709.2.df2ba1c";
const EXPECTED_PROVIDER: &str = "CUDAExecutionProvider";
const EXPECTED_ORT_DLL: &str = "onnxruntime.dll";
const EXPECTED_CUDA_PROVIDER_DLL: &str = "onnxruntime_providers_cuda.dll";
const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;
const MAX_FINAL_PATH_CHARS: usize = 32_768;
const LEGACY_RUNTIME_ENVS: &[&str] = &["ORT_DYLIB_PATH", "CALYX_ORT_CAPI", "CALYX_NVIDIA_DLL_DIRS"];
const REQUIRED_ARTIFACT_VERSIONS: &[(&str, &str)] = &[
    ("onnxruntime", "1.27.1"),
    ("cublas", "13.5.1.27"),
    ("cuda-nvrtc", "13.3.33"),
    ("cuda-runtime", "13.3.29"),
    ("cudnn", "9.24.0.43"),
    ("cufft", "12.3.0.29"),
    ("curand", "10.4.3.29"),
    ("nvjitlink", "13.3.33"),
];
const CONTRACT_REMEDIATION: &str =
    "restore the checked-in CUDA 13 runtime lock and rebuild Astrolabe from the canonical checkout";
const BUNDLE_REMEDIATION: &str = "run scripts\\windows-gnu-toolchain.ps1 -Issue 484 -Bootstrap from C:\\code\\Astrolabe, then start a new process without legacy ORT path variables";

const LOCK_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/toolchains/ort-cuda13.3-windows-x86_64.lock.json"
));

static RUNTIME_STATE: OnceLock<Mutex<RuntimeState>> = OnceLock::new();
static EXECUTION_DECISION: OnceLock<Mutex<ExecutionDecision>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxRuntimeContractAttestation {
    pub schema: String,
    pub lock_sha256: String,
    pub bundle_id: String,
    pub platform: String,
    pub layout: String,
    pub ort_version: String,
    pub ort_file_version: String,
    pub ort_api: u32,
    pub provider: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxLoadedModuleAttestation {
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub file_version: Option<String>,
    pub source: String,
    pub system_trust: Option<calyx_forge::cuda_runtime::SystemModuleTrustAttestation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxRuntimeArtifactAttestation {
    pub id: String,
    pub distribution: String,
    pub version: String,
    pub filename: String,
    pub url: String,
    pub bytes: u64,
    pub sha256: String,
    pub archive_verification: String,
    pub license_expression: String,
}

pub type OnnxCudaDeviceAttestation = calyx_forge::PinnedCudaDeviceAttestation;

/// Unforgeable process decision permitting separately commissioned CPU lenses.
///
/// This can only be created before CUDA execution is selected and only when
/// the exact pinned CUDA Runtime and exact system CUDA Driver independently
/// report no device. A CUDA provider, construction, or inference failure never
/// creates this authorization.
#[derive(Clone, Debug)]
pub struct OnnxCpuAuthorization {
    requested_runtime_ordinal: u32,
    decision_code: &'static str,
    _private: (),
}

impl OnnxCpuAuthorization {
    pub fn requested_runtime_ordinal(&self) -> u32 {
        self.requested_runtime_ordinal
    }

    pub fn decision_code(&self) -> &'static str {
        self.decision_code
    }
}

/// Stable Windows file identity read from the same handle as artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableFileIdentity {
    pub volume_serial_number: u32,
    pub file_index: u64,
}

/// Immutable one-handle snapshot used for exact ONNX/tokenizer commits.
#[derive(Clone, Debug)]
pub struct ImmutableFileSnapshot {
    pub final_path: PathBuf,
    pub identity: ImmutableFileIdentity,
    pub bytes: Vec<u8>,
}

/// Open directory identity retained while a frozen artifact set is read.
#[derive(Debug)]
pub struct ImmutableDirectoryRoot {
    handle: File,
    final_path: PathBuf,
    identity: ImmutableFileIdentity,
}

impl ImmutableDirectoryRoot {
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub fn identity(&self) -> ImmutableFileIdentity {
        self.identity
    }

    fn attest_unchanged(&self) -> Result<()> {
        let observed_path = final_path_from_handle(&self.handle)?;
        let observed_identity = immutable_file_identity(&self.handle)?;
        if !same_final_path(&observed_path, &self.final_path) || observed_identity != self.identity
        {
            return Err(runtime_error(
                "CALYX_ONNX_ARTIFACT_ROOT_CHANGED",
                format!(
                    "immutable artifact root changed: before path={} identity={:?}; after path={} identity={observed_identity:?}",
                    self.final_path.display(),
                    self.identity,
                    observed_path.display()
                ),
                "stop concurrent model-root replacement and retry in a new process",
            ));
        }
        Ok(())
    }
}

/// Retained physical-device-bound stream supplied to one CUDA ONNX session.
///
/// ORT receives the stable stream pointer during provider construction. Every
/// explicit access is serialized because CUDA green/primary context handles
/// do not provide an unconstrained `Sync` contract.
#[derive(Debug)]
pub struct OnnxCudaExecutionStream {
    inner: Mutex<calyx_forge::CudaPrimaryContextStream>,
    device: OnnxCudaDeviceAttestation,
}

#[derive(Clone, Debug)]
enum ExecutionDecision {
    Undecided,
    Cuda,
    CpuNoDevice(OnnxCpuAuthorization),
    Failed(CalyxError),
}

impl Default for ExecutionDecision {
    fn default() -> Self {
        Self::Undecided
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxRuntimeAttestation {
    pub schema: String,
    pub contract: OnnxRuntimeContractAttestation,
    pub bundle_root: PathBuf,
    pub bundle_receipt: PathBuf,
    pub bundle_receipt_sha256: String,
    pub provisioned_at_utc: String,
    pub ort_build_info: String,
    pub api_non_null: Vec<u32>,
    pub first_api_null: u32,
    pub available_providers: Vec<String>,
    pub provider_available: bool,
    pub artifacts: Vec<OnnxRuntimeArtifactAttestation>,
    pub validated_file_count: usize,
    pub validated_notice_count: usize,
    pub modules: Vec<OnnxLoadedModuleAttestation>,
    pub cuda_device: Option<OnnxCudaDeviceAttestation>,
}

pub fn expected_runtime_contract() -> Result<OnnxRuntimeContractAttestation> {
    let lock = parse_and_validate_embedded_lock()?;
    Ok(contract_attestation(&lock, &sha256_bytes(LOCK_BYTES)))
}

pub fn current_runtime_attestation() -> Result<Option<OnnxRuntimeAttestation>> {
    let Some(state) = RUNTIME_STATE.get() else {
        return Ok(None);
    };
    let mut state = state.lock().map_err(|_| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_STATE_POISONED",
            "the process-global ONNX runtime state mutex was poisoned while reading attestation",
            "terminate this process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    if let Some(error) = &state.core_failure {
        return Err(error.clone());
    }
    if let Some(error) = &state.cuda_failure {
        return Err(error.clone());
    }
    if state
        .live
        .as_ref()
        .is_some_and(|live| live.receipt.provider_available)
    {
        let refresh = refresh_cuda_module_attestation(
            state.live.as_mut().expect("checked above"),
            &sha256_bytes(LOCK_BYTES),
            true,
        );
        if let Err(error) = refresh {
            state.cuda_failure = Some(error.clone());
            return Err(error);
        }
    }
    Ok(state.live.as_ref().map(|live| live.receipt.clone()))
}

/// Makes the one process-wide learned-execution decision for a CPU-only host.
///
/// A usable GPU permanently selects CUDA. Only matching zero-device readbacks
/// from the exact pinned CUDA Runtime and exact system CUDA Driver can mint the
/// opaque CPU capability. Every other probe failure is terminal for this
/// process and is never converted to CPU work.
pub fn authorize_cpu_companion() -> Result<OnnxCpuAuthorization> {
    let state = EXECUTION_DECISION.get_or_init(|| Mutex::new(ExecutionDecision::default()));
    let mut decision = state.lock().map_err(|_| execution_decision_poisoned())?;
    match &*decision {
        ExecutionDecision::Cuda => return Err(cpu_execution_unauthorized()),
        ExecutionDecision::CpuNoDevice(authorization) => return Ok(authorization.clone()),
        ExecutionDecision::Failed(error) => return Err(error.clone()),
        ExecutionDecision::Undecided => {}
    }

    let requested = match calyx_forge::configured_cuda_runtime_ordinal() {
        Ok(requested) => requested,
        Err(error) => {
            let error = runtime_error(
                "CALYX_ONNX_EXECUTION_DECISION_FAILED",
                format!(
                    "resolve CALYX_CUDA_DEVICE for the startup execution decision failed: {error}"
                ),
                "repair the pinned CUDA Runtime/device-selection boundary and restart; do not construct a CPU lens from an ambiguous startup state",
            );
            *decision = ExecutionDecision::Failed(error.clone());
            return Err(error);
        }
    };
    match calyx_forge::select_pinned_cuda_device(requested) {
        Ok(device) => {
            tracing::info!(
                code = "CALYX_ONNX_EXECUTION_MODE_CUDA",
                runtime_ordinal = device.ordinal,
                execution_device = %device.frozen_execution_device(),
                "selected CUDA as the process-wide learned-execution mode"
            );
            *decision = ExecutionDecision::Cuda;
            Err(cpu_execution_unauthorized())
        }
        Err(error) if error.code() == calyx_forge::CUDA_NO_DEVICE_ATTESTED_CODE => {
            let authorization = OnnxCpuAuthorization {
                requested_runtime_ordinal: requested,
                decision_code: calyx_forge::CUDA_NO_DEVICE_ATTESTED_CODE,
                _private: (),
            };
            tracing::info!(
                code = authorization.decision_code,
                requested_runtime_ordinal = requested,
                "selected the separately commissioned CPU companion as the process-wide learned-execution mode"
            );
            *decision = ExecutionDecision::CpuNoDevice(authorization.clone());
            Ok(authorization)
        }
        Err(error) => {
            let error = runtime_error(
                "CALYX_ONNX_EXECUTION_DECISION_FAILED",
                format!(
                    "CUDA startup probe failed with {} while selecting learned execution: {error}",
                    error.code()
                ),
                "repair the CUDA provider/runtime/device failure and restart; never convert a CUDA failure into CPU execution",
            );
            *decision = ExecutionDecision::Failed(error.clone());
            Err(error)
        }
    }
}

/// Creates and retains one physical-identity-bound CUDA stream for an ONNX
/// session. The caller supplies this exact pointer to the CUDA EP and keeps the
/// returned owner alive for the entire session lifetime.
pub fn create_cuda_execution_stream(
    device: &OnnxCudaDeviceAttestation,
) -> Result<OnnxCudaExecutionStream> {
    claim_cuda_execution()?;
    let selected = selected_cuda_device(OnnxRuntimePolicy::CudaFailLoud, Some(device.ordinal))?
        .ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISSING",
                "CUDA stream construction has no selected physical-device receipt",
                "restart from the pinned CUDA runtime and preserve the device receipt",
            )
        })?;
    if !selected.same_stable_device(device) {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_STREAM_DEVICE_MISMATCH",
            format!(
                "requested stream device {} differs from process device {}",
                device.frozen_execution_device(),
                selected.frozen_execution_device()
            ),
            "terminate the process and restart with every ONNX session selecting one physical CUDA device",
        ));
    }
    let stream = calyx_forge::CudaPrimaryContextStream::create_by_pci_bus_id(
        &selected.cuda_runtime_pci_bus_id,
    )
    .map_err(forge_runtime_boundary_error)?;
    attest_cuda_stream(&stream, &selected)?;
    Ok(OnnxCudaExecutionStream {
        inner: Mutex::new(stream),
        device: selected,
    })
}

impl OnnxCudaExecutionStream {
    pub fn stream_ptr(&self) -> Result<*mut ()> {
        let stream = self.inner.lock().map_err(|_| cuda_stream_poisoned())?;
        attest_cuda_stream(&stream, &self.device)?;
        Ok(stream.stream_ptr())
    }

    pub fn synchronize_and_attest(&self) -> Result<()> {
        let stream = self.inner.lock().map_err(|_| cuda_stream_poisoned())?;
        stream.synchronize().map_err(forge_runtime_boundary_error)?;
        attest_cuda_stream(&stream, &self.device)
    }

    pub fn device(&self) -> &OnnxCudaDeviceAttestation {
        &self.device
    }
}

/// Opens one artifact once, proves the handle-resolved target is a confined
/// regular file, then reads exactly that handle into memory.
///
/// `required_root` retains the directory handle for the whole artifact batch.
/// Containment is checked before size-based allocation or byte reads. Root and
/// file path, identity, and length are re-read after the snapshot to detect
/// replacement or mutation.
pub fn snapshot_immutable_file(
    path: &Path,
    required_root: Option<&ImmutableDirectoryRoot>,
    maximum_bytes: u64,
) -> Result<ImmutableFileSnapshot> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_ARTIFACT_OPEN_FAILED",
                format!(
                    "open immutable artifact {} with read-only sharing failed: {error}",
                    path.display()
                ),
                "restore a readable regular artifact inside its frozen root and retry in a new process",
            )
        })?;
    let final_path = final_path_from_handle(&file)?;
    if let Some(root) = required_root {
        root.attest_unchanged()?;
        if !final_path_is_within(&final_path, root.final_path()) {
            return Err(runtime_error(
                "CALYX_ONNX_ARTIFACT_PATH_ESCAPE",
                format!(
                    "opened artifact {} resolves to {} outside frozen root {}",
                    path.display(),
                    final_path.display(),
                    root.final_path().display()
                ),
                "place every ONNX external-data artifact under the model's immutable directory and remove junction/reparse escapes",
            ));
        }
    }
    let metadata = file.metadata().map_err(|error| {
        runtime_error(
            "CALYX_ONNX_ARTIFACT_METADATA_FAILED",
            format!(
                "read metadata from opened artifact {} failed: {error}",
                final_path.display()
            ),
            "restore a readable regular artifact and retry in a new process",
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0
    {
        return Err(runtime_error(
            "CALYX_ONNX_ARTIFACT_NOT_REGULAR",
            format!(
                "opened artifact {} is not a regular non-reparse file",
                final_path.display()
            ),
            "replace the artifact with a regular file under the frozen model root",
        ));
    }
    let expected_bytes = metadata.len();
    if expected_bytes > maximum_bytes {
        return Err(runtime_error(
            "CALYX_ONNX_ARTIFACT_SIZE_LIMIT",
            format!(
                "artifact {} has {expected_bytes} bytes, exceeding its {maximum_bytes}-byte frozen read budget",
                final_path.display()
            ),
            "commission an artifact within the measured RAM/VRAM budget or raise the explicit budget before process startup",
        ));
    }
    let identity = immutable_file_identity(&file)?;
    let byte_len = usize::try_from(expected_bytes).map_err(|_| {
        runtime_error(
            "CALYX_ONNX_ARTIFACT_SIZE_OVERFLOW",
            format!(
                "artifact {} length {expected_bytes} exceeds process address space",
                final_path.display()
            ),
            "commission a smaller artifact that fits the native process address space",
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(byte_len).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_ARTIFACT_ALLOCATION_FAILED",
            format!(
                "reserve {byte_len} bytes for immutable artifact {} failed: {error}",
                final_path.display()
            ),
            "free host RAM or commission a smaller artifact; the model was not partially committed",
        )
    })?;
    bytes.resize(byte_len, 0);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let count = file
            .seek_read(&mut bytes[offset..], offset as u64)
            .map_err(|error| {
                runtime_error(
                    "CALYX_ONNX_ARTIFACT_READ_FAILED",
                    format!(
                        "read immutable artifact {} at offset {offset} failed: {error}",
                        final_path.display()
                    ),
                    "restore the frozen artifact and retry in a new process",
                )
            })?;
        if count == 0 {
            return Err(runtime_error(
                "CALYX_ONNX_ARTIFACT_CHANGED",
                format!(
                    "artifact {} ended at {offset} bytes after its handle reported {expected_bytes}",
                    final_path.display()
                ),
                "stop concurrent artifact mutation and retry from an immutable model directory",
            ));
        }
        offset = offset.checked_add(count).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_ARTIFACT_SIZE_OVERFLOW",
                "immutable artifact read offset overflowed usize",
                "commission a smaller artifact that fits the native process address space",
            )
        })?;
    }
    let mut extra = [0u8; 1];
    if file
        .seek_read(&mut extra, expected_bytes)
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_ARTIFACT_READ_FAILED",
                format!(
                    "read immutable artifact {} terminal byte failed: {error}",
                    final_path.display()
                ),
                "restore the frozen artifact and retry in a new process",
            )
        })?
        != 0
    {
        return Err(runtime_error(
            "CALYX_ONNX_ARTIFACT_CHANGED",
            format!(
                "artifact {} grew while it was being snapshotted",
                final_path.display()
            ),
            "stop concurrent artifact mutation and retry from an immutable model directory",
        ));
    }
    let final_path_after = final_path_from_handle(&file)?;
    let identity_after = immutable_file_identity(&file)?;
    let bytes_after = file
        .metadata()
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_ARTIFACT_METADATA_FAILED",
                format!(
                    "re-read metadata from {} failed: {error}",
                    final_path.display()
                ),
                "restore the frozen artifact and retry in a new process",
            )
        })?
        .len();
    if !same_final_path(&final_path_after, &final_path)
        || identity_after != identity
        || bytes_after != expected_bytes
    {
        return Err(runtime_error(
            "CALYX_ONNX_ARTIFACT_CHANGED",
            format!(
                "artifact changed during snapshot: before path={} identity={identity:?} bytes={expected_bytes}; after path={} identity={identity_after:?} bytes={bytes_after}",
                final_path.display(),
                final_path_after.display()
            ),
            "stop concurrent artifact mutation and retry from an immutable model directory",
        ));
    }
    if let Some(root) = required_root {
        root.attest_unchanged()?;
    }
    Ok(ImmutableFileSnapshot {
        final_path,
        identity,
        bytes,
    })
}

/// Resolves one existing directory through an open handle for later
/// containment checks by [`snapshot_immutable_file`].
pub fn open_immutable_directory(path: &Path) -> Result<ImmutableDirectoryRoot> {
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_ARTIFACT_ROOT_OPEN_FAILED",
                format!("open immutable artifact root {} failed: {error}", path.display()),
                "restore the model/profile root as an accessible directory and retry in a new process",
            )
        })?;
    let metadata = directory.metadata().map_err(|error| {
        runtime_error(
            "CALYX_ONNX_ARTIFACT_ROOT_METADATA_FAILED",
            format!(
                "read artifact-root metadata {} failed: {error}",
                path.display()
            ),
            "restore the model/profile root as an accessible directory and retry in a new process",
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(runtime_error(
            "CALYX_ONNX_ARTIFACT_ROOT_NOT_DIRECTORY",
            format!("artifact root {} is not a directory", path.display()),
            "select the directory containing the frozen artifacts",
        ));
    }
    let final_path = final_path_from_handle(&directory)?;
    let identity = immutable_file_identity(&directory)?;
    Ok(ImmutableDirectoryRoot {
        handle: directory,
        final_path,
        identity,
    })
}

/// Returns live available physical host memory for an artifact snapshot budget.
pub fn available_host_memory_bytes() -> Result<u64> {
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(last_windows_error(
            "GlobalMemoryStatusEx for immutable artifact budget",
        ));
    }
    if status.ullAvailPhys == 0 {
        return Err(runtime_error(
            "CALYX_ONNX_ARTIFACT_HOST_MEMORY_UNAVAILABLE",
            "Windows reports zero available physical memory for immutable artifact snapshots",
            "free host RAM before loading a learned lens",
        ));
    }
    Ok(status.ullAvailPhys)
}

/// Establishes the process-wide, hash-attested CUDA DLL search boundary.
///
/// This initializes only the pinned ORT core and exact DLL directory. CUDA
/// provider and device initialization remain deferred until a CUDA policy is
/// selected, so an explicitly commissioned CPU runtime can still start on a
/// machine without a usable GPU. CUDA-enabled process entry points call this
/// before any `cudarc`, Candle, FastEmbed, or ORT API can resolve a DLL.
pub fn initialize_pinned_cuda_runtime_boundary() -> Result<OnnxRuntimeAttestation> {
    ensure_core_runtime()?;
    current_runtime_attestation()?.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_ATTESTATION_MISSING",
            "pinned CUDA runtime boundary initialized without a live attestation",
            "terminate the process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })
}

pub fn ensure_runtime(
    policy: OnnxRuntimePolicy,
    requested_cuda_device: Option<u32>,
) -> Result<PathBuf> {
    match policy {
        OnnxRuntimePolicy::CudaFailLoud => claim_cuda_execution()?,
        OnnxRuntimePolicy::CpuExplicit => require_cpu_execution_decision()?,
    }
    let core_path = ensure_core_runtime()?;
    if policy != OnnxRuntimePolicy::CudaFailLoud {
        return Ok(core_path);
    }

    let state = RUNTIME_STATE.get_or_init(|| Mutex::new(RuntimeState::default()));
    let mut state = state.lock().map_err(|_| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_STATE_POISONED",
            "the process-global ONNX runtime state mutex was poisoned",
            "terminate this process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    if let Some(error) = &state.cuda_failure {
        return Err(error.clone());
    }
    let requested_cuda_device = match requested_cuda_device {
        Some(device) => device,
        None => {
            let error = runtime_error(
                "CALYX_ONNX_CUDA_DEVICE_MISSING",
                "CUDA ORT initialization did not provide an attested CUDA Runtime ordinal",
                "resolve the process-global CUDA Runtime ordinal before constructing a CUDA ORT session",
            );
            state.cuda_failure = Some(error.clone());
            return Err(error);
        }
    };
    let live = state.live.as_mut().expect("core initialized above");
    if live.receipt.cuda_device.is_none() {
        if let Err(error) = initialize_cuda(live, requested_cuda_device) {
            state.cuda_failure = Some(error.clone());
            return Err(error);
        }
    } else if live
        .receipt
        .cuda_device
        .as_ref()
        .is_none_or(|device| device.ordinal != requested_cuda_device)
    {
        let error = runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_SELECTION_CHANGED",
            format!(
                "process-global ORT is already pinned to CUDA Runtime ordinal {}, later request selected ordinal {requested_cuda_device}",
                live.receipt.cuda_device.as_ref().map_or_else(
                    || "unattested".to_string(),
                    |device| device.ordinal.to_string()
                )
            ),
            "terminate the process and restart with every ORT consumer selecting one physical CUDA device",
        );
        state.cuda_failure = Some(error.clone());
        return Err(error);
    }
    Ok(core_path)
}

fn ensure_core_runtime() -> Result<PathBuf> {
    let state = RUNTIME_STATE.get_or_init(|| Mutex::new(RuntimeState::default()));
    let mut state = state.lock().map_err(|_| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_STATE_POISONED",
            "the process-global ONNX runtime state mutex was poisoned",
            "terminate this process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    if let Some(error) = &state.core_failure {
        return Err(error.clone());
    }
    if state.live.is_none() {
        match initialize_core() {
            Ok(live) => state.live = Some(live),
            Err(error) => {
                state.core_failure = Some(error.clone());
                return Err(error);
            }
        }
    }
    Ok(state
        .live
        .as_ref()
        .expect("initialized above")
        .core_path
        .clone())
}

fn claim_cuda_execution() -> Result<()> {
    let state = EXECUTION_DECISION.get_or_init(|| Mutex::new(ExecutionDecision::default()));
    let mut decision = state.lock().map_err(|_| execution_decision_poisoned())?;
    match &*decision {
        ExecutionDecision::Undecided => {
            tracing::info!(
                code = "CALYX_ONNX_EXECUTION_MODE_CUDA",
                "selected CUDA as the process-wide learned-execution mode"
            );
            *decision = ExecutionDecision::Cuda;
            Ok(())
        }
        ExecutionDecision::Cuda => Ok(()),
        ExecutionDecision::CpuNoDevice(_) => Err(runtime_error(
            "CALYX_ONNX_CUDA_AFTER_CPU_DECISION",
            "CUDA execution was requested after startup selected the CPU-only companion",
            "terminate the process and restart after restoring GPU visibility; never change learned-execution mode in place",
        )),
        ExecutionDecision::Failed(error) => Err(error.clone()),
    }
}

fn require_cpu_execution_decision() -> Result<()> {
    let state = EXECUTION_DECISION.get_or_init(|| Mutex::new(ExecutionDecision::default()));
    let decision = state.lock().map_err(|_| execution_decision_poisoned())?;
    match &*decision {
        ExecutionDecision::CpuNoDevice(_) => Ok(()),
        ExecutionDecision::Cuda | ExecutionDecision::Undecided => Err(cpu_execution_unauthorized()),
        ExecutionDecision::Failed(error) => Err(error.clone()),
    }
}

fn attest_cuda_stream(
    stream: &calyx_forge::CudaPrimaryContextStream,
    device: &OnnxCudaDeviceAttestation,
) -> Result<()> {
    if stream.driver_ordinal() != device.cuda_driver_ordinal
        || stream.physical_identity() != device.identity
    {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_STREAM_DEVICE_MISMATCH",
            format!(
                "retained stream reports driver_ordinal={} identity={}; runtime receipt records driver_ordinal={} identity={}",
                stream.driver_ordinal(),
                stream.physical_identity(),
                device.cuda_driver_ordinal,
                device.identity
            ),
            "terminate the process, preserve both receipts, and repair the CUDA Runtime/Driver mapping",
        ));
    }
    stream
        .attest_identity()
        .map_err(forge_runtime_boundary_error)?;
    let observed = calyx_forge::attest_pinned_cuda_driver_identity(device.identity)
        .map_err(forge_runtime_boundary_error)?;
    if observed != device.cuda_driver_ordinal {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_STREAM_DEVICE_MISMATCH",
            format!(
                "independent CUDA Driver readback resolved {} to ordinal {observed}; receipt records {}",
                device.identity, device.cuda_driver_ordinal
            ),
            "terminate the process, preserve both receipts, and repair the CUDA Runtime/Driver mapping",
        ));
    }
    Ok(())
}

fn execution_decision_poisoned() -> CalyxError {
    runtime_error(
        "CALYX_ONNX_EXECUTION_DECISION_POISONED",
        "the process-global learned-execution decision mutex was poisoned",
        "terminate this process, preserve its logs, and restart before constructing any learned lens",
    )
}

fn cpu_execution_unauthorized() -> CalyxError {
    runtime_error(
        "CALYX_ONNX_CPU_COMPANION_UNAUTHORIZED",
        "the separately commissioned CPU companion is not authorized because startup did not prove matching zero-device results from the exact CUDA Runtime and Driver",
        "use the CUDA lens on a GPU host; CPU execution is permitted only when authorize_cpu_companion obtains dual Runtime/Driver no-device evidence before any CUDA path",
    )
}

fn cuda_stream_poisoned() -> CalyxError {
    runtime_error(
        "CALYX_ONNX_CUDA_STREAM_STATE_POISONED",
        "the retained CUDA execution-stream mutex was poisoned",
        "terminate the owning worker process, preserve its logs, and reload the frozen panel in a new generation",
    )
}

pub fn selected_cuda_device(
    policy: OnnxRuntimePolicy,
    requested_cuda_device: Option<u32>,
) -> Result<Option<OnnxCudaDeviceAttestation>> {
    if policy != OnnxRuntimePolicy::CudaFailLoud {
        require_cpu_execution_decision()?;
        return Ok(None);
    }
    ensure_runtime(policy, requested_cuda_device)?;
    let requested = requested_cuda_device.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_MISSING",
            "CUDA device selection did not provide a CUDA Runtime ordinal",
            "resolve the process-global CUDA Runtime ordinal before constructing a CUDA ORT session",
        )
    })?;
    let shared =
        calyx_forge::select_pinned_cuda_device(requested).map_err(forge_runtime_boundary_error)?;
    let attestation = current_runtime_attestation()?.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_ATTESTATION_MISSING",
            "CUDA device selection has no process-global runtime attestation",
            "terminate the process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    let device = attestation.cuda_device.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISSING",
            "CUDA policy is active but the runtime attestation has no selected device",
            "terminate the process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    if !shared.same_stable_device(&device) {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISMATCH",
            format!(
                "ONNX receipt device {} differs from Forge process-global device {}",
                device.frozen_execution_device(),
                shared.frozen_execution_device()
            ),
            "terminate the process, preserve both attestations, and repair the shared CUDA device boundary",
        ));
    }
    Ok(Some(device))
}

#[derive(Default)]
struct RuntimeState {
    live: Option<LiveRuntime>,
    core_failure: Option<CalyxError>,
    cuda_failure: Option<CalyxError>,
}

struct LiveRuntime {
    lock: RuntimeLock,
    core_path: PathBuf,
    _module_handles: ModuleStack,
    receipt: OnnxRuntimeAttestation,
}

struct OwnedModule(usize);

struct CommittedApiModuleGuard(Option<OwnedModule>);

struct ModuleStack(Vec<OwnedModule>);

impl ModuleStack {
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn push(&mut self, module: OwnedModule) {
        self.0.push(module);
    }
}

impl Drop for ModuleStack {
    fn drop(&mut self) {
        while self.0.pop().is_some() {}
    }
}

impl OwnedModule {
    fn raw(&self) -> HMODULE {
        self.0 as HMODULE
    }
}

impl CommittedApiModuleGuard {
    fn new(module: OwnedModule) -> Self {
        Self(Some(module))
    }

    fn into_owned(mut self) -> OwnedModule {
        self.0.take().expect("committed API module is present")
    }
}

impl Drop for CommittedApiModuleGuard {
    fn drop(&mut self) {
        if let Some(module) = self.0.take() {
            // Once ort::set_api succeeds, the process-global table points into
            // this DLL even if a later initialization/attestation step fails.
            // Keep it mapped until worker exit so a structured error cannot
            // leave dangling function pointers in a still-running process.
            mem::forget(module);
        }
    }
}

impl Drop for OwnedModule {
    fn drop(&mut self) {
        if self.0 == 0 {
            return;
        }
        let handle = std::mem::replace(&mut self.0, 0) as HMODULE;
        if unsafe { FreeLibrary(handle) } == 0 {
            let windows_error = unsafe { GetLastError() };
            tracing::error!(
                code = "CALYX_ONNX_RUNTIME_MODULE_CLEANUP_FAILED",
                windows_error,
                "FreeLibrary failed while releasing a registry-owned runtime module"
            );
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLock {
    schema: String,
    bundle: BundleContract,
    contract: OrtContract,
    artifacts: Vec<ArtifactContract>,
    files: Vec<FileContract>,
    notices: Vec<NoticeContract>,
    loaded_module_policy: LoadedModulePolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleContract {
    id: String,
    platform: String,
    layout: String,
    root_prefix: String,
    root_from: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrtContract {
    ort_version: String,
    ort_file_version: String,
    ort_api: u32,
    api_non_null: Vec<u32>,
    first_api_null: u32,
    provider: String,
    ort_dll: String,
    provider_dll: String,
    direct_non_system_imports: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactContract {
    id: String,
    distribution: String,
    version: String,
    filename: String,
    url: String,
    bytes: u64,
    sha256: String,
    archive_verification: String,
    record: Option<String>,
    metadata: Option<String>,
    license_expression: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileContract {
    artifact: String,
    archive_path: String,
    bundle_path: String,
    bytes: u64,
    sha256: String,
    file_version: Option<String>,
    authenticode: AuthenticodeContract,
    role: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticodeContract {
    status: String,
    subject: String,
    thumbprint: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeContract {
    artifact: String,
    archive_path: String,
    bundle_path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadedModulePolicy {
    boundary_load: Vec<String>,
    dependency_preload_order: Vec<String>,
    ort_managed_load: Vec<String>,
    bundle_module_globs: Vec<String>,
    system_modules: Vec<SystemModulePolicy>,
    system_roots: Vec<String>,
    reject_application_dir: bool,
    reject_path_search: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemModulePolicy {
    name: String,
    required_root: String,
    signature_kind: String,
    signer_organization: String,
    signed_company_name: String,
}

fn initialize_core() -> Result<LiveRuntime> {
    reject_legacy_environment()?;
    let lock = parse_and_validate_embedded_lock()?;
    let lock_sha256 = sha256_bytes(LOCK_BYTES);
    let (root, bundle_receipt_sha256, provisioned_at_utc) = {
        let boundary = calyx_forge::cuda_runtime::initialize_pinned_cuda_runtime_boundary()
            .map_err(forge_runtime_boundary_error)?;
        validate_forge_boundary(&boundary, &lock, &lock_sha256, false)?;
        (
            boundary.bundle_root,
            boundary.bundle_receipt_sha256,
            boundary.provisioned_at_utc,
        )
    };
    reject_ambient_managed_modules(&lock, &root, &enumerate_process_modules()?)?;
    configure_process_dll_search()?;
    let core_path = locked_dll_path(&lock, &root, &lock.contract.ort_dll)?;
    let core_handle = load_exact_library(&core_path)?;
    let api = preflight_ort_api(core_handle.raw(), &lock.contract)?;
    let build_info = ort_build_info(api)?;
    let available_providers = available_providers(api)?;
    if !available_providers
        .iter()
        .any(|provider| provider == &lock.contract.provider)
    {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_PROVIDER_UNAVAILABLE",
            format!(
                "pinned ORT provider inventory {:?} omits {}",
                available_providers, lock.contract.provider
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let api_committed = ort::set_api(unsafe { (*api).clone() });
    if !api_committed {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_API_PREINITIALIZED",
            format!(
                "the ort crate API table was initialized before Calyx could install the exact API24 table from {}",
                core_path.display()
            ),
            "terminate the process and ensure every ONNX consumer enters through calyx-onnx-runtime before any ort API or alternative-backend registration",
        ));
    }
    let core_handle = CommittedApiModuleGuard::new(core_handle);
    let committed = ort::init().commit();
    if !committed {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_PREINITIALIZED",
            "ORT global environment was configured before Calyx could commit the exact installed API24 backend",
            "terminate the process and ensure every ONNX consumer calls the Calyx runtime boundary before any ort API",
        ));
    }
    let modules = attest_loaded_modules(&lock, &root)?;
    let mut module_handles = ModuleStack::with_capacity(2);
    module_handles.push(core_handle.into_owned());
    Ok(LiveRuntime {
        lock: lock.clone(),
        core_path,
        _module_handles: module_handles,
        receipt: OnnxRuntimeAttestation {
            schema: "calyx-onnx-runtime-attestation-v4".to_string(),
            contract: contract_attestation(&lock, &lock_sha256),
            bundle_root: root.clone(),
            bundle_receipt: root.join(RECEIPT_FILE),
            bundle_receipt_sha256,
            provisioned_at_utc,
            ort_build_info: build_info,
            api_non_null: lock.contract.api_non_null.clone(),
            first_api_null: lock.contract.first_api_null,
            available_providers,
            provider_available: false,
            artifacts: artifact_attestations(&lock),
            validated_file_count: lock.files.len(),
            validated_notice_count: lock.notices.len(),
            modules,
            cuda_device: None,
        },
    })
}

fn initialize_cuda(live: &mut LiveRuntime, requested: u32) -> Result<()> {
    let lock_sha256 = sha256_bytes(LOCK_BYTES);
    let boundary = calyx_forge::cuda_runtime::initialize_pinned_cuda_dependencies()
        .map_err(forge_runtime_boundary_error)?;
    validate_forge_boundary(&boundary, &live.lock, &lock_sha256, true)?;
    let device =
        calyx_forge::select_pinned_cuda_device(requested).map_err(forge_runtime_boundary_error)?;
    let observed_driver_ordinal = calyx_forge::attest_pinned_cuda_driver_identity(device.identity)
        .map_err(forge_runtime_boundary_error)?;
    if observed_driver_ordinal != device.cuda_driver_ordinal {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISMATCH",
            format!(
                "Forge selected runtime_ordinal={} driver_ordinal={} identity={}; independent exact-nvcuda PCI+UUID readback resolved driver_ordinal={observed_driver_ordinal}",
                device.ordinal,
                device.cuda_driver_ordinal,
                device.frozen_execution_device()
            ),
            "terminate the process, preserve the device receipt, and repair the CUDA Runtime/Driver/NVML identity boundary",
        ));
    }
    refresh_cuda_module_attestation(live, &lock_sha256, false)?;
    live.receipt.cuda_device = Some(device);
    Ok(())
}

fn refresh_cuda_module_attestation(
    live: &mut LiveRuntime,
    lock_sha256: &str,
    require_provider: bool,
) -> Result<()> {
    let boundary = calyx_forge::cuda_runtime::attest_pinned_cuda_dependencies()
        .map_err(forge_runtime_boundary_error)?;
    validate_forge_boundary(&boundary, &live.lock, lock_sha256, true)?;
    let mut modules = boundary
        .modules
        .into_iter()
        .map(|module| OnnxLoadedModuleAttestation {
            name: module.name,
            path: module.path,
            bytes: module.bytes,
            sha256: module.sha256,
            file_version: module.file_version,
            source: module.source,
            system_trust: module.system_trust,
        })
        .collect::<Vec<_>>();
    if require_provider {
        modules.extend(attest_ort_managed_modules(
            &live.lock,
            &live.receipt.bundle_root,
        )?);
    }
    modules.sort_by(|left, right| left.name.cmp(&right.name));
    live.receipt.modules = modules;
    Ok(())
}

/// Promotes provider residency only after a real ORT model/session constructor
/// has returned successfully. The caller must invoke this immediately after
/// construction; inventory queries and locked bytes never count as execution.
pub fn attest_cuda_provider_after_session() -> Result<()> {
    let state = RUNTIME_STATE.get_or_init(|| Mutex::new(RuntimeState::default()));
    let mut state = state.lock().map_err(|_| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_STATE_POISONED",
            "the process-global ONNX runtime state mutex was poisoned during provider attestation",
            "terminate this process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    if let Some(error) = &state.cuda_failure {
        return Err(error.clone());
    }
    let Some(live) = state.live.as_mut() else {
        let error = runtime_error(
            "CALYX_ONNX_RUNTIME_NOT_INITIALIZED",
            "a model constructor returned before the pinned ONNX runtime was initialized",
            "construct every ONNX model through the Calyx runtime boundary",
        );
        state.cuda_failure = Some(error.clone());
        return Err(error);
    };
    if live.receipt.cuda_device.is_none() {
        let error = runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISSING",
            "a CUDA model constructor returned without an attested physical-device receipt",
            "terminate the process and reconstruct the model through the pinned CUDA device boundary",
        );
        state.cuda_failure = Some(error.clone());
        return Err(error);
    }
    let lock_sha256 = sha256_bytes(LOCK_BYTES);
    if let Err(error) = refresh_cuda_module_attestation(live, &lock_sha256, true) {
        state.cuda_failure = Some(error.clone());
        return Err(error);
    }
    live.receipt.provider_available = true;
    Ok(())
}

fn forge_runtime_boundary_error(error: calyx_forge::ForgeError) -> CalyxError {
    match error {
        calyx_forge::ForgeError::RuntimeBoundary {
            code,
            detail,
            remediation,
        } => CalyxError {
            code,
            message: detail,
            remediation,
        },
        other => runtime_error(
            "CALYX_ONNX_RUNTIME_BOUNDARY_FAILED",
            other.to_string(),
            "inspect the Forge CUDA runtime boundary failure and repair the pinned runtime before retrying",
        ),
    }
}

fn validate_forge_boundary(
    boundary: &calyx_forge::cuda_runtime::PinnedCudaRuntimeAttestation,
    lock: &RuntimeLock,
    lock_sha256: &str,
    require_cuda: bool,
) -> Result<()> {
    require_contract(
        boundary.schema == "calyx-pinned-cuda-runtime-attestation-v3",
        "Forge runtime attestation schema mismatch",
    )?;
    require_contract(
        boundary.lock_sha256 == lock_sha256,
        "Forge runtime lock digest mismatch",
    )?;
    require_contract(
        boundary.bundle_id == lock.bundle.id,
        "Forge runtime bundle id mismatch",
    )?;
    require_contract(
        boundary.validated_file_count == lock.files.len()
            && boundary.validated_notice_count == lock.notices.len(),
        "Forge runtime validated-count mismatch",
    )?;
    require_contract(
        !boundary.provisioned_at_utc.trim().is_empty()
            && boundary.bundle_receipt_sha256.len() == 64,
        "Forge runtime receipt provenance is incomplete",
    )?;

    let expected_root = resolve_and_validate_root(lock, lock_sha256)?;
    let observed_root = canonicalize_existing_dir(&boundary.bundle_root, "Forge bundle root")?;
    require_contract(
        same_path(&observed_root, &expected_root),
        "Forge runtime root differs from the registry runtime root",
    )?;
    let expected_receipt =
        canonicalize_existing_file(&expected_root.join(RECEIPT_FILE), "bundle receipt")?;
    let observed_receipt =
        canonicalize_existing_file(&boundary.bundle_receipt, "Forge bundle receipt")?;
    require_contract(
        same_path(&observed_receipt, &expected_receipt),
        "Forge runtime receipt path mismatch",
    )?;

    let locked = expected_dlls(lock, &expected_root)?;
    let scheduled = lock.loaded_module_policy.boundary_load.iter().chain(
        require_cuda
            .then_some(lock.loaded_module_policy.dependency_preload_order.iter())
            .into_iter()
            .flatten(),
    );
    let mut expected_names = scheduled
        .map(|path| bundle_basename(path).map(|name| name.to_ascii_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
    if require_cuda {
        expected_names.insert("nvcuda.dll".to_string());
        expected_names.insert("nvml.dll".to_string());
    }
    let observed = boundary
        .modules
        .iter()
        .map(|module| (module.name.to_ascii_lowercase(), module))
        .collect::<BTreeMap<_, _>>();
    require_contract(
        observed.len() == boundary.modules.len(),
        "Forge runtime attestation contains duplicate module names",
    )?;
    require_contract(
        observed.keys().cloned().collect::<BTreeSet<_>>() == expected_names,
        "Forge runtime module set differs from the locked module set",
    )?;
    let expected_ort_managed = lock
        .loaded_module_policy
        .ort_managed_load
        .iter()
        .map(|path| bundle_basename(path).map(|name| name.to_ascii_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
    let observed_ort_managed = boundary
        .ort_managed_modules
        .iter()
        .map(|module| (module.name.to_ascii_lowercase(), module))
        .collect::<BTreeMap<_, _>>();
    require_contract(
        observed_ort_managed.len() == boundary.ort_managed_modules.len()
            && observed_ort_managed
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected_ort_managed,
        "Forge ORT-managed module contract differs from the lock",
    )?;
    for (name, module) in observed_ort_managed {
        let file = locked.get(&name).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                format!("Forge ORT-managed module {name} is absent from the lock"),
                CONTRACT_REMEDIATION,
            )
        })?;
        let expected_path = canonicalize_existing_file(
            &expected_root.join(windows_relative_path(&file.bundle_path)?),
            "locked ORT-managed module",
        )?;
        let observed_path = canonicalize_existing_file(&module.path, "Forge ORT-managed module")?;
        require_contract(
            same_path(&observed_path, &expected_path)
                && module.bytes == file.bytes
                && module.sha256 == file.sha256
                && module.file_version == file.file_version
                && module.source == format!("bundle:{}", file.artifact)
                && module.loader == "onnxruntime-provider-api"
                && module.state == "validated-not-directly-mapped",
            &format!("Forge ORT-managed module attestation is invalid for {name}"),
        )?;
    }
    reject_reparse_entry(&boundary.system_module_root, "Forge OS system-module root")?;
    let system32 =
        canonicalize_existing_dir(&boundary.system_module_root, "Forge OS system-module root")?;
    reject_reparse_entry(&system32, "canonical Forge OS system-module root")?;
    for (name, module) in observed {
        let observed_path = canonicalize_existing_file(&module.path, "Forge loaded module")?;
        if let Some(file) = locked.get(&name) {
            let expected_path = canonicalize_existing_file(
                &expected_root.join(windows_relative_path(&file.bundle_path)?),
                "locked managed module",
            )?;
            require_contract(
                same_path(&observed_path, &expected_path)
                    && module.bytes == file.bytes
                    && module.sha256 == file.sha256
                    && module.file_version == file.file_version
                    && module.system_trust.is_none(),
                &format!("Forge attestation differs from lock for {name}"),
            )?;
        } else {
            let expected_path =
                canonicalize_existing_file(&system32.join(&name), "NVIDIA system module")?;
            let policy = lock
                .loaded_module_policy
                .system_modules
                .iter()
                .find(|policy| policy.name.eq_ignore_ascii_case(&name))
                .ok_or_else(|| {
                    runtime_error(
                        "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                        format!("system module {name} has no trust policy"),
                        CONTRACT_REMEDIATION,
                    )
                })?;
            let trust = module.system_trust.as_ref().ok_or_else(|| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_SYSTEM_TRUST_MISSING",
                    format!("Forge supplied no catalog trust proof for {name}"),
                    BUNDLE_REMEDIATION,
                )
            })?;
            require_contract(
                same_path(&observed_path, &expected_path)
                    && module.bytes > 0
                    && module.sha256.len() == 64
                    && trust.schema == "calyx-system-module-trust-v1"
                    && trust.module_name.eq_ignore_ascii_case(&name)
                    && same_path(&trust.module_path, &expected_path)
                    && trust.file_bytes == module.bytes
                    && trust.file_sha256 == module.sha256
                    && trust.signature_kind == "windows-catalog-authenticode"
                    && trust.winverifytrust_status == 0
                    && trust.signer_organization == policy.signer_organization
                    && !trust.signer_certificate_sha256.is_empty()
                    && trust.signed_company_name == policy.signed_company_name
                    && module.file_version.as_deref() == Some(trust.signed_file_version.as_str())
                    && !trust.signed_file_version.trim().is_empty()
                    && !trust.signed_product_name.trim().is_empty()
                    && !trust.version_translations.is_empty(),
                &format!("Forge system-module attestation is invalid for {name}"),
            )?;
        }
    }
    Ok(())
}

fn parse_and_validate_embedded_lock() -> Result<RuntimeLock> {
    let lock: RuntimeLock = serde_json::from_slice(LOCK_BYTES).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
            format!("parse embedded CUDA runtime lock failed: {error}"),
            CONTRACT_REMEDIATION,
        )
    })?;
    validate_lock_contract(&lock)?;
    Ok(lock)
}

fn validate_lock_contract(lock: &RuntimeLock) -> Result<()> {
    require_contract(lock.schema == LOCK_SCHEMA, "unexpected lock schema")?;
    require_contract(
        lock.bundle.platform == EXPECTED_PLATFORM,
        "unexpected bundle platform",
    )?;
    require_contract(
        lock.bundle.layout == EXPECTED_LAYOUT,
        "unexpected bundle layout",
    )?;
    require_contract(
        lock.bundle.root_prefix == EXPECTED_ROOT_PREFIX,
        "unexpected bundle root_prefix",
    )?;
    require_contract(!lock.bundle.id.trim().is_empty(), "bundle id is empty")?;
    require_contract(
        !lock.bundle.root_prefix.trim().is_empty(),
        "bundle root_prefix is empty",
    )?;
    require_contract(
        lock.bundle
            .root_from
            .eq_ignore_ascii_case("sha256(lock_file_bytes)"),
        "bundle root_from must be sha256(lock_file_bytes)",
    )?;
    require_contract(
        lock.contract.ort_version == EXPECTED_ORT_VERSION,
        "unexpected ORT version",
    )?;
    require_contract(
        lock.contract.ort_file_version == EXPECTED_ORT_FILE_VERSION,
        "unexpected ORT file version",
    )?;
    require_contract(
        lock.contract.ort_api == ort::sys::ORT_API_VERSION && lock.contract.ort_api == 24,
        "ORT API does not match the linked ort api-24 contract",
    )?;
    require_contract(
        lock.contract.provider == EXPECTED_PROVIDER,
        "unexpected execution provider",
    )?;
    require_contract(
        basename_eq(&lock.contract.ort_dll, EXPECTED_ORT_DLL),
        "unexpected ORT DLL",
    )?;
    require_contract(
        basename_eq(&lock.contract.provider_dll, EXPECTED_CUDA_PROVIDER_DLL),
        "unexpected CUDA provider DLL",
    )?;
    require_contract(
        lock.contract.api_non_null == [24, 25, 26, 27],
        "unexpected api_non_null contract",
    )?;
    require_contract(
        lock.contract.first_api_null == 28,
        "unexpected first_api_null contract",
    )?;
    require_contract(
        lock.loaded_module_policy.reject_application_dir
            && lock.loaded_module_policy.reject_path_search,
        "loaded-module policy must reject application-directory and PATH search",
    )?;
    let system_modules = lock
        .loaded_module_policy
        .system_modules
        .iter()
        .map(|module| (module.name.to_ascii_lowercase(), module))
        .collect::<BTreeMap<_, _>>();
    require_contract(
        system_modules.len() == lock.loaded_module_policy.system_modules.len()
            && system_modules.len() == 2
            && system_modules.contains_key("nvcuda.dll")
            && system_modules.contains_key("nvml.dll"),
        "system module identity/cardinality mismatch",
    )?;
    for module in system_modules.values() {
        require_contract(
            module
                .required_root
                .eq_ignore_ascii_case("%SystemRoot%\\System32")
                && module.signature_kind == "catalog"
                && module.signer_organization == "Microsoft Corporation"
                && module.signed_company_name == "NVIDIA Corporation",
            "system module trust policy differs from the Windows NVIDIA driver contract",
        )?;
    }
    require_contract(
        !lock.loaded_module_policy.system_roots.is_empty(),
        "system_roots is empty",
    )?;
    require_contract(
        lock.loaded_module_policy.system_roots.len() == 1
            && lock.loaded_module_policy.system_roots[0]
                .eq_ignore_ascii_case("%SystemRoot%\\System32"),
        "system_roots must exactly identify System32",
    )?;
    require_contract(
        !lock.loaded_module_policy.bundle_module_globs.is_empty(),
        "bundle_module_globs is empty",
    )?;

    let artifact_ids: BTreeSet<&str> = lock
        .artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect();
    require_contract(
        artifact_ids.len() == lock.artifacts.len(),
        "artifact ids are not unique",
    )?;
    require_contract(
        lock.artifacts.len() == REQUIRED_ARTIFACT_VERSIONS.len(),
        "artifact set cardinality does not match the pinned CUDA closure",
    )?;
    for (id, version) in REQUIRED_ARTIFACT_VERSIONS {
        require_contract(
            lock.artifacts
                .iter()
                .any(|artifact| artifact.id == *id && artifact.version == *version),
            &format!("pinned artifact {id} {version} is missing"),
        )?;
    }
    for artifact in &lock.artifacts {
        require_contract(
            !artifact.distribution.trim().is_empty(),
            "artifact distribution is empty",
        )?;
        require_contract(
            !artifact.version.trim().is_empty(),
            "artifact version is empty",
        )?;
        require_contract(
            !artifact.filename.trim().is_empty(),
            "artifact filename is empty",
        )?;
        require_contract(!artifact.url.trim().is_empty(), "artifact URL is empty")?;
        require_contract(artifact.bytes > 0, "artifact byte count is zero")?;
        require_sha256(&artifact.sha256, "artifact")?;
        require_contract(
            !artifact.license_expression.trim().is_empty(),
            "artifact license is empty",
        )?;
        require_contract(
            match artifact.archive_verification.as_str() {
                "wheel-record-sha256" => {
                    artifact
                        .record
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                        && artifact
                            .metadata
                            .as_deref()
                            .is_some_and(|value| !value.trim().is_empty())
                }
                "release-archive-sha256" => {
                    artifact.record.is_none() && artifact.metadata.is_none()
                }
                _ => false,
            },
            "artifact archive-verification contract is invalid",
        )?;
    }
    let mut paths = BTreeSet::new();
    let mut dll_names = BTreeSet::new();
    for file in &lock.files {
        require_contract(
            artifact_ids.contains(file.artifact.as_str()),
            "file references unknown artifact",
        )?;
        validate_relative_bundle_path(&file.bundle_path, true)?;
        require_contract(
            paths.insert(file.bundle_path.to_ascii_lowercase()),
            "duplicate bundle path",
        )?;
        require_contract(file.bytes > 0, "bundle file byte count is zero")?;
        require_sha256(&file.sha256, "bundle file")?;
        require_contract(
            !file.archive_path.trim().is_empty(),
            "bundle file archive_path is empty",
        )?;
        require_contract(!file.role.trim().is_empty(), "bundle file role is empty")?;
        require_contract(
            file.authenticode.status.eq_ignore_ascii_case("valid"),
            "bundle PE signature is not valid",
        )?;
        require_contract(
            !file.authenticode.subject.trim().is_empty(),
            "bundle PE signer subject is empty",
        )?;
        require_contract(
            !file.authenticode.thumbprint.trim().is_empty(),
            "bundle PE signer thumbprint is empty",
        )?;
        if file.bundle_path.to_ascii_lowercase().ends_with(".dll") {
            let name = bundle_basename(&file.bundle_path)?;
            require_contract(
                dll_names.insert(name.to_ascii_lowercase()),
                "duplicate managed DLL basename",
            )?;
        }
    }
    let boundary = lock
        .loaded_module_policy
        .boundary_load
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let preload = lock
        .loaded_module_policy
        .dependency_preload_order
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let ort_managed = lock
        .loaded_module_policy
        .ort_managed_load
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    require_contract(
        boundary.len() == lock.loaded_module_policy.boundary_load.len()
            && preload.len() == lock.loaded_module_policy.dependency_preload_order.len()
            && ort_managed.len() == lock.loaded_module_policy.ort_managed_load.len(),
        "module load phase contains duplicate paths",
    )?;
    require_contract(
        boundary.is_disjoint(&preload)
            && boundary.is_disjoint(&ort_managed)
            && preload.is_disjoint(&ort_managed),
        "module load phases overlap",
    )?;
    let mut scheduled = boundary.clone();
    scheduled.extend(preload.iter().cloned());
    scheduled.extend(ort_managed.iter().cloned());
    require_contract(
        scheduled
            == lock
                .files
                .iter()
                .map(|file| file.bundle_path.to_ascii_lowercase())
                .collect(),
        "module load phases must name every locked DLL exactly once",
    )?;
    require_contract(
        boundary == BTreeSet::from([lock.contract.ort_dll.to_ascii_lowercase()]),
        "boundary load must contain only the ORT core",
    )?;
    require_contract(
        ort_managed == BTreeSet::from([lock.contract.provider_dll.to_ascii_lowercase()]),
        "ORT-managed load must contain only the CUDA provider",
    )?;
    for path in lock
        .loaded_module_policy
        .boundary_load
        .iter()
        .chain(&lock.loaded_module_policy.dependency_preload_order)
        .chain(&lock.loaded_module_policy.ort_managed_load)
    {
        validate_relative_bundle_path(path, true)?;
    }
    for notice in &lock.notices {
        require_contract(
            artifact_ids.contains(notice.artifact.as_str()),
            "notice references unknown artifact",
        )?;
        validate_relative_bundle_path(&notice.bundle_path, false)?;
        require_contract(
            paths.insert(notice.bundle_path.to_ascii_lowercase()),
            "duplicate bundle/notice path",
        )?;
        require_contract(notice.bytes > 0, "notice byte count is zero")?;
        require_sha256(&notice.sha256, "notice")?;
        require_contract(
            !notice.archive_path.trim().is_empty(),
            "notice archive_path is empty",
        )?;
    }
    for required in [&lock.contract.ort_dll, &lock.contract.provider_dll] {
        let required = bundle_basename(required)?;
        require_contract(
            dll_names.contains(&required.to_ascii_lowercase()),
            "required ORT DLL missing from files",
        )?;
    }
    for import in &lock.contract.direct_non_system_imports {
        require_contract(
            dll_names.contains(&import.to_ascii_lowercase()),
            "direct provider import missing from files",
        )?;
    }
    Ok(())
}

fn resolve_and_validate_root(lock: &RuntimeLock, lock_sha256: &str) -> Result<PathBuf> {
    let raw = env::var_os(RUNTIME_ROOT_ENV).ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_ROOT_MISSING",
            format!("{RUNTIME_ROOT_ENV} is not set"),
            BUNDLE_REMEDIATION,
        )
    })?;
    if raw.is_empty() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_ROOT_MISSING",
            format!("{RUNTIME_ROOT_ENV} is empty"),
            BUNDLE_REMEDIATION,
        ));
    }
    let raw_root = Path::new(&raw);
    reject_reparse_entry(raw_root, "CUDA runtime root")?;
    let root = canonicalize_existing_dir(raw_root, "CUDA runtime root")?;
    let expected_name = format!(
        "{}-{lock_sha256}",
        lock.bundle.root_prefix.trim_end_matches('-')
    );
    let actual_name = root.file_name().and_then(OsStr::to_str).unwrap_or_default();
    if !actual_name.eq_ignore_ascii_case(&expected_name) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_ROOT_IDENTITY_MISMATCH",
            format!(
                "{RUNTIME_ROOT_ENV} resolved to {}; expected immutable root basename {expected_name}",
                root.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let parent_name = root
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if !parent_name.eq_ignore_ascii_case(".toolchains") {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_ROOT_UNOWNED",
            format!(
                "runtime root {} is not directly under an owned .toolchains directory",
                root.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let app_dir = current_application_dir()?;
    if same_path(&root, &app_dir) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_APPLICATION_DIR_REFUSED",
            format!(
                "runtime root {} is the application directory",
                root.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(root)
}

fn verify_locked_file(
    root: &Path,
    relative: &str,
    expected_bytes: u64,
    expected_hash: &str,
) -> Result<()> {
    let path = root.join(windows_relative_path(relative)?);
    let canonical = canonicalize_existing_file(&path, "locked runtime file")?;
    if !path_is_within(&canonical, root) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_PATH_ESCAPE",
            format!(
                "locked path {relative} canonicalized outside {} to {}",
                root.display(),
                canonical.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let metadata = fs::metadata(&canonical).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
            format!("stat {} failed: {error}", canonical.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    if metadata.len() != expected_bytes {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_SIZE_MISMATCH",
            format!(
                "{} has {} bytes; lock requires {expected_bytes}",
                canonical.display(),
                metadata.len()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let actual = sha256_file(&canonical)?;
    if !actual.eq_ignore_ascii_case(expected_hash) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_HASH_MISMATCH",
            format!(
                "{} SHA256 is {actual}; lock requires {expected_hash}",
                canonical.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(())
}

fn reject_legacy_environment() -> Result<()> {
    for name in LEGACY_RUNTIME_ENVS {
        if let Some(value) = env::var_os(name) {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_LEGACY_PATH_REFUSED",
                format!(
                    "legacy {name}={} is set; only {RUNTIME_ROOT_ENV} may select the locked runtime",
                    PathBuf::from(value).display()
                ),
                "remove ORT_DYLIB_PATH, CALYX_ORT_CAPI, and CALYX_NVIDIA_DLL_DIRS; provision and select the immutable CUDA 13 bundle instead",
            ));
        }
    }
    Ok(())
}

fn configure_process_dll_search() -> Result<()> {
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(last_windows_error(
            "SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)",
        ));
    }
    Ok(())
}

fn load_exact_library(path: &Path) -> Result<OwnedModule> {
    let wide = wide_path(path);
    let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), flags) };
    if module.is_null() {
        return Err(last_windows_error(format!(
            "LoadLibraryExW exact {}",
            path.display()
        )));
    }
    Ok(OwnedModule(module as usize))
}

fn preflight_ort_api(module: HMODULE, contract: &OrtContract) -> Result<*const ort::sys::OrtApi> {
    let proc =
        unsafe { GetProcAddress(module, c"OrtGetApiBase".as_ptr().cast()) }.ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_API_EXPORT_MISSING",
                "exact onnxruntime.dll does not export OrtGetApiBase",
                BUNDLE_REMEDIATION,
            )
        })?;
    let get_api_base: unsafe extern "system" fn() -> *const ort::sys::OrtApiBase =
        unsafe { mem::transmute(proc) };
    let base = unsafe { get_api_base() };
    if base.is_null() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_API_BASE_NULL",
            "OrtGetApiBase returned null",
            BUNDLE_REMEDIATION,
        ));
    }
    let version_ptr = unsafe { ((*base).GetVersionString)() };
    if version_ptr.is_null() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_VERSION_NULL",
            "ORT GetVersionString returned null",
            BUNDLE_REMEDIATION,
        ));
    }
    let version = unsafe { CStr::from_ptr(version_ptr) }
        .to_str()
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_VERSION_INVALID",
                format!("ORT version string is not UTF-8: {error}"),
                BUNDLE_REMEDIATION,
            )
        })?;
    if version != contract.ort_version {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_VERSION_MISMATCH",
            format!(
                "loaded ORT reports {version}; lock requires {}",
                contract.ort_version
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let mut selected = ptr::null();
    for api in &contract.api_non_null {
        let value = unsafe { ((*base).GetApi)(*api) };
        if value.is_null() {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_API_MISMATCH",
                format!("ORT GetApi({api}) returned null but the lock requires non-null"),
                BUNDLE_REMEDIATION,
            ));
        }
        if *api == contract.ort_api {
            selected = value;
        }
    }
    if !unsafe { ((*base).GetApi)(contract.first_api_null) }.is_null() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_API_CEILING_MISMATCH",
            format!(
                "ORT GetApi({}) is non-null but the lock requires the first null API",
                contract.first_api_null
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    if selected.is_null() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_API_MISMATCH",
            format!("lock did not yield selected API {}", contract.ort_api),
            CONTRACT_REMEDIATION,
        ));
    }
    Ok(selected)
}

fn ort_build_info(api: *const ort::sys::OrtApi) -> Result<String> {
    let ptr = unsafe { ((*api).GetBuildInfoString)() };
    if ptr.is_null() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_BUILD_INFO_NULL",
            "ORT GetBuildInfoString returned null",
            BUNDLE_REMEDIATION,
        ));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_BUILD_INFO_INVALID",
                format!("ORT build-info string is not UTF-8: {error}"),
                BUNDLE_REMEDIATION,
            )
        })
}

fn available_providers(api: *const ort::sys::OrtApi) -> Result<Vec<String>> {
    let mut providers: *mut *mut c_char = ptr::null_mut();
    let mut count = 0i32;
    let status = unsafe { ((*api).GetAvailableProviders)(&mut providers, &mut count) };
    ensure_ort_status_ok(api, status, "GetAvailableProviders")?;
    if providers.is_null() || count <= 0 {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_PROVIDER_INVENTORY_EMPTY",
            format!("ORT GetAvailableProviders returned pointer={providers:p} count={count}"),
            BUNDLE_REMEDIATION,
        ));
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut parse_error = None;
    for index in 0..count {
        let value = unsafe { *providers.offset(index as isize) };
        if value.is_null() {
            parse_error = Some(runtime_error(
                "CALYX_ONNX_RUNTIME_PROVIDER_INVENTORY_INVALID",
                format!("ORT provider inventory entry {index} is null"),
                BUNDLE_REMEDIATION,
            ));
            break;
        }
        match unsafe { CStr::from_ptr(value) }.to_str() {
            Ok(provider) => out.push(provider.to_string()),
            Err(error) => {
                parse_error = Some(runtime_error(
                    "CALYX_ONNX_RUNTIME_PROVIDER_INVENTORY_INVALID",
                    format!("ORT provider inventory entry {index} is not UTF-8: {error}"),
                    BUNDLE_REMEDIATION,
                ));
                break;
            }
        }
    }
    let release = unsafe { ((*api).ReleaseAvailableProviders)(providers, count) };
    ensure_ort_status_ok(api, release, "ReleaseAvailableProviders")?;
    if let Some(error) = parse_error {
        return Err(error);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn ensure_ort_status_ok(
    api: *const ort::sys::OrtApi,
    status: ort::sys::OrtStatusPtr,
    operation: &str,
) -> Result<()> {
    if status.0.is_null() {
        return Ok(());
    }
    let message_ptr = unsafe { ((*api).GetErrorMessage)(status.0) };
    let message = if message_ptr.is_null() {
        "ORT returned a status with a null error message".to_string()
    } else {
        unsafe { CStr::from_ptr(message_ptr) }
            .to_string_lossy()
            .into_owned()
    };
    unsafe { ((*api).ReleaseStatus)(status.0) };
    Err(runtime_error(
        "CALYX_ONNX_RUNTIME_API_CALL_FAILED",
        format!("ORT {operation} failed: {message}"),
        BUNDLE_REMEDIATION,
    ))
}

fn reject_ambient_managed_modules(
    lock: &RuntimeLock,
    root: &Path,
    modules: &[PathBuf],
) -> Result<()> {
    let expected = expected_dlls(lock, root)?;
    let app_dir = current_application_dir()?;
    for module in modules {
        let Some(name) = module.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        let key = name.to_ascii_lowercase();
        let managed_like = expected.contains_key(&key)
            || lock
                .loaded_module_policy
                .bundle_module_globs
                .iter()
                .any(|pattern| wildcard_matches(pattern, name));
        if !managed_like {
            continue;
        }
        let canonical = canonicalize_existing_file(module, "loaded managed-like module")?;
        let Some(file) = expected.get(&key) else {
            return Err(ambient_module_error(
                name,
                &canonical,
                "module name matches the locked managed namespace but is absent from the lock",
            ));
        };
        let required = canonicalize_existing_file(
            &root.join(windows_relative_path(&file.bundle_path)?),
            "locked managed module",
        )?;
        if !same_path(&canonical, &required) {
            return Err(ambient_module_error(
                name,
                &canonical,
                &format!("required exact path is {}", required.display()),
            ));
        }
        if lock.loaded_module_policy.reject_application_dir && path_is_within(&canonical, &app_dir)
        {
            return Err(ambient_module_error(
                name,
                &canonical,
                "application-directory loading is forbidden",
            ));
        }
        verify_locked_file(root, &file.bundle_path, file.bytes, &file.sha256)?;
    }
    Ok(())
}

fn attest_loaded_modules(
    lock: &RuntimeLock,
    root: &Path,
) -> Result<Vec<OnnxLoadedModuleAttestation>> {
    let modules = enumerate_process_modules()?;
    reject_ambient_managed_modules(lock, root, &modules)?;
    let expected = expected_dlls(lock, root)?;
    let mut loaded = BTreeMap::new();
    for path in modules {
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        let name = name.to_string();
        let key = name.to_ascii_lowercase();
        if expected.contains_key(&key) {
            if loaded.insert(key, path).is_some() {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_DUPLICATE_MODULE",
                    format!("process loaded duplicate managed module basename {name}"),
                    BUNDLE_REMEDIATION,
                ));
            }
        }
    }
    let mut out = Vec::new();
    for (key, file) in expected {
        let core = basename_eq(&key, &lock.contract.ort_dll);
        if !core {
            continue;
        }
        let path = loaded.get(&key).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_MODULE_NOT_LOADED",
                format!("locked managed module {key} is not present in the process module table"),
                BUNDLE_REMEDIATION,
            )
        })?;
        out.push(OnnxLoadedModuleAttestation {
            name: key,
            path: canonicalize_existing_file(path, "loaded managed module")?,
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            file_version: file.file_version.clone(),
            source: format!("bundle:{}", file.artifact),
            system_trust: None,
        });
    }
    out.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(out)
}

fn attest_ort_managed_modules(
    lock: &RuntimeLock,
    root: &Path,
) -> Result<Vec<OnnxLoadedModuleAttestation>> {
    let process_modules = enumerate_process_modules()?;
    reject_ambient_managed_modules(lock, root, &process_modules)?;
    let locked = expected_dlls(lock, root)?;
    let required = lock
        .loaded_module_policy
        .ort_managed_load
        .iter()
        .map(|path| bundle_basename(path).map(|name| name.to_ascii_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut loaded = BTreeMap::new();
    for path in process_modules {
        let Some(name) = path.file_name().and_then(OsStr::to_str).map(str::to_owned) else {
            continue;
        };
        let key = name.to_ascii_lowercase();
        if required.contains(&key) && loaded.insert(key.clone(), path).is_some() {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_DUPLICATE_MODULE",
                format!("process loaded duplicate ORT-managed module basename {name}"),
                BUNDLE_REMEDIATION,
            ));
        }
    }
    let mut out = Vec::with_capacity(required.len());
    for name in required {
        let file = locked.get(&name).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                format!("ORT-managed module {name} is absent from the lock"),
                CONTRACT_REMEDIATION,
            )
        })?;
        let observed = loaded.get(&name).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_CUDA_PROVIDER_NOT_RESIDENT",
                format!(
                    "a CUDA model constructor returned successfully but ORT-managed module {name} is absent from the process module table"
                ),
                "terminate the process, preserve the constructor logs, and repair the provider/session construction path; do not report CUDA availability",
            )
        })?;
        let observed = canonicalize_existing_file(observed, "loaded ORT-managed module")?;
        let expected = canonicalize_existing_file(
            &root.join(windows_relative_path(&file.bundle_path)?),
            "locked ORT-managed module",
        )?;
        if !same_path(&observed, &expected) {
            return Err(ambient_module_error(
                &name,
                &observed,
                &format!("required exact ORT-managed path is {}", expected.display()),
            ));
        }
        verify_locked_file(root, &file.bundle_path, file.bytes, &file.sha256)?;
        out.push(OnnxLoadedModuleAttestation {
            name,
            path: observed,
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            file_version: file.file_version.clone(),
            source: format!("bundle:{};loader=onnxruntime-provider-api", file.artifact),
            system_trust: None,
        });
    }
    out.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(out)
}

fn enumerate_process_modules() -> Result<Vec<PathBuf>> {
    let process = unsafe { GetCurrentProcess() };
    let mut capacity = 256usize;
    loop {
        let mut modules: Vec<HMODULE> = vec![ptr::null_mut(); capacity];
        let mut needed = 0u32;
        let bytes = u32::try_from(modules.len().saturating_mul(mem::size_of::<HMODULE>()))
            .map_err(|_| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_MODULE_ENUM_OVERFLOW",
                    "process module enumeration buffer exceeds u32",
                    "terminate the process and preserve its module inventory for investigation",
                )
            })?;
        if unsafe { K32EnumProcessModules(process, modules.as_mut_ptr(), bytes, &mut needed) } == 0
        {
            return Err(last_windows_error("K32EnumProcessModules"));
        }
        let count = needed as usize / mem::size_of::<HMODULE>();
        if count > capacity {
            capacity = count.saturating_add(64);
            continue;
        }
        modules.truncate(count);
        let mut out = Vec::with_capacity(count);
        for module in modules {
            let mut path_capacity = 512usize;
            loop {
                let mut path = vec![0u16; path_capacity];
                let len = unsafe {
                    K32GetModuleFileNameExW(process, module, path.as_mut_ptr(), path.len() as u32)
                } as usize;
                if len == 0 {
                    return Err(last_windows_error("K32GetModuleFileNameExW"));
                }
                if len + 1 < path.len() {
                    path.truncate(len);
                    out.push(PathBuf::from(String::from_utf16_lossy(&path)));
                    break;
                }
                path_capacity = path_capacity.checked_mul(2).ok_or_else(|| {
                    runtime_error(
                        "CALYX_ONNX_RUNTIME_MODULE_PATH_OVERFLOW",
                        "loaded module path buffer overflowed",
                        "terminate the process and preserve its module inventory for investigation",
                    )
                })?;
            }
        }
        return Ok(out);
    }
}

fn expected_dlls<'a>(
    lock: &'a RuntimeLock,
    _root: &Path,
) -> Result<BTreeMap<String, &'a FileContract>> {
    let mut out = BTreeMap::new();
    for file in &lock.files {
        if file.bundle_path.to_ascii_lowercase().ends_with(".dll") {
            out.insert(
                bundle_basename(&file.bundle_path)?.to_ascii_lowercase(),
                file,
            );
        }
    }
    Ok(out)
}

fn locked_dll_path(lock: &RuntimeLock, root: &Path, basename: &str) -> Result<PathBuf> {
    let file = lock
        .files
        .iter()
        .find(|file| basename_eq(&file.bundle_path, basename))
        .ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                format!("lock does not contain managed DLL {basename}"),
                CONTRACT_REMEDIATION,
            )
        })?;
    canonicalize_existing_file(
        &root.join(windows_relative_path(&file.bundle_path)?),
        "locked DLL",
    )
}

fn contract_attestation(lock: &RuntimeLock, lock_sha256: &str) -> OnnxRuntimeContractAttestation {
    OnnxRuntimeContractAttestation {
        schema: lock.schema.clone(),
        lock_sha256: lock_sha256.to_string(),
        bundle_id: lock.bundle.id.clone(),
        platform: lock.bundle.platform.clone(),
        layout: lock.bundle.layout.clone(),
        ort_version: lock.contract.ort_version.clone(),
        ort_file_version: lock.contract.ort_file_version.clone(),
        ort_api: lock.contract.ort_api,
        provider: lock.contract.provider.clone(),
    }
}

fn artifact_attestations(lock: &RuntimeLock) -> Vec<OnnxRuntimeArtifactAttestation> {
    lock.artifacts
        .iter()
        .map(|artifact| OnnxRuntimeArtifactAttestation {
            id: artifact.id.clone(),
            distribution: artifact.distribution.clone(),
            version: artifact.version.clone(),
            filename: artifact.filename.clone(),
            url: artifact.url.clone(),
            bytes: artifact.bytes,
            sha256: artifact.sha256.clone(),
            archive_verification: artifact.archive_verification.clone(),
            license_expression: artifact.license_expression.clone(),
        })
        .collect()
}

fn validate_relative_bundle_path(raw: &str, require_bin: bool) -> Result<()> {
    let path = windows_relative_path(raw)?;
    if require_bin && path.components().next() != Some(Component::Normal(OsStr::new("bin"))) {
        return Err(contract_error(format!(
            "managed file {raw} is not under flat bin/"
        )));
    }
    Ok(())
}

fn windows_relative_path(raw: &str) -> Result<PathBuf> {
    if raw.trim().is_empty() || raw.contains('\\') || raw.starts_with('/') {
        return Err(contract_error(format!(
            "bundle path {raw:?} is not a canonical forward-slash relative path"
        )));
    }
    let path = PathBuf::from(raw.replace('/', "\\"));
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(contract_error(format!(
            "bundle path {raw:?} contains a root or traversal component"
        )));
    }
    Ok(path)
}

fn bundle_basename(raw: &str) -> Result<&str> {
    raw.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| contract_error(format!("bundle path {raw:?} has no basename")))
}

fn basename_eq(raw: &str, expected: &str) -> bool {
    let actual = raw.rsplit(['/', '\\']).next();
    let expected = expected.rsplit(['/', '\\']).next();
    actual
        .zip(expected)
        .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let parts: Vec<_> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    let mut offset = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(found) = value[offset..].find(part) else {
            return false;
        };
        if index == 0 && !pattern.starts_with('*') && found != 0 {
            return false;
        }
        offset += found + part.len();
    }
    pattern.ends_with('*') || parts.last().is_some_and(|part| value.ends_with(part))
}

fn canonicalize_existing_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_MISSING",
            format!("canonicalize {label} {} failed: {error}", path.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    if !canonical.is_file() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_MISSING",
            format!("{label} {} is not a file", canonical.display()),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(canonical)
}

fn reject_reparse_entry(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_PATH_UNREADABLE",
            format!(
                "read {label} metadata for {} failed: {error}",
                path.display()
            ),
            BUNDLE_REMEDIATION,
        )
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_REPARSE_ENTRY",
            format!("{label} {} is a reparse point", path.display()),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(())
}

fn canonicalize_existing_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_DIRECTORY_MISSING",
            format!("canonicalize {label} {} failed: {error}", path.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    if !canonical.is_dir() {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_DIRECTORY_MISSING",
            format!("{label} {} is not a directory", canonical.display()),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(canonical)
}

fn current_application_dir() -> Result<PathBuf> {
    let executable = env::current_exe().map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_APPLICATION_IDENTITY_UNAVAILABLE",
            format!("resolve current executable failed: {error}"),
            "restart from the canonical Astrolabe launcher and preserve the process environment for investigation",
        )
    })?;
    let directory = executable.parent().ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_APPLICATION_IDENTITY_UNAVAILABLE",
            format!(
                "current executable {} has no parent directory",
                executable.display()
            ),
            "restart from the canonical Astrolabe launcher and preserve the process environment for investigation",
        )
    })?;
    canonicalize_existing_dir(directory, "application directory")
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let root = root
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    path == root || path.starts_with(&(root + "\\"))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
            format!("open {} for SHA256 failed: {error}", path.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
                format!("read {} for SHA256 failed: {error}", path.display()),
                BUNDLE_REMEDIATION,
            )
        })?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    require_contract(
        value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && value == value.to_ascii_lowercase(),
        &format!("{label} SHA256 is not 64 lowercase hexadecimal characters"),
    )
}

fn require_contract(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(contract_error(message.to_string()))
    }
}

fn contract_error(message: String) -> CalyxError {
    runtime_error(
        "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
        message,
        CONTRACT_REMEDIATION,
    )
}

fn ambient_module_error(name: &str, path: &Path, detail: &str) -> CalyxError {
    runtime_error(
        "CALYX_ONNX_RUNTIME_AMBIENT_MODULE",
        format!(
            "refusing already-loaded managed-like module {name} at {}: {detail}",
            path.display()
        ),
        "terminate this process, remove ambient/System32/application ORT or NVIDIA runtime copies, and restart with only CALYX_CUDA13_RUNTIME_ROOT",
    )
}

fn last_windows_error(context: impl Into<String>) -> CalyxError {
    runtime_error(
        "CALYX_ONNX_RUNTIME_WINDOWS_LOAD_FAILED",
        format!("{} failed with Windows error {}", context.into(), unsafe {
            GetLastError()
        }),
        BUNDLE_REMEDIATION,
    )
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

fn final_path_from_handle(file: &File) -> Result<PathBuf> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut capacity = 512usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        } as usize;
        if written == 0 {
            return Err(last_windows_error(
                "GetFinalPathNameByHandleW for immutable artifact",
            ));
        }
        if written < buffer.len() {
            buffer.truncate(written);
            if buffer.is_empty() || buffer.contains(&0) {
                return Err(runtime_error(
                    "CALYX_ONNX_ARTIFACT_FINAL_PATH_INVALID",
                    "opened immutable artifact has an empty final path or interior NUL",
                    "restore the artifact as a regular file under its frozen root",
                ));
            }
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity = written.checked_add(1).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_ARTIFACT_FINAL_PATH_OVERFLOW",
                "opened immutable artifact final-path length overflowed usize",
                "move the artifact to a shorter canonical path",
            )
        })?;
        if capacity > MAX_FINAL_PATH_CHARS {
            return Err(runtime_error(
                "CALYX_ONNX_ARTIFACT_FINAL_PATH_OVERFLOW",
                format!("opened immutable artifact final path requires {capacity} UTF-16 units"),
                "move the artifact to a shorter canonical path",
            ));
        }
    }
}

fn immutable_file_identity(file: &File) -> Result<ImmutableFileIdentity> {
    let mut information = unsafe { mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) } == 0
    {
        return Err(last_windows_error(
            "GetFileInformationByHandle for immutable artifact",
        ));
    }
    Ok(ImmutableFileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

fn final_path_is_within(path: &Path, root: &Path) -> bool {
    let path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let root = root.as_os_str().encode_wide().collect::<Vec<_>>();
    if root.is_empty() || path.len() < root.len() || !wide_prefix_equal(&path, &root) {
        return false;
    }
    path.len() == root.len()
        || root
            .last()
            .is_some_and(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
        || path
            .get(root.len())
            .is_some_and(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
}

fn same_final_path(left: &Path, right: &Path) -> bool {
    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    left.len() == right.len() && wide_prefix_equal(&left, &right)
}

fn wide_prefix_equal(value: &[u16], prefix: &[u16]) -> bool {
    let Ok(prefix_len) = i32::try_from(prefix.len()) else {
        return false;
    };
    if value.len() < prefix.len() {
        return false;
    }
    unsafe {
        CompareStringOrdinal(value.as_ptr(), prefix_len, prefix.as_ptr(), prefix_len, 1)
            == CSTR_EQUAL
    }
}

fn runtime_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CalyxError {
    let message = message.into();
    tracing::error!(
        code,
        message = %message,
        remediation,
        "process-global pinned ONNX Runtime boundary failed closed"
    );
    CalyxError {
        code,
        message,
        remediation,
    }
}
