use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CStr, OsStr, OsString, c_char};
use std::fs::{self, File, OpenOptions};
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use nvml_wrapper::{Nvml, cuda_driver_version_major, cuda_driver_version_minor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HANDLE, HMODULE};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, GetFinalPathNameByHandleW};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    SetDefaultDllDirectories,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub use crate::cuda_system_trust::{SystemModuleTrustAttestation, SystemModuleVersionTranslation};
use crate::cuda_system_trust::{
    SystemModuleTrustPolicy, VerifiedSystemFile, verify_driver_store_companion,
    verify_system_module,
};
use crate::{ForgeError, PinnedCudaDeviceIdentity, Result};

pub const RUNTIME_ROOT_ENV: &str = "CALYX_CUDA13_RUNTIME_ROOT";
/// Emitted only after the exact pinned CUDA Runtime and exact system CUDA
/// Driver independently report zero devices in the same startup probe.
pub const CUDA_NO_DEVICE_ATTESTED_CODE: &str = "CALYX_CUDA_NO_DEVICE_ATTESTED";
const LOCK_SCHEMA: &str = "astrolabe.windows-ort-cuda-runtime-lock.v3";
const RECEIPT_SCHEMA: &str = "astrolabe.windows-ort-cuda-runtime-receipt.v2";
const LOCK_FILE: &str = "bundle.lock.json";
const LOCK_DIGEST_FILE: &str = "bundle.lock.sha256";
const RECEIPT_FILE: &str = "bundle.receipt.json";
const EXPECTED_PLATFORM: &str = "windows-x86_64";
const EXPECTED_LAYOUT: &str = "flat-bin-v1";
const EXPECTED_ROOT_PREFIX: &str = "ort-cuda13.3-windows-x86_64";
const EXPECTED_ORT_VERSION: &str = "1.27.1";
const EXPECTED_ORT_FILE_VERSION: &str = "1.27.20260709.2.df2ba1c";
const EXPECTED_PROVIDER: &str = "CUDAExecutionProvider";
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
const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;
const MAX_FINAL_PATH_CHARS: usize = 32_768;
const LEGACY_RUNTIME_ENVS: &[&str] = &["ORT_DYLIB_PATH", "CALYX_ORT_CAPI", "CALYX_NVIDIA_DLL_DIRS"];
const SYSTEM_MODULES: &[&str] = &["nvcuda.dll", "nvml.dll"];
const CONTRACT_REMEDIATION: &str =
    "restore the checked-in CUDA 13 runtime lock and rebuild Astrolabe from the canonical checkout";
const BUNDLE_REMEDIATION: &str = "restore the pinned CUDA 13 runtime bundle for this host, then start a new process with no legacy CUDA/ORT path variables set. Note: CUDA is unavailable on Apple Silicon — the Forge backend there is Metal (calyx-forge `metal` feature), not CUDA";
const DEVICE_REMEDIATION: &str = "repair the pinned CUDA 13 runtime and NVIDIA driver, select a CUDA Runtime-visible physical GPU, and restart the process";

const LOCK_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/toolchains/ort-cuda13.3-windows-x86_64.lock.json"
));

static BOUNDARY: OnceLock<std::result::Result<PinnedRuntimeBoundary, ForgeError>> = OnceLock::new();
static CUDA_DEPENDENCIES: OnceLock<std::result::Result<PinnedCudaRuntime, ForgeError>> =
    OnceLock::new();
static CUDA_DEVICE_SELECTION: OnceLock<Mutex<CudaDeviceSelectionState>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedCudaModuleAttestation {
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub file_version: Option<String>,
    pub source: String,
    pub system_trust: Option<SystemModuleTrustAttestation>,
}

/// Exact locked module whose lifetime is owned by ONNX Runtime rather than
/// Forge. Forge validates these bytes and rejects ambient copies, but never
/// maps them directly; a successful ORT session must prove residency later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedCudaOrtManagedModuleAttestation {
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub file_version: Option<String>,
    pub source: String,
    pub loader: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedCudaRuntimeAttestation {
    pub schema: String,
    pub lock_sha256: String,
    pub bundle_id: String,
    pub bundle_root: PathBuf,
    pub bundle_receipt: PathBuf,
    pub bundle_receipt_sha256: String,
    pub provisioned_at_utc: String,
    pub system_module_root: PathBuf,
    pub validated_file_count: usize,
    pub validated_notice_count: usize,
    pub modules: Vec<PinnedCudaModuleAttestation>,
    pub ort_managed_modules: Vec<PinnedCudaOrtManagedModuleAttestation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedCudaDeviceAttestation {
    pub schema: String,
    pub ordinal: u32,
    pub visible_device_count: u32,
    pub cuda_driver_ordinal: u32,
    pub identity: PinnedCudaDeviceIdentity,
    pub name: String,
    pub uuid: String,
    pub cuda_runtime_pci_bus_id: String,
    pub nvml_pci_bus_id: String,
    pub nvml_uuid: String,
    pub identity_source: String,
    pub compute_capability: String,
    pub total_vram_bytes: u64,
    pub used_vram_bytes: u64,
    pub free_vram_bytes: u64,
    pub nvidia_driver_version: String,
    pub cuda_driver_version: String,
}

impl PinnedCudaDeviceAttestation {
    pub fn frozen_execution_device(&self) -> String {
        self.identity.canonical_execution_token()
    }

    pub fn same_stable_device(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.ordinal == other.ordinal
            && self.visible_device_count == other.visible_device_count
            && self.cuda_driver_ordinal == other.cuda_driver_ordinal
            && self.identity == other.identity
            && self.name == other.name
            && self.uuid == other.uuid
            && self.cuda_runtime_pci_bus_id == other.cuda_runtime_pci_bus_id
            && self.nvml_pci_bus_id == other.nvml_pci_bus_id
            && self.nvml_uuid == other.nvml_uuid
            && self.compute_capability == other.compute_capability
            && self.total_vram_bytes == other.total_vram_bytes
            && self.nvidia_driver_version == other.nvidia_driver_version
            && self.cuda_driver_version == other.cuda_driver_version
    }
}

#[derive(Default)]
struct CudaDeviceSelectionState {
    selected: Option<PinnedCudaDeviceAttestation>,
    failure: Option<ForgeError>,
}

#[derive(Clone, Copy)]
enum CudaDeviceRequest {
    RuntimeOrdinal(u32),
    PhysicalIdentity(PinnedCudaDeviceIdentity),
}

struct PinnedCudaRuntime {
    state: Mutex<PinnedCudaRuntimeState>,
    system_module_handles: BTreeMap<String, OwnedModule>,
    _dependency_handles: ModuleStack,
}

struct PinnedCudaRuntimeState {
    attestation: PinnedCudaRuntimeAttestation,
    phase: PinnedCudaRuntimePhase,
    failure: Option<ForgeError>,
    _driver_store_handles: ModuleStack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinnedCudaRuntimePhase {
    DependenciesInitialized,
    DriverCompanionsAttested,
}

struct AttestedModuleSet {
    modules: Vec<PinnedCudaModuleAttestation>,
    driver_store_handles: ModuleStack,
}

struct PinnedRuntimeBoundary {
    lock: RuntimeLock,
    root: PathBuf,
    system32: PathBuf,
    attestation: PinnedCudaRuntimeAttestation,
    _core_handle: OwnedModule,
    _ort_managed_file_guards: Vec<VerifiedBundleFile>,
}

struct OwnedModule {
    handle: usize,
    _file_guard: ModuleFileGuard,
}

enum ModuleFileGuard {
    Bundle { _verified: VerifiedBundleFile },
    System { _verified: VerifiedSystemFile },
}

struct VerifiedBundleFile {
    _file: File,
    path: PathBuf,
}

struct ModuleStack(Vec<OwnedModule>);

impl OwnedModule {
    fn raw(&self) -> HMODULE {
        self.handle as HMODULE
    }
}

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

impl Drop for OwnedModule {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        let handle = std::mem::replace(&mut self.handle, 0) as HMODULE;
        if unsafe { FreeLibrary(handle) } == 0 {
            let windows_error = unsafe { GetLastError() };
            tracing::error!(
                code = "CALYX_ONNX_RUNTIME_MODULE_CLEANUP_FAILED",
                windows_error,
                "FreeLibrary failed while releasing a pinned CUDA runtime module"
            );
        }
    }
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleContract {
    id: String,
    platform: String,
    layout: String,
    root_prefix: String,
    root_from: String,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticodeContract {
    status: String,
    subject: String,
    thumbprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeContract {
    artifact: String,
    archive_path: String,
    bundle_path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadedModulePolicy {
    boundary_load: Vec<String>,
    dependency_preload_order: Vec<String>,
    ort_managed_load: Vec<String>,
    bundle_module_globs: Vec<String>,
    system_modules: Vec<SystemModulePolicy>,
    driver_store_companions: Vec<DriverStoreCompanionPolicy>,
    system_roots: Vec<String>,
    reject_application_dir: bool,
    reject_path_search: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemModulePolicy {
    name: String,
    required_root: String,
    signature_kind: String,
    signer_organization: String,
    signed_company_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriverStoreCompanionPolicy {
    name: String,
    attestation_name: String,
    owner: String,
    required_root: String,
    signature_kind: String,
    signer_organization: String,
    signed_company_name: String,
    require_same_catalog: bool,
    require_same_signer_certificate: bool,
    require_same_file_version: bool,
    require_same_product_name: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleReceipt {
    schema: String,
    bundle_id: String,
    lock_sha256: String,
    provisioned_at_utc: String,
    artifacts: Vec<ReceiptArtifact>,
    files: Vec<ReceiptFile>,
    notices: Vec<ReceiptNotice>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptArtifact {
    id: String,
    filename: String,
    bytes: u64,
    sha256: String,
    verification: String,
    archive_entries: u64,
    manifest_entries: u64,
    manifest_entries_verified: u64,
    locked_payloads_verified: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptFile {
    path: String,
    bytes: u64,
    sha256: String,
    file_version: Option<String>,
    authenticode: AuthenticodeContract,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptNotice {
    path: String,
    bytes: u64,
    sha256: String,
}

pub fn initialize_pinned_cuda_runtime_boundary() -> Result<PinnedCudaRuntimeAttestation> {
    match BOUNDARY.get_or_init(initialize_boundary) {
        Ok(boundary) => Ok(boundary.attestation.clone()),
        Err(error) => Err(error.clone()),
    }
}

pub fn initialize_pinned_cuda_dependencies() -> Result<PinnedCudaRuntimeAttestation> {
    cached_cuda_runtime_attestation()
}

pub fn attest_pinned_cuda_dependencies() -> Result<PinnedCudaRuntimeAttestation> {
    cached_cuda_runtime_attestation()
}

fn cached_cuda_runtime_attestation() -> Result<PinnedCudaRuntimeAttestation> {
    let runtime = match CUDA_DEPENDENCIES.get_or_init(initialize_cuda_dependencies) {
        Ok(runtime) => runtime,
        Err(error) => return Err(error.clone()),
    };
    let state = runtime.state.lock().map_err(|_| {
        runtime_error(
            "CALYX_CUDA_RUNTIME_STATE_POISONED",
            "the process-global pinned CUDA runtime state mutex was poisoned",
            "terminate the process, preserve its logs, and restart from the pinned CUDA runtime",
        )
    })?;
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    // Initialization retained every exact loaded module handle and a read-only
    // file guard that denies write/delete sharing. DriverStore companions are
    // promoted exactly once after the first real Driver API use and retain
    // both their loaded-module references and file guards in this state.
    // Ordinary execution attestation is therefore a cached receipt read, not
    // a multi-gigabyte per-call rehash.
    Ok(state.attestation.clone())
}

/// Commits the one legitimate loaded-module transition after the CUDA Driver
/// has been exercised. The signed DriverStore companions are independently
/// verified, their exact module references and file guards are retained
/// process-wide, and every later call is an O(1) receipt read. A failed
/// promotion is terminal.
pub fn attest_pinned_cuda_driver_dependencies() -> Result<PinnedCudaRuntimeAttestation> {
    let runtime = match CUDA_DEPENDENCIES.get_or_init(initialize_cuda_dependencies) {
        Ok(runtime) => runtime,
        Err(error) => return Err(error.clone()),
    };
    let boundary = match BOUNDARY.get_or_init(initialize_boundary) {
        Ok(boundary) => boundary,
        Err(error) => return Err(error.clone()),
    };
    let mut state = runtime.state.lock().map_err(|_| {
        runtime_error(
            "CALYX_CUDA_RUNTIME_STATE_POISONED",
            "the process-global pinned CUDA runtime state mutex was poisoned during DriverStore companion promotion",
            "terminate the process, preserve its logs, and restart from the pinned CUDA runtime",
        )
    })?;
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    if state.phase == PinnedCudaRuntimePhase::DriverCompanionsAttested {
        return Ok(state.attestation.clone());
    }
    let attested = match enumerate_process_modules().and_then(|modules| {
        attest_modules(
            &boundary.lock,
            &boundary.root,
            &boundary.system32,
            &modules,
            true,
            true,
            true,
        )
    }) {
        Ok(attested) => attested,
        Err(error) => {
            state.failure = Some(error.clone());
            return Err(error);
        }
    };
    state.attestation.modules = attested.modules;
    state._driver_store_handles = attested.driver_store_handles;
    state.phase = PinnedCudaRuntimePhase::DriverCompanionsAttested;
    Ok(state.attestation.clone())
}

/// Explicitly re-enumerates and re-hashes the complete pinned CUDA module
/// closure and compares it with the committed phase receipt. This is for
/// operator/readiness audits, not an inference hot path. Revalidation never
/// promotes or rewrites state; any difference is terminal for the process.
pub fn revalidate_pinned_cuda_dependencies() -> Result<PinnedCudaRuntimeAttestation> {
    let runtime = match CUDA_DEPENDENCIES.get_or_init(initialize_cuda_dependencies) {
        Ok(runtime) => runtime,
        Err(error) => return Err(error.clone()),
    };
    let boundary = match BOUNDARY.get_or_init(initialize_boundary) {
        Ok(boundary) => boundary,
        Err(error) => return Err(error.clone()),
    };
    let mut state = runtime.state.lock().map_err(|_| {
        runtime_error(
            "CALYX_CUDA_RUNTIME_STATE_POISONED",
            "the process-global pinned CUDA runtime state mutex was poisoned during explicit deep revalidation",
            "terminate the process, preserve its logs, and restart from the pinned CUDA runtime",
        )
    })?;
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    let require_driver_store_companions =
        state.phase == PinnedCudaRuntimePhase::DriverCompanionsAttested;
    let attested = match enumerate_process_modules().and_then(|modules| {
        attest_modules(
            &boundary.lock,
            &boundary.root,
            &boundary.system32,
            &modules,
            true,
            require_driver_store_companions,
            true,
        )
    }) {
        Ok(attested) => attested,
        Err(error) => {
            state.failure = Some(error.clone());
            return Err(error);
        }
    };
    if attested.modules != state.attestation.modules {
        let error = runtime_error(
            "CALYX_ONNX_RUNTIME_MODULE_STATE_CHANGED",
            format!(
                "explicit CUDA module revalidation differs from the committed {:?} receipt",
                state.phase
            ),
            "terminate the process, preserve both module inventories, and repair the pinned CUDA runtime before retrying",
        );
        state.failure = Some(error.clone());
        return Err(error);
    }
    Ok(state.attestation.clone())
}

/// Select one CUDA Runtime-visible device and pin its physical identity process-wide.
pub fn select_pinned_cuda_device(runtime_ordinal: u32) -> Result<PinnedCudaDeviceAttestation> {
    initialize_pinned_cuda_dependencies()?;
    let selected =
        select_pinned_cuda_device_request(CudaDeviceRequest::RuntimeOrdinal(runtime_ordinal))?;
    attest_pinned_cuda_driver_dependencies()?;
    Ok(selected)
}

/// Selects one device for an embedded native CUDA kernel without initializing
/// the ONNX/cuDNN provider stack.
///
/// This is not a relaxed or ambient CUDA path. It validates the same immutable
/// runtime bundle and maps exact locked `cudart64_13.dll` PCI identity through
/// signed System32 NVML UUID and `nvcuda.dll` Driver enumeration. It merely
/// avoids loading model-runtime DLLs that a CUBIN-only kernel does not consume.
pub fn select_pinned_cuda_device_for_native_kernel(
    runtime_ordinal: u32,
) -> Result<PinnedCudaDeviceAttestation> {
    initialize_pinned_cuda_runtime_boundary()?;
    select_pinned_cuda_device_request(CudaDeviceRequest::RuntimeOrdinal(runtime_ordinal))
}

/// Resolve a frozen physical identity through the current CUDA Runtime visibility map.
pub fn select_pinned_cuda_device_by_identity(
    identity: PinnedCudaDeviceIdentity,
) -> Result<PinnedCudaDeviceAttestation> {
    initialize_pinned_cuda_dependencies()?;
    let selected =
        select_pinned_cuda_device_request(CudaDeviceRequest::PhysicalIdentity(identity))?;
    attest_pinned_cuda_driver_dependencies()?;
    Ok(selected)
}

pub fn current_pinned_cuda_device() -> Result<Option<PinnedCudaDeviceAttestation>> {
    let Some(state) = CUDA_DEVICE_SELECTION.get() else {
        return Ok(None);
    };
    let state = state.lock().map_err(|_| {
        runtime_error(
            "CALYX_CUDA_DEVICE_STATE_POISONED",
            "the process-global CUDA device-selection mutex was poisoned",
            "terminate the process, preserve its logs, and restart from the pinned CUDA runtime",
        )
    })?;
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    Ok(state.selected.clone())
}

/// Independently re-read the exact system CUDA Driver's PCI+UUID mapping for the
/// process-pinned physical device. This remains available to ONNX-only builds
/// that establish the runtime boundary without compiling the cudarc math backend.
pub fn attest_pinned_cuda_driver_identity(
    expected_identity: PinnedCudaDeviceIdentity,
) -> Result<u32> {
    initialize_pinned_cuda_dependencies()?;
    let runtime = match CUDA_DEPENDENCIES.get_or_init(initialize_cuda_dependencies) {
        Ok(runtime) => runtime,
        Err(error) => return Err(error.clone()),
    };
    let nvcuda = runtime
        .system_module_handles
        .get("nvcuda.dll")
        .ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_MODULE_NOT_LOADED",
                "the initialized pinned CUDA runtime retained no nvcuda.dll module handle",
                BUNDLE_REMEDIATION,
            )
        })?;
    let observed = attest_pinned_cuda_driver_identity_with_module(expected_identity, nvcuda.raw())?;
    attest_pinned_cuda_driver_dependencies()?;
    Ok(observed)
}

/// Re-attests the native-kernel device contract without loading ONNX provider
/// dependencies. The selected PCI+UUID must already have been pinned by
/// [`select_pinned_cuda_device_for_native_kernel`].
pub fn attest_pinned_cuda_driver_identity_for_native_kernel(
    expected_identity: PinnedCudaDeviceIdentity,
) -> Result<u32> {
    initialize_pinned_cuda_runtime_boundary()?;
    let boundary = match BOUNDARY.get_or_init(initialize_boundary) {
        Ok(boundary) => boundary,
        Err(error) => return Err(error.clone()),
    };
    let nvcuda_module = load_verified_system_module(boundary, "nvcuda.dll")?;
    attest_pinned_cuda_driver_identity_with_module(expected_identity, nvcuda_module.raw())
}

fn attest_pinned_cuda_driver_identity_with_module(
    expected_identity: PinnedCudaDeviceIdentity,
    nvcuda_module: HMODULE,
) -> Result<u32> {
    let selected = current_pinned_cuda_device()?.ok_or_else(|| {
        runtime_error(
            "CALYX_CUDA_DEVICE_ATTESTATION_MISSING",
            "cannot attest the CUDA Driver identity before selecting one process-global physical CUDA device",
            DEVICE_REMEDIATION,
        )
    })?;
    if selected.identity != expected_identity {
        return Err(runtime_error(
            "CALYX_CUDA_DRIVER_DEVICE_SELECTION_MISMATCH",
            format!(
                "requested Driver identity {expected_identity}; process receipt records {}",
                selected.identity
            ),
            DEVICE_REMEDIATION,
        ));
    }
    let observed = cuda_driver_ordinal_for_identity(nvcuda_module, expected_identity)?;
    if observed != selected.cuda_driver_ordinal {
        return Err(runtime_error(
            "CALYX_CUDA_DRIVER_ORDINAL_MISMATCH",
            format!(
                "exact nvcuda PCI+UUID enumeration resolved {expected_identity} to Driver ordinal {observed}; process receipt records {}",
                selected.cuda_driver_ordinal
            ),
            DEVICE_REMEDIATION,
        ));
    }
    Ok(observed)
}

fn select_pinned_cuda_device_request(
    request: CudaDeviceRequest,
) -> Result<PinnedCudaDeviceAttestation> {
    let state =
        CUDA_DEVICE_SELECTION.get_or_init(|| Mutex::new(CudaDeviceSelectionState::default()));
    let mut state = state.lock().map_err(|_| {
        runtime_error(
            "CALYX_CUDA_DEVICE_STATE_POISONED",
            "the process-global CUDA device-selection mutex was poisoned",
            "terminate the process, preserve its logs, and restart from the pinned CUDA runtime",
        )
    })?;
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    if let Some(selected) = &state.selected {
        let request_matches = match request {
            CudaDeviceRequest::RuntimeOrdinal(ordinal) => ordinal == selected.ordinal,
            CudaDeviceRequest::PhysicalIdentity(identity) => identity == selected.identity,
        };
        if request_matches {
            return Ok(selected.clone());
        }
        let requested = match request {
            CudaDeviceRequest::RuntimeOrdinal(ordinal) => format!("runtime_ordinal={ordinal}"),
            CudaDeviceRequest::PhysicalIdentity(identity) => format!("identity={identity}"),
        };
        let error = runtime_error(
            "CALYX_CUDA_DEVICE_SELECTION_CHANGED",
            format!(
                "process already pinned runtime_ordinal={} driver_ordinal={} identity={}; later request selected {requested}",
                selected.ordinal,
                selected.cuda_driver_ordinal,
                selected.frozen_execution_device()
            ),
            "terminate the process and restart with every GPU runtime selecting the same physical device",
        );
        state.failure = Some(error.clone());
        return Err(error);
    }
    let candidate = match resolve_cuda_device(request) {
        Ok(candidate) => candidate,
        Err(error) => {
            state.failure = Some(error.clone());
            return Err(error);
        }
    };
    tracing::info!(
        code = "CALYX_CUDA_DEVICE_PINNED",
        runtime_ordinal = candidate.ordinal,
        driver_ordinal = candidate.cuda_driver_ordinal,
        visible_device_count = candidate.visible_device_count,
        pci_bus_id = %candidate.cuda_runtime_pci_bus_id,
        uuid = %candidate.nvml_uuid,
        name = %candidate.name,
        compute_capability = %candidate.compute_capability,
        "pinned one physical CUDA device for every process-local GPU runtime"
    );
    state.selected = Some(candidate.clone());
    Ok(candidate)
}

fn resolve_cuda_device(request: CudaDeviceRequest) -> Result<PinnedCudaDeviceAttestation> {
    let boundary = match BOUNDARY.get_or_init(initialize_boundary) {
        Ok(boundary) => boundary,
        Err(error) => return Err(error.clone()),
    };
    let cudart_contract = boundary
        .lock
        .files
        .iter()
        .find(|file| {
            bundle_basename(&file.bundle_path)
                .is_ok_and(|name| name.eq_ignore_ascii_case("cudart64_13.dll"))
        })
        .ok_or_else(|| {
            runtime_error(
                "CALYX_CUDA_RUNTIME_CONTRACT_INVALID",
                "the pinned runtime lock omits cudart64_13.dll",
                CONTRACT_REMEDIATION,
            )
        })?;
    let cudart = load_locked_bundle_library(&boundary.root, cudart_contract)?;
    let visible_device_count = cuda_runtime_device_count(cudart.raw())?;
    if visible_device_count == 0 {
        let nvcuda = load_verified_system_module(boundary, "nvcuda.dll")?;
        let driver_device_count = cuda_driver_device_count(nvcuda.raw())?;
        if driver_device_count != 0 {
            return Err(runtime_error(
                "CALYX_CUDA_DRIVER_RUNTIME_INCONSISTENT",
                format!(
                    "the exact pinned CUDA Runtime reports zero visible devices, but the exact system CUDA Driver reports {driver_device_count} devices"
                ),
                "repair the CUDA Runtime/Driver visibility mismatch and restart the process; this inconsistent state must not authorize CPU execution",
            ));
        }
        return Err(runtime_error(
            CUDA_NO_DEVICE_ATTESTED_CODE,
            "the exact pinned CUDA Runtime and exact system CUDA Driver independently report zero CUDA devices",
            "use the separately commissioned CPU companion panel, or expose a usable NVIDIA GPU and restart the process",
        ));
    }
    let runtime_ordinal = match request {
        CudaDeviceRequest::RuntimeOrdinal(runtime_ordinal) => {
            if runtime_ordinal >= visible_device_count {
                return Err(runtime_error(
                    "CALYX_CUDA_DEVICE_UNAVAILABLE",
                    format!(
                        "requested CUDA Runtime ordinal {runtime_ordinal} is outside the visible range 0..{}",
                        visible_device_count - 1
                    ),
                    DEVICE_REMEDIATION,
                ));
            }
            runtime_ordinal
        }
        CudaDeviceRequest::PhysicalIdentity(identity) => {
            let expected_pci = identity.canonical_pci_bus_id();
            let mut matches = Vec::new();
            for ordinal in 0..visible_device_count {
                let pci = cuda_runtime_device_pci_bus_id(cudart.raw(), ordinal)?;
                let observed =
                    PinnedCudaDeviceIdentity::from_pci_and_uuid(&pci, &identity.canonical_uuid())
                        .map_err(cuda_identity_error)?;
                if observed.canonical_pci_bus_id() == expected_pci {
                    matches.push(ordinal);
                }
            }
            let [runtime_ordinal] = matches.as_slice() else {
                return Err(runtime_error(
                    "CALYX_CUDA_FROZEN_DEVICE_UNAVAILABLE",
                    format!(
                        "frozen physical device {} matched {} CUDA Runtime-visible ordinals",
                        identity,
                        matches.len()
                    ),
                    "restore visibility of the commissioned physical GPU, or select its distinct CPU companion lens; do not rewrite the frozen identity",
                ));
            };
            *runtime_ordinal
        }
    };
    let cuda_runtime_pci_bus_id = cuda_runtime_device_pci_bus_id(cudart.raw(), runtime_ordinal)?;
    attest_resolved_cuda_device(
        boundary,
        runtime_ordinal,
        visible_device_count,
        cuda_runtime_pci_bus_id,
        match request {
            CudaDeviceRequest::PhysicalIdentity(identity) => Some(identity),
            CudaDeviceRequest::RuntimeOrdinal(_) => None,
        },
    )
}

fn attest_resolved_cuda_device(
    boundary: &PinnedRuntimeBoundary,
    ordinal: u32,
    visible_device_count: u32,
    cuda_runtime_pci_bus_id: String,
    expected_identity: Option<PinnedCudaDeviceIdentity>,
) -> Result<PinnedCudaDeviceAttestation> {
    let verified_nvml =
        verify_locked_system_module(&boundary.lock, &boundary.system32, "nvml.dll")?;
    let nvml_path = verified_nvml.path().to_path_buf();
    let nvml = Nvml::builder()
        .lib_path(nvml_path.as_os_str())
        .init()
        .map_err(|error| {
            runtime_error(
                "CALYX_CUDA_NVML_INIT_FAILED",
                format!("load exact NVML {} failed: {error}", nvml_path.display()),
                DEVICE_REMEDIATION,
            )
        })?;
    let device = nvml
        .device_by_pci_bus_id(cuda_runtime_pci_bus_id.as_str())
        .map_err(|error| {
            runtime_error(
                "CALYX_CUDA_DEVICE_IDENTITY_MISMATCH",
                format!(
                    "NVML could not resolve CUDA Runtime ordinal {ordinal} PCI identity {cuda_runtime_pci_bus_id}: {error}"
                ),
                DEVICE_REMEDIATION,
            )
        })?;
    let name = device.name().map_err(nvml_device_error("name"))?;
    let nvml_uuid = device.uuid().map_err(nvml_device_error("UUID"))?;
    let nvml_pci_bus_id = device
        .pci_info()
        .map_err(nvml_device_error("PCI identity"))?
        .bus_id;
    let runtime_identity =
        PinnedCudaDeviceIdentity::from_pci_and_uuid(&cuda_runtime_pci_bus_id, &nvml_uuid)
            .map_err(cuda_identity_error)?;
    let nvml_identity = PinnedCudaDeviceIdentity::from_pci_and_uuid(&nvml_pci_bus_id, &nvml_uuid)
        .map_err(cuda_identity_error)?;
    if runtime_identity != nvml_identity {
        return Err(runtime_error(
            "CALYX_CUDA_DEVICE_IDENTITY_MISMATCH",
            format!(
                "CUDA Runtime ordinal {ordinal} reports PCI {cuda_runtime_pci_bus_id}; NVML reports {nvml_pci_bus_id} / {nvml_uuid}"
            ),
            DEVICE_REMEDIATION,
        ));
    }
    if expected_identity.is_some_and(|expected| expected != runtime_identity) {
        return Err(runtime_error(
            "CALYX_CUDA_FROZEN_DEVICE_IDENTITY_MISMATCH",
            format!(
                "frozen identity {} resolved by PCI to different NVML identity {}",
                expected_identity.expect("checked above"),
                runtime_identity
            ),
            "restore the commissioned physical GPU or select its distinct CPU companion lens; never rewrite frozen identity from ambient hardware",
        ));
    }
    let nvcuda_module = load_verified_system_module(boundary, "nvcuda.dll")?;
    let cuda_driver_ordinal =
        cuda_driver_ordinal_for_identity(nvcuda_module.raw(), runtime_identity)?;
    let compute = device
        .cuda_compute_capability()
        .map_err(nvml_device_error("compute capability"))?;
    let memory = device
        .memory_info()
        .map_err(nvml_device_error("memory info"))?;
    let nvidia_driver_version = nvml
        .sys_driver_version()
        .map_err(nvml_system_error("driver version"))?;
    let cuda_version = nvml
        .sys_cuda_driver_version()
        .map_err(nvml_system_error("CUDA driver version"))?;
    Ok(PinnedCudaDeviceAttestation {
        schema: "calyx-pinned-cuda-device-attestation-v1".to_string(),
        ordinal,
        visible_device_count,
        cuda_driver_ordinal,
        identity: runtime_identity,
        name,
        uuid: nvml_uuid.clone(),
        cuda_runtime_pci_bus_id,
        nvml_pci_bus_id,
        nvml_uuid,
        identity_source: "exact cudart64_13!cudaDeviceGetPCIBusId -> system-trusted nvmlDeviceGetHandleByPciBusId_v2/nvmlDeviceGetUUID -> system-trusted nvcuda!cuDeviceGetPCIBusId+cuDeviceGetUuid_v2 ordinal enumeration".to_string(),
        compute_capability: format!("{}.{}", compute.major, compute.minor),
        total_vram_bytes: memory.total,
        used_vram_bytes: memory.used,
        free_vram_bytes: memory.free,
        nvidia_driver_version,
        cuda_driver_version: format!(
            "{}.{}",
            cuda_driver_version_major(cuda_version),
            cuda_driver_version_minor(cuda_version)
        ),
    })
}

fn load_verified_system_module(
    boundary: &PinnedRuntimeBoundary,
    name: &str,
) -> Result<OwnedModule> {
    let verified = verify_locked_system_module(&boundary.lock, &boundary.system32, name)?;
    let path = verified.path().to_path_buf();
    load_exact_library(
        &path,
        ModuleFileGuard::System {
            _verified: verified,
        },
    )
}

fn cuda_runtime_device_count(module: HMODULE) -> Result<u32> {
    type CudaGetDeviceCount = unsafe extern "system" fn(*mut i32) -> i32;
    let proc = unsafe { GetProcAddress(module, c"cudaGetDeviceCount".as_ptr().cast()) }
        .ok_or_else(|| {
            runtime_error(
                "CALYX_CUDA_RUNTIME_EXPORT_MISSING",
                "exact cudart64_13.dll does not export cudaGetDeviceCount",
                BUNDLE_REMEDIATION,
            )
        })?;
    let cuda_get_device_count: CudaGetDeviceCount = unsafe { mem::transmute(proc) };
    let mut count = 0i32;
    let status = unsafe { cuda_get_device_count(&mut count) };
    if status == 100 {
        return Ok(0);
    }
    if status != 0 {
        return Err(cuda_runtime_call_error(
            module,
            "cudaGetDeviceCount",
            status,
        ));
    }
    u32::try_from(count).map_err(|_| {
        runtime_error(
            "CALYX_CUDA_DEVICE_IDENTITY_INVALID",
            format!("exact cudart64_13.dll returned invalid device count {count}"),
            DEVICE_REMEDIATION,
        )
    })
}

fn cuda_driver_device_count(module: HMODULE) -> Result<u32> {
    type CuInit = unsafe extern "system" fn(u32) -> i32;
    type CuDeviceGetCount = unsafe extern "system" fn(*mut i32) -> i32;

    let cu_init: CuInit = unsafe { mem::transmute(required_export(module, c"cuInit")?) };
    let cu_device_get_count: CuDeviceGetCount =
        unsafe { mem::transmute(required_export(module, c"cuDeviceGetCount")?) };
    let init_status = unsafe { cu_init(0) };
    if init_status == 100 {
        return Ok(0);
    }
    if init_status != 0 {
        return Err(cuda_driver_call_error(module, "cuInit", init_status));
    }
    let mut count = 0i32;
    let count_status = unsafe { cu_device_get_count(&mut count) };
    if count_status != 0 {
        return Err(cuda_driver_call_error(
            module,
            "cuDeviceGetCount",
            count_status,
        ));
    }
    u32::try_from(count).map_err(|_| {
        runtime_error(
            "CALYX_CUDA_DRIVER_DEVICE_COUNT_INVALID",
            format!("the exact system CUDA Driver returned invalid device count {count}"),
            DEVICE_REMEDIATION,
        )
    })
}

fn cuda_runtime_device_pci_bus_id(module: HMODULE, ordinal: u32) -> Result<String> {
    type CudaDeviceGetPciBusId = unsafe extern "system" fn(*mut c_char, i32, i32) -> i32;
    let proc = unsafe { GetProcAddress(module, c"cudaDeviceGetPCIBusId".as_ptr().cast()) }
        .ok_or_else(|| {
            runtime_error(
                "CALYX_CUDA_RUNTIME_EXPORT_MISSING",
                "exact cudart64_13.dll does not export cudaDeviceGetPCIBusId",
                BUNDLE_REMEDIATION,
            )
        })?;
    let cuda_device_get_pci_bus_id: CudaDeviceGetPciBusId = unsafe { mem::transmute(proc) };
    let ordinal = i32::try_from(ordinal).map_err(|_| {
        runtime_error(
            "CALYX_CUDA_DEVICE_IDENTITY_INVALID",
            "CUDA Runtime ordinal exceeds the i32 ABI",
            DEVICE_REMEDIATION,
        )
    })?;
    let mut pci_bus_id = [0u8; 32];
    let status = unsafe {
        cuda_device_get_pci_bus_id(
            pci_bus_id.as_mut_ptr().cast(),
            pci_bus_id.len() as i32,
            ordinal,
        )
    };
    if status != 0 {
        return Err(cuda_runtime_call_error(
            module,
            "cudaDeviceGetPCIBusId",
            status,
        ));
    }
    bounded_ascii_identity(&pci_bus_id, "cudaDeviceGetPCIBusId")
}

fn cuda_driver_ordinal_for_identity(
    module: HMODULE,
    expected_identity: PinnedCudaDeviceIdentity,
) -> Result<u32> {
    #[repr(C)]
    struct CuUuid {
        bytes: [i8; 16],
    }

    type CuInit = unsafe extern "system" fn(u32) -> i32;
    type CuDeviceGetCount = unsafe extern "system" fn(*mut i32) -> i32;
    type CuDeviceGet = unsafe extern "system" fn(*mut i32, i32) -> i32;
    type CuDeviceGetPciBusId = unsafe extern "system" fn(*mut c_char, i32, i32) -> i32;
    type CuDeviceGetUuidV2 = unsafe extern "system" fn(*mut CuUuid, i32) -> i32;
    let cu_init: CuInit = unsafe { mem::transmute(required_export(module, c"cuInit")?) };
    let cu_device_get_count: CuDeviceGetCount =
        unsafe { mem::transmute(required_export(module, c"cuDeviceGetCount")?) };
    let cu_device_get: CuDeviceGet =
        unsafe { mem::transmute(required_export(module, c"cuDeviceGet")?) };
    let cu_device_get_pci_bus_id: CuDeviceGetPciBusId =
        unsafe { mem::transmute(required_export(module, c"cuDeviceGetPCIBusId")?) };
    let cu_device_get_uuid_v2: CuDeviceGetUuidV2 =
        unsafe { mem::transmute(required_export(module, c"cuDeviceGetUuid_v2")?) };
    let status = unsafe { cu_init(0) };
    if status != 0 {
        return Err(cuda_driver_call_error(module, "cuInit", status));
    }
    let mut count = 0i32;
    let status = unsafe { cu_device_get_count(&mut count) };
    if status != 0 {
        return Err(cuda_driver_call_error(module, "cuDeviceGetCount", status));
    }
    if count <= 0 {
        return Err(runtime_error(
            "CALYX_CUDA_DRIVER_RUNTIME_INCONSISTENT",
            "the exact pinned CUDA Runtime reported a visible device, but the exact system CUDA Driver reports zero devices",
            "repair the CUDA Runtime/Driver visibility mismatch and restart the process; this inconsistent state must not authorize CPU execution",
        ));
    }
    let mut matches = Vec::new();
    for driver_ordinal in 0..count {
        let mut device = 0i32;
        let status = unsafe { cu_device_get(&mut device, driver_ordinal) };
        if status != 0 {
            return Err(cuda_driver_call_error(module, "cuDeviceGet", status));
        }
        let mut pci_bus_id = [0u8; 32];
        let status = unsafe {
            cu_device_get_pci_bus_id(
                pci_bus_id.as_mut_ptr().cast(),
                pci_bus_id.len() as i32,
                device,
            )
        };
        if status != 0 {
            return Err(cuda_driver_call_error(
                module,
                "cuDeviceGetPCIBusId",
                status,
            ));
        }
        let observed_pci = bounded_ascii_identity(&pci_bus_id, "cuDeviceGetPCIBusId")?;
        let mut observed_uuid = CuUuid { bytes: [0; 16] };
        let status = unsafe { cu_device_get_uuid_v2(&mut observed_uuid, device) };
        if status != 0 {
            return Err(cuda_driver_call_error(module, "cuDeviceGetUuid_v2", status));
        }
        let observed_identity = PinnedCudaDeviceIdentity::from_pci_and_uuid_bytes(
            &observed_pci,
            observed_uuid.bytes.map(|byte| byte as u8),
        )
        .map_err(cuda_identity_error)?;
        if observed_identity == expected_identity {
            matches.push(driver_ordinal);
        }
    }
    let [driver_ordinal] = matches.as_slice() else {
        return Err(runtime_error(
            "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_MISMATCH",
            format!(
                "CUDA Runtime/NVML physical identity {expected_identity} matched {} CUDA Driver ordinals by cuDeviceGetPCIBusId+cuDeviceGetUuid_v2",
                matches.len()
            ),
            DEVICE_REMEDIATION,
        ));
    };
    u32::try_from(*driver_ordinal).map_err(|_| {
        runtime_error(
            "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_INVALID",
            format!("CUDA Driver ordinal {driver_ordinal} exceeds u32"),
            DEVICE_REMEDIATION,
        )
    })
}

fn required_export(module: HMODULE, name: &CStr) -> Result<unsafe extern "system" fn() -> isize> {
    unsafe { GetProcAddress(module, name.as_ptr().cast()) }.ok_or_else(|| {
        runtime_error(
            "CALYX_CUDA_DRIVER_EXPORT_MISSING",
            format!(
                "exact system nvcuda.dll does not export {}",
                name.to_string_lossy()
            ),
            DEVICE_REMEDIATION,
        )
    })
}

fn bounded_ascii_identity(bytes: &[u8], operation: &str) -> Result<String> {
    let nul = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        runtime_error(
            "CALYX_CUDA_DEVICE_IDENTITY_INVALID",
            format!("{operation} returned no NUL terminator in its bounded output"),
            DEVICE_REMEDIATION,
        )
    })?;
    let value = std::str::from_utf8(&bytes[..nul]).map_err(|error| {
        runtime_error(
            "CALYX_CUDA_DEVICE_IDENTITY_INVALID",
            format!("{operation} returned invalid UTF-8: {error}"),
            DEVICE_REMEDIATION,
        )
    })?;
    if value.is_empty() || !value.is_ascii() {
        return Err(runtime_error(
            "CALYX_CUDA_DEVICE_IDENTITY_INVALID",
            format!("{operation} returned invalid identity {value:?}"),
            DEVICE_REMEDIATION,
        ));
    }
    Ok(value.to_string())
}

fn cuda_identity_error(detail: String) -> ForgeError {
    runtime_error(
        "CALYX_CUDA_DEVICE_IDENTITY_INVALID",
        detail,
        DEVICE_REMEDIATION,
    )
}

fn cuda_runtime_call_error(module: HMODULE, operation: &'static str, status: i32) -> ForgeError {
    let name = cuda_runtime_error_text(module, c"cudaGetErrorName", status)
        .unwrap_or_else(|| "unavailable".to_string());
    let detail = cuda_runtime_error_text(module, c"cudaGetErrorString", status)
        .unwrap_or_else(|| "unavailable".to_string());
    runtime_error(
        "CALYX_CUDA_RUNTIME_CALL_FAILED",
        format!("exact cudart64_13.dll {operation} failed with status {status} ({name}): {detail}"),
        DEVICE_REMEDIATION,
    )
}

fn cuda_runtime_error_text(module: HMODULE, export: &CStr, status: i32) -> Option<String> {
    type CudaGetErrorText = unsafe extern "system" fn(i32) -> *const c_char;
    let proc = unsafe { GetProcAddress(module, export.as_ptr().cast()) }?;
    let get_text: CudaGetErrorText = unsafe { mem::transmute(proc) };
    let value = unsafe { get_text(status) };
    bounded_driver_text(value)
}

fn cuda_driver_call_error(module: HMODULE, operation: &'static str, status: i32) -> ForgeError {
    let name = cuda_driver_error_text(module, c"cuGetErrorName", status)
        .unwrap_or_else(|| "unavailable".to_string());
    let detail = cuda_driver_error_text(module, c"cuGetErrorString", status)
        .unwrap_or_else(|| "unavailable".to_string());
    runtime_error(
        "CALYX_CUDA_DRIVER_CALL_FAILED",
        format!(
            "exact system nvcuda.dll {operation} failed with status {status} ({name}): {detail}"
        ),
        DEVICE_REMEDIATION,
    )
}

fn cuda_driver_error_text(module: HMODULE, export: &CStr, status: i32) -> Option<String> {
    type CuGetErrorText = unsafe extern "system" fn(i32, *mut *const c_char) -> i32;
    let proc = unsafe { GetProcAddress(module, export.as_ptr().cast()) }?;
    let get_text: CuGetErrorText = unsafe { mem::transmute(proc) };
    let mut value = ptr::null();
    if unsafe { get_text(status, &mut value) } != 0 {
        return None;
    }
    bounded_driver_text(value)
}

fn bounded_driver_text(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(value) };
    if value.to_bytes().len() > 1024 {
        return Some("invalid overlong CUDA error text".to_string());
    }
    Some(value.to_string_lossy().into_owned())
}

fn nvml_device_error(
    operation: &'static str,
) -> impl FnOnce(nvml_wrapper::error::NvmlError) -> ForgeError {
    move |error| {
        runtime_error(
            "CALYX_CUDA_DEVICE_ATTESTATION_FAILED",
            format!("NVML device {operation} query failed: {error}"),
            DEVICE_REMEDIATION,
        )
    }
}

fn nvml_system_error(
    operation: &'static str,
) -> impl FnOnce(nvml_wrapper::error::NvmlError) -> ForgeError {
    move |error| {
        runtime_error(
            "CALYX_CUDA_DRIVER_ATTESTATION_FAILED",
            format!("NVML system {operation} query failed: {error}"),
            DEVICE_REMEDIATION,
        )
    }
}

fn initialize_boundary() -> Result<PinnedRuntimeBoundary> {
    reject_legacy_environment()?;
    let lock: RuntimeLock = serde_json::from_slice(LOCK_BYTES).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
            format!("parse embedded CUDA runtime lock failed: {error}"),
            CONTRACT_REMEDIATION,
        )
    })?;
    validate_lock(&lock)?;
    let lock_sha256 = sha256_bytes(LOCK_BYTES);
    let root = resolve_root(&lock, &lock_sha256)?;
    let (receipt, receipt_sha256) = validate_bundle(&root, &lock, &lock_sha256)?;
    let system32 = system_directory()?;
    reject_system32_aliases(&system32, &lock)?;
    reject_ambient_modules(
        &lock,
        &root,
        &system32,
        &enumerate_process_modules()?,
        false,
        false,
    )?;
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(last_windows_error(
            "SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)",
        ));
    }

    let core = lock
        .files
        .iter()
        .find(|file| {
            bundle_basename(&file.bundle_path)
                .is_ok_and(|name| name.eq_ignore_ascii_case("onnxruntime.dll"))
        })
        .ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                "lock omits onnxruntime.dll",
                CONTRACT_REMEDIATION,
            )
        })?;
    let core_handle = load_locked_bundle_library(&root, core)?;
    let modules = attest_modules(
        &lock,
        &root,
        &system32,
        &enumerate_process_modules()?,
        false,
        false,
        false,
    )?
    .modules;
    let (ort_managed_modules, ort_managed_file_guards) =
        open_locked_ort_managed_modules(&lock, &root)?;
    let attestation = PinnedCudaRuntimeAttestation {
        schema: "calyx-pinned-cuda-runtime-attestation-v3".to_string(),
        lock_sha256,
        bundle_id: lock.bundle.id.clone(),
        bundle_root: root.clone(),
        bundle_receipt: root.join(RECEIPT_FILE),
        bundle_receipt_sha256: receipt_sha256,
        provisioned_at_utc: receipt.provisioned_at_utc,
        system_module_root: system32.clone(),
        validated_file_count: lock.files.len(),
        validated_notice_count: lock.notices.len(),
        modules,
        ort_managed_modules,
    };
    Ok(PinnedRuntimeBoundary {
        lock,
        root,
        system32,
        attestation,
        _core_handle: core_handle,
        _ort_managed_file_guards: ort_managed_file_guards,
    })
}

fn initialize_cuda_dependencies() -> Result<PinnedCudaRuntime> {
    let boundary = match BOUNDARY.get_or_init(initialize_boundary) {
        Ok(boundary) => boundary,
        Err(error) => return Err(error.clone()),
    };
    reject_ambient_modules(
        &boundary.lock,
        &boundary.root,
        &boundary.system32,
        &enumerate_process_modules()?,
        true,
        false,
    )?;
    let mut system_module_handles = BTreeMap::new();
    for name in SYSTEM_MODULES {
        let verified = verify_locked_system_module(&boundary.lock, &boundary.system32, name)?;
        let path = verified.path().to_path_buf();
        let handle = load_exact_library(
            &path,
            ModuleFileGuard::System {
                _verified: verified,
            },
        )?;
        if system_module_handles
            .insert(name.to_ascii_lowercase(), handle)
            .is_some()
        {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                format!("duplicate retained system module handle for {name}"),
                CONTRACT_REMEDIATION,
            ));
        }
    }
    let mut dependency_handles = ModuleStack::with_capacity(
        boundary
            .lock
            .loaded_module_policy
            .dependency_preload_order
            .len(),
    );
    for bundle_path in &boundary.lock.loaded_module_policy.dependency_preload_order {
        let file = boundary
            .lock
            .files
            .iter()
            .find(|file| file.bundle_path.eq_ignore_ascii_case(bundle_path))
            .ok_or_else(|| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                    format!("module load order references unlocked path {bundle_path}"),
                    CONTRACT_REMEDIATION,
                )
            })?;
        dependency_handles.push(load_locked_bundle_library(&boundary.root, file)?);
    }

    let attested = attest_modules(
        &boundary.lock,
        &boundary.root,
        &boundary.system32,
        &enumerate_process_modules()?,
        true,
        false,
        false,
    )?;
    let mut attestation = boundary.attestation.clone();
    attestation.modules = attested.modules;
    Ok(PinnedCudaRuntime {
        state: Mutex::new(PinnedCudaRuntimeState {
            attestation,
            phase: PinnedCudaRuntimePhase::DependenciesInitialized,
            failure: None,
            _driver_store_handles: attested.driver_store_handles,
        }),
        system_module_handles,
        _dependency_handles: dependency_handles,
    })
}

fn validate_lock(lock: &RuntimeLock) -> Result<()> {
    require(lock.schema == LOCK_SCHEMA, "unexpected lock schema")?;
    require(
        lock.bundle.platform == EXPECTED_PLATFORM,
        "unexpected platform",
    )?;
    require(
        lock.bundle.layout == EXPECTED_LAYOUT,
        "unexpected bundle layout",
    )?;
    require(
        lock.bundle.root_prefix == EXPECTED_ROOT_PREFIX,
        "unexpected bundle root prefix",
    )?;
    require(
        lock.bundle.root_from == "sha256(lock_file_bytes)",
        "unexpected bundle root derivation",
    )?;
    require(!lock.bundle.id.trim().is_empty(), "bundle id is empty")?;
    require(
        lock.contract.ort_version == EXPECTED_ORT_VERSION
            && lock.contract.ort_file_version == EXPECTED_ORT_FILE_VERSION
            && lock.contract.ort_api == 24
            && lock.contract.api_non_null == [24, 25, 26, 27]
            && lock.contract.first_api_null == 28
            && lock.contract.provider == EXPECTED_PROVIDER
            && bundle_basename(&lock.contract.ort_dll)?.eq_ignore_ascii_case("onnxruntime.dll")
            && bundle_basename(&lock.contract.provider_dll)?
                .eq_ignore_ascii_case("onnxruntime_providers_cuda.dll"),
        "ORT runtime contract differs from the pinned CUDA 13 closure",
    )?;
    require(
        lock.loaded_module_policy.reject_application_dir
            && lock.loaded_module_policy.reject_path_search,
        "loaded-module policy does not reject ambient search",
    )?;
    require(
        lock.loaded_module_policy.system_roots.len() == 2
            && lock
                .loaded_module_policy
                .system_roots
                .iter()
                .map(|root| root.to_ascii_lowercase())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    "%systemroot%\\system32".to_string(),
                    "%systemroot%\\system32\\driverstore\\filerepository".to_string(),
                ]),
        "system module roots must be exactly System32 and DriverStore FileRepository",
    )?;
    let system_modules = lock
        .loaded_module_policy
        .system_modules
        .iter()
        .map(|module| (module.name.to_ascii_lowercase(), module))
        .collect::<BTreeMap<_, _>>();
    require(
        system_modules.len() == lock.loaded_module_policy.system_modules.len()
            && system_modules.len() == SYSTEM_MODULES.len()
            && SYSTEM_MODULES
                .iter()
                .all(|name| system_modules.contains_key(*name)),
        "system module identity/cardinality mismatch",
    )?;
    for module in system_modules.values() {
        require(
            module
                .required_root
                .eq_ignore_ascii_case("%SystemRoot%\\System32")
                && module.signature_kind == "catalog"
                && module.signer_organization == "Microsoft Corporation"
                && module.signed_company_name == "NVIDIA Corporation",
            "system module trust policy differs from the Windows NVIDIA driver contract",
        )?;
    }
    let companions = lock
        .loaded_module_policy
        .driver_store_companions
        .iter()
        .map(|module| (module.attestation_name.to_ascii_lowercase(), module))
        .collect::<BTreeMap<_, _>>();
    require(
        companions.len() == lock.loaded_module_policy.driver_store_companions.len()
            && companions.len() == 2
            && companions.contains_key("nvcuda64.dll")
            && companions.contains_key("nvml.driverstore.dll"),
        "DriverStore companion identity/cardinality mismatch",
    )?;
    for (attestation_name, companion) in companions {
        require(
            ((attestation_name == "nvcuda64.dll"
                && companion.name.eq_ignore_ascii_case("nvcuda64.dll")
                && companion.owner.eq_ignore_ascii_case("nvcuda.dll"))
                || (attestation_name == "nvml.driverstore.dll"
                    && companion.name.eq_ignore_ascii_case("nvml.dll")
                    && companion.owner.eq_ignore_ascii_case("nvml.dll")))
                && companion
                    .required_root
                    .eq_ignore_ascii_case("%SystemRoot%\\System32\\DriverStore\\FileRepository")
                && companion.signature_kind == "catalog"
                && companion.signer_organization == "Microsoft Corporation"
                && companion.signed_company_name == "NVIDIA Corporation"
                && companion.require_same_catalog
                && companion.require_same_signer_certificate
                && companion.require_same_file_version
                && companion.require_same_product_name,
            "DriverStore companion trust policy differs from the Windows NVIDIA driver contract",
        )?;
    }
    require(
        !lock.loaded_module_policy.bundle_module_globs.is_empty(),
        "bundle module globs are empty",
    )?;

    let artifact_ids = lock
        .artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<BTreeSet<_>>();
    require(
        artifact_ids.len() == lock.artifacts.len()
            && artifact_ids.len() == REQUIRED_ARTIFACT_VERSIONS.len(),
        "artifact identity/cardinality mismatch",
    )?;
    for (id, version) in REQUIRED_ARTIFACT_VERSIONS {
        require(
            lock.artifacts
                .iter()
                .any(|artifact| artifact.id == *id && artifact.version == *version),
            &format!("pinned artifact {id} {version} is missing"),
        )?;
    }
    for artifact in &lock.artifacts {
        require(
            !artifact.distribution.trim().is_empty()
                && !artifact.filename.trim().is_empty()
                && !artifact.url.trim().is_empty()
                && !artifact.license_expression.trim().is_empty()
                && artifact.bytes > 0,
            "artifact provenance is incomplete",
        )?;
        require(
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
        require_sha256(&artifact.sha256, "artifact")?;
    }

    let files = lock
        .files
        .iter()
        .map(|file| file.bundle_path.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let basenames = lock
        .files
        .iter()
        .map(|file| bundle_basename(&file.bundle_path).map(|name| name.to_ascii_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
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
    require(
        files.len() == lock.files.len(),
        "duplicate locked file path",
    )?;
    require(
        basenames.len() == lock.files.len(),
        "duplicate locked module basename",
    )?;
    require(
        boundary.len() == lock.loaded_module_policy.boundary_load.len()
            && preload.len() == lock.loaded_module_policy.dependency_preload_order.len()
            && ort_managed.len() == lock.loaded_module_policy.ort_managed_load.len(),
        "duplicate module load-phase path",
    )?;
    require(
        boundary.is_disjoint(&preload)
            && boundary.is_disjoint(&ort_managed)
            && preload.is_disjoint(&ort_managed),
        "module load phases overlap",
    )?;
    let mut scheduled = boundary.clone();
    scheduled.extend(preload.iter().cloned());
    scheduled.extend(ort_managed.iter().cloned());
    require(
        files == scheduled,
        "module load phases are not an exact file permutation",
    )?;
    require(
        boundary == BTreeSet::from([lock.contract.ort_dll.to_ascii_lowercase()]),
        "boundary load phase must contain only the ORT core",
    )?;
    require(
        ort_managed == BTreeSet::from([lock.contract.provider_dll.to_ascii_lowercase()]),
        "ORT-managed load phase must contain only the CUDA provider",
    )?;
    for file in &lock.files {
        require(
            artifact_ids.contains(file.artifact.as_str())
                && !file.archive_path.trim().is_empty()
                && !file.role.trim().is_empty()
                && file.bytes > 0
                && file.authenticode.status.eq_ignore_ascii_case("valid")
                && !file.authenticode.subject.trim().is_empty()
                && !file.authenticode.thumbprint.trim().is_empty()
                && file.bundle_path.to_ascii_lowercase().ends_with(".dll"),
            "locked file provenance is incomplete",
        )?;
        require_sha256(&file.sha256, "locked file")?;
        windows_relative_path(&file.bundle_path)?;
    }
    for notice in &lock.notices {
        require(
            artifact_ids.contains(notice.artifact.as_str())
                && !notice.archive_path.trim().is_empty()
                && notice.bytes > 0,
            "locked notice provenance is incomplete",
        )?;
        require_sha256(&notice.sha256, "locked notice")?;
        windows_relative_path(&notice.bundle_path)?;
    }
    for import in &lock.contract.direct_non_system_imports {
        require(
            basenames.contains(&import.to_ascii_lowercase()),
            "direct provider import is absent from the bundle",
        )?;
    }
    Ok(())
}

fn resolve_root(lock: &RuntimeLock, lock_sha256: &str) -> Result<PathBuf> {
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
    let expected = format!("{}-{lock_sha256}", lock.bundle.root_prefix);
    let actual = root.file_name().and_then(OsStr::to_str).ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_ROOT_IDENTITY_MISMATCH",
            format!("runtime root {} has no UTF-8 basename", root.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    if actual != expected {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_ROOT_IDENTITY_MISMATCH",
            format!("runtime root basename {actual} does not equal {expected}"),
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
    let app_dir = canonicalize_existing_dir(
        env::current_exe()
            .map_err(|error| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_APPLICATION_IDENTITY_UNAVAILABLE",
                    format!("resolve current executable failed: {error}"),
                    BUNDLE_REMEDIATION,
                )
            })?
            .parent()
            .ok_or_else(|| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_APPLICATION_IDENTITY_UNAVAILABLE",
                    "current executable has no parent directory",
                    BUNDLE_REMEDIATION,
                )
            })?,
        "application directory",
    )?;
    if path_is_within(&root, &app_dir) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_APPLICATION_DIR_REFUSED",
            format!(
                "runtime root {} is inside the application directory",
                root.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(root)
}

fn validate_bundle(
    root: &Path,
    lock: &RuntimeLock,
    lock_sha256: &str,
) -> Result<(BundleReceipt, String)> {
    verify_exact_bytes(&root.join(LOCK_FILE), LOCK_BYTES, "published lock")?;
    verify_exact_bytes(
        &root.join(LOCK_DIGEST_FILE),
        format!("{lock_sha256}\n").as_bytes(),
        "published lock digest",
    )?;
    let receipt_path = canonicalize_existing_file(&root.join(RECEIPT_FILE), "bundle receipt")?;
    reject_reparse_entry(&receipt_path, "bundle receipt")?;
    let receipt_bytes = fs::read(&receipt_path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
            format!("read {} failed: {error}", receipt_path.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    let receipt: BundleReceipt = serde_json::from_slice(&receipt_bytes).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
            format!("parse {} failed: {error}", receipt_path.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    require_bundle(
        receipt.schema == RECEIPT_SCHEMA,
        "unexpected receipt schema",
    )?;
    require_bundle(
        receipt.bundle_id == lock.bundle.id,
        "receipt bundle id mismatch",
    )?;
    require_bundle(
        receipt.lock_sha256 == lock_sha256,
        "receipt lock digest mismatch",
    )?;
    require_bundle(
        !receipt.provisioned_at_utc.trim().is_empty(),
        "receipt provenance is incomplete",
    )?;
    let receipt_artifacts = receipt
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    require_bundle(
        receipt_artifacts.len() == receipt.artifacts.len()
            && receipt_artifacts.len() == lock.artifacts.len(),
        "receipt artifact identity/cardinality mismatch",
    )?;
    for expected in &lock.artifacts {
        let actual = receipt_artifacts.get(expected.id.as_str()).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
                format!("receipt omits artifact {}", expected.id),
                BUNDLE_REMEDIATION,
            )
        })?;
        require_bundle(
            actual.filename == expected.filename
                && actual.bytes == expected.bytes
                && actual.sha256 == expected.sha256
                && actual.verification == expected.archive_verification,
            &format!("receipt artifact contract differs for {}", expected.id),
        )?;
        let locked_payload_count = lock
            .files
            .iter()
            .filter(|file| file.artifact == expected.id)
            .count()
            + lock
                .notices
                .iter()
                .filter(|notice| notice.artifact == expected.id)
                .count();
        require_bundle(
            actual.archive_entries > 0
                && actual.locked_payloads_verified == locked_payload_count as u64
                && match expected.archive_verification.as_str() {
                    "wheel-record-sha256" => {
                        actual.archive_entries == actual.manifest_entries
                            && actual.manifest_entries_verified == actual.manifest_entries
                            && actual.manifest_entries >= locked_payload_count as u64
                    }
                    "release-archive-sha256" => {
                        actual.manifest_entries == 0
                            && actual.manifest_entries_verified == 0
                            && actual.archive_entries >= locked_payload_count as u64
                    }
                    _ => false,
                },
            &format!(
                "receipt artifact verification counts are invalid for {}",
                expected.id
            ),
        )?;
    }

    let mut allowed = BTreeSet::from([
        LOCK_FILE.to_ascii_lowercase(),
        LOCK_DIGEST_FILE.to_ascii_lowercase(),
        RECEIPT_FILE.to_ascii_lowercase(),
    ]);
    let receipt_files = receipt
        .files
        .iter()
        .map(|file| (file.path.to_ascii_lowercase(), file))
        .collect::<BTreeMap<_, _>>();
    let receipt_notices = receipt
        .notices
        .iter()
        .map(|notice| (notice.path.to_ascii_lowercase(), notice))
        .collect::<BTreeMap<_, _>>();
    for file in &lock.files {
        let relative = file.bundle_path.to_ascii_lowercase();
        let receipt_file = receipt_files.get(&relative).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
                format!("receipt omits {}", file.bundle_path),
                BUNDLE_REMEDIATION,
            )
        })?;
        require_bundle(
            receipt_file.bytes == file.bytes
                && receipt_file.sha256 == file.sha256
                && receipt_file.file_version == file.file_version
                && receipt_file.authenticode.status == file.authenticode.status
                && receipt_file.authenticode.subject == file.authenticode.subject
                && receipt_file.authenticode.thumbprint == file.authenticode.thumbprint,
            &format!("receipt contract differs for {}", file.bundle_path),
        )?;
        verify_locked_file(root, &file.bundle_path, file.bytes, &file.sha256)?;
        allowed.insert(relative);
    }
    for notice in &lock.notices {
        let relative = notice.bundle_path.to_ascii_lowercase();
        let receipt_notice = receipt_notices.get(&relative).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
                format!("receipt omits {}", notice.bundle_path),
                BUNDLE_REMEDIATION,
            )
        })?;
        require_bundle(
            receipt_notice.bytes == notice.bytes && receipt_notice.sha256 == notice.sha256,
            &format!("receipt contract differs for {}", notice.bundle_path),
        )?;
        verify_locked_file(root, &notice.bundle_path, notice.bytes, &notice.sha256)?;
        allowed.insert(relative);
    }
    require_bundle(
        receipt_files.len() == lock.files.len() && receipt_notices.len() == lock.notices.len(),
        "receipt contains unlocked entries",
    )?;
    let observed = enumerate_bundle_paths(root)?;
    require_bundle(
        observed == allowed,
        "bundle contains missing or unlocked paths",
    )?;
    Ok((receipt, sha256_bytes(&receipt_bytes)))
}

fn reject_system32_aliases(system32: &Path, lock: &RuntimeLock) -> Result<()> {
    let exact = lock
        .files
        .iter()
        .filter_map(|file| bundle_basename(&file.bundle_path).ok())
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    for candidate in cudarc_candidate_basenames() {
        if candidate.eq_ignore_ascii_case("nvcuda.dll") || exact.contains(&candidate) {
            continue;
        }
        if system32.join(&candidate).exists() {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_AMBIENT_MODULE",
                format!("forbidden cudarc alias {} exists in System32", candidate),
                "remove the unowned CUDA alias from System32, repair the NVIDIA driver if needed, and restart",
            ));
        }
    }
    Ok(())
}

fn cudarc_candidate_basenames() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for logical in ["cuda", "nvcuda", "cublas", "cublasLt", "curand", "nvrtc"] {
        for candidate in [
            format!("{logical}.dll"),
            format!("{logical}64.dll"),
            format!("{logical}64_13.dll"),
            format!("{logical}64_133.dll"),
            format!("{logical}64_133_0.dll"),
            format!("{logical}64_130_3.dll"),
            format!("{logical}64_10.dll"),
            format!("{logical}64_11.dll"),
            format!("{logical}64_12.dll"),
            format!("{logical}64_130_0.dll"),
            format!("{logical}64_9.dll"),
            format!("{logical}.dll.13"),
            format!("{logical}.dll.12"),
            format!("{logical}.dll.11"),
            format!("{logical}.dll.10"),
            format!("{logical}.dll.9"),
            format!("{logical}.dll.1"),
        ] {
            out.insert(candidate.to_ascii_lowercase());
        }
    }
    out
}

fn reject_ambient_modules(
    lock: &RuntimeLock,
    root: &Path,
    system32: &Path,
    modules: &[PathBuf],
    require_cuda: bool,
    allow_ort_managed: bool,
) -> Result<()> {
    let expected = expected_module_paths(lock, root, system32, require_cuda)?;
    let permitted_ort_managed = if allow_ort_managed {
        expected_ort_managed_paths(lock, root)?
    } else {
        BTreeMap::new()
    };
    for module in modules {
        let Some(name) = module.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        let managed = lock
            .loaded_module_policy
            .bundle_module_globs
            .iter()
            .any(|pattern| wildcard_match(pattern, name))
            || cudarc_candidate_basenames().contains(&lower)
            || SYSTEM_MODULES.iter().any(|system| lower == *system);
        if !managed {
            continue;
        }
        let canonical = canonicalize_existing_file(module, "loaded CUDA module")?;
        match expected
            .get(&lower)
            .or_else(|| permitted_ort_managed.get(&lower))
        {
            Some(required) if same_path(&canonical, required) => {}
            Some(required) => {
                if require_cuda {
                    if let Some(policy) = driver_store_companion_policy(lock, &lower) {
                        let owner = verify_locked_system_module(lock, system32, &policy.owner)?;
                        let _companion = verify_locked_driver_store_companion(
                            system32,
                            policy,
                            &canonical,
                            owner.attestation(),
                        )?;
                        continue;
                    }
                }
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_AMBIENT_MODULE",
                    format!(
                        "{name} is loaded from {}; exact required path is {}",
                        canonical.display(),
                        required.display()
                    ),
                    BUNDLE_REMEDIATION,
                ));
            }
            None if require_cuda => {
                let Some(policy) = driver_store_companion_policy(lock, &lower) else {
                    return Err(runtime_error(
                        "CALYX_ONNX_RUNTIME_AMBIENT_MODULE",
                        format!(
                            "unowned CUDA alias {name} is loaded from {}",
                            canonical.display()
                        ),
                        BUNDLE_REMEDIATION,
                    ));
                };
                let owner = verify_locked_system_module(lock, system32, &policy.owner)?;
                let _companion = verify_locked_driver_store_companion(
                    system32,
                    policy,
                    &canonical,
                    owner.attestation(),
                )?;
            }
            None => {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_AMBIENT_MODULE",
                    format!(
                        "unowned CUDA alias {name} is loaded from {}",
                        canonical.display()
                    ),
                    BUNDLE_REMEDIATION,
                ));
            }
        }
    }
    Ok(())
}

fn attest_modules(
    lock: &RuntimeLock,
    root: &Path,
    system32: &Path,
    modules: &[PathBuf],
    require_cuda: bool,
    // NVIDIA maps the CUDA and NVML DriverStore implementations lazily on the first
    // real API calls. Dependency preload accepts absence; post-driver-use refreshes do not.
    require_driver_store_companions: bool,
    allow_ort_managed: bool,
) -> Result<AttestedModuleSet> {
    reject_ambient_modules(
        lock,
        root,
        system32,
        modules,
        require_cuda,
        allow_ort_managed,
    )?;
    let expected = expected_module_paths(lock, root, system32, require_cuda)?;
    let companion_names = require_cuda
        .then(|| {
            lock.loaded_module_policy
                .driver_store_companions
                .iter()
                .map(|policy| policy.name.to_ascii_lowercase())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut loaded = BTreeMap::<String, Vec<&PathBuf>>::new();
    for module in modules {
        let Some(name) = module.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        let key = name.to_ascii_lowercase();
        if expected.contains_key(&key) || companion_names.contains(&key) {
            loaded.entry(key).or_default().push(module);
        }
    }
    let file_contracts = lock
        .files
        .iter()
        .map(|file| {
            Ok((
                bundle_basename(&file.bundle_path)?.to_ascii_lowercase(),
                file,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut out = Vec::with_capacity(expected.len() + companion_names.len());
    let mut driver_store_handles = ModuleStack::with_capacity(companion_names.len());
    for (name, required) in expected {
        let candidates = loaded.get(&name).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_MODULE_NOT_LOADED",
                format!("required CUDA module {name} is absent from the process"),
                BUNDLE_REMEDIATION,
            )
        })?;
        let mut exact = candidates
            .iter()
            .map(|observed| canonicalize_existing_file(observed, "loaded CUDA module"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|canonical| same_path(canonical, &required))
            .collect::<Vec<_>>();
        if exact.len() != 1 {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_MODULE_IDENTITY_AMBIGUOUS",
                format!(
                    "required CUDA module {name} has {} exact loaded instances at {}; observed candidates: {}",
                    exact.len(),
                    required.display(),
                    candidates
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                BUNDLE_REMEDIATION,
            ));
        }
        let canonical = exact.remove(0);
        if let Some(file) = file_contracts.get(&name) {
            verify_locked_file(root, &file.bundle_path, file.bytes, &file.sha256)?;
            out.push(PinnedCudaModuleAttestation {
                name,
                path: canonical,
                bytes: file.bytes,
                sha256: file.sha256.clone(),
                file_version: file.file_version.clone(),
                source: format!("bundle:{}", file.artifact),
                system_trust: None,
            });
        } else {
            let verified = verify_locked_system_module(lock, system32, &name)?;
            let trust = verified.attestation().clone();
            if !same_path(verified.path(), &canonical) {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_SYSTEM_TRUST_PATH_MISMATCH",
                    format!(
                        "system trust resolved {} to {}; loaded path is {}",
                        name,
                        verified.path().display(),
                        canonical.display()
                    ),
                    BUNDLE_REMEDIATION,
                ));
            }
            out.push(PinnedCudaModuleAttestation {
                name,
                path: canonical.clone(),
                bytes: trust.file_bytes,
                sha256: trust.file_sha256.clone(),
                file_version: Some(trust.signed_file_version.clone()),
                source: "system-driver:system32+catalog-authenticode+version-info".to_string(),
                system_trust: Some(trust),
            });
        }
    }
    if require_cuda {
        for policy in &lock.loaded_module_policy.driver_store_companions {
            let loaded_name = policy.name.to_ascii_lowercase();
            let owner = out
                .iter()
                .find(|module| module.name.eq_ignore_ascii_case(&policy.owner))
                .and_then(|module| {
                    module
                        .system_trust
                        .as_ref()
                        .map(|trust| (module.path.clone(), trust.clone()))
                })
                .ok_or_else(|| {
                    runtime_error(
                        "CALYX_ONNX_RUNTIME_SYSTEM_TRUST_MISSING",
                        format!(
                            "DriverStore companion {} has no verified owner receipt for {}",
                            policy.name, policy.owner
                        ),
                        BUNDLE_REMEDIATION,
                    )
                })?;
            let mut companion_paths = loaded
                .get(&loaded_name)
                .into_iter()
                .flatten()
                .map(|observed| {
                    canonicalize_existing_file(observed, "loaded DriverStore companion")
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|canonical| !same_path(canonical, &owner.0))
                .collect::<Vec<_>>();
            if companion_paths.is_empty() {
                if require_driver_store_companions {
                    return Err(runtime_error(
                        "CALYX_ONNX_RUNTIME_MODULE_NOT_LOADED",
                        format!(
                            "required signed DriverStore companion {} for {} is absent after the CUDA Driver API was exercised",
                            policy.name, policy.owner
                        ),
                        BUNDLE_REMEDIATION,
                    ));
                }
                continue;
            }
            if companion_paths.len() != 1 {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_MODULE_IDENTITY_AMBIGUOUS",
                    format!(
                        "DriverStore companion {} for {} has {} non-owner loaded instances: {}",
                        policy.name,
                        policy.owner,
                        companion_paths.len(),
                        companion_paths
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    BUNDLE_REMEDIATION,
                ));
            }
            let canonical = companion_paths.remove(0);
            let verified =
                verify_locked_driver_store_companion(system32, policy, &canonical, &owner.1)?;
            let trust = verified.attestation().clone();
            let retained_handle = load_exact_library(
                &canonical,
                ModuleFileGuard::System {
                    _verified: verified,
                },
            )?;
            out.push(PinnedCudaModuleAttestation {
                name: policy.attestation_name.to_ascii_lowercase(),
                path: canonical,
                bytes: trust.file_bytes,
                sha256: trust.file_sha256.clone(),
                file_version: Some(trust.signed_file_version.clone()),
                source: format!(
                    "system-driver:driverstore-companion;owner={};catalog+signer+version+product-bound",
                    policy.owner.to_ascii_lowercase()
                ),
                system_trust: Some(trust),
            });
            driver_store_handles.push(retained_handle);
        }
    }
    out.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(AttestedModuleSet {
        modules: out,
        driver_store_handles,
    })
}

fn verify_locked_system_module(
    lock: &RuntimeLock,
    system32: &Path,
    name: &str,
) -> Result<VerifiedSystemFile> {
    let policy = lock
        .loaded_module_policy
        .system_modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_SYSTEM_POLICY_MISSING",
                format!("the runtime lock has no system-module trust policy for {name}"),
                CONTRACT_REMEDIATION,
            )
        })?;
    if !policy
        .required_root
        .eq_ignore_ascii_case("%SystemRoot%\\System32")
    {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
            format!(
                "system-module {} requires unsupported root token {}; expected literal %SystemRoot%\\System32",
                policy.name, policy.required_root
            ),
            CONTRACT_REMEDIATION,
        ));
    }
    let required_root = system32.to_path_buf();
    verify_system_module(
        &required_root.join(&policy.name),
        &SystemModuleTrustPolicy {
            module_name: policy.name.clone(),
            required_root,
            authenticode_signer_organization: policy.signer_organization.clone(),
            signed_company_name: policy.signed_company_name.clone(),
        },
    )
}

fn driver_store_companion_policy<'a>(
    lock: &'a RuntimeLock,
    name: &str,
) -> Option<&'a DriverStoreCompanionPolicy> {
    lock.loaded_module_policy
        .driver_store_companions
        .iter()
        .find(|policy| policy.name.eq_ignore_ascii_case(name))
}

fn verify_locked_driver_store_companion(
    system32: &Path,
    policy: &DriverStoreCompanionPolicy,
    path: &Path,
    owner: &SystemModuleTrustAttestation,
) -> Result<VerifiedSystemFile> {
    verify_driver_store_companion(
        path,
        &SystemModuleTrustPolicy {
            module_name: policy.name.clone(),
            required_root: system32.join("DriverStore").join("FileRepository"),
            authenticode_signer_organization: policy.signer_organization.clone(),
            signed_company_name: policy.signed_company_name.clone(),
        },
        owner,
    )
}

fn expected_module_paths(
    lock: &RuntimeLock,
    root: &Path,
    system32: &Path,
    require_cuda: bool,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    let scheduled = lock.loaded_module_policy.boundary_load.iter().chain(
        require_cuda
            .then_some(lock.loaded_module_policy.dependency_preload_order.iter())
            .into_iter()
            .flatten(),
    );
    for bundle_path in scheduled {
        let file = lock
            .files
            .iter()
            .find(|file| file.bundle_path.eq_ignore_ascii_case(bundle_path))
            .ok_or_else(|| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                    format!("module load phase references unlocked path {bundle_path}"),
                    CONTRACT_REMEDIATION,
                )
            })?;
        let name = bundle_basename(&file.bundle_path)?.to_ascii_lowercase();
        let path = canonicalize_existing_file(
            &root.join(windows_relative_path(&file.bundle_path)?),
            "locked CUDA module",
        )?;
        out.insert(name, path);
    }
    if require_cuda {
        for name in SYSTEM_MODULES {
            out.insert(
                name.to_string(),
                canonicalize_existing_file(&system32.join(name), "NVIDIA system module")?,
            );
        }
    }
    Ok(out)
}

fn expected_ort_managed_paths(
    lock: &RuntimeLock,
    root: &Path,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    for bundle_path in &lock.loaded_module_policy.ort_managed_load {
        let file = lock
            .files
            .iter()
            .find(|file| file.bundle_path.eq_ignore_ascii_case(bundle_path))
            .ok_or_else(|| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                    format!("ORT-managed load phase references unlocked path {bundle_path}"),
                    CONTRACT_REMEDIATION,
                )
            })?;
        out.insert(
            bundle_basename(&file.bundle_path)?.to_ascii_lowercase(),
            canonicalize_existing_file(
                &root.join(windows_relative_path(&file.bundle_path)?),
                "locked ORT-managed module",
            )?,
        );
    }
    Ok(out)
}

fn open_locked_ort_managed_modules(
    lock: &RuntimeLock,
    root: &Path,
) -> Result<(
    Vec<PinnedCudaOrtManagedModuleAttestation>,
    Vec<VerifiedBundleFile>,
)> {
    let expected = expected_ort_managed_paths(lock, root)?;
    let files = lock
        .files
        .iter()
        .map(|file| {
            Ok((
                bundle_basename(&file.bundle_path)?.to_ascii_lowercase(),
                file,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut out = Vec::with_capacity(expected.len());
    let mut guards = Vec::with_capacity(expected.len());
    for (name, path) in expected {
        let file = files.get(&name).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                format!("ORT-managed module {name} has no file contract"),
                CONTRACT_REMEDIATION,
            )
        })?;
        let guard = open_verified_locked_file(root, &file.bundle_path, file.bytes, &file.sha256)?;
        if !same_path(&guard.path, &path) {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_FILE_CHANGED",
                format!(
                    "retained ORT-managed file handle resolves to {}; expected {}",
                    guard.path.display(),
                    path.display()
                ),
                BUNDLE_REMEDIATION,
            ));
        }
        out.push(PinnedCudaOrtManagedModuleAttestation {
            name,
            path,
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            file_version: file.file_version.clone(),
            source: format!("bundle:{}", file.artifact),
            loader: "onnxruntime-provider-api".to_string(),
            state: "validated-not-directly-mapped".to_string(),
        });
        guards.push(guard);
    }
    out.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((out, guards))
}

fn enumerate_bundle_paths(root: &Path) -> Result<BTreeSet<String>> {
    fn visit(root: &Path, current: &Path, out: &mut BTreeSet<String>) -> Result<()> {
        for entry in fs::read_dir(current).map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_DIRECTORY_UNREADABLE",
                format!("read {} failed: {error}", current.display()),
                BUNDLE_REMEDIATION,
            )
        })? {
            let entry = entry.map_err(|error| {
                runtime_error(
                    "CALYX_ONNX_RUNTIME_DIRECTORY_UNREADABLE",
                    format!("read entry under {} failed: {error}", current.display()),
                    BUNDLE_REMEDIATION,
                )
            })?;
            let path = entry.path();
            reject_reparse_entry(&path, "bundle entry")?;
            if path.is_dir() {
                visit(root, &path, out)?;
            } else if path.is_file() {
                let relative = path.strip_prefix(root).map_err(|error| {
                    runtime_error(
                        "CALYX_ONNX_RUNTIME_PATH_ESCAPE",
                        format!("strip root from {} failed: {error}", path.display()),
                        BUNDLE_REMEDIATION,
                    )
                })?;
                out.insert(
                    relative
                        .to_string_lossy()
                        .replace('\\', "/")
                        .to_ascii_lowercase(),
                );
            } else {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_UNLOCKED_ENTRY",
                    format!("unsupported bundle entry {}", path.display()),
                    BUNDLE_REMEDIATION,
                ));
            }
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    visit(root, root, &mut out)?;
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
                    BUNDLE_REMEDIATION,
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
                        BUNDLE_REMEDIATION,
                    )
                })?;
            }
        }
        return Ok(out);
    }
}

fn load_locked_bundle_library(root: &Path, contract: &FileContract) -> Result<OwnedModule> {
    let verified = open_verified_locked_file(
        root,
        &contract.bundle_path,
        contract.bytes,
        &contract.sha256,
    )?;
    let path = verified.path.clone();
    load_exact_library(
        &path,
        ModuleFileGuard::Bundle {
            _verified: verified,
        },
    )
}

fn load_exact_library(path: &Path, file_guard: ModuleFileGuard) -> Result<OwnedModule> {
    let wide = wide_path(path);
    let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), flags) };
    if module.is_null() {
        return Err(last_windows_error(format!(
            "LoadLibraryExW exact {}",
            path.display()
        )));
    }
    Ok(OwnedModule {
        handle: module as usize,
        _file_guard: file_guard,
    })
}

fn verify_locked_file(root: &Path, relative: &str, bytes: u64, sha256: &str) -> Result<()> {
    open_verified_locked_file(root, relative, bytes, sha256).map(|_| ())
}

fn open_verified_locked_file(
    root: &Path,
    relative: &str,
    bytes: u64,
    sha256: &str,
) -> Result<VerifiedBundleFile> {
    let requested = root.join(windows_relative_path(relative)?);
    reject_reparse_entry(&requested, "locked runtime file")?;
    let path = canonicalize_existing_file(&requested, "locked runtime file")?;
    reject_reparse_entry(&path, "locked runtime file")?;
    if !path_is_within(&path, root) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_PATH_ESCAPE",
            format!(
                "locked runtime file {} resolves outside bundle root {}",
                path.display(),
                root.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
                format!(
                    "open {} with read-only sharing failed: {error}",
                    path.display()
                ),
                BUNDLE_REMEDIATION,
            )
        })?;
    let handle_path = final_path(&file)?;
    if !same_path(&handle_path, &path) {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_CHANGED",
            format!(
                "opened runtime handle resolves to {}; expected {}",
                handle_path.display(),
                path.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let actual_bytes = file
        .metadata()
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
                format!("stat open handle for {} failed: {error}", path.display()),
                BUNDLE_REMEDIATION,
            )
        })?
        .len();
    if actual_bytes != bytes {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_SIZE_MISMATCH",
            format!(
                "{} has {actual_bytes} bytes; lock requires {bytes}",
                path.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let actual = sha256_open_file(&file, &path, actual_bytes)?;
    if actual != sha256 {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_HASH_MISMATCH",
            format!(
                "{} SHA256 is {actual}; lock requires {sha256}",
                path.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(VerifiedBundleFile { _file: file, path })
}

fn verify_exact_bytes(path: &Path, expected: &[u8], label: &str) -> Result<()> {
    let path = canonicalize_existing_file(path, label)?;
    reject_reparse_entry(&path, label)?;
    let observed = fs::read(&path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
            format!("read {} failed: {error}", path.display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    if observed != expected {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_LOCK_MISMATCH",
            format!("{label} {} differs from embedded bytes", path.display()),
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
                BUNDLE_REMEDIATION,
            ));
        }
    }
    Ok(())
}

fn windows_relative_path(raw: &str) -> Result<PathBuf> {
    let normalized = raw.replace('/', "\\");
    let path = PathBuf::from(&normalized);
    if normalized.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
            format!("runtime lock path is not safe and relative: {raw}"),
            CONTRACT_REMEDIATION,
        ));
    }
    Ok(path)
}

fn bundle_basename(raw: &str) -> Result<String> {
    windows_relative_path(raw)?
        .file_name()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
                format!("runtime lock path has no UTF-8 basename: {raw}"),
                CONTRACT_REMEDIATION,
            )
        })
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

fn system_directory() -> Result<PathBuf> {
    let mut capacity = 512usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        let written =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if written == 0 {
            return Err(last_windows_error("GetSystemDirectoryW"));
        }
        if written < buffer.len() {
            buffer.truncate(written);
            if buffer.is_empty() || buffer.contains(&0) {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_SYSTEM_ROOT_INVALID",
                    "GetSystemDirectoryW returned an empty path or interior NUL",
                    "repair the Windows installation and restart Astrolabe",
                ));
            }
            let requested = PathBuf::from(OsString::from_wide(&buffer));
            reject_reparse_entry(&requested, "OS System32 directory")?;
            let canonical = canonicalize_existing_dir(&requested, "OS System32 directory")?;
            reject_reparse_entry(&canonical, "canonical OS System32 directory")?;
            return Ok(canonical);
        }
        capacity = written.checked_add(1).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_SYSTEM_ROOT_INVALID",
                "GetSystemDirectoryW required path length overflowed usize",
                "repair the Windows installation and restart Astrolabe",
            )
        })?;
        if capacity > MAX_FINAL_PATH_CHARS {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_SYSTEM_ROOT_INVALID",
                format!("GetSystemDirectoryW required {capacity} UTF-16 code units"),
                "repair the Windows installation and restart Astrolabe",
            ));
        }
    }
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

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let mut offset = 0usize;
    for (index, part) in parts.iter().enumerate() {
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

fn final_path(file: &File) -> Result<PathBuf> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut capacity = 512usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        } as usize;
        if written == 0 {
            return Err(last_windows_error("GetFinalPathNameByHandleW"));
        }
        if written < buffer.len() {
            buffer.truncate(written);
            if buffer.contains(&0) {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_FILE_CHANGED",
                    "opened runtime handle path contains an interior NUL",
                    BUNDLE_REMEDIATION,
                ));
            }
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity = written.checked_add(1).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_MODULE_PATH_OVERFLOW",
                "opened runtime handle path length overflowed",
                BUNDLE_REMEDIATION,
            )
        })?;
        if capacity > MAX_FINAL_PATH_CHARS {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_MODULE_PATH_OVERFLOW",
                format!("opened runtime handle path requires {capacity} UTF-16 characters"),
                BUNDLE_REMEDIATION,
            ));
        }
    }
}

fn sha256_open_file(file: &File, path: &Path, expected_bytes: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut offset = 0u64;
    loop {
        let count = file.seek_read(&mut buffer, offset).map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
                format!(
                    "read {} for SHA256 at offset {offset} failed: {error}",
                    path.display()
                ),
                BUNDLE_REMEDIATION,
            )
        })?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        offset = offset.checked_add(count as u64).ok_or_else(|| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_FILE_UNREADABLE",
                format!("{} length overflowed during SHA256", path.display()),
                BUNDLE_REMEDIATION,
            )
        })?;
    }
    if offset != expected_bytes {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_FILE_CHANGED",
            format!(
                "read {offset} bytes from {}; open-handle metadata reported {expected_bytes}",
                path.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    require(
        value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && value == value.to_ascii_lowercase(),
        &format!("{label} SHA256 is not lowercase hexadecimal"),
    )
}

fn require(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(runtime_error(
            "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
            detail,
            CONTRACT_REMEDIATION,
        ))
    }
}

fn require_bundle(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(runtime_error(
            "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
            detail,
            BUNDLE_REMEDIATION,
        ))
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn last_windows_error(operation: impl Into<String>) -> ForgeError {
    let operation = operation.into();
    let code = unsafe { GetLastError() };
    runtime_error(
        "CALYX_ONNX_RUNTIME_WINDOWS_LOAD_FAILED",
        format!("{operation} failed with Windows error {code}"),
        BUNDLE_REMEDIATION,
    )
}

fn runtime_error(
    code: &'static str,
    detail: impl Into<String>,
    remediation: &'static str,
) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code,
        detail: detail.into(),
        remediation,
    }
}
