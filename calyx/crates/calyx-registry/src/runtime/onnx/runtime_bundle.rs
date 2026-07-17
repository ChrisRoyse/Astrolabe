#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CStr, OsStr, c_char};
use std::fs::{self, File};
use std::io::Read;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use calyx_core::{CalyxError, Result};
use ort::ep::{CUDA, ExecutionProvider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    SetDefaultDllDirectories,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::OnnxProviderPolicy;

const RUNTIME_ROOT_ENV: &str = "CALYX_CUDA13_RUNTIME_ROOT";
const LOCK_SCHEMA: &str = "astrolabe.windows-ort-cuda-runtime-lock.v2";
const RECEIPT_FILE: &str = "bundle.receipt.json";
const EXPECTED_LAYOUT: &str = "flat-bin-v1";
const EXPECTED_PLATFORM: &str = "windows-x86_64";
const EXPECTED_ROOT_PREFIX: &str = "ort-cuda13.3-windows-x86_64";
const EXPECTED_ORT_VERSION: &str = "1.26.0";
const EXPECTED_ORT_FILE_VERSION: &str = "1.26.20260504.3.55c5c82";
const EXPECTED_PROVIDER: &str = "CUDAExecutionProvider";
const EXPECTED_ORT_DLL: &str = "onnxruntime.dll";
const EXPECTED_CUDA_PROVIDER_DLL: &str = "onnxruntime_providers_cuda.dll";
const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;
const LEGACY_RUNTIME_ENVS: &[&str] = &["ORT_DYLIB_PATH", "CALYX_ORT_CAPI", "CALYX_NVIDIA_DLL_DIRS"];
const REQUIRED_ARTIFACT_VERSIONS: &[(&str, &str)] = &[
    ("onnxruntime", "1.26.0"),
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
    pub license_expression: String,
}

pub type OnnxCudaDeviceAttestation = calyx_forge::PinnedCudaDeviceAttestation;

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
        );
        if let Err(error) = refresh {
            state.cuda_failure = Some(error.clone());
            return Err(error);
        }
    }
    Ok(state.live.as_ref().map(|live| live.receipt.clone()))
}

/// Establishes the process-wide, hash-attested CUDA DLL search boundary.
///
/// This initializes only the pinned ORT core and exact DLL directory. CUDA
/// provider and device initialization remain deferred until a CUDA policy is
/// selected, so an explicitly commissioned CPU runtime can still start on a
/// machine without a usable GPU. CUDA-enabled process entry points call this
/// before any `cudarc`, Candle, FastEmbed, or ORT API can resolve a DLL.
pub fn initialize_pinned_cuda_runtime_boundary() -> Result<OnnxRuntimeAttestation> {
    ensure_runtime(OnnxProviderPolicy::CpuExplicit)?;
    current_runtime_attestation()?.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_ATTESTATION_MISSING",
            "pinned CUDA runtime boundary initialized without a live attestation",
            "terminate the process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })
}

pub(super) fn ensure_runtime(policy: OnnxProviderPolicy) -> Result<PathBuf> {
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
    if policy == OnnxProviderPolicy::CudaFailLoud {
        if let Some(error) = &state.cuda_failure {
            return Err(error.clone());
        }
        let live = state.live.as_mut().expect("initialized above");
        if !live.receipt.provider_available {
            if let Err(error) = initialize_cuda(live) {
                state.cuda_failure = Some(error.clone());
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

pub(super) fn selected_cuda_device(
    policy: OnnxProviderPolicy,
) -> Result<Option<OnnxCudaDeviceAttestation>> {
    if policy != OnnxProviderPolicy::CudaFailLoud {
        return Ok(None);
    }
    let requested = super::session::configured_cuda_device()?;
    let requested_u32 = u32::try_from(requested).map_err(|_| {
        runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_INVALID",
            format!("configured CUDA Runtime ordinal {requested} exceeds u32"),
            "set CALYX_CUDA_DEVICE to a CUDA Runtime-visible ordinal",
        )
    })?;
    ensure_runtime(policy)?;
    let shared = calyx_forge::select_pinned_cuda_device(requested_u32)
        .map_err(forge_runtime_boundary_error)?;
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

pub(super) fn attest_after_model_constructor(
    policy: OnnxProviderPolicy,
    bound_stream: Option<&super::green_context::GreenContextHandle>,
) -> Result<()> {
    if policy != OnnxProviderPolicy::CudaFailLoud {
        if bound_stream.is_some() {
            return Err(runtime_error(
                "CALYX_ONNX_CPU_SESSION_HAS_CUDA_STREAM",
                "CPU-policy ONNX constructor retained a CUDA execution stream",
                "construct CPU and CUDA companion lenses through distinct provider policies",
            ));
        }
        return Ok(());
    }
    ensure_runtime(policy)?;
    let receipt = current_runtime_attestation()?.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_ATTESTATION_MISSING",
            "CUDA model construction completed without a live runtime attestation",
            "terminate the process, preserve its logs, and restart from the pinned runtime bundle",
        )
    })?;
    let selected = receipt.cuda_device.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISSING",
            "CUDA model construction completed without a selected physical-device receipt",
            "terminate the process and restart from the pinned CUDA runtime boundary",
        )
    })?;
    let stream = bound_stream.ok_or_else(|| {
        runtime_error(
            "CALYX_ONNX_BOUND_STREAM_MISSING",
            "CUDA model construction did not retain an Astrolabe-owned execution stream",
            "construct the CUDA EP with an attested compute stream and retain it for the full model lifetime",
        )
    })?;
    super::green_context::attest_selected_stream(stream, &selected)
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
    record: String,
    metadata: String,
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
    bundle_load_order: Vec<String>,
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
    let committed = ort::init_from(&core_path)
        .map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_INIT_FAILED",
                format!(
                    "initialize exact ORT core {} failed: {error}",
                    core_path.display()
                ),
                BUNDLE_REMEDIATION,
            )
        })?
        .commit();
    if !committed {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_PREINITIALIZED",
            "ORT global environment was configured before Calyx could commit the pinned runtime",
            "terminate the process and ensure every ONNX consumer calls the Calyx runtime boundary before any ort API",
        ));
    }
    let modules = attest_loaded_modules(&lock, &root)?;
    let mut module_handles = ModuleStack::with_capacity(2);
    module_handles.push(core_handle);
    Ok(LiveRuntime {
        lock: lock.clone(),
        core_path,
        _module_handles: module_handles,
        receipt: OnnxRuntimeAttestation {
            schema: "calyx-onnx-runtime-attestation-v3".to_string(),
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

fn initialize_cuda(live: &mut LiveRuntime) -> Result<()> {
    let lock_sha256 = sha256_bytes(LOCK_BYTES);
    let boundary = calyx_forge::cuda_runtime::initialize_pinned_cuda_dependencies()
        .map_err(forge_runtime_boundary_error)?;
    validate_forge_boundary(&boundary, &live.lock, &lock_sha256, true)?;
    let requested = super::session::configured_cuda_device()?;
    let requested = u32::try_from(requested).map_err(|_| {
        runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_INVALID",
            format!("configured CUDA Runtime ordinal {requested} exceeds u32"),
            "set CALYX_CUDA_DEVICE to a CUDA Runtime-visible ordinal",
        )
    })?;
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
    let available = CUDA::default().is_available().map_err(|error| {
        runtime_error(
            "CALYX_ONNX_CUDA_PROVIDER_QUERY_FAILED",
            format!("query {EXPECTED_PROVIDER} availability from pinned ORT failed: {error}"),
            BUNDLE_REMEDIATION,
        )
    })?;
    if !available {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_PROVIDER_UNAVAILABLE",
            format!(
                "pinned ORT {} does not report {EXPECTED_PROVIDER}",
                live.core_path.display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    refresh_cuda_module_attestation(live, &lock_sha256)?;
    live.receipt.provider_available = true;
    live.receipt.cuda_device = Some(device);
    Ok(())
}

fn refresh_cuda_module_attestation(live: &mut LiveRuntime, lock_sha256: &str) -> Result<()> {
    let boundary = calyx_forge::cuda_runtime::attest_pinned_cuda_dependencies()
        .map_err(forge_runtime_boundary_error)?;
    validate_forge_boundary(&boundary, &live.lock, lock_sha256, true)?;
    live.receipt.modules = boundary
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
        .collect();
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
        boundary.schema == "calyx-pinned-cuda-runtime-attestation-v2",
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
    let mut expected_names = locked
        .keys()
        .filter(|name| require_cuda || basename_eq(name, &lock.contract.ort_dll))
        .cloned()
        .collect::<BTreeSet<_>>();
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
        lock.contract.api_non_null == [24, 25, 26],
        "unexpected api_non_null contract",
    )?;
    require_contract(
        lock.contract.first_api_null == 27,
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
            !artifact.record.trim().is_empty(),
            "artifact RECORD path is empty",
        )?;
        require_contract(
            !artifact.metadata.trim().is_empty(),
            "artifact METADATA path is empty",
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
    let load_order = lock
        .loaded_module_policy
        .bundle_load_order
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    require_contract(
        load_order.len() == lock.loaded_module_policy.bundle_load_order.len(),
        "bundle load order contains duplicate paths",
    )?;
    require_contract(
        load_order
            == lock
                .files
                .iter()
                .map(|file| file.bundle_path.to_ascii_lowercase())
                .collect(),
        "bundle load order must name every locked DLL exactly once",
    )?;
    for path in &lock.loaded_module_policy.bundle_load_order {
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

fn runtime_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CalyxError {
    CalyxError {
        code,
        message: message.into(),
        remediation,
    }
}
