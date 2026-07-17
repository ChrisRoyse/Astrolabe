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
use nvml_wrapper::{Nvml, cuda_driver_version_major, cuda_driver_version_minor};
use ort::ep::{CUDA, ExecutionProvider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    AddDllDirectory, GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_USER_DIRS, LoadLibraryExW,
    SetDefaultDllDirectories,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::OnnxProviderPolicy;

const RUNTIME_ROOT_ENV: &str = "CALYX_CUDA13_RUNTIME_ROOT";
const LOCK_SCHEMA: &str = "astrolabe.windows-ort-cuda-runtime-lock.v1";
const LOCK_FILE: &str = "bundle.lock.json";
const LOCK_DIGEST_FILE: &str = "bundle.lock.sha256";
const RECEIPT_FILE: &str = "bundle.receipt.json";
const RECEIPT_SCHEMA: &str = "astrolabe.windows-ort-cuda-runtime-receipt.v1";
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxCudaDeviceAttestation {
    pub ordinal: u32,
    pub name: String,
    pub uuid: String,
    pub compute_capability: String,
    pub total_vram_bytes: u64,
    pub used_vram_bytes: u64,
    pub free_vram_bytes: u64,
    pub nvidia_driver_version: String,
    pub cuda_driver_version: String,
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
    let state = state.lock().map_err(|_| {
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
    Ok(state.live.as_ref().map(|live| live.receipt.clone()))
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

#[derive(Default)]
struct RuntimeState {
    live: Option<LiveRuntime>,
    core_failure: Option<CalyxError>,
    cuda_failure: Option<CalyxError>,
}

struct LiveRuntime {
    lock: RuntimeLock,
    root: PathBuf,
    core_path: PathBuf,
    _dll_directory_cookie: usize,
    _module_handles: Vec<usize>,
    receipt: OnnxRuntimeAttestation,
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
    forbidden_providers: Vec<String>,
    forbidden_archive_dlls: Vec<String>,
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
    bundle_module_globs: Vec<String>,
    driver: DriverPolicy,
    system_roots: Vec<String>,
    reject_application_dir: bool,
    reject_path_search: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriverPolicy {
    name: String,
    required_root: String,
    publisher: String,
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
    archive_entries: u64,
    record_entries: u64,
    record_entries_verified: u64,
    locked_record_entries_verified: u64,
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

fn initialize_core() -> Result<LiveRuntime> {
    reject_legacy_environment()?;
    let lock = parse_and_validate_embedded_lock()?;
    let lock_sha256 = sha256_bytes(LOCK_BYTES);
    let root = resolve_and_validate_root(&lock, &lock_sha256)?;
    let (bundle_receipt, bundle_receipt_sha256) =
        validate_installed_bundle(&root, &lock, &lock_sha256)?;
    let bin = canonicalize_existing_dir(&root.join("bin"), "runtime bin")?;
    reject_ambient_managed_modules(&lock, &root, &enumerate_process_modules()?)?;
    let cookie = configure_process_dll_search(&bin)?;
    let core_path = locked_dll_path(&lock, &root, &lock.contract.ort_dll)?;
    let core_handle = load_exact_library(&core_path)?;
    let api = preflight_ort_api(core_handle, &lock.contract)?;
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
    for forbidden in &lock.contract.forbidden_providers {
        if available_providers
            .iter()
            .any(|provider| provider.eq_ignore_ascii_case(forbidden))
        {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_FORBIDDEN_PROVIDER",
                format!("pinned ORT unexpectedly exposes forbidden provider {forbidden}"),
                BUNDLE_REMEDIATION,
            ));
        }
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
    let modules = attest_loaded_modules(&lock, &root, false)?;
    Ok(LiveRuntime {
        lock: lock.clone(),
        root: root.clone(),
        core_path,
        _dll_directory_cookie: cookie,
        _module_handles: vec![core_handle as usize],
        receipt: OnnxRuntimeAttestation {
            schema: "calyx-onnx-runtime-attestation-v1".to_string(),
            contract: contract_attestation(&lock, &lock_sha256),
            bundle_root: root.clone(),
            bundle_receipt: root.join(RECEIPT_FILE),
            bundle_receipt_sha256,
            provisioned_at_utc: bundle_receipt.provisioned_at_utc,
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
    let modules_before = enumerate_process_modules()?;
    reject_ambient_managed_modules(&live.lock, &live.root, &modules_before)?;
    reject_ambient_driver_modules(&live.lock.loaded_module_policy, &modules_before)?;
    let driver_root = canonicalize_existing_dir(
        &expand_windows_path(&live.lock.loaded_module_policy.driver.required_root),
        "NVIDIA driver required root",
    )?;
    let driver_path = canonicalize_existing_file(
        &driver_root.join(&live.lock.loaded_module_policy.driver.name),
        "NVIDIA CUDA driver DLL",
    )?;
    let driver_handle = load_exact_library(&driver_path)?;
    live._module_handles.push(driver_handle as usize);
    let mut dlls: Vec<&FileContract> = live
        .lock
        .files
        .iter()
        .filter(|file| file.bundle_path.to_ascii_lowercase().ends_with(".dll"))
        .filter(|file| !basename_eq(&file.bundle_path, &live.lock.contract.ort_dll))
        .collect();
    dlls.sort_by_key(|file| {
        if basename_eq(&file.bundle_path, &live.lock.contract.provider_dll) {
            (2u8, file.bundle_path.as_str())
        } else if basename_eq(&file.bundle_path, "onnxruntime_providers_shared.dll") {
            (1u8, file.bundle_path.as_str())
        } else {
            (0u8, file.bundle_path.as_str())
        }
    });
    for file in dlls {
        let path = canonicalize_existing_file(
            &live.root.join(windows_relative_path(&file.bundle_path)?),
            "managed CUDA runtime DLL",
        )?;
        let handle = load_exact_library(&path)?;
        live._module_handles.push(handle as usize);
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
    let (device, nvml_path, nvml_handle) = attest_cuda_device(&live.lock.loaded_module_policy)?;
    live._module_handles.push(nvml_handle);
    let mut modules = attest_loaded_modules(&live.lock, &live.root, true)?;
    modules.push(attest_exact_system_module(
        "nvml.dll",
        &nvml_path,
        "system-driver:system32-path+sha256",
        &enumerate_process_modules()?,
    )?);
    modules.sort_by(|left, right| left.name.cmp(&right.name));
    live.receipt.provider_available = true;
    live.receipt.modules = modules;
    live.receipt.cuda_device = Some(device);
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
    require_contract(
        lock.loaded_module_policy
            .driver
            .name
            .eq_ignore_ascii_case("nvcuda.dll"),
        "driver policy must identify nvcuda.dll",
    )?;
    require_contract(
        !lock.loaded_module_policy.driver.publisher.trim().is_empty(),
        "driver publisher is empty",
    )?;
    require_contract(
        !lock.loaded_module_policy.system_roots.is_empty(),
        "system_roots is empty",
    )?;
    require_contract(
        lock.loaded_module_policy.system_roots.len() == 1
            && lock.loaded_module_policy.system_roots[0]
                .eq_ignore_ascii_case(&lock.loaded_module_policy.driver.required_root),
        "system_roots must exactly identify the driver required_root",
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
    for forbidden in &lock.contract.forbidden_archive_dlls {
        require_contract(
            !lock
                .files
                .iter()
                .any(|file| file.archive_path.eq_ignore_ascii_case(forbidden)),
            "forbidden archive DLL present in bundle",
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

fn validate_installed_bundle(
    root: &Path,
    lock: &RuntimeLock,
    lock_sha256: &str,
) -> Result<(BundleReceipt, String)> {
    let copied_lock = fs::read(root.join(LOCK_FILE)).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_LOCK_MISSING",
            format!("read {} failed: {error}", root.join(LOCK_FILE).display()),
            BUNDLE_REMEDIATION,
        )
    })?;
    if copied_lock != LOCK_BYTES {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_LOCK_MISMATCH",
            format!(
                "{} is not byte-identical to the embedded lock",
                root.join(LOCK_FILE).display()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    let copied_digest = fs::read_to_string(root.join(LOCK_DIGEST_FILE)).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_LOCK_DIGEST_MISSING",
            format!(
                "read {} failed: {error}",
                root.join(LOCK_DIGEST_FILE).display()
            ),
            BUNDLE_REMEDIATION,
        )
    })?;
    if copied_digest.trim() != lock_sha256 {
        return Err(runtime_error(
            "CALYX_ONNX_RUNTIME_LOCK_DIGEST_MISMATCH",
            format!(
                "{} records {}, expected {lock_sha256}",
                root.join(LOCK_DIGEST_FILE).display(),
                copied_digest.trim()
            ),
            BUNDLE_REMEDIATION,
        ));
    }
    for file in &lock.files {
        verify_locked_file(root, &file.bundle_path, file.bytes, &file.sha256)?;
    }
    for notice in &lock.notices {
        verify_locked_file(root, &notice.bundle_path, notice.bytes, &notice.sha256)?;
    }
    let receipt_path = root.join(RECEIPT_FILE);
    let receipt_bytes = fs::read(&receipt_path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_RECEIPT_MISSING",
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
    validate_bundle_receipt(&receipt, lock, lock_sha256)?;
    reject_extra_bundle_entries(root, lock)?;
    Ok((receipt, sha256_bytes(&receipt_bytes)))
}

fn validate_bundle_receipt(
    receipt: &BundleReceipt,
    lock: &RuntimeLock,
    lock_sha256: &str,
) -> Result<()> {
    require_receipt(
        receipt.schema == RECEIPT_SCHEMA,
        "unexpected receipt schema",
    )?;
    require_receipt(
        receipt.bundle_id == lock.bundle.id,
        "receipt bundle_id mismatch",
    )?;
    require_receipt(
        receipt.lock_sha256 == lock_sha256,
        "receipt lock_sha256 mismatch",
    )?;
    require_receipt(
        !receipt.provisioned_at_utc.trim().is_empty(),
        "receipt provisioned_at_utc is empty",
    )?;

    let artifacts: BTreeMap<_, _> = receipt
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    require_receipt(
        artifacts.len() == receipt.artifacts.len() && artifacts.len() == lock.artifacts.len(),
        "receipt artifact cardinality/identity mismatch",
    )?;
    for expected in &lock.artifacts {
        let actual = artifacts
            .get(expected.id.as_str())
            .ok_or_else(|| receipt_error(format!("receipt omits artifact {}", expected.id)))?;
        require_receipt(
            actual.filename == expected.filename,
            "receipt artifact filename mismatch",
        )?;
        require_receipt(
            actual.bytes == expected.bytes,
            "receipt artifact byte count mismatch",
        )?;
        require_receipt(
            actual.sha256 == expected.sha256,
            "receipt artifact SHA256 mismatch",
        )?;
        require_receipt(
            actual.archive_entries > 0,
            "receipt artifact archive_entries is zero",
        )?;
        require_receipt(
            actual.archive_entries == actual.record_entries
                && actual.record_entries_verified == actual.record_entries,
            "receipt artifact RECORD/archive verification counts disagree",
        )?;
        require_receipt(
            actual.locked_record_entries_verified > 0
                && actual.locked_record_entries_verified <= actual.record_entries,
            "receipt locked RECORD verification count is invalid",
        )?;
    }

    let files: BTreeMap<_, _> = receipt
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    require_receipt(
        files.len() == receipt.files.len() && files.len() == lock.files.len(),
        "receipt file cardinality/identity mismatch",
    )?;
    for expected in &lock.files {
        let actual = files
            .get(expected.bundle_path.as_str())
            .ok_or_else(|| receipt_error(format!("receipt omits file {}", expected.bundle_path)))?;
        require_receipt(
            actual.bytes == expected.bytes,
            "receipt file byte count mismatch",
        )?;
        require_receipt(
            actual.sha256 == expected.sha256,
            "receipt file SHA256 mismatch",
        )?;
        require_receipt(
            actual.file_version == expected.file_version,
            "receipt file version mismatch",
        )?;
        require_receipt(
            actual.authenticode.status == expected.authenticode.status
                && actual.authenticode.subject == expected.authenticode.subject
                && actual.authenticode.thumbprint == expected.authenticode.thumbprint,
            "receipt file Authenticode facts mismatch",
        )?;
    }

    let notices: BTreeMap<_, _> = receipt
        .notices
        .iter()
        .map(|notice| (notice.path.as_str(), notice))
        .collect();
    require_receipt(
        notices.len() == receipt.notices.len() && notices.len() == lock.notices.len(),
        "receipt notice cardinality/identity mismatch",
    )?;
    for expected in &lock.notices {
        let actual = notices.get(expected.bundle_path.as_str()).ok_or_else(|| {
            receipt_error(format!("receipt omits notice {}", expected.bundle_path))
        })?;
        require_receipt(
            actual.bytes == expected.bytes,
            "receipt notice byte count mismatch",
        )?;
        require_receipt(
            actual.sha256 == expected.sha256,
            "receipt notice SHA256 mismatch",
        )?;
    }
    Ok(())
}

fn reject_extra_bundle_entries(root: &Path, lock: &RuntimeLock) -> Result<()> {
    let mut expected_files: BTreeSet<String> = lock
        .files
        .iter()
        .map(|file| file.bundle_path.to_ascii_lowercase())
        .chain(
            lock.notices
                .iter()
                .map(|notice| notice.bundle_path.to_ascii_lowercase()),
        )
        .collect();
    expected_files.extend(
        [LOCK_FILE, LOCK_DIGEST_FILE, RECEIPT_FILE]
            .into_iter()
            .map(str::to_ascii_lowercase),
    );
    let mut expected_dirs = BTreeSet::new();
    for file in &expected_files {
        let mut path = Path::new(file);
        while let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            expected_dirs.insert(parent.to_string_lossy().replace('\\', "/"));
            path = parent;
        }
    }
    inspect_bundle_directory(root, root, &expected_files, &expected_dirs)
}

fn inspect_bundle_directory(
    root: &Path,
    directory: &Path,
    expected_files: &BTreeSet<String>,
    expected_dirs: &BTreeSet<String>,
) -> Result<()> {
    let entries = fs::read_dir(directory).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_RUNTIME_DIRECTORY_UNREADABLE",
            format!(
                "read runtime directory {} failed: {error}",
                directory.display()
            ),
            BUNDLE_REMEDIATION,
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_DIRECTORY_UNREADABLE",
                format!(
                    "enumerate runtime directory {} failed: {error}",
                    directory.display()
                ),
                BUNDLE_REMEDIATION,
            )
        })?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|_| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_PATH_ESCAPE",
                format!(
                    "runtime entry {} is not below {}",
                    path.display(),
                    root.display()
                ),
                BUNDLE_REMEDIATION,
            )
        })?;
        let key = relative
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            runtime_error(
                "CALYX_ONNX_RUNTIME_DIRECTORY_UNREADABLE",
                format!("read metadata for {} failed: {error}", path.display()),
                BUNDLE_REMEDIATION,
            )
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_REPARSE_ENTRY",
                format!(
                    "runtime bundle contains a symbolic/reparse entry at {}",
                    path.display()
                ),
                BUNDLE_REMEDIATION,
            ));
        }
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            if !expected_dirs.contains(&key) {
                return Err(runtime_error(
                    "CALYX_ONNX_RUNTIME_UNLOCKED_ENTRY",
                    format!(
                        "runtime bundle contains unlocked directory {}",
                        path.display()
                    ),
                    BUNDLE_REMEDIATION,
                ));
            }
            inspect_bundle_directory(root, &path, expected_files, expected_dirs)?;
        } else if !file_type.is_file() || !expected_files.contains(&key) {
            return Err(runtime_error(
                "CALYX_ONNX_RUNTIME_UNLOCKED_ENTRY",
                format!("runtime bundle contains unlocked entry {}", path.display()),
                BUNDLE_REMEDIATION,
            ));
        }
    }
    Ok(())
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

fn configure_process_dll_search(bin: &Path) -> Result<usize> {
    let flags = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS;
    if unsafe { SetDefaultDllDirectories(flags) } == 0 {
        return Err(last_windows_error(
            "SetDefaultDllDirectories(SYSTEM32|USER_DIRS)",
        ));
    }
    let wide = wide_path(bin);
    let cookie = unsafe { AddDllDirectory(wide.as_ptr()) };
    if cookie.is_null() {
        return Err(last_windows_error(format!(
            "AddDllDirectory {}",
            bin.display()
        )));
    }
    Ok(cookie as usize)
}

fn load_exact_library(path: &Path) -> Result<HMODULE> {
    let wide = wide_path(path);
    let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
        | LOAD_LIBRARY_SEARCH_SYSTEM32
        | LOAD_LIBRARY_SEARCH_USER_DIRS;
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), flags) };
    if module.is_null() {
        return Err(last_windows_error(format!(
            "LoadLibraryExW exact {}",
            path.display()
        )));
    }
    Ok(module)
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
    require_cuda: bool,
) -> Result<Vec<OnnxLoadedModuleAttestation>> {
    let modules = enumerate_process_modules()?;
    reject_ambient_managed_modules(lock, root, &modules)?;
    let expected = expected_dlls(lock, root)?;
    let mut loaded = BTreeMap::new();
    for path in modules {
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
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
        if !require_cuda && !core {
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
        });
    }
    if require_cuda {
        let driver = attest_driver_module(lock, &enumerate_process_modules()?)?;
        out.push(driver);
    }
    out.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(out)
}

fn attest_driver_module(
    lock: &RuntimeLock,
    modules: &[PathBuf],
) -> Result<OnnxLoadedModuleAttestation> {
    let policy = &lock.loaded_module_policy.driver;
    let matches: Vec<_> = modules
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(&policy.name))
        })
        .collect();
    if matches.len() != 1 {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_DRIVER_MODULE_INVALID",
            format!(
                "expected exactly one loaded {}, observed {}",
                policy.name,
                matches.len()
            ),
            "repair the NVIDIA driver installation and restart the process before loading any ONNX lens",
        ));
    }
    let path = canonicalize_existing_file(matches[0], "NVIDIA CUDA driver module")?;
    let required_root = canonicalize_existing_dir(
        &expand_windows_path(&policy.required_root),
        "driver required_root",
    )?;
    let required = canonicalize_existing_file(
        &required_root.join(&policy.name),
        "required NVIDIA CUDA driver module",
    )?;
    if !same_path(&path, &required) {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_DRIVER_PATH_MISMATCH",
            format!(
                "{} loaded from {}; exact required path is {}",
                policy.name,
                path.display(),
                required.display()
            ),
            "repair the NVIDIA driver installation and remove ambient nvcuda.dll copies",
        ));
    }
    let metadata = fs::metadata(&path).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_CUDA_DRIVER_UNREADABLE",
            format!("stat {} failed: {error}", path.display()),
            "repair the NVIDIA driver installation and restart the process",
        )
    })?;
    Ok(OnnxLoadedModuleAttestation {
        name: policy.name.to_ascii_lowercase(),
        path: path.clone(),
        bytes: metadata.len(),
        sha256: sha256_file(&path)?,
        file_version: None,
        source: "system-driver:system32-path+sha256+nvml".to_string(),
    })
}

fn attest_exact_system_module(
    name: &str,
    expected_path: &Path,
    source: &str,
    modules: &[PathBuf],
) -> Result<OnnxLoadedModuleAttestation> {
    let matches: Vec<_> = modules
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .collect();
    if matches.len() != 1 {
        return Err(runtime_error(
            "CALYX_ONNX_SYSTEM_MODULE_INVALID",
            format!(
                "expected exactly one loaded {name} module, observed {}",
                matches.len()
            ),
            "repair the NVIDIA driver and restart the process before loading any ONNX lens",
        ));
    }
    let actual = canonicalize_existing_file(matches[0], "loaded NVIDIA system module")?;
    let expected = canonicalize_existing_file(expected_path, "required NVIDIA system module")?;
    if !same_path(&actual, &expected) {
        return Err(runtime_error(
            "CALYX_ONNX_SYSTEM_MODULE_PATH_MISMATCH",
            format!(
                "loaded {name} from {}; exact required path is {}",
                actual.display(),
                expected.display()
            ),
            "repair the NVIDIA driver, remove ambient NVIDIA DLL copies, and restart the process",
        ));
    }
    let metadata = fs::metadata(&actual).map_err(|error| {
        runtime_error(
            "CALYX_ONNX_SYSTEM_MODULE_UNREADABLE",
            format!("stat {} failed: {error}", actual.display()),
            "repair the NVIDIA driver and restart the process",
        )
    })?;
    Ok(OnnxLoadedModuleAttestation {
        name: name.to_ascii_lowercase(),
        path: actual.clone(),
        bytes: metadata.len(),
        sha256: sha256_file(&actual)?,
        file_version: None,
        source: source.to_string(),
    })
}

fn reject_ambient_exact_system_module(
    name: &str,
    expected_path: &Path,
    modules: &[PathBuf],
) -> Result<()> {
    let matches: Vec<_> = modules
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .collect();
    if matches.len() > 1 {
        return Err(runtime_error(
            "CALYX_ONNX_SYSTEM_MODULE_INVALID",
            format!(
                "process already contains {} loaded {name} modules",
                matches.len()
            ),
            "terminate the process, remove ambient NVIDIA DLL copies, and restart",
        ));
    }
    if let Some(path) = matches.first() {
        let actual = canonicalize_existing_file(path, "preloaded NVIDIA system module")?;
        if !same_path(&actual, expected_path) {
            return Err(runtime_error(
                "CALYX_ONNX_SYSTEM_MODULE_PATH_MISMATCH",
                format!(
                    "preloaded {name} is at {}; exact required path is {}",
                    actual.display(),
                    expected_path.display()
                ),
                "terminate the process, remove ambient NVIDIA DLL copies, and repair the NVIDIA driver",
            ));
        }
    }
    Ok(())
}

fn reject_ambient_driver_modules(policy: &LoadedModulePolicy, modules: &[PathBuf]) -> Result<()> {
    let required_root = canonicalize_existing_dir(
        &expand_windows_path(&policy.driver.required_root),
        "NVIDIA driver required_root",
    )?;
    let required = canonicalize_existing_file(
        &required_root.join(&policy.driver.name),
        "required NVIDIA CUDA driver module",
    )?;
    let matches: Vec<_> = modules
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(&policy.driver.name))
        })
        .collect();
    if matches.len() > 1 {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_DRIVER_MODULE_INVALID",
            format!(
                "process already contains {} loaded {} modules",
                matches.len(),
                policy.driver.name
            ),
            "terminate the process, remove ambient NVIDIA driver DLL copies, and restart",
        ));
    }
    if let Some(path) = matches.first() {
        let path = canonicalize_existing_file(path, "preloaded NVIDIA CUDA driver module")?;
        if !same_path(&path, &required) {
            return Err(runtime_error(
                "CALYX_ONNX_CUDA_DRIVER_PATH_MISMATCH",
                format!(
                    "preloaded {} is at {}; exact required path is {}",
                    policy.driver.name,
                    path.display(),
                    required.display()
                ),
                "terminate the process, remove ambient nvcuda.dll copies, and repair the NVIDIA driver",
            ));
        }
    }
    Ok(())
}

fn attest_cuda_device(
    policy: &LoadedModulePolicy,
) -> Result<(OnnxCudaDeviceAttestation, PathBuf, usize)> {
    if env::var_os("CUDA_VISIBLE_DEVICES").is_some() {
        return Err(runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_MAPPING_AMBIGUOUS",
            "CUDA_VISIBLE_DEVICES is set, so the configured ORT ordinal cannot be proven against the physical NVML ordinal",
            "unset CUDA_VISIBLE_DEVICES and select the physical GPU with CALYX_ONNX_CUDA_DEVICE before starting the resident worker",
        ));
    }
    let ordinal = super::session::configured_cuda_device()? as u32;
    let system_root = canonicalize_existing_dir(
        &expand_windows_path(&policy.driver.required_root),
        "NVIDIA driver system root",
    )?;
    let nvml_path = canonicalize_existing_file(&system_root.join("nvml.dll"), "NVML DLL")?;
    reject_ambient_exact_system_module("nvml.dll", &nvml_path, &enumerate_process_modules()?)?;
    let nvml_handle = load_exact_library(&nvml_path)? as usize;
    let nvml = Nvml::builder()
        .lib_path(nvml_path.as_os_str())
        .init()
        .map_err(|error| runtime_error(
            "CALYX_ONNX_NVML_INIT_FAILED",
            format!("load NVML from {} failed: {error}", nvml_path.display()),
            "repair the NVIDIA driver installation and ensure nvml.dll exists in the locked system root",
        ))?;
    let device = nvml.device_by_index(ordinal).map_err(|error| runtime_error(
        "CALYX_ONNX_CUDA_DEVICE_UNAVAILABLE",
        format!("NVML device_by_index({ordinal}) failed: {error}"),
        "set CALYX_ONNX_CUDA_DEVICE to an ordinal reported by nvidia-smi and restart the worker",
    ))?;
    let name = device.name().map_err(nvml_device_error("name"))?;
    let uuid = device.uuid().map_err(nvml_device_error("uuid"))?;
    let compute = device
        .cuda_compute_capability()
        .map_err(nvml_device_error("CUDA compute capability"))?;
    let memory = device
        .memory_info()
        .map_err(nvml_device_error("memory info"))?;
    let nvidia_driver_version = nvml
        .sys_driver_version()
        .map_err(nvml_system_error("driver version"))?;
    let cuda_version = nvml
        .sys_cuda_driver_version()
        .map_err(nvml_system_error("CUDA driver version"))?;
    Ok((
        OnnxCudaDeviceAttestation {
            ordinal,
            name,
            uuid,
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
        },
        nvml_path,
        nvml_handle,
    ))
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

fn expand_windows_path(raw: &str) -> PathBuf {
    let mut value = raw.replace('/', "\\");
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(replacement) = env::var_os(name).and_then(|value| value.into_string().ok()) {
            value = value.replace(&format!("%{name}%"), &replacement);
        }
    }
    PathBuf::from(value)
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
    let mut buffer = [0u8; 1024 * 1024];
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

fn require_receipt(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(receipt_error(message.to_string()))
    }
}

fn contract_error(message: String) -> CalyxError {
    runtime_error(
        "CALYX_ONNX_RUNTIME_CONTRACT_INVALID",
        message,
        CONTRACT_REMEDIATION,
    )
}

fn receipt_error(message: String) -> CalyxError {
    runtime_error(
        "CALYX_ONNX_RUNTIME_RECEIPT_INVALID",
        message,
        BUNDLE_REMEDIATION,
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

fn nvml_device_error(
    operation: &'static str,
) -> impl FnOnce(nvml_wrapper::error::NvmlError) -> CalyxError {
    move |error| {
        runtime_error(
            "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_FAILED",
            format!("NVML device {operation} query failed: {error}"),
            "repair the NVIDIA driver, verify the selected GPU with nvidia-smi, and restart the worker",
        )
    }
}

fn nvml_system_error(
    operation: &'static str,
) -> impl FnOnce(nvml_wrapper::error::NvmlError) -> CalyxError {
    move |error| {
        runtime_error(
            "CALYX_ONNX_CUDA_DRIVER_ATTESTATION_FAILED",
            format!("NVML system {operation} query failed: {error}"),
            "repair the NVIDIA driver and restart the worker",
        )
    }
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
