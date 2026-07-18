use std::sync::{Arc, OnceLock};

use cudarc::driver::{
    CudaContext as CudarcContext, CudaModule, CudaStream as CudarcStream, result, sys,
};

use crate::{BackendKind, DeviceInfo, ForgeError, PinnedCudaDeviceIdentity, Result};

const BYTES_PER_MIB: u64 = 1024 * 1024;
const MIN_FREE_VRAM_MIB: u64 = 4096;
const CUDA_REMEDIATION: &str =
    "Check that CUDA is installed and nvidia-smi shows an available CUDA GPU";
const CUDA_IDENTITY_REMEDIATION: &str = "terminate the process, preserve its CUDA attestation logs, and repair the Runtime/Driver/NVML physical-device mapping before restarting";

#[derive(Clone, Debug)]
pub struct CudaContext {
    inner: Arc<CudarcContext>,
    determinism: bool,
    driver_ordinal: u32,
    physical_identity: PinnedCudaDeviceIdentity,
    name: String,
    compute_capability: (i32, i32),
    total_mem_mib: u64,
    free_mem_mib_at_init: u64,
    dependency_boundary: CudaDependencyBoundary,
    distance_module: Arc<OnceLock<Arc<CudaModule>>>,
    topk_module: Arc<OnceLock<Arc<CudaModule>>>,
    mxfp_gemm_module: Arc<OnceLock<Arc<CudaModule>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CudaDependencyBoundary {
    FullModelRuntime,
    NativeKernel,
}

impl CudaDependencyBoundary {
    const fn evidence(self) -> &'static str {
        match self {
            Self::FullModelRuntime => "pinned-cuda-runtime-nvml-driver+onnx-provider",
            Self::NativeKernel => "pinned-cudart-nvml-driver-native-kernel",
        }
    }
}

#[derive(Debug)]
pub struct CudaPrimaryContextStream {
    stream: Arc<CudarcStream>,
    primary: CudaContext,
}

impl CudaPrimaryContextStream {
    pub fn create_by_pci_bus_id(pci_bus_id: &str) -> Result<Self> {
        let primary = init_cuda_by_pci_bus_id(pci_bus_id, false)?;
        let stream = primary.inner().new_stream().map_err(|error| {
            device_unavailable(
                primary.driver_ordinal(),
                format!(
                    "create non-blocking CUDA stream for {} failed: {error}",
                    primary.physical_identity()
                ),
            )
        })?;
        attest_cudarc_context(
            stream.context().as_ref(),
            primary.driver_ordinal(),
            primary.physical_identity(),
        )?;
        Ok(Self { stream, primary })
    }

    pub fn stream_ptr(&self) -> *mut () {
        self.stream.cu_stream().cast()
    }

    pub fn driver_ordinal(&self) -> u32 {
        self.primary.driver_ordinal()
    }

    pub fn physical_identity(&self) -> PinnedCudaDeviceIdentity {
        self.primary.physical_identity()
    }

    pub fn attest_identity(&self) -> Result<()> {
        attest_cudarc_context(
            self.stream.context().as_ref(),
            self.primary.driver_ordinal(),
            self.primary.physical_identity(),
        )
    }

    /// Wait until every operation queued on this exact retained stream has completed.
    pub fn synchronize(&self) -> Result<()> {
        self.stream.synchronize().map_err(|error| {
            device_unavailable(
                self.primary.driver_ordinal(),
                format!(
                    "synchronize retained CUDA stream for {} failed: {error}",
                    self.primary.physical_identity()
                ),
            )
        })
    }
}

impl CudaContext {
    pub fn inner(&self) -> &Arc<CudarcContext> {
        &self.inner
    }

    pub fn determinism(&self) -> bool {
        self.determinism
    }

    pub fn device_idx(&self) -> u32 {
        self.driver_ordinal
    }

    pub fn driver_ordinal(&self) -> u32 {
        self.driver_ordinal
    }

    pub fn physical_identity(&self) -> PinnedCudaDeviceIdentity {
        self.physical_identity
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn compute_capability(&self) -> (i32, i32) {
        self.compute_capability
    }

    pub fn total_mem_mib(&self) -> u64 {
        self.total_mem_mib
    }

    pub fn free_mem_mib_at_init(&self) -> u64 {
        self.free_mem_mib_at_init
    }

    /// Exact dependency/device authority used to construct this context.
    pub fn selection_authority(&self) -> &'static str {
        self.dependency_boundary.evidence()
    }

    /// Re-reads the context's Driver ordinal and PCI+UUID identity.
    pub fn attest_physical_identity(&self) -> Result<()> {
        match self.dependency_boundary {
            CudaDependencyBoundary::FullModelRuntime => attest_cudarc_context(
                self.inner.as_ref(),
                self.driver_ordinal,
                self.physical_identity,
            ),
            CudaDependencyBoundary::NativeKernel => attest_native_kernel_context(
                self.inner.as_ref(),
                self.driver_ordinal,
                self.physical_identity,
            ),
        }
    }

    /// Re-reads only the live Driver context ordinal, PCI identity, and UUID.
    ///
    /// Context construction, packed-plan upload, and explicit post-run
    /// verification use [`Self::attest_physical_identity`] to re-attest the
    /// complete dependency boundary. A resident kernel dispatch uses this
    /// direct check so every execution still fails closed on a changed CUDA
    /// context without reloading and re-hashing the immutable runtime/NVML
    /// libraries on its performance-critical path.
    pub(crate) fn attest_execution_identity(&self) -> Result<()> {
        attest_cudarc_context_identity(
            self.inner.as_ref(),
            self.driver_ordinal,
            self.physical_identity,
            "resident-kernel",
        )
    }

    /// Live free device VRAM in bytes via `cudaMemGetInfo` (in-process — never
    /// `nvidia-smi`). The returned value reflects *current* free memory and
    /// therefore accounts for every other resident process on the GPU (the TEI
    /// containers, dcgm-exporter). This is the truth source the VRAM budgeter
    /// consults before each large dispatch; it never assumes a fixed 32 GiB.
    ///
    /// Fail-loud: a driver error surfaces as
    /// [`ForgeError::DeviceUnavailable`] (`CALYX_FORGE_DEVICE_UNAVAILABLE`) —
    /// there is no zero-fill fallback, so callers can treat the unknown state
    /// as over-budget.
    pub fn free_device_vram_bytes(&self) -> Result<usize> {
        let (free_bytes, _total_bytes) =
            self.inner
                .mem_get_info()
                .map_err(|err| ForgeError::DeviceUnavailable {
                    device: self.physical_identity.canonical_execution_token(),
                    detail: format!("CUDA cudaMemGetInfo (live free-VRAM query) failed: {err}"),
                    remediation: CUDA_REMEDIATION.to_string(),
                })?;
        Ok(free_bytes)
    }

    pub(crate) fn distance_module_cache(&self) -> &OnceLock<Arc<CudaModule>> {
        &self.distance_module
    }

    pub(crate) fn topk_module_cache(&self) -> &OnceLock<Arc<CudaModule>> {
        &self.topk_module
    }

    pub(crate) fn mxfp_gemm_module_cache(&self) -> &OnceLock<Arc<CudaModule>> {
        &self.mxfp_gemm_module
    }
}

/// Construct a CUDA context for one CUDA Runtime-visible ordinal.
///
/// The Runtime and Driver APIs can expose different ordinal maps. On Windows the
/// public selector is therefore resolved through the process-global PCI+UUID
/// receipt before cudarc receives the attested Driver ordinal.
pub fn init_cuda(runtime_ordinal: u32, determinism: bool) -> Result<CudaContext> {
    #[cfg(windows)]
    {
        let selected = crate::cuda_runtime::select_pinned_cuda_device(runtime_ordinal)?;
        init_cuda_from_selected(
            &selected,
            determinism,
            CudaDependencyBoundary::FullModelRuntime,
        )
    }

    #[cfg(not(windows))]
    {
        let driver_ordinal = runtime_ordinal;
        let identity = driver_device_identity_for_ordinal(driver_ordinal)?;
        init_cuda_driver_ordinal(
            driver_ordinal,
            identity,
            determinism,
            CudaDependencyBoundary::NativeKernel,
            None,
        )
    }
}

/// Constructs a CUDA context for embedded native kernels without initializing
/// ONNX/cuDNN provider DLLs that the kernel cannot call.
///
/// Windows still resolves the requested Runtime ordinal through exact locked
/// cudart PCI identity, signed NVML UUID, and exact nvcuda Driver enumeration.
/// No ambient ordinal assumption or CPU/backend fallback is permitted.
pub fn init_cuda_native_kernel(runtime_ordinal: u32, determinism: bool) -> Result<CudaContext> {
    #[cfg(windows)]
    {
        let selected =
            crate::cuda_runtime::select_pinned_cuda_device_for_native_kernel(runtime_ordinal)?;
        init_cuda_from_selected(&selected, determinism, CudaDependencyBoundary::NativeKernel)
    }

    #[cfg(not(windows))]
    init_cuda(runtime_ordinal, determinism)
}

#[cfg(windows)]
fn init_cuda_from_selected(
    selected: &crate::cuda_runtime::PinnedCudaDeviceAttestation,
    determinism: bool,
    dependency_boundary: CudaDependencyBoundary,
) -> Result<CudaContext> {
    match dependency_boundary {
        CudaDependencyBoundary::FullModelRuntime => {
            attest_cuda_driver_ordinal(selected.cuda_driver_ordinal, selected.identity)?;
        }
        CudaDependencyBoundary::NativeKernel => {
            let observed =
                crate::cuda_runtime::attest_pinned_cuda_driver_identity_for_native_kernel(
                    selected.identity,
                )?;
            if observed != selected.cuda_driver_ordinal {
                return Err(identity_mismatch(
                    "CALYX_CUDA_DRIVER_ORDINAL_MISMATCH",
                    format!(
                        "native-kernel device contract resolved {} to Driver ordinal {observed}, but selection recorded {}",
                        selected.identity, selected.cuda_driver_ordinal
                    ),
                ));
            }
        }
    }
    init_cuda_driver_ordinal(
        selected.cuda_driver_ordinal,
        selected.identity,
        determinism,
        dependency_boundary,
        Some(selected),
    )
}

fn init_cuda_driver_ordinal(
    driver_ordinal: u32,
    physical_identity: PinnedCudaDeviceIdentity,
    determinism: bool,
    dependency_boundary: CudaDependencyBoundary,
    #[cfg(windows)] selected: Option<&crate::cuda_runtime::PinnedCudaDeviceAttestation>,
    #[cfg(not(windows))] _selected: Option<&()>,
) -> Result<CudaContext> {
    let device = physical_identity.canonical_execution_token();
    let inner = CudarcContext::new(driver_ordinal as usize).map_err(|err| {
        device_unavailable(
            driver_ordinal,
            format!("CUDA Driver context init for {physical_identity} failed: {err}"),
        )
    })?;

    #[cfg(windows)]
    if let Some(selected) = selected {
        match dependency_boundary {
            CudaDependencyBoundary::FullModelRuntime => attest_cudarc_context(
                inner.as_ref(),
                selected.cuda_driver_ordinal,
                selected.identity,
            )?,
            CudaDependencyBoundary::NativeKernel => attest_native_kernel_context(
                inner.as_ref(),
                selected.cuda_driver_ordinal,
                selected.identity,
            )?,
        }
    }

    let name = inner.name().map_err(|err| {
        device_unavailable(
            driver_ordinal,
            format!("CUDA device name query for {physical_identity} failed: {err}"),
        )
    })?;
    let compute_capability = inner.compute_capability().map_err(|err| {
        device_unavailable(
            driver_ordinal,
            format!("CUDA compute capability query failed: {err}"),
        )
    })?;
    let (free_bytes, total_bytes) = inner.mem_get_info().map_err(|err| {
        device_unavailable(
            driver_ordinal,
            format!("CUDA VRAM query for {physical_identity} failed: {err}"),
        )
    })?;
    let free_mem_mib = bytes_to_mib(free_bytes);
    ensure_min_free_vram(&device, free_mem_mib)?;
    #[cfg(windows)]
    match dependency_boundary {
        CudaDependencyBoundary::FullModelRuntime => {
            crate::cuda_runtime::attest_pinned_cuda_driver_dependencies()?;
        }
        CudaDependencyBoundary::NativeKernel => {
            let observed =
                crate::cuda_runtime::attest_pinned_cuda_driver_identity_for_native_kernel(
                    physical_identity,
                )?;
            if observed != driver_ordinal {
                return Err(identity_mismatch(
                    "CALYX_CUDA_DRIVER_ORDINAL_MISMATCH",
                    format!(
                        "native-kernel post-construction attestation resolved {physical_identity} to Driver ordinal {observed}, expected {driver_ordinal}"
                    ),
                ));
            }
        }
    }

    Ok(CudaContext {
        inner,
        determinism,
        driver_ordinal,
        physical_identity,
        name,
        compute_capability,
        total_mem_mib: bytes_to_mib(total_bytes),
        free_mem_mib_at_init: free_mem_mib,
        dependency_boundary,
        distance_module: Arc::new(OnceLock::new()),
        topk_module: Arc::new(OnceLock::new()),
        mxfp_gemm_module: Arc::new(OnceLock::new()),
    })
}

pub fn init_cuda_by_pci_bus_id(pci_bus_id: &str, determinism: bool) -> Result<CudaContext> {
    #[cfg(windows)]
    {
        let selected = require_current_pinned_device("construct a CUDA context by PCI identity")?;
        let requested = parse_pci_bus_id(pci_bus_id)?;
        let pinned = parse_pci_bus_id(&selected.identity.canonical_pci_bus_id())?;
        if requested != pinned {
            return Err(identity_mismatch(
                "CALYX_CUDA_CONTEXT_DEVICE_SELECTION_MISMATCH",
                format!(
                    "requested PCI identity {pci_bus_id} differs from process-pinned {}",
                    selected.identity
                ),
            ));
        }
        init_cuda_from_selected(
            &selected,
            determinism,
            CudaDependencyBoundary::FullModelRuntime,
        )
    }

    #[cfg(not(windows))]
    {
        let driver_ordinal = driver_ordinal_for_pci_bus_id(pci_bus_id)?;
        let identity = driver_device_identity_for_ordinal(driver_ordinal)?;
        init_cuda_driver_ordinal(
            driver_ordinal,
            identity,
            determinism,
            CudaDependencyBoundary::NativeKernel,
            None,
        )
    }
}

pub fn driver_ordinal_for_pci_bus_id(pci_bus_id: &str) -> Result<u32> {
    #[cfg(windows)]
    {
        crate::cuda_runtime::initialize_pinned_cuda_dependencies()?;
        let selected = require_current_pinned_device("resolve a CUDA Driver ordinal")?;
        if parse_pci_bus_id(pci_bus_id)?
            != parse_pci_bus_id(&selected.identity.canonical_pci_bus_id())?
        {
            return Err(identity_mismatch(
                "CALYX_CUDA_DRIVER_DEVICE_SELECTION_MISMATCH",
                format!(
                    "requested PCI identity {pci_bus_id} differs from process-pinned {}",
                    selected.identity
                ),
            ));
        }
        let observed = driver_ordinal_for_identity(selected.identity)?;
        if observed != selected.cuda_driver_ordinal {
            return Err(identity_mismatch(
                "CALYX_CUDA_DRIVER_ORDINAL_MISMATCH",
                format!(
                    "Driver PCI+UUID enumeration resolved {} to ordinal {observed}, but the process receipt records {}",
                    selected.identity, selected.cuda_driver_ordinal
                ),
            ));
        }
        crate::cuda_runtime::attest_pinned_cuda_driver_dependencies()?;
        Ok(observed)
    }

    #[cfg(not(windows))]
    driver_ordinal_for_pci_only(pci_bus_id)
}

#[cfg(not(windows))]
fn driver_ordinal_for_pci_only(pci_bus_id: &str) -> Result<u32> {
    let expected = parse_pci_bus_id(pci_bus_id)?;
    result::init().map_err(|error| ForgeError::DeviceUnavailable {
        device: format!("pci:{pci_bus_id}"),
        detail: format!("CUDA driver initialization failed while resolving PCI identity: {error}"),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    let count = result::device::get_count().map_err(|error| ForgeError::DeviceUnavailable {
        device: format!("pci:{pci_bus_id}"),
        detail: format!("CUDA driver device enumeration failed: {error}"),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    if count <= 0 {
        return Err(ForgeError::DeviceUnavailable {
            device: format!("pci:{pci_bus_id}"),
            detail: "CUDA driver reported zero devices while resolving an attested PCI identity"
                .to_string(),
            remediation: CUDA_REMEDIATION.to_string(),
        });
    }

    let mut matched = None;
    for ordinal in 0..count {
        let device =
            result::device::get(ordinal).map_err(|error| ForgeError::DeviceUnavailable {
                device: format!("cuda-driver:{ordinal}"),
                detail: format!("CUDA driver device lookup failed: {error}"),
                remediation: CUDA_REMEDIATION.to_string(),
            })?;
        let observed = driver_pci_bus_id(device, ordinal)?;
        if parse_pci_bus_id(&observed)? != expected {
            continue;
        }
        let ordinal = u32::try_from(ordinal).map_err(|_| ForgeError::DeviceUnavailable {
            device: format!("pci:{pci_bus_id}"),
            detail: "CUDA driver returned a negative or overflowing device ordinal".to_string(),
            remediation: CUDA_REMEDIATION.to_string(),
        })?;
        if matched.replace(ordinal).is_some() {
            return Err(ForgeError::DeviceUnavailable {
                device: format!("pci:{pci_bus_id}"),
                detail: "multiple CUDA driver ordinals resolved to the same PCI identity"
                    .to_string(),
                remediation: CUDA_REMEDIATION.to_string(),
            });
        }
    }
    matched.ok_or_else(|| ForgeError::DeviceUnavailable {
        device: format!("pci:{pci_bus_id}"),
        detail: "the CUDA driver cannot resolve the CUDA Runtime-attested PCI identity".to_string(),
        remediation: CUDA_REMEDIATION.to_string(),
    })
}

fn driver_ordinal_for_identity(expected: PinnedCudaDeviceIdentity) -> Result<u32> {
    result::init().map_err(|error| ForgeError::DeviceUnavailable {
        device: expected.canonical_execution_token(),
        detail: format!(
            "CUDA driver initialization failed during physical-device enumeration: {error}"
        ),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    let count = result::device::get_count().map_err(|error| ForgeError::DeviceUnavailable {
        device: expected.canonical_execution_token(),
        detail: format!("CUDA driver device enumeration failed: {error}"),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    if count <= 0 {
        return Err(identity_mismatch(
            "CALYX_CUDA_DRIVER_RUNTIME_INCONSISTENT",
            "CUDA Driver reported zero devices after the CUDA Runtime pinned a physical identity",
        ));
    }
    let mut matches = Vec::new();
    for ordinal in 0..count {
        let ordinal_u32 = u32::try_from(ordinal).map_err(|_| {
            identity_mismatch(
                "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_INVALID",
                format!("CUDA Driver returned invalid ordinal {ordinal}"),
            )
        })?;
        let observed = driver_device_identity_for_ordinal(ordinal_u32)?;
        if observed == expected {
            matches.push(ordinal_u32);
        }
    }
    let [ordinal] = matches.as_slice() else {
        return Err(identity_mismatch(
            "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_MISMATCH",
            format!(
                "pinned physical identity {expected} matched {} CUDA Driver ordinals",
                matches.len()
            ),
        ));
    };
    Ok(*ordinal)
}

pub fn attest_cuda_driver_ordinal(
    driver_ordinal: u32,
    expected_identity: PinnedCudaDeviceIdentity,
) -> Result<()> {
    #[cfg(windows)]
    {
        crate::cuda_runtime::initialize_pinned_cuda_dependencies()?;
        let selected = require_current_pinned_device("attest a CUDA Driver ordinal")?;
        if selected.cuda_driver_ordinal != driver_ordinal || selected.identity != expected_identity
        {
            return Err(identity_mismatch(
                "CALYX_CUDA_DRIVER_DEVICE_SELECTION_MISMATCH",
                format!(
                    "requested driver_ordinal={driver_ordinal} identity={expected_identity}; process receipt records driver_ordinal={} identity={}",
                    selected.cuda_driver_ordinal, selected.identity
                ),
            ));
        }
    }

    let observed = driver_device_identity_for_ordinal(driver_ordinal)?;
    if observed != expected_identity {
        return Err(identity_mismatch(
            "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_MISMATCH",
            format!(
                "CUDA Driver ordinal {driver_ordinal} resolved to {observed}, expected {expected_identity}"
            ),
        ));
    }

    #[cfg(windows)]
    crate::cuda_runtime::attest_pinned_cuda_driver_dependencies()?;
    Ok(())
}

pub fn attest_cudarc_context(
    context: &CudarcContext,
    expected_driver_ordinal: u32,
    expected_identity: PinnedCudaDeviceIdentity,
) -> Result<()> {
    attest_cudarc_context_identity(
        context,
        expected_driver_ordinal,
        expected_identity,
        "cudarc",
    )?;
    attest_cuda_driver_ordinal(expected_driver_ordinal, expected_identity)
}

fn attest_cudarc_context_identity(
    context: &CudarcContext,
    expected_driver_ordinal: u32,
    expected_identity: PinnedCudaDeviceIdentity,
    boundary: &str,
) -> Result<()> {
    let observed_ordinal = u32::try_from(context.ordinal()).map_err(|_| {
        identity_mismatch(
            "CALYX_CUDA_DRIVER_CONTEXT_IDENTITY_INVALID",
            format!("cudarc context ordinal {} exceeds u32", context.ordinal()),
        )
    })?;
    if observed_ordinal != expected_driver_ordinal {
        return Err(identity_mismatch(
            "CALYX_CUDA_DRIVER_CONTEXT_IDENTITY_MISMATCH",
            format!(
                "{boundary} context reports Driver ordinal {observed_ordinal}, expected {expected_driver_ordinal} for {expected_identity}"
            ),
        ));
    }
    let observed_identity = driver_device_identity(
        context.cu_device(),
        i32::try_from(observed_ordinal).map_err(|_| {
            identity_mismatch(
                "CALYX_CUDA_DRIVER_CONTEXT_IDENTITY_INVALID",
                format!("cudarc context ordinal {observed_ordinal} exceeds i32"),
            )
        })?,
    )?;
    if observed_identity != expected_identity {
        return Err(identity_mismatch(
            "CALYX_CUDA_DRIVER_CONTEXT_IDENTITY_MISMATCH",
            format!(
                "{boundary} context resolved to {observed_identity}, expected {expected_identity}"
            ),
        ));
    }
    Ok(())
}

fn attest_native_kernel_context(
    context: &CudarcContext,
    expected_driver_ordinal: u32,
    expected_identity: PinnedCudaDeviceIdentity,
) -> Result<()> {
    #[cfg(windows)]
    {
        let attested = crate::cuda_runtime::attest_pinned_cuda_driver_identity_for_native_kernel(
            expected_identity,
        )?;
        if attested != expected_driver_ordinal {
            return Err(identity_mismatch(
                "CALYX_CUDA_DRIVER_ORDINAL_MISMATCH",
                format!(
                    "native-kernel bundle attestation resolved {expected_identity} to Driver ordinal {attested}, expected {expected_driver_ordinal}"
                ),
            ));
        }
    }
    attest_cudarc_context_identity(
        context,
        expected_driver_ordinal,
        expected_identity,
        "native-kernel",
    )
}

fn driver_device_identity_for_ordinal(driver_ordinal: u32) -> Result<PinnedCudaDeviceIdentity> {
    result::init().map_err(|error| ForgeError::DeviceUnavailable {
        device: format!("cuda-driver:{driver_ordinal}"),
        detail: format!("CUDA driver initialization failed: {error}"),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    let ordinal = i32::try_from(driver_ordinal).map_err(|_| {
        identity_mismatch(
            "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_INVALID",
            format!("CUDA Driver ordinal {driver_ordinal} exceeds i32"),
        )
    })?;
    let device = result::device::get(ordinal).map_err(|error| ForgeError::DeviceUnavailable {
        device: format!("cuda-driver:{driver_ordinal}"),
        detail: format!("CUDA driver device lookup failed: {error}"),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    driver_device_identity(device, ordinal)
}

fn driver_device_identity(
    device: sys::CUdevice,
    driver_ordinal: i32,
) -> Result<PinnedCudaDeviceIdentity> {
    let pci_bus_id = driver_pci_bus_id(device, driver_ordinal)?;
    let uuid = result::device::get_uuid(device).map_err(|error| {
        identity_mismatch(
            "CALYX_CUDA_DRIVER_DEVICE_IDENTITY_QUERY_FAILED",
            format!("CUDA Driver cuDeviceGetUuid_v2 failed for ordinal {driver_ordinal}: {error}"),
        )
    })?;
    let uuid = uuid.bytes.map(|byte| byte as u8);
    PinnedCudaDeviceIdentity::from_pci_and_uuid_bytes(&pci_bus_id, uuid)
        .map_err(|detail| identity_mismatch("CALYX_CUDA_DRIVER_DEVICE_IDENTITY_INVALID", detail))
}

#[cfg(windows)]
fn require_current_pinned_device(
    operation: &str,
) -> Result<crate::cuda_runtime::PinnedCudaDeviceAttestation> {
    crate::cuda_runtime::current_pinned_cuda_device()?.ok_or_else(|| {
        identity_mismatch(
            "CALYX_CUDA_DEVICE_ATTESTATION_MISSING",
            format!("cannot {operation} before selecting one process-global physical CUDA device"),
        )
    })
}

fn driver_pci_bus_id(device: sys::CUdevice, ordinal: i32) -> Result<String> {
    let mut buffer = [0u8; 32];
    let len = i32::try_from(buffer.len()).map_err(|_| ForgeError::DeviceUnavailable {
        device: format!("cuda-driver:{ordinal}"),
        detail: "PCI identity buffer length exceeds the CUDA driver ABI".to_string(),
        remediation: CUDA_REMEDIATION.to_string(),
    })?;
    unsafe { sys::cuDeviceGetPCIBusId(buffer.as_mut_ptr().cast(), len, device).result() }.map_err(
        |error| ForgeError::DeviceUnavailable {
            device: format!("cuda-driver:{ordinal}"),
            detail: format!("CUDA driver PCI identity query failed: {error}"),
            remediation: CUDA_REMEDIATION.to_string(),
        },
    )?;
    let nul =
        buffer
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| ForgeError::DeviceUnavailable {
                device: format!("cuda-driver:{ordinal}"),
                detail: "CUDA driver returned no NUL terminator in the bounded PCI identity buffer"
                    .to_string(),
                remediation: CUDA_REMEDIATION.to_string(),
            })?;
    let value =
        std::str::from_utf8(&buffer[..nul]).map_err(|error| ForgeError::DeviceUnavailable {
            device: format!("cuda-driver:{ordinal}"),
            detail: format!("CUDA driver returned a non-UTF-8 PCI identity: {error}"),
            remediation: CUDA_REMEDIATION.to_string(),
        })?;
    parse_pci_bus_id(value)?;
    Ok(value.to_string())
}

fn parse_pci_bus_id(value: &str) -> Result<(u32, u32, u32, u32)> {
    let parsed = (|| {
        let (domain, rest) = value.split_once(':')?;
        let (bus, rest) = rest.split_once(':')?;
        let (device, function) = rest.split_once('.')?;
        Some((
            u32::from_str_radix(domain, 16).ok()?,
            u32::from_str_radix(bus, 16).ok()?,
            u32::from_str_radix(device, 16).ok()?,
            u32::from_str_radix(function, 16).ok()?,
        ))
    })()
    .filter(|identity| {
        identity.0 <= 0xffff && identity.1 <= 0xff && identity.2 <= 0x1f && identity.3 <= 7
    });
    parsed.ok_or_else(|| ForgeError::DeviceUnavailable {
        device: format!("pci:{value}"),
        detail: "CUDA PCI identity is malformed or outside PCI domain/bus/device/function bounds"
            .to_string(),
        remediation: CUDA_REMEDIATION.to_string(),
    })
}

pub fn query_device_info(ctx: &CudaContext) -> DeviceInfo {
    DeviceInfo {
        kind: BackendKind::Cuda,
        name: ctx.name.clone(),
        avx512: false,
        vram_mib: Some(ctx.total_mem_mib),
    }
}

fn ensure_min_free_vram(device: &str, free_mem_mib: u64) -> Result<()> {
    if free_mem_mib < MIN_FREE_VRAM_MIB {
        return Err(ForgeError::DeviceUnavailable {
            device: device.to_string(),
            detail: format!(
                "less than 4 GiB VRAM free; free_vram_mib={free_mem_mib}; TEI containers may be using GPU memory"
            ),
            remediation: CUDA_REMEDIATION.to_string(),
        });
    }
    Ok(())
}

fn identity_mismatch(code: &'static str, detail: impl Into<String>) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code,
        detail: detail.into(),
        remediation: CUDA_IDENTITY_REMEDIATION,
    }
}

fn device_unavailable(device_idx: u32, detail: String) -> ForgeError {
    ForgeError::DeviceUnavailable {
        device: device_label(device_idx),
        detail,
        remediation: CUDA_REMEDIATION.to_string(),
    }
}

fn device_label(device_idx: u32) -> String {
    format!("cuda:{device_idx}")
}

fn bytes_to_mib(bytes: usize) -> u64 {
    (bytes as u64) / BYTES_PER_MIB
}
