use std::sync::Arc;
use std::time::Instant;

use cudarc::driver::CudaModule;
use cudarc::nvrtc::Ptx;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CudaContext, ForgeError, Result};

const KERNEL_REMEDIATION: &str = "Run the exact CUDA 13.3.33 CUBIN on the shared configured RTX 5090/sm_120a device; rebuild with the pinned native Windows launcher if any compiler, module, policy, or device field differs";

pub const DISTANCE_CUBIN: &[u8] = include_bytes!(env!("FORGE_DISTANCE_CUBIN_PATH"));
pub const TOPK_CUBIN: &[u8] = include_bytes!(env!("FORGE_TOPK_CUBIN_PATH"));
pub const MXFP_GEMM_CUBIN: &[u8] = include_bytes!(env!("FORGE_MXFP_GEMM_CUBIN_PATH"));

pub const DISTANCE_CUBIN_PATH: &str = env!("FORGE_DISTANCE_CUBIN_PATH");
pub const TOPK_CUBIN_PATH: &str = env!("FORGE_TOPK_CUBIN_PATH");
pub const MXFP_GEMM_CUBIN_PATH: &str = env!("FORGE_MXFP_GEMM_CUBIN_PATH");

pub const CUDA_KERNEL_POLICY_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/cuda-kernel-policy-v1.json"
));

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CudaToolkitComponentAttestation {
    pub name: &'static str,
    pub sha256: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CudaKernelModuleAttestation {
    pub name: &'static str,
    pub source_sha256: &'static str,
    pub module_sha256: &'static str,
    pub module_bytes: u64,
    pub entry_points: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CudaKernelBuildAttestation {
    pub schema: &'static str,
    pub toolkit_version: &'static str,
    pub toolkit_version_manifest_sha256: &'static str,
    pub toolkit_components: &'static [CudaToolkitComponentAttestation],
    pub nvcc_release: &'static str,
    pub nvcc_version: &'static str,
    pub nvcc_build: &'static str,
    pub nvcc_sha256: &'static str,
    pub host_compiler_sha256: &'static str,
    pub target: &'static str,
    pub module_kind: &'static str,
    pub fmad: bool,
    pub compiler_flags: &'static [&'static str],
    pub policy_record_sha256: &'static str,
    pub modules: &'static [CudaKernelModuleAttestation],
}

include!(concat!(env!("OUT_DIR"), "/forge_cuda_kernel_build.rs"));

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CudaKernelRuntimeAttestation {
    pub schema: &'static str,
    pub module_name: &'static str,
    pub source_sha256: &'static str,
    pub module_kind: &'static str,
    pub module_sha256: &'static str,
    pub module_bytes: u64,
    pub target: &'static str,
    pub fmad: bool,
    pub toolkit_version: &'static str,
    pub toolkit_version_manifest_sha256: &'static str,
    pub toolkit_components: &'static [CudaToolkitComponentAttestation],
    pub nvcc_release: &'static str,
    pub nvcc_version: &'static str,
    pub nvcc_build: &'static str,
    pub nvcc_sha256: &'static str,
    pub host_compiler_sha256: &'static str,
    pub policy_record_sha256: &'static str,
    pub runtime_ordinal: u32,
    pub driver_ordinal: u32,
    pub physical_device: String,
    pub compute_capability: (i32, i32),
    pub module_load_elapsed_ns: u64,
}

#[derive(Debug)]
pub(crate) struct LoadedCudaModule {
    module: Arc<CudaModule>,
    module_load_elapsed_ns: u64,
}

impl LoadedCudaModule {
    pub(crate) fn module(&self) -> Arc<CudaModule> {
        self.module.clone()
    }
}

pub fn cuda_kernel_build_attestation() -> &'static CudaKernelBuildAttestation {
    &CUDA_KERNEL_BUILD_ATTESTATION
}

pub(crate) fn module_attestation(name: &str) -> Result<&'static CudaKernelModuleAttestation> {
    CUDA_KERNEL_BUILD_ATTESTATION
        .modules
        .iter()
        .find(|module| module.name == name)
        .ok_or_else(|| ForgeError::RuntimeBoundary {
            code: "CALYX_FORGE_CUDA_KERNEL_ATTESTATION_MISSING",
            detail: format!("no embedded module attestation exists for kernel set {name}"),
            remediation: KERNEL_REMEDIATION,
        })
}

pub(crate) fn ensure_kernel_capability(ctx: &CudaContext, module_name: &str) -> Result<()> {
    if ctx.compute_capability() == (12, 0) {
        return Ok(());
    }
    Err(ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_CUDA_KERNEL_CAPABILITY_MISMATCH",
        detail: format!(
            "module={module_name} target={} runtime_ordinal={} driver_ordinal={} physical_device={} observed_compute_capability={}.{} expected=12.0",
            CUDA_KERNEL_BUILD_ATTESTATION.target,
            ctx.runtime_ordinal(),
            ctx.driver_ordinal(),
            ctx.physical_identity(),
            ctx.compute_capability().0,
            ctx.compute_capability().1
        ),
        remediation: KERNEL_REMEDIATION,
    })
}

pub(crate) fn load_embedded_cubin(
    ctx: &CudaContext,
    module_name: &'static str,
    bytes: &'static [u8],
    cache: &std::sync::OnceLock<Result<LoadedCudaModule>>,
) -> Result<Arc<CudaModule>> {
    ensure_kernel_capability(ctx, module_name)?;
    let attestation = module_attestation(module_name)?;
    let loaded = cache.get_or_init(|| {
        let observed_bytes = u64::try_from(bytes.len()).map_err(|_| ForgeError::RuntimeBoundary {
            code: "CALYX_FORGE_CUDA_KERNEL_MODULE_SIZE_INVALID",
            detail: format!("module={module_name} byte length exceeds u64"),
            remediation: KERNEL_REMEDIATION,
        })?;
        let observed_sha256 = sha256_hex(bytes);
        if observed_bytes != attestation.module_bytes
            || observed_sha256 != attestation.module_sha256
        {
            return Err(ForgeError::RuntimeBoundary {
                code: "CALYX_FORGE_CUDA_KERNEL_MODULE_ATTESTATION_MISMATCH",
                detail: format!(
                    "module={module_name} expected_bytes={} observed_bytes={observed_bytes} expected_sha256={} observed_sha256={observed_sha256}",
                    attestation.module_bytes, attestation.module_sha256
                ),
                remediation: KERNEL_REMEDIATION,
            });
        }
        let started = Instant::now();
        let module = ctx
            .inner()
            .load_module(Ptx::from_binary(bytes.to_vec()))
            .map_err(|error| ForgeError::RuntimeBoundary {
                code: "CALYX_FORGE_CUDA_KERNEL_MODULE_LOAD_FAILED",
                detail: format!(
                    "module={module_name} target={} sha256={} runtime_ordinal={} driver_ordinal={} physical_device={} detail={error}",
                    CUDA_KERNEL_BUILD_ATTESTATION.target,
                    attestation.module_sha256,
                    ctx.runtime_ordinal(),
                    ctx.driver_ordinal(),
                    ctx.physical_identity()
                ),
                remediation: KERNEL_REMEDIATION,
            })?;
        Ok(LoadedCudaModule {
            module,
            module_load_elapsed_ns: elapsed_ns(started)?,
        })
    });
    match loaded {
        Ok(loaded) => Ok(loaded.module()),
        Err(error) => Err(error.clone()),
    }
}

pub(crate) fn runtime_attestation(
    ctx: &CudaContext,
    module_name: &'static str,
    loaded: &LoadedCudaModule,
) -> Result<CudaKernelRuntimeAttestation> {
    let module = module_attestation(module_name)?;
    Ok(CudaKernelRuntimeAttestation {
        schema: CUDA_KERNEL_BUILD_ATTESTATION.schema,
        module_name,
        source_sha256: module.source_sha256,
        module_kind: CUDA_KERNEL_BUILD_ATTESTATION.module_kind,
        module_sha256: module.module_sha256,
        module_bytes: module.module_bytes,
        target: CUDA_KERNEL_BUILD_ATTESTATION.target,
        fmad: CUDA_KERNEL_BUILD_ATTESTATION.fmad,
        toolkit_version: CUDA_KERNEL_BUILD_ATTESTATION.toolkit_version,
        toolkit_version_manifest_sha256: CUDA_KERNEL_BUILD_ATTESTATION
            .toolkit_version_manifest_sha256,
        toolkit_components: CUDA_KERNEL_BUILD_ATTESTATION.toolkit_components,
        nvcc_release: CUDA_KERNEL_BUILD_ATTESTATION.nvcc_release,
        nvcc_version: CUDA_KERNEL_BUILD_ATTESTATION.nvcc_version,
        nvcc_build: CUDA_KERNEL_BUILD_ATTESTATION.nvcc_build,
        nvcc_sha256: CUDA_KERNEL_BUILD_ATTESTATION.nvcc_sha256,
        host_compiler_sha256: CUDA_KERNEL_BUILD_ATTESTATION.host_compiler_sha256,
        policy_record_sha256: CUDA_KERNEL_BUILD_ATTESTATION.policy_record_sha256,
        runtime_ordinal: ctx.runtime_ordinal(),
        driver_ordinal: ctx.driver_ordinal(),
        physical_device: ctx.physical_identity().canonical_execution_token(),
        compute_capability: ctx.compute_capability(),
        module_load_elapsed_ns: loaded.module_load_elapsed_ns,
    })
}

fn elapsed_ns(started: Instant) -> Result<u64> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|_| ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_CUDA_TIMING_OVERFLOW",
        detail: "monotonic elapsed nanoseconds exceeded u64 while loading a CUDA module"
            .to_string(),
        remediation: KERNEL_REMEDIATION,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(feature = "cuda-policy-measurement")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaKernelMeasurementArtifact {
    pub module_name: &'static str,
    pub module_kind: &'static str,
    pub fmad: bool,
    pub bytes: &'static [u8],
}

#[cfg(feature = "cuda-policy-measurement")]
pub const CUDA_KERNEL_MEASUREMENT_ARTIFACTS: &[CudaKernelMeasurementArtifact] = &[
    CudaKernelMeasurementArtifact {
        module_name: "distance",
        module_kind: "ptx",
        fmad: false,
        bytes: include_bytes!(env!("FORGE_DISTANCE_FMAD_OFF_PTX_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "distance",
        module_kind: "cubin",
        fmad: false,
        bytes: include_bytes!(env!("FORGE_DISTANCE_FMAD_OFF_CUBIN_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "distance",
        module_kind: "ptx",
        fmad: true,
        bytes: include_bytes!(env!("FORGE_DISTANCE_FMAD_ON_PTX_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "distance",
        module_kind: "cubin",
        fmad: true,
        bytes: include_bytes!(env!("FORGE_DISTANCE_FMAD_ON_CUBIN_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "topk",
        module_kind: "ptx",
        fmad: false,
        bytes: include_bytes!(env!("FORGE_TOPK_FMAD_OFF_PTX_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "topk",
        module_kind: "cubin",
        fmad: false,
        bytes: include_bytes!(env!("FORGE_TOPK_FMAD_OFF_CUBIN_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "topk",
        module_kind: "ptx",
        fmad: true,
        bytes: include_bytes!(env!("FORGE_TOPK_FMAD_ON_PTX_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "topk",
        module_kind: "cubin",
        fmad: true,
        bytes: include_bytes!(env!("FORGE_TOPK_FMAD_ON_CUBIN_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "mxfp_gemm",
        module_kind: "ptx",
        fmad: false,
        bytes: include_bytes!(env!("FORGE_MXFP_GEMM_FMAD_OFF_PTX_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "mxfp_gemm",
        module_kind: "cubin",
        fmad: false,
        bytes: include_bytes!(env!("FORGE_MXFP_GEMM_FMAD_OFF_CUBIN_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "mxfp_gemm",
        module_kind: "ptx",
        fmad: true,
        bytes: include_bytes!(env!("FORGE_MXFP_GEMM_FMAD_ON_PTX_PATH")),
    },
    CudaKernelMeasurementArtifact {
        module_name: "mxfp_gemm",
        module_kind: "cubin",
        fmad: true,
        bytes: include_bytes!(env!("FORGE_MXFP_GEMM_FMAD_ON_CUBIN_PATH")),
    },
];
