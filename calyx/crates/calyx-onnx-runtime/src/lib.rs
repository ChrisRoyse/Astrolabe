//! Process-global, pinned ONNX Runtime ownership for Calyx consumers.
//!
//! Every in-process ORT consumer must enter through this crate before touching
//! an `ort` API. The crate owns the sole exact `ort::set_api` commit and rejects
//! ambient runtime-path variables, preloaded competing ORT modules, runtime
//! drift, and CUDA device changes.

#[cfg(all(feature = "runtime", windows))]
mod windows;

#[cfg(all(feature = "runtime", windows))]
pub use windows::{
    ImmutableDirectoryRoot, ImmutableFileIdentity, ImmutableFileSnapshot, OnnxCpuAuthorization,
    OnnxCudaDeviceAttestation, OnnxCudaExecutionStream, OnnxLoadedModuleAttestation,
    OnnxRuntimeArtifactAttestation, OnnxRuntimeAttestation, OnnxRuntimeContractAttestation,
    attest_cuda_provider_after_session, authorize_cpu_companion, available_host_memory_bytes,
    create_cuda_execution_stream, current_runtime_attestation, ensure_runtime,
    expected_runtime_contract, initialize_pinned_cuda_runtime_boundary, open_immutable_directory,
    selected_cuda_device, snapshot_immutable_file,
};

/// Requested execution policy for the exact pinned ORT environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnnxRuntimePolicy {
    /// Require CUDA and fail when any part of provider/device initialization
    /// cannot be proven. This policy is never retried on CPU.
    CudaFailLoud,
    /// Construct a separately commissioned CPU lens. Authorization that CUDA
    /// is genuinely absent belongs to the caller's startup-selection layer.
    CpuExplicit,
}
