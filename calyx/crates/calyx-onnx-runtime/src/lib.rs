//! Process-global, pinned ONNX Runtime ownership for Calyx consumers.
//!
//! Every in-process ORT consumer must enter through this crate before touching
//! an `ort` API. The crate owns the sole exact `ort::set_api` commit and rejects
//! ambient runtime-path variables, preloaded competing ORT modules, runtime
//! drift, and CUDA device changes.

// The Windows ORT implementation (`src/windows.rs`, ~3.1k LOC) was removed
// 2026-08-02 with the Windows platform doctrine: ASTROLABE targets
// aarch64-apple-darwin only. It was gated `cfg(all(feature = "runtime",
// windows))` and so never compiled on this host, which is exactly why its
// removal cannot change macOS behavior. Restoring Windows support means
// restoring a supported Windows target first, not un-deleting this module.

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
