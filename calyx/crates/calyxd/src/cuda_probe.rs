//! CUDA device preflight for `calyxd` (PH65 · T02).
//!
//! In server mode any CUDA initialization failure is immediately fatal with a
//! structured [`DaemonError::DeviceUnavailable`] (`CALYX_FORGE_DEVICE_UNAVAILABLE`)
//! — there is NO silent fallback to CPU (16 §4, A16). The probe runs at startup
//! before the daemon accepts any work, so a GPU-less or mis-driver'd host fails
//! loud at boot instead of degrading silently at dispatch time.
//!
//! The env var `CALYX_FORCE_CUDA_FAIL=1` forces the failure path deterministically
//! for FSV (only the exact string `"1"` triggers it).

use crate::error::DaemonError;

/// Env var that deterministically forces the failure path (FSV injection).
pub const FORCE_FAIL_ENV: &str = "CALYX_FORCE_CUDA_FAIL";

/// Device facts captured at a successful CUDA init. Logged at startup and reused
/// by the VRAM budget enforcer (T03) and the healthcheck (T04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaDeviceInfo {
    /// Marketing name reported by the CUDA/NVML stack.
    pub device_name: String,
    /// Total device VRAM in MiB.
    pub vram_total_mib: u32,
    /// Compute capability as `"major.minor"`, e.g. `"12.0"` (sm_120).
    pub compute_cap: String,
}

/// Probe the CUDA device `calyxd` will run Forge on. Fatal on any failure;
/// never returns a CPU-fallback placeholder.
///
/// `CALYX_FORCE_CUDA_FAIL=1` short-circuits to a forced failure for FSV. Any
/// other value (absent, `"0"`, etc.) runs the real probe.
pub fn probe_cuda_device() -> Result<CudaDeviceInfo, DaemonError> {
    if std::env::var(FORCE_FAIL_ENV).as_deref() == Ok("1") {
        return Err(DaemonError::device_unavailable(format!(
            "forced by {FORCE_FAIL_ENV}=1 (deterministic FSV injection)"
        )));
    }
    probe_real_device()
}

#[cfg(feature = "cuda")]
fn probe_real_device() -> Result<CudaDeviceInfo, DaemonError> {
    // Real `cudaSetDevice`/`cuInit` via calyx-forge. determinism=false: the
    // budgeter/probe don't need the deterministic-kernel mode here.
    let runtime_ordinal = calyx_forge::configured_cuda_runtime_ordinal().map_err(|err| {
        DaemonError::device_unavailable(format!("CUDA device selection failed: {err}"))
    })?;
    let ctx = calyx_forge::init_cuda(runtime_ordinal, false).map_err(|err| {
        DaemonError::device_unavailable(format!(
            "CUDA init on Runtime-visible ordinal {runtime_ordinal} failed: {err}"
        ))
    })?;
    let (major, minor) = ctx.compute_capability();
    let total = ctx.total_mem_mib();
    let vram_total_mib = u32::try_from(total).map_err(|_| {
        DaemonError::device_unavailable(format!("device VRAM {total} MiB does not fit u32"))
    })?;
    Ok(CudaDeviceInfo {
        device_name: ctx.name().to_string(),
        vram_total_mib,
        compute_cap: format!("{major}.{minor}"),
    })
}

#[cfg(not(feature = "cuda"))]
fn probe_real_device() -> Result<CudaDeviceInfo, DaemonError> {
    // Fail loud: a non-CUDA build cannot serve in GPU mode. This is the absence
    // of a capability, not a fallback — the daemon refuses to start.
    Err(DaemonError::device_unavailable(
        "calyxd was built without the `cuda` feature; rebuild with `--features cuda` \
         on an NVIDIA GPU host (server mode requires a working GPU and will not start without one)",
    ))
}
