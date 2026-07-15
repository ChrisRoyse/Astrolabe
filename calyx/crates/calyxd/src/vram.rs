//! Daemon-level VRAM budget enforcer (PH65 · T03).
//!
//! `calyxd` can share one CUDA GPU with co-resident embedding services and
//! other GPU workloads. Before any Forge dispatch the daemon must confirm
//! the configured `vram_budget_mib` ceiling is not breached *given whatever is
//! already resident*. Any request that would breach it fails closed with
//! `CALYX_FORGE_VRAM_BUDGET` — no silent over-allocation.
//!
//! Live usage is read via **NVML** (`nvml-wrapper`), not `cudaMemGetInfo`: NVML
//! is the library `nvidia-smi` itself uses, so it reports the true board total
//! and device-wide used bytes consistent with `nvidia-smi`, whereas
//! `cudaMemGetInfo` reports the runtime-usable total (~32110 MiB, net of the
//! CUDA context + driver reserve) and only post-context free. NVML is the right
//! source of truth for honoring every co-resident workload. The usage probe is injected
//! behind [`VramUsage`] so the budget arithmetic is unit-tested with
//! hand-computed MiB on any host.
//!
//! Power: Calyx does not schedule against power directly — it stays within the
//! VRAM budget, which keeps concurrent kernel pressure (and thus power) bounded.

use serde::Serialize;

use crate::cuda_probe::CudaDeviceInfo;
use crate::error::DaemonError;

const BYTES_PER_MIB: u64 = 1024 * 1024;

/// TEI endpoints documented for operator-facing budget-exhaustion errors.
const TEI_ENDPOINTS: &str = ":18190 (calyx-e5), :18188 (calyx-bge-m3), :8088 (legacy general), :8089 (reranker), :8090 (legal)";

/// A point-in-time device VRAM reading in MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VramReading {
    /// Total board VRAM reported by NVML.
    pub total_mib: u32,
    /// Device-wide VRAM currently in use by ALL processes (incl. resident TEI).
    pub used_mib: u32,
}

/// Source of live device VRAM usage. Production reads NVML; tests inject a
/// deterministic reading. A probe failure is `Err` — never a zero-fill.
pub trait VramUsage {
    fn read(&self) -> Result<VramReading, DaemonError>;
}

/// Startup audit snapshot, logged at boot and serialized for the health JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VramAuditReport {
    /// Device-wide VRAM resident before Calyx allocates (the TEI + others footprint).
    pub tei_used_mib: u32,
    /// Configured Calyx ceiling from `calyx.toml`.
    pub calyx_budget_mib: u32,
    /// Board total VRAM (NVML), e.g. 32607.
    pub device_total_mib: u32,
}

/// Enforces the configured VRAM ceiling against live device usage.
pub struct VramBudget<U: VramUsage> {
    budget_mib: u32,
    device_total_mib: u32,
    usage: U,
}

// Manual Debug (the NVML handle in `usage` is not `Debug`); prints the budget
// fields, which is what logs and `unwrap_err()` diagnostics actually want.
impl<U: VramUsage> std::fmt::Debug for VramBudget<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VramBudget")
            .field("budget_mib", &self.budget_mib)
            .field("device_total_mib", &self.device_total_mib)
            .finish_non_exhaustive()
    }
}

impl<U: VramUsage> VramBudget<U> {
    /// Direct constructor (used by `from_config` and by tests with a mock probe).
    pub fn new(budget_mib: u32, device_total_mib: u32, usage: U) -> Self {
        Self {
            budget_mib,
            device_total_mib,
            usage,
        }
    }

    /// Build from the config budget + a probed device, validating the budget
    /// fits the board and that residents have not already exhausted it.
    ///
    /// Fail-closed at construction (not later at dispatch):
    /// - `vram_budget_mib > device board total` → `CALYX_FORGE_VRAM_BUDGET`.
    /// - resident footprint already `> vram_budget_mib` → `CALYX_FORGE_VRAM_BUDGET`
    ///   naming the TEI endpoints.
    pub fn from_config(
        cfg_budget_mib: u32,
        device: &CudaDeviceInfo,
        usage: U,
    ) -> Result<Self, DaemonError> {
        let reading = usage.read()?;
        let device_total_mib = reading.total_mib;
        if cfg_budget_mib == 0 {
            return Err(DaemonError::vram_budget(
                "vram_budget_mib is 0; the daemon needs a positive budget to dispatch Forge work",
            ));
        }
        if cfg_budget_mib > device_total_mib {
            return Err(DaemonError::vram_budget(format!(
                "vram_budget_mib {cfg_budget_mib} exceeds device board total {device_total_mib} MiB \
                 (NVML); cuda-probe reported {} MiB usable",
                device.vram_total_mib
            )));
        }
        if reading.used_mib > cfg_budget_mib {
            return Err(DaemonError::vram_budget(format!(
                "resident GPU footprint {} MiB already exceeds vram_budget_mib {cfg_budget_mib}; \
                 free GPU memory or raise the budget (resident TEI: {TEI_ENDPOINTS})",
                reading.used_mib
            )));
        }
        Ok(Self::new(cfg_budget_mib, device_total_mib, usage))
    }

    /// Live device-wide VRAM in use (incl. resident TEI), in MiB.
    pub fn allocated_mib(&self) -> Result<u32, DaemonError> {
        Ok(self.usage.read()?.used_mib)
    }

    /// Budget headroom remaining; saturates at 0 (never underflows).
    pub fn available_mib(&self) -> Result<u32, DaemonError> {
        Ok(self.budget_mib.saturating_sub(self.allocated_mib()?))
    }

    /// Admission check before a Forge dispatch. Fails closed with
    /// `CALYX_FORGE_VRAM_BUDGET` if `in-use + required` would breach the budget.
    pub fn check_can_allocate(&self, required_mib: u32) -> Result<(), DaemonError> {
        let used = self.allocated_mib()?;
        let projected = used.saturating_add(required_mib);
        if projected > self.budget_mib {
            return Err(DaemonError::vram_budget(format!(
                "request {required_mib} MiB + in-use {used} MiB = {projected} MiB exceeds \
                 vram_budget_mib {} MiB (resident TEI: {TEI_ENDPOINTS})",
                self.budget_mib
            )));
        }
        Ok(())
    }

    /// Snapshot the resident footprint vs budget at startup.
    pub fn startup_vram_audit(&self) -> Result<VramAuditReport, DaemonError> {
        let used = self.allocated_mib()?;
        Ok(VramAuditReport {
            tei_used_mib: used,
            calyx_budget_mib: self.budget_mib,
            device_total_mib: self.device_total_mib,
        })
    }
}

/// Production [`VramUsage`] backed by NVML (`nvml-wrapper`). NVML is loaded
/// dynamically at construction; absence of the driver/library is a loud error.
pub struct NvmlVramUsage {
    nvml: nvml_wrapper::Nvml,
}

impl NvmlVramUsage {
    /// Initialize NVML once (the constructor dynamically loads `libnvidia-ml`,
    /// which is comparatively expensive — hold the handle for the daemon's life).
    pub fn init() -> Result<Self, DaemonError> {
        // Load the driver-side library name for the host OS. Linux driver-only
        // hosts ship `libnvidia-ml.so.1` but not the unversioned dev symlink;
        // Windows driver hosts expose `nvml.dll` in System32.
        let library = nvml_library_name();
        let nvml = nvml_wrapper::Nvml::builder()
            .lib_path(std::ffi::OsStr::new(library))
            .init()
            .map_err(|err| {
                DaemonError::device_unavailable(format!(
                    "NVML init failed loading {library} (is the NVIDIA driver present?): {err}"
                ))
            })?;
        Ok(Self { nvml })
    }
}

impl VramUsage for NvmlVramUsage {
    fn read(&self) -> Result<VramReading, DaemonError> {
        let device = self.nvml.device_by_index(0).map_err(|err| {
            DaemonError::device_unavailable(format!("NVML device_by_index(0) failed: {err}"))
        })?;
        let mem = device.memory_info().map_err(|err| {
            DaemonError::device_unavailable(format!("NVML memory_info() failed: {err}"))
        })?;
        let total_mib = u32::try_from(mem.total / BYTES_PER_MIB).map_err(|_| {
            DaemonError::vram_budget(format!(
                "NVML total {} bytes does not fit u32 MiB",
                mem.total
            ))
        })?;
        let used_mib = u32::try_from(mem.used / BYTES_PER_MIB).map_err(|_| {
            DaemonError::vram_budget(format!("NVML used {} bytes does not fit u32 MiB", mem.used))
        })?;
        Ok(VramReading {
            total_mib,
            used_mib,
        })
    }
}

fn nvml_library_name() -> &'static str {
    if cfg!(windows) {
        "nvml.dll"
    } else {
        "libnvidia-ml.so.1"
    }
}

