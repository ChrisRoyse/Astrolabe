//! Env-gated permanent sub-phase timing for the kernel_artifact and
//! label_propagation cold-index phases (#443).
//!
//! Mirrors the `ASTRO_ARCH_TIMING` pattern (#434) and the `ASTRO_SHADOW_TIMING`
//! corpus-phase telemetry (#401): silent unless the operator sets
//! `ASTRO_KERNEL_TIMING`, so a normal index prints nothing. When set, each
//! measured kernel-build / label-propagation sub-stage emits one line
//!
//! ```text
//! astro.kernel.timing phase=<phase> sub=<sub-stage> ms=<wall-ms>
//! ```
//!
//! to stderr so the #443 3-scale matrix can attribute the phase totals (at
//! n=45,557: kernel_artifact 83,238ms, label_propagation 43,694ms) to a real
//! sub-stage instead of a guess. Low volume — a handful of lines per phase per
//! index, never per-node spew. Timing carries no behaviour: the emitted numbers
//! never feed a decision, so a build with the variable set is byte-identical to
//! one without it.

/// Sub-phase wall-clock timer for one kernel/label-propagation phase.
///
/// Construct with [`KernelPhaseTiming::start`] naming the enclosing phase, then
/// call [`KernelPhaseTiming::lap`] after each sub-stage; each `lap` reports the
/// time since the previous `lap` (or since `start`) and re-arms the mark. The
/// enablement decision is read once at `start`, so a disabled timer is a couple
/// of cheap `Instant::now()` calls and nothing else.
pub struct KernelPhaseTiming {
    enabled: bool,
    phase: &'static str,
    mark: std::time::Instant,
}

impl KernelPhaseTiming {
    /// Starts a timer for `phase`, reading `ASTRO_KERNEL_TIMING` once.
    pub fn start(phase: &'static str) -> Self {
        Self {
            enabled: std::env::var_os("ASTRO_KERNEL_TIMING").is_some(),
            phase,
            mark: std::time::Instant::now(),
        }
    }

    /// Whether timing lines are being emitted (the variable was set at `start`).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Emits the elapsed wall-clock since the previous `lap`/`start` for
    /// sub-stage `sub`, then re-arms the mark. A no-op except re-arming the mark
    /// when timing is disabled.
    pub fn lap(&mut self, sub: &str) {
        if self.enabled {
            eprintln!(
                "astro.kernel.timing phase={} sub={} ms={}",
                self.phase,
                sub,
                self.mark.elapsed().as_millis()
            );
        }
        self.mark = std::time::Instant::now();
    }
}
