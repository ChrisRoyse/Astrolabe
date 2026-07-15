//! The PH59 25-hazard register exposed as one gauge per hazard (PH66 T03).
//!
//! Each hazard from PRD `24 §7` / the PH59 hazard register gets a
//! `calyx_hazard_<id>` gauge carrying a
//! `hazard` label equal to its id. The value is 1 when that hazard's mitigation
//! tripwire is currently firing and 0 when nominal. Distinct metric *names* (not
//! one name with 25 label values) are intentional: the Grafana 25-row table and
//! the Alertmanager rules reference hazards individually, and the FSV gate greps
//! `^calyx_hazard_` expecting exactly one line per hazard.

use prometheus::{IntGaugeVec, Opts, Registry};

/// Canonical PH59 hazard ids, in register order (rows 1–25). This array is the
/// single source of truth for which hazards exist; the order matches the PH59
/// task cards (T01 rows 1–5, T02 rows 6–8, … T06 rows 22–25).
pub const HAZARD_IDS: [&str; 25] = [
    // T01 — resource/operational (rows 1–5)
    "compaction_storm",
    "flush_stall",
    "tombstone_buildup",
    "fsync_spike",
    "wal_bloat",
    // T02 — MVCC/VRAM/heap (rows 6–8)
    "mvcc_version_pileup",
    "vram_oom",
    "heap_oom",
    // T03 — numerical/index (rows 9–12)
    "nan_propagation",
    "quant_drift",
    "codebook_staleness",
    "ann_corruption",
    // T04 — concurrency (rows 13–16)
    "hot_shard_skew",
    "lock_contention",
    "cache_stampede",
    "slow_lens_hol",
    // T05 — disk/clock/anneal (rows 17–21)
    "disk_full",
    "arc_thrash",
    "clock_skew",
    "anneal_thrash",
    "panel_explosion",
    // T06 — security/upgrade (rows 22–25)
    "secret_leakage",
    "nondeterminism",
    "whole_host_loss",
    "upgrade_skew",
];

/// One `calyx_hazard_<id>` gauge per PH59 hazard, registered into a shared
/// registry and pre-initialized to 0 (nominal) so all 25 series exist from the
/// first scrape.
pub struct HazardGauges {
    gauges: Vec<(&'static str, IntGaugeVec)>,
}

impl HazardGauges {
    /// Registers all 25 hazard gauges into `registry`. A duplicate name is a
    /// programming error and panics at init (never silently overwrite a metric).
    pub fn register(registry: &Registry) -> Self {
        let mut gauges = Vec::with_capacity(HAZARD_IDS.len());
        for &id in HAZARD_IDS.iter() {
            let gauge = IntGaugeVec::new(
                Opts::new(
                    format!("calyx_hazard_{id}"),
                    format!(
                        "PH59 hazard '{id}': 1 when this hazard's mitigation tripwire is \
                         currently firing, 0 when nominal (fail-closed)"
                    ),
                ),
                &["hazard"],
            )
            .unwrap_or_else(|error| panic!("define calyx_hazard_{id}: {error}"));
            registry
                .register(Box::new(gauge.clone()))
                .unwrap_or_else(|error| {
                    panic!("register calyx_hazard_{id} (duplicate registration is a bug): {error}")
                });
            gauge.with_label_values(&[id]).set(0);
            gauges.push((id, gauge));
        }
        Self { gauges }
    }

    /// Sets hazard `hazard_id` to triggered (1) or nominal (0). An unknown id is
    /// a hard error — the caller named a hazard outside the 25-row register, and
    /// silently inventing a new series would corrupt the dashboard (fail-closed).
    pub fn set(&self, hazard_id: &str, triggered: bool) -> Result<(), String> {
        let gauge = self
            .gauges
            .iter()
            .find(|(id, _)| *id == hazard_id)
            .map(|(_, gauge)| gauge)
            .ok_or_else(|| {
                format!("unknown hazard id '{hazard_id}'; not one of the 25 PH59 register hazards")
            })?;
        gauge
            .with_label_values(&[hazard_id])
            .set(i64::from(triggered));
        Ok(())
    }
}
