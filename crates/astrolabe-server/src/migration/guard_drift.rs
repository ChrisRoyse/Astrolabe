//! Server wiring for guard drift monitoring (P7.4, #48 server residue, DoD #2).
//!
//! Each `guard_check` produces per-slot pass/fail outcomes. The guard crate
//! (`astrolabe_guard::drift`) owns the rolling per-slot rejection-rate monitor with
//! its hysteresis latch ("fires exactly once per window crossing"); this module
//! makes that monitor **durable across checks** — every check is a separate
//! request/process, so the rolling window and the latch are persisted as the
//! crate's [`SlotDriftSnapshot`] set in the config store and restored on the next
//! check. When a slot crosses its calibrated drift bound the emitted
//! [`DriftProposal`] is appended to a bounded per-project proposals list, which is
//! surfaced (labeled) on `optimizer_status` and `get_readiness`.
//!
//! The persisted image round-trips through [`SlotDriftSnapshot::to_json`] /
//! [`SlotDriftSnapshot::from_json`] (proven to preserve the latch in the guard
//! crate's `snapshot_round_trip_preserves_latch_no_refire` test), so the
//! "fires once per crossing" property holds across process boundaries.

use super::*;

use astrolabe_guard::check::CheckReport;
use astrolabe_guard::drift::{ProfileDriftMonitor, SlotDriftSnapshot};
use astrolabe_guard::profile::GuardProfile;

/// Config-store key (per project) holding the per-slot monitor snapshots.
const GUARD_DRIFT_SNAPSHOTS_KEY: &str = "guard_drift_snapshots_json";
/// Config-store key (per project) holding the bounded drift-proposal history.
const GUARD_DRIFT_PROPOSALS_KEY: &str = "guard_drift_proposals_json";
/// Retained recent proposals (a bounded surface, not a knob that changes any
/// measured result — an operational cap on the surfaced history length).
const GUARD_DRIFT_PROPOSALS_RETAINED: usize = 50;

/// Record one `guard_check` report's per-slot outcomes into the durable drift
/// monitor, persisting the updated window/latch and appending any fresh crossing
/// proposals. Returns the number of proposals this report produced.
///
/// The monitor is restored from the persisted snapshots when present (preserving
/// the rolling window and hysteresis latch) and otherwise seeded from the
/// calibrated profile's drift bounds.
pub(crate) fn record_guard_check_outcomes(
    cache_dir: &Path,
    project: &str,
    profile: &GuardProfile,
    report: &CheckReport,
) -> Result<usize, DynError> {
    let mut monitor = match read_drift_snapshots(cache_dir, project)? {
        Some(snapshots) if !snapshots.is_empty() => {
            ProfileDriftMonitor::from_snapshots(&snapshots)
        }
        _ => ProfileDriftMonitor::from_profile(profile),
    };

    let proposals = monitor.observe_report(report);

    // Persist the updated per-slot snapshots (window + latch), readback-verified.
    let snapshots_json: Vec<Value> = monitor.snapshots().iter().map(snapshot_to_json).collect();
    let snapshots_text = serde_json::to_string(&snapshots_json)?;
    write_config_value(
        cache_dir,
        &metadata_key(project, GUARD_DRIFT_SNAPSHOTS_KEY),
        &snapshots_text,
    )?;
    let readback = read_config_value(cache_dir, &metadata_key(project, GUARD_DRIFT_SNAPSHOTS_KEY))?;
    if readback.as_deref() != Some(snapshots_text.as_str()) {
        return Err(format!(
            "ASTRO_GUARD_DRIFT_SNAPSHOT_MISMATCH: drift monitor snapshots for {project:?} did not read back byte-identically; remediation: the config store diverged from the committed monitor state"
        )
        .into());
    }

    if !proposals.is_empty() {
        let mut history = read_drift_proposals_raw(cache_dir, project)?;
        for proposal in &proposals {
            // The proposal's own canonical bytes are the durable record.
            let value: Value = serde_json::from_slice(&proposal.canonical_bytes())?;
            history.push(value);
        }
        let start = history.len().saturating_sub(GUARD_DRIFT_PROPOSALS_RETAINED);
        let trimmed = history[start..].to_vec();
        write_config_value(
            cache_dir,
            &metadata_key(project, GUARD_DRIFT_PROPOSALS_KEY),
            &serde_json::to_string(&trimmed)?,
        )?;
    }

    Ok(proposals.len())
}

/// Read the persisted per-slot monitor snapshots (None when unset).
fn read_drift_snapshots(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<Vec<SlotDriftSnapshot>>, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, GUARD_DRIFT_SNAPSHOTS_KEY))?
    else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(&raw)?;
    let Some(array) = value.as_array() else {
        return Ok(None);
    };
    let snapshots = array.iter().filter_map(snapshot_from_json).collect();
    Ok(Some(snapshots))
}

/// Map a monitor snapshot to its canonical persisted JSON (finite numbers).
fn snapshot_to_json(snapshot: &SlotDriftSnapshot) -> Value {
    json!({
        "slot": snapshot.slot,
        "window": snapshot.window,
        "drift_bound": finite_f64(snapshot.drift_bound),
        "calibrated_far": finite_f64(snapshot.calibrated_far),
        "samples": snapshot.samples,
        "above": snapshot.above,
    })
}

/// Parse a monitor snapshot from persisted JSON. Returns `None` on any missing or
/// mistyped field so a corrupt persisted image fails closed (the slot is dropped).
fn snapshot_from_json(value: &Value) -> Option<SlotDriftSnapshot> {
    Some(SlotDriftSnapshot {
        slot: value.get("slot")?.as_str()?.to_string(),
        window: value.get("window")?.as_u64()? as usize,
        drift_bound: value.get("drift_bound")?.as_f64()? as f32,
        calibrated_far: value.get("calibrated_far")?.as_f64()? as f32,
        samples: value
            .get("samples")?
            .as_array()?
            .iter()
            .map(Value::as_bool)
            .collect::<Option<Vec<bool>>>()?,
        above: value.get("above")?.as_bool()?,
    })
}

/// A finite JSON number for an `f32` (a non-finite value maps to `0`).
fn finite_f64(value: f32) -> Value {
    serde_json::Number::from_f64(value as f64)
        .map(Value::Number)
        .unwrap_or_else(|| Value::from(0))
}

/// Read the raw persisted drift-proposal history (empty when unset).
fn read_drift_proposals_raw(cache_dir: &Path, project: &str) -> Result<Vec<Value>, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, GUARD_DRIFT_PROPOSALS_KEY))?
    else {
        return Ok(Vec::new());
    };
    let value: Value = serde_json::from_str(&raw)?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

/// Surface the persisted drift proposals as a labeled section for
/// `optimizer_status` / `get_readiness`. Always present (an empty list when no
/// crossing has fired) so the surface is honest about "no drift observed".
pub(crate) fn drift_proposals_section(cache_dir: &Path, project: &str) -> Value {
    let proposals = read_drift_proposals_raw(cache_dir, project).unwrap_or_default();
    json!({
        "schema": "astro.guard.drift_surface.v1",
        "count": proposals.len(),
        "proposals": proposals,
        "trust": "verified",
        "freshness": if proposals.is_empty() { "not_evaluated" } else { "fresh" },
        "note": "recalibration proposals emitted when a guard slot's rolling rejection rate crosses its calibrated drift bound (1.5x FAR); each fires once per window crossing (Anneal recalibration lands P8)",
    })
}
