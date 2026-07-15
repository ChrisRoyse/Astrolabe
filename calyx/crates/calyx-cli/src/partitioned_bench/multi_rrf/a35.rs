use std::collections::BTreeSet;

use calyx_core::CalyxError;
use serde_json::{Value, json};

use super::{OpenSlot, Plan, report};
use crate::a35_signal::require_recorded_countable_content_signal_kind;
use crate::error::{CliError, CliResult};

const MIN_LENSES: usize = 10;
const MIN_BITS_ABOUT: f32 = 0.05;

pub(super) fn validate_plan(plan: &Plan) -> CliResult {
    if plan.slots.len() < MIN_LENSES {
        return Err(a35_error(
            "CALYX_FSV_A35_PANEL_TOO_SMALL",
            format!(
                "partitioned-rrf plan has {} lenses; A35 requires at least {MIN_LENSES}",
                plan.slots.len()
            ),
            "run the gate with a persisted real panel of at least ten frozen content lenses",
        ));
    }
    let mut lens_ids = BTreeSet::new();
    for slot in &plan.slots {
        let name = slot.name.as_deref().unwrap_or("<unnamed>");
        require_recorded_countable_content_signal_kind(
            name,
            slot.signal_kind.as_deref(),
            "partitioned-rrf A35 gate",
        )?;
        let lens_id = required(slot.lens_id.as_deref(), slot.slot, "lens_id")?;
        let weights = required(slot.weights_sha256.as_deref(), slot.slot, "weights_sha256")?;
        if !hex_len(lens_id, 32) {
            return Err(a35_error(
                "CALYX_FSV_A35_LENS_ID_INVALID",
                format!("slot {} lens_id must be 32 lowercase hex chars", slot.slot),
                "persist the frozen LensId from the registry in the RRF plan",
            ));
        }
        if !hex_len(weights, 64) {
            return Err(a35_error(
                "CALYX_FSV_A35_WEIGHTS_SHA_INVALID",
                format!(
                    "slot {} weights_sha256 must be 64 lowercase hex chars",
                    slot.slot
                ),
                "persist the frozen weights_sha256 from the registry in the RRF plan",
            ));
        }
        let bits = slot.bits_about.ok_or_else(|| {
            a35_error(
                "CALYX_FSV_A35_BITS_REQUIRED",
                format!("slot {} missing bits_about", slot.slot),
                "read Assay bits_about for every lens before running the RRF gate",
            )
        })?;
        if !bits.is_finite() || bits < MIN_BITS_ABOUT {
            return Err(a35_error(
                "CALYX_FSV_A35_BITS_BELOW_FLOOR",
                format!(
                    "slot {} bits_about={bits:.6} below {MIN_BITS_ABOUT:.2}",
                    slot.slot
                ),
                "use only signal-bearing lenses with Assay bits_about at or above the floor",
            ));
        }
        if !lens_ids.insert(lens_id.to_owned()) {
            return Err(a35_error(
                "CALYX_FSV_A35_DUPLICATE_LENS",
                format!("duplicate lens_id {lens_id} in partitioned-rrf plan"),
                "use ten distinct frozen content lenses in the panel",
            ));
        }
    }
    Ok(())
}

pub(super) fn lens_roster(slots: &[OpenSlot]) -> Vec<Value> {
    slots
        .iter()
        .map(|slot| {
            json!({
                "slot": slot.spec.slot,
                "name": slot.spec.name.as_deref(),
                "lens_id": slot.spec.lens_id.as_deref().expect("A35 validated"),
                "weights_sha256": slot.spec.weights_sha256.as_deref().expect("A35 validated"),
                "signal_kind": slot.spec.signal_kind.as_deref().expect("A35 validated"),
            })
        })
        .collect()
}

pub(super) fn per_lens_bits(slots: &[OpenSlot]) -> Vec<Value> {
    slots
        .iter()
        .map(|slot| {
            json!({
                "slot": slot.spec.slot,
                "name": slot.spec.name.as_deref(),
                "lens_id": slot.spec.lens_id.as_deref().expect("A35 validated"),
                "signal_kind": slot.spec.signal_kind.as_deref().expect("A35 validated"),
                "bits_about": slot.spec.bits_about.expect("A35 validated"),
            })
        })
        .collect()
}

pub(super) fn fused_result(
    fused_recall: Option<f32>,
    latency_us: &Value,
    sample_readback: &[Value],
) -> Value {
    json!({
        "fusion": "rrf",
        "metric_class": report::METRIC_CLASS,
        "metric_scope": report::METRIC_SCOPE,
        "truth_reference_class": report::TRUTH_REFERENCE_CLASS,
        "valid_real_outcome": false,
        "grounded_phase_exit_eligible": false,
        "ground_truth_recall_at_k": fused_recall,
        "latency_us": latency_us,
        "sample_fused_top_k": sample_readback
            .first()
            .and_then(|row| row.get("partitioned_fused_top_k"))
            .cloned()
            .unwrap_or_else(|| json!([])),
    })
}

fn required<'a>(value: Option<&'a str>, slot: u16, field: &str) -> CliResult<&'a str> {
    value.filter(|text| !text.is_empty()).ok_or_else(|| {
        a35_error(
            "CALYX_FSV_A35_ROSTER_REQUIRED",
            format!("slot {slot} missing {field}"),
            "persist lens_id and weights_sha256 for every RRF plan slot",
        )
    })
}

fn hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn a35_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    CliError::Calyx(CalyxError {
        code,
        message: message.into(),
        remediation,
    })
}
