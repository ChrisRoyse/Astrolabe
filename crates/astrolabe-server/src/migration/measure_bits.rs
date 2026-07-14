use super::*;

use astrolabe_assay::{CalibrationConfig, StrategyObservation, build_calibration_card};

/// Response envelope schema for the `measure_bits` tool.
pub(crate) const MEASURE_BITS_SCHEMA: &str = "astrolabe.measure_bits.v1";
/// Schema of a persisted assay card document (the payload each mode serves).
pub(crate) const ASSAY_CARD_SCHEMA: &str = "astrolabe.assay_card.v1";

/// The six measurement modes the tool exposes (blueprint 08_ASSAY §8).
pub(crate) const MEASURE_BITS_MODES: [&str; 6] = [
    "signals",
    "sufficiency",
    "redundancy",
    "synergy",
    "causality",
    "calibration",
];

/// Config key of a persisted card for `(project, mode, axis?, scope?)`.
///
/// Panel-wide modes (`redundancy`, `calibration`) ignore the axis; a per-axis
/// mode keys its card by axis. Scope, when present, further partitions the key.
pub(crate) fn measure_bits_card_key(
    project: &str,
    mode: &str,
    axis: Option<&str>,
    scope: Option<&str>,
) -> String {
    let mut suffix = format!("assay_card.{mode}");
    if !mode_is_panel_wide(mode)
        && let Some(axis) = axis
    {
        suffix.push_str(&format!(".axis:{axis}"));
    }
    if let Some(scope) = scope {
        suffix.push_str(&format!(".scope:{scope}"));
    }
    metadata_key(project, &suffix)
}

/// Config key of the persisted calibration observations used by `refresh:true`.
pub(crate) fn measure_bits_calibration_inputs_key(project: &str, scope: Option<&str>) -> String {
    let mut suffix = "assay_calibration_inputs".to_string();
    if let Some(scope) = scope {
        suffix.push_str(&format!(".scope:{scope}"));
    }
    metadata_key(project, &suffix)
}

/// Whether a mode measures the whole panel (no per-axis card).
pub(crate) fn mode_is_panel_wide(mode: &str) -> bool {
    matches!(mode, "redundancy" | "calibration")
}

/// An optional string as a JSON value (`null` when absent).
fn opt_str(value: Option<&str>) -> Value {
    value.map(Value::from).unwrap_or(Value::Null)
}

/// True when an `axis` argument is present but not a usable non-empty string.
///
/// The caller asked for a specific axis; a malformed one is refused rather than
/// silently ignored. Absence of the key is the legitimate panel-wide default.
pub(crate) fn measure_bits_axis_arg_invalid(args: &Map<String, Value>) -> bool {
    args.contains_key("axis") && string_arg(args, "axis").is_none()
}

/// Builds the `measure_bits` response for one request.
///
/// Serves the persisted card for `(project, mode, axis?, scope?)` with a
/// `trust`/`freshness`/`provenance` envelope (15 §3). A `refresh:true` request
/// for the `calibration` mode recomputes the card on demand from the persisted
/// observations and re-persists it with an incremented sequence and reset
/// freshness; other modes label `refresh_applied:false` because their recompute
/// is owned by the background assay lane. An absent card, or a refresh with no
/// persisted inputs, is refused fail-closed with `{code, message, remediation}`.
pub(crate) fn measure_bits_json_at(
    cache_dir: &Path,
    project: &str,
    mode: &str,
    axis: Option<&str>,
    scope: Option<&str>,
    refresh: bool,
) -> Result<Value, DynError> {
    if !MEASURE_BITS_MODES.contains(&mode) {
        return Ok(measure_bits_refused(
            project,
            mode,
            axis,
            scope,
            "ASTRO_ASSAY_MEASURE_BITS_MODE_UNSUPPORTED",
            format!("measure_bits mode {mode:?} is not available"),
            "use one of signals, sufficiency, redundancy, synergy, causality, calibration",
        ));
    }
    if refresh && mode == "calibration" {
        return refresh_calibration_card_at(cache_dir, project, scope);
    }

    let key = measure_bits_card_key(project, mode, axis, scope);
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        return Ok(measure_bits_refused(
            project,
            mode,
            axis,
            scope,
            "ASTRO_ASSAY_MEASURE_BITS_CARD_UNAVAILABLE",
            format!(
                "no persisted {mode} card for project {project:?} (scope={scope:?}, axis={axis:?})"
            ),
            "run the assay lane for this scope, or call measure_bits with refresh:true (calibration) after persisting its inputs",
        ));
    };
    let doc: Value = match serde_json::from_str(&raw) {
        Ok(doc) => doc,
        Err(error) => {
            return Ok(measure_bits_refused(
                project,
                mode,
                axis,
                scope,
                "ASTRO_ASSAY_MEASURE_BITS_CARD_CORRUPT",
                format!("persisted {mode} card at config:{key} did not parse: {error}"),
                "delete the corrupt card row and re-run the assay lane / refresh",
            ));
        }
    };
    if let Some(reason) = measure_bits_card_doc_invalid(&doc) {
        return Ok(measure_bits_refused(
            project,
            mode,
            axis,
            scope,
            "ASTRO_ASSAY_MEASURE_BITS_CARD_CORRUPT",
            format!("persisted {mode} card at config:{key} is invalid: {reason}"),
            "delete the malformed card row and re-run the assay lane / refresh",
        ));
    }

    let mut response = json!({
        "schema": MEASURE_BITS_SCHEMA,
        "project": project,
        "mode": mode,
        "axis": opt_str(axis),
        "scope": opt_str(scope),
        "status": "served",
        "trust": doc.get("trust").cloned().unwrap_or(Value::Null),
        "freshness": doc.get("freshness").cloned().unwrap_or(Value::Null),
        "provenance": doc.get("provenance").cloned().unwrap_or_else(|| json!([])),
        "seq": doc.get("seq").cloned().unwrap_or(Value::Null),
        "freshness_lag": doc.get("freshness_lag").cloned().unwrap_or(json!(0)),
        "produced_at": doc.get("produced_at").cloned().unwrap_or(Value::Null),
        "card": doc.get("card").cloned().unwrap_or(Value::Null),
        "source": format!("config:{key}"),
        "refresh_applied": false,
    });
    if refresh {
        // A refresh was requested for a mode whose recompute is owned by the
        // background assay lane, not this on-demand path: serve the cached card
        // but label the degradation rather than silently ignoring the flag.
        if let Some(object) = response.as_object_mut() {
            object.insert(
                "refresh_status".to_string(),
                json!("unavailable_lane_owned"),
            );
            object.insert(
                "refresh_note".to_string(),
                json!(format!(
                    "on-demand refresh is wired for mode=\"calibration\"; {mode} recompute runs in the background assay lane"
                )),
            );
        }
    }
    refresh_value_artifact_hash(&mut response);
    Ok(response)
}

/// Recomputes the calibration card from persisted observations and re-persists it.
fn refresh_calibration_card_at(
    cache_dir: &Path,
    project: &str,
    scope: Option<&str>,
) -> Result<Value, DynError> {
    let inputs_key = measure_bits_calibration_inputs_key(project, scope);
    let Some(raw) = read_config_value(cache_dir, &inputs_key)? else {
        return Ok(measure_bits_refused(
            project,
            "calibration",
            None,
            scope,
            "ASTRO_ASSAY_MEASURE_BITS_REFRESH_INPUTS_MISSING",
            format!("no persisted calibration observations at config:{inputs_key}"),
            "persist the per-strategy ground-truth observations for this scope before requesting refresh:true",
        ));
    };
    let observations: Vec<StrategyObservation> = match serde_json::from_str(&raw) {
        Ok(observations) => observations,
        Err(error) => {
            return Ok(measure_bits_refused(
                project,
                "calibration",
                None,
                scope,
                "ASTRO_ASSAY_MEASURE_BITS_REFRESH_INPUTS_CORRUPT",
                format!("calibration observations at config:{inputs_key} did not parse: {error}"),
                "repair the persisted calibration observations before requesting refresh:true",
            ));
        }
    };

    let cfg = CalibrationConfig::from_defaults()
        .map_err(|error| -> DynError { format!("{}: {}", error.code(), error.message()).into() })?;
    let card = match build_calibration_card(&observations, &cfg) {
        Ok(card) => card,
        Err(error) => {
            return Ok(measure_bits_refused(
                project,
                "calibration",
                None,
                scope,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };

    let card_value = serde_json::to_value(&card)?;
    let any_fallback = card
        .strategies
        .iter()
        .any(|s| s.source == astrolabe_assay::CalibrationSource::PriorFallback);
    let trust = if any_fallback {
        "provisional"
    } else {
        "trusted"
    };

    let key = measure_bits_card_key(project, "calibration", None, scope);
    let prev_seq = read_config_value(cache_dir, &key)?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|doc| doc.get("seq").and_then(Value::as_u64));
    let seq = prev_seq.map(|s| s + 1).unwrap_or(0);
    let produced_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let doc = json!({
        "schema": ASSAY_CARD_SCHEMA,
        "mode": "calibration",
        "project": project,
        "scope": opt_str(scope),
        "seq": seq,
        "produced_at": produced_at,
        "freshness": "fresh",
        "freshness_lag": 0,
        "trust": trust,
        "provenance": [
            format!("measure_bits:refresh:calibration:{project}"),
            format!("config:{inputs_key}"),
        ],
        "card": card_value,
    });
    let serialized = doc.to_string();
    write_config_value(cache_dir, &key, &serialized)?;

    // FSV: read the row back through a fresh connection and confirm the persisted
    // bytes parse to exactly the document that was written — a writer return value
    // is never treated as evidence of persisted state (standing invariant 5).
    match read_config_value(cache_dir, &key)? {
        None => {
            return Err(format!(
                "ASTRO_ASSAY_MEASURE_BITS_REFRESH_WRITE_LOST: calibration card at config:{key} was not readable back immediately after write. Remediation: check the config store filesystem and retry."
            )
            .into());
        }
        Some(readback_raw) => {
            let readback: Value = serde_json::from_str(&readback_raw).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ASSAY_MEASURE_BITS_REFRESH_READBACK_CORRUPT: calibration card at config:{key} did not parse after write: {error}. Remediation: delete the corrupt row and retry refresh."
                )
                .into()
            })?;
            if readback != doc {
                return Err(format!(
                    "ASTRO_ASSAY_MEASURE_BITS_REFRESH_READBACK_MISMATCH: calibration card at config:{key} read back a different value than was written. Remediation: quarantine the config store and retry refresh."
                )
                .into());
            }
        }
    }

    let mut response = json!({
        "schema": MEASURE_BITS_SCHEMA,
        "project": project,
        "mode": "calibration",
        "axis": Value::Null,
        "scope": opt_str(scope),
        "status": "refreshed",
        "trust": trust,
        "freshness": "fresh",
        "provenance": [
            format!("measure_bits:refresh:calibration:{project}"),
            format!("config:{inputs_key}"),
        ],
        "seq": seq,
        "freshness_lag": 0,
        "produced_at": produced_at,
        "card": doc.get("card").cloned().unwrap_or(Value::Null),
        "source": format!("config:{key}"),
        "refresh_applied": true,
    });
    refresh_value_artifact_hash(&mut response);
    Ok(response)
}

/// Validates a persisted card document carries the required labels (15 §3).
pub(crate) fn measure_bits_card_doc_invalid(doc: &Value) -> Option<&'static str> {
    let Some(object) = doc.as_object() else {
        return Some("card document must be an object");
    };
    if object.get("schema").and_then(Value::as_str) != Some(ASSAY_CARD_SCHEMA) {
        return Some("card document schema must be astrolabe.assay_card.v1");
    }
    if object.get("trust").and_then(Value::as_str).is_none() {
        return Some("card document requires a string trust label");
    }
    if object.get("freshness").and_then(Value::as_str).is_none() {
        return Some("card document requires a string freshness label");
    }
    if !json_string_array_nonempty(object.get("provenance")) {
        return Some("card document requires non-empty string provenance");
    }
    if object.get("seq").and_then(Value::as_u64).is_none() {
        return Some("card document requires an integer seq");
    }
    if object.get("card").is_none() {
        return Some("card document requires a card payload");
    }
    None
}

/// Builds a fail-closed refusal envelope with a `{code, message, remediation}`.
fn measure_bits_refused(
    project: &str,
    mode: &str,
    axis: Option<&str>,
    scope: Option<&str>,
    code: &str,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> Value {
    json!({
        "schema": MEASURE_BITS_SCHEMA,
        "project": project,
        "mode": mode,
        "axis": opt_str(axis),
        "scope": opt_str(scope),
        "status": "refused",
        "code": code,
        "message": message.into(),
        "remediation": remediation.into(),
        "trust": "provisional",
        "freshness": "not_evaluated",
        "provenance": [],
    })
}

/// Surfaces the persisted redundancy card's effective rank (`n_eff`) for
/// `get_architecture` (blueprint 08 §3 / capability 4.4). Returns a labeled
/// `unavailable` aspect when no redundancy card is persisted.
pub(crate) fn read_redundancy_neff_aspect(cache_dir: &Path, project: &str) -> Value {
    let key = measure_bits_card_key(project, "redundancy", None, None);
    let raw = match read_config_value(cache_dir, &key) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return json!({
                "schema": ASSAY_CARD_SCHEMA,
                "mode": "redundancy",
                "status": "unavailable",
                "n_eff": Value::Null,
                "freshness": "not_evaluated",
                "trust": "provisional",
                "source": format!("config:{key}:missing"),
                "remediation": "run measure_bits redundancy for this project to persist n_eff",
            });
        }
        Err(error) => {
            return json!({
                "schema": ASSAY_CARD_SCHEMA,
                "mode": "redundancy",
                "status": "error",
                "n_eff": Value::Null,
                "freshness": "not_evaluated",
                "trust": "provisional",
                "reason": error.to_string(),
            });
        }
    };
    let Ok(doc) = serde_json::from_str::<Value>(&raw) else {
        return json!({
            "schema": ASSAY_CARD_SCHEMA,
            "mode": "redundancy",
            "status": "invalid",
            "n_eff": Value::Null,
            "freshness": "fresh",
            "trust": "provisional",
            "source": format!("config:{key}"),
        });
    };
    let n_eff = doc
        .get("card")
        .and_then(|card| card.get("n_eff"))
        .cloned()
        .unwrap_or(Value::Null);
    let n_slots = doc
        .get("card")
        .and_then(|card| card.get("n_slots"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "schema": ASSAY_CARD_SCHEMA,
        "mode": "redundancy",
        "status": if n_eff.is_null() { "invalid" } else { "measured" },
        "n_eff": n_eff,
        "n_slots": n_slots,
        "total_correlation_bits": doc
            .get("card")
            .and_then(|card| card.get("total_correlation_bits"))
            .cloned()
            .unwrap_or(Value::Null),
        "freshness": doc.get("freshness").cloned().unwrap_or(Value::Null),
        "trust": doc.get("trust").cloned().unwrap_or(Value::Null),
        "seq": doc.get("seq").cloned().unwrap_or(Value::Null),
        "source": format!("config:{key}"),
        "metadata_ref": key,
    })
}
