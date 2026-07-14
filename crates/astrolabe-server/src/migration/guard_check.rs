use super::*;

use astrolabe_guard::calibration::{CalibrationDomain, CalibrationLanguage};
use astrolabe_guard::check::{
    Exemplar, GUARD_NEW_REGION_SCHEMA, GUARD_VERDICT_SCHEMA, MeasuredSymbol, NewRegionRecord,
    SlotFeature, SymbolSlotInput, check_candidate, measure_for_check, measure_for_index,
    resolve_region, slot_input_from_panel, verdict_ledger_payload_bytes,
};
use astrolabe_guard::profile::{
    GuardProfile, GuardSlot, GuardVerdict, SlotCalibration, default_content_policy,
};
use astrolabe_panel::PanelDriver;
use calyx_core::CxId;

/// Which measurement mode `guard_check` runs in for the candidate and exemplars.
///
/// The mode is **declared**, never silently inferred into a fallback: `vector` consumes
/// operator-supplied per-slot lens vectors (the wave-10 path), while `panel` derives the
/// slot vectors from each symbol's source text through the real libcbm + panel pipeline —
/// the true same-instruments-as-indexing path (#331). A panel failure in `panel` mode
/// fails closed; it never reverts to the supplied path (standing invariant #3).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MeasurementMode {
    Vector,
    Panel,
}

/// Actor recorded on the guard-check verdict ledger entry.
pub(crate) const GUARD_CHECK_ACTOR: &str = "astrolabe-server-guard-check";

/// `guard_check` (blueprint 10_GUARD.md §3/§6, P7.3): measure a candidate through
/// the SAME instruments as indexing, resolve its comparison region (kernel-near
/// trusted exemplars first, peripheral fallback), score every guard slot's cosine
/// against the persisted profile's calibrated tau, route the per-slot outcomes
/// into accept / new_region / quarantine / refuse (never a flattened average),
/// and ledger the verdict (kind=Guard, subject=Cx(target)) with full per-slot
/// detail.
///
/// Request shape (two declared measurement modes; ambiguity is refused):
/// ```json
/// // measurement = "vector" (operator-supplied per-slot lens vectors):
/// {
///   "project": "demo",
///   "target": "<candidate cx hex>",
///   "measurement": "vector",
///   "candidate": {"slots": [{"slot": "code_semantic", "vector": [..]}, ...]},
///   "exemplars": [
///     {"cx": "<hex>", "kernel_near": true, "slots": [{"slot": .., "vector": [..]}, ...]},
///     ...
///   ]
/// }
/// // measurement = "panel" (derive slot vectors from source through the panel — #331):
/// {
///   "project": "demo",
///   "target": "<candidate cx hex>",
///   "measurement": "panel",
///   "candidate": {"source": "..", "symbol_name": "..", "properties": {..}, ..},
///   "exemplars": [{"cx": "<hex>", "kernel_near": true, "source": "..", ..}, ...]
/// }
/// ```
/// With no explicit `measurement`, the mode is inferred from the candidate's shape (a
/// `slots` array is `vector`; panel inputs are `panel`); both/neither is a refusal.
///
/// Fail-closed: no persisted calibrated profile, an unparseable target CxId, a
/// candidate/exemplar missing a guard slot or carrying a degenerate vector, or an
/// empty comparison region all refuse with a structured `{code,message,remediation}`
/// and persist no verdict.
pub(crate) fn handle_guard_check(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return guard_check_refused(
            "ASTRO_GUARD_CHECK_INVALID",
            "guard_check arguments must be a JSON object",
            "Pass a JSON object with project, target, candidate, and exemplars.",
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return guard_check_refused(
            "ASTRO_GUARD_CHECK_INVALID",
            "guard_check requires project",
            "Pass the project whose guard profile is being consulted.",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    guard_check_at(&cache_dir, &project, args_obj)
}

/// FSV-testable core: everything after the project is resolved, rooted at an
/// explicit `cache_dir` so contract tests drive it against a real temp vault.
pub(crate) fn guard_check_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return guard_check_refused(
            "ASTRO_GUARD_CHECK_NOT_SHADOW",
            "guard_check requires calyx shadow indexing",
            "run index_repository with calyx=\"shadow\" and guard_calibrate before checking",
        );
    }

    // 1. Load the persisted, calibrated guard profile (from guard_calibrate).
    let profile = match load_persisted_profile(cache_dir, project) {
        Ok(profile) => profile,
        Err((code, message, remediation)) => {
            return guard_check_refused_owned(code, message, remediation);
        }
    };

    // 2. Target CxId (verdict subject).
    let Some(target_raw) =
        string_arg(args_obj, "target").or_else(|| string_arg(args_obj, "subject"))
    else {
        return guard_check_refused(
            "ASTRO_GUARD_CHECK_INVALID",
            "guard_check requires target (candidate CxId hex)",
            "Pass target as the candidate symbol's CxId hex.",
        );
    };
    let Ok(target_cx) = CxId::from_str(target_raw) else {
        return guard_check_refused_owned(
            "ASTRO_GUARD_CHECK_INVALID",
            format!("target {target_raw:?} is not a valid CxId hex"),
            "Pass a 32-hex-character CxId as target.".to_string(),
        );
    };
    let target_cx_hex = target_cx.to_string();

    // 3-4. Declared measurement mode: `vector` (operator-supplied per-slot lens
    //      vectors) vs `panel` (derive slot vectors from source text through the real
    //      libcbm + panel pipeline, the same instruments as indexing — #331). Ambiguity
    //      is refused, never guessed; a panel failure fails closed.
    let mode = match resolve_measurement_mode(args_obj) {
        Ok(mode) => mode,
        Err((code, message, remediation)) => {
            return guard_check_refused_owned(code, message, remediation);
        }
    };
    let (candidate, exemplars) = match mode {
        MeasurementMode::Vector => {
            let candidate = match parse_symbol_input(args_obj.get("candidate"), "candidate") {
                Ok(input) => match measure_for_check(&input) {
                    Ok(measured) => measured,
                    Err(error) => {
                        return guard_check_refused_str(
                            error.code(),
                            error.message(),
                            error.remediation(),
                        );
                    }
                },
                Err((code, message, remediation)) => {
                    return guard_check_refused_owned(code, message, remediation);
                }
            };
            let exemplars = match parse_exemplars(args_obj.get("exemplars")) {
                Ok(exemplars) => exemplars,
                Err((code, message, remediation)) => {
                    return guard_check_refused_owned(code, message, remediation);
                }
            };
            (candidate, exemplars)
        }
        MeasurementMode::Panel => match measure_candidate_and_exemplars_through_panel(args_obj) {
            Ok(pair) => pair,
            Err((code, message, remediation)) => {
                return guard_check_refused_owned(code, message, remediation);
            }
        },
    };

    // 5. Resolve region (kernel-near first, peripheral fallback) + route.
    let region = match resolve_region(&exemplars) {
        Ok(region) => region,
        Err(error) => {
            return guard_check_refused_str(error.code(), error.message(), error.remediation());
        }
    };
    let report = match check_candidate(&candidate, &profile, &region) {
        Ok(report) => report,
        Err(error) => {
            return guard_check_refused_str(error.code(), error.message(), error.remediation());
        }
    };

    // 6. Ledger the verdict (subject = target CxId, kind = Guard) with the full
    //    per-slot detail, then persist a new-region record when routed novel.
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return guard_check_refused_owned(
            "ASTRO_GUARD_CHECK_VAULT_MISSING",
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before checking the guard".to_string(),
        );
    }
    let payload = verdict_ledger_payload_bytes(&report, &target_cx_hex);
    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger],
    )?;
    let ledger_ref = vault.append_ledger_entry(
        calyx_ledger::EntryKind::Guard,
        SubjectId::Cx(target_cx),
        payload.clone(),
        ActorId::Service(GUARD_CHECK_ACTOR.to_string()),
    )?;
    drop(vault);
    let seq = ledger_ref.seq;

    let mut new_region_record: Option<Value> = None;
    if report.combined.verdict == GuardVerdict::NewRegion {
        match NewRegionRecord::record(&report, &target_cx_hex) {
            Ok(mut record) => {
                record.verdict_ledger_seq = Some(seq);
                let record_json = new_region_record_json(&record, seq);
                let key = new_region_key(project, &target_cx_hex);
                write_config_value(cache_dir, &key, &record_json.to_string())?;
                new_region_record = Some(record_json);
            }
            Err(error) => {
                return guard_check_refused_str(error.code(), error.message(), error.remediation());
            }
        }
    }

    // 7. FSV pairing: read the persisted ledger entry back and confirm the served
    //    per-slot detail matches the persisted bytes.
    let readback = match calyx_aster::ledger_view::read_ledger_seq(&vault_dir, seq)? {
        Some(row) => {
            let entry = decode_ledger(&row.bytes)?;
            serde_json::from_slice::<Value>(&entry.payload).unwrap_or(Value::Null)
        }
        None => Value::Null,
    };

    tool_json_result(json!({
        "schema": GUARD_VERDICT_SCHEMA,
        "status": "checked",
        "project": project,
        "target_cx": target_cx_hex,
        "verdict": report.combined.verdict.as_str(),
        "provisional": report.combined.provisional,
        "region_class": report.region_class.as_str(),
        "measures": report.measures,
        "reason": report.combined.reason,
        "remediation": report.remediation,
        "nearest_exemplar": {
            "cx": report.nearest_exemplar.cx_id_hex,
            "kernel_near": report.nearest_exemplar.kernel_near,
            "mean_cosine": finite_f64_check(report.nearest_exemplar.mean_cosine),
        },
        "slots": report
            .combined
            .per_slot
            .iter()
            .map(|sv| json!({
                "slot": sv.slot.as_str(),
                "panel_source": sv.slot.panel_source(),
                "kind": sv.slot.kind().as_str(),
                "cos": finite_f64_check(sv.cos),
                "tau": finite_f64_check(sv.tau),
                "pass": sv.pass(),
            }))
            .collect::<Vec<_>>(),
        "new_region": new_region_record,
        "ledger_ref": {
            "seq": seq,
            "entry_hash": hex_lower(&ledger_ref.hash),
            "subject": {"kind": "cx", "id": target_cx_hex},
            "kind": "guard",
        },
        "verdict_readback": readback,
        "trust": report.trust,
        "freshness": report.freshness,
        "source": format!("AsterVault:ColumnFamily::Ledger seq={seq}"),
    }))
}

/// Resolve the declared measurement mode. An explicit `measurement` field wins;
/// otherwise it is inferred from the candidate's shape — a `slots` array (per-slot
/// vectors) is `vector`, panel inputs (`source`/`symbol_name`/`properties`) are `panel`.
/// Both or neither present is a fail-closed ambiguity, never a silent default.
fn resolve_measurement_mode(
    args_obj: &Map<String, Value>,
) -> Result<MeasurementMode, (&'static str, String, String)> {
    if let Some(raw) = args_obj.get("measurement").and_then(Value::as_str) {
        return match raw {
            "vector" => Ok(MeasurementMode::Vector),
            "panel" => Ok(MeasurementMode::Panel),
            other => Err((
                "ASTRO_GUARD_CHECK_MEASUREMENT_INVALID",
                format!("guard_check measurement `{other}` is not recognized"),
                "Pass measurement \"panel\" (derive slot vectors from source through the panel) or \
                 \"vector\" (operator-supplied per-slot vectors)."
                    .to_string(),
            )),
        };
    }
    let candidate = args_obj.get("candidate").and_then(Value::as_object);
    let has_slots = candidate
        .and_then(|obj| obj.get("slots"))
        .and_then(Value::as_array)
        .is_some();
    let has_panel = candidate.is_some_and(|obj| {
        ["source", "symbol_name", "qualified_name", "properties"]
            .iter()
            .any(|key| obj.contains_key(*key))
    });
    match (has_slots, has_panel) {
        (true, false) => Ok(MeasurementMode::Vector),
        (false, true) => Ok(MeasurementMode::Panel),
        (true, true) => Err((
            "ASTRO_GUARD_CHECK_MEASUREMENT_AMBIGUOUS",
            "guard_check candidate carries both per-slot vectors and panel inputs; the \
             measurement mode is ambiguous"
                .to_string(),
            "Declare measurement \"panel\" or \"vector\", or pass only panel inputs (panel) or only \
             a slots array (vector)."
                .to_string(),
        )),
        (false, false) => Err((
            "ASTRO_GUARD_CHECK_MEASUREMENT_MISSING",
            "guard_check candidate has neither per-slot vectors nor panel inputs".to_string(),
            "Pass candidate panel inputs with measurement \"panel\", or a slots array with \
             measurement \"vector\"."
                .to_string(),
        )),
    }
}

/// Measure the candidate and exemplars through the real libcbm + panel pipeline (#331):
/// each symbol's panel-source slot vectors are measured with the same instruments as
/// indexing, then densified into the guard's per-slot input via
/// [`slot_input_from_panel`]. A panel failure or a partially-measured symbol fails
/// closed; the panel path never falls back to supplied vectors.
fn measure_candidate_and_exemplars_through_panel(
    args_obj: &Map<String, Value>,
) -> Result<(MeasuredSymbol, Vec<Exemplar>), (&'static str, String, String)> {
    let panel_version = args_obj
        .get("panel_version")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(DEFAULT_PANEL_VERSION);
    let driver = PanelDriver::new(panel_version).map_err(|err| {
        (
            "ASTRO_GUARD_CHECK_PANEL_VERSION",
            format!("panel version {panel_version} is invalid: {}", err.message()),
            "Check with panel version 1 (S0-S22) or 2 (S0-S23).".to_string(),
        )
    })?;
    let runtime = ShadowSlotRuntime;

    let measure = |obj: &Map<String, Value>,
                   index: usize|
     -> Result<MeasuredSymbol, (&'static str, String, String)> {
        let map = measure_guard_panel_sources(&driver, &runtime, obj, index)
            .map_err(|(_code, message, remediation)| {
                ("ASTRO_GUARD_CHECK_PANEL_FAILED", message, remediation)
            })?;
        let input = slot_input_from_panel(&map).map_err(|error| {
            (
                error.code(),
                error.message().to_string(),
                error.remediation().to_string(),
            )
        })?;
        measure_for_check(&input).map_err(|error| {
            (
                error.code(),
                error.message().to_string(),
                error.remediation().to_string(),
            )
        })
    };

    let Some(candidate_obj) = args_obj.get("candidate").and_then(Value::as_object) else {
        return Err((
            "ASTRO_GUARD_CHECK_INVALID",
            "guard_check (panel mode) requires a candidate object with panel inputs".to_string(),
            "Pass candidate with source and its indexed panel inputs (symbol_name, properties, …)."
                .to_string(),
        ));
    };
    let candidate = measure(candidate_obj, 0)?;

    let Some(exemplar_array) = args_obj.get("exemplars").and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_CHECK_INVALID",
            "guard_check requires an exemplars array".to_string(),
            "Provide the enclosing scope's trusted exemplars, each with panel inputs.".to_string(),
        ));
    };
    let mut exemplars = Vec::with_capacity(exemplar_array.len());
    for (index, entry) in exemplar_array.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            return Err((
                "ASTRO_GUARD_CHECK_INVALID",
                format!("exemplar #{index} must be an object"),
                "Each exemplar needs cx, kernel_near, and panel inputs.".to_string(),
            ));
        };
        let cx = obj
            .get("cx")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("exemplar:{index}"));
        let kernel_near = obj
            .get("kernel_near")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let measured = measure(obj, index)?;
        exemplars.push(Exemplar {
            cx_id_hex: cx,
            kernel_near,
            measured,
        });
    }
    Ok((candidate, exemplars))
}

/// Reconstruct the calibrated [`GuardProfile`] from the persisted
/// `astrolabe.optimizer_guard_health.v1` config the guard_calibrate tool wrote.
/// Every fixed guard slot must be present with a numeric tau; a missing profile
/// or slot fails closed.
fn load_persisted_profile(
    cache_dir: &Path,
    project: &str,
) -> Result<GuardProfile, (&'static str, String, String)> {
    let key = metadata_key(project, "optimizer_guard_health_json");
    let raw = read_config_value(cache_dir, &key)
        .map_err(|error| {
            (
                "ASTRO_GUARD_CHECK_UNCALIBRATED",
                format!("failed to read guard health config: {error}"),
                "run guard_calibrate for this project before checking".to_string(),
            )
        })?
        .ok_or((
            "ASTRO_GUARD_CHECK_UNCALIBRATED",
            "no calibrated guard profile is persisted for this project".to_string(),
            "run guard_calibrate for this project's domain before checking".to_string(),
        ))?;
    let health: Value = serde_json::from_str(&raw).map_err(|error| {
        (
            "ASTRO_GUARD_CHECK_UNCALIBRATED",
            format!("guard health config is malformed: {error}"),
            "recalibrate the guard profile; the persisted config is unreadable".to_string(),
        )
    })?;
    let domain_label = health.get("domain").and_then(Value::as_str).unwrap_or("");
    let domain = domain_from_label(domain_label).ok_or((
        "ASTRO_GUARD_CHECK_UNCALIBRATED",
        format!("guard health config domain {domain_label:?} is unrecognized"),
        "recalibrate the guard profile for a supported language/scope".to_string(),
    ))?;
    let slots_json = health.get("slots").and_then(Value::as_array).ok_or((
        "ASTRO_GUARD_CHECK_UNCALIBRATED",
        "guard health config has no slots".to_string(),
        "recalibrate the guard profile; no per-slot taus are persisted".to_string(),
    ))?;

    let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let entry = slots_json
            .iter()
            .find(|row| row.get("slot").and_then(Value::as_str) == Some(slot.as_str()))
            .ok_or((
                "ASTRO_GUARD_CHECK_UNCALIBRATED",
                format!("guard profile is missing slot `{}`", slot.as_str()),
                "recalibrate the guard profile so every fixed slot has a tau".to_string(),
            ))?;
        let tau = entry.get("tau").and_then(Value::as_f64).ok_or((
            "ASTRO_GUARD_CHECK_UNCALIBRATED",
            format!("guard profile slot `{}` has no numeric tau", slot.as_str()),
            "recalibrate the guard profile; a slot tau is missing".to_string(),
        ))? as f32;
        let mut calibration = SlotCalibration::cold_start(slot);
        calibration.tau = tau;
        calibration.provisional = false;
        calibration.target_far = entry
            .get("target_far")
            .and_then(Value::as_f64)
            .map(|value| value as f32)
            .unwrap_or_else(|| slot.default_target_far());
        calibration.achieved_far = entry
            .get("far")
            .and_then(Value::as_f64)
            .map(|v| v as f32)
            .unwrap_or(0.0);
        calibration.achieved_frr = entry
            .get("frr")
            .and_then(Value::as_f64)
            .map(|v| v as f32)
            .unwrap_or(0.0);
        slots.push(calibration);
    }

    Ok(GuardProfile {
        domain,
        slots,
        content_policy: default_content_policy(),
        provisional: false,
        corpus_hash: [0u8; 32],
        calibrated_ledger_seq: None,
    })
}

/// Parse a "language/scope_class" domain label back into a [`CalibrationDomain`].
fn domain_from_label(label: &str) -> Option<CalibrationDomain> {
    let (language_str, scope_class) = label.split_once('/')?;
    let language = CalibrationLanguage::ALL
        .iter()
        .copied()
        .find(|l| l.as_str() == language_str)?;
    CalibrationDomain::new(language, scope_class).ok()
}

/// Parse a `{"slots": [{"slot": .., "vector": [..]}, ...]}` object into the
/// shared [`SymbolSlotInput`].
fn parse_symbol_input(
    value: Option<&Value>,
    field: &str,
) -> Result<SymbolSlotInput, (&'static str, String, String)> {
    let Some(obj) = value.and_then(Value::as_object) else {
        return Err((
            "ASTRO_GUARD_CHECK_INVALID",
            format!("{field} must be an object with a slots array"),
            format!("Pass {field} as {{\"slots\": [{{\"slot\":..,\"vector\":[..]}}]}}."),
        ));
    };
    let Some(slot_specs) = obj.get("slots").and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_CHECK_INVALID",
            format!("{field}.slots must be an array"),
            "Provide one slot object per fixed guard slot with a numeric vector.".to_string(),
        ));
    };
    let mut slots = Vec::with_capacity(slot_specs.len());
    for spec in slot_specs {
        let Some(slot_name) = spec.get("slot").and_then(Value::as_str) else {
            return Err((
                "ASTRO_GUARD_CHECK_INVALID",
                format!("{field}.slots entry is missing slot"),
                "Each slot object needs a slot name and a numeric vector.".to_string(),
            ));
        };
        let Some(slot) = guard_slot_from_str(slot_name) else {
            return Err((
                "ASTRO_GUARD_CHECK_INVALID",
                format!("{field} slot `{slot_name}` is not a fixed guard slot"),
                "Use one of the seven fixed guard slot names.".to_string(),
            ));
        };
        let Some(vector_json) = spec.get("vector").and_then(Value::as_array) else {
            return Err((
                "ASTRO_GUARD_CHECK_INVALID",
                format!("{field} slot `{slot_name}` requires a numeric vector array"),
                "Provide the measured lens vector for this slot.".to_string(),
            ));
        };
        let mut vector = Vec::with_capacity(vector_json.len());
        for component in vector_json {
            let Some(number) = component.as_f64() else {
                return Err((
                    "ASTRO_GUARD_CHECK_INVALID",
                    format!("{field} slot `{slot_name}` vector has a non-numeric component"),
                    "All vector components must be JSON numbers.".to_string(),
                ));
            };
            vector.push(number as f32);
        }
        slots.push(SlotFeature { slot, vector });
    }
    Ok(SymbolSlotInput { slots })
}

/// Parse the exemplars array into measured [`Exemplar`]s via the shared indexing
/// instrument (byte-identical to the candidate's measurement path).
fn parse_exemplars(value: Option<&Value>) -> Result<Vec<Exemplar>, (&'static str, String, String)> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_CHECK_INVALID",
            "guard_check requires an exemplars array".to_string(),
            "Provide the enclosing scope's trusted exemplars, each measured on every guard slot."
                .to_string(),
        ));
    };
    let mut exemplars = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            return Err((
                "ASTRO_GUARD_CHECK_INVALID",
                format!("exemplar #{index} must be an object"),
                "Each exemplar needs cx, kernel_near, and a slots array.".to_string(),
            ));
        };
        let cx = obj
            .get("cx")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("exemplar:{index}"));
        let kernel_near = obj
            .get("kernel_near")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let input = parse_symbol_input(Some(entry), "exemplar")?;
        let measured: MeasuredSymbol = measure_for_index(&input).map_err(|error| {
            (
                error.code(),
                error.message().to_string(),
                error.remediation().to_string(),
            )
        })?;
        exemplars.push(Exemplar {
            cx_id_hex: cx,
            kernel_near,
            measured,
        });
    }
    Ok(exemplars)
}

fn guard_slot_from_str(name: &str) -> Option<GuardSlot> {
    GuardSlot::ALL
        .iter()
        .copied()
        .find(|slot| slot.as_str() == name)
}

/// Serialize a new-region lifecycle record as the surfaceable config value.
fn new_region_record_json(record: &NewRegionRecord, verdict_seq: u64) -> Value {
    json!({
        "schema": GUARD_NEW_REGION_SCHEMA,
        "subject_cx": record.subject_cx_hex,
        "state": record.state.as_str(),
        "verdict_ledger_seq": verdict_seq,
        "grounding_ref": record.grounding_ref,
        "freshness": "fresh",
        "trust": "provisional",
        "provenance": [format!("guard_check:{verdict_seq}")],
    })
}

fn new_region_key(project: &str, cx_hex: &str) -> String {
    metadata_key(project, &format!("guard_new_region:{cx_hex}"))
}

// Served slot numbers must byte-match the persisted verdict payload, which
// writes shortest-decimal f32 (`verdict_ledger_payload_bytes`). A bare
// `as f64` widening serves 0.9999998807907104 where the ledger row reads back
// 0.9999999 — same measurement, unequal JSON.
fn finite_f64_check(value: f32) -> f64 {
    astrolabe_guard::check::canonical_slot_number(value)
}

fn guard_check_refused(code: &str, message: &str, remediation: &str) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}

fn guard_check_refused_owned(
    code: &str,
    message: String,
    remediation: String,
) -> Result<String, DynError> {
    guard_check_refused_str(code, &message, &remediation)
}

fn guard_check_refused_str(
    code: &str,
    message: &str,
    remediation: &str,
) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}
