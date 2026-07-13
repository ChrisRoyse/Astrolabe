use super::*;

use astrolabe_guard::calibration::{CalibrationDomain, CalibrationLanguage};
use astrolabe_guard::profile::{
    CONFORMAL_ALPHA, GUARD_PROFILE_SCHEMA, GuardProfile, GuardSlot, SlotCalibration,
    calibrate_slot, calibration_meta_payload_bytes, default_content_policy,
};

/// Actor recorded on the guard calibration ledger entry.
pub(crate) const GUARD_CALIBRATE_ACTOR: &str = "astrolabe-server-guard-calibrate";

/// `guard_calibrate` (blueprint 10_GUARD.md §1/§5): build/refresh a per-domain
/// [`GuardProfile`] from measured per-slot good/bad cosine populations, ledger
/// the calibration (subject = `SubjectId::Guard`, kind `Guard`), and persist the
/// `astrolabe.optimizer_guard_health.v1` profile the optimizer/readiness
/// surfaces read.
///
/// Request shape:
/// ```json
/// {
///   "project": "demo",
///   "domain": {"language": "rust", "scope_class": "core"},
///   "alpha": 0.05,
///   "slots": [
///     {"slot": "code_semantic", "good_scores": [..], "bad_scores": [..]},
///     ... one entry per fixed guard slot ...
///   ]
/// }
/// ```
///
/// Fail-closed: a malformed request, an unknown/missing slot, or any slot whose
/// held-out FAR breaches its finite-sample bound refuses (structured
/// `{code,message,remediation}`), never persists a partial or over-accepting
/// profile.
pub(crate) fn handle_guard_calibrate(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return guard_calibrate_refused(
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "guard_calibrate arguments must be a JSON object",
            "Pass a JSON object with project, domain, and slots.",
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return guard_calibrate_refused(
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "guard_calibrate requires project",
            "Pass the project whose guard profile is being calibrated.",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    guard_calibrate_at(&cache_dir, &project, args_obj)
}

/// FSV-testable core: everything after the project is resolved, rooted at an
/// explicit `cache_dir` so contract tests drive it against a real temp vault.
pub(crate) fn guard_calibrate_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return guard_calibrate_refused(
            "ASTRO_GUARD_CALIBRATE_NOT_SHADOW",
            "guard_calibrate requires calyx shadow indexing",
            "run index_repository with calyx=\"shadow\" before calibrating the guard",
        );
    }

    let domain = match parse_domain(args_obj) {
        Ok(domain) => domain,
        Err((code, message, remediation)) => {
            return guard_calibrate_refused(code, message, remediation);
        }
    };
    let alpha = args_obj
        .get("alpha")
        .and_then(Value::as_f64)
        .map(|value| value as f32)
        .unwrap_or(CONFORMAL_ALPHA);

    let Some(slot_specs) = args_obj.get("slots").and_then(Value::as_array) else {
        return guard_calibrate_refused(
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "guard_calibrate requires a slots array",
            "Provide one slot object per fixed guard slot with good_scores and bad_scores.",
        );
    };

    // Calibrate every fixed guard slot from its supplied score populations. A
    // missing slot or a calibration failure refuses the whole run.
    let mut calibrations: Vec<SlotCalibration> = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let Some(spec) = slot_specs.iter().find(|spec| {
            spec.get("slot").and_then(Value::as_str) == Some(slot.as_str())
        }) else {
            return guard_calibrate_refused_owned(
                "ASTRO_GUARD_CALIBRATE_SLOT_MISSING",
                format!("slots is missing required guard slot `{}`", slot.as_str()),
                "Supply a slot object for every fixed guard slot before calibrating.".to_string(),
            );
        };
        let good_scores = match parse_scores(spec, "good_scores", slot) {
            Ok(scores) => scores,
            Err((code, message, remediation)) => {
                return guard_calibrate_refused_owned(code, message, remediation);
            }
        };
        let bad_scores = match parse_scores(spec, "bad_scores", slot) {
            Ok(scores) => scores,
            Err((code, message, remediation)) => {
                return guard_calibrate_refused_owned(code, message, remediation);
            }
        };
        match calibrate_slot(slot, &good_scores, &bad_scores, slot.default_target_far(), alpha) {
            Ok(calibration) => calibrations.push(calibration),
            Err(error) => {
                // Surface the guard-crate error code verbatim (e.g.
                // ASTRO_GUARD_SLOT_UNSPLITTABLE, ASTRO_GUARD_FAR_BOUND_EXCEEDED).
                return guard_calibrate_refused_str(
                    error.code(),
                    &format!("slot `{}`: {}", slot.as_str(), error.message()),
                    error.remediation(),
                );
            }
        }
    }

    let profile = GuardProfile {
        domain: domain.clone(),
        slots: calibrations,
        content_policy: default_content_policy(),
        provisional: false,
        corpus_hash: [0u8; 32],
        calibrated_ledger_seq: None,
    };

    // Ledger the calibration (subject = Guard(profile_hash)), then persist the
    // consumer-contract guard-health profile referencing that ledger seq.
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return guard_calibrate_refused_owned(
            "ASTRO_GUARD_CALIBRATE_VAULT_MISSING",
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before calibrating the guard".to_string(),
        );
    }
    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger],
    )?;
    let payload = calibration_meta_payload_bytes(&profile);
    let profile_hash = profile.canonical_profile_hash().to_vec();
    let ledger_ref = vault.append_ledger_entry(
        calyx_ledger::EntryKind::Guard,
        SubjectId::Guard(profile_hash.clone()),
        payload.clone(),
        ActorId::Service(GUARD_CALIBRATE_ACTOR.to_string()),
    )?;
    drop(vault);
    let seq = ledger_ref.seq;

    let health = guard_health_config_json(&profile, project, seq);
    let key = metadata_key(project, "optimizer_guard_health_json");
    write_config_value(cache_dir, &key, &health.to_string())?;

    // FSV pairing: read the persisted config row back and confirm it round-trips.
    let readback = read_config_value(cache_dir, &key)?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);

    tool_json_result(json!({
        "schema": GUARD_PROFILE_SCHEMA,
        "status": "calibrated",
        "project": project,
        "domain": domain.label(),
        "profile_hash": profile.profile_hash_hex(),
        "corpus_hash": profile.corpus_hash_hex(),
        "alpha": alpha,
        "ledger_ref": {
            "seq": seq,
            "entry_hash": hex_lower(&ledger_ref.hash),
            "subject": {"kind": "guard", "id_hex": hex_lower(&profile_hash)},
            "kind": "guard",
        },
        "slots": profile
            .slots
            .iter()
            .map(guard_calibrate_slot_json)
            .collect::<Vec<_>>(),
        "guard_health_config_key": key,
        "guard_health_readback": readback,
        "freshness": "fresh",
        "trust": "verified",
        "source": format!("AsterVault:ColumnFamily::Ledger + config:{key}"),
    }))
}

/// Build the `astrolabe.optimizer_guard_health.v1` config value the optimizer
/// and readiness surfaces validate and read (see `optimizer_guard_health_*`).
pub(crate) fn guard_health_config_json(
    profile: &GuardProfile,
    _project: &str,
    ledger_seq: u64,
) -> Value {
    let mut slots = Vec::with_capacity(profile.slots.len());
    for calibration in &profile.slots {
        slots.push(json!({
            "slot": calibration.slot.as_str(),
            "panel_source": calibration.slot.panel_source(),
            "kind": calibration.slot.kind().as_str(),
            "tau": finite_f64(calibration.tau),
            "target_far": finite_f64(calibration.target_far),
            "far": finite_f64(calibration.achieved_far),
            "frr": finite_f64(calibration.achieved_frr),
            "drift": finite_f64(calibration.drift_bound),
            "last_calibrated_ledger_seq": ledger_seq,
            "freshness": "fresh",
            "trust": "verified",
            "provenance": [format!("guard_calibrate:{}:{ledger_seq}", profile.domain.label())],
        }));
    }
    json!({
        "schema": OPTIMIZER_GUARD_HEALTH_SCHEMA,
        "status": "measured",
        "freshness": "fresh",
        "trust": "verified",
        "profile_id": format!("guard-profile:{}", profile.profile_hash_hex()),
        "domain": profile.domain.label(),
        "corpus_hash": profile.corpus_hash_hex(),
        "slots": slots,
    })
}

fn guard_calibrate_slot_json(calibration: &SlotCalibration) -> Value {
    json!({
        "slot": calibration.slot.as_str(),
        "panel_source": calibration.slot.panel_source(),
        "kind": calibration.slot.kind().as_str(),
        "tau": finite_f64(calibration.tau),
        "target_far": finite_f64(calibration.target_far),
        "achieved_far": finite_f64(calibration.achieved_far),
        "achieved_frr": finite_f64(calibration.achieved_frr),
        "drift_bound": finite_f64(calibration.drift_bound),
        "n_bad_calibration": calibration.n_bad_calibration,
        "n_bad_validation": calibration.n_bad_validation,
        "n_good": calibration.n_good,
        "provisional": calibration.provisional,
    })
}

/// Convert an `f32` to a JSON-safe `f64` (guarding against `NaN`/`Infinity`,
/// which serde_json cannot serialize).
fn finite_f64(value: f32) -> f64 {
    if value.is_finite() { value as f64 } else { 0.0 }
}

fn parse_domain(
    args_obj: &Map<String, Value>,
) -> Result<CalibrationDomain, (&'static str, &'static str, &'static str)> {
    let Some(domain_obj) = args_obj.get("domain").and_then(Value::as_object) else {
        return Err((
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "guard_calibrate requires a domain object",
            "Pass domain as {\"language\":..,\"scope_class\":..}.",
        ));
    };
    let Some(language_str) = domain_obj.get("language").and_then(Value::as_str) else {
        return Err((
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "domain.language is required",
            "Pass a supported language such as rust, python, or typescript.",
        ));
    };
    let Some(language) = language_from_str(language_str) else {
        return Err((
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "domain.language is not a supported calibration language",
            "Use one of: rust, python, javascript, typescript, go, java, c, cpp, csharp, ruby.",
        ));
    };
    let scope_class = domain_obj.get("scope_class").and_then(Value::as_str).unwrap_or("");
    CalibrationDomain::new(language, scope_class).map_err(|_| {
        (
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "domain.scope_class must be a non-empty scope class",
            "Pass a non-empty scope_class such as core, frontend, or test.",
        )
    })
}

fn language_from_str(value: &str) -> Option<CalibrationLanguage> {
    CalibrationLanguage::ALL.iter().copied().find(|language| language.as_str() == value)
}

fn parse_scores(
    spec: &Value,
    field: &str,
    slot: GuardSlot,
) -> Result<Vec<f32>, (&'static str, String, String)> {
    let Some(array) = spec.get(field).and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_CALIBRATE_INVALID",
            format!("slot `{}` requires a numeric {field} array", slot.as_str()),
            format!("Provide {field} as an array of measured cosine scores for slot {}.", slot.as_str()),
        ));
    };
    let mut scores = Vec::with_capacity(array.len());
    for value in array {
        let Some(score) = value.as_f64() else {
            return Err((
                "ASTRO_GUARD_CALIBRATE_INVALID",
                format!("slot `{}` {field} contains a non-numeric entry", slot.as_str()),
                "All score entries must be JSON numbers.".to_string(),
            ));
        };
        scores.push(score as f32);
    }
    Ok(scores)
}

/// Fail-closed refusal: a structured `{code}: {message}; remediation: {..}`
/// tool error (isError=true), consistent with the other astrolabe tool
/// preconditions. The message always contains the human-readable reason so
/// substring assertions and agents can surface it directly.
fn guard_calibrate_refused(
    code: &str,
    message: &str,
    remediation: &str,
) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}

fn guard_calibrate_refused_owned(
    code: &str,
    message: String,
    remediation: String,
) -> Result<String, DynError> {
    guard_calibrate_refused_str(code, &message, &remediation)
}

fn guard_calibrate_refused_str(
    code: &str,
    message: &str,
    remediation: &str,
) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}
