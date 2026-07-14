use super::*;

use astrolabe_bridge::{ExtractedFile, Language};
use astrolabe_guard::auto::{MeasuredSymbol, calibrate_auto, guard_slot_panel_sources};
use astrolabe_guard::calibration::{CalibrationDomain, CalibrationLanguage};
use astrolabe_guard::profile::{
    CONFORMAL_ALPHA, GUARD_PROFILE_SCHEMA, GuardProfile, GuardSlot, SlotCalibration,
    calibrate_slot, calibration_meta_payload_bytes, default_content_policy,
};
use astrolabe_panel::{ApiCall, EncoderLensInput, PanelDriver, StructuralTrigram, encode_slot};
use calyx_core::{SlotId, SlotVector};

/// Panel slot id of the S1 struct-trigram lens (guard `StructTrigrams` source).
const PANEL_SLOT_STRUCT_TRIGRAMS: u16 = 1;
/// Panel slot id of the S4 api-callees lens (guard `ApiCallees` source).
const PANEL_SLOT_API_CALLEES: u16 = 4;
/// Wall-clock ceiling for a single per-snippet libcbm reparse. A resource bound
/// (not a scoring threshold): a snippet that will not parse within this budget is
/// a fail-closed reparse fault, never a silently dropped structural slot.
const GUARD_REPARSE_TIMEOUT_MICROS: i64 = 2_000_000;

/// Which population-source mode `guard_calibrate` runs in.
///
/// The mode is **declared**, never silently inferred into a fallback: `auto` derives
/// per-slot cosine populations by scoring `sources` through the real panel, while
/// `supplied` consumes operator-supplied `slots` cosine arrays. A panel failure in
/// `auto` fails closed — it never reverts to the supplied path (standing invariant #3).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CalibrationMode {
    Supplied,
    Auto,
}

impl CalibrationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Supplied => "supplied",
            Self::Auto => "auto",
        }
    }
}

/// A fail-closed refusal carried out of a profile builder: `(code, message, remediation)`.
pub(crate) type GuardRefusal = (String, String, String);

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

    // Declared mode selection: `auto` (score sources through the panel) vs
    // `supplied` (operator cosine arrays). Ambiguity is refused, never guessed.
    let mode = match resolve_calibration_mode(args_obj) {
        Ok(mode) => mode,
        Err((code, message, remediation)) => {
            return guard_calibrate_refused_owned(&code, message, remediation);
        }
    };

    let profile = match mode {
        CalibrationMode::Supplied => build_supplied_profile(args_obj, &domain, alpha),
        CalibrationMode::Auto => build_auto_profile(args_obj, &domain, alpha),
    };
    let profile = match profile {
        Ok(profile) => profile,
        Err((code, message, remediation)) => {
            return guard_calibrate_refused_owned(&code, message, remediation);
        }
    };

    finalize_guard_calibration(cache_dir, project, &domain, profile, alpha, mode)
}

/// Resolve the declared calibration mode. An explicit `mode` field wins; otherwise
/// the mode is inferred from exactly one of `slots`/`sources` being present. Both or
/// neither present is a fail-closed ambiguity (never a silent default).
fn resolve_calibration_mode(
    args_obj: &Map<String, Value>,
) -> Result<CalibrationMode, GuardRefusal> {
    let has_slots = args_obj.get("slots").and_then(Value::as_array).is_some();
    let has_sources = args_obj.get("sources").and_then(Value::as_array).is_some();
    match args_obj.get("mode").and_then(Value::as_str) {
        Some("supplied") => Ok(CalibrationMode::Supplied),
        Some("auto") => Ok(CalibrationMode::Auto),
        Some(other) => Err((
            "ASTRO_GUARD_CALIBRATE_MODE_INVALID".to_string(),
            format!("guard_calibrate mode `{other}` is not recognized"),
            "Pass mode \"auto\" (score sources through the panel) or \"supplied\" (operator cosine arrays).".to_string(),
        )),
        None => match (has_slots, has_sources) {
            (true, false) => Ok(CalibrationMode::Supplied),
            (false, true) => Ok(CalibrationMode::Auto),
            (true, true) => Err((
                "ASTRO_GUARD_CALIBRATE_MODE_AMBIGUOUS".to_string(),
                "guard_calibrate received both slots and sources; the mode is ambiguous".to_string(),
                "Declare mode \"auto\" or \"supplied\", or pass only sources (auto) or only slots (supplied).".to_string(),
            )),
            (false, false) => Err((
                "ASTRO_GUARD_CALIBRATE_MODE_MISSING".to_string(),
                "guard_calibrate requires either sources (auto) or slots (supplied)".to_string(),
                "Pass sources with mode \"auto\", or slots with mode \"supplied\".".to_string(),
            )),
        },
    }
}

/// Build a guard profile from operator-supplied per-slot cosine arrays (the wave-9
/// path). A missing slot or a per-slot calibration failure refuses the whole run.
fn build_supplied_profile(
    args_obj: &Map<String, Value>,
    domain: &CalibrationDomain,
    alpha: f32,
) -> Result<GuardProfile, GuardRefusal> {
    let Some(slot_specs) = args_obj.get("slots").and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_CALIBRATE_INVALID".to_string(),
            "guard_calibrate (supplied mode) requires a slots array".to_string(),
            "Provide one slot object per fixed guard slot with good_scores and bad_scores."
                .to_string(),
        ));
    };

    let mut calibrations: Vec<SlotCalibration> = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let Some(spec) = slot_specs
            .iter()
            .find(|spec| spec.get("slot").and_then(Value::as_str) == Some(slot.as_str()))
        else {
            return Err((
                "ASTRO_GUARD_CALIBRATE_SLOT_MISSING".to_string(),
                format!("slots is missing required guard slot `{}`", slot.as_str()),
                "Supply a slot object for every fixed guard slot before calibrating.".to_string(),
            ));
        };
        let good_scores =
            parse_scores(spec, "good_scores", slot).map_err(|(c, m, r)| (c.to_string(), m, r))?;
        let bad_scores =
            parse_scores(spec, "bad_scores", slot).map_err(|(c, m, r)| (c.to_string(), m, r))?;
        match calibrate_slot(
            slot,
            &good_scores,
            &bad_scores,
            slot.default_target_far(),
            alpha,
        ) {
            Ok(calibration) => calibrations.push(calibration),
            Err(error) => {
                // Surface the guard-crate error code verbatim (e.g.
                // ASTRO_GUARD_SLOT_UNSPLITTABLE, ASTRO_GUARD_FAR_BOUND_EXCEEDED).
                return Err((
                    error.code().to_string(),
                    format!("slot `{}`: {}", slot.as_str(), error.message()),
                    error.remediation().to_string(),
                ));
            }
        }
    }

    Ok(GuardProfile {
        domain: domain.clone(),
        slots: calibrations,
        content_policy: default_content_policy(),
        provisional: false,
        corpus_hash: [0u8; 32],
        calibrated_ledger_seq: None,
    })
}

/// Ledger + persist the calibrated profile and return the tool JSON. Shared by both
/// the supplied and auto modes so a calibration produced by either path is paired
/// with its ledger entry and read back from the persisted config row (FSV).
fn finalize_guard_calibration(
    cache_dir: &Path,
    project: &str,
    domain: &CalibrationDomain,
    profile: GuardProfile,
    alpha: f32,
    mode: CalibrationMode,
) -> Result<String, DynError> {
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
        "mode": mode.as_str(),
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

/// Build a guard profile by scoring `sources` through the **real panel** over the
/// shadow-indexed corpus (the auto path, blueprint 10_GUARD.md §1/§3).
///
/// Each source carries its panel-encoder inputs (symbol name, path, language, parsed
/// CBM `properties`) plus a `class` of `good` (in-distribution / trusted) or `bad`
/// (out-of-distribution). Every source is measured through [`ShadowSlotRuntime`] — the
/// same real encoders the live import uses — and the resulting per-slot vectors feed
/// [`calibrate_auto`], which builds a trusted-region centroid from the good set and
/// scores each case as its cosine to that centroid. A panel measurement failure fails
/// closed here; it never reverts to the supplied path (standing invariant #3).
fn build_auto_profile(
    args_obj: &Map<String, Value>,
    domain: &CalibrationDomain,
    alpha: f32,
) -> Result<GuardProfile, GuardRefusal> {
    let Some(sources) = args_obj.get("sources").and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_CALIBRATE_INVALID".to_string(),
            "guard_calibrate (auto mode) requires a sources array".to_string(),
            "Provide sources: each an object with panel inputs and class \"good\"|\"bad\"."
                .to_string(),
        ));
    };

    let panel_version = args_obj
        .get("panel_version")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(DEFAULT_PANEL_VERSION);
    let driver = PanelDriver::new(panel_version).map_err(|err| {
        (
            "ASTRO_GUARD_CALIBRATE_PANEL_VERSION".to_string(),
            format!(
                "panel version {panel_version} is invalid: {}",
                err.message()
            ),
            "Calibrate with panel version 1 (S0-S22) or 2 (S0-S23).".to_string(),
        )
    })?;
    let runtime = ShadowSlotRuntime;

    let mut good: Vec<MeasuredSymbol> = Vec::new();
    let mut bad: Vec<MeasuredSymbol> = Vec::new();
    // (class, qualified_name) identities hashed into the auto corpus provenance.
    let mut identities: Vec<String> = Vec::with_capacity(sources.len());
    for (index, source) in sources.iter().enumerate() {
        let Some(obj) = source.as_object() else {
            return Err((
                "ASTRO_GUARD_CALIBRATE_INVALID".to_string(),
                format!("source #{index} is not a JSON object"),
                "Each source must be an object with panel inputs and a class.".to_string(),
            ));
        };
        let class = obj.get("class").and_then(Value::as_str);
        let qualified_name = obj
            .get("qualified_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let measured = measure_source_through_panel(&driver, &runtime, obj, index)?;
        match class {
            Some("good") => {
                identities.push(format!("good|{qualified_name}"));
                good.push(measured);
            }
            Some("bad") => {
                identities.push(format!("bad|{qualified_name}"));
                bad.push(measured);
            }
            _ => {
                return Err((
                    "ASTRO_GUARD_CALIBRATE_SOURCE_CLASS".to_string(),
                    format!(
                        "source #{index} has no recognized class (expected \"good\" or \"bad\")"
                    ),
                    "Tag every source good (in-distribution) or bad (out-of-distribution)."
                        .to_string(),
                ));
            }
        }
    }

    let corpus_hash = auto_corpus_hash(&identities);
    calibrate_auto(
        domain.clone(),
        panel_version,
        &good,
        &bad,
        corpus_hash,
        alpha,
    )
    .map_err(|err| {
        (
            err.code().to_string(),
            err.message().to_string(),
            err.remediation().to_string(),
        )
    })
}

/// Measure one source object through the real panel and extract its guard panel
/// source slot vectors into a [`MeasuredSymbol`]. A panel error is a fail-closed
/// refusal (never a silent skip).
fn measure_source_through_panel(
    driver: &PanelDriver,
    runtime: &ShadowSlotRuntime,
    obj: &Map<String, Value>,
    index: usize,
) -> Result<MeasuredSymbol, GuardRefusal> {
    Ok(MeasuredSymbol {
        slots: measure_guard_panel_sources(driver, runtime, obj, index)?,
    })
}

/// Measure one source object through the real panel and extract its guard panel-source
/// slot vectors, keyed by panel slot id. Shared by the guard_calibrate auto path (which
/// wraps the map in an [`astrolabe_guard::auto::MeasuredSymbol`]) and the guard_check
/// panel-driven candidate/exemplar path (#331, which hands the map to
/// [`astrolabe_guard::check::slot_input_from_panel`]). A panel error is a fail-closed
/// refusal, never a silent skip.
pub(crate) fn measure_guard_panel_sources(
    driver: &PanelDriver,
    runtime: &ShadowSlotRuntime,
    obj: &Map<String, Value>,
    index: usize,
) -> Result<BTreeMap<u16, SlotVector>, GuardRefusal> {
    let string_field = |key: &str| -> String {
        obj.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let label = source_symbol_label(obj, index)?;
    let source_bytes = obj
        .get("source")
        .and_then(Value::as_str)
        .map(|text| text.as_bytes().to_vec())
        .unwrap_or_default();
    let properties = obj
        .get("properties")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let input = PanelInput {
        label,
        available_slots: shadow_available_slots().into_iter().collect(),
        source_bytes,
        symbol_name: string_field("symbol_name"),
        qualified_name: string_field("qualified_name"),
        rel_file_path: string_field("rel_file_path"),
        language: string_field("language"),
        signature: string_field("signature"),
        properties,
        scalars: BTreeMap::new(),
    };
    let readout = driver.measure(&input, runtime).map_err(|err| {
        (
            "ASTRO_GUARD_CALIBRATE_PANEL_FAILED".to_string(),
            format!(
                "source #{index} panel measurement failed: {}",
                err.message()
            ),
            "Fix the source's panel inputs or re-index the project; the auto path never falls \
             back to supplied cosines on a panel failure."
                .to_string(),
        )
    })?;

    let mut slots: BTreeMap<u16, SlotVector> = BTreeMap::new();
    for guard_slot in GuardSlot::ALL {
        for panel_slot in guard_slot_panel_sources(guard_slot) {
            if let Some(vector) = readout.slots.get(&SlotId::new(*panel_slot)) {
                slots.insert(*panel_slot, vector.clone());
            }
        }
    }

    // The shadow runtime cannot synthesize the S1 (struct-trigram) and S4
    // (api-callee) encoder inputs from properties alone, so it returns them
    // `Absent` (#331/#341). Measure them here from a real per-snippet libcbm
    // reparse of the candidate source — the same instruments the indexing
    // pipeline runs per symbol — and override the two panel sources. A reparse
    // fault is a fail-closed refusal, never a silently-absent structural slot.
    let (s1, s4) = reparse_structural_panel_sources(
        &input.source_bytes,
        &input.rel_file_path,
        &input.language,
        &input.symbol_name,
        index,
    )?;
    slots.insert(PANEL_SLOT_STRUCT_TRIGRAMS, s1);
    slots.insert(PANEL_SLOT_API_CALLEES, s4);
    Ok(slots)
}

/// Measure one symbol object through the panel + the #341 per-snippet reparse into
/// the guard's densified per-slot [`astrolabe_guard::check::MeasuredSymbol`].
///
/// This is the single measurement instrument every **secondary-process** guard
/// surface shares — `guard_check` (panel mode), the commit-OOD watcher tick
/// (#355), and the PostToolUse advisory hook (#355) all measure a candidate or
/// exemplar through THIS one path, never a parallel one, so a symbol scored in the
/// watcher/hook is measured byte-identically to one scored on the request path. The
/// raw [`GuardRefusal`] — carrying the specific reparse/encode code — is returned
/// so each caller wraps it in its own labeled envelope (or, for the advisory hook,
/// maps it to a labeled silent skip). A measurement fault is always a fail-closed
/// refusal, never a silently-absent slot (standing invariants #2/#3).
pub(crate) fn measure_symbol_from_panel(
    driver: &PanelDriver,
    runtime: &ShadowSlotRuntime,
    obj: &Map<String, Value>,
    index: usize,
) -> Result<astrolabe_guard::check::MeasuredSymbol, GuardRefusal> {
    let map = measure_guard_panel_sources(driver, runtime, obj, index)?;
    let input = astrolabe_guard::check::slot_input_from_panel(&map).map_err(|error| {
        (
            error.code().to_string(),
            error.message().to_string(),
            error.remediation().to_string(),
        )
    })?;
    astrolabe_guard::check::measure_for_check(&input).map_err(|error| {
        (
            error.code().to_string(),
            error.message().to_string(),
            error.remediation().to_string(),
        )
    })
}

/// Measure the S1 (struct-trigram) and S4 (api-callee) panel sources of one
/// candidate/exemplar source snippet through a real per-snippet libcbm reparse.
///
/// This is the per-snippet reparse subsystem (#341): the shadow runtime hardcodes
/// these two encoder inputs to `None` because they cannot be reconstructed from the
/// stored `properties` vocabulary, so a fresh candidate snippet could not be
/// structurally measured at all. Here the snippet is re-parsed in memory with the
/// same libcbm tree-sitter grammar the symbol was indexed under, the primary
/// definition's normalised AST node-type struct trigrams (S1) and attributed callees
/// (S4) are extracted — the identical instruments indexing uses per symbol — and each
/// is encoded through the real panel lens. Every failure mode is a labeled fail-closed
/// refusal: empty source, an unresolvable language tag, a parse fault, no measurable
/// structure, or an encoder contract violation. It never returns a silently-absent or
/// fabricated structural slot (standing invariants #2/#3).
fn reparse_structural_panel_sources(
    source_bytes: &[u8],
    rel_file_path: &str,
    language_hint: &str,
    symbol_name: &str,
    index: usize,
) -> Result<(SlotVector, SlotVector), GuardRefusal> {
    let refusal = |code: &str, message: String, remediation: &str| -> GuardRefusal {
        (code.to_string(), message, remediation.to_string())
    };

    let source = std::str::from_utf8(source_bytes).map_err(|_| {
        refusal(
            "ASTRO_GUARD_REPARSE_SOURCE_NOT_UTF8",
            format!("source #{index} is not valid UTF-8; the guard reparse cannot tree-sit it"),
            "Provide the candidate's source text as UTF-8; binary blobs are not measurable code.",
        )
    })?;
    if source.trim().is_empty() {
        return Err(refusal(
            "ASTRO_GUARD_REPARSE_EMPTY_SOURCE",
            format!("source #{index} has no source text to reparse for its S1/S4 panel sources"),
            "Supply the candidate symbol's source body; an empty snippet has no structural surface.",
        ));
    }

    let language = resolve_reparse_language(rel_file_path, language_hint).ok_or_else(|| {
        refusal(
            "ASTRO_GUARD_REPARSE_LANGUAGE_UNKNOWN",
            format!(
                "source #{index} has no resolvable libcbm grammar (rel_file_path `{rel_file_path}`, \
                 language `{language_hint}`)"
            ),
            "Tag the source with a supported language or a file path libcbm recognizes; the reparse \
             never guesses a grammar.",
        )
    })?;

    let extracted = ExtractedFile::extract(
        source,
        language,
        "astro_guard_reparse",
        if rel_file_path.is_empty() {
            "snippet"
        } else {
            rel_file_path
        },
        GUARD_REPARSE_TIMEOUT_MICROS,
    )
    .map_err(|err| {
        refusal(
            "ASTRO_GUARD_REPARSE_PARSE_FAILED",
            format!("source #{index} libcbm reparse failed: {err}"),
            "Reject the candidate as unparseable; the guard never scores a snippet it cannot parse.",
        )
    })?;

    let definitions = extracted.definitions().map_err(|err| {
        refusal(
            "ASTRO_GUARD_REPARSE_PARSE_FAILED",
            format!("source #{index} reparse produced no readable definitions: {err}"),
            "Reject the candidate as unparseable; the guard never scores a snippet it cannot parse.",
        )
    })?;
    // Primary definition: the one whose name matches the declared symbol, else the
    // widest line span (the enclosing symbol of a single-symbol snippet).
    let primary = definitions
        .iter()
        .find(|def| !symbol_name.is_empty() && def.name == symbol_name)
        .or_else(|| {
            definitions
                .iter()
                .max_by_key(|def| def.end_line.saturating_sub(def.start_line))
        })
        .ok_or_else(|| {
            refusal(
                "ASTRO_GUARD_REPARSE_NO_STRUCTURE",
                format!("source #{index} reparse extracted no definition to measure S1/S4 from"),
                "Supply a complete symbol definition (function/method/type), not a bare fragment.",
            )
        })?;

    // S1: normalised AST node-type struct trigrams from the primary def's body.
    let trigrams = primary.parsed_struct_trigrams().map_err(|err| {
        refusal(
            "ASTRO_GUARD_REPARSE_PARSE_FAILED",
            format!("source #{index} struct-trigram readback failed: {err}"),
            "Treat this as libcbm serialization drift and reject the reparse as a fault.",
        )
    })?;
    if trigrams.is_empty() {
        return Err(refusal(
            "ASTRO_GUARD_REPARSE_NO_STRUCTURE",
            format!(
                "source #{index} (`{}`) has no weighted structural trigram; S1 is unmeasurable",
                primary.name
            ),
            "Measure a symbol with real control/expression structure; a trivial body has no S1 \
             surface and is refused rather than scored on an empty vector.",
        ));
    }
    let struct_trigrams: Vec<StructuralTrigram> = trigrams
        .into_iter()
        .map(|(a, b, c, weight)| StructuralTrigram { a, b, c, weight })
        .collect();
    let s1_input = EncoderLensInput {
        struct_trigrams: Some(struct_trigrams),
        ..EncoderLensInput::default()
    };
    let s1 = encode_slot(SlotId::new(PANEL_SLOT_STRUCT_TRIGRAMS), &s1_input).map_err(|err| {
        refusal(
            "ASTRO_GUARD_REPARSE_ENCODE_FAILED",
            format!(
                "source #{index} S1 struct-trigram encode failed: {}",
                err.message()
            ),
            "Reject the candidate; its structural trigrams do not encode to a valid S1 vector.",
        )
    })?;

    // S4: callees attributed to the primary def, aggregated by callee. A fresh
    // snippet has no cross-file resolution, so callees are unresolved (the panel
    // hashes them under the `unresolved:` term) — identical for candidate and
    // exemplar measured through this same path.
    let calls = extracted.calls().map_err(|err| {
        refusal(
            "ASTRO_GUARD_REPARSE_PARSE_FAILED",
            format!("source #{index} callee readback failed: {err}"),
            "Reject the candidate as unparseable; the guard never scores a snippet it cannot parse.",
        )
    })?;
    let mut callee_counts: BTreeMap<String, f32> = BTreeMap::new();
    for call in &calls {
        let attributed = call
            .enclosing_func_qn
            .as_deref()
            .is_none_or(|qn| qn == primary.qualified_name);
        if attributed && !call.callee_name.trim().is_empty() {
            *callee_counts.entry(call.callee_name.clone()).or_insert(0.0) += 1.0;
        }
    }
    if callee_counts.is_empty() {
        return Err(refusal(
            "ASTRO_GUARD_REPARSE_NO_STRUCTURE",
            format!(
                "source #{index} (`{}`) makes no calls; S4 (api_callees) is unmeasurable",
                primary.name
            ),
            "Measure a symbol that invokes an API surface; a call-free body has no S4 surface and \
             is refused rather than scored on an empty vector.",
        ));
    }
    let api_calls: Vec<ApiCall> = callee_counts
        .into_iter()
        .map(|(callee, call_count)| ApiCall {
            callee,
            call_count,
            resolved: false,
        })
        .collect();
    let s4_input = EncoderLensInput {
        api_calls: Some(api_calls),
        ..EncoderLensInput::default()
    };
    let s4 = encode_slot(SlotId::new(PANEL_SLOT_API_CALLEES), &s4_input).map_err(|err| {
        refusal(
            "ASTRO_GUARD_REPARSE_ENCODE_FAILED",
            format!(
                "source #{index} S4 api-callee encode failed: {}",
                err.message()
            ),
            "Reject the candidate; its callees do not encode to a valid S4 vector.",
        )
    })?;

    Ok((s1, s4))
}

/// Resolve the libcbm grammar for a reparse, preferring the indexed file path (the
/// authority the indexing pipeline uses) and falling back to a canonical filename
/// synthesized from the declared language tag. Returns `None` when neither resolves
/// to a real grammar — the caller refuses rather than guessing.
fn resolve_reparse_language(rel_file_path: &str, language_hint: &str) -> Option<Language> {
    if !rel_file_path.trim().is_empty()
        && let Some(language) = Language::from_filename(rel_file_path)
    {
        return Some(language);
    }
    let hint = language_hint.trim().to_ascii_lowercase();
    let filename = match hint.as_str() {
        "rust" | "rs" => "snippet.rs",
        "python" | "py" => "snippet.py",
        "javascript" | "js" => "snippet.js",
        "typescript" | "ts" => "snippet.ts",
        "tsx" => "snippet.tsx",
        "jsx" => "snippet.jsx",
        "go" | "golang" => "snippet.go",
        "java" => "snippet.java",
        "c" => "snippet.c",
        "cpp" | "c++" | "cxx" => "snippet.cpp",
        "csharp" | "c#" | "cs" => "snippet.cs",
        "ruby" | "rb" => "snippet.rb",
        "php" => "snippet.php",
        "kotlin" | "kt" => "snippet.kt",
        "swift" => "snippet.swift",
        "scala" => "snippet.scala",
        _ => return None,
    };
    Language::from_filename(filename)
}

/// Parse a source's `label` into a [`SymbolLabel`] governing panel applicability.
/// Absent label defaults to `Function` (a callable, where every guard slot applies);
/// a present-but-unrecognized label is a fail-closed refusal.
fn source_symbol_label(
    obj: &Map<String, Value>,
    index: usize,
) -> Result<astrolabe_domain::SymbolLabel, GuardRefusal> {
    use astrolabe_domain::SymbolLabel;
    let Some(raw) = obj.get("label").and_then(Value::as_str) else {
        return Ok(SymbolLabel::Function);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(SymbolLabel::Function);
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "function" => Ok(SymbolLabel::Function),
        "method" => Ok(SymbolLabel::Method),
        "macro" => Ok(SymbolLabel::Macro),
        "class" => Ok(SymbolLabel::Class),
        "struct" => Ok(SymbolLabel::Struct),
        "interface" => Ok(SymbolLabel::Interface),
        "enum" => Ok(SymbolLabel::Enum),
        "trait" => Ok(SymbolLabel::Trait),
        "type" => Ok(SymbolLabel::Type),
        "typealias" => Ok(SymbolLabel::TypeAlias),
        "module" => Ok(SymbolLabel::Module),
        "file" => Ok(SymbolLabel::File),
        "namespace" => Ok(SymbolLabel::Namespace),
        "impl" => Ok(SymbolLabel::Impl),
        other => Err((
            "ASTRO_GUARD_CALIBRATE_SOURCE_LABEL".to_string(),
            format!("source #{index} label `{other}` is not a recognized symbol label"),
            "Use a callable/type/module label such as function, method, class, or module."
                .to_string(),
        )),
    }
}

/// SHA-256 over the sorted, newline-framed `(class|qualified_name)` identities — the
/// auto corpus provenance pinned into the guard profile's `corpus_hash`.
fn auto_corpus_hash(identities: &[String]) -> [u8; 32] {
    let mut sorted: Vec<&String> = identities.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"astro.guard.auto_corpus.v1\0");
    for identity in sorted {
        hasher.update(identity.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
    let scope_class = domain_obj
        .get("scope_class")
        .and_then(Value::as_str)
        .unwrap_or("");
    CalibrationDomain::new(language, scope_class).map_err(|_| {
        (
            "ASTRO_GUARD_CALIBRATE_INVALID",
            "domain.scope_class must be a non-empty scope class",
            "Pass a non-empty scope_class such as core, frontend, or test.",
        )
    })
}

fn language_from_str(value: &str) -> Option<CalibrationLanguage> {
    CalibrationLanguage::ALL
        .iter()
        .copied()
        .find(|language| language.as_str() == value)
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
            format!(
                "Provide {field} as an array of measured cosine scores for slot {}.",
                slot.as_str()
            ),
        ));
    };
    let mut scores = Vec::with_capacity(array.len());
    for value in array {
        let Some(score) = value.as_f64() else {
            return Err((
                "ASTRO_GUARD_CALIBRATE_INVALID",
                format!(
                    "slot `{}` {field} contains a non-numeric entry",
                    slot.as_str()
                ),
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
