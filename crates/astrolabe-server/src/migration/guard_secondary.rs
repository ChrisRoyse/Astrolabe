//! Panel measurement in **secondary processes** (P7.4, blueprint `10_GUARD.md`
//! §5, #48 DoD 3-4, #355).
//!
//! Two guard surfaces measure a candidate/exemplar **outside** the main import
//! request path — the commit-OOD watcher tick and the PostToolUse advisory hook.
//! Both are the same underlying capability: measure changed/edited symbols through
//! the guard panel instrument in a background tick or hook, then surface the
//! verdict. Neither invents a parallel measurement path — each measures through the
//! single shared [`measure_symbol_from_panel`] instrument (the #341 per-snippet
//! libcbm reparse that populates S1/S4), exactly the instrument `guard_check`
//! (panel mode) uses, so a symbol scored in the watcher/hook is measured
//! byte-identically to one scored on the request path.
//!
//! ## Commit-OOD watcher tick (DoD #3)
//!
//! When the incremental watcher converges a project it scores that project's
//! changed symbols against the calibrated profile. A symbol that does not conform
//! to its trusted region (any verdict other than `accept`) makes the commit
//! **out-of-distribution** and the guard emits a `new_region` reactive trigger
//! carrying the **commit ref**; a commit whose symbols all conform surfaces no
//! alarm. The per-commit report is appended to a durable, readback-verified review
//! surface persisted in the config store and surfaced (labeled) on
//! `optimizer_status` / `get_readiness` alongside the guard drift proposals — the
//! same monitor-persistence discipline the drift surface uses.
//!
//! ## PostToolUse advisory hook (DoD #4)
//!
//! After an agent tool edits code, an **advisory** quick guard check scores the
//! two cheapest slots (S18 code-semantic, S4 api-callees) of the edited candidate
//! against its enclosing-scope exemplars. It is strictly advisory: it runs the
//! pure scoring on a worker thread bounded by the registry-declared
//! [`ADVISORY_HOOK_BUDGET_MS`] budget and, on timeout or fault, goes **silent** —
//! the skip is labeled and **counted** in the persisted surface (never a silent
//! swallow), and the agent flow is never blocked past the budget. The candidate
//! and exemplars are measured on the caller thread (the libcbm reparse handle is
//! `!Send`, so it cannot cross to the worker) and are themselves bounded by the
//! reparse timeout; only the pure per-slot scoring runs under the deadline worker.

use super::*;

use astrolabe_guard::check::{Exemplar, canonical_slot_number};
use astrolabe_guard::commit::{COMMIT_OOD_SCHEMA, CommitOodReport, CommitSymbol, score_commit};
use astrolabe_guard::hook::{
    ADVISORY_HOOK_SCHEMA, AdvisoryOutcome, AdvisorySignal, quick_signal_owned,
    run_advisory_hook_with_budget,
};
use astrolabe_guard::profile::ADVISORY_HOOK_BUDGET_MS;
use astrolabe_panel::PanelDriver;

/// Config-store key (per project) holding the bounded commit-OOD review history.
const GUARD_COMMIT_OOD_REVIEWS_KEY: &str = "guard_commit_ood_reviews_json";
/// Config-store key (per project) holding a pending commit-OOD scoring request the
/// watcher tick consumes (`{commit_ref, symbols:[...]}` — the same shape the
/// `guard_commit_ood` tool accepts).
const GUARD_COMMIT_OOD_PENDING_KEY: &str = "guard_commit_ood_pending_json";
/// Config-store key (per project) holding the latest advisory-hook outcome + the
/// cumulative advisory/silent counters.
const GUARD_ADVISORY_HOOK_KEY: &str = "guard_advisory_hook_json";
/// Retained recent commit-OOD reviews (a bounded surface cap, not a knob that
/// changes any measured verdict — an operational cap on surfaced history length,
/// mirroring the guard drift proposal retention).
const GUARD_COMMIT_OOD_REVIEWS_RETAINED: usize = 50;

/// Schema tag for the commit-OOD review surface on optimizer_status/get_readiness.
const COMMIT_OOD_SURFACE_SCHEMA: &str = "astro.guard.commit_ood_surface.v1";
/// Schema tag for the advisory-hook served/persisted outcome.
const ADVISORY_HOOK_SURFACE_SCHEMA: &str = "astro.guard.advisory_hook_surface.v1";

// ===========================================================================
// Commit-OOD watcher/review surface (DoD #3)
// ===========================================================================

/// `guard_commit_ood`: score a commit's changed symbols through the guard panel
/// instrument and surface any out-of-distribution verdicts on the review surface.
///
/// Request shape (panel measurement, the same #341 instrument as guard_check):
/// ```json
/// {
///   "project": "demo",
///   "commit_ref": "commit:abc123",
///   "panel_version": 1,
///   "symbols": [
///     {
///       "cx": "<changed symbol CxId hex>",
///       "identity_locked": true,          // optional override; else the persisted lock inventory
///       "candidate": {"source": "..", "symbol_name": "..", "properties": {..}, ..},
///       "exemplars": [{"cx": "<hex>", "kernel_near": true, "source": "..", ..}, ...]
///     }
///   ]
/// }
/// ```
///
/// Fail-closed: not-shadow, no calibrated profile, a missing commit_ref, an empty
/// symbols set, a symbol missing panel inputs / a comparison region, or a panel
/// measurement fault all refuse with `{code,message,remediation}` and persist no
/// review (an unscored change is never treated as conforming).
pub(crate) fn handle_guard_commit_ood(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return guard_secondary_refused(
            "ASTRO_GUARD_COMMIT_OOD_INVALID",
            "guard_commit_ood arguments must be a JSON object",
            "Pass a JSON object with project, commit_ref, and symbols.",
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return guard_secondary_refused(
            "ASTRO_GUARD_COMMIT_OOD_INVALID",
            "guard_commit_ood requires project",
            "Pass the project whose commit is being scored.",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    guard_commit_ood_at(&cache_dir, &project, args_obj)
}

/// FSV-testable core: everything after the project is resolved, rooted at an
/// explicit `cache_dir` so contract tests drive it against a real temp vault.
pub(crate) fn guard_commit_ood_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return guard_secondary_refused(
            "ASTRO_GUARD_COMMIT_OOD_NOT_SHADOW",
            "guard_commit_ood requires calyx shadow indexing",
            "run index_repository with calyx=\"shadow\" and guard_calibrate before scoring a commit",
        );
    }

    let profile = match load_persisted_profile(cache_dir, project) {
        Ok(profile) => profile,
        Err((code, message, remediation)) => {
            return guard_secondary_refused_owned(code.to_string(), message, remediation);
        }
    };

    let Some(commit_ref) = string_arg(args_obj, "commit_ref")
        .or_else(|| string_arg(args_obj, "commit"))
        .map(str::to_string)
    else {
        return guard_secondary_refused(
            "ASTRO_GUARD_COMMIT_OOD_INVALID",
            "guard_commit_ood requires commit_ref",
            "Pass commit_ref as the commit that introduced the changed symbols.",
        );
    };

    let Some(symbols_json) = args_obj.get("symbols").and_then(Value::as_array) else {
        return guard_secondary_refused(
            "ASTRO_GUARD_COMMIT_OOD_INVALID",
            "guard_commit_ood requires a symbols array",
            "Pass the commit's changed symbols, each with candidate panel inputs and exemplars.",
        );
    };
    if symbols_json.is_empty() {
        return guard_secondary_refused(
            "ASTRO_GUARD_COMMIT_OOD_INVALID",
            "guard_commit_ood symbols array is empty",
            "Pass at least one changed symbol; an empty commit has nothing to score.",
        );
    }

    let panel_version = args_obj
        .get("panel_version")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(DEFAULT_PANEL_VERSION);
    let driver = match PanelDriver::new(panel_version) {
        Ok(driver) => driver,
        Err(err) => {
            return guard_secondary_refused_owned(
                "ASTRO_GUARD_COMMIT_OOD_PANEL_VERSION".to_string(),
                format!("panel version {panel_version} is invalid: {}", err.message()),
                "Score with panel version 1 (S0-S22) or 2 (S0-S23).".to_string(),
            );
        }
    };
    let runtime = ShadowSlotRuntime;
    let inventory = load_lock_inventory(cache_dir, project)?;

    let mut commit_symbols = Vec::with_capacity(symbols_json.len());
    for (index, entry) in symbols_json.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            return guard_secondary_refused_owned(
                "ASTRO_GUARD_COMMIT_OOD_INVALID".to_string(),
                format!("symbol #{index} must be an object"),
                "Each changed symbol needs cx, candidate panel inputs, and exemplars.".to_string(),
            );
        };
        let Some(cx_hex) = obj.get("cx").and_then(Value::as_str).map(str::to_string) else {
            return guard_secondary_refused_owned(
                "ASTRO_GUARD_COMMIT_OOD_INVALID".to_string(),
                format!("symbol #{index} requires cx (the changed symbol's CxId hex)"),
                "Pass cx as the changed symbol's CxId hex; it is the trigger subject.".to_string(),
            );
        };
        let Some(candidate_obj) = obj.get("candidate").and_then(Value::as_object) else {
            return guard_secondary_refused_owned(
                "ASTRO_GUARD_COMMIT_OOD_INVALID".to_string(),
                format!("symbol #{index} requires a candidate object with panel inputs"),
                "Pass candidate with source and its indexed panel inputs (symbol_name, properties, …)."
                    .to_string(),
            );
        };
        let candidate = match measure_symbol_from_panel(&driver, &runtime, candidate_obj, index) {
            Ok(measured) => measured,
            Err((code, message, remediation)) => {
                return guard_secondary_refused_owned(
                    "ASTRO_GUARD_COMMIT_OOD_PANEL_FAILED".to_string(),
                    format!("[{code}] {message}"),
                    remediation,
                );
            }
        };
        let exemplars = match measure_exemplars(&driver, &runtime, obj.get("exemplars")) {
            Ok(exemplars) => exemplars,
            Err((code, message, remediation)) => {
                return guard_secondary_refused_owned(code, message, remediation);
            }
        };
        // The declared identity_locked wins when present; otherwise the persisted
        // lock inventory decides (so a locked public surface's signature drift
        // routes to an identity refuse, not a masquerading content new_region).
        let identity_locked = obj
            .get("identity_locked")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| inventory.is_locked(&cx_hex));
        commit_symbols.push(CommitSymbol {
            cx_id_hex: cx_hex,
            identity_locked,
            candidate,
            exemplars,
        });
    }

    let report = match score_commit(&commit_ref, &commit_symbols, &profile) {
        Ok(report) => report,
        Err(error) => {
            return guard_secondary_refused_owned(
                error.code().to_string(),
                error.message().to_string(),
                error.remediation().to_string(),
            );
        }
    };

    record_commit_ood_review(cache_dir, project, &report)?;
    let readback = commit_ood_reviews_section(cache_dir, project);

    tool_json_result(json!({
        "schema": COMMIT_OOD_SCHEMA,
        "status": "scored",
        "project": project,
        "commit_ref": report.commit_ref,
        "scored": report.scored,
        "ood": report.ood,
        "triggers": report.triggers.iter().map(commit_ood_trigger_json).collect::<Vec<_>>(),
        "review_surface": readback,
        "source": format!("config:{}", metadata_key(project, GUARD_COMMIT_OOD_REVIEWS_KEY)),
        "trust": "verified",
        "freshness": "fresh",
    }))
}

/// Measure an `exemplars` JSON array into densified [`Exemplar`]s through the shared
/// panel instrument (byte-identical to the candidate's measurement path).
fn measure_exemplars(
    driver: &PanelDriver,
    runtime: &ShadowSlotRuntime,
    value: Option<&Value>,
) -> Result<Vec<Exemplar>, GuardRefusal> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Err((
            "ASTRO_GUARD_COMMIT_OOD_INVALID".to_string(),
            "each changed symbol requires an exemplars array".to_string(),
            "Provide the enclosing scope's trusted exemplars, each with panel inputs.".to_string(),
        ));
    };
    let mut exemplars = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            return Err((
                "ASTRO_GUARD_COMMIT_OOD_INVALID".to_string(),
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
        let measured = measure_symbol_from_panel(driver, runtime, obj, index)?;
        exemplars.push(Exemplar {
            cx_id_hex: cx,
            kernel_near,
            measured,
        });
    }
    Ok(exemplars)
}

/// Append one commit-OOD report to the bounded review history, readback-verified.
fn record_commit_ood_review(
    cache_dir: &Path,
    project: &str,
    report: &CommitOodReport,
) -> Result<(), DynError> {
    let mut history = read_commit_ood_reviews_raw(cache_dir, project)?;
    history.push(commit_ood_report_json(report));
    let start = history
        .len()
        .saturating_sub(GUARD_COMMIT_OOD_REVIEWS_RETAINED);
    let trimmed = history[start..].to_vec();
    let text = serde_json::to_string(&trimmed)?;
    let key = metadata_key(project, GUARD_COMMIT_OOD_REVIEWS_KEY);
    write_config_value(cache_dir, &key, &text)?;
    let readback = read_config_value(cache_dir, &key)?;
    if readback.as_deref() != Some(text.as_str()) {
        return Err(format!(
            "ASTRO_GUARD_COMMIT_OOD_REVIEW_MISMATCH: commit-OOD review surface for {project:?} did not read back byte-identically; remediation: the config store diverged from the committed review state"
        )
        .into());
    }
    Ok(())
}

/// Read the raw persisted commit-OOD review history (empty when unset).
fn read_commit_ood_reviews_raw(cache_dir: &Path, project: &str) -> Result<Vec<Value>, DynError> {
    let Some(raw) =
        read_config_value(cache_dir, &metadata_key(project, GUARD_COMMIT_OOD_REVIEWS_KEY))?
    else {
        return Ok(Vec::new());
    };
    let value: Value = serde_json::from_str(&raw)?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

/// Canonical JSON of one commit-OOD report for the review surface.
fn commit_ood_report_json(report: &CommitOodReport) -> Value {
    json!({
        "schema": COMMIT_OOD_SCHEMA,
        "commit_ref": report.commit_ref,
        "scored": report.scored,
        "ood": report.ood,
        "triggers": report.triggers.iter().map(commit_ood_trigger_json).collect::<Vec<_>>(),
        "trust": "verified",
        "freshness": "fresh",
    })
}

/// Canonical JSON of one commit-OOD trigger (the review-surface record for a
/// non-conforming changed symbol).
fn commit_ood_trigger_json(trigger: &astrolabe_guard::commit::CommitOodTrigger) -> Value {
    json!({
        "trigger": trigger.trigger,
        "commit_ref": trigger.commit_ref,
        "subject_cx": trigger.subject_cx_hex,
        "verdict": trigger.verdict.as_str(),
        "region_class": trigger.region_class,
        "reason": trigger.reason,
    })
}

/// Surface the persisted commit-OOD reviews as a labeled section for
/// `optimizer_status` / `get_readiness`. Always present (an empty list when the
/// watcher has raised no OOD alarm) so the surface is honest about "no commit
/// drift observed".
pub(crate) fn commit_ood_reviews_section(cache_dir: &Path, project: &str) -> Value {
    let reviews = read_commit_ood_reviews_raw(cache_dir, project).unwrap_or_default();
    let ood_count = reviews
        .iter()
        .filter(|review| review.get("ood").and_then(Value::as_bool) == Some(true))
        .count();
    json!({
        "schema": COMMIT_OOD_SURFACE_SCHEMA,
        "count": reviews.len(),
        "ood_count": ood_count,
        "reviews": reviews,
        "trust": "verified",
        "freshness": if reviews.is_empty() { "not_evaluated" } else { "fresh" },
        "note": "commit-OOD verdicts raised by the incremental watcher tick when a commit's changed symbol does not conform to its trusted region; each carries the commit ref (new_region reactive trigger to the review surface)",
    })
}

/// Score a pending commit-OOD request enqueued for `project`, if any, from inside
/// the incremental watcher tick. The changed symbols + their exemplars are read
/// from the persisted `guard_commit_ood_pending_json` request (the same shape the
/// `guard_commit_ood` tool accepts), measured through the shared panel instrument,
/// and the resulting verdicts appended to the review surface. The request is
/// cleared once consumed. Returns the number of OOD triggers raised (0 when there
/// is no pending request or the commit conforms).
///
/// A scoring fault is a labeled error returned to the watcher loop (which logs it
/// and continues) — a bad request never crashes the tick, but is also never
/// silently swallowed.
pub(crate) fn score_pending_commit_ood(cache_dir: &Path, project: &str) -> Result<usize, DynError> {
    let Some(raw) =
        read_config_value(cache_dir, &metadata_key(project, GUARD_COMMIT_OOD_PENDING_KEY))?
    else {
        return Ok(0);
    };
    if raw.trim().is_empty() {
        return Ok(0);
    }
    let request: Value = serde_json::from_str(&raw)?;
    let Some(request_obj) = request.as_object() else {
        // A malformed pending request is cleared (never re-processed) but reported.
        delete_config_value(cache_dir, &metadata_key(project, GUARD_COMMIT_OOD_PENDING_KEY))?;
        return Err(format!(
            "ASTRO_GUARD_COMMIT_OOD_PENDING_INVALID: pending commit-OOD request for {project:?} is not a JSON object"
        )
        .into());
    };
    // Consume the request first so a scoring fault cannot wedge the tick on a
    // permanently-failing request.
    delete_config_value(cache_dir, &metadata_key(project, GUARD_COMMIT_OOD_PENDING_KEY))?;

    let response = guard_commit_ood_at(cache_dir, project, request_obj)?;
    let value: Value = serde_json::from_str(&response)?;
    // A refused score is surfaced (never counted as "0 conforming"): propagate the
    // labeled refusal to the watcher loop, which records it as a degraded tick.
    if value.get("isError").and_then(Value::as_bool) == Some(true) {
        let text = value
            .get("content")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .unwrap_or("guard_commit_ood refused the pending request");
        return Err(format!("pending commit-OOD scoring refused for {project:?}: {text}").into());
    }
    let triggers = value
        .get("structuredContent")
        .and_then(|sc| sc.get("triggers"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    Ok(triggers)
}

// ===========================================================================
// PostToolUse advisory hook (DoD #4)
// ===========================================================================

/// `guard_advisory_hook`: score the two advisory slots (S18 code-semantic, S4
/// api-callees) of an edited candidate against its enclosing-scope exemplars under
/// the registry-declared budget, and persist a labeled advisory / silent-skip
/// outcome. Strictly advisory — never blocks, never refuses a valid candidate; a
/// timeout or scoring fault is a labeled, **counted** silent skip.
///
/// Request shape (panel measurement, the same #341 instrument as guard_check):
/// ```json
/// {
///   "project": "demo",
///   "panel_version": 1,
///   "budget_ms": 300,                 // optional per-call deadline; default ADVISORY_HOOK_BUDGET_MS
///   "candidate": {"source": "..", "symbol_name": "..", "properties": {..}, ..},
///   "exemplars": [{"cx": "<hex>", "kernel_near": true, "source": "..", ..}, ...]
/// }
/// ```
///
/// Fail-closed only at the tool boundary (not-shadow, no calibrated profile,
/// malformed args, missing candidate) — these are misconfigurations the hook
/// consumer ignores. A candidate that measures but cannot be scored in budget is a
/// labeled silent skip, not a refusal.
pub(crate) fn handle_guard_advisory_hook(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return guard_secondary_refused(
            "ASTRO_GUARD_HOOK_INVALID",
            "guard_advisory_hook arguments must be a JSON object",
            "Pass a JSON object with project, candidate, and exemplars.",
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return guard_secondary_refused(
            "ASTRO_GUARD_HOOK_INVALID",
            "guard_advisory_hook requires project",
            "Pass the project whose edited candidate is being advised on.",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    guard_advisory_hook_at(&cache_dir, &project, args_obj)
}

/// FSV-testable core: everything after the project is resolved, rooted at an
/// explicit `cache_dir` so contract tests drive it against a real temp vault.
pub(crate) fn guard_advisory_hook_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return guard_secondary_refused(
            "ASTRO_GUARD_HOOK_NOT_SHADOW",
            "guard_advisory_hook requires calyx shadow indexing",
            "run index_repository with calyx=\"shadow\" and guard_calibrate before advising",
        );
    }

    let profile = match load_persisted_profile(cache_dir, project) {
        Ok(profile) => profile,
        Err((code, message, remediation)) => {
            return guard_secondary_refused_owned(code.to_string(), message, remediation);
        }
    };

    let Some(candidate_obj) = args_obj.get("candidate").and_then(Value::as_object) else {
        return guard_secondary_refused(
            "ASTRO_GUARD_HOOK_INVALID",
            "guard_advisory_hook requires a candidate object with panel inputs",
            "Pass candidate with source and its indexed panel inputs (symbol_name, properties, …).",
        );
    };

    // Registry-declared budget with an optional per-call tightening override. The
    // default is the registry knob; the never-blocks guarantee holds for any value.
    let budget_ms = args_obj
        .get("budget_ms")
        .and_then(Value::as_u64)
        .unwrap_or(ADVISORY_HOOK_BUDGET_MS);
    let budget_overridden = args_obj.get("budget_ms").and_then(Value::as_u64).is_some();

    let panel_version = args_obj
        .get("panel_version")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(DEFAULT_PANEL_VERSION);
    let driver = match PanelDriver::new(panel_version) {
        Ok(driver) => driver,
        Err(err) => {
            return guard_secondary_refused_owned(
                "ASTRO_GUARD_HOOK_PANEL_VERSION".to_string(),
                format!("panel version {panel_version} is invalid: {}", err.message()),
                "Advise with panel version 1 (S0-S22) or 2 (S0-S23).".to_string(),
            );
        }
    };
    let runtime = ShadowSlotRuntime;

    // Measure the candidate + exemplars on the CALLER thread: the libcbm reparse
    // handle is `!Send`, so it cannot cross onto the deadline worker. A measurement
    // fault is a labeled silent skip (advisory never refuses a candidate it merely
    // could not measure), counted in the persisted surface — not a swallow.
    let candidate = match measure_symbol_from_panel(&driver, &runtime, candidate_obj, 0) {
        Ok(measured) => measured,
        Err((code, message, _remediation)) => {
            return persist_and_serve_advisory(
                cache_dir,
                project,
                AdvisoryOutcome::SilentError {
                    code: "ASTRO_GUARD_HOOK_MEASUREMENT_FAILED".to_string(),
                },
                budget_ms,
                budget_overridden,
                Some(format!("[{code}] {message}")),
            );
        }
    };
    let exemplars = match measure_exemplars(&driver, &runtime, args_obj.get("exemplars")) {
        Ok(exemplars) => exemplars,
        Err((_code, message, _remediation)) => {
            return persist_and_serve_advisory(
                cache_dir,
                project,
                AdvisoryOutcome::SilentError {
                    code: "ASTRO_GUARD_HOOK_EXEMPLARS_UNMEASURABLE".to_string(),
                },
                budget_ms,
                budget_overridden,
                Some(message),
            );
        }
    };

    // Only the pure per-slot scoring runs under the deadline worker; the caller's
    // wall clock is bounded by `budget_ms` regardless of how slow the scoring is.
    // The measured candidate/exemplars + owned profile move onto the worker.
    let outcome = run_advisory_hook_with_budget(budget_ms, move || {
        quick_signal_owned(candidate, profile, exemplars)
    });
    persist_and_serve_advisory(cache_dir, project, outcome, budget_ms, budget_overridden, None)
}

/// Persist the advisory outcome (latest outcome + cumulative counters, readback
/// verified) and serve it. Every silent skip is **counted** — the persisted
/// counters are the durable proof the degradation was labeled, not swallowed.
fn persist_and_serve_advisory(
    cache_dir: &Path,
    project: &str,
    outcome: AdvisoryOutcome,
    budget_ms: u64,
    budget_overridden: bool,
    silent_detail: Option<String>,
) -> Result<String, DynError> {
    let (outcome_kind, signal_json, elapsed_ms, code): (&str, Value, Option<u64>, Option<String>) =
        match &outcome {
            AdvisoryOutcome::Advisory(signal) => {
                ("advisory", advisory_signal_json(signal), None, None)
            }
            // The outcome's budget_ms equals the input by construction of
            // run_advisory_hook_with_budget; we serve the input budget uniformly.
            AdvisoryOutcome::SilentTimeout { elapsed_ms, .. } => {
                ("silent_timeout", Value::Null, Some(*elapsed_ms), None)
            }
            AdvisoryOutcome::SilentError { code } => {
                ("silent_error", Value::Null, None, Some(code.to_string()))
            }
        };

    let mut counters = read_advisory_counters(cache_dir, project)?;
    *counters.entry(outcome_kind.to_string()).or_insert(0) += 1;

    let record = json!({
        "schema": ADVISORY_HOOK_SURFACE_SCHEMA,
        "project": project,
        "outcome": outcome_kind,
        "advisory": outcome.is_advisory(),
        "budget_ms": budget_ms,
        "budget_overridden": budget_overridden,
        "signal": signal_json,
        "elapsed_ms": elapsed_ms,
        "code": code,
        "detail": silent_detail,
        "counters": {
            "advisory": counters.get("advisory").copied().unwrap_or(0),
            "silent_timeout": counters.get("silent_timeout").copied().unwrap_or(0),
            "silent_error": counters.get("silent_error").copied().unwrap_or(0),
        },
        "note": "advisory only; never blocks the agent flow — a timeout or fault is a labeled, counted silent skip",
        "trust": "verified",
        "freshness": "fresh",
    });

    let text = serde_json::to_string(&record)?;
    let key = metadata_key(project, GUARD_ADVISORY_HOOK_KEY);
    write_config_value(cache_dir, &key, &text)?;
    let readback = read_config_value(cache_dir, &key)?;
    if readback.as_deref() != Some(text.as_str()) {
        return Err(format!(
            "ASTRO_GUARD_HOOK_SURFACE_MISMATCH: advisory-hook surface for {project:?} did not read back byte-identically; remediation: the config store diverged from the committed outcome"
        )
        .into());
    }

    tool_json_result(record)
}

/// Read the persisted cumulative advisory-hook counters (empty when unset).
fn read_advisory_counters(
    cache_dir: &Path,
    project: &str,
) -> Result<BTreeMap<String, u64>, DynError> {
    let mut counters = BTreeMap::new();
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, GUARD_ADVISORY_HOOK_KEY))?
    else {
        return Ok(counters);
    };
    let value: Value = serde_json::from_str(&raw)?;
    if let Some(object) = value.get("counters").and_then(Value::as_object) {
        for kind in ["advisory", "silent_timeout", "silent_error"] {
            if let Some(count) = object.get(kind).and_then(Value::as_u64) {
                counters.insert(kind.to_string(), count);
            }
        }
    }
    Ok(counters)
}

/// Canonical JSON of a completed advisory signal (per-slot cos/tau/pass on the two
/// advisory slots). Slot numbers use the canonical shortest-decimal f32 image so a
/// readback compares byte-identically.
fn advisory_signal_json(signal: &AdvisorySignal) -> Value {
    json!({
        "schema": ADVISORY_HOOK_SCHEMA,
        "any_below": signal.any_below,
        "note": signal.note,
        "slots": signal.slots.iter().map(|sv| json!({
            "slot": sv.slot.as_str(),
            "cos": canonical_slot_number(sv.cos),
            "tau": canonical_slot_number(sv.tau),
            "pass": sv.pass(),
        })).collect::<Vec<_>>(),
    })
}

// ===========================================================================
// Refusal helpers
// ===========================================================================

fn guard_secondary_refused(
    code: &str,
    message: &str,
    remediation: &str,
) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}

fn guard_secondary_refused_owned(
    code: String,
    message: String,
    remediation: String,
) -> Result<String, DynError> {
    tool_error_result(format!("{code}: {message}; remediation: {remediation}"))
}
