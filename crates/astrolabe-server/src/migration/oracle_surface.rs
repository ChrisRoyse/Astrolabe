use super::*;

use astrolabe_domain::{TrustTag, rollup_trust};
use astrolabe_oracle::{
    AbductionConfig, AbductionOutcome, AbductionReport, AbductionRequest, CauseHypothesis,
    FlakyOutcome, FlakyRefusal, ForecastConfig, ForecastOutcome, ForecastReport, OccurrenceRecord,
    OracleError, RecurrenceRefusal, abduce_cause, failure_events_from_occurrences,
    forecast_flaky_window, forecast_recurrence, outcome_series_from_occurrences,
    read_occurrence_rows,
};
use calyx_core::{CxId, Ts};

// ---------------------------------------------------------------------------
// Envelope schemas
// ---------------------------------------------------------------------------

/// Envelope schema for the `abduce_cause` MCP tool.
pub(crate) const ABDUCE_CAUSE_SCHEMA: &str = "astrolabe.abduce_cause.v1";
/// Envelope schema for the `forecast` MCP tool.
pub(crate) const FORECAST_SCHEMA: &str = "astrolabe.forecast.v1";

// ---------------------------------------------------------------------------
// Stable failure codes (abduce_cause)
// ---------------------------------------------------------------------------

const ASTRO_ABDUCE_SHADOW_REQUIRED: &str = "ASTRO_ABDUCE_SHADOW_REQUIRED";
const ASTRO_ABDUCE_VAULT_MISSING: &str = "ASTRO_ABDUCE_VAULT_MISSING";
const ASTRO_ABDUCE_FAILURE_REQUIRED: &str = "ASTRO_ABDUCE_FAILURE_REQUIRED";
const ASTRO_ABDUCE_FAILURE_UNRESOLVED: &str = "ASTRO_ABDUCE_FAILURE_UNRESOLVED";
const ASTRO_ABDUCE_OBSERVED_AT_INVALID: &str = "ASTRO_ABDUCE_OBSERVED_AT_INVALID";

// ---------------------------------------------------------------------------
// Stable failure codes (forecast)
// ---------------------------------------------------------------------------

const ASTRO_FORECAST_SHADOW_REQUIRED: &str = "ASTRO_FORECAST_SHADOW_REQUIRED";
const ASTRO_FORECAST_VAULT_MISSING: &str = "ASTRO_FORECAST_VAULT_MISSING";
const ASTRO_FORECAST_SUBJECT_REQUIRED: &str = "ASTRO_FORECAST_SUBJECT_REQUIRED";
const ASTRO_FORECAST_SUBJECT_UNRESOLVED: &str = "ASTRO_FORECAST_SUBJECT_UNRESOLVED";
const ASTRO_FORECAST_NOW_INVALID: &str = "ASTRO_FORECAST_NOW_INVALID";
const ASTRO_FORECAST_MODE_UNSUPPORTED: &str = "ASTRO_FORECAST_MODE_UNSUPPORTED";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Reconstructs the in-memory occurrence corpus from the durable `Kv` CF rows.
/// This is the FSV path shared by abduce and forecast: the evidence is read back
/// from persisted, key-verified rows, never from an in-memory planner echo.
fn read_occurrence_records<C>(vault: &AsterVault<C>) -> Result<Vec<OccurrenceRecord>, DynError>
where
    C: Clock,
{
    let records = read_occurrence_rows(vault)?
        .into_iter()
        .map(|persisted| {
            let row = persisted.row;
            OccurrenceRecord {
                subject: row.subject,
                change_id: row.change_id,
                source: row.source,
                change_ts: row.change_ts,
                outcome_ts: row.outcome_ts,
                lag_s: row.lag_s,
                decay_weight: row.decay_weight,
                credit: row.credit,
                passed: row.passed,
                candidate_count: row.candidate_count,
                trust: row.trust,
            }
        })
        .collect();
    Ok(records)
}

fn trust_str(trust: TrustTag) -> &'static str {
    trust.as_str()
}

fn refused(
    schema: &str,
    project: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": schema,
        "project": project,
        "status": "refused",
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:pre-result:no-answer-emitted"],
    })
}

fn oracle_error_refused(schema: &str, project: &str, error: &OracleError) -> Value {
    refused(
        schema,
        project,
        error.code,
        error.message.clone(),
        error.remediation,
    )
}

// ===========================================================================
// abduce_cause
// ===========================================================================

/// Shared core for the `abduce_cause` MCP tool. Reads the persisted CBM graph
/// and oracle change→outcome corpus for a shadow-indexed project, reverse-walks
/// the propagation edges backward from an observed failure, and answers with the
/// ranked root-cause hypotheses (or an honest deficit card / coded refusal).
pub(crate) fn abduce_cause_json_at(
    cache_dir: &Path,
    project: &str,
    failure: Option<&str>,
    observed_at: Option<&str>,
    recent_changes: &[String],
) -> Result<Value, DynError> {
    let Some(failure_name) = failure.filter(|name| !name.is_empty()) else {
        return Ok(refused(
            ABDUCE_CAUSE_SCHEMA,
            project,
            ASTRO_ABDUCE_FAILURE_REQUIRED,
            "abduce_cause requires failure: the qualified name of the failing symbol to reason back from",
            "pass failure: the qualified name of the symbol whose failure you want the root cause of",
        ));
    };

    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(refused(
            ABDUCE_CAUSE_SCHEMA,
            project,
            ASTRO_ABDUCE_SHADOW_REQUIRED,
            format!("abduce_cause requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before abducing causes",
        ));
    }

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(refused(
            ABDUCE_CAUSE_SCHEMA,
            project,
            ASTRO_ABDUCE_VAULT_MISSING,
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before abducing causes",
        ));
    }

    // Resolve observed_at to the failure instant (recency + causality reference).
    // Absent → the server wall clock; a malformed value fails closed.
    let observed_ts: Ts = match observed_at {
        Some(raw) if !raw.trim().is_empty() => match astrolabe_anchors::parse_observed_at(raw) {
            Ok(ts) => ts,
            Err(error) => {
                return Ok(refused(
                    ABDUCE_CAUSE_SCHEMA,
                    project,
                    ASTRO_ABDUCE_OBSERVED_AT_INVALID,
                    format!("abduce_cause observed_at is invalid: {}", error.message()),
                    "pass observed_at as a non-negative integer epoch (seconds or ms); it is the instant the failure was observed",
                ));
            }
        },
        _ => now_epoch_seconds(),
    };

    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Kv,
            ColumnFamily::Ledger,
            ColumnFamily::Recurrence,
        ],
    )?;
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project)?;
    let node_map = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;
    let records = read_occurrence_records(&vault)?;
    drop(vault);

    let mut cx_to_qn: BTreeMap<CxId, String> = BTreeMap::new();
    for (qn, cx) in &node_map {
        cx_to_qn.insert(*cx, qn.clone());
    }

    let Some(&failure_cx) = node_map.get(failure_name) else {
        return Ok(refused(
            ABDUCE_CAUSE_SCHEMA,
            project,
            ASTRO_ABDUCE_FAILURE_UNRESOLVED,
            format!("failure symbol {failure_name:?} did not resolve to an indexed constellation"),
            "pass a qualified name present in this project's indexed graph (see search_graph); re-index if the symbol is new",
        ));
    };

    // Resolve the recent-change cross-check set. Unresolved names are counted and
    // labeled (never a silent guess), but do not fail the call — they only fail to
    // provide their cross-check boost.
    let mut recent_cx: BTreeSet<CxId> = BTreeSet::new();
    let mut recent_unresolved: Vec<String> = Vec::new();
    for name in recent_changes {
        match node_map.get(name) {
            Some(cx) => {
                recent_cx.insert(*cx);
            }
            None => recent_unresolved.push(name.clone()),
        }
    }

    let (edges, _tests, build) = consequence_edges_from_snapshot(&snapshot);
    let config = AbductionConfig::default();
    let request = AbductionRequest {
        failure: failure_cx,
        observed_ts,
        recent_changes: recent_cx,
    };

    let failure_label = cx_label(failure_cx, &cx_to_qn);
    match abduce_cause(&edges, &records, &request, &config) {
        Ok(AbductionOutcome::Grounded(report)) => Ok(abduce_grounded_json(
            project,
            observed_ts,
            &failure_label,
            &report,
            &cx_to_qn,
            &build,
            &recent_unresolved,
        )),
        Ok(AbductionOutcome::Insufficient(report)) => {
            let deficits: Vec<Value> = report
                .deficits
                .iter()
                .map(|d| {
                    json!({
                        "sensor": d.sensor,
                        "have": d.have,
                        "need": d.need,
                        "bits_short": d.bits_short,
                    })
                })
                .collect();
            Ok(json!({
                "schema": ABDUCE_CAUSE_SCHEMA,
                "project": project,
                "status": "insufficient",
                "failure": failure_label,
                "observed_ts": observed_ts,
                "deficits": deficits,
                "remediation": report.remediation,
                "graph": graph_build_json(&build),
                "recent_change_unresolved": recent_unresolved,
                "trust": "provisional",
                "freshness": "fresh",
                "provenance": ["refusal:insufficient-failure-history:deficit-card"],
            }))
        }
        Err(error) => Ok(oracle_error_refused(ABDUCE_CAUSE_SCHEMA, project, &error)),
    }
}

#[allow(clippy::too_many_arguments)]
fn abduce_grounded_json(
    project: &str,
    observed_ts: Ts,
    failure_label: &Value,
    report: &AbductionReport,
    cx_to_qn: &BTreeMap<CxId, String>,
    build: &GraphBuild,
    recent_unresolved: &[String],
) -> Value {
    let hypotheses: Vec<Value> = report
        .hypotheses
        .iter()
        .map(|h| hypothesis_json(h, cx_to_qn))
        .collect();
    // Roll the per-hypothesis trust up fail-closed: the envelope is Trusted only
    // when every ranked hypothesis is Trusted; any provisional/structural leaf
    // (or an empty set) drops the whole envelope to provisional.
    let envelope_trust = rollup_trust(report.hypotheses.iter().map(|h| h.trust));
    json!({
        "schema": ABDUCE_CAUSE_SCHEMA,
        "project": project,
        "status": "grounded",
        "failure": failure_label,
        "observed_ts": observed_ts,
        "hypotheses": hypotheses,
        "hypothesis_count": report.hypotheses.len(),
        "graph": graph_build_json(build),
        "recent_change_unresolved": recent_unresolved,
        "trust": trust_str(envelope_trust),
        "freshness": "fresh",
        "provenance": [
            "graph:read_cbm_graph_snapshot",
            "evidence:read_occurrence_rows(Kv)",
            "abduce:reverse-walk",
        ],
    })
}

fn hypothesis_json(h: &CauseHypothesis, cx_to_qn: &BTreeMap<CxId, String>) -> Value {
    json!({
        "cause": cx_label(h.cause, cx_to_qn),
        "confidence": h.confidence,
        "depth": h.depth,
        "grounded": h.grounded,
        "fail_support": h.fail_support,
        "trust": trust_str(h.trust),
        "recent_change_boosted": h.recent_change_boosted,
        "drives_boosted": h.drives_boosted,
        "disconfirming_test": h.disconfirming_test.map(|t| cx_label(t, cx_to_qn)),
        "hop_path": cx_path(&h.hop_path, cx_to_qn),
    })
}

/// MCP dispatch entry point for `abduce_cause`.
pub(crate) fn handle_abduce_cause(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("abduce_cause arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("abduce_cause requires project");
    };
    let failure = string_arg(args_obj, "failure")
        .or_else(|| string_arg(args_obj, "subject"))
        .map(ToOwned::to_owned);
    let observed_at = match args_obj.get("observed_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(_) => {
            return tool_error_result(
                "abduce_cause observed_at must be a non-negative integer epoch",
            );
        }
    };
    let recent_changes = string_array_field(&args, "recent_changes");

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = abduce_cause_json_at(
        &cache_dir,
        &project,
        failure.as_deref(),
        observed_at.as_deref(),
        &recent_changes,
    )?;
    match value.get("status").and_then(Value::as_str) {
        Some("refused") => tool_json_error_result(value),
        _ => tool_json_result(value),
    }
}

// ===========================================================================
// forecast
// ===========================================================================

/// Shared core for the `forecast` MCP tool. Reads the persisted oracle
/// change→outcome corpus for a shadow-indexed project and forecasts the
/// recurrence cadence of a subject's failure series (`mode="recurrence"`) or a
/// test's clean failure-recurrence window, refusing on flaky evidence
/// (`mode="flaky"`). Honest refusals (`ASTRO_NO_RECURRENCE`,
/// `ASTRO_FLAKY_EVIDENCE`) are surfaced as coded `{code, message, remediation}`
/// envelopes; the forecast interval is labeled with its trust.
pub(crate) fn forecast_json_at(
    cache_dir: &Path,
    project: &str,
    subject: Option<&str>,
    now: Option<&str>,
    mode: &str,
) -> Result<Value, DynError> {
    let Some(subject_name) = subject.filter(|name| !name.is_empty()) else {
        return Ok(refused(
            FORECAST_SCHEMA,
            project,
            ASTRO_FORECAST_SUBJECT_REQUIRED,
            "forecast requires subject: the qualified name of the symbol/test to forecast",
            "pass subject: the qualified name of the symbol whose failure recurrence you want forecast",
        ));
    };

    if !matches!(mode, "recurrence" | "flaky") {
        return Ok(refused(
            FORECAST_SCHEMA,
            project,
            ASTRO_FORECAST_MODE_UNSUPPORTED,
            format!("forecast mode {mode:?} is not available"),
            "use mode=\"recurrence\" (default) or mode=\"flaky\"",
        ));
    }

    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(refused(
            FORECAST_SCHEMA,
            project,
            ASTRO_FORECAST_SHADOW_REQUIRED,
            format!("forecast requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before forecasting",
        ));
    }

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(refused(
            FORECAST_SCHEMA,
            project,
            ASTRO_FORECAST_VAULT_MISSING,
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before forecasting",
        ));
    }

    let now_ts: Ts = match now {
        Some(raw) if !raw.trim().is_empty() => match astrolabe_anchors::parse_observed_at(raw) {
            Ok(ts) => ts,
            Err(error) => {
                return Ok(refused(
                    FORECAST_SCHEMA,
                    project,
                    ASTRO_FORECAST_NOW_INVALID,
                    format!("forecast now is invalid: {}", error.message()),
                    "pass now as a non-negative integer epoch (seconds or ms); it is the reference instant for the overdue hazard",
                ));
            }
        },
        _ => now_epoch_seconds(),
    };

    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Graph, ColumnFamily::Base, ColumnFamily::Kv],
    )?;
    let node_map = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;
    let records = read_occurrence_records(&vault)?;
    drop(vault);

    let mut cx_to_qn: BTreeMap<CxId, String> = BTreeMap::new();
    for (qn, cx) in &node_map {
        cx_to_qn.insert(*cx, qn.clone());
    }

    let Some(&subject_cx) = node_map.get(subject_name) else {
        return Ok(refused(
            FORECAST_SCHEMA,
            project,
            ASTRO_FORECAST_SUBJECT_UNRESOLVED,
            format!("subject symbol {subject_name:?} did not resolve to an indexed constellation"),
            "pass a qualified name present in this project's indexed graph (see search_graph); re-index if the symbol is new",
        ));
    };

    let subject_label = cx_label(subject_cx, &cx_to_qn);
    let config = ForecastConfig::default();

    match mode {
        "recurrence" => {
            let events = failure_events_from_occurrences(&records, subject_cx);
            match forecast_recurrence(&events, now_ts, Some(subject_cx), &config) {
                Ok(ForecastOutcome::Forecast(report)) => Ok(forecast_report_json(
                    project,
                    "recurrence",
                    &subject_label,
                    now_ts,
                    &report,
                )),
                Ok(ForecastOutcome::NoRecurrence(refusal)) => Ok(no_recurrence_json(
                    project,
                    "recurrence",
                    &subject_label,
                    &refusal,
                )),
                Err(error) => Ok(oracle_error_refused(FORECAST_SCHEMA, project, &error)),
            }
        }
        _ => {
            let series = outcome_series_from_occurrences(&records, subject_cx);
            match forecast_flaky_window(&series, subject_cx, now_ts, &config) {
                Ok(FlakyOutcome::Window(report)) => Ok(forecast_report_json(
                    project,
                    "flaky",
                    &subject_label,
                    now_ts,
                    &report,
                )),
                Ok(FlakyOutcome::Flaky(refusal)) => {
                    Ok(flaky_refused_json(project, &subject_label, &refusal))
                }
                Ok(FlakyOutcome::NoRecurrence(refusal)) => Ok(no_recurrence_json(
                    project,
                    "flaky",
                    &subject_label,
                    &refusal,
                )),
                Err(error) => Ok(oracle_error_refused(FORECAST_SCHEMA, project, &error)),
            }
        }
    }
}

fn forecast_report_json(
    project: &str,
    mode: &str,
    subject_label: &Value,
    now_ts: Ts,
    report: &ForecastReport,
) -> Value {
    json!({
        "schema": FORECAST_SCHEMA,
        "project": project,
        "status": "forecast",
        "mode": mode,
        "subject": subject_label,
        "now_ts": now_ts,
        "event_count": report.event_count,
        "interval_count": report.interval_count,
        "median_cadence_secs": report.median_cadence_secs,
        "mad_secs": report.mad_secs,
        "next_occurrence_ts": report.next_occurrence_ts,
        // The credible interval on the next occurrence — always labeled with its
        // trust; a small-sample forecast is provisional (interval widened), never
        // presented as a certain cadence.
        "interval": {
            "low_ts": report.interval_low_ts,
            "high_ts": report.interval_high_ts,
            "small_sample": report.small_sample,
        },
        "regularity": report.regularity,
        "confidence": report.confidence,
        "overdue_hazard": report.overdue_hazard,
        "small_sample": report.small_sample,
        "periodicity": {
            "period_secs": report.periodicity.period_secs,
            "strength": report.periodicity.strength,
        },
        "regime_changes": report
            .regime_changes
            .iter()
            .map(|r| json!({
                "at_event_index": r.at_event_index,
                "at_ts": r.at_ts,
                "direction": match r.direction {
                    astrolabe_oracle::RegimeDirection::Speedup => "speedup",
                    astrolabe_oracle::RegimeDirection::Slowdown => "slowdown",
                },
            }))
            .collect::<Vec<_>>(),
        "trust": trust_str(report.trust),
        "freshness": "fresh",
        "provenance": [
            "evidence:read_occurrence_rows(Kv)",
            format!("forecast:{mode}"),
        ],
    })
}

fn no_recurrence_json(
    project: &str,
    mode: &str,
    subject_label: &Value,
    refusal: &RecurrenceRefusal,
) -> Value {
    json!({
        "schema": FORECAST_SCHEMA,
        "project": project,
        "status": "refused",
        "mode": mode,
        "subject": subject_label,
        "code": refusal.code,
        "message": format!(
            "too few failure events to forecast a cadence: have {}, need {}",
            refusal.have_events, refusal.need_events
        ),
        "remediation": refusal.remediation,
        "have_events": refusal.have_events,
        "need_events": refusal.need_events,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:no-recurrence:too-few-events"],
    })
}

fn flaky_refused_json(project: &str, subject_label: &Value, refusal: &FlakyRefusal) -> Value {
    json!({
        "schema": FORECAST_SCHEMA,
        "project": project,
        "status": "refused",
        "mode": "flaky",
        "subject": subject_label,
        "code": refusal.code,
        "message": format!(
            "the pass/fail series is flaky (self-consistency {:.4} < floor {:.4}); refusing to forecast a cadence from self-inconsistent noise",
            refusal.self_consistency, refusal.floor
        ),
        "remediation": refusal.remediation,
        "self_consistency": refusal.self_consistency,
        "floor": refusal.floor,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:flaky-evidence:self-inconsistent"],
    })
}

/// MCP dispatch entry point for `forecast`.
pub(crate) fn handle_forecast(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("forecast arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("forecast requires project");
    };
    let subject = string_arg(args_obj, "subject")
        .or_else(|| string_arg(args_obj, "test"))
        .map(ToOwned::to_owned);
    let mode = string_arg(args_obj, "mode")
        .unwrap_or("recurrence")
        .to_owned();
    let now = match args_obj.get("now") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(_) => return tool_error_result("forecast now must be a non-negative integer epoch"),
    };

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = forecast_json_at(
        &cache_dir,
        &project,
        subject.as_deref(),
        now.as_deref(),
        &mode,
    )?;
    match value.get("status").and_then(Value::as_str) {
        Some("refused") => tool_json_error_result(value),
        _ => tool_json_result(value),
    }
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
