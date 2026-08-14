use super::*;

/// Envelope schema for the `anchor_outcome` MCP tool / `astrolabe cli
/// anchor_outcome` subcommand.
pub(crate) const ANCHOR_OUTCOME_SCHEMA: &str = "astrolabe.anchor_outcome.v1";
/// Ledger actor recorded for every anchor ingest driven by this surface.
pub(crate) const ANCHOR_OUTCOME_ACTOR: &str = "astrolabe-anchor-outcome";

/// Shared request path for the `anchor_outcome` MCP tool and its `astrolabe cli
/// anchor_outcome` subcommand.
///
/// Both surfaces funnel identical raw arguments through this one function, which
/// (1) enforces the shadow dial, (2) builds the validated outcome request via the
/// single `astrolabe_anchors::build_test_run_request` path, (3) resolves subject
/// ids to current constellation ids from the persisted vault node map, and (4)
/// ingests the anchors in one atomic Grounding-ledger group commit. Every stage
/// is fail-closed: an unknown outcome kind, malformed report/timestamp, a
/// source/confidence that violates the grounding invariants, or a conflicting
/// re-post each return a labeled `status: "refused"` envelope with its stable
/// `{code, message, remediation}` and no partial anchor is written. Because both
/// paths construct the request here from the same inputs, identical inputs
/// persist byte-identical anchor and ledger state by construction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn anchor_outcome_json_at(
    cache_dir: &Path,
    project: &str,
    kind: &str,
    source: &str,
    confidence: Option<f32>,
    format: &str,
    report_text: &str,
    observed_at: &str,
) -> Result<Value, DynError> {
    if kind != "test_run" {
        return Ok(anchor_outcome_refused(
            project,
            source,
            "ASTRO_ANCHOR_KIND_UNSUPPORTED",
            format!(
                "anchor_outcome outcome kind {kind:?} is not available on this surface; only \
                 test_run is wired with a built-in payload"
            ),
            "pass kind=\"test_run\" with a format + report, or file an issue to wire the \
             agent_task/review/incident/manual_label payloads",
        ));
    }

    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(anchor_outcome_refused(
            project,
            source,
            "ASTRO_ANCHOR_SHADOW_REQUIRED",
            format!("anchor_outcome requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before anchoring outcomes",
        ));
    }

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(anchor_outcome_refused(
            project,
            source,
            "ASTRO_ANCHOR_VAULT_MISSING",
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before anchoring outcomes",
        ));
    }

    // Single shared request-construction path: identical inputs => byte-identical
    // OutcomeAnchorRequest on both the MCP and CLI surfaces by construction.
    let request = match astrolabe_anchors::build_test_run_request(
        source,
        observed_at,
        confidence,
        format,
        report_text,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(anchor_outcome_refused(
                project,
                source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };

    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Ledger,
            ColumnFamily::Anchors,
            ColumnFamily::Graph,
        ],
    )?;
    // Subject -> CxId resolution against the persisted node map; unresolved
    // subjects are accounted (never a silent guess) by ingest_outcome_anchors.
    let cx_ids = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;
    let report = match astrolabe_anchors::ingest_outcome_anchors(
        &vault,
        &request,
        &cx_ids,
        ANCHOR_OUTCOME_ACTOR,
    ) {
        Ok(report) => report,
        Err(error) => {
            drop(vault);
            return Ok(anchor_outcome_refused(
                project,
                source,
                error.code,
                error.message,
                error.remediation,
            ));
        }
    };
    drop(vault);

    let status = if report.anchors_written > 0 {
        "grounded"
    } else {
        "noop"
    };
    let unmapped_count = report.unmapped_subjects.len();
    Ok(json!({
        "schema": ANCHOR_OUTCOME_SCHEMA,
        "project": project,
        "status": status,
        "outcome_kind": request.kind.as_str(),
        "source": request.source,
        "observed_at": request.observed_at,
        "confidence": request.confidence,
        "subjects_presented": request.subjects.len(),
        "anchors_written": report.anchors_written,
        "anchors_deduplicated": report.anchors_deduplicated,
        "rows_written": report.rows_written,
        "unmapped_subjects": report.unmapped_subjects,
        "unmapped_subject_count": unmapped_count,
        "anchor_dump_hash": report.anchor_dump_hash,
        "ledger_ref": ledger_ref_json(&report.ledger_ref),
        "fsv": report.fsv.as_ref().map(fsv_ack_envelope),
        "grounding_delta": {
            "anchors_written": report.anchors_written,
            "rows_written": report.rows_written,
            "ledger_seq": report.ledger_ref.seq,
        },
        // Source trust is a grounding property, distinct from the verified FSV
        // witness above. Proxy evidence can never ride as Trusted.
        "trust": report.trust.as_str(),
        "freshness": "fresh",
        "provenance": [
            format!("ledger:grounding:seq={}", report.ledger_ref.seq),
            format!("anchor_dump_hash:{}", report.anchor_dump_hash),
            format!("source:{}", request.source),
        ],
    }))
}

/// Builds a fail-closed refusal envelope with stable `{code, message,
/// remediation}` and HONEST labels.
fn anchor_outcome_refused(
    project: &str,
    source: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": ANCHOR_OUTCOME_SCHEMA,
        "project": project,
        "status": "refused",
        "source": source,
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "anchors_written": 0,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:pre-commit:no-anchor-written"],
    })
}

/// MCP/CLI dispatch entry point for `anchor_outcome` (routed identically from the
/// JSON-RPC surface and from `astrolabe cli anchor_outcome` via
/// `migration::handle_tool_raw`).
pub(crate) fn handle_anchor_outcome(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("anchor_outcome arguments must be a JSON object");
    };
    let Some(project) = string_arg(args_obj, "project") else {
        return tool_error_result("anchor_outcome requires project");
    };
    let kind = string_arg(args_obj, "kind").unwrap_or("test_run");
    let Some(source) = string_arg(args_obj, "source") else {
        return tool_error_result(
            "anchor_outcome requires a catalog source prefix (ci:/trace:/review:/git:revert:/git:fix:/agent:/survival:)",
        );
    };
    let Some(format) = string_arg(args_obj, "format") else {
        return tool_error_result(
            "anchor_outcome test_run requires format (junit_xml, cargo_test_json, pytest_verbose, go_test_json, or vitest_json)",
        );
    };
    let Some(report_text) = string_arg(args_obj, "report") else {
        return tool_error_result("anchor_outcome test_run requires a non-empty report");
    };
    let confidence = match args_obj.get("confidence") {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_f64() {
            Some(number) => Some(number as f32),
            None => return tool_error_result("anchor_outcome confidence must be a number"),
        },
    };
    let observed_at = match args_obj.get("observed_at") {
        None | Some(Value::Null) => now_epoch_seconds().to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(_) => {
            return tool_error_result(
                "anchor_outcome observed_at must be a non-negative integer epoch",
            );
        }
    };

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = anchor_outcome_json_at(
        &cache_dir,
        project,
        kind,
        source,
        confidence,
        format,
        report_text,
        &observed_at,
    )?;
    if value.get("status").and_then(Value::as_str) == Some("refused") {
        tool_json_error_result(value)
    } else {
        tool_json_result(value)
    }
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
