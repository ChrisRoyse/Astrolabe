use super::*;

/// Envelope schema for the `anchor_erase` MCP tool / `astrolabe cli
/// anchor_erase` subcommand.
pub(crate) const ANCHOR_ERASE_SCHEMA: &str = "astrolabe.anchor_erase.v1";
/// Ledger actor recorded for every anchor erasure driven by this surface.
pub(crate) const ANCHOR_ERASE_ACTOR: &str = "astrolabe-anchor-erase";

/// Shared request path for the `anchor_erase` MCP tool and its `astrolabe cli
/// anchor_erase` subcommand.
///
/// Erasure is destructive to the *serving* view — retracted anchors leave every
/// active query — so this surface is fail-closed at every stage: an unconfirmed
/// request, a non-shadow project, a missing vault, or an invalid source/timestamp
/// each return a labeled `status: "refused"` envelope with its stable
/// `{code, message, remediation}` and no tombstone is written. When the request is
/// admitted it funnels through the single `astrolabe_anchors::erase_anchors_by_source`
/// primitive, which appends an `AnchorTombstoneV1` (never rewriting the original
/// `Anchors` CF rows) paired with a Grounding ledger entry in one atomic group
/// commit, and returns a full-readback FSV witness whenever a tombstone was
/// committed. The response serves what was persisted: the retraction count, the
/// paired ledger ref, and the FSV ack.
///
/// Erasure retracts the anchors attributed to `source`; it deliberately does
/// **not** touch `AnchorPromotionV1` facts. Whether erasing a resolving source
/// should un-justify the promotions it granted is an open owner decision (#354);
/// until it is decided this surface takes the fail-safe path — it never silently
/// un-justifies a promotion — and labels the boundary in `promotion_semantics`.
pub(crate) fn anchor_erase_json_at(
    cache_dir: &Path,
    project: &str,
    source: &str,
    confirm: bool,
    observed_at: &str,
) -> Result<Value, DynError> {
    if !confirm {
        return Ok(anchor_erase_refused(
            project,
            source,
            "ASTRO_ANCHOR_ERASE_UNCONFIRMED",
            "anchor_erase is destructive to the serving view — erased anchors leave every active \
             query — and requires explicit confirmation",
            "re-issue the request with confirm=true once you intend to retract every anchor from \
             this source",
        ));
    }

    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(anchor_erase_refused(
            project,
            source,
            "ASTRO_ANCHOR_SHADOW_REQUIRED",
            format!("anchor_erase requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before erasing anchors",
        ));
    }

    // Parse + validate the retraction timestamp fail-closed on the same helper the
    // anchor_outcome surface uses (blank/non-numeric/negative/overflow/0 refuse).
    let retracted_at = match astrolabe_anchors::parse_observed_at(observed_at) {
        Ok(value) => value,
        Err(error) => {
            return Ok(anchor_erase_refused(
                project,
                source,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            ));
        }
    };

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(anchor_erase_refused(
            project,
            source,
            "ASTRO_ANCHOR_VAULT_MISSING",
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before erasing anchors",
        ));
    }

    let vault = open_shadow_vault_writable_latest_selected(
        &vault_dir,
        &vault_id,
        &vault_salt,
        // Tombstones land in Kv; the paired ledger entry in Ledger; Anchors is read
        // (never rewritten) to count the retracted rows.
        vec![
            ColumnFamily::Ledger,
            ColumnFamily::Anchors,
            ColumnFamily::Kv,
            ColumnFamily::TimeIndex,
        ],
    )?;
    let report = match astrolabe_anchors::erase_anchors_by_source(
        &vault,
        source,
        retracted_at,
        ANCHOR_ERASE_ACTOR,
    ) {
        Ok(report) => report,
        Err(error) => {
            drop(vault);
            return Ok(anchor_erase_refused(
                project,
                source,
                error.code,
                error.message,
                error.remediation,
            ));
        }
    };
    drop(vault);

    // "erased" when this call committed a fresh tombstone; "noop" when the source
    // was already retracted or held no anchors (idempotent, ledger-only replay).
    let status = if report.tombstone_written {
        "erased"
    } else {
        "noop"
    };
    Ok(json!({
        "schema": ANCHOR_ERASE_SCHEMA,
        "project": project,
        "status": status,
        "source": source,
        "retracted_at": retracted_at,
        "anchors_retracted": report.anchors_retracted,
        "tombstone_written": report.tombstone_written,
        "ledger_ref": ledger_ref_json(&report.ledger_ref),
        "fsv": report.fsv.as_ref().map(fsv_ack_envelope),
        // Erasure retracts the source's anchors from serving; it does not touch
        // append-only promotion facts (open owner decision #354). Labeled, never
        // silently un-justified.
        "promotion_semantics": "append_only_promotions_untouched",
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [
            format!("ledger:grounding:seq={}", report.ledger_ref.seq),
            format!("source:{source}"),
            format!("anchor_tombstone:{}", ANCHOR_ERASE_SCHEMA),
        ],
    }))
}

/// Builds a fail-closed refusal envelope with stable `{code, message,
/// remediation}` and HONEST labels. No tombstone is written on this path.
fn anchor_erase_refused(
    project: &str,
    source: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": ANCHOR_ERASE_SCHEMA,
        "project": project,
        "status": "refused",
        "source": source,
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "anchors_retracted": 0,
        "tombstone_written": false,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:pre-commit:no-tombstone-written"],
    })
}

/// MCP/CLI dispatch entry point for `anchor_erase` (routed identically from the
/// JSON-RPC surface and from `astrolabe cli anchor_erase` via
/// `migration::handle_tool_raw`).
pub(crate) fn handle_anchor_erase(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("anchor_erase arguments must be a JSON object");
    };
    let Some(project) = string_arg(args_obj, "project") else {
        return tool_error_result("anchor_erase requires project");
    };
    let Some(source) = string_arg(args_obj, "source") else {
        return tool_error_result(
            "anchor_erase requires the catalog source to retract (the value anchors were sourced \
             under, e.g. ci:github:owner/repo:run-42)",
        );
    };
    // Destructive operation: require explicit confirmation. Absent/false/non-bool
    // all refuse rather than proceed.
    let confirm = match args_obj.get("confirm") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return tool_error_result("anchor_erase confirm must be a boolean"),
    };
    let observed_at = match args_obj.get("observed_at") {
        None | Some(Value::Null) => now_epoch_seconds().to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(_) => {
            return tool_error_result(
                "anchor_erase observed_at must be a non-negative integer epoch",
            );
        }
    };

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = anchor_erase_json_at(&cache_dir, project, source, confirm, &observed_at)?;
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
