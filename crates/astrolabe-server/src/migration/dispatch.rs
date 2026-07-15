use super::*;

pub fn handle_tool_raw(
    runner: &CbmToolRunner,
    tool_name: &str,
    args_json: &str,
) -> Result<String, DynError> {
    match tool_name {
        "index_repository" => handle_index_repository(runner, args_json),
        "delete_project" => handle_delete_project(runner, args_json),
        "index_status" => handle_index_status(runner, args_json),
        "get_architecture" => handle_get_architecture(runner, args_json),
        "detect_anomalies" => handle_detect_anomalies(args_json),
        "get_provenance" => handle_get_provenance(args_json),
        "optimizer_status" => handle_optimizer_status(args_json),
        "get_readiness" => handle_get_readiness(args_json),
        "measure_bits" => handle_measure_bits(args_json),
        "impute_fields" => handle_impute_fields(args_json),
        "anchor_outcome" => handle_anchor_outcome(args_json),
        "anchor_erase" => handle_anchor_erase(args_json),
        "predict_impact" => handle_predict_impact(args_json),
        "abduce_cause" => handle_abduce_cause(args_json),
        "forecast" => handle_forecast(args_json),
        "coverage_ingest" => handle_coverage_ingest(args_json),
        "guard_calibrate" => handle_guard_calibrate(args_json),
        "guard_check" => handle_guard_check(args_json),
        "guard_commit_ood" => handle_guard_commit_ood(args_json),
        "guard_advisory_hook" => handle_guard_advisory_hook(args_json),
        "guard_lock" => handle_guard_lock(args_json),
        "assay_gate" => handle_assay_gate(args_json),
        "get_kernel" => handle_get_kernel(args_json),
        "kernel_answer" => handle_kernel_answer(args_json),
        "team_artifact" => handle_team_artifact(runner, args_json),
        "search_graph" => handle_search_graph(runner, args_json),
        "query_graph" => handle_query_graph(runner, args_json),
        "trace_path" | "trace_call_path" => handle_trace_path(runner, args_json),
        "find_similar" => handle_find_similar(args_json),
        "detect_changes" => handle_detect_changes_grounded_risk(runner, args_json),
        _ => Ok(runner.handle_tool_raw(tool_name, args_json)?),
    }
}

pub fn handle_jsonrpc_raw(
    runner: &CbmToolRunner,
    request_json: &str,
) -> Result<Option<String>, DynError> {
    let Ok(request) = serde_json::from_str::<Value>(request_json) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(request_obj) = request.as_object() else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(method) = request_obj.get("method").and_then(Value::as_str) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if method == "tools/list" {
        return handle_tools_list_jsonrpc(runner, request_json);
    }
    if method != "tools/call" {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let Some(id) = request_obj
        .get("id")
        .filter(|id| id.is_string() || id.is_number())
    else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(params) = request_obj.get("params").and_then(Value::as_object) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if !should_intercept_tool_call(tool_name) {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let Some(args_obj) = arguments.as_object() else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if !should_wrap_tool(tool_name, args_obj)? {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let args_json = serde_json::to_string(&arguments)?;
    let result_raw = handle_tool_raw(runner, tool_name, &args_json)?;
    Ok(Some(jsonrpc_result_response(id.clone(), &result_raw)?))
}

pub(crate) fn should_intercept_tool_call(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "index_repository"
            | "delete_project"
            | "index_status"
            | "get_architecture"
            | "detect_changes"
            | "query_graph"
            | "trace_path"
            | "trace_call_path"
    ) || is_advertised_astrolabe_tool(tool_name)
}

pub(crate) fn is_advertised_astrolabe_tool(tool_name: &str) -> bool {
    astrolabe_tool_definitions()
        .iter()
        .any(|definition| definition.get("name").and_then(Value::as_str) == Some(tool_name))
}

/// Print per-tool `--help` for an ASTROLABE-NATIVE tool (#428) — a tool served by
/// this Rust dispatch rather than the C schema registry (e.g. `get_provenance`,
/// `kernel_answer`, `anchor_erase`). Membership is the SAME native set the run
/// path dispatches from — presence in [`astrolabe_tool_definitions`], the exact
/// predicate [`is_advertised_astrolabe_tool`] tests — so `--help` and execution can
/// never disagree about whether a native tool exists.
///
/// The help text is derived entirely from the tool's `tool_defs` `inputSchema`
/// (the single source of truth also served over `tools/list`); no per-tool help is
/// hand-written. Its output shape mirrors the C formatter
/// `cbm_cli_print_tool_help_prog` byte-for-byte (`Usage:` lines with `prog`, then
/// `Arguments (JSON object keys):` and one `  name <type>[ [required]][  desc]`
/// line per property) so both halves of the CLI surface print identically.
///
/// Returns `Ok(true)` when `tool_name` is a native tool (help printed), `Ok(false)`
/// when it is not in the native registry (nothing printed) so the caller can fail
/// closed with `ASTRO_CLI_UNKNOWN_TOOL`. Fails closed with a labeled error naming
/// the tool and the registry gap when a name that IS in the native registry somehow
/// carries no `inputSchema` object — a `tool_defs` defect that must never ship, and
/// is never papered over with empty help.
pub(crate) fn print_astrolabe_native_tool_help(
    prog: &str,
    tool_name: &str,
) -> Result<bool, DynError> {
    let Some(definition) = astrolabe_tool_definitions()
        .into_iter()
        .find(|definition| definition.get("name").and_then(Value::as_str) == Some(tool_name))
    else {
        return Ok(false);
    };

    let schema = definition
        .get("inputSchema")
        .and_then(Value::as_object)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_CLI_NATIVE_TOOL_SCHEMA_MISSING: astrolabe-native tool '{tool_name}' is \
                 registered for dispatch but its tool_defs definition carries no inputSchema \
                 object, so its --help cannot be derived; remediation: add an inputSchema \
                 (type/properties/required) to the '{tool_name}' definition in \
                 crates/astrolabe-server/src/migration/tool_defs.rs"
            )
            .into()
        })?;

    // Only the two supported input forms are advertised, exactly as the C formatter
    // does (one contract with the Rust host, #378/#411): --args-file <path> and
    // piped stdin. The removed raw-JSON argv and `--flag value` forms are NOT shown.
    println!("Usage:");
    println!("  {prog} cli {tool_name} --args-file <path-to-json>");
    println!("  echo '<json>' | {prog} cli {tool_name}");
    println!();
    println!("Arguments (JSON object keys):");

    let required: std::collections::BTreeSet<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, spec) in properties {
            // Mirror the C formatter's defaults: absent `type` prints as <string>,
            // absent `description` prints nothing after the type.
            let type_str = spec.get("type").and_then(Value::as_str).unwrap_or("string");
            let desc = spec
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            let req = if required.contains(name.as_str()) {
                " [required]"
            } else {
                ""
            };
            if desc.is_empty() {
                println!("  {name} <{type_str}>{req}");
            } else {
                println!("  {name} <{type_str}>{req}  {desc}");
            }
        }
    }

    Ok(true)
}

pub(crate) fn handle_tools_list_jsonrpc(
    runner: &CbmToolRunner,
    request_json: &str,
) -> Result<Option<String>, DynError> {
    let Some(response) = runner.handle_jsonrpc_raw(request_json)? else {
        return Ok(None);
    };
    Ok(Some(augment_tools_list_response(&response)?))
}

pub(crate) fn augment_tools_list_response(response_json: &str) -> Result<String, DynError> {
    let mut response: Value = serde_json::from_str(response_json)?;
    let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) else {
        return Ok(response_json.to_string());
    };
    let is_final_page = !result.contains_key("nextCursor");
    let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) else {
        return Ok(response_json.to_string());
    };
    // Astrolabe's own tools are appended only on the final page so a client
    // walking cursors sees each tool exactly once.
    if is_final_page {
        for definition in astrolabe_tool_definitions() {
            let Some(name) = definition.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !tools
                .iter()
                .any(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
            {
                tools.push(definition);
            }
        }
    }
    // #328: overlay the Astrolabe-side extensions onto the CBM `search_graph`
    // schema so MCP clients can discover propagated_label + fusion from tools/list.
    // The overlay must apply on WHATEVER page `search_graph` appears: CBM
    // paginates tools/list and serves `search_graph` on a non-final page, so
    // gating the whole augmentation on the final page served the bare legacy
    // schema (found by the #328 live-binary readback FSV).
    for tool in tools.iter_mut() {
        match tool.get("name").and_then(Value::as_str) {
            Some("search_graph") => overlay_search_graph_extensions(tool),
            // #43: advertise the opt-in `scored` best-first knob on the CBM
            // trace_path schema so clients can discover it, same overlay pattern.
            Some("trace_path") | Some("trace_call_path") => overlay_trace_path_extensions(tool),
            // #43: advertise the opt-in `as_of` time-travel knob on the CBM
            // query_graph schema so clients can discover it, same overlay pattern.
            Some("query_graph") => overlay_query_graph_extensions(tool),
            _ => {}
        }
    }
    Ok(serde_json::to_string(&response)?)
}

/// #328: merge the Astrolabe `search_graph` extension properties into the CBM
/// tool's `inputSchema.properties`, leaving any CBM-native property untouched.
pub(crate) fn overlay_search_graph_extensions(tool: &mut Value) {
    let Some(schema) = tool.get_mut("inputSchema").and_then(Value::as_object_mut) else {
        return;
    };
    let properties = schema
        .entry("properties")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(properties) = properties.as_object_mut() else {
        return;
    };
    for (name, spec) in search_graph_astrolabe_property_overlay() {
        properties.entry(name).or_insert(spec);
    }
}

/// #43: merge the Astrolabe `scored` extension property into the CBM `trace_path`
/// tool's `inputSchema.properties`, leaving CBM-native properties untouched.
pub(crate) fn overlay_trace_path_extensions(tool: &mut Value) {
    let Some(schema) = tool.get_mut("inputSchema").and_then(Value::as_object_mut) else {
        return;
    };
    let properties = schema
        .entry("properties")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(properties) = properties.as_object_mut() else {
        return;
    };
    for (name, spec) in trace_path_astrolabe_property_overlay() {
        properties.entry(name).or_insert(spec);
    }
}

/// #43: merge the Astrolabe `as_of` extension property into the CBM `query_graph`
/// tool's `inputSchema.properties`, leaving CBM-native properties untouched.
pub(crate) fn overlay_query_graph_extensions(tool: &mut Value) {
    let Some(schema) = tool.get_mut("inputSchema").and_then(Value::as_object_mut) else {
        return;
    };
    let properties = schema
        .entry("properties")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(properties) = properties.as_object_mut() else {
        return;
    };
    for (name, spec) in query_graph_astrolabe_property_overlay() {
        properties.entry(name).or_insert(spec);
    }
}

pub(crate) fn should_wrap_tool(
    tool_name: &str,
    args: &Map<String, Value>,
) -> Result<bool, DynError> {
    match tool_name {
        // Always wrap delete_project: the Astrolabe host-side sidecar family
        // (lowered mirror, vault, locks, search index, per-project config rows)
        // can outlive a dial-off project, so cleanup must run regardless of the
        // current dial — never gate it on read_dial (#417).
        "delete_project" => Ok(true),
        "index_repository" => {
            if args.contains_key("calyx")
                || args.contains_key("calyx_search")
                || args.contains_key("calyx_skills")
            {
                return Ok(true);
            }
            let Some(project) = index_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        "index_status" => {
            let Some(project) = status_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        "get_architecture" => {
            let Some(project) = status_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        "detect_changes" => {
            // Only augment grounded risk when the project is shadow-indexed; a
            // non-shadow project has no vault, so it passes straight through with
            // the pure legacy detect_changes shape.
            let Some(project) = status_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        "trace_path" | "trace_call_path" => {
            // The scored best-first re-rank is the ONLY divergence from CBM's plain
            // BFS. Without `scored:true` we never intercept, so the legacy traversal
            // is served byte-for-byte by libcbm (the #43 plain-BFS byte-parity floor).
            Ok(trace_path_scored_requested(args))
        }
        "query_graph" => {
            // The `as_of` time-travel is the ONLY divergence from CBM's live Cypher.
            // Without `as_of` we never intercept, so the query is served byte-for-byte
            // by libcbm against the live store (#43 live-query byte-parity floor).
            Ok(query_graph_as_of_requested(args))
        }
        name if is_advertised_astrolabe_tool(name) => Ok(true),
        _ => Ok(false),
    }
}

pub(crate) fn handle_index_repository(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("index_repository", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("index_repository", args_json)?);
    };

    let search_scale_override = match parse_search_scale_override(args_obj) {
        Ok(value) => value,
        Err(message) => return tool_error_result(message),
    };
    let skill_discovery_override = match parse_skill_discovery_override(args_obj) {
        Ok(value) => value,
        Err(message) => return tool_error_result(message),
    };
    let project = index_project_from_args(args_obj)?;
    let explicit_dial = args_obj.get("calyx");
    let dial = match explicit_dial {
        Some(value) => match MigrationDial::parse(value) {
            Ok(dial) => dial,
            Err(message) => return tool_error_result(message),
        },
        None => project
            .as_ref()
            .map(|project| read_dial(project))
            .transpose()?
            .unwrap_or(MigrationDial::Off),
    };

    if explicit_dial.is_none() && dial == MigrationDial::Off {
        if search_scale_override.is_some() {
            return tool_error_result(
                "calyx_search requires calyx=\"shadow\" or a persisted shadow dial for this project",
            );
        }
        if skill_discovery_override.is_some() {
            return tool_error_result(
                "calyx_skills requires calyx=\"shadow\" or a persisted shadow dial for this project",
            );
        }
        return Ok(runner.handle_tool_raw("index_repository", args_json)?);
    }

    let sanitized_args = strip_calyx_arg(args_obj)?;
    let repo_path = string_arg(args_obj, "repo_path")
        .or_else(|| string_arg(args_obj, "name"))
        .map(PathBuf::from);
    let skills = skill_discovery_config(skill_discovery_override.as_ref());
    // #412: Windows path-budget preflight, narrowed to the SQLite VFS ceiling.
    // Extended-length (`\\?\`) support now covers the whole store family (C
    // pipeline writer, both SQLite VFSes, Calyx vault via Rust std), so a deep-
    // but-valid store (the #409 failing config: deep store + 128-byte bounded
    // name) is SERVED, not refused. The only residual hard ceiling is the bundled
    // SQLite amalgamations' SQLITE_WIN32_MAX_PATH_BYTES (1040) UTF-8 path cap, so
    // the preflight refuses only when the longest store-family SQLite path (the
    // as_of bucket, nesting the derived name twice) would exceed that — a
    // structural OS/SQLite limit, not a tunable.
    if let Some(repo) = repo_path.as_deref() {
        let budget_project = match project.as_deref() {
            Some(project) => Some(project.to_string()),
            None => repo
                .to_str()
                .and_then(|path| astrolabe_bridge::cbm_project_name_from_path(path).ok()),
        };
        if let Some(budget_project) = budget_project {
            let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
            if let Some(refusal) = store_path_budget_refusal(&cache_dir, &budget_project) {
                return tool_error_result(refusal);
            }
        }
    }
    // #405: run the CBM index pass OUT OF PROCESS (supervised worker, no FFI row
    // sink — a callback cannot cross the process boundary), so a hard pass abort
    // (segfault/abort-class) is contained in the child and can NEVER leave a
    // partially-written vault. On a clean exit the row-sink-equivalent import
    // candidate is rebuilt from the child's persisted `<project>.db` (the SQLite
    // `nodes`/`edges` tables and the old row-sink stream are two serializations of
    // the identical in-memory dump arrays, so the derived surfaces are byte-
    // identical). Vault writes begin only after this fully-clean pass.
    let (result, project, row_sink) =
        match run_shadow_index_pass(runner, &sanitized_args, project.as_deref(), &skills)? {
            ShadowIndexPassOutcome::Completed {
                raw_result,
                project,
                candidate,
            } => (raw_result, project, candidate),
            ShadowIndexPassOutcome::Failed { error_result } => {
                // Fail closed. The pass ran out of process and returned no graph, so
                // the vault was never touched (no partial manifests/surfaces). A
                // contained hard abort surfaces as ASTRO_SHADOW_INDEX_PASS_CRASHED
                // with the worker exit code / log tail; a graceful libcbm error is
                // returned verbatim, exactly as before.
                return shadow_index_pass_error_result(&error_result);
            }
        };
    persist_dial(&project, dial)?;
    if dial == MigrationDial::Off {
        return Ok(result);
    }
    let search_scale_settings =
        match search_scale_settings_for_import(&project, search_scale_override) {
            Ok(settings) => settings,
            Err(error) => return tool_error_result(format!("search scale config failed: {error}")),
        };

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let Some(_shadow_import_lock) = try_shadow_import_lock(&cache_dir, &project)? else {
        return augment_tool_result(&result, shadow_import_busy_summary_at(&cache_dir, &project));
    };
    let outcome = match import_shadow_vault_with_archaeology(
        &project,
        Some(row_sink),
        &search_scale_settings,
        repo_path.as_deref(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return tool_error_result(format!("shadow import failed: {error}")),
    };
    persist_shadow_outcome(&project, &outcome)?;
    // #244: record the exact CBM index args so a later runner-driven refresh can
    // replay the pipeline and reconcile genuine staleness with real surfaces.
    persist_shadow_index_args(&cache_dir, &project, &sanitized_args)?;
    augment_tool_result(
        &result,
        json!({
            "calyx": "shadow",
            "vault_fingerprint": outcome.sqlite_fingerprint_sha256,
            "grounding_summary": grounding_summary(&outcome),
        }),
    )
}

pub(crate) fn handle_index_status(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    }

    let result = runner.handle_tool_raw("index_status", args_json)?;
    if tool_result_is_error(&result)? {
        return Ok(result);
    }
    // #244: reconcile with the runner so genuine staleness is *repaired* (real
    // row-sink-derived surfaces regenerated from current source) rather than merely
    // refused. The #222 guard remains the fail-closed floor inside this call when
    // reconciliation cannot run.
    let refresh_status = match reconcile_shadow_import_current(runner, &project) {
        Ok(status) => status,
        Err(error) => {
            return tool_error_result(format!("shadow import recovery failed: {error}"));
        }
    };
    let mut summary = shadow_status_summary(&project)?;
    if refresh_status == ShadowRefreshStatus::Busy
        && let Some(summary_obj) = summary.as_object_mut()
    {
        let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
        merge_object(
            summary_obj,
            shadow_import_busy_summary_at(&cache_dir, &project)
                .as_object()
                .expect("busy summary object"),
        );
    }
    augment_tool_result(&result, summary)
}

pub(crate) fn handle_get_architecture(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let result = runner.handle_tool_raw("get_architecture", args_json)?;
    if tool_result_is_error(&result)? {
        return Ok(result);
    }
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(result);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(result);
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return Ok(result);
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return Ok(result);
    }
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    augment_tool_result(
        &result,
        json!({
            "astrolabe": {
                "skill_tree": read_skill_tree_metadata(&cache_dir, &project)?,
                "bridges": read_bridges_metadata(&cache_dir, &project)?,
                "kernel_context": read_kernel_context_metadata(&cache_dir, &project)?,
                "anomalies": read_anomaly_report(&cache_dir, &project)?,
                "provenance": read_provenance_metadata(&cache_dir, &project)?,
                "agreement_graph": read_agreement_graph_aspect(&cache_dir, &project)?,
                "redundancy": read_redundancy_neff_aspect(&cache_dir, &project),
                "layout_map": read_layout_map_aspect(&cache_dir, &project)?,
                // #43: the two aspects that were genuinely missing on main
                // (kernel_context/agreement_graph/n_eff already serve above).
                "grounding_gaps": read_grounding_gaps_aspect(&cache_dir, &project)?,
                "signal_ranking": read_signal_ranking_aspect(&cache_dir, &project)?,
            },
        }),
    )
}

/// The Astrolabe-only `search_graph` knobs that must never reach the CBM tool
/// (which rejects unknown args): the #42 fusion engine controls and the #69
/// propagated_label filter. Advertised in tools/list via
/// [`search_graph_astrolabe_property_overlay`].
const SEARCH_GRAPH_ASTROLABE_ONLY_KEYS: [&str; 4] = [
    "fusion",
    "fusion_override",
    "temporal_alpha_millis",
    "propagated_label",
];

/// `search_graph` with Astrolabe extensions (#42 fusion, #69 propagated_label).
///
/// Default (no Astrolabe knob) is a byte-identical passthrough to the CBM tool.
/// `fusion: true` (#42) serves the Sextant-fused engine instead of legacy BM25.
/// `propagated_label` (#69) intersects the raw CBM hits against the project's
/// persisted propagated labels so an inferred label such as `security-sensitive`
/// is usable as an exact search filter. Every Astrolabe-only knob is stripped
/// before the CBM tool sees it. Fails closed (coded) when a filter/fusion request
/// cannot be served (missing project, not shadow-indexed, propagation/vault
/// unavailable).
pub(crate) fn handle_search_graph(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("search_graph", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("search_graph", args_json)?);
    };

    // #42: opt-in fused engine. Only an explicit `fusion: true` diverts from the
    // legacy path; anything else keeps the byte-identical CBM passthrough.
    if args_obj.get("fusion").and_then(Value::as_bool) == Some(true) {
        return run_fused_search_graph(args_obj);
    }

    let label_filter = string_arg(args_obj, "propagated_label").map(ToOwned::to_owned);
    let carries_astrolabe_knob = SEARCH_GRAPH_ASTROLABE_ONLY_KEYS
        .iter()
        .any(|key| args_obj.contains_key(*key));
    if !carries_astrolabe_knob {
        // Pure legacy request — pass the original bytes through unchanged.
        return Ok(runner.handle_tool_raw("search_graph", args_json)?);
    }

    // Strip every Astrolabe-only knob before the CBM tool, which rejects unknown args.
    let mut sanitized = args_obj.clone();
    for key in SEARCH_GRAPH_ASTROLABE_ONLY_KEYS {
        sanitized.remove(key);
    }
    let sanitized_json = serde_json::to_string(&Value::Object(sanitized.clone()))?;

    let raw = runner.handle_tool_raw("search_graph", &sanitized_json)?;
    if tool_result_is_error(&raw)? {
        return Ok(raw);
    }

    // With only fusion-family knobs present (e.g. an inert `fusion: false`), the
    // sanitized legacy result is the answer; the label filter is optional.
    let Some(label_filter) = label_filter.filter(|label| !label.is_empty()) else {
        return Ok(raw);
    };

    let Some(project) = status_project_from_args(&sanitized)? else {
        return tool_error_result(
            "ASTRO_SEARCH_GRAPH_PROPAGATED_LABEL_PROJECT: propagated_label filter requires project; remediation: pass the project whose propagated labels should filter the search",
        );
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "ASTRO_SEARCH_GRAPH_PROPAGATED_LABEL_SHADOW: propagated_label filter requires calyx shadow indexing; rerun index_repository with calyx=\"shadow\"",
        );
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let kernel_context = read_kernel_context_metadata(&cache_dir, &project)?;
    let labeled_symbols = match propagated_label_symbol_ids(&kernel_context, &label_filter) {
        Ok(ids) => ids,
        Err(message) => return tool_error_result(message),
    };
    filter_search_graph_result_by_label(&raw, &label_filter, &labeled_symbols)
}

pub(crate) fn handle_detect_anomalies(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("detect_anomalies arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("detect_anomalies requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "detect_anomalies requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let kind_filter = string_arg(args_obj, "kind");
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let report = read_anomaly_report(&cache_dir, &project)?;
    let security = read_security_screen_metadata(&cache_dir, &project)?;
    let report = merge_prompt_injection_anomalies(report, security, &project);
    let filtered = match filter_anomaly_report_json(report, kind_filter) {
        Ok(filtered) => filtered,
        Err(error) => return tool_error_result(error.to_string()),
    };
    tool_json_result(filtered)
}

pub(crate) fn handle_get_provenance(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("get_provenance arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("get_provenance requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "get_provenance requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let Some(mode) = string_arg(args_obj, "mode") else {
        return tool_error_result(
            "get_provenance requires mode: lineage, answer_trace, verify_chain, reproduce, or inter_agent_trust",
        );
    };
    let subject_id = string_arg(args_obj, "subject_id").or_else(|| string_arg(args_obj, "subject"));
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let mut store = match provenance_store_for_project(&cache_dir, &project) {
        Ok(store) => store,
        Err(error) => return tool_error_result(error.to_string()),
    };
    // #67 (blueprint 9.5): inter-agent trust is the one-call verification a second
    // agent runs against a context pack claimed by a first agent. The claimed
    // manifest is verified against this serving vault's persisted manifest; a
    // tampered claim fails closed with a coded error naming the failing check.
    if mode == "inter_agent_trust" {
        return handle_inter_agent_trust(&project, &store, args_obj);
    }
    // #284: `mode="lineage"` for a ledger subject key is served from the real
    // persisted ledger, not row-sink symbol metadata. The scan verifies the whole
    // hash-chain first and fails closed on a broken chain or undecodable row, so
    // its coded refusal is surfaced here rather than degrading into a row-sink
    // answer.
    if let Err(error) =
        apply_ledger_backed_lineage(&mut store, &cache_dir, &project, mode, subject_id)
    {
        return tool_error_result(error.to_string());
    }
    // #67 DoD 1: reproduce is live re-execution of the #40 kernel answer engine
    // against the persisted current vault graph — an unchanged vault reproduces
    // bit-exact, a perturbed vault fails closed with REPRODUCE_DRIFT_EXCEEDED
    // naming the drift magnitude. `drift_bound_microunits` may only tighten the
    // pinned 1e-3 bound. When no reproduce fixture is persisted yet (pre-#343),
    // this is a no-op and reproduce serves the recorded digest/drift path.
    let drift_bound_override = args_obj
        .get("drift_bound_microunits")
        .and_then(Value::as_u64);
    if let Err(error) = apply_live_reproduce(
        &mut store,
        &cache_dir,
        &project,
        mode,
        subject_id,
        drift_bound_override,
    ) {
        return tool_error_result(error.to_string());
    }
    let response = match get_provenance(&store, &ProvenanceQuery::new(mode, subject_id)) {
        Ok(response) => response,
        Err(error) => {
            return tool_error_result(format!(
                "{}: {}; remediation: {}",
                error.code(),
                error.message(),
                error.remediation()
            ));
        }
    };
    tool_json_result(provenance_response_json(&project, &response))
}

/// Serves `get_provenance(mode="inter_agent_trust")`: the one-call verification a
/// second agent runs against a context pack claimed by a first agent (blueprint
/// 9.5, #67).
///
/// The claimed manifest is supplied either as a `manifest` object
/// (`pack_id`/`ledger_ref`/`vault_fingerprint`/`member_hash`) or as an
/// `attestation` string — the self-describing artifact the serving agent handed
/// over, which is parsed and self-checked before it is trusted as a claim. The
/// claim is verified against this serving vault's persisted manifest via
/// [`verify_pack_manifest_claim`]; all four fields must match. A tampered claim
/// fails closed with the coded `{code, message, remediation}` error naming the
/// failing check rather than returning a verified-looking envelope, and a
/// self-inconsistent attestation fails closed as attestation-corrupt.
pub(crate) fn handle_inter_agent_trust(
    project: &str,
    store: &ProvenanceStore,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let claimed = match args_obj.get("manifest") {
        Some(manifest_value) => match pack_manifest_from_json(manifest_value) {
            Ok(manifest) => manifest,
            Err(error) => {
                return tool_error_result(format!(
                    "get_provenance mode=\"inter_agent_trust\" manifest is malformed: {error}; remediation: pass a manifest object with pack_id, ledger_ref{{seq,chain_hash}}, vault_fingerprint, and member_hash, or an attestation artifact string"
                ));
            }
        },
        None => match string_arg(args_obj, "attestation") {
            Some(attestation) => match parse_pack_manifest_attestation(attestation.as_bytes()) {
                Ok(manifest) => manifest,
                Err(error) => {
                    return tool_error_result(format!(
                        "{}: {}; remediation: {}",
                        error.code(),
                        error.message(),
                        error.remediation()
                    ));
                }
            },
            None => {
                return tool_error_result(
                    "get_provenance mode=\"inter_agent_trust\" requires the claimed context pack: pass a manifest object or an attestation artifact string",
                );
            }
        },
    };
    match verify_pack_manifest_claim(store, &claimed) {
        Ok(report) => tool_json_result(inter_agent_trust_report_json(project, &report)),
        Err(error) => tool_error_result(format!(
            "{}: {}; remediation: {}",
            error.code(),
            error.message(),
            error.remediation()
        )),
    }
}

pub(crate) fn handle_optimizer_status(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("optimizer_status arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("optimizer_status requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "optimizer_status requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let mode = string_arg(args_obj, "mode").unwrap_or("status");
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match mode {
        "status" => {
            let anneal_env = std::env::var("ASTRO_ANNEAL").ok();
            tool_json_result(optimizer_status_json_at(
                &cache_dir,
                &project,
                anneal_env.as_deref(),
            )?)
        }
        "ack_triggers" => {
            let Some(raw_subscription_id) = string_arg(args_obj, "subscription_id") else {
                return tool_error_result(
                    "ASTRO_OPTIMIZER_ACK_SUBSCRIPTION_REQUIRED: optimizer_status mode=\"ack_triggers\" requires subscription_id; remediation: read optimizer_status.reactive_triggers.subscriptions and retry with one returned subscription_id",
                );
            };
            let subscription_id = match SubscriptionId::from_str(raw_subscription_id) {
                Ok(subscription_id) => subscription_id,
                Err(error) => {
                    return tool_error_result(format!(
                        "ASTRO_OPTIMIZER_ACK_SUBSCRIPTION_INVALID: invalid subscription_id {raw_subscription_id:?}: {error}; remediation: use a subscription_id returned by optimizer_status.reactive_triggers.subscriptions"
                    ));
                }
            };
            let value = optimizer_ack_triggers_json_at(&cache_dir, &project, subscription_id)?;
            if value.get("status").and_then(Value::as_str) == Some("refused") {
                tool_json_error_result(value)
            } else {
                tool_json_result(value)
            }
        }
        "propose" => {
            let anneal_env = std::env::var("ASTRO_ANNEAL").ok();
            let value = optimizer_propose_json_at(&cache_dir, &project, anneal_env.as_deref())?;
            if value.get("status").and_then(Value::as_str) == Some("refused") {
                tool_json_error_result(value)
            } else {
                tool_json_result(value)
            }
        }
        other => tool_error_result(format!(
            "ASTRO_OPTIMIZER_MODE_UNSUPPORTED: optimizer_status mode {other:?} is not available; remediation: use mode=\"status\", mode=\"ack_triggers\", or mode=\"propose\""
        )),
    }
}

pub(crate) fn handle_get_readiness(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("get_readiness arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("get_readiness requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "get_readiness requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let scope = string_arg(args_obj, "scope");
    let axis = string_arg(args_obj, "axis");
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    tool_json_result(readiness_status_json_at(&cache_dir, &project, scope, axis)?)
}

pub(crate) fn handle_measure_bits(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("measure_bits arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("measure_bits requires project");
    };
    let Some(mode) = string_arg(args_obj, "mode") else {
        return tool_error_result(
            "ASTRO_ASSAY_MEASURE_BITS_MODE_REQUIRED: measure_bits requires mode; remediation: pass one of signals, sufficiency, redundancy, synergy, causality, calibration",
        );
    };
    if !MEASURE_BITS_MODES.contains(&mode) {
        return tool_error_result(format!(
            "ASTRO_ASSAY_MEASURE_BITS_MODE_UNSUPPORTED: measure_bits mode {mode:?} is not available; remediation: use one of signals, sufficiency, redundancy, synergy, causality, calibration"
        ));
    }
    // An axis argument that is present but not a non-empty string is refused: the
    // caller asked for a specific axis and we will not silently ignore a malformed
    // one. Absence of the key is the legitimate panel-wide default.
    if measure_bits_axis_arg_invalid(args_obj) {
        return tool_error_result(
            "ASTRO_ASSAY_MEASURE_BITS_AXIS_INVALID: measure_bits axis must be a non-empty string when provided; remediation: pass a named outcome axis or omit axis for a panel-wide mode",
        );
    }
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "measure_bits requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let axis = string_arg(args_obj, "axis");
    let scope = string_arg(args_obj, "scope");
    let refresh = args_obj
        .get("refresh")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = measure_bits_json_at(&cache_dir, &project, mode, axis, scope, refresh)?;
    if value.get("status").and_then(Value::as_str) == Some("refused") {
        tool_json_error_result(value)
    } else {
        tool_json_result(value)
    }
}

pub(crate) fn handle_impute_fields(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("impute_fields arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("impute_fields requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "impute_fields requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let Some(target) = string_arg(args_obj, "target") else {
        return tool_error_result("impute_fields requires target");
    };
    let Some(field) = string_arg(args_obj, "field") else {
        return tool_error_result("impute_fields requires field");
    };
    if !matches!(field, "doc" | "types" | "callees" | "tests") {
        return tool_error_result(
            "impute_fields field must be one of doc, types, callees, or tests",
        );
    }
    let write_as_trusted = args_obj
        .get("write_as_trusted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = impute_fields_json_at(&cache_dir, &project, target, field, write_as_trusted)?;
    if value.get("status").and_then(Value::as_str) == Some("refused") {
        tool_json_error_result(value)
    } else {
        tool_json_result(value)
    }
}

/// #412: Windows total-path budget preflight for the per-project store family,
/// narrowed to the one residual structural ceiling that survives extended-length
/// (`\\?\`) support.
///
/// After #412, every store-family open is extended-length-safe: the Calyx vault
/// opens and all `std::fs` operations go through Rust std (verbatim-prefixed at
/// the 32767 ceiling), the C pipeline writer widens via `cbm_fopen`, and both the
/// cbm and rusqlite SQLite VFSes prefix `\\?\` for paths over `MAX_PATH`. The only
/// remaining hard ceiling is that the two bundled SQLite amalgamations cap a
/// UTF-8 database path at `SQLITE_WIN32_MAX_PATH_BYTES` (`MAX_PATH*4 = 1040`)
/// bytes before that wide conversion; a longer path is refused by SQLite itself.
/// So the preflight now guards only that SQLite ceiling — deep-but-valid stores
/// (the #409/#412 failing configuration) pass and are served.
///
/// [`SQLITE_VFS_PATH_BUDGET`] is a conservative margin under 1040. The longest
/// store-family SQLite path is the as_of bucket
/// `<store>\.astrolabe-asof\<name>\bucket-<digits>\<name>.db`, which nests the
/// (128-byte-capped) project name TWICE; [`AS_OF_STORE_FAMILY_RESERVE`] is that
/// chain's separator + suffix bytes. Both are structural filename constants, not
/// tunables.
const SQLITE_VFS_PATH_BUDGET: usize = 1024;
/// Separator + fixed-suffix bytes of the longest store-family SQLite path, the
/// as_of bucket chain: `\.astrolabe-asof\` (17) + `\bucket-<=20 digits>\` (29) +
/// `.db` (3) = 49, rounded up for margin. The variable `<name>` appears twice and
/// is added by [`store_path_budget_refusal`].
const AS_OF_STORE_FAMILY_RESERVE: usize = 52;

/// Returns a fail-closed refusal message when the longest store-family SQLite path
/// for this project cannot fit the SQLite Windows VFS byte budget even with
/// extended-length (`\\?\`) opens — naming the offending components and the
/// arithmetic — or `None` when the family fits. See [`SQLITE_VFS_PATH_BUDGET`].
fn store_path_budget_refusal(cache_dir: &Path, project: &str) -> Option<String> {
    let store_len = cache_dir.as_os_str().to_string_lossy().len();
    // The as_of bucket nests <project> twice; guard that worst case up front so a
    // later time-travel query cannot exceed the SQLite VFS ceiling either.
    let needed = store_len + 2 * project.len() + AS_OF_STORE_FAMILY_RESERVE;
    if needed <= SQLITE_VFS_PATH_BUDGET {
        return None;
    }
    Some(format!(
        "ASTRO_STORE_PATH_BUDGET_EXCEEDED: the store path family for this project cannot fit the \
         SQLite Windows VFS path budget even with extended-length (\\\\?\\) opens: store dir \
         {cache_dir:?} ({store_len} bytes) + the as_of bucket chain nesting the derived project \
         name {project:?} ({} bytes) twice + {AS_OF_STORE_FAMILY_RESERVE} suffix bytes = {needed} \
         bytes > {SQLITE_VFS_PATH_BUDGET} (SQLITE_WIN32_MAX_PATH_BYTES); remediation: point \
         CBM_CACHE_DIR at a shorter absolute path (the derived project name is already capped at \
         128 bytes)",
        project.len()
    ))
}
