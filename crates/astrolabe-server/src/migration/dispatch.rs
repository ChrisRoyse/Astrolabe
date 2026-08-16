use super::*;

pub fn handle_tool_raw(
    runner: &CbmToolRunner,
    tool_name: &str,
    args_json: &str,
) -> Result<String, DynError> {
    let _activation_fence = crate::activation_epoch::admit_tool_call(tool_name, args_json)?;
    handle_tool_raw_admitted(runner, tool_name, args_json)
}

fn handle_tool_raw_admitted(
    runner: &CbmToolRunner,
    tool_name: &str,
    args_json: &str,
) -> Result<String, DynError> {
    if let Some(definition) = astrolabe_native_tool_definition(tool_name)
        && let Err(error) = validate_native_tool_arguments(tool_name, definition, args_json)
    {
        if let Some(result) = tool_fault_result_from_error(error.as_ref()) {
            tracing::warn!(
                tool = tool_name,
                code = ToolFault::from_error(error.as_ref()).map(|fault| fault.code().to_string()),
                "mcp.native_tool.argument_refused"
            );
            return result;
        }
        return Err(error);
    }
    match tool_name {
        "list_projects" => handle_list_projects(runner, args_json),
        "index_repository" => handle_index_repository(runner, args_json),
        "delete_project" => handle_delete_project(runner, args_json),
        "index_status" => handle_index_status(runner, args_json),
        "get_architecture" => handle_get_architecture(runner, args_json),
        "detect_anomalies" => handle_detect_anomalies(args_json),
        "get_provenance" => handle_get_provenance(args_json),
        "optimizer_status" => handle_optimizer_status(args_json),
        "get_readiness" => handle_get_readiness(args_json),
        "measure_bits" => handle_measure_bits(args_json),
        "causal_analysis" => handle_causal_analysis(args_json),
        "expected_gain" => handle_expected_gain(args_json),
        "impute_fields" => handle_impute_fields(args_json),
        "anchor_outcome" => handle_anchor_outcome(args_json),
        "anchor_erase" => handle_anchor_erase(args_json),
        "predict_impact" => handle_predict_impact(args_json),
        "abduce_cause" => handle_abduce_cause(args_json),
        "discover_latent_links" => handle_discover_latent_links(args_json),
        "discover_associations" => handle_discover_associations(args_json),
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
    if let Err(fault) = validate_mcp_request_metadata(method, request_obj) {
        tracing::warn!(method, code = fault.code(), "mcp.request_metadata_invalid");
        return request_invalid_params_response(request_obj, fault);
    }
    if method == "tools/list" {
        return handle_tools_list_jsonrpc(runner, request_json);
    }
    if method != "tools/call" {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let Some(params) = request_obj.get("params").and_then(Value::as_object) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let args_json = serde_json::to_string(&arguments)?;
    let _activation_fence = crate::activation_epoch::admit_tool_call(tool_name, &args_json)?;
    let Some(id) = request_obj
        .get("id")
        .filter(|id| id.is_string() || id.is_number())
    else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if !should_intercept_tool_call(tool_name) {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }
    if is_advertised_astrolabe_tool(tool_name) {
        let result_raw = handle_tool_raw_admitted(runner, tool_name, &args_json)?;
        return Ok(Some(jsonrpc_result_response(id.clone(), &result_raw)?));
    }
    let Some(args_obj) = arguments.as_object() else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if !should_wrap_tool(tool_name, args_obj)? {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let result_raw = handle_tool_raw_admitted(runner, tool_name, &args_json)?;
    Ok(Some(jsonrpc_result_response(id.clone(), &result_raw)?))
}

/// Validate the common MCP request envelope before method-specific validation
/// or tool dispatch. `_meta` is protocol metadata, not a tool argument: its
/// object may carry extension keys and values, but the field itself must keep
/// the object shape declared by MCP RequestParams.
fn validate_mcp_request_metadata(
    method: &str,
    request: &Map<String, Value>,
) -> Result<(), ToolFault> {
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(metadata) = params.get("_meta") else {
        return Ok(());
    };
    if metadata.is_object() {
        return Ok(());
    }

    Err(ToolFault::new(
        "ASTRO_MCP_REQUEST_META_INVALID",
        format!(
            "{method} params._meta must be a JSON object; received {}",
            json_type_name(metadata)
        ),
        "send params._meta as an object containing protocol metadata, or omit it when the negotiated MCP protocol permits omission",
    )
    .with_argument("params._meta", "object or omitted", metadata)
    .with_detail("method", method))
}

fn request_invalid_params_response(
    request: &Map<String, Value>,
    fault: ToolFault,
) -> Result<Option<String>, DynError> {
    let Some(id) = request
        .get("id")
        .filter(|id| id.is_string() || id.is_number() || id.is_null())
        .cloned()
    else {
        // JSON-RPC notifications never receive a response. The structured
        // warning emitted by the caller is the durable process diagnostic.
        return Ok(None);
    };
    Ok(Some(jsonrpc_invalid_params_response(id, fault)?))
}

pub(crate) fn should_intercept_tool_call(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "list_projects"
            | "index_repository"
            | "delete_project"
            | "index_status"
            | "get_architecture"
            | "search_graph"
            | "detect_changes"
            | "query_graph"
            | "trace_path"
            | "trace_call_path"
    ) || is_advertised_astrolabe_tool(tool_name)
}

pub(crate) fn is_advertised_astrolabe_tool(tool_name: &str) -> bool {
    astrolabe_native_tool_definition(tool_name).is_some()
}

fn astrolabe_native_tool_definition(tool_name: &str) -> Option<&'static Value> {
    astrolabe_tool_definitions()
        .iter()
        .find(|definition| definition.get("name").and_then(Value::as_str) == Some(tool_name))
}

/// Validate a native request against the exact `inputSchema` object served by
/// `tools/list` before the handler can open Config, SQLite, or any vault family.
/// The supported schema vocabulary is deliberately small and exactly matches
/// the checked-in native definitions: object/array/scalar types, properties,
/// required fields, closed objects, enums, constants, negated constants, and
/// inclusive/exclusive numeric bounds.
fn validate_native_tool_arguments(
    tool_name: &str,
    definition: &Value,
    args_json: &str,
) -> Result<(), DynError> {
    let value = serde_json::from_str::<Value>(args_json).map_err(|error| {
        ToolFault::new(
            "ASTRO_MCP_ARGUMENTS_JSON_INVALID",
            format!("{tool_name} arguments are not valid JSON: {error}"),
            "pass one JSON object matching this tool's inputSchema from tools/list",
        )
    })?;
    let schema = definition
        .get("inputSchema")
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_NATIVE_SCHEMA_MISSING: {tool_name} has no inputSchema; remediation: repair the immutable native definition before dispatch"
            )
            .into()
        })?;
    validate_schema_value(tool_name, "arguments", schema, &value)
}

fn validate_schema_value(
    tool_name: &str,
    path: &str,
    schema: &Value,
    actual: &Value,
) -> Result<(), DynError> {
    let schema = schema.as_object().ok_or_else(|| -> DynError {
        format!(
            "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} schema at {path} is not an object; remediation: repair the immutable native definition before dispatch"
        )
        .into()
    })?;
    if let Some(expected_type) = schema.get("type") {
        let expected_type = expected_type.as_str().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} schema type at {path} is not a string; remediation: repair the immutable native definition before dispatch"
            )
            .into()
        })?;
        if !json_value_matches_type(actual, expected_type) {
            return Err(ToolFault::new(
                "ASTRO_MCP_ARGUMENT_TYPE_INVALID",
                format!(
                    "{tool_name} argument {path:?} must be JSON type {expected_type}; received {}",
                    json_type_name(actual)
                ),
                "correct the named value to match the inputSchema returned by tools/list, then retry",
            )
            .with_argument(path, expected_type, actual)
            .into());
        }
    }
    if let Some(variants) = schema.get("enum") {
        let variants = variants.as_array().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} enum at {path} is not an array; remediation: repair the immutable native definition before dispatch"
            )
            .into()
        })?;
        if !variants.contains(actual) {
            return Err(ToolFault::new(
                "ASTRO_MCP_ARGUMENT_ENUM_INVALID",
                format!("{tool_name} argument {path:?} is not an advertised enum value"),
                "use one of the exact enum values returned in this tool's tools/list inputSchema",
            )
            .with_detail("argument", path)
            .with_detail("allowed_values", variants.clone())
            .with_detail("observed_value", actual.clone())
            .into());
        }
    }
    if let Some(expected) = schema.get("const")
        && actual != expected
    {
        return Err(ToolFault::new(
            "ASTRO_MCP_ARGUMENT_CONST_INVALID",
            format!("{tool_name} argument {path:?} does not equal its advertised constant"),
            "use the exact const value returned in this tool's tools/list inputSchema",
        )
        .with_detail("argument", path)
        .with_detail("expected_value", expected.clone())
        .with_detail("observed_value", actual.clone())
        .into());
    }
    if let Some(negated) = schema.get("not") {
        let negated = negated.as_object().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} not at {path} is not an object; remediation: repair the immutable native definition before dispatch"
            )
            .into()
        })?;
        let forbidden = negated.get("const").ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} supports not only with one const at {path}; remediation: express the negated input as not={{const:...}}"
            )
            .into()
        })?;
        if negated.len() != 1 {
            return Err(format!(
                "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} supports not only with one const at {path}; remediation: remove unsupported keywords from the negated schema"
            )
            .into());
        }
        if actual == forbidden {
            return Err(ToolFault::new(
                "ASTRO_MCP_ARGUMENT_CONST_FORBIDDEN",
                format!("{tool_name} argument {path:?} equals its advertised forbidden constant"),
                "use a value other than the exact not.const value returned in this tool's tools/list inputSchema",
            )
            .with_detail("argument", path)
            .with_detail("forbidden_value", forbidden.clone())
            .with_detail("observed_value", actual.clone())
            .into());
        }
    }
    validate_schema_number_bounds(tool_name, path, schema, actual)?;
    validate_schema_integer_multiple(tool_name, path, schema, actual)?;

    if let Some(object) = actual.as_object() {
        let properties = match schema.get("properties") {
            Some(value) => Some(value.as_object().ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} properties at {path} are not an object; remediation: repair the immutable native definition before dispatch"
                )
                .into()
            })?),
            None => None,
        };
        if let Some(required) = schema.get("required") {
            let required = required.as_array().ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} required at {path} is not an array; remediation: repair the immutable native definition before dispatch"
                )
                .into()
            })?;
            for required_name in required {
                let required_name = required_name.as_str().ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} required entry at {path} is not a string; remediation: repair the immutable native definition before dispatch"
                    )
                    .into()
                })?;
                if !object.contains_key(required_name) {
                    return Err(ToolFault::new(
                        "ASTRO_MCP_ARGUMENT_REQUIRED",
                        format!("{tool_name} requires argument {required_name:?}"),
                        "supply every field listed in this tool's tools/list inputSchema.required array",
                    )
                    .with_detail("argument", required_name)
                    .with_detail("argument_path", format!("{path}.{required_name}"))
                    .into());
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            let properties = properties.ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_MCP_NATIVE_SCHEMA_INVALID: closed {tool_name} object at {path} has no properties map; remediation: repair the immutable native definition before dispatch"
                )
                .into()
            })?;
            if let Some((name, value)) = object
                .iter()
                .find(|(name, _)| !properties.contains_key(name.as_str()))
            {
                return Err(ToolFault::new(
                    "ASTRO_MCP_ARGUMENT_UNKNOWN",
                    format!("{tool_name} received unknown argument {name:?} at {path}"),
                    "remove the unknown field or use a field advertised in this tool's tools/list inputSchema",
                )
                .with_argument(format!("{path}.{name}"), "advertised property", value)
                .into());
            }
        }
        if let Some(properties) = properties {
            for (name, property_schema) in properties {
                if let Some(value) = object.get(name) {
                    validate_schema_value(
                        tool_name,
                        &format!("{path}.{name}"),
                        property_schema,
                        value,
                    )?;
                }
            }
        }
    }
    if let Some(array) = actual.as_array()
        && let Some(items) = schema.get("items")
    {
        for (ordinal, value) in array.iter().enumerate() {
            validate_schema_value(tool_name, &format!("{path}[{ordinal}]"), items, value)?;
        }
    }
    Ok(())
}

/// Validate the integer subset of JSON Schema `multipleOf` exactly, without
/// floating-point rounding. Every native schema using this keyword currently
/// declares an integer argument and a positive integer divisor. A future
/// non-integer declaration is rejected as an immutable-schema defect instead
/// of being approximately interpreted.
fn validate_schema_integer_multiple(
    tool_name: &str,
    path: &str,
    schema: &Map<String, Value>,
    actual: &Value,
) -> Result<(), DynError> {
    let Some(multiple_value) = schema.get("multipleOf") else {
        return Ok(());
    };
    let Some(multiple) = multiple_value.as_u64().filter(|value| *value > 0) else {
        return Err(format!(
            "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} multipleOf at {path} must be a positive integer; remediation: repair the immutable native definition before dispatch"
        )
        .into());
    };
    let remainder = if let Some(value) = actual.as_u64() {
        value % multiple
    } else if let Some(value) = actual.as_i64() {
        value.unsigned_abs() % multiple
    } else {
        return Err(format!(
            "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} uses integer-only multipleOf at {path} for a non-integer value; remediation: declare type=integer with a positive integer divisor"
        )
        .into());
    };
    if remainder != 0 {
        return Err(ToolFault::new(
            "ASTRO_MCP_ARGUMENT_MULTIPLE_INVALID",
            format!(
                "{tool_name} argument {path:?} is not an exact multiple of advertised multipleOf {multiple}"
            ),
            "use a value exactly divisible by the multipleOf returned by tools/list",
        )
        .with_detail("argument", path)
        .with_detail("multiple_of", multiple)
        .with_detail("observed_value", actual.clone())
        .into());
    }
    Ok(())
}

fn validate_schema_number_bounds(
    tool_name: &str,
    path: &str,
    schema: &Map<String, Value>,
    actual: &Value,
) -> Result<(), DynError> {
    let Some(number) = actual.as_f64() else {
        return Ok(());
    };
    for bound_name in ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] {
        let Some(bound_value) = schema.get(bound_name) else {
            continue;
        };
        let bound = bound_value.as_f64().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_NATIVE_SCHEMA_INVALID: {tool_name} {bound_name} at {path} is not numeric; remediation: repair the immutable native definition before dispatch"
            )
            .into()
        })?;
        let violates = if bound_name == "minimum" {
            number < bound
        } else if bound_name == "maximum" {
            number > bound
        } else if bound_name == "exclusiveMinimum" {
            number <= bound
        } else {
            number >= bound
        };
        if violates {
            return Err(ToolFault::new(
                "ASTRO_MCP_ARGUMENT_BOUND_INVALID",
                format!("{tool_name} argument {path:?} violates advertised {bound_name} {bound}"),
                "use a value inside the exact numeric bounds returned by tools/list",
            )
            .with_detail("argument", path)
            .with_detail("bound", bound_name)
            .with_detail("bound_value", bound)
            .with_detail("observed_value", number)
            .into());
        }
    }
    Ok(())
}

fn json_value_matches_type(value: &Value, expected_type: &str) -> bool {
    match expected_type {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
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
        .iter()
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
    let request: Value = serde_json::from_str(request_json)?;
    let Some(request) = request.as_object() else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(id) = request
        .get("id")
        .filter(|id| id.is_string() || id.is_number() || id.is_null())
        .cloned()
    else {
        // Preserve JSON-RPC notification/invalid-id behavior in the native
        // owner rather than manufacturing a response for a request with no
        // response identity.
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };

    if let Some(params) = request.get("params") {
        let Some(params) = params.as_object() else {
            let fault = ToolFault::new(
                "ASTRO_MCP_TOOLS_LIST_PARAMS_INVALID",
                "tools/list params must be a JSON object when present",
                "send tools/list with params={} or omit params; no cursor is required because this executable publishes its complete bounded roster in one response",
            )
            .with_argument("params", "object or omitted", params);
            tracing::warn!(
                code = fault.code(),
                actual_type = json_type_name(params),
                "mcp.tools_list_invalid_params"
            );
            return Ok(Some(jsonrpc_invalid_params_response(id, fault)?));
        };
        if let Some((name, value)) = params
            .iter()
            .find(|(name, _)| !matches!(name.as_str(), "cursor" | "_meta"))
        {
            let fault = ToolFault::new(
                "ASTRO_MCP_TOOLS_LIST_ARGUMENT_UNKNOWN",
                format!("tools/list received unknown parameter {name:?}"),
                "remove the unknown parameter; only protocol _meta or a server-issued cursor is defined, and this executable returns its complete bounded roster without issuing one",
            )
            .with_argument(
                format!("params.{name}"),
                "_meta, cursor, or omitted",
                value,
            );
            tracing::warn!(
                code = fault.code(),
                parameter = name.as_str(),
                actual_type = json_type_name(value),
                "mcp.tools_list_unknown_param"
            );
            return Ok(Some(jsonrpc_invalid_params_response(id, fault)?));
        }
        if let Some(cursor) = params.get("cursor") {
            let mut fault = ToolFault::new(
                "ASTRO_MCP_TOOLS_CURSOR_INVALID",
                "this executable did not issue a tools/list cursor",
                "discard the stale or foreign cursor and issue tools/list without cursor; the complete bounded roster is returned in one response",
            )
            .with_argument("cursor", "omitted (no nextCursor was issued)", cursor);
            if let Some(cursor) = cursor.as_str() {
                fault = fault.with_detail("received_cursor", cursor);
            }
            tracing::warn!(
                code = fault.code(),
                actual_type = json_type_name(cursor),
                "mcp.tools_list_invalid_cursor"
            );
            return Ok(Some(jsonrpc_invalid_params_response(id, fault)?));
        }
    }

    let cbm_registry = runner.tool_definitions_raw()?;
    let result = compose_complete_tool_roster(&cbm_registry)?;
    let tool_count = result
        .get("tools")
        .and_then(|value| value.as_array())
        .map_or(0, |tools| tools.len());
    tracing::info!(tool_count, "mcp.tools_list_complete_roster");
    Ok(Some(jsonrpc_result_response(
        id,
        &serde_json::to_string(&result)?,
    )?))
}

/// Compose the one authoritative public roster from both immutable registries.
///
/// #1110/#1132 / #1064 PC-35 + PC-38: N is the compile-time registry size,
/// currently 40 definitions (14 CBM + 26 Rust-native). This performs one deterministic O(N)
/// pass over generation-invariant schema values, opens no project/vault store,
/// and writes no state. CBM order comes first for legacy compatibility; a name
/// present in both registries keeps the CBM definition, after which Astrolabe's
/// explicit schema overlays are applied. Duplicate names *within* the CBM
/// registry are a frozen-contract defect and fail closed.
pub(crate) fn compose_complete_tool_roster(cbm_registry_json: &str) -> Result<Value, DynError> {
    let mut result: Value = serde_json::from_str(cbm_registry_json)?;
    let Some(result_object) = result.as_object_mut() else {
        return Err("ASTRO_MCP_CBM_TOOL_REGISTRY_INVALID: the complete CBM tool registry was not a JSON object; remediation: repair cbm_mcp_tools_list before serving tools/list".into());
    };
    if result_object.contains_key("nextCursor") {
        return Err("ASTRO_MCP_CBM_TOOL_REGISTRY_PAGINATED: the complete CBM registry export unexpectedly carried nextCursor; remediation: bind the host to cbm_mcp_tools_list, never the paginated request path".into());
    }
    let Some(tools) = result_object.get_mut("tools").and_then(Value::as_array_mut) else {
        return Err("ASTRO_MCP_CBM_TOOL_REGISTRY_INVALID: the complete CBM tool registry did not contain a tools array; remediation: repair cbm_mcp_tools_list before serving tools/list".into());
    };

    let mut names = BTreeSet::new();
    for definition in tools.iter() {
        let name = tool_definition_name(definition, "CBM")?;
        if !names.insert(name.to_string()) {
            return Err(format!(
                "ASTRO_MCP_TOOL_REGISTRY_DUPLICATE: CBM registered tool '{name}' more than once; remediation: keep exactly one immutable definition for each public tool name"
            )
            .into());
        }
    }
    for definition in astrolabe_tool_definitions() {
        let name = tool_definition_name(definition, "Astrolabe-native")?;
        // Explicit precedence rule: a legacy CBM definition owns a shared name;
        // the overlays below add only Astrolabe's declared extensions.
        if names.insert(name.to_string()) {
            tools.push(definition.clone());
        }
    }

    // #328: overlay the Astrolabe-side extensions onto the CBM `search_graph`
    // schema so MCP clients can discover propagated_label + fusion from tools/list.
    // The overlay runs only after the full registry union so there is exactly
    // one public definition to extend.
    for tool in tools.iter_mut() {
        match tool.get("name").and_then(Value::as_str) {
            Some("index_repository") => overlay_index_repository_extensions(tool)?,
            Some("get_architecture") => overlay_get_architecture_extensions(tool)?,
            Some("search_graph") => overlay_search_graph_extensions(tool)?,
            // #43: advertise the opt-in `scored` best-first knob on the CBM
            // trace_path schema so clients can discover it, same overlay pattern.
            Some("trace_path") | Some("trace_call_path") => overlay_trace_path_extensions(tool)?,
            // #43: advertise the opt-in `as_of` time-travel knob on the CBM
            // query_graph schema so clients can discover it, same overlay pattern.
            Some("query_graph") => overlay_query_graph_extensions(tool)?,
            _ => {}
        }
    }
    Ok(result)
}

fn tool_definition_name<'a>(definition: &'a Value, registry: &str) -> Result<&'a str, DynError> {
    definition
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            format!(
                "ASTRO_MCP_TOOL_DEFINITION_NAME_MISSING: {registry} registry contains a tool definition without a non-empty name; remediation: repair the frozen registry definition before serving tools/list"
            )
            .into()
        })
}

fn jsonrpc_invalid_params_response(id: Value, fault: ToolFault) -> Result<String, DynError> {
    Ok(serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32602,
            "message": "Invalid params",
            "data": fault.envelope(),
        }
    }))?)
}

const INDEX_REPOSITORY_BASE_PUBLIC_ARGS: [&str; 5] = [
    "repo_path",
    "mode",
    "target_projects",
    GENERATION_OBSERVED_AT_MS_ARG,
    "persistence",
];
const INDEX_REPOSITORY_PUBLIC_ARGS: [&str; 8] = [
    "repo_path",
    "mode",
    "target_projects",
    GENERATION_OBSERVED_AT_MS_ARG,
    "persistence",
    MIGRATION_DIAL_ARG,
    SEARCH_SCALE_ARG,
    SKILL_DISCOVERY_ARG,
];

fn index_repository_astrolabe_property_overlay() -> Vec<(String, Value)> {
    vec![
        (
            GENERATION_OBSERVED_AT_MS_ARG.to_string(),
            generation_clock_property_schema(),
        ),
        (
            MIGRATION_DIAL_ARG.to_string(),
            migration_dial_property_schema(),
        ),
        (
            SEARCH_SCALE_ARG.to_string(),
            search_scale_override_property_schema(),
        ),
        (
            SKILL_DISCOVERY_ARG.to_string(),
            skill_discovery_override_property_schema(),
        ),
    ]
}

/// Merge one handler-owned property set into a legacy tool definition. A
/// malformed base schema or a differently-defined collision is a registry
/// defect and refuses the entire tools/list response instead of silently
/// omitting or overriding public behavior.
fn overlay_tool_properties(
    tool: &mut Value,
    expected_tool_name: &str,
    overlay: Vec<(String, Value)>,
) -> Result<(), DynError> {
    let actual_name = tool
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_TOOL_SCHEMA_INVALID: {expected_tool_name} definition has no non-empty name; remediation: repair the immutable tool registry"
            )
            .into()
        })?;
    if actual_name != expected_tool_name {
        return Err(format!(
            "ASTRO_MCP_TOOL_SCHEMA_NAME_MISMATCH: expected {expected_tool_name:?}, observed {actual_name:?}; remediation: route each schema overlay to its exact tool definition"
        )
        .into());
    }
    let schema = tool
        .get_mut("inputSchema")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_TOOL_SCHEMA_INVALID: {expected_tool_name}.inputSchema is not an object; remediation: repair the immutable base definition before applying extensions"
            )
            .into()
        })?;
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!(
            "ASTRO_MCP_TOOL_SCHEMA_INVALID: {expected_tool_name}.inputSchema.type is not object; remediation: repair the immutable base definition before applying extensions"
        )
        .into());
    }
    let properties = schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_MCP_TOOL_SCHEMA_INVALID: {expected_tool_name}.inputSchema.properties is not an object; remediation: repair the immutable base definition before applying extensions"
            )
            .into()
        })?;
    for (name, spec) in overlay {
        if let Some(existing) = properties.get(&name) {
            if existing != &spec {
                return Err(format!(
                    "ASTRO_MCP_TOOL_SCHEMA_COLLISION: {expected_tool_name}.{name} has different base and host schemas; remediation: keep one canonical property definition shared by schema and handler validation"
                )
                .into());
            }
        } else {
            properties.insert(name, spec);
        }
    }
    Ok(())
}

/// #1073: add every public Astrolabe argument consumed by the
/// `index_repository` host handler and close the object against unknown fields.
fn overlay_index_repository_extensions(tool: &mut Value) -> Result<(), DynError> {
    let base_properties = tool
        .get("inputSchema")
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .ok_or_else(|| -> DynError {
            "ASTRO_MCP_INDEX_SCHEMA_INVALID: index_repository base properties are missing; remediation: repair the CBM registry before serving tools/list".into()
        })?;
    for name in base_properties.keys() {
        if !INDEX_REPOSITORY_BASE_PUBLIC_ARGS.contains(&name.as_str())
            && !INDEX_REPOSITORY_PUBLIC_ARGS.contains(&name.as_str())
        {
            return Err(format!(
                "ASTRO_MCP_INDEX_SCHEMA_UNOWNED_PROPERTY: base index_repository schema advertises unowned property {name:?}; remediation: add one handler-validated canonical contract for that property before exposing it"
            )
            .into());
        }
    }
    overlay_tool_properties(
        tool,
        "index_repository",
        index_repository_astrolabe_property_overlay(),
    )?;
    let schema = tool
        .get_mut("inputSchema")
        .and_then(Value::as_object_mut)
        .ok_or("ASTRO_MCP_INDEX_SCHEMA_INVALID: index_repository inputSchema disappeared during overlay")?;
    match schema.get("additionalProperties") {
        None | Some(Value::Bool(false)) => {
            schema.insert("additionalProperties".to_string(), Value::Bool(false));
        }
        Some(other) => {
            return Err(format!(
                "ASTRO_MCP_INDEX_SCHEMA_OPEN: index_repository additionalProperties is {other}; remediation: keep the public request closed and add every supported field to the canonical contract"
            )
            .into());
        }
    }
    Ok(())
}

fn validate_index_repository_public_arguments(args: &Map<String, Value>) -> Result<(), ToolFault> {
    for (name, value) in args {
        if !INDEX_REPOSITORY_PUBLIC_ARGS.contains(&name.as_str()) {
            return Err(ToolFault::new(
                "ASTRO_INDEX_ARGUMENT_UNKNOWN",
                format!("index_repository received unknown public argument {name:?}"),
                "remove the unknown field or use a field advertised by this server's index_repository tools/list schema",
            )
            .with_argument(
                name,
                format!("one of {}", INDEX_REPOSITORY_PUBLIC_ARGS.join(", ")),
                value,
            ));
        }
    }
    Ok(())
}

/// #1120: extend the existing selector enum from the same constants consumed
/// by `ArchitectureRequestPlan`, then close the now-host-validated request.
fn overlay_get_architecture_extensions(tool: &mut Value) -> Result<(), DynError> {
    let schema = tool
        .get_mut("inputSchema")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| -> DynError {
            "ASTRO_MCP_ARCHITECTURE_SCHEMA_INVALID: get_architecture.inputSchema is not an object; remediation: repair the immutable CBM definition".into()
        })?;
    let properties = schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| -> DynError {
            "ASTRO_MCP_ARCHITECTURE_SCHEMA_INVALID: get_architecture properties are missing; remediation: repair the immutable CBM definition".into()
        })?;
    let aspects = properties
        .get_mut("aspects")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| -> DynError {
            "ASTRO_MCP_ARCHITECTURE_SCHEMA_INVALID: get_architecture.aspects is not an object; remediation: repair the immutable CBM definition".into()
        })?;
    let variants = aspects
        .get_mut("items")
        .and_then(Value::as_object_mut)
        .and_then(|items| items.get_mut("enum"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| -> DynError {
            "ASTRO_MCP_ARCHITECTURE_SCHEMA_INVALID: get_architecture.aspects.items.enum is missing; remediation: repair the immutable CBM definition".into()
        })?;
    let observed = variants
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if observed != CBM_ARCHITECTURE_ASPECTS {
        return Err(format!(
            "ASTRO_MCP_ARCHITECTURE_SCHEMA_DRIFT: legacy aspect enum was {observed:?}, expected {:?}; remediation: reconcile the CBM handler and the host canonical selector set before serving tools/list",
            CBM_ARCHITECTURE_ASPECTS
        )
        .into());
    }
    variants.extend(
        ASTROLABE_ARCHITECTURE_ASPECTS
            .into_iter()
            .map(|aspect| Value::String(aspect.to_string())),
    );
    aspects.insert(
        "description".to_string(),
        Value::String(
            "Aspects to include. Omit for the complete legacy CBM architecture without extra Calyx reads; overview is the compact legacy summary; all includes every legacy and Astrolabe aspect. Astrolabe selectors read only their named persisted project surface. search_scale serves the exact Calyx backend/admission plan; weave serves the exact Weave/Loom family, cross-term, association, Sextant quantization, and Forge commissioning receipts. signal_ranking reads the exact committed Assay transaction and returns a structured tool error for a validated preserved failed publication even when the live shadow dial is absent. kernel is an alias for kernel_context and n_eff is an alias for redundancy. Astrolabe aspects are project-scoped and refuse a non-empty path rather than returning an unscoped answer."
                .to_string(),
        ),
    );
    match schema.get("additionalProperties") {
        None | Some(Value::Bool(false)) => {
            schema.insert("additionalProperties".to_string(), Value::Bool(false));
        }
        Some(other) => {
            return Err(format!(
                "ASTRO_MCP_ARCHITECTURE_SCHEMA_OPEN: get_architecture additionalProperties is {other}; remediation: keep the request closed and add supported fields to the canonical contract"
            )
            .into());
        }
    }
    Ok(())
}

/// #328: merge the Astrolabe `search_graph` extension properties into the CBM
/// tool's `inputSchema.properties`, refusing schema drift.
pub(crate) fn overlay_search_graph_extensions(tool: &mut Value) -> Result<(), DynError> {
    overlay_tool_properties(
        tool,
        "search_graph",
        search_graph_astrolabe_property_overlay(),
    )
}

/// #43: merge the Astrolabe `scored` extension property into the CBM `trace_path`
/// tool's `inputSchema.properties`, leaving CBM-native properties untouched.
pub(crate) fn overlay_trace_path_extensions(tool: &mut Value) -> Result<(), DynError> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("trace_path")
        .to_string();
    overlay_tool_properties(tool, &name, trace_path_astrolabe_property_overlay())
}

/// #43: merge the Astrolabe `as_of` extension property into the CBM `query_graph`
/// tool's `inputSchema.properties`, leaving CBM-native properties untouched.
pub(crate) fn overlay_query_graph_extensions(tool: &mut Value) -> Result<(), DynError> {
    overlay_tool_properties(
        tool,
        "query_graph",
        query_graph_astrolabe_property_overlay(),
    )
}

pub(crate) fn should_wrap_tool(
    tool_name: &str,
    args: &Map<String, Value>,
) -> Result<bool, DynError> {
    match tool_name {
        "list_projects" => Ok(true),
        // Always wrap delete_project: the Astrolabe host-side sidecar family
        // (lowered mirror, vault, locks, search index, per-project config rows)
        // can outlive a dial-off project, so cleanup must run regardless of the
        // current dial — never gate it on read_dial (#417).
        "delete_project" => Ok(true),
        // Every index generation crosses the project transition, including the
        // byte-parity dial-off path. Letting the ordinary call bypass this host
        // wrapper would leave resident query handles outside #753 coordination.
        "index_repository" => Ok(true),
        "index_status" => {
            let Some(project) = status_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        // Always wrap so the host-owned selector/schema contract is enforced
        // identically for legacy and shadow projects before any store access.
        "get_architecture" => Ok(true),
        "search_graph" => {
            Ok(search_graph_has_astrolabe_knob(args) || shadow_project_requested(args)?.is_some())
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
            // A stale shadow graph must be refused before either the scored Astrolabe
            // ranking or the byte-identical CBM traversal can serve it (#916).
            Ok(trace_path_scored_requested(args) || shadow_project_requested(args)?.is_some())
        }
        "query_graph" => {
            // Live shadow Cypher reads and historical reads both answer from the
            // persisted graph; refuse stale graph state before serving either (#916).
            Ok(query_graph_as_of_requested(args) || shadow_project_requested(args)?.is_some())
        }
        name if is_advertised_astrolabe_tool(name) => Ok(true),
        _ => Ok(false),
    }
}

pub(crate) fn handle_list_projects(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let result = runner.handle_tool_raw("list_projects", args_json)?;
    if tool_result_is_error(&result)? {
        return Ok(result);
    }
    augment_tool_result(
        &result,
        json!({
            "reader_process_generation": crate::activation_epoch::reader_generation_fields()?,
        }),
    )
}

fn shadow_project_requested(args: &Map<String, Value>) -> Result<Option<String>, DynError> {
    let Some(project) = status_project_from_args(args)? else {
        return Ok(None);
    };
    if read_dial(&project)? == MigrationDial::Shadow {
        Ok(Some(project))
    } else {
        Ok(None)
    }
}

pub(crate) fn handle_index_repository(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let args = match serde_json::from_str::<Value>(args_json) {
        Ok(args) => args,
        Err(error) => {
            return ToolFault::new(
                "ASTRO_INDEX_ARGUMENTS_JSON_INVALID",
                format!("index_repository arguments are not valid JSON: {error}"),
                "pass one JSON object matching the advertised index_repository input schema",
            )
            .into_result();
        }
    };
    let Some(args_obj) = args.as_object() else {
        return ToolFault::new(
            "ASTRO_INDEX_ARGUMENTS_OBJECT_REQUIRED",
            "index_repository arguments must be a JSON object",
            "pass one JSON object matching the advertised index_repository input schema",
        )
        .with_argument("arguments", "JSON object", &args)
        .into_result();
    };
    if args_obj.contains_key(astrolabe_bridge::ASTRO_COMPILATION_CONTEXT_ARG) {
        return ToolFault::new(
            "ASTRO_COMPILE_CONTEXT_PRIVATE_ARG_COLLISION",
            format!(
                "caller supplied reserved argument {:?}",
                astrolabe_bridge::ASTRO_COMPILATION_CONTEXT_ARG
            ),
            "remove the private transport field and let Astrolabe derive it from repo_path",
        )
        .with_detail("argument", astrolabe_bridge::ASTRO_COMPILATION_CONTEXT_ARG)
        .into_result();
    }
    if args_obj.contains_key(GENERATION_OBSERVED_AT_MS_PRIVATE_ARG) {
        return ToolFault::new(
            "ASTRO_GENERATION_CLOCK_PRIVATE_ARG_COLLISION",
            format!(
                "caller supplied reserved argument {GENERATION_OBSERVED_AT_MS_PRIVATE_ARG:?}"
            ),
            "remove the private transport field and use generation_observed_at_ms for an explicit reproducible generation",
        )
        .with_detail(
            "argument",
            Value::String(GENERATION_OBSERVED_AT_MS_PRIVATE_ARG.to_string()),
        )
        .into_result();
    }
    if args_obj.contains_key("name") {
        return ToolFault::new(
            "CBM_PROJECT_NAME_OVERRIDE_REFUSED",
            "project storage identity is derived only from the canonical repository root",
            "remove the name argument and use the project returned by index_repository",
        )
        .with_detail("argument", "name")
        .into_result();
    }
    if let Err(fault) = validate_index_repository_public_arguments(args_obj) {
        tracing::warn!(code = fault.code(), "mcp.index_repository.argument_refused");
        return fault.into_result();
    }
    let generation_clock_request = match GenerationClockRequest::parse(args_obj) {
        Ok(request) => request,
        Err(fault) => return fault.into_result(),
    };
    let activation_fence = crate::activation_epoch::require_active_generation("index_repository")?;

    let search_scale_override = match parse_search_scale_override(args_obj) {
        Ok(value) => value,
        Err(message) => {
            return ToolFault::new(
                "ASTRO_SEARCH_SCALE_ARGUMENT_INVALID",
                message,
                "pass calyx_search as the closed object advertised by index_repository tools/list",
            )
            .with_detail("argument", SEARCH_SCALE_ARG)
            .into_result();
        }
    };
    let skill_discovery_override = match parse_skill_discovery_override(args_obj) {
        Ok(value) => value,
        Err(message) => {
            return ToolFault::new(
                "ASTRO_SKILL_DISCOVERY_ARGUMENT_INVALID",
                message,
                "pass calyx_skills as the closed object advertised by index_repository tools/list",
            )
            .with_detail("argument", SKILL_DISCOVERY_ARG)
            .into_result();
        }
    };
    let project = index_project_from_args(args_obj)?;
    let explicit_dial = args_obj.get(MIGRATION_DIAL_ARG);
    let dial = match explicit_dial {
        Some(value) => match MigrationDial::parse(value) {
            Ok(dial) => dial,
            Err(message) => {
                return ToolFault::new(
                    "ASTRO_MIGRATION_DIAL_ARGUMENT_INVALID",
                    message,
                    "pass calyx=\"off\" or calyx=\"shadow\" exactly; omit it only to reuse persisted project state",
                )
                .with_argument(
                    MIGRATION_DIAL_ARG,
                    "string enum off|shadow",
                    value,
                )
                .into_result();
            }
        },
        None => project
            .as_ref()
            .map(|project| read_dial(project))
            .transpose()?
            .unwrap_or(MigrationDial::Off),
    };

    let sanitized_args = strip_calyx_arg(args_obj)?;
    let repo_path = string_arg(args_obj, "repo_path").map(PathBuf::from);

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
        if let (Some(project), Some(repo_path)) = (project.as_deref(), repo_path.as_deref()) {
            let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
            let generation_clock = match generation_clock_request.resolve() {
                Ok(clock) => clock,
                Err(fault) => return fault.into_result(),
            };
            return run_project_index_transition(
                runner,
                &cache_dir,
                project,
                repo_path,
                |transition_grant| {
                    run_supervised_index_with_transition(
                        runner,
                        &sanitized_args,
                        &cache_dir,
                        transition_grant,
                        generation_clock,
                    )
                },
            );
        }
        let generation_clock = match generation_clock_request.resolve() {
            Ok(clock) => clock,
            Err(fault) => return fault.into_result(),
        };
        let worker_args = generation_clock.bind_worker_arg(&sanitized_args)?;
        return Ok(runner.handle_tool_raw("index_repository", &worker_args)?);
    }

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
    if dial == MigrationDial::Off {
        let result =
            if let (Some(project), Some(repo_path)) = (project.as_deref(), repo_path.as_deref()) {
                let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
                let generation_clock = match generation_clock_request.resolve() {
                    Ok(clock) => clock,
                    Err(fault) => return fault.into_result(),
                };
                run_project_index_transition(
                    runner,
                    &cache_dir,
                    project,
                    repo_path,
                    |transition_grant| {
                        run_supervised_index_with_transition(
                            runner,
                            &sanitized_args,
                            &cache_dir,
                            transition_grant,
                            generation_clock,
                        )
                    },
                )?
            } else {
                let generation_clock = match generation_clock_request.resolve() {
                    Ok(clock) => clock,
                    Err(fault) => return fault.into_result(),
                };
                let worker_args = generation_clock.bind_worker_arg(&sanitized_args)?;
                runner.handle_tool_raw("index_repository", &worker_args)?
            };
        if let Some(project) = project
            .or_else(|| project_from_tool_result(&result))
            .filter(|project| !project.trim().is_empty())
        {
            persist_dial(&project, dial)?;
        }
        return Ok(result);
    }
    let Some(project) = project.or_else(|| {
        repo_path.as_deref().and_then(|path| {
            path.to_str()
                .and_then(|path| astrolabe_bridge::cbm_project_name_from_path(path).ok())
        })
    }) else {
        return tool_error_result(
            "ASTRO_SHADOW_PROJECT_UNRESOLVED: shadow indexing requires a resolvable project name or repo_path; remediation: pass a valid repo_path",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if repo_path
        .as_deref()
        .is_some_and(astrolabe_anchors::archaeology::is_git_work_tree)
        && let Err(error) = super::git_archaeology::preflight_git_archaeology_persistence_limits()
    {
        return tool_error_result(error.to_string());
    }
    // Serialize the complete per-project decision before entering the durable
    // project transition. This lets an unchanged hit remain genuinely read-only:
    // the transition protocol persists active/terminal receipts, so acquiring it
    // before the cache decision would mutate config on every no-op call. The same
    // import lock is held through a miss and its full transition, preventing a
    // competing index process from changing the effective settings between the
    // admission read and staged publication.
    let Some(shadow_import_lock) = try_shadow_import_lock(&cache_dir, &project)? else {
        return tool_error_result(format!(
            "ASTRO_SHADOW_IMPORT_BUSY: a shadow publication for project {project:?} is already active at {}; remediation: retry after that exact owner completes",
            shadow_import_lock_path(&cache_dir, &project).display()
        ));
    };
    let search_scale_settings =
        match search_scale_settings_for_import(&project, search_scale_override) {
            Ok(settings) => settings,
            Err(error) => return tool_error_result(format!("search scale config failed: {error}")),
        };
    let similarity_config = match SimilarityPlannerConfig::resolve_runtime() {
        Ok(config) => config,
        Err(error) => {
            let mut fault =
                ToolFault::new(error.code, error.message.clone(), error.remediation.clone())
                    .with_detail("knob", error.knob);
            if let Some(environment) = error.environment {
                fault = fault.with_detail("environment", environment);
            }
            if let Some(observed_value) = error.observed_value {
                fault = fault.with_detail("observed_value", observed_value);
            }
            return fault.into_result();
        }
    };
    let index_admission_identity = shadow_index_admission_identity(
        &sanitized_args,
        &search_scale_settings,
        &skills,
        &similarity_config,
    )?;
    let mut action_policy =
        shadow_index_action_policy(&cache_dir, &project, &index_admission_identity)?;
    if let Some(repo) = repo_path
        .as_deref()
        .filter(|repo| astrolabe_anchors::archaeology::is_git_work_tree(repo))
    {
        match try_shadow_index_noop_admission(
            &cache_dir,
            &project,
            repo,
            &index_admission_identity,
            &action_policy,
        )? {
            ShadowIndexNoopAdmission::Hit { result } => {
                eprintln!(
                    "astro.shadow.index_phase phase=preseed_noop status=hit project={project} identity_sha256={}",
                    index_admission_identity.identity_sha256()
                );
                return Ok(result);
            }
            ShadowIndexNoopAdmission::Miss {
                reason,
                action_policy: miss_policy,
            } => {
                action_policy = miss_policy;
                eprintln!(
                    "astro.shadow.index_phase phase=preseed_noop status=miss project={project} reason={reason} identity_sha256={}",
                    index_admission_identity.identity_sha256()
                );
            }
        }
    } else {
        eprintln!(
            "astro.shadow.index_phase phase=preseed_noop status=miss project={project} reason=non_git_source"
        );
    }
    if let Some(repo) = repo_path
        .as_deref()
        .filter(|repo| astrolabe_anchors::archaeology::is_git_work_tree(repo))
        && let Err(error) =
            super::git_archaeology::preflight_git_archaeology_scratch(repo, &project)
    {
        return tool_error_result(error.to_string());
    }
    // Resolve only after a pre-seed no-op miss, but before the project
    // transition or staged publication mutates durable state. One immutable
    // value is then carried through CBM, archaeology, assay, and Calyx.
    let generation_clock = match generation_clock_request.resolve() {
        Ok(clock) => clock,
        Err(fault) => return fault.into_result(),
    };
    let transition_root = repo_path.as_deref().ok_or_else(|| -> DynError {
        "ASTRO_PROJECT_TRANSITION_ROOT_REQUIRED: shadow indexing requires repo_path for exact transition identity; remediation: pass the canonical repository root".into()
    })?;
    run_project_index_transition(
        runner,
        &cache_dir,
        &project,
        transition_root,
        |transition_grant| {
            let shadow_started = std::time::Instant::now();
            let stage_started = std::time::Instant::now();
            let mut publication = ShadowPublication::begin(&cache_dir, &project)?;
            eprintln!(
                "astro.shadow.index_phase phase=stage_seed elapsed_ms={} total_ms={}",
                stage_started.elapsed().as_millis(),
                shadow_started.elapsed().as_millis()
            );
            // #1037: the complete keying identity of the CBM pass. A corpus with no
            // git work tree cannot be keyed, so preservation/resume are labeled
            // unavailable rather than keyed on a partial identity.
            let stage_fingerprint = match PreservedStageFingerprint::capture(
                &project,
                repo_path.as_deref(),
                &index_admission_identity,
                PUBLICATION_SCHEMA,
                generation_clock,
            ) {
                Ok(fingerprint) => Some(fingerprint),
                Err(error) => {
                    eprintln!(
                        "astro.shadow.preserved_stage project={project} status=unavailable reason={error}"
                    );
                    None
                }
            };
            let staged_args = match supervised_index_worker_args(
                &sanitized_args,
                publication.stage_cache(),
                transition_grant,
                generation_clock,
            ) {
                Ok(args) => args,
                Err(error) => return Err(publication.abort("worker argument binding", error)),
            };
            let mut adoption_evidence = Value::Null;
            let pass = if resume_preserved_stage_requested() {
                let Some(fingerprint) = stage_fingerprint.as_ref() else {
                    return tool_error_result(
                        publication
                            .abort(
                                "preserved stage adoption",
                                "ASTRO_SHADOW_PRESERVED_STAGE_CORPUS_UNIDENTIFIABLE: a seeded resume was requested but this corpus has no exact identity to match a preserved stage against; remediation: unset ASTRO_SHADOW_RESUME_PRESERVED_STAGE and run a full index",
                            )
                            .to_string(),
                    );
                };
                let adopted = match publication.adopt_preserved_stage(fingerprint) {
                    Ok(adopted) => adopted,
                    Err(error) => {
                        return tool_error_result(
                            publication
                                .abort("preserved stage adoption", error)
                                .to_string(),
                        );
                    }
                };
                adoption_evidence = adopted.evidence_json();
                match resume_shadow_index_pass_from_adopted_stage(
                    &adopted,
                    &project,
                    &skills,
                    publication.stage_cache(),
                ) {
                    Ok(pass) => pass,
                    Err(error) => {
                        return tool_error_result(
                            publication
                                .abort("preserved stage resume", error)
                                .to_string(),
                        );
                    }
                }
            } else {
                match run_shadow_index_pass(
                    runner,
                    &staged_args,
                    Some(&project),
                    &skills,
                    publication.stage_cache(),
                ) {
                    Ok(pass) => pass,
                    Err(error) => {
                        return tool_error_result(
                            publication
                                .abort("staged index execution", error)
                                .to_string(),
                        );
                    }
                }
            };
            let (result, resolved_project, row_sink) = match pass {
                ShadowIndexPassOutcome::Completed {
                    raw_result,
                    project,
                    candidate,
                } => (raw_result, project, candidate),
                ShadowIndexPassOutcome::Failed { error_result } => {
                    let error_result = match shadow_index_pass_error_result(&error_result) {
                        Ok(error_result) => error_result,
                        Err(error) => {
                            return tool_error_result(
                                publication
                                    .abort("staged index error normalization", error)
                                    .to_string(),
                            );
                        }
                    };
                    if let Err(error) = publication
                        .abort_preserving_tool_error("staged index refusal", &error_result)
                    {
                        return tool_error_result(error.to_string());
                    }
                    return Ok(error_result);
                }
            };
            // The completed CBM store is already the expensive durable product.
            // Arm it before touching its declared log so any promotion/readback
            // failure preserves rather than destroys the stage (#1037).
            if let Some(fingerprint) = stage_fingerprint.as_ref()
                && let Err(error) = publication.arm_stage_preservation(fingerprint, &result)
            {
                return tool_error_result(
                    publication
                        .abort("stage preservation arming", error)
                        .to_string(),
                );
            }
            let result = match promote_shadow_skip_log(
                &result,
                publication.stage_cache(),
                &cache_dir,
                &project,
            ) {
                Ok(result) => result,
                Err(error) => {
                    return tool_error_result(
                        publication
                            .abort("index skip-log promotion", error)
                            .to_string(),
                    );
                }
            };
            // Rebind preserved-stage replay to the response containing the durable
            // content-addressed log receipt. This replaces, never weakens, the
            // pre-promotion arming above.
            if let Some(fingerprint) = stage_fingerprint.as_ref()
                && let Err(error) = publication.arm_stage_preservation(fingerprint, &result)
            {
                return tool_error_result(
                    publication
                        .abort("stage preservation arming", error)
                        .to_string(),
                );
            }
            let staged = (|| -> Result<(String, ShadowImportOutcome), DynError> {
                if resolved_project != project {
                    return Err(format!(
                "ASTRO_SHADOW_PROJECT_MISMATCH: staged index resolved project {resolved_project:?}, expected {project:?}; remediation: pass one canonical repo_path/project identity and retry"
            )
            .into());
                }
                publication.checkpoint_stage_source()?;
                // #1040: the staged store is durable and quiescent from here, and
                // nothing writes it again. Journal that fact with its exact digest
                // before the long vault import, so an external kill leaves the next
                // reconcile something it can verify and rescue instead of destroy.
                publication.journal_stage_completion()?;
                let outcome = import_shadow_vault_with_archaeology_at(ShadowImportRequest {
                    cache_dir: publication.stage_cache(),
                    project: &project,
                    row_sink,
                    search_scale_settings: &search_scale_settings,
                    similarity_config: &similarity_config,
                    repo: repo_path.as_deref(),
                    action_policy: &action_policy,
                    generation_clock,
                })?;
                Ok((result, outcome))
            })();
            let (result, outcome) = match staged {
                Ok(staged) => staged,
                Err(error) => {
                    return tool_error_result(publication.abort("staged build", error).to_string());
                }
            };
            let publish_started = std::time::Instant::now();
            let outcome = match publication.publish(
                outcome,
                dial,
                &sanitized_args,
                &index_admission_identity,
                activation_fence.as_ref(),
            ) {
                Ok(outcome) => outcome,
                Err(error) => return tool_error_result(error.to_string()),
            };
            eprintln!(
                "astro.shadow.index_phase phase=publication elapsed_ms={} total_ms={}",
                publish_started.elapsed().as_millis(),
                shadow_started.elapsed().as_millis()
            );
            let post_publish_verification = if outcome.publication_required {
                let verify_started = std::time::Instant::now();
                let receipt = match post_publish_verify_project(
                    &cache_dir,
                    &project,
                    &outcome,
                    &shadow_import_lock,
                ) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        if let Some(result) = tool_fault_result_from_error(error.as_ref()) {
                            return result;
                        }
                        return Err(error);
                    }
                };
                eprintln!(
                    "astro.shadow.index_phase phase=post_publish_verify elapsed_ms={} total_ms={}",
                    verify_started.elapsed().as_millis(),
                    shadow_started.elapsed().as_millis()
                );
                receipt
            } else {
                json!({
                    "schema": PERIODIC_VERIFY_CHAIN_SCHEMA,
                    "project": project,
                    "status": "not_required",
                    "operation": POST_PUBLISH_VERIFY_OPERATION,
                    "publication_required": false,
                    "durable_state_changed": false,
                    "reason": "the content-addressed artifact generation was not replaced",
                    "freshness": "current",
                    "trust": "verified",
                })
            };
            augment_tool_result(
                &result,
                json!({
                    "calyx": "shadow",
                    "generation_clock": outcome.generation_clock_provenance.clone(),
                    "vault_fingerprint": outcome.sqlite_fingerprint_sha256,
                    "grounding_summary": grounding_summary(&outcome)?,
                    "post_publish_verification": post_publish_verification,
                    // Never an unlabeled claim: a generation published from an
                    // adopted preserved stage says so, with its resume token (#1037).
                    "preserved_stage_resume": adoption_evidence,
                }),
            )
        },
    )
}

fn supervised_index_worker_args(
    args_json: &str,
    worker_cache: &Path,
    transition_grant: &ProjectTransitionWorkerGrant,
    generation_clock: GenerationClock,
) -> Result<String, DynError> {
    let clock_bound_args = generation_clock.bind_worker_arg(args_json)?;
    let mut value: Value = serde_json::from_str(&clock_bound_args)?;
    let object = value.as_object_mut().ok_or_else(|| -> DynError {
        "ASTRO_INDEX_WORKER_ARGS_OBJECT_REQUIRED: sanitized index arguments must remain a JSON object"
            .into()
    })?;
    for private_arg in [
        crate::ASTRO_INDEX_WORKER_CACHE_DIR_ARG,
        crate::ASTRO_INDEX_WORKER_TRANSITION_GRANT_ARG,
    ] {
        if !object.contains_key(private_arg) {
            continue;
        }
        return Err(format!(
            "ASTRO_INDEX_WORKER_PRIVATE_ARG_COLLISION: caller supplied reserved argument {:?}; remediation: remove that private transport field",
            private_arg
        )
        .into());
    }
    let worker_cache_text = worker_cache.to_str().ok_or_else(|| -> DynError {
        format!(
            "ASTRO_INDEX_WORKER_CACHE_PATH_NOT_UTF8: transaction cache path is not UTF-8: {}",
            worker_cache.display()
        )
        .into()
    })?;
    object.insert(
        crate::ASTRO_INDEX_WORKER_CACHE_DIR_ARG.to_string(),
        Value::String(worker_cache_text.to_string()),
    );
    object.insert(
        crate::ASTRO_INDEX_WORKER_TRANSITION_GRANT_ARG.to_string(),
        transition_grant.for_worker_cache(worker_cache)?,
    );
    Ok(serde_json::to_string(&value)?)
}

/// Move a shadow worker's declared full skip log out of its transaction stage
/// before successful publication removes that stage (#1024).
///
/// The C indexer writes the complete, uncapped outcome inventory beneath its
/// active cache. A shadow worker's active cache is transaction-owned, so leaving
/// the reported path untouched makes a successful response point at bytes that
/// publication immediately deletes. Promotion is one same-volume rename followed
/// by an independent read/hash over the already-produced log; it performs no
/// repository, SQLite, or vault traversal (PC-32/37/38/41).
fn promote_shadow_skip_log(
    result: &str,
    stage_cache: &Path,
    live_cache: &Path,
    project: &str,
) -> Result<String, DynError> {
    let envelope: Value = serde_json::from_str(result)?;
    let structured_path = envelope
        .get("structuredContent")
        .and_then(|value| value.get("logfile"))
        .and_then(Value::as_str);
    let text_payload = envelope
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .map(serde_json::from_str::<Value>)
        .transpose()?;
    let text_path = text_payload
        .as_ref()
        .and_then(|value| value.get("logfile"))
        .and_then(Value::as_str);
    let reported = match (structured_path, text_path) {
        (None, None) => return Ok(result.to_string()),
        (Some(left), Some(right)) if left == right => left,
        (Some(_), Some(_)) => {
            return Err(
                "ASTRO_SHADOW_INDEX_LOG_ENVELOPE_MISMATCH: structuredContent.logfile and content[0].text.logfile disagree; remediation: preserve the stage and repair the MCP mirror before retrying"
                    .into(),
            );
        }
        _ => {
            return Err(
                "ASTRO_SHADOW_INDEX_LOG_ENVELOPE_INCOMPLETE: exactly one MCP result representation declares a skip log; remediation: preserve the stage and repair the MCP mirror before retrying"
                    .into(),
            );
        }
    };

    let reported_path = PathBuf::from(reported);
    if !reported_path.is_file() {
        return Err(format!(
            "ASTRO_SHADOW_INDEX_LOG_MISSING: the completed index declared skip log {} but the file is absent; remediation: preserve the staged generation and inspect CBM log publication",
            reported_path.display()
        )
        .into());
    }
    let source_parent = reported_path.parent().ok_or_else(|| -> DynError {
        "ASTRO_SHADOW_INDEX_LOG_PARENT_MISSING: the declared skip log has no parent directory; remediation: preserve the stage and inspect CBM log path construction".into()
    })?;
    let stage_log_dir = stage_cache.join("logs");
    let live_log_dir = live_cache.join("logs");
    let canonical_parent = fs::canonicalize(source_parent)?;
    let from_stage =
        stage_log_dir.exists() && canonical_parent == fs::canonicalize(&stage_log_dir)?;
    let from_live = live_log_dir.exists() && canonical_parent == fs::canonicalize(&live_log_dir)?;
    if !from_stage && !from_live {
        return Err(format!(
            "ASTRO_SHADOW_INDEX_LOG_PATH_ESCAPE: declared skip log {} belongs to neither the exact transaction log directory {} nor live log directory {}; remediation: preserve all paths and repair worker cache binding",
            reported_path.display(),
            stage_log_dir.display(),
            live_log_dir.display()
        )
        .into());
    }

    let (source_bytes, source_sha256) = shadow_skip_log_hash(&reported_path)?;
    fs::create_dir_all(&live_log_dir)?;
    let destination = if from_live {
        reported_path.clone()
    } else {
        live_log_dir.join(format!("{project}-{source_sha256}.log"))
    };
    if from_stage {
        if destination.exists() {
            let existing = shadow_skip_log_hash(&destination)?;
            if existing != (source_bytes, source_sha256.clone()) {
                return Err(format!(
                    "ASTRO_SHADOW_INDEX_LOG_CONTENT_ADDRESS_COLLISION: existing durable log {} does not match declared stage bytes for sha256 {}; remediation: preserve both files and inspect the content-address invariant",
                    destination.display(), source_sha256
                )
                .into());
            }
        } else {
            fs::rename(&reported_path, &destination)?;
        }
    }
    let (durable_bytes, durable_sha256) = shadow_skip_log_hash(&destination)?;
    if durable_bytes != source_bytes || durable_sha256 != source_sha256 {
        return Err(format!(
            "ASTRO_SHADOW_INDEX_LOG_READBACK_MISMATCH: durable log {} disagrees with the declared stage bytes; remediation: preserve the transaction and durable log and inspect the same-volume promotion",
            destination.display()
        )
        .into());
    }
    augment_tool_result(
        result,
        json!({
            "logfile": destination,
            "logfile_bytes": durable_bytes,
            "logfile_sha256": durable_sha256,
        }),
    )
}

fn shadow_skip_log_hash(path: &Path) -> Result<(u64, String), DynError> {
    use std::io::BufRead as _;

    let mut reader = std::io::BufReader::new(fs::File::open(path)?);
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        bytes = bytes.checked_add(chunk.len() as u64).ok_or_else(|| -> DynError {
            format!(
                "ASTRO_SHADOW_INDEX_LOG_SIZE_OVERFLOW: byte count overflowed while hashing {}; remediation: preserve the log and repair the size representation",
                path.display()
            )
            .into()
        })?;
        hasher.update(chunk);
        let consumed = chunk.len();
        reader.consume(consumed);
    }
    Ok((bytes, hex_lower(&hasher.finalize())))
}

fn run_supervised_index_with_transition(
    runner: &CbmToolRunner,
    args_json: &str,
    worker_cache: &Path,
    transition_grant: &ProjectTransitionWorkerGrant,
    generation_clock: GenerationClock,
) -> Result<String, DynError> {
    let worker_args =
        supervised_index_worker_args(args_json, worker_cache, transition_grant, generation_clock)?;
    Ok(runner.handle_index_repository_supervised(&worker_args)?)
}

pub(crate) fn handle_index_status(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let args = match serde_json::from_str::<Value>(args_json) {
        Ok(args) => args,
        Err(error) => {
            return index_status_error_result(
                "ASTRO_INDEX_STATUS_ARGS_INVALID",
                format!("index_status arguments must be valid JSON: {error}"),
                "Pass a JSON object containing project.",
                None,
                None,
            );
        }
    };
    let Some(args_obj) = args.as_object() else {
        return index_status_error_result(
            "ASTRO_INDEX_STATUS_ARGS_OBJECT_REQUIRED",
            "index_status arguments must be a JSON object.",
            "Pass {\"project\":\"<project>\"}.",
            None,
            None,
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return index_status_error_result(
            "ASTRO_INDEX_STATUS_PROJECT_REQUIRED",
            "index_status requires project.",
            "Pass project, project_name, project_id, or projectName.",
            None,
            None,
        );
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        let result = runner.handle_tool_raw("index_status", args_json)?;
        if tool_result_is_error(&result)? {
            return index_status_error_result(
                "ASTRO_INDEX_STATUS_PROJECT_NOT_FOUND",
                format!(
                    "index_status could not read project {project:?}: {}",
                    tool_result_primary_text(&result).unwrap_or_else(|| result.clone())
                ),
                "Index the project first with calyx=\"shadow\" or pass the exact persisted project identifier.",
                Some(&project),
                None,
            );
        }
        return Ok(result);
    }

    let summary = match shadow_status_summary(&project) {
        Ok(summary) => summary,
        Err(error) => {
            let cause = error.to_string();
            return index_status_error_result(
                index_status_shadow_error_code(&cause),
                format!("index_status shadow summary failed for project {project:?}: {cause}"),
                "Inspect the named persisted shadow surface/config row, preserve the generation, and rerun index_repository with calyx=\"shadow\" from the authoritative source.",
                Some(&project),
                Some(cause),
            );
        }
    };
    tool_json_result(summary)
}

fn index_status_error_result(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
    project: Option<&str>,
    cause: Option<String>,
) -> Result<String, DynError> {
    let mut error = json!({
        "schema": "astrolabe.index_status.error.v1",
        "tool": "index_status",
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "trust": "verified-error",
        "freshness": "current",
    });
    if let Some(project) = project {
        error["project"] = json!(project);
    }
    if let Some(cause) = cause {
        error["cause"] = json!(cause);
    }
    tool_json_error_result(error)
}

fn index_status_shadow_error_code(cause: &str) -> &'static str {
    if cause.contains("ASTRO_SHADOW_SURFACE_MISSING") {
        "ASTRO_INDEX_STATUS_SURFACE_MISSING"
    } else if cause.contains("ASTRO_SHADOW_SURFACE_JSON_INVALID")
        || cause.contains("ASTRO_SHADOW_SURFACE_JSON_TRAILING_BYTES")
    {
        "ASTRO_INDEX_STATUS_SURFACE_MALFORMED"
    } else {
        "ASTRO_INDEX_STATUS_SHADOW_SUMMARY_FAILED"
    }
}

fn tool_result_primary_text(result: &str) -> Option<String> {
    let value: Value = serde_json::from_str(result).ok()?;
    value
        .get("content")?
        .as_array()?
        .iter()
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .find(|text| !text.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn architecture_aspect_read_failed_result(
    project: &str,
    outputs: &BTreeSet<&'static str>,
    cause: String,
) -> Result<String, DynError> {
    ToolFault::new(
        "ASTRO_ARCHITECTURE_ASPECT_READ_FAILED",
        format!(
            "get_architecture could not read the requested persisted Calyx aspect state for project {project:?}: {cause}"
        ),
        "inspect the named persisted generation and owning producer, repair or regenerate it, then retry the unchanged aspect request",
    )
    .with_detail(
        "requested_astrolabe_aspects",
        outputs.iter().copied().collect::<Vec<_>>(),
    )
    .with_detail("cause", cause)
    .into_result()
}

pub(crate) fn handle_get_architecture(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let args = match serde_json::from_str::<Value>(args_json) {
        Ok(args) => args,
        Err(error) => {
            return ToolFault::new(
                "ASTRO_ARCHITECTURE_ARGUMENTS_JSON_INVALID",
                format!("get_architecture arguments are not valid JSON: {error}"),
                "pass one JSON object matching the advertised get_architecture input schema",
            )
            .into_result();
        }
    };
    let Some(args_obj) = args.as_object() else {
        return ToolFault::new(
            "ASTRO_ARCHITECTURE_ARGUMENTS_OBJECT_REQUIRED",
            "get_architecture arguments must be a JSON object",
            "pass one JSON object matching the advertised get_architecture input schema",
        )
        .with_argument("arguments", "JSON object", &args)
        .into_result();
    };
    let plan = match ArchitectureRequestPlan::parse(args_obj) {
        Ok(plan) => plan,
        Err(fault) => {
            tracing::warn!(code = fault.code(), "mcp.get_architecture.argument_refused");
            return fault.into_result();
        }
    };
    let project = args_obj
        .get("project")
        .and_then(Value::as_str)
        .expect("ArchitectureRequestPlan validated project")
        .to_string();
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if read_dial_at(&cache_dir, &project)? != MigrationDial::Shadow {
        if plan.astrolabe_outputs.contains("signal_ranking")
            && let Err(error) = classify_preserved_signal_card_state(&cache_dir, &project)
        {
            return architecture_aspect_read_failed_result(
                &project,
                &plan.astrolabe_outputs,
                error.to_string(),
            );
        }
        if !plan.astrolabe_outputs.is_empty() {
            return ToolFault::new(
                "ASTRO_ARCHITECTURE_SHADOW_REQUIRED",
                format!(
                    "project {project:?} is not shadow-indexed, so its requested Calyx architecture aspects have no project vault"
                ),
                "run index_repository with calyx=\"shadow\" for this project, then retry the unchanged aspect request",
            )
            .with_detail(
                "requested_astrolabe_aspects",
                plan.astrolabe_outputs.iter().copied().collect::<Vec<_>>(),
            )
            .into_result();
        }
        let cbm_args = plan
            .cbm_args_json
            .as_deref()
            .expect("a request without Astrolabe aspects always retains CBM arguments");
        return Ok(runner.handle_tool_raw("get_architecture", cbm_args)?);
    }
    if let Some(refusal) = shadow_graph_freshness_refusal(&cache_dir, &project, "get_architecture")?
    {
        return Ok(refusal);
    }

    let Some(cbm_args) = plan.cbm_args_json.as_deref() else {
        let astrolabe = match read_astrolabe_architecture_aspects(
            &cache_dir,
            &project,
            &plan.astrolabe_outputs,
        ) {
            Ok(value) => value,
            Err(error) => {
                return architecture_aspect_read_failed_result(
                    &project,
                    &plan.astrolabe_outputs,
                    error.to_string(),
                );
            }
        };
        return tool_json_result(json!({
            "project": project,
            "astrolabe": astrolabe,
        }));
    };
    // In a mixed request the CBM architecture result is a prerequisite. Do not
    // open any Calyx store when that prerequisite refuses or errors (PC-13/35).
    let result = runner.handle_tool_raw("get_architecture", cbm_args)?;
    if tool_result_is_error(&result)? || plan.astrolabe_outputs.is_empty() {
        return Ok(result);
    }
    let astrolabe =
        match read_astrolabe_architecture_aspects(&cache_dir, &project, &plan.astrolabe_outputs) {
            Ok(value) => value,
            Err(error) => {
                return architecture_aspect_read_failed_result(
                    &project,
                    &plan.astrolabe_outputs,
                    error.to_string(),
                );
            }
        };
    augment_tool_result(
        &result,
        json!({
            "astrolabe": astrolabe,
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

/// Keep schema overlay routing and execution on one exact extension-key set so
/// a newly advertised knob cannot bypass Astrolabe's validator over JSON-RPC.
fn search_graph_has_astrolabe_knob(args: &Map<String, Value>) -> bool {
    SEARCH_GRAPH_ASTROLABE_ONLY_KEYS
        .iter()
        .any(|key| args.contains_key(*key))
}

fn search_graph_argument_type_error(
    argument: &str,
    expected_type: &str,
    actual: &Value,
) -> Result<String, DynError> {
    tool_json_error_result(json!({
        "code": "ASTRO_MCP_INVALID_ARGUMENT",
        "message": format!(
            "search_graph argument '{argument}' must be {expected_type}; received {}",
            json_type_name(actual)
        ),
        "remediation": "send search_graph arguments that conform to the inputSchema returned by tools/list; correct the named field's JSON type and retry",
        "argument": argument,
        "expected_type": expected_type,
        "actual_type": json_type_name(actual),
    }))
}

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

    if let Some(value) = args_obj.get("fusion")
        && !value.is_boolean()
    {
        return search_graph_argument_type_error("fusion", "a JSON boolean", value);
    }
    if let Some(value) = args_obj.get("fusion_override")
        && !value.is_object()
    {
        return search_graph_argument_type_error("fusion_override", "a JSON object", value);
    }
    if let Some(value) = args_obj.get("temporal_alpha_millis")
        && !(value.is_i64() || value.is_u64())
    {
        return search_graph_argument_type_error("temporal_alpha_millis", "a JSON integer", value);
    }
    if let Some(value) = args_obj.get("propagated_label")
        && !value.is_string()
    {
        return search_graph_argument_type_error("propagated_label", "a JSON string", value);
    }

    let shadow_project = shadow_project_requested(args_obj)?;
    let cache_dir = if shadow_project.is_some() {
        Some(astrolabe_bridge::cbm_cache_dir()?)
    } else {
        None
    };
    if let (Some(project), Some(cache_dir)) = (shadow_project.as_deref(), cache_dir.as_ref())
        && let Some(refusal) = shadow_graph_freshness_refusal(cache_dir, project, "search_graph")?
    {
        return Ok(refusal);
    }

    // #42: opt-in fused engine. Only an explicit `fusion: true` diverts from the
    // legacy path; anything else keeps the byte-identical CBM passthrough.
    if args_obj.get("fusion").and_then(Value::as_bool) == Some(true) {
        return run_fused_search_graph(args_obj);
    }

    let label_filter = string_arg(args_obj, "propagated_label").map(ToOwned::to_owned);
    let carries_astrolabe_knob = search_graph_has_astrolabe_knob(args_obj);
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

    let cache_dir = match cache_dir {
        Some(cache_dir) => cache_dir,
        None => astrolabe_bridge::cbm_cache_dir()?,
    };
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
    let subject_id = string_arg(args_obj, "subject_id");
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

fn measure_bits_transaction_read_failed_result(
    project: &str,
    mode: &str,
    cause: String,
) -> Result<String, DynError> {
    ToolFault::new(
        "ASTRO_ASSAY_SIGNAL_TRANSACTION_READ_FAILED",
        format!(
            "measure_bits refused to serve project {project:?} because its persisted Assay state could not be verified"
        ),
        "preserve _config.db and signal-cards.ndjson, inspect the exact cause field, then reindex or run the explicit #885 recovery protocol",
    )
    .with_detail("mode", mode)
    .with_detail("project", project)
    .with_detail("cause", cause)
    .into_result()
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
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if read_dial_at(&cache_dir, &project)? != MigrationDial::Shadow {
        if mode == "signals"
            && let Err(error) = classify_preserved_signal_card_state(&cache_dir, &project)
        {
            return measure_bits_transaction_read_failed_result(&project, mode, error.to_string());
        }
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
    if refresh && mode != "calibration" {
        return ToolFault::new(
            "ASTRO_MEASURE_BITS_REFRESH_UNSUPPORTED",
            format!(
                "refresh=true is implemented only for mode=calibration, received mode={mode:?}"
            ),
            format!(
                "omit refresh to read the persisted {mode} card, or use mode=calibration with refresh=true to recompute and persist calibration"
            ),
        )
        .with_detail("mode", mode)
        .with_detail("refresh", true)
        .into_result();
    }
    let value = match measure_bits_json_at(&cache_dir, &project, mode, axis, scope, refresh) {
        Ok(value) => value,
        Err(error) => {
            return measure_bits_transaction_read_failed_result(&project, mode, error.to_string());
        }
    };
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
