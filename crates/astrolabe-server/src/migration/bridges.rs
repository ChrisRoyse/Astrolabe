use super::*;
pub(crate) const BRIDGE_COLLECTION_SCHEMA: &str = "astrolabe.bridge_collection.v1";

pub(crate) fn bridges_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let (scopes, skipped_properties) = bridge_scope_kernels_from_rows(rows);
    if scopes.len() < 2 {
        return bridges_unavailable_json(
            "bridge scope metadata missing; row-sink nodes must declare bridge_scopes/scopes for at least two scopes",
        );
    }
    if scopes.len() > 16 {
        return bridges_unavailable_json(
            "bridge scope metadata declared more than 16 scopes; use an explicit bridge scope query before materializing pairwise reports",
        );
    }

    let scope_ids = scopes.keys().cloned().collect::<Vec<_>>();
    let mut reports = Vec::new();
    for left_index in 0..scope_ids.len() {
        for right_index in (left_index + 1)..scope_ids.len() {
            let left = scopes
                .get(&scope_ids[left_index])
                .expect("scope id from map");
            let right = scopes
                .get(&scope_ids[right_index])
                .expect("scope id from map");
            reports.push(bridge_symbols(left, right));
        }
    }

    bridges_json(&reports, skipped_properties)
}

pub(crate) fn bridge_scope_kernels_from_rows(
    rows: &CbmPipelineRows,
) -> (BTreeMap<String, BridgeScopeKernel>, usize) {
    let fingerprint = hex_lower(&row_sink_fingerprint(rows));
    let mut by_scope = BTreeMap::<String, Vec<BridgeKernelSymbol>>::new();
    let mut grounded_by_scope = BTreeMap::<String, bool>::new();
    let mut skipped_properties = 0;

    for node in &rows.nodes {
        if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
            continue;
        }
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        let scopes = bridge_scopes_for_node(&properties);
        if scopes.is_empty() {
            continue;
        }
        let node_grounded = properties
            .get("kernel_grounded")
            .or_else(|| properties.get("grounded"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        for scope in scopes {
            let weight = bridge_node_kernel_weight(&properties, &scope);
            let provenance = bridge_node_provenance(node, &properties, &scope);
            by_scope
                .entry(scope.clone())
                .or_default()
                .push(BridgeKernelSymbol::new(
                    node.qualified_name.clone(),
                    node.qualified_name.clone(),
                    weight,
                    provenance,
                ));
            grounded_by_scope
                .entry(scope)
                .and_modify(|grounded| *grounded = *grounded && node_grounded)
                .or_insert(node_grounded);
        }
    }

    let scopes = by_scope
        .into_iter()
        .map(|(scope_id, symbols)| {
            let grounded = grounded_by_scope.get(&scope_id).copied().unwrap_or(false);
            (
                scope_id.clone(),
                BridgeScopeKernel::new(
                    scope_id.clone(),
                    SHADOW_VAULT_ID,
                    format!("row-sink:{fingerprint}:{scope_id}"),
                    grounded,
                    symbols,
                ),
            )
        })
        .collect();
    (scopes, skipped_properties)
}

pub(crate) fn bridge_scopes_for_node(properties: &Value) -> Vec<String> {
    let mut scopes = BTreeSet::new();
    for field in ["bridge_scopes", "astrolabe_scopes", "scope_ids", "scopes"] {
        if let Some(values) = properties.get(field).and_then(Value::as_array) {
            for value in values {
                if let Some(scope) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|scope| !scope.is_empty())
                {
                    scopes.insert(scope.to_string());
                }
            }
        }
    }
    if let Some(scope) = properties
        .get("scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
    {
        scopes.insert(scope.to_string());
    }
    scopes.into_iter().collect()
}

pub(crate) fn bridge_node_kernel_weight(properties: &Value, scope: &str) -> u64 {
    properties
        .get("kernel_weights")
        .and_then(Value::as_object)
        .and_then(|weights| weights.get(scope))
        .and_then(Value::as_u64)
        .or_else(|| properties.get("kernel_weight").and_then(Value::as_u64))
        .filter(|weight| *weight > 0)
        .unwrap_or(1)
}

pub(crate) fn bridge_node_provenance(
    node: &astrolabe_bridge::CbmPipelineNodeRow,
    properties: &Value,
    scope: &str,
) -> String {
    properties
        .get("bridge_scope_provenance")
        .and_then(Value::as_object)
        .and_then(|provenance| provenance.get(scope))
        .and_then(Value::as_str)
        .or_else(|| properties.get("provenance_ref").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("row_sink:{}:{}#scope:{scope}", node.project, node.id))
}

pub(crate) fn bridges_json(reports: &[BridgeReport], skipped_properties: usize) -> Value {
    let mut artifact_bytes = Vec::new();
    for report in reports {
        artifact_bytes.extend(bridge_report_artifact_bytes(report));
    }
    let bridge_count = reports
        .iter()
        .map(|report| report.bridges.len())
        .sum::<usize>();
    let all_verified =
        skipped_properties == 0 && reports.iter().all(|report| report.trust == "verified");
    json!({
        "schema": BRIDGE_COLLECTION_SCHEMA,
        "report_schema": BRIDGE_SCHEMA,
        "status": if skipped_properties == 0 { "built" } else { "partial" },
        "scope_source": "row_sink_explicit_bridge_scopes",
        "scope_pair_count": reports.len(),
        "bridge_count": bridge_count,
        "skipped_count": skipped_properties,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "reports": reports.iter().map(bridge_report_json).collect::<Vec<_>>(),
        "freshness": "fresh",
        "trust": if all_verified { "verified" } else { "provisional" },
    })
}

pub(crate) fn bridge_report_json(report: &BridgeReport) -> Value {
    json!({
        "schema": report.schema,
        "scope_a": report.scope_a,
        "scope_b": report.scope_b,
        "cache_key": report.cache_key,
        "bridge_count": report.bridges.len(),
        "bridges": report.bridges.iter().map(|bridge| {
            json!({
                "symbol_id": bridge.symbol_id,
                "qualified_name": bridge.qualified_name,
                "combined_kernel_weight": bridge.combined_kernel_weight,
                "scope_a_kernel_weight": bridge.scope_a_kernel_weight,
                "scope_b_kernel_weight": bridge.scope_b_kernel_weight,
                "provenance": {
                    "scope_a": bridge.provenance.scope_a,
                    "scope_b": bridge.provenance.scope_b,
                },
                "freshness": bridge.freshness,
                "trust": bridge.trust,
            })
        }).collect::<Vec<_>>(),
        "freshness": report.freshness,
        "trust": report.trust,
    })
}

pub(crate) fn bridges_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": BRIDGE_COLLECTION_SCHEMA,
        "report_schema": BRIDGE_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with row-sink bridge scope metadata or request a narrowed bridge scope pair before using architecture bridge aspects",
    })
}

pub(crate) fn read_bridges_metadata(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "bridge_reports_json"))?
    else {
        return Ok(bridges_unavailable_json(
            "bridge report metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(bridges_unavailable_json(&format!(
            "stored bridge_reports_json invalid: {error}"
        ))),
    }
}
