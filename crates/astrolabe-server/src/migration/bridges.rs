use super::*;
pub(crate) const BRIDGE_COLLECTION_SCHEMA: &str = "astrolabe.bridge_collection.v1";

/// Upper bound on the number of scopes materialized into pairwise bridge reports.
///
/// Pairwise report materialization is O(scopes²), so a repo with many directory
/// scopes must be bounded before pairing. When more scopes carry cross-scope
/// bridge symbols than this, the scopes with the most bridge symbols are kept and
/// the remainder are dropped and disclosed as `scopes_truncated` — never silently.
pub(crate) const MAX_BRIDGE_REPORT_SCOPES: usize = 16;

pub(crate) fn bridges_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    // Prefer explicit row-sink scope metadata (planted connectors, cross-repo
    // seeds). Real corpora never carry explicit `bridge_scopes`, so fall back to
    // deriving scopes from the persisted graph: a symbol grounded in two directory
    // scopes at once (defined in one, referenced from another) is a bridge (5.11).
    let (explicit_scopes, explicit_skipped) = bridge_scope_kernels_from_rows(rows);
    let (scopes, skipped_properties, scope_source) = if explicit_scopes.len() >= 2 {
        (
            explicit_scopes,
            explicit_skipped,
            "row_sink_explicit_bridge_scopes",
        )
    } else {
        let (derived, derived_skipped) = bridge_scope_kernels_derived_from_graph(rows);
        (
            derived,
            derived_skipped,
            "graph_structural_scope_membership",
        )
    };

    let scope_count = scopes.len();
    if scope_count < 2 {
        return bridges_unavailable_json(
            "no bridge scopes available: fewer than two scopes carry a symbol grounded in another \
             scope; declare row-sink bridge_scopes metadata, or index a repository whose symbols \
             are referenced across at least two directory scopes",
        );
    }

    let (selected, scopes_truncated) = select_top_bridge_scopes(scopes, MAX_BRIDGE_REPORT_SCOPES);
    let scope_ids = selected.keys().cloned().collect::<Vec<_>>();
    let mut reports = Vec::new();
    for left_index in 0..scope_ids.len() {
        for right_index in (left_index + 1)..scope_ids.len() {
            let left = selected
                .get(&scope_ids[left_index])
                .expect("scope id from map");
            let right = selected
                .get(&scope_ids[right_index])
                .expect("scope id from map");
            reports.push(bridge_symbols(left, right));
        }
    }

    bridges_json(
        &reports,
        skipped_properties,
        scope_source,
        scope_count,
        scopes_truncated,
    )
}

/// Keeps the `max` scopes carrying the most bridge symbols and returns how many
/// were dropped, so pairwise materialization stays O(max²) on a repo with many
/// directory scopes. Ranking is deterministic (member count desc, then scope id)
/// and the retained scopes are returned key-sorted so pairing order is stable and
/// worker-count invariant.
pub(crate) fn select_top_bridge_scopes(
    scopes: BTreeMap<String, BridgeScopeKernel>,
    max: usize,
) -> (BTreeMap<String, BridgeScopeKernel>, usize) {
    if scopes.len() <= max {
        return (scopes, 0);
    }
    let total = scopes.len();
    let mut ranked = scopes.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|(left_id, left), (right_id, right)| {
        right
            .symbols
            .len()
            .cmp(&left.symbols.len())
            .then_with(|| left_id.cmp(right_id))
    });
    ranked.truncate(max);
    let dropped = total - ranked.len();
    (ranked.into_iter().collect(), dropped)
}

/// Derives bridge-scope kernels from the persisted graph structure alone (#388).
///
/// A "scope" is the first [`astrolabe_domain::knobs::bridge_scope_path_depth`]
/// root-relative directory components of a symbol's file (the shared repo root is
/// stripped so scopes are rooted identically whether the row-sink recorded
/// absolute or repo-relative paths). A symbol node grounds its own home scope plus
/// every scope a *reference* edge (a call/import/impl, never structural
/// containment) reaches it from; a symbol grounded in ≥2 scopes is a bridge
/// candidate and is placed in each grounding scope's kernel with a weight equal to
/// the number of structural associations tying it to that scope. Every input is a
/// real graph fact, so nothing is skipped (returns `0`).
pub(crate) fn bridge_scope_kernels_derived_from_graph(
    rows: &CbmPipelineRows,
) -> (BTreeMap<String, BridgeScopeKernel>, usize) {
    let fingerprint = hex_lower(&row_sink_fingerprint(rows));

    // Eligible symbol nodes (named, non-project, file-anchored) and their file's
    // directory components.
    let mut dir_components_by_node: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    let mut node_by_id: BTreeMap<i64, &astrolabe_bridge::CbmPipelineNodeRow> = BTreeMap::new();
    for node in &rows.nodes {
        if node.qualified_name.trim().is_empty()
            || node.label.eq_ignore_ascii_case("project")
            || node.file_path.trim().is_empty()
        {
            continue;
        }
        dir_components_by_node.insert(node.id, file_dir_components(&node.file_path));
        node_by_id.insert(node.id, node);
    }
    if node_by_id.len() < 2 {
        return (BTreeMap::new(), 0);
    }

    // Strip the shared repo-root prefix so scopes are root-independent.
    let prefix_len = common_prefix_len(dir_components_by_node.values());
    let depth = astrolabe_domain::knobs::bridge_scope_path_depth();
    let home_scope: BTreeMap<i64, String> = dir_components_by_node
        .iter()
        .map(|(id, components)| {
            (
                *id,
                scope_from_dir_components(components, prefix_len, depth),
            )
        })
        .collect();

    // Per symbol: scope -> weight. Seed each symbol's home scope with the
    // definition (weight 1); each cross-scope reference edge adds the caller's
    // scope with a reference-count weight.
    let mut scopes_by_node: BTreeMap<i64, BTreeMap<String, u64>> = BTreeMap::new();
    for (id, scope) in &home_scope {
        let mut weights = BTreeMap::new();
        weights.insert(scope.clone(), 1u64);
        scopes_by_node.insert(*id, weights);
    }
    for edge in &rows.edges {
        if !is_bridge_reference_edge(&edge.edge_type) {
            continue;
        }
        let Some(caller_scope) = home_scope.get(&edge.source_id) else {
            continue;
        };
        let Some(callee_scopes) = scopes_by_node.get_mut(&edge.target_id) else {
            continue;
        };
        *callee_scopes.entry(caller_scope.clone()).or_insert(0) += 1;
    }

    // A symbol grounded in ≥2 scopes is a bridge candidate; place it in each.
    let mut by_scope: BTreeMap<String, Vec<BridgeKernelSymbol>> = BTreeMap::new();
    for (id, scope_weights) in &scopes_by_node {
        if scope_weights.len() < 2 {
            continue;
        }
        let node = node_by_id.get(id).expect("eligible node id");
        for (scope, weight) in scope_weights {
            by_scope
                .entry(scope.clone())
                .or_default()
                .push(BridgeKernelSymbol::new(
                    node.qualified_name.clone(),
                    node.qualified_name.clone(),
                    *weight,
                    format!("row_sink_graph:{}:{}#scope:{scope}", node.project, node.id),
                ));
        }
    }

    let scopes = by_scope
        .into_iter()
        .map(|(scope_id, symbols)| {
            (
                scope_id.clone(),
                BridgeScopeKernel::new(
                    scope_id.clone(),
                    SHADOW_VAULT_ID,
                    format!("row-sink-graph:{fingerprint}:{scope_id}"),
                    // Every member is a real file-anchored symbol tied to this scope
                    // by real edges, so the scope's structural membership is grounded.
                    true,
                    symbols,
                ),
            )
        })
        .collect();
    (scopes, 0)
}

/// True when `edge_type` expresses a cross-domain *reference* (a caller using a
/// symbol) rather than structural containment or definition nesting.
///
/// Containment/definition edges (`CONTAINS*`, `DEFINES*`) nest a symbol inside its
/// own file or directory; counting them would make every symbol a trivial bridge
/// to its own home scope. Only usage edges — any `*CALLS` variant plus `IMPORTS`,
/// `IMPLEMENTS`, `EXTENDS`, `USES`, `REFERENCES`, `SEMANTICALLY_RELATED` — ground a
/// symbol in a *caller's* scope and can therefore reveal a real cross-domain span.
pub(crate) fn is_bridge_reference_edge(edge_type: &str) -> bool {
    let edge = edge_type.trim().to_ascii_uppercase();
    if edge.is_empty() || edge.starts_with("CONTAINS") || edge.starts_with("DEFINES") {
        return false;
    }
    edge == "CALL"
        || edge.ends_with("CALLS")
        || edge == "IMPORTS"
        || edge == "IMPLEMENTS"
        || edge == "EXTENDS"
        || edge == "USES"
        || edge == "REFERENCES"
        || edge == "SEMANTICALLY_RELATED"
}

/// The directory components of a file path (all components except the filename),
/// with `/` and `\` both treated as separators and empty / `.` / drive-letter
/// (`C:`) components dropped. A path with no directory part yields an empty vec.
pub(crate) fn file_dir_components(file_path: &str) -> Vec<String> {
    let mut components = file_path
        .split(['/', '\\'])
        .map(str::trim)
        .filter(|component| {
            !component.is_empty()
                && *component != "."
                && !(component.len() == 2
                    && component.ends_with(':')
                    && component.starts_with(|c: char| c.is_ascii_alphabetic()))
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    // Drop the filename (last component); the remainder is the containing directory.
    components.pop();
    components
}

/// The length of the longest shared leading run of directory components across
/// every eligible node, so the common repo root is stripped before scoping.
pub(crate) fn common_prefix_len<'a, I>(dir_components: I) -> usize
where
    I: IntoIterator<Item = &'a Vec<String>>,
{
    let mut iter = dir_components.into_iter();
    let Some(first) = iter.next() else {
        return 0;
    };
    let mut prefix = first.clone();
    for components in iter {
        let shared = prefix
            .iter()
            .zip(components.iter())
            .take_while(|(left, right)| left == right)
            .count();
        prefix.truncate(shared);
        if prefix.is_empty() {
            return 0;
        }
    }
    prefix.len()
}

/// The scope id for a node: the first `depth` root-relative directory components
/// (after stripping the shared `prefix_len`), joined with `/`. A file sitting at
/// the shared root has no distinguishing directory, so it maps to `<root>`.
pub(crate) fn scope_from_dir_components(
    dir_components: &[String],
    prefix_len: usize,
    depth: usize,
) -> String {
    let relative = dir_components.get(prefix_len..).unwrap_or(&[]);
    if relative.is_empty() {
        return "<root>".to_string();
    }
    let take = depth.min(relative.len());
    relative[..take].join("/")
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

pub(crate) fn bridges_json(
    reports: &[BridgeReport],
    skipped_properties: usize,
    scope_source: &str,
    scope_count: usize,
    scopes_truncated: usize,
) -> Value {
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
        "scope_source": scope_source,
        "scope_count": scope_count,
        "scopes_truncated": scopes_truncated,
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
