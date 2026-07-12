use super::*;

/// Operator override for the registry-declared skill-discovery knobs (#198).
///
/// Only knobs an operator may legitimately tune are exposed. Bounds are deliberately **not**
/// re-declared here: they live in the `astrolabe-kernel` knob registry, which stays the
/// single source of truth for `skills.discovery.max_symbols`.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct SkillDiscoveryOverride {
    /// `skills.discovery.max_symbols` — the node-limit guard on the O(n²) discovery sweep.
    pub(crate) max_symbols: Option<u64>,
}

/// Parses the `calyx_skills` request object on `index_repository`.
///
/// An unknown field or a non-integer value is rejected outright. A numerically out-of-bounds
/// `max_symbols` is passed through unchanged to the kernel's registry validation, which
/// refuses it with `ASTRO_SKILL_DISCOVERY_KNOB_RANGE`. Out-of-range values are never clamped
/// to the nearest bound: clamping is a silent fallback that would leave the operator
/// believing they had raised the cap while the run quietly enforced a different one.
pub(crate) fn parse_skill_discovery_override(
    args: &Map<String, Value>,
) -> Result<Option<SkillDiscoveryOverride>, String> {
    let Some(value) = args.get("calyx_skills") else {
        return Ok(None);
    };
    let obj = value
        .as_object()
        .ok_or_else(|| "calyx_skills must be a JSON object".to_string())?;
    for key in obj.keys() {
        if key.as_str() != "max_symbols" {
            return Err(format!(
                "unknown calyx_skills field {key:?}; expected max_symbols"
            ));
        }
    }
    let max_symbols =
        match obj.get("max_symbols") {
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                "calyx_skills.max_symbols must be an unsigned integer".to_string()
            })?),
            None => None,
        };
    Ok(Some(SkillDiscoveryOverride { max_symbols }))
}

/// Builds the skill-discovery config for an import: registry defaults, with any operator
/// override applied verbatim.
///
/// A value outside the registered bounds is carried through unchanged so `build_skill_tree`
/// refuses it — it is never clamped into range.
pub(crate) fn skill_discovery_config(
    request: Option<&SkillDiscoveryOverride>,
) -> SkillDiscoveryConfig {
    let mut config = SkillDiscoveryConfig::default();
    if let Some(max_symbols) = request.and_then(|request| request.max_symbols) {
        config.max_symbols = max_symbols;
    }
    config
}

// Default-config convenience wrapper used only by tests; every production caller
// passes an explicit SkillDiscoveryConfig via *_with_config below, so this is gated
// to test builds rather than shipped as dead code (invariant 6).
#[cfg(test)]
pub(crate) fn skill_tree_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    skill_tree_from_row_sink_rows_with_config(rows, &SkillDiscoveryConfig::default())
}

/// Runs skill discovery over the row-sink rows under `config` (#198).
///
/// A kernel refusal is surfaced with its `{code, message, remediation}` intact. Flattening it
/// into an uncoded "unavailable" reason string — as this path previously did — stripped the
/// operator's path to acting on it: `ASTRO_SKILL_DISCOVERY_NODE_LIMIT` is remediable by
/// raising `skills.discovery.max_symbols` within its registered bounds, but only if the
/// caller can see the code and the remediation.
pub(crate) fn skill_tree_from_row_sink_rows_with_config(
    rows: &CbmPipelineRows,
    config: &SkillDiscoveryConfig,
) -> Value {
    let inputs = skill_inputs_from_row_sink_rows(rows);
    match build_skill_tree(&inputs, config) {
        Ok(tree) => skill_tree_json(&tree, config),
        Err(error) => skill_tree_refused_json(&error, config),
    }
}

/// Fail-closed skill-tree surface carrying the kernel's coded refusal verbatim (#198).
pub(crate) fn skill_tree_refused_json(
    error: &astrolabe_domain::DomainError,
    config: &SkillDiscoveryConfig,
) -> Value {
    json!({
        "schema": SKILL_TREE_SCHEMA,
        "status": "refused",
        "knob_registry_version": SKILL_DISCOVERY_KNOB_REGISTRY_VERSION,
        "max_symbols": config.max_symbols,
        "code": error.code(),
        "message": error.message(),
        "remediation": error.remediation(),
        "skill_count": Value::Null,
        "noise_count": Value::Null,
        "skills": [],
        "noise_symbols": [],
        "freshness": "not_evaluated",
        "trust": "provisional",
    })
}

pub(crate) fn skill_inputs_from_row_sink_rows(rows: &CbmPipelineRows) -> Vec<SkillSymbolInput> {
    rows.nodes
        .iter()
        .filter(|node| !node.qualified_name.trim().is_empty())
        .filter(|node| !node.label.eq_ignore_ascii_case("project"))
        .filter_map(|node| {
            let tokens = skill_tokens_for_node(node);
            if tokens.is_empty() {
                return None;
            }
            Some(SkillSymbolInput::new(
                node.qualified_name.clone(),
                node.qualified_name.clone(),
                node.file_path.clone(),
                tokens,
            ))
        })
        .collect()
}

pub(crate) fn skill_tokens_for_node(
    node: &astrolabe_bridge::CbmPipelineNodeRow,
) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    push_skill_tokens(&mut tokens, &node.name);
    push_skill_tokens(&mut tokens, &node.file_path);
    if let Ok(properties) = serde_json::from_str::<Value>(&node.properties_json) {
        for field in ["docstring", "signature", "route_path"] {
            if let Some(value) = properties.get(field).and_then(Value::as_str) {
                push_skill_tokens(&mut tokens, value);
            }
        }
        for field in ["param_names", "decorators"] {
            if let Some(values) = properties.get(field).and_then(Value::as_array) {
                for value in values {
                    if let Some(value) = value.as_str() {
                        push_skill_tokens(&mut tokens, value);
                    }
                }
            }
        }
    }
    tokens
}

pub(crate) fn push_skill_tokens(tokens: &mut BTreeSet<String>, text: &str) {
    for token in text
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
    {
        if token.len() >= 2 {
            tokens.insert(token);
        }
    }
}

pub(crate) fn skill_tree_json(tree: &SkillTree, config: &SkillDiscoveryConfig) -> Value {
    let artifact_bytes = skill_tree_artifact_bytes(tree);
    json!({
        "schema": tree.schema,
        "status": "built",
        "knob_registry_version": tree.knob_registry_version,
        // The node-limit bound this run actually enforced, so an operator reads back which
        // cap admitted the tree instead of assuming the registry default was in force.
        "max_symbols": config.max_symbols,
        "skill_count": tree.skills.len(),
        "noise_count": tree.noise_symbols.len(),
        "membership_hash": tree.membership_hash,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "skills": tree.skills.iter().map(skill_node_json).collect::<Vec<_>>(),
        "noise_symbols": tree.noise_symbols,
        "freshness": tree.freshness,
        "trust": tree.trust,
    })
}

pub(crate) fn skill_node_json(skill: &astrolabe_kernel::SkillNode) -> Value {
    json!({
        "skill_id": skill.skill_id,
        "name": skill.name,
        "members": skill.members,
        "exemplar_tokens": skill.exemplar_tokens,
        "membership_hash": skill.membership_hash,
    })
}

pub(crate) fn skill_tree_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": SKILL_TREE_SCHEMA,
        "status": "unavailable",
        "knob_registry_version": SKILL_DISCOVERY_KNOB_REGISTRY_VERSION,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with row-sink metadata available before using skill-scoped search or architecture skill aspects",
    })
}

pub(crate) fn read_skill_tree_metadata(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "skill_tree_json"))? else {
        return Ok(skill_tree_unavailable_json(
            "skill tree metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(skill_tree_unavailable_json(&format!(
            "stored skill_tree_json invalid: {error}"
        ))),
    }
}
