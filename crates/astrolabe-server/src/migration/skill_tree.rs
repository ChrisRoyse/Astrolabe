use super::*;

pub(crate) fn skill_tree_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let inputs = skill_inputs_from_row_sink_rows(rows);
    match build_skill_tree(&inputs, &SkillDiscoveryConfig::default()) {
        Ok(tree) => skill_tree_json(&tree),
        Err(error) => skill_tree_unavailable_json(&format!("skill discovery failed: {error}")),
    }
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

pub(crate) fn skill_tokens_for_node(node: &astrolabe_bridge::CbmPipelineNodeRow) -> BTreeSet<String> {
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

pub(crate) fn skill_tree_json(tree: &SkillTree) -> Value {
    let artifact_bytes = skill_tree_artifact_bytes(tree);
    json!({
        "schema": tree.schema,
        "status": "built",
        "knob_registry_version": tree.knob_registry_version,
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
