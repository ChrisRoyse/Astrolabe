use super::*;

use astrolabe_oracle::{OracleEvidence, PredictConfig, grounded_risk};

/// Envelope schema for the grounded-risk block layered onto `detect_changes`.
pub(crate) const DETECT_CHANGES_RISK_SCHEMA: &str = "astrolabe.detect_changes_grounded_risk.v1";

/// Runs the legacy CBM `detect_changes` and layers oracle-backed grounded risk
/// onto its impacted symbols (blueprint P6.3 scaffold, finalized #52).
///
/// The augmentation is strictly additive: the CBM result's legacy shape
/// (`changed_files`, `changed_count`, `impacted_symbols`, `depth`) is preserved
/// verbatim and a `grounded_risk` block is merged alongside it. For each impacted
/// symbol the oracle change→outcome corpus provides a probability-based risk when
/// grounded evidence exists; a symbol with no evidence (or a repo with no mined
/// corpus) falls back to the registry-declared provisional risk, clearly labeled
/// `trust: provisional` (HONEST invariant 3 — every degradation is labeled, never
/// silent). Any augmentation error degrades to the legacy shape with a labeled
/// `grounded_risk` block explaining why, so `detect_changes` never fails on the
/// grounding path.
pub(crate) fn handle_detect_changes_grounded_risk(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    // Always run the real CBM tool first; grounded risk is layered on additively.
    let raw = runner.handle_tool_raw("detect_changes", args_json)?;

    // A CBM error result carries no symbols to ground: return it untouched.
    if tool_result_is_error(&raw).unwrap_or(false) {
        return Ok(raw);
    }

    // Resolve the project so we can open its grounded-change vault.
    let project = serde_json::from_str::<Value>(args_json)
        .ok()
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|obj| status_project_from_args(obj).ok().flatten());
    let Some(project) = project else {
        return augment_tool_result(
            &raw,
            ungrounded_block("no project argument; cannot resolve a grounded-change vault"),
        );
    };

    match grounded_risk_block(&project, &raw) {
        Ok(block) => augment_tool_result(&raw, block),
        Err(error) => augment_tool_result(
            &raw,
            ungrounded_block(&format!("grounded-risk augmentation unavailable: {error}")),
        ),
    }
}

/// Builds the grounded-risk block for a shadow-indexed project by reading the
/// oracle occurrence corpus and the node map back from the persisted vault.
fn grounded_risk_block(project: &str, raw: &str) -> Result<Value, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(&cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(ungrounded_block(
            "shadow vault missing; run index_repository with calyx=\"shadow\" before grounding risk",
        ));
    }

    // FSV read path: the evidence index and node map are reconstructed from the
    // durable Kv/Graph CF rows, never from an in-memory planner echo.
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Kv, ColumnFamily::Graph],
    )?;
    let evidence = OracleEvidence::from_vault(&vault)?;
    let node_map = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;
    drop(vault);

    let config = PredictConfig::default();
    let fallback = config.provisional_fallback_risk();
    let ceiling = config.served_ceiling();

    let mut symbols = Vec::new();
    let mut grounded_count = 0usize;
    let mut all_trusted = true;
    for name in impacted_symbol_names(raw) {
        let (risk_value, trust, grounded, evidence_n) = match node_map.get(&name) {
            Some(cx) => {
                // Oracle-backed probability replaces the structural fallback.
                let risk = grounded_risk(&evidence, *cx, fallback, &config)?;
                if risk.grounded {
                    grounded_count += 1;
                }
                (
                    risk.risk,
                    risk.trust.as_str(),
                    risk.grounded,
                    risk.evidence_n,
                )
            }
            // Unresolved symbol (name not in the node map): provisional fallback.
            None => (fallback, "provisional", false, 0usize),
        };
        if trust != "trusted" {
            all_trusted = false;
        }
        symbols.push(json!({
            "symbol": name,
            "risk": risk_value,
            "ceiling": ceiling,
            "trust": trust,
            "grounded": grounded,
            "evidence_occurrences": evidence_n,
        }));
    }

    let status = if grounded_count > 0 {
        "grounded"
    } else {
        "ungrounded"
    };
    let block_trust = if !symbols.is_empty() && all_trusted {
        "trusted"
    } else {
        "provisional"
    };
    Ok(json!({
        "grounded_risk": {
            "schema": DETECT_CHANGES_RISK_SCHEMA,
            "status": status,
            "grounded_symbol_count": grounded_count,
            "symbol_count": symbols.len(),
            "symbols": symbols,
            "trust": block_trust,
            "freshness": "fresh",
            "provenance": [
                format!("oracle-corpus:project={project}"),
                "vault:ColumnFamily::Kv+Graph".to_string(),
            ],
        }
    }))
}

/// A labeled fallback grounded-risk block for the ungrounded/unavailable path.
fn ungrounded_block(reason: &str) -> Value {
    json!({
        "grounded_risk": {
            "schema": DETECT_CHANGES_RISK_SCHEMA,
            "status": "ungrounded",
            "grounded_symbol_count": 0,
            "symbol_count": 0,
            "symbols": [],
            "trust": "provisional",
            "freshness": "fresh",
            "reason": reason,
            "provenance": ["fallback:no-grounded-evidence"],
        }
    })
}

/// Extracts the impacted symbol names from a CBM `detect_changes` result.
///
/// The CBM tool returns an MCP text-result envelope whose `content[0].text` (or
/// `structuredContent`, when present) holds the inner object with the
/// `impacted_symbols` array; each element carries a `name`. Names are returned
/// deduplicated and sorted so the augmentation is deterministic.
fn impacted_symbol_names(raw: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let inner = value.get("structuredContent").cloned().or_else(|| {
        value
            .get("content")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
    });
    let Some(inner) = inner else {
        return Vec::new();
    };
    let mut names = Vec::new();
    if let Some(array) = inner.get("impacted_symbols").and_then(Value::as_array) {
        for item in array {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && !name.is_empty()
            {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbm_result(impacted: &[&str]) -> String {
        let symbols: Vec<Value> = impacted
            .iter()
            .map(|name| json!({"name": name, "label": "Function", "file": "src/lib.rs"}))
            .collect();
        let inner = json!({
            "changed_files": ["src/lib.rs"],
            "changed_count": 1,
            "impacted_symbols": symbols,
            "depth": 2,
        });
        serde_json::to_string(&json!({
            "content": [{"type": "text", "text": serde_json::to_string(&inner).unwrap()}],
            "isError": false,
        }))
        .unwrap()
    }

    #[test]
    fn impacted_symbol_names_parses_and_dedups_from_text_envelope() {
        let raw = cbm_result(&["beta", "alpha", "alpha"]);
        assert_eq!(impacted_symbol_names(&raw), vec!["alpha", "beta"]);
    }

    #[test]
    fn impacted_symbol_names_empty_when_no_symbols() {
        let raw = cbm_result(&[]);
        assert!(impacted_symbol_names(&raw).is_empty());
        assert!(impacted_symbol_names("not json").is_empty());
    }

    #[test]
    fn ungrounded_block_is_labeled_provisional() {
        let block = ungrounded_block("shadow vault missing");
        let risk = &block["grounded_risk"];
        assert_eq!(risk["status"], "ungrounded");
        assert_eq!(risk["trust"], "provisional");
        assert_eq!(risk["schema"], DETECT_CHANGES_RISK_SCHEMA);
        assert_eq!(risk["reason"], "shadow vault missing");
    }

    #[test]
    fn ungrounded_block_merges_and_preserves_legacy_shape() {
        // The augmentation is additive: legacy detect_changes fields survive.
        let raw = cbm_result(&["alpha"]);
        let augmented = augment_tool_result(&raw, ungrounded_block("no evidence")).unwrap();
        let value: Value = serde_json::from_str(&augmented).unwrap();
        let text = value["content"][0]["text"].as_str().unwrap();
        let inner: Value = serde_json::from_str(text).unwrap();
        // Legacy shape preserved.
        assert_eq!(inner["changed_count"], 1);
        assert!(inner["impacted_symbols"].is_array());
        // Grounded-risk block layered on, labeled provisional.
        assert_eq!(inner["grounded_risk"]["status"], "ungrounded");
        assert_eq!(inner["grounded_risk"]["trust"], "provisional");
    }
}
