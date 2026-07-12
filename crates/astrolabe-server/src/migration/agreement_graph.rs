//! `get_architecture` agreement-graph aspect wiring (#231).
//!
//! Thin server surface over `astrolabe_weave::agreement_graph_aspect`: opens the
//! persisted shadow vault read-only, recomputes the six designed-pair agreement
//! edges from persisted XTerm CF rows, and returns the aspect payload with its
//! HONEST grounding labels intact. All graph logic and its edge-triad FSV tests
//! live in `astrolabe-weave`; this module only reads persisted state and shapes
//! the response. It never zero-fills an absent edge and fails closed on any
//! corrupt persisted row (surfacing the labeled unavailable payload rather than
//! a partial graph).

use super::*;

/// Reads the agreement-graph aspect from the persisted shadow vault.
///
/// Returns a labeled `unavailable` payload (freshness `not_evaluated`, trust
/// `provisional`, with a reason and remediation) when the shadow vault is
/// absent or a persisted row is corrupt — never a silent or partial graph.
pub(crate) fn read_agreement_graph_aspect(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(agreement_graph_unavailable_json(
            "shadow vault absent; rerun index_repository with calyx=\"shadow\" before requesting the agreement-graph aspect",
        ));
    }
    let vault = match open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::XTerm],
    ) {
        Ok(vault) => vault,
        Err(error) => {
            return Ok(agreement_graph_unavailable_json(&format!(
                "shadow vault open failed: {error}"
            )));
        }
    };
    let aspect = match astrolabe_weave::agreement_graph_aspect(&vault) {
        Ok(aspect) => aspect,
        Err(error) => {
            return Ok(agreement_graph_unavailable_json(&format!(
                "{}: {}; remediation: {}",
                error.code, error.message, error.remediation
            )));
        }
    };
    let mut value = serde_json::to_value(&aspect)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "source_state".to_string(),
            json!({
                "source": astrolabe_weave::AGREEMENT_GRAPH_ASPECT_PROVENANCE,
                "vault_dir": vault_dir,
                "freshness": "fresh",
                "trust": "verified",
            }),
        );
    }
    Ok(value)
}

/// Labeled fail-closed payload for an agreement-graph aspect that could not be
/// recomputed from persisted state.
pub(crate) fn agreement_graph_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": astrolabe_weave::AGREEMENT_GRAPH_ASPECT_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "provenance": astrolabe_weave::AGREEMENT_GRAPH_ASPECT_PROVENANCE,
        "reason": reason,
        "remediation": "rerun index_repository with calyx=\"shadow\" and persisted eager cross-terms before requesting the agreement-graph aspect",
    })
}
