use super::*;

pub(crate) fn optimizer_propose_json_at(
    cache_dir: &Path,
    project: &str,
    astrolabe_anneal_env: Option<&str>,
) -> Result<Value, DynError> {
    let kill_switch = optimizer_kill_switch_json(astrolabe_anneal_env);
    if kill_switch["global_freeze"].as_bool().unwrap_or(false) {
        return Ok(optimizer_propose_refused_json(
            project,
            "ASTRO_OPTIMIZER_PROPOSE_FROZEN",
            "ASTRO_ANNEAL=0 freezes optimizer proposal generation",
            "unset ASTRO_ANNEAL or set it to a non-zero value before retrying mode=\"propose\"",
            "process_env:ASTRO_ANNEAL",
            "verified",
        ));
    }

    let frozen_knobs = optimizer_freeze_status_json(cache_dir, project, false)?;
    if let Some(reason) = optimizer_freezes_block_propose(&frozen_knobs) {
        return Ok(optimizer_propose_refused_json(
            project,
            "ASTRO_OPTIMIZER_PROPOSE_KNOB_FROZEN",
            reason,
            "remove or narrow the proposal-generation freeze before retrying mode=\"propose\"",
            format!("config:{}", metadata_key(project, "optimizer_freezes_json")),
            "verified",
        ));
    }

    let deficits_key = metadata_key(project, "optimizer_deficits_json");
    let proposals_key = metadata_key(project, "optimizer_proposals_json");
    let Some(raw_deficits) = read_config_value(cache_dir, &deficits_key)? else {
        return Ok(optimizer_propose_refused_json(
            project,
            "ASTRO_OPTIMIZER_PROPOSE_DEFICITS_MISSING",
            "optimizer_deficits_json is not persisted for this project",
            "run measure_bits sufficiency and persist measured optimizer deficits before retrying mode=\"propose\"",
            format!("config:{deficits_key}:missing"),
            "verified",
        ));
    };
    let deficits_value = match serde_json::from_str::<Value>(&raw_deficits) {
        Ok(value) => value,
        Err(error) => {
            return Ok(optimizer_propose_refused_json(
                project,
                "ASTRO_OPTIMIZER_PROPOSE_DEFICITS_INVALID",
                format!("stored optimizer_deficits_json invalid: {error}"),
                "repair optimizer_deficits_json before retrying mode=\"propose\"",
                format!("config:{deficits_key}"),
                "provisional",
            ));
        }
    };
    let deficits_value = match optimizer_deficits_config_value(deficits_value, &deficits_key) {
        Ok(value) => value,
        Err(reason) => {
            return Ok(optimizer_propose_refused_json(
                project,
                "ASTRO_OPTIMIZER_PROPOSE_DEFICITS_INVALID",
                reason,
                "repair optimizer_deficits_json before retrying mode=\"propose\"",
                format!("config:{deficits_key}"),
                "provisional",
            ));
        }
    };
    let deficits = deficits_value
        .get("deficits")
        .and_then(Value::as_array)
        .expect("validated optimizer deficits array");
    let (proposals, skipped) =
        optimizer_generate_proposals_from_deficits(project, &deficits_key, deficits);
    let proposal_count = proposals.len();
    let skipped_count = skipped.len();
    let status = if proposal_count == 0 {
        "empty"
    } else {
        "generated"
    };
    let remediation = if proposal_count == 0 {
        Value::String(
            "all measured deficits were skipped; inspect generation.skipped before relying on pending proposals"
                .to_string(),
        )
    } else {
        Value::Null
    };
    let queue = json!({
        "schema": OPTIMIZER_PROPOSALS_SCHEMA,
        "project": project,
        "status": status,
        "proposal_count": proposal_count,
        "proposals": proposals,
        "source": format!("config:{proposals_key}"),
        "deficit_source": format!("config:{deficits_key}"),
        "freshness": "fresh",
        "trust": "verified",
        "generation": {
            "mode": "propose",
            "source_schema": OPTIMIZER_DEFICITS_SCHEMA,
            "source": format!("config:{deficits_key}"),
            "generated_count": proposal_count,
            "skipped_count": skipped_count,
            "skipped": skipped,
            "freshness": "fresh",
            "trust": "verified",
        },
        "remediation": remediation,
    });

    // #122: the queue is written *before* it can be verified, so a readback failure must be
    // compensated, not merely reported. Capture the pre-write value first: the compensating
    // rollback restores it, or deletes the key when the project had no queue, so a refusal
    // leaves the store in a state equivalent to "this propose never ran".
    let prior = read_config_value(cache_dir, &proposals_key)?;
    write_config_value(cache_dir, &proposals_key, &queue.to_string())?;

    // Every post-write failure below leaves a row behind if it is not compensated — including
    // the two that previously escaped as bare `?` errors (an unreadable key, and bytes that
    // do not parse back as JSON). All three are readback failures of the same write.
    let mismatch = match read_config_value(cache_dir, &proposals_key)? {
        None => Some(
            "optimizer proposal queue write was not readable back from the config store"
                .to_string(),
        ),
        Some(raw) => match serde_json::from_str::<Value>(&raw) {
            Err(error) => Some(format!(
                "optimizer proposal queue readback did not parse as JSON: {error}"
            )),
            Ok(readback) if readback != queue => {
                Some("optimizer proposal queue write did not match config readback".to_string())
            }
            Ok(_) => None,
        },
    };
    if let Some(reason) = mismatch {
        return Ok(optimizer_propose_readback_mismatch_json(
            cache_dir,
            project,
            &proposals_key,
            prior.as_deref(),
            reason,
        ));
    }

    Ok(queue)
}

/// Outcome of the #122 compensating rollback, proven by an independent readback.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum OptimizerProposalsRollback {
    /// The project had no persisted queue before the refused write, so the key was removed.
    Removed,
    /// The project had a queue before the refused write, so those exact bytes were restored.
    RestoredPrior,
}

impl OptimizerProposalsRollback {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::RestoredPrior => "restored_prior",
        }
    }
}

/// Builds the readback-mismatch refusal for `mode="propose"`, **after** compensating the
/// write that failed verification (#122).
///
/// Without the compensation the handler refused while leaving the just-written queue
/// persisted: `mode="status"` would then go on serving that different-yet-valid queue as
/// pending, so durable state contradicted the refusal the caller was handed. This is the
/// saga rule — a step that cannot be verified is undone, leaving the system equivalent to
/// "the operation never ran".
///
/// The refusal always carries `{code, message, remediation}`. When the compensation itself
/// cannot be verified, the refusal says so under a distinct code rather than implying a
/// clean rollback that did not happen.
pub(crate) fn optimizer_propose_readback_mismatch_json(
    cache_dir: &Path,
    project: &str,
    proposals_key: &str,
    prior: Option<&str>,
    reason: String,
) -> Value {
    let rollback = match rollback_optimizer_proposals(cache_dir, proposals_key, prior) {
        Ok(rollback) => rollback,
        Err(error) => {
            let mut refusal = optimizer_propose_refused_json(
                project,
                "ASTRO_OPTIMIZER_PROPOSE_READBACK_MISMATCH_RESIDUE",
                format!(
                    "{reason}; the compensating rollback of that unverified write also failed: \
                     {error}"
                ),
                format!(
                    "the mismatched proposal queue may still be persisted at \
                     config:{proposals_key}; repair the config store, then delete or restore \
                     that key by hand before trusting mode=\"status\" pending proposals"
                ),
                format!("config:{proposals_key}"),
                "provisional",
            );
            refusal["rollback"] = json!({
                "status": "failed",
                "key": format!("config:{proposals_key}"),
                "residue": "unknown",
                "freshness": "not_evaluated",
                "trust": "provisional",
            });
            return refusal;
        }
    };
    let mut refusal = optimizer_propose_refused_json(
        project,
        "ASTRO_OPTIMIZER_PROPOSE_READBACK_MISMATCH",
        reason,
        "inspect the config store before retrying mode=\"propose\"; the unverified write was \
         rolled back, so no proposal queue from this refused run is persisted",
        format!("config:{proposals_key}"),
        "provisional",
    );
    refusal["rollback"] = json!({
        "status": rollback.as_str(),
        "key": format!("config:{proposals_key}"),
        "residue": "none",
        // The rollback was proven by reading the key back, not by the delete/write returning
        // Ok — a mutation's return value is not evidence of persisted state.
        "verification": "config_readback",
        "freshness": "fresh",
        "trust": "verified",
    });
    refusal
}

/// Compensating transaction for an optimizer-propose write that failed readback verification.
///
/// Restores `prior`, or deletes the key when there was no prior value, then **independently
/// reads the key back** to prove the residue is gone. Idempotent, so a retried compensation
/// is safe. Returns an error if the store does not read back as the pre-write state — the
/// caller surfaces that as a distinct refusal rather than claiming a clean rollback.
fn rollback_optimizer_proposals(
    cache_dir: &Path,
    proposals_key: &str,
    prior: Option<&str>,
) -> Result<OptimizerProposalsRollback, DynError> {
    let rollback = match prior {
        Some(prior) => {
            write_config_value(cache_dir, proposals_key, prior)?;
            OptimizerProposalsRollback::RestoredPrior
        }
        None => {
            delete_config_value(cache_dir, proposals_key)?;
            OptimizerProposalsRollback::Removed
        }
    };
    let observed = read_config_value(cache_dir, proposals_key)?;
    if observed.as_deref() != prior {
        return Err(format!(
            "rollback of {proposals_key} did not read back as the pre-write state (expected {}, \
             observed {})",
            prior.map_or("the key to be absent", |_| "the prior queue bytes"),
            observed.map_or("absent", |_| "a different value"),
        )
        .into());
    }
    Ok(rollback)
}

pub(crate) fn optimizer_deficits_config_value(value: Value, key: &str) -> Result<Value, String> {
    let Some(object) = value.as_object() else {
        return Err("optimizer_deficits_json must be an object".to_string());
    };
    if object.get("schema").and_then(Value::as_str) != Some(OPTIMIZER_DEFICITS_SCHEMA) {
        return Err(format!(
            "optimizer_deficits_json schema must be {OPTIMIZER_DEFICITS_SCHEMA}"
        ));
    }
    if object.get("status").and_then(Value::as_str) != Some("measured") {
        return Err("optimizer_deficits_json status must be measured".to_string());
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Err("optimizer_deficits_json requires freshness and trust labels".to_string());
    }
    let Some(deficits) = object.get("deficits").and_then(Value::as_array) else {
        return Err("optimizer_deficits_json deficits must be an array".to_string());
    };
    for (index, deficit) in deficits.iter().enumerate() {
        if let Some(reason) = optimizer_deficit_invalid(deficit) {
            return Err(format!(
                "optimizer_deficits_json deficits[{index}] {reason}"
            ));
        }
    }

    let mut out = object.clone();
    out.insert("source".to_string(), json!(format!("config:{key}")));
    Ok(Value::Object(out))
}

pub(crate) fn optimizer_deficit_invalid(deficit: &Value) -> Option<&'static str> {
    let Some(object) = deficit.as_object() else {
        return Some("must be an object");
    };
    for field in [
        "deficit_id",
        "axis",
        "suggested_action",
        "template_family",
        "slot",
    ] {
        if object.get(field).and_then(Value::as_str).is_none() {
            return Some(
                "requires string deficit_id, axis, suggested_action, template_family, and slot",
            );
        }
    }
    for field in ["measured_bits", "required_bits"] {
        if object.get(field).and_then(Value::as_f64).is_none() {
            return Some("requires numeric measured_bits and required_bits");
        }
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    if !json_string_array_nonempty(object.get("provenance")) {
        return Some("requires non-empty string provenance");
    }
    None
}

pub(crate) fn optimizer_generate_proposals_from_deficits(
    project: &str,
    deficits_key: &str,
    deficits: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    let mut proposals = Vec::new();
    let mut skipped = Vec::new();
    for deficit in deficits {
        let object = deficit
            .as_object()
            .expect("validated optimizer deficit object");
        let deficit_id = object
            .get("deficit_id")
            .and_then(Value::as_str)
            .expect("validated deficit_id");
        let suggested_action = object
            .get("suggested_action")
            .and_then(Value::as_str)
            .expect("validated suggested_action");
        let measured_bits = object
            .get("measured_bits")
            .and_then(Value::as_f64)
            .expect("validated measured_bits");
        let required_bits = object
            .get("required_bits")
            .and_then(Value::as_f64)
            .expect("validated required_bits");
        if measured_bits >= required_bits {
            skipped.push(optimizer_deficit_skipped_json(
                deficit_id,
                "not_deficient",
                "measured_bits is not below required_bits",
            ));
            continue;
        }
        if !matches!(suggested_action, "ProposeLens" | "propose_lens") {
            skipped.push(optimizer_deficit_skipped_json(
                deficit_id,
                "unsupported_action",
                "suggested_action is not ProposeLens",
            ));
            continue;
        }
        let template_family = object
            .get("template_family")
            .and_then(Value::as_str)
            .expect("validated template_family");
        let Some(candidate_kind) = optimizer_template_candidate_kind(template_family) else {
            skipped.push(optimizer_deficit_skipped_json(
                deficit_id,
                "unsupported_template_family",
                "template_family has no Astrolabe proposal template",
            ));
            continue;
        };
        proposals.push(optimizer_deficit_proposal_json(
            project,
            deficits_key,
            deficit,
            candidate_kind,
        ));
    }
    (proposals, skipped)
}

pub(crate) fn optimizer_template_candidate_kind(template_family: &str) -> Option<&'static str> {
    match template_family {
        "derived_metric" => Some("derived_metric_lens"),
        "hashed_set" => Some("hashed_set_lens"),
        "interaction" => Some("interaction_lens"),
        "frequency" => Some("frequency_lens"),
        "pca" => Some("pca_lens"),
        _ => None,
    }
}

pub(crate) fn optimizer_deficit_proposal_json(
    project: &str,
    deficits_key: &str,
    deficit: &Value,
    candidate_kind: &str,
) -> Value {
    let object = deficit
        .as_object()
        .expect("validated optimizer deficit object");
    let deficit_id = object
        .get("deficit_id")
        .and_then(Value::as_str)
        .expect("validated deficit_id");
    let axis = object
        .get("axis")
        .and_then(Value::as_str)
        .expect("validated axis");
    let template_family = object
        .get("template_family")
        .and_then(Value::as_str)
        .expect("validated template_family");
    let slot = object
        .get("slot")
        .and_then(Value::as_str)
        .expect("validated slot");
    let provenance = json!([
        format!("config:{deficits_key}"),
        format!("deficit:{deficit_id}")
    ]);
    json!({
        "proposal_id": optimizer_proposal_id(project, deficit_id, axis, template_family, slot),
        "state": "pending_differentiation_gate",
        "deficit": {
            "deficit_id": deficit_id,
            "axis": axis,
            "scope": object.get("scope").cloned().unwrap_or(Value::Null),
            "measured_bits": object.get("measured_bits").cloned().unwrap_or(Value::Null),
            "required_bits": object.get("required_bits").cloned().unwrap_or(Value::Null),
            "freshness": object.get("freshness").cloned().unwrap_or(Value::Null),
            "trust": object.get("trust").cloned().unwrap_or(Value::Null),
            "provenance": object.get("provenance").cloned().unwrap_or(Value::Null),
        },
        "candidate": {
            "kind": candidate_kind,
            "template_family": template_family,
            "slot": slot,
            "field": object.get("field").cloned().unwrap_or(Value::Null),
            "freshness": "fresh",
            "trust": "provisional",
            "provenance": provenance.clone(),
        },
        "differentiation_gate": {
            "status": "pending",
            "freshness": "not_evaluated",
            "trust": "provisional",
            "remediation": "run P8.3 differentiation gate before admitting this proposal",
        },
        "freshness": "fresh",
        "trust": "provisional",
        "provenance": provenance,
    })
}

pub(crate) fn optimizer_proposal_id(
    project: &str,
    deficit_id: &str,
    axis: &str,
    template_family: &str,
    slot: &str,
) -> String {
    let digest = Sha256::digest(format!(
        "{project}\0{deficit_id}\0{axis}\0{template_family}\0{slot}"
    ));
    let hex = hex_lower(&digest);
    format!("proposal:{}", &hex[..16])
}

pub(crate) fn optimizer_deficit_skipped_json(deficit_id: &str, code: &str, reason: &str) -> Value {
    json!({
        "deficit_id": deficit_id,
        "code": code,
        "reason": reason,
        "freshness": "fresh",
        "trust": "verified",
    })
}

pub(crate) fn optimizer_freezes_block_propose(frozen_knobs: &Value) -> Option<String> {
    if frozen_knobs.get("status").and_then(Value::as_str) == Some("invalid") {
        return Some(
            "optimizer_freezes_json is invalid, so optimizer proposal generation is refused"
                .to_string(),
        );
    }
    let knobs = frozen_knobs.get("knobs").and_then(Value::as_array)?;
    for knob in knobs {
        if let Some(label) = optimizer_freeze_knob_blocks_propose(knob) {
            return Some(format!(
                "optimizer proposal generation is frozen by knob {label:?}"
            ));
        }
    }
    None
}

pub(crate) fn optimizer_freeze_knob_blocks_propose(knob: &Value) -> Option<&str> {
    if let Some(label) = knob.as_str() {
        return optimizer_freeze_label_blocks_propose(label).then_some(label);
    }
    let object = knob.as_object()?;
    if object
        .get("frozen")
        .and_then(Value::as_bool)
        .is_some_and(|frozen| !frozen)
    {
        return None;
    }
    let label = object
        .get("knob")
        .or_else(|| object.get("name"))
        .or_else(|| object.get("id"))
        .and_then(Value::as_str)?;
    optimizer_freeze_label_blocks_propose(label).then_some(label)
}

pub(crate) fn optimizer_freeze_label_blocks_propose(label: &str) -> bool {
    matches!(
        label,
        "all" | "anneal" | "propose" | "proposal_generation" | "optimizer_proposals"
    )
}

pub(crate) fn optimizer_propose_refused_json(
    project: &str,
    code: &str,
    message: impl Into<String>,
    remediation: impl Into<String>,
    source: impl Into<String>,
    trust: &str,
) -> Value {
    json!({
        "schema": OPTIMIZER_PROPOSALS_SCHEMA,
        "project": project,
        "status": "refused",
        "code": code,
        "message": message.into(),
        "remediation": remediation.into(),
        "proposal_count": Value::Null,
        "proposals": [],
        "source": source.into(),
        "freshness": "fresh",
        "trust": trust,
    })
}

pub(crate) fn optimizer_pending_proposals_json(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let key = metadata_key(project, "optimizer_proposals_json");
    if let Some(raw) = read_config_value(cache_dir, &key)? {
        return Ok(match serde_json::from_str::<Value>(&raw) {
            Ok(value) => optimizer_proposals_config_json(value, &key),
            Err(error) => optimizer_proposals_invalid_json(
                &key,
                format!("stored optimizer_proposals_json invalid: {error}"),
            ),
        });
    }
    Ok(json!({
        "status": "unavailable",
        "proposal_count": Value::Null,
        "proposals": [],
        "freshness": "not_evaluated",
        "trust": "provisional",
        "source": format!("config:{key}:missing"),
        "reason": "anneal proposal store is not enabled in the current shadow stage",
        "remediation": "wire the P8.3 deficit-to-candidate proposal pipeline before serving optimizer proposals",
    }))
}

pub(crate) fn optimizer_proposals_config_json(value: Value, key: &str) -> Value {
    let Some(object) = value.as_object() else {
        return optimizer_proposals_invalid_json(key, "optimizer_proposals_json must be an object");
    };
    if object.get("schema").and_then(Value::as_str) != Some(OPTIMIZER_PROPOSALS_SCHEMA) {
        return optimizer_proposals_invalid_json(
            key,
            format!("optimizer_proposals_json schema must be {OPTIMIZER_PROPOSALS_SCHEMA}"),
        );
    }
    if object.get("status").and_then(Value::as_str).is_none()
        || object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return optimizer_proposals_invalid_json(
            key,
            "optimizer_proposals_json requires status, freshness, and trust labels",
        );
    }
    let Some(proposals) = object.get("proposals").and_then(Value::as_array) else {
        return optimizer_proposals_invalid_json(
            key,
            "optimizer_proposals_json proposals must be an array",
        );
    };
    for (index, proposal) in proposals.iter().enumerate() {
        if let Some(reason) = optimizer_proposal_invalid(proposal) {
            return optimizer_proposals_invalid_json(
                key,
                format!("optimizer_proposals_json proposals[{index}] {reason}"),
            );
        }
    }

    let mut out = object.clone();
    out.insert("proposal_count".to_string(), json!(proposals.len()));
    out.insert("source".to_string(), json!(format!("config:{key}")));
    out.insert(
        "remediation".to_string(),
        object.get("remediation").cloned().unwrap_or(Value::Null),
    );
    Value::Object(out)
}

pub(crate) fn optimizer_proposal_invalid(proposal: &Value) -> Option<&'static str> {
    let Some(object) = proposal.as_object() else {
        return Some("must be an object");
    };
    if object.get("proposal_id").and_then(Value::as_str).is_none()
        || object.get("state").and_then(Value::as_str).is_none()
    {
        return Some("requires string proposal_id and state");
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    if !json_string_array_nonempty(object.get("provenance")) {
        return Some("requires non-empty string provenance");
    }
    let Some(deficit) = object.get("deficit") else {
        return Some("requires measured deficit object");
    };
    if optimizer_proposal_deficit_invalid(deficit).is_some() {
        return Some("requires measured deficit labels, numeric bits, and provenance");
    }
    let Some(candidate) = object.get("candidate") else {
        return Some("requires candidate object");
    };
    if optimizer_proposal_candidate_invalid(candidate).is_some() {
        return Some("requires candidate kind, labels, and provenance");
    }
    None
}

pub(crate) fn optimizer_proposal_deficit_invalid(deficit: &Value) -> Option<&'static str> {
    let Some(object) = deficit.as_object() else {
        return Some("must be an object");
    };
    if object.get("axis").and_then(Value::as_str).is_none() {
        return Some("requires string axis");
    }
    for field in ["measured_bits", "required_bits"] {
        if object.get(field).and_then(Value::as_f64).is_none() {
            return Some("requires numeric measured_bits and required_bits");
        }
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    if !json_string_array_nonempty(object.get("provenance")) {
        return Some("requires non-empty string provenance");
    }
    None
}

pub(crate) fn optimizer_proposal_candidate_invalid(candidate: &Value) -> Option<&'static str> {
    let Some(object) = candidate.as_object() else {
        return Some("must be an object");
    };
    if object.get("kind").and_then(Value::as_str).is_none() {
        return Some("requires string kind");
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    if !json_string_array_nonempty(object.get("provenance")) {
        return Some("requires non-empty string provenance");
    }
    None
}

pub(crate) fn optimizer_proposals_invalid_json(key: &str, reason: impl Into<String>) -> Value {
    json!({
        "schema": OPTIMIZER_PROPOSALS_SCHEMA,
        "status": "invalid",
        "proposal_count": Value::Null,
        "proposals": [],
        "freshness": "fresh",
        "trust": "provisional",
        "source": format!("config:{key}"),
        "reason": reason.into(),
        "remediation": "repair optimizer_proposals_json before treating optimizer proposals as pending",
    })
}
