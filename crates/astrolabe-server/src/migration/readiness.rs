use super::*;
pub(crate) const GET_READINESS_SCHEMA: &str = "astrolabe.get_readiness.v1";
pub(crate) const READINESS_TIER_MEASUREMENTS_SCHEMA: &str = "astrolabe.readiness_tiers.v1";

pub(crate) fn readiness_status_json_at(
    cache_dir: &Path,
    project: &str,
    scope: Option<&str>,
    axis: Option<&str>,
) -> Result<Value, DynError> {
    let effective_scope = scope.unwrap_or(project);
    let effective_axis = axis.unwrap_or("general");
    let kernel_context = read_kernel_context_metadata(cache_dir, project)?;
    let readiness_measurements = readiness_tier_measurements_json(cache_dir, project)?;
    let layout_coherence_tier =
        readiness_layout_coherence_tier(cache_dir, project, effective_scope)?;
    let tiers = vec![
        readiness_configured_tier(
            &readiness_measurements,
            "oracle_clean",
            effective_scope,
            effective_axis,
            "oracle-clean >= 0.7",
            "oracle_evidence:not_persisted",
            "mine and persist oracle outcome anchors plus flakiness/self-consistency ceilings for this scope",
        ),
        readiness_configured_tier(
            &readiness_measurements,
            "panel_sufficient",
            effective_scope,
            effective_axis,
            "panel bits sufficient for axis entropy",
            "assay_sufficiency:not_persisted",
            "run measure_bits sufficiency for the requested axis and persist the panel/axis deficit card",
        ),
        readiness_kernel_recall_tier(&kernel_context, effective_scope),
        readiness_configured_tier(
            &readiness_measurements,
            "calibrated",
            effective_scope,
            effective_axis,
            "guard tau calibrated within ceiling",
            "guard_profiles:not_persisted",
            "run guard_calibrate and persist per-slot tau/FAR/FRR profile metadata for this scope",
        ),
        readiness_configured_tier(
            &readiness_measurements,
            "goodhart_defended",
            effective_scope,
            effective_axis,
            "Goodhart gaming check g(tau) >= 0.9",
            "anneal_goodhart:not_persisted",
            "run and persist the anneal Goodhart/dominance defense before enabling autonomy",
        ),
        readiness_configured_tier(
            &readiness_measurements,
            "mistakes_closed",
            effective_scope,
            effective_axis,
            "no recurring closed-mistake regressions",
            "mistake_closure:not_persisted",
            "run mistake-closure replay and persist wrong-only-once regression state for this scope",
        ),
        layout_coherence_tier,
    ];
    let ready = tiers.iter().all(readiness_tier_passed);
    let first_failing = tiers
        .iter()
        .find(|tier| !readiness_tier_passed(tier))
        .cloned();
    let measured_tier_count = tiers
        .iter()
        .filter(|tier| tier.get("measured").and_then(Value::as_bool) == Some(true))
        .count();
    let source_state_verified = kernel_context.get("trust").and_then(Value::as_str)
        == Some("verified")
        && readiness_measurements.get("trust").and_then(Value::as_str) == Some("verified");
    let trust = if ready && source_state_verified && tiers.iter().all(readiness_tier_verified) {
        "verified"
    } else {
        "provisional"
    };
    let mut response = json!({
        "schema": GET_READINESS_SCHEMA,
        "project": project,
        "scope": effective_scope,
        "axis": effective_axis,
        "status": if ready { "ready" } else { "not_ready" },
        "ready": ready,
        "freshness": "fresh",
        "trust": trust,
        "measured_tier_count": measured_tier_count,
        "tier_count": tiers.len(),
        "tiers": tiers,
        // P7.4 (#48): guard drift recalibration proposals feed the readiness view —
        // an elevated rolling rejection rate is a signal the calibrated tier is
        // drifting and recalibration is due (labeled; empty when no crossing fired).
        "guard_drift": drift_proposals_section(cache_dir, project),
        "first_failing_tier": first_failing.as_ref().map(|tier| {
            json!({
                "tier": tier.get("tier").cloned().unwrap_or(Value::Null),
                "cheapest_fix": tier.get("cheapest_fix").cloned().unwrap_or(Value::Null),
                "source": tier.get("source").cloned().unwrap_or(Value::Null),
            })
        }),
        "source_state": {
            "kernel_context": {
                "schema": kernel_context.get("schema").cloned().unwrap_or(Value::Null),
                "status": kernel_context.get("status").cloned().unwrap_or(Value::Null),
                "freshness": kernel_context.get("freshness").cloned().unwrap_or(Value::Null),
                "trust": kernel_context.get("trust").cloned().unwrap_or(Value::Null),
                "metadata_ref": metadata_key(project, "kernel_context_json"),
            },
            "readiness_tiers": {
                "schema": readiness_measurements.get("schema").cloned().unwrap_or(Value::Null),
                "status": readiness_measurements.get("status").cloned().unwrap_or(Value::Null),
                "freshness": readiness_measurements.get("freshness").cloned().unwrap_or(Value::Null),
                "trust": readiness_measurements.get("trust").cloned().unwrap_or(Value::Null),
                "metadata_ref": metadata_key(project, "readiness_tiers_json"),
            },
        },
    });
    refresh_readiness_artifact_hash(&mut response);
    Ok(response)
}

pub(crate) fn readiness_unavailable_tier(
    tier: &str,
    required: &str,
    source: &str,
    cheapest_fix: &str,
) -> Value {
    json!({
        "tier": tier,
        "pass": false,
        "measured": false,
        "value": Value::Null,
        "required": required,
        "provenance_refs": [],
        "source": source,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "cheapest_fix": cheapest_fix,
    })
}

pub(crate) fn readiness_tier_measurements_json(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let key = metadata_key(project, "readiness_tiers_json");
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        return Ok(json!({
            "schema": READINESS_TIER_MEASUREMENTS_SCHEMA,
            "status": "unavailable",
            "tiers": [],
            "source": format!("config:{key}:missing"),
            "metadata_ref": key,
            "freshness": "not_evaluated",
            "trust": "provisional",
            "reason": "readiness_tiers_json is not persisted for this project",
            "remediation": "persist measured readiness tier rows before relying on non-kernel readiness tiers",
        }));
    };
    let value = match serde_json::from_str::<Value>(&raw) {
        Ok(value) => value,
        Err(error) => {
            return Ok(readiness_tier_measurements_invalid_json(
                &key,
                format!("stored readiness_tiers_json invalid: {error}"),
            ));
        }
    };
    Ok(match readiness_tier_measurements_config_json(value, &key) {
        Ok(value) => value,
        Err(reason) => readiness_tier_measurements_invalid_json(&key, reason),
    })
}

pub(crate) fn readiness_tier_measurements_config_json(
    value: Value,
    key: &str,
) -> Result<Value, String> {
    let Some(object) = value.as_object() else {
        return Err("readiness_tiers_json must be an object".to_string());
    };
    if object.get("schema").and_then(Value::as_str) != Some(READINESS_TIER_MEASUREMENTS_SCHEMA) {
        return Err(format!(
            "readiness_tiers_json schema must be {READINESS_TIER_MEASUREMENTS_SCHEMA}"
        ));
    }
    if object.get("status").and_then(Value::as_str) != Some("measured") {
        return Err("readiness_tiers_json status must be measured".to_string());
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Err(
            "readiness_tiers_json requires status, freshness, and trust labels".to_string(),
        );
    }
    let Some(tiers) = object.get("tiers").and_then(Value::as_array) else {
        return Err("readiness_tiers_json tiers must be an array".to_string());
    };
    for (index, tier) in tiers.iter().enumerate() {
        if let Some(reason) = readiness_measurement_tier_invalid(tier) {
            return Err(format!("readiness_tiers_json tiers[{index}] {reason}"));
        }
    }
    let mut out = object.clone();
    out.insert("source".to_string(), json!(format!("config:{key}")));
    out.insert("metadata_ref".to_string(), json!(key));
    Ok(Value::Object(out))
}

pub(crate) fn readiness_measurement_tier_invalid(tier: &Value) -> Option<&'static str> {
    let Some(object) = tier.as_object() else {
        return Some("must be an object");
    };
    if object.get("tier").and_then(Value::as_str).is_none() {
        return Some("requires string tier");
    }
    if object.get("scope").is_some() && object.get("scope").and_then(Value::as_str).is_none() {
        return Some("scope must be a string when present");
    }
    if object.get("axis").is_some() && object.get("axis").and_then(Value::as_str).is_none() {
        return Some("axis must be a string when present");
    }
    if object.get("measured").and_then(Value::as_bool) != Some(true)
        || object.get("pass").and_then(Value::as_bool).is_none()
    {
        return Some("requires measured=true and boolean pass");
    }
    if object.get("value").is_none() {
        return Some("requires value");
    }
    if object.get("required").and_then(Value::as_str).is_none()
        || object.get("source").and_then(Value::as_str).is_none()
    {
        return Some("requires required and source labels");
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    if !json_string_array_nonempty(object.get("provenance_refs")) {
        return Some("requires non-empty string provenance_refs");
    }
    if object.get("pass").and_then(Value::as_bool) == Some(false)
        && object.get("cheapest_fix").and_then(Value::as_str).is_none()
    {
        return Some("failing tiers require cheapest_fix");
    }
    None
}

pub(crate) fn readiness_tier_measurements_invalid_json(
    key: &str,
    reason: impl Into<String>,
) -> Value {
    json!({
        "schema": READINESS_TIER_MEASUREMENTS_SCHEMA,
        "status": "invalid",
        "tiers": [],
        "source": format!("config:{key}"),
        "metadata_ref": key,
        "freshness": "fresh",
        "trust": "provisional",
        "reason": reason.into(),
        "remediation": "repair readiness_tiers_json before relying on non-kernel readiness tiers",
    })
}

pub(crate) fn readiness_configured_tier(
    measurements: &Value,
    tier: &str,
    scope: &str,
    axis: &str,
    required: &str,
    missing_source: &str,
    cheapest_fix: &str,
) -> Value {
    match measurements.get("status").and_then(Value::as_str) {
        Some("invalid") => {
            return json!({
                "tier": tier,
                "pass": false,
                "measured": false,
                "value": Value::Null,
                "required": required,
                "provenance_refs": [],
                "source": measurements.get("source").cloned().unwrap_or_else(|| json!("readiness_tiers_json:invalid")),
                "freshness": "fresh",
                "trust": "provisional",
                "reason": measurements.get("reason").cloned().unwrap_or_else(|| json!("readiness tier measurements invalid")),
                "cheapest_fix": measurements.get("remediation").cloned().unwrap_or_else(|| json!(cheapest_fix)),
            });
        }
        Some("unavailable") => {
            return readiness_unavailable_tier(tier, required, missing_source, cheapest_fix);
        }
        _ => {}
    }
    let Some(rows) = measurements.get("tiers").and_then(Value::as_array) else {
        return readiness_unavailable_tier(tier, required, missing_source, cheapest_fix);
    };
    let Some(row) = rows
        .iter()
        .find(|row| readiness_tier_row_matches(row, tier, scope, axis))
    else {
        return readiness_unavailable_tier(tier, required, missing_source, cheapest_fix);
    };
    let mut out = row
        .as_object()
        .expect("validated readiness tier row")
        .clone();
    out.insert(
        "metadata_ref".to_string(),
        measurements
            .get("metadata_ref")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "cheapest_fix".to_string(),
        row.get("cheapest_fix").cloned().unwrap_or(Value::Null),
    );
    Value::Object(out)
}

pub(crate) fn readiness_tier_row_matches(row: &Value, tier: &str, scope: &str, axis: &str) -> bool {
    let Some(object) = row.as_object() else {
        return false;
    };
    if object.get("tier").and_then(Value::as_str) != Some(tier) {
        return false;
    }
    let scope_matches = object
        .get("scope")
        .and_then(Value::as_str)
        .is_none_or(|value| value == scope);
    let axis_matches = object
        .get("axis")
        .and_then(Value::as_str)
        .is_none_or(|value| value == axis);
    scope_matches && axis_matches
}

pub(crate) fn readiness_kernel_recall_tier(kernel_context: &Value, scope: &str) -> Value {
    let summaries = kernel_context
        .get("scope_summaries")
        .and_then(|scope_summaries| scope_summaries.get("summaries"))
        .and_then(Value::as_array);
    let Some(summary) = summaries.and_then(|summaries| {
        summaries
            .iter()
            .find(|summary| summary.get("scope_id").and_then(Value::as_str) == Some(scope))
    }) else {
        return readiness_unavailable_tier(
            "kernel_exists",
            "kernel recall >= 0.95, tested",
            "kernel_context.scope_summaries:scope_missing",
            "index with explicit kernel scope metadata and recall readback for the requested scope",
        );
    };
    let recall_millipoints = summary
        .get("recall_millipoints")
        .and_then(Value::as_u64)
        .or_else(|| {
            summary
                .get("recall")
                .and_then(Value::as_object)
                .and_then(|recall| {
                    recall
                        .get("recalled")
                        .and_then(Value::as_u64)
                        .zip(recall.get("total").and_then(Value::as_u64))
                })
                .and_then(|(recalled, total)| {
                    (total > 0).then_some(recalled.saturating_mul(1000) / total)
                })
        });
    let Some(recall_millipoints) = recall_millipoints else {
        return readiness_unavailable_tier(
            "kernel_exists",
            "kernel recall >= 0.95, tested",
            "kernel_context.scope_summaries:recall_missing",
            "persist tested kernel recall for this scope before using readiness as an autonomy gate",
        );
    };
    let provenance_refs = summary
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(|member| member.get("provenance_ref").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let pass = recall_millipoints >= 950;
    json!({
        "tier": "kernel_exists",
        "pass": pass,
        "measured": true,
        "value": {
            "scope_id": scope,
            "recall": summary.get("recall").cloned().unwrap_or(Value::Null),
            "recall_millipoints": recall_millipoints,
        },
        "required": "kernel recall >= 0.95, tested",
        "required_millipoints": 950,
        "provenance_refs": provenance_refs,
        "source": "kernel_context.scope_summaries",
        "freshness": summary.get("freshness").and_then(Value::as_str).unwrap_or("fresh"),
        "trust": summary.get("trust").and_then(Value::as_str).unwrap_or("provisional"),
        "cheapest_fix": if pass {
            Value::Null
        } else {
            Value::String("increase or repair the scoped kernel until persisted recall_millipoints is at least 950".to_string())
        },
    })
}

/// The `layout_coherence` readiness tier (#313 / #180d).
///
/// Reads the persisted per-scope layout-coherence enforcement decision back off
/// the shadow vault (the observe-only / escalation-ladder verdict the shadow
/// import wrote from the measured mean `placement_truth` agreement) and surfaces
/// it as a measured readiness tier. The tier PASSES only when the ladder licensed
/// escalation (coherence at or above the registry escalation threshold); below the
/// floor it is observe-only. Fails closed to a labeled unavailable tier when no
/// enforcement row is persisted for the scope (no S23 posteriors, or a scope with
/// no scored members) or the persisted row is malformed — never a fabricated pass.
pub(crate) fn readiness_layout_coherence_tier(
    cache_dir: &Path,
    project: &str,
    scope: &str,
) -> Result<Value, DynError> {
    const REQUIRED: &str = "layout coherence >= escalation threshold, measured";
    let unavailable = |source: &'static str| {
        readiness_unavailable_tier(
            "layout_coherence",
            REQUIRED,
            source,
            "index with calyx=\"shadow\" so S23 layer_role posteriors persist and the layout \
             enforcement ladder scores this scope's mean placement_truth agreement, or declare \
             the directory role in astro.layout.declared_map.v1",
        )
    };
    let enforce_scope = if scope == project {
        layout_enforcement_project_scope()
    } else {
        scope
    };
    let Some(row) = read_layout_enforcement_row(cache_dir, project, enforce_scope)? else {
        return Ok(unavailable("layout_enforcement:not_persisted"));
    };
    let coherence = row.get("coherence").and_then(Value::as_f64);
    let mode = row
        .get("enforcement_mode")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let (Some(coherence), Some(mode)) = (coherence, mode) else {
        return Ok(unavailable("layout_enforcement:malformed"));
    };
    let observe_only = row.get("enforcement_skipped").and_then(Value::as_bool) == Some(true);
    let pass = mode == "escalation_licensed";
    let trust = row
        .get("trust")
        .and_then(Value::as_str)
        .unwrap_or("provisional")
        .to_string();
    Ok(json!({
        "tier": "layout_coherence",
        "pass": pass,
        "measured": true,
        "value": {
            "scope": enforce_scope,
            "coherence": coherence,
            "coherence_bits": row.get("coherence_bits").cloned().unwrap_or(Value::Null),
            "enforcement_mode": mode,
            "enforcement_skipped": observe_only,
            "coherence_floor": row.get("coherence_floor").cloned().unwrap_or(Value::Null),
            "escalation_threshold": row.get("escalation_threshold").cloned().unwrap_or(Value::Null),
            "member_count": row.get("member_count").cloned().unwrap_or(Value::Null),
        },
        "required": REQUIRED,
        "provenance_refs": [row.get("provenance").and_then(Value::as_str).unwrap_or("AsterVault:ColumnFamily::Kv:layout_enforcement")],
        "source": "shadow_vault:layout_enforcement",
        "freshness": "fresh",
        "trust": trust,
        "enforcement_mode": mode,
        "observe_only": observe_only,
        "knob_content_sha256": row.get("knob_content_sha256").cloned().unwrap_or(Value::Null),
        "cheapest_fix": if pass {
            Value::Null
        } else if observe_only {
            Value::String("layout coherence is at or below the chance floor: the enforcement ladder is observe-only. Move drifting symbols to role-matching directories (or reclassify the directory in astro.layout.declared_map.v1) until the scope's mean placement_truth agreement rises above the escalation threshold.".to_string())
        } else {
            Value::String("layout coherence is monitored but below the escalation threshold: raise the scope's mean placement_truth agreement (align member roles with the directory role) before layout enforcement can escalate past observe-only.".to_string())
        },
    }))
}

pub(crate) fn readiness_tier_passed(tier: &Value) -> bool {
    tier.get("pass").and_then(Value::as_bool) == Some(true)
}

pub(crate) fn readiness_tier_verified(tier: &Value) -> bool {
    tier.get("trust").and_then(Value::as_str) == Some("verified")
}

pub(crate) fn refresh_readiness_artifact_hash(readiness: &mut Value) {
    let mut artifact_source = readiness.clone();
    if let Some(object) = artifact_source.as_object_mut() {
        object.remove("artifact_sha256");
    }
    let artifact_bytes = serde_json::to_vec(&artifact_source).unwrap_or_default();
    readiness["artifact_sha256"] = json!(hex_lower(&Sha256::digest(&artifact_bytes)));
}
