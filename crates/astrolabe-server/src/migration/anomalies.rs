use super::*;

pub(crate) fn anomalies_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let (substrates, calibrations, skipped_properties) = anomaly_inputs_from_rows(rows);
    match detect_anomalies(&substrates, &calibrations, None, true) {
        Ok(report) => anomaly_report_json(&report, skipped_properties),
        Err(error) => anomaly_report_unavailable_json(&format!("detect_anomalies failed: {error}")),
    }
}

/// Migration-safe decode of a persisted row's optional per-pair calibration key.
///
/// Absent or JSON `null` => `Ok(None)` (the legacy pair-agnostic slot, so old
/// blind-spot rows keep byte-compatible single-pair behavior). Present but not a
/// non-empty string => `Err(())` so a malformed `pair_key` fails closed as a
/// schema-skipped row rather than being silently reinterpreted as "no pair".
fn row_sink_pair_key(value: &Value) -> Result<Option<String>, ()> {
    match value.get("pair_key") {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => {
            let text = raw.as_str().ok_or(())?.trim();
            if text.is_empty() {
                return Err(());
            }
            Ok(Some(text.to_string()))
        }
    }
}

pub(crate) fn anomaly_inputs_from_rows(
    rows: &CbmPipelineRows,
) -> (Vec<AnomalySubstrateRow>, Vec<AnomalyCalibration>, usize) {
    let mut substrates = Vec::new();
    let mut calibrations = Vec::new();
    let mut skipped_properties = 0;

    for node in &rows.nodes {
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        if let Some(values) = properties
            .get("anomaly_substrates")
            .and_then(Value::as_array)
        {
            for value in values {
                let Some(kind) = value
                    .get("kind")
                    .and_then(Value::as_str)
                    .and_then(|kind| kind.parse::<AnomalyKind>().ok())
                else {
                    skipped_properties += 1;
                    continue;
                };
                let Some(score) = value.get("score_millipoints").and_then(Value::as_u64) else {
                    skipped_properties += 1;
                    continue;
                };
                let subject_id = value
                    .get("subject_id")
                    .and_then(Value::as_str)
                    .unwrap_or(&node.qualified_name);
                let message = value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("row-sink anomaly substrate");
                let pair_key = match row_sink_pair_key(value) {
                    Ok(pair_key) => pair_key,
                    Err(()) => {
                        skipped_properties += 1;
                        continue;
                    }
                };
                let provenance = string_array_field(value, "substrate_provenance_refs");
                let evidence = string_array_field(value, "lens_evidence");
                let mut row = AnomalySubstrateRow::new(
                    kind,
                    subject_id.to_string(),
                    score,
                    message.to_string(),
                    if provenance.is_empty() {
                        vec![format!("row_sink:{}:{}#anomaly", node.project, node.id)]
                    } else {
                        provenance
                    },
                    evidence,
                );
                if let Some(pair_key) = pair_key {
                    row = row.with_pair_key(pair_key);
                }
                substrates.push(row);
            }
        }
        if let Some(values) = properties
            .get("anomaly_calibrations")
            .and_then(Value::as_array)
        {
            for value in values {
                let Some(kind) = value
                    .get("kind")
                    .and_then(Value::as_str)
                    .and_then(|kind| kind.parse::<AnomalyKind>().ok())
                else {
                    skipped_properties += 1;
                    continue;
                };
                let Some(medium) = value
                    .get("medium_min_score_millipoints")
                    .and_then(Value::as_u64)
                else {
                    skipped_properties += 1;
                    continue;
                };
                let Some(high) = value
                    .get("high_min_score_millipoints")
                    .and_then(Value::as_u64)
                else {
                    skipped_properties += 1;
                    continue;
                };
                let pair_key = match row_sink_pair_key(value) {
                    Ok(pair_key) => pair_key,
                    Err(()) => {
                        skipped_properties += 1;
                        continue;
                    }
                };
                let provenance = value
                    .get("provenance_ref")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| {
                        format!("row_sink:{}:{}#anomaly_calibration", node.project, node.id)
                    });
                let mut calibration = AnomalyCalibration::new(kind, medium, high, provenance);
                if let Some(pair_key) = pair_key {
                    calibration = calibration.with_pair_key(pair_key);
                }
                calibrations.push(calibration);
            }
        }
    }

    (substrates, calibrations, skipped_properties)
}

pub(crate) fn anomaly_report_json(report: &AnomalyReport, skipped_properties: usize) -> Value {
    let artifact_bytes = anomaly_report_artifact_bytes(report);
    let status = if skipped_properties > 0 || !report.skipped.is_empty() {
        "partial"
    } else if report.findings.is_empty() {
        "empty"
    } else {
        "built"
    };
    json!({
        "schema": report.schema,
        "status": status,
        "kind_filter": report.kind_filter.map(|kind| kind.as_str()),
        "finding_count": report.findings.len(),
        "skipped_count": report.skipped.len(),
        "metadata_skipped_count": skipped_properties,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "findings": report.findings.iter().map(anomaly_finding_json).collect::<Vec<_>>(),
        "skipped": report.skipped.iter().map(|skipped| json!({
            "kind": skipped.kind.as_str(),
            "subject_id": skipped.subject_id,
            "reason": skipped.reason,
            "freshness": skipped.freshness,
            "trust": skipped.trust,
        })).collect::<Vec<_>>(),
        "freshness": report.freshness,
        "trust": if skipped_properties == 0 { report.trust } else { "provisional" },
    })
}

pub(crate) fn anomaly_finding_json(finding: &astrolabe_weave::AnomalyFinding) -> Value {
    json!({
        "kind": finding.kind.as_str(),
        "subject_id": finding.subject_id,
        "severity": finding.severity.as_str(),
        "score_millipoints": finding.score_millipoints,
        "message": finding.message,
        "substrate_provenance_refs": finding.substrate_provenance_refs,
        "calibration_provenance_ref": finding.calibration_provenance_ref,
        "lens_evidence": finding.lens_evidence,
        "freshness": finding.freshness,
        "trust": finding.trust,
    })
}

pub(crate) fn anomaly_report_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": DETECT_ANOMALIES_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with anomaly substrate metadata or wait for live xterm/assay/reactive rows before using detect_anomalies",
    })
}

pub(crate) fn read_anomaly_report(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    match read_live_anomaly_report(cache_dir, project) {
        Ok(Some(report)) => Ok(report),
        Ok(None) => read_anomaly_report_metadata(cache_dir, project),
        Err(error) => Err(error),
    }
}

pub(crate) fn read_live_anomaly_report(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<Value>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(None);
    }
    let mut selected_cfs = vec![
        ColumnFamily::XTerm,
        ColumnFamily::Assay,
        ColumnFamily::Reactive,
        // The blind-spot sweep reconstructs SimilarityNodes from the live vault.
        // read_cbm_graph_snapshot reads node identity (qualified_name <-> CxId)
        // from Base + Graph and asserts no legacy series state via Kv +
        // Recurrence; the slot CFs carry the confident/neighbor lens vectors.
        ColumnFamily::Base,
        ColumnFamily::Graph,
        ColumnFamily::Kv,
        ColumnFamily::Recurrence,
    ];
    selected_cfs.extend(
        blind_spot_slots(&DEFAULT_BLIND_SPOT_PAIRS)
            .into_iter()
            .map(ColumnFamily::slot),
    );
    selected_cfs.push(ColumnFamily::Compression);
    selected_cfs.sort();
    selected_cfs.dedup();
    let vault = open_shadow_vault_read_only(&vault_dir, &vault_id, &vault_salt, selected_cfs)?;
    let mut inputs = live_anomaly_inputs_from_vault(&vault)?;
    let blind_spot = merge_live_blind_spot_inputs(&vault, &vault_dir, project, &mut inputs)?;
    if !inputs.has_anomaly_inputs() {
        return Ok(None);
    }
    let report = detect_anomalies(&inputs.substrates, &inputs.calibrations, None, true)?;
    let mut value = anomaly_report_json(&report, inputs.skipped_rows);
    value["source"] = json!("AsterVault:ColumnFamily::XTerm+Assay+Reactive+BlindSpot");
    value["source_state"] = live_anomaly_source_state_json(&inputs, &vault_dir, &blind_spot);
    refresh_anomaly_report_counts_and_artifact(&mut value);
    Ok(Some(value))
}

/// The labeled outcome of folding the live blind-spot sweep into the anomaly
/// inputs — recorded in `source_state` so a degradation (no graph snapshot, a
/// slot-decode failure, or a per-pair calibration deficit) is never silent.
pub(crate) enum BlindSpotMergeOutcome {
    /// The sweep ran; carries the merged inputs' summary counts.
    Swept(BlindSpotAnomalyInputs),
    /// The sweep could not run against the live vault; carries the labeled reason.
    Unavailable(String),
}

/// Reconstructs SimilarityNodes from the live vault and folds the blind-spot
/// sweep's `BlindSpot` substrate rows and measured calibration into `inputs`.
///
/// Fail-open with a label: if the graph snapshot cannot be read or a slot vector
/// cannot be decoded, the other anomaly kinds still report and the blind-spot
/// degradation is surfaced as [`BlindSpotMergeOutcome::Unavailable`] rather than
/// aborting the whole `detect_anomalies` call.
pub(crate) fn merge_live_blind_spot_inputs<C: Clock>(
    vault: &AsterVault<C>,
    vault_panel_root: &Path,
    project: &str,
    inputs: &mut LiveAnomalyInputs,
) -> Result<BlindSpotMergeOutcome, DynError> {
    let slots = blind_spot_slots(&DEFAULT_BLIND_SPOT_PAIRS);
    let nodes = reconstruct_similarity_nodes(vault, vault_panel_root, project, &slots)?;
    Ok(
        match blind_spot_anomaly_inputs(
            &nodes,
            &DEFAULT_BLIND_SPOT_PAIRS,
            &BlindSpotConfig::default(),
        ) {
            Ok(blind_spot) => {
                inputs
                    .substrates
                    .extend(blind_spot.substrates.iter().cloned());
                inputs
                    .calibrations
                    .extend(blind_spot.calibrations.iter().cloned());
                BlindSpotMergeOutcome::Swept(blind_spot)
            }
            Err(error) => BlindSpotMergeOutcome::Unavailable(format!(
                "blind-spot sweep refused: {} ({})",
                error.message(),
                error.code()
            )),
        },
    )
}

/// Reconstructs the live corpus's [`SimilarityNode`]s (non-structural symbols,
/// each carrying the requested `slots`) from the vault's graph snapshot and slot
/// column families — the read-side twin of the shadow importer's slot load.
pub(crate) fn reconstruct_similarity_nodes<C: Clock>(
    vault: &AsterVault<C>,
    vault_panel_root: &Path,
    project: &str,
    slots: &[SlotId],
) -> Result<Vec<SimilarityNode>, DynError> {
    let snapshot_lease = vault.retain_latest_snapshot();
    let at_seq = snapshot_lease.seq();
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot_at(vault, project, at_seq)?;
    let source = WeaveSlotSource::open(at_seq, Some(vault_panel_root), snapshot.panel_version)?;
    let mut slot_rows = std::collections::BTreeMap::<
        SlotId,
        std::collections::BTreeMap<calyx_core::CxId, SlotVector>,
    >::new();
    for slot in slots {
        slot_rows.insert(
            *slot,
            source.resolve_column(vault, *slot)?.into_iter().collect(),
        );
        snapshot_lease.record_progress();
    }
    let mut nodes = Vec::new();
    for node in snapshot.nodes.iter().filter(|node| !node.structural) {
        let Some(cx_id) = node.cx_id else {
            continue;
        };
        let mut similarity_node =
            SimilarityNode::new(node.atom_id.clone(), node.qualified_name.clone());
        for slot in slots {
            if let Some(vector) = slot_rows.get(slot).and_then(|rows| rows.get(&cx_id)) {
                similarity_node.slots.insert(*slot, vector.clone());
            }
        }
        nodes.push(similarity_node);
    }
    Ok(nodes)
}

pub(crate) fn live_anomaly_source_state_json(
    inputs: &LiveAnomalyInputs,
    vault_dir: &Path,
    blind_spot: &BlindSpotMergeOutcome,
) -> Value {
    json!({
        "source": "AsterVault:ColumnFamily::XTerm+Assay+Reactive+BlindSpot",
        "vault_dir": vault_dir,
        "snapshot": inputs.snapshot,
        "xterm_rows_read": inputs.xterm_rows_read,
        "assay_rows_read": inputs.assay_rows_read,
        // Shared XTerm CF co-tenant rows (layout placement_truth, #369) skipped
        // during the live XTerm scan: a counted, labeled skip, not a degradation
        // (invariant 3). Before #369 these rows failed the whole read closed.
        "xterm_cotenant_rows_skipped": inputs.xterm_cotenant_rows_skipped,
        // Shared Assay CF co-tenant rows (delta-invalidation, #348) skipped
        // during load: a counted, labeled skip, not a degradation (invariant 3).
        "assay_cotenant_rows_skipped": inputs.assay_cotenant_rows_skipped,
        "reactive_fired_rows_read": inputs.reactive_rows_read,
        "schema_skipped_rows": inputs.skipped_rows,
        "blind_spot": blind_spot_source_state_json(blind_spot),
        "freshness": "fresh",
        "trust": if inputs.skipped_rows == 0 { "verified" } else { "provisional" },
    })
}

pub(crate) fn blind_spot_source_state_json(outcome: &BlindSpotMergeOutcome) -> Value {
    match outcome {
        BlindSpotMergeOutcome::Swept(inputs) => json!({
            "status": "swept",
            "pairs": DEFAULT_BLIND_SPOT_PAIRS
                .iter()
                .map(|pair| pair.pair_key())
                .collect::<Vec<_>>(),
            "scored_symbols": inputs.scored_symbols,
            "skipped_symbols": inputs.skipped_symbols,
            "substrate_rows": inputs.substrates.len(),
            "calibrations": inputs.calibrations.len(),
            "deficits": inputs.deficits.iter().map(|deficit| json!({
                "pair_key": deficit.pair_key,
                "code": deficit.code,
                "message": deficit.message,
                "n_eff": deficit.n_eff,
            })).collect::<Vec<_>>(),
        }),
        BlindSpotMergeOutcome::Unavailable(reason) => json!({
            "status": "unavailable",
            "reason": reason,
            "trust": "provisional",
        }),
    }
}

pub(crate) fn read_anomaly_report_metadata(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "anomaly_report_json"))?
    else {
        return Ok(anomaly_report_unavailable_json(
            "anomaly report metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(anomaly_report_unavailable_json(&format!(
            "stored anomaly_report_json invalid: {error}"
        ))),
    }
}

pub(crate) fn filter_anomaly_report_json(
    mut report: Value,
    kind_filter: Option<&str>,
) -> Result<Value, DynError> {
    let Some(kind_filter) = kind_filter else {
        return Ok(report);
    };
    let kind = kind_filter.parse::<AnomalyKind>()?;
    if let Some(findings) = report.get_mut("findings").and_then(Value::as_array_mut) {
        findings.retain(|finding| finding["kind"] == kind.as_str());
        report["finding_count"] = json!(findings.len());
    }
    if let Some(skipped) = report.get_mut("skipped").and_then(Value::as_array_mut) {
        skipped.retain(|skipped| skipped["kind"] == kind.as_str());
        report["skipped_count"] = json!(skipped.len());
    }
    report["kind_filter"] = json!(kind.as_str());
    refresh_anomaly_report_counts_and_artifact(&mut report);
    Ok(report)
}

pub(crate) fn merge_prompt_injection_anomalies(
    mut report: Value,
    security: Value,
    project: &str,
) -> Value {
    let Some(prompt) = security.get("prompt_injection") else {
        return report;
    };
    let findings = prompt
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let skips = prompt
        .get("skips")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if findings.is_empty() && skips.is_empty() {
        return report;
    }
    if !report.is_object() {
        report = anomaly_report_unavailable_json(
            "stored anomaly report was not a JSON object while merging prompt-injection findings",
        );
    }
    let report_obj = report.as_object_mut().expect("report object");
    if !report_obj
        .get("findings")
        .is_some_and(serde_json::Value::is_array)
    {
        report_obj.insert("findings".to_string(), json!([]));
    }
    if !report_obj
        .get("skipped")
        .is_some_and(serde_json::Value::is_array)
    {
        report_obj.insert("skipped".to_string(), json!([]));
    }

    let prompt_findings = findings
        .iter()
        .map(|finding| prompt_injection_anomaly_finding_json(finding, project))
        .collect::<Vec<_>>();
    report_obj
        .get_mut("findings")
        .and_then(Value::as_array_mut)
        .expect("findings array")
        .extend(prompt_findings);

    let prompt_skips = skips
        .iter()
        .map(prompt_injection_anomaly_skip_json)
        .collect::<Vec<_>>();
    report_obj
        .get_mut("skipped")
        .and_then(Value::as_array_mut)
        .expect("skipped array")
        .extend(prompt_skips);

    report_obj.insert(
        "prompt_injection_screen".to_string(),
        json!({
            "screen": PROMPT_INJECTION_FINDING_KIND,
            "status": prompt.get("status").cloned().unwrap_or(Value::Null),
            "pattern_registry_version": prompt
                .get("pattern_registry_version")
                .cloned()
                .unwrap_or_else(|| json!(PROMPT_INJECTION_PATTERN_REGISTRY_VERSION)),
            "finding_count": prompt.get("finding_count").cloned().unwrap_or(Value::Null),
            "skipped_count": prompt.get("skipped_count").cloned().unwrap_or(Value::Null),
            "source": format!("config:{}", metadata_key(project, "security_screen_json")),
        }),
    );
    refresh_anomaly_report_counts_and_artifact(&mut report);
    report
}

pub(crate) fn prompt_injection_anomaly_finding_json(finding: &Value, project: &str) -> Value {
    let source_id = finding
        .get("source_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let pattern_id = finding
        .get("pattern_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let family = finding
        .get("family")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let source_kind = finding
        .get("source_kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    json!({
        "kind": AnomalyKind::PromptInjection.as_str(),
        "subject_id": source_id,
        "severity": finding.get("severity").cloned().unwrap_or_else(|| json!("medium")),
        "score_millipoints": Value::Null,
        "message": format!("prompt-injection-shaped prose matched {pattern_id} in {source_id}"),
        "substrate_provenance_refs": [
            format!("security_screen:{project}:prompt_injection:{source_kind}:{source_id}")
        ],
        "calibration_provenance_ref": PROMPT_INJECTION_PATTERN_REGISTRY_VERSION,
        "lens_evidence": [
            format!("prompt_injection:{pattern_id}"),
            format!("family:{family}")
        ],
        "source_kind": source_kind,
        "pattern_id": pattern_id,
        "family": family,
        "matched_signature": finding.get("matched_signature").cloned().unwrap_or(Value::Null),
        "freshness": finding.get("freshness").cloned().unwrap_or_else(|| json!("fresh")),
        "trust": finding.get("trust").cloned().unwrap_or_else(|| json!("provisional")),
        "remediation": finding.get("remediation").cloned().unwrap_or(Value::Null),
    })
}

pub(crate) fn prompt_injection_anomaly_skip_json(skip: &Value) -> Value {
    json!({
        "kind": AnomalyKind::PromptInjection.as_str(),
        "subject_id": skip
            .get("subject")
            .or_else(|| skip.get("source_id"))
            .cloned()
            .unwrap_or_else(|| json!("project")),
        "reason": skip
            .get("reason")
            .cloned()
            .unwrap_or_else(|| json!("prompt_injection_screen_skipped")),
        "freshness": skip
            .get("freshness")
            .cloned()
            .unwrap_or_else(|| json!("not_evaluated")),
        "trust": skip
            .get("trust")
            .cloned()
            .unwrap_or_else(|| json!("provisional")),
    })
}

pub(crate) fn refresh_anomaly_report_counts_and_artifact(report: &mut Value) {
    let finding_count = report
        .get("findings")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let skipped_count = report
        .get("skipped")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let metadata_skipped_count = report
        .get("metadata_skipped_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let previous_status = report
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    if previous_status != "unavailable" || finding_count > 0 || skipped_count > 0 {
        report["status"] = json!(if skipped_count > 0
            || metadata_skipped_count > 0
            || previous_status == "unavailable"
        {
            "partial"
        } else if finding_count == 0 {
            "empty"
        } else {
            "built"
        });
        report["freshness"] = json!("fresh");
    }
    report["finding_count"] = json!(finding_count);
    report["skipped_count"] = json!(skipped_count);
    report["trust"] = if anomaly_report_all_entries_verified(report) {
        json!("verified")
    } else {
        json!("provisional")
    };

    let mut artifact_source = report.clone();
    if let Some(object) = artifact_source.as_object_mut() {
        object.remove("artifact_sha256");
    }
    let artifact_bytes = serde_json::to_vec(&artifact_source).unwrap_or_default();
    report["artifact_sha256"] = json!(hex_lower(&Sha256::digest(&artifact_bytes)));
}

pub(crate) fn anomaly_report_all_entries_verified(report: &Value) -> bool {
    let status = report
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    if status == "unavailable" {
        return false;
    }
    let metadata_skipped_count = report
        .get("metadata_skipped_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if metadata_skipped_count > 0 {
        return false;
    }
    let findings_verified =
        report
            .get("findings")
            .and_then(Value::as_array)
            .is_none_or(|findings| {
                findings
                    .iter()
                    .all(|finding| finding.get("trust").and_then(Value::as_str) == Some("verified"))
            });
    let skips_verified = report
        .get("skipped")
        .and_then(Value::as_array)
        .is_none_or(|skips| {
            skips
                .iter()
                .all(|skip| skip.get("trust").and_then(Value::as_str) == Some("verified"))
        });
    findings_verified && skips_verified
}
