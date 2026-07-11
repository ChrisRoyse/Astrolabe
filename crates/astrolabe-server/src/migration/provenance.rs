use super::*;
pub(crate) const PROVENANCE_SURFACE_SCHEMA: &str = "astrolabe.provenance_surface.v1";

pub(crate) fn provenance_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let fingerprint = hex_lower(&row_sink_fingerprint(rows));
    let ledger_head = LedgerPointer::new(0, format!("row-sink:{fingerprint}"));
    let mut store = ProvenanceStore {
        vault_fingerprint: format!("row-sink:{fingerprint}"),
        ledger_head: ledger_head.clone(),
        chain: ChainVerification {
            status: ChainStatus::Intact,
            checked_from: 0,
            // Row-sink provenance has no durable ledger: the attested range is empty
            // (checked_end == checked_from), so no sequence is fabricated as verified.
            checked_end: 0,
            provenance: ledger_head,
        },
        symbols: BTreeMap::new(),
        answers: BTreeMap::new(),
        reproductions: BTreeMap::new(),
        manifests: BTreeMap::new(),
    };
    let mut skipped_properties = 0usize;

    for node in &rows.nodes {
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        if let Some(lineage) = symbol_lineage_from_node(node, &properties, &mut skipped_properties)
        {
            store.symbols.insert(lineage.symbol_id.clone(), lineage);
        }
        if let Some(trace) = answer_trace_from_properties(&properties, &mut skipped_properties) {
            store.answers.insert(trace.answer_id.clone(), trace);
        }
        if let Some(record) = reproduce_record_from_properties(&properties, &mut skipped_properties)
        {
            store.reproductions.insert(record.answer_id.clone(), record);
        }
        if let Some(manifest) = pack_manifest_from_properties(&properties, &mut skipped_properties)
        {
            store.manifests.insert(manifest.pack_id.clone(), manifest);
        }
    }

    if store.symbols.is_empty()
        && store.answers.is_empty()
        && store.reproductions.is_empty()
        && store.manifests.is_empty()
    {
        return provenance_unavailable_json(
            "provenance metadata missing; row-sink nodes must declare provenance_lineage, provenance_answer, provenance_reproduce, or provenance_manifest blocks",
        );
    }

    provenance_surface_json(&store, skipped_properties)
}

pub(crate) fn symbol_lineage_from_node(
    node: &astrolabe_bridge::CbmPipelineNodeRow,
    properties: &Value,
    skipped_properties: &mut usize,
) -> Option<SymbolLineage> {
    if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
        return None;
    }
    let events = properties
        .get("provenance_lineage")
        .or_else(|| properties.get("lineage_events"))
        .and_then(Value::as_array)?;
    let symbol_id = properties
        .get("provenance_symbol_id")
        .or_else(|| properties.get("symbol_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&node.qualified_name);
    let versions = events
        .iter()
        .filter_map(|event| lineage_event_from_value(event, skipped_properties))
        .collect::<Vec<_>>();
    if versions.is_empty() {
        *skipped_properties += 1;
        return None;
    }
    Some(SymbolLineage {
        symbol_id: symbol_id.to_string(),
        versions,
    })
}

pub(crate) fn lineage_event_from_value(
    value: &Value,
    skipped_properties: &mut usize,
) -> Option<astrolabe_provenance::LineageEvent> {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let ledger = value
        .get("ledger")
        .and_then(ledger_pointer_from_value)
        .or_else(|| ledger_pointer_from_value(value));
    let summary = value
        .get("summary")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (Some(kind), Some(ledger), Some(summary)) = (kind, ledger, summary) else {
        *skipped_properties += 1;
        return None;
    };
    Some(astrolabe_provenance::LineageEvent {
        kind: kind.to_string(),
        ledger,
        summary: summary.to_string(),
    })
}

pub(crate) fn answer_trace_from_properties(
    properties: &Value,
    skipped_properties: &mut usize,
) -> Option<AnswerTrace> {
    let value = properties
        .get("provenance_answer")
        .or_else(|| properties.get("answer_trace"))?;
    let Some(answer_id) = value
        .get("answer_id")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        *skipped_properties += 1;
        return None;
    };
    let kernel_entry = optional_ledger_pointer_field(value, "kernel_entry", skipped_properties);
    let fusion_weights_ref =
        optional_ledger_pointer_field(value, "fusion_weights_ref", skipped_properties);
    let guard_verdict_ref =
        optional_ledger_pointer_field(value, "guard_verdict_ref", skipped_properties);
    let hops = value
        .get("hops")
        .and_then(Value::as_array)
        .map(|hops| {
            hops.iter()
                .filter_map(|hop| answer_hop_from_value(hop, skipped_properties))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // The freshness block carries the answer's as-of ledger watermark; downstream
    // freshness is measured as the gap between it and the current head. A missing block
    // used to be fabricated as `fresh(max input seq)`, an unfalsifiable freshness claim.
    // Require it: an absent or malformed freshness block means the trace is skipped
    // (counted in `skipped_properties`), never defaulted to fresh.
    let Some(freshness) = value.get("freshness").and_then(freshness_from_value) else {
        *skipped_properties += 1;
        return None;
    };
    Some(AnswerTrace {
        answer_id: answer_id.to_string(),
        kernel_entry,
        hops,
        fusion_weights_ref,
        guard_verdict_ref,
        freshness,
    })
}

pub(crate) fn answer_hop_from_value(
    value: &Value,
    skipped_properties: &mut usize,
) -> Option<AnswerHop> {
    let from_symbol = value
        .get("from_symbol")
        .or_else(|| value.get("from"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let to_symbol = value
        .get("to_symbol")
        .or_else(|| value.get("to"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let ledger = value.get("ledger").and_then(ledger_pointer_from_value);
    let (Some(from_symbol), Some(to_symbol), Some(ledger)) = (from_symbol, to_symbol, ledger)
    else {
        *skipped_properties += 1;
        return None;
    };
    Some(AnswerHop {
        from_symbol: from_symbol.to_string(),
        to_symbol: to_symbol.to_string(),
        ledger,
    })
}

pub(crate) fn reproduce_record_from_properties(
    properties: &Value,
    skipped_properties: &mut usize,
) -> Option<ReproduceRecord> {
    let value = properties
        .get("provenance_reproduce")
        .or_else(|| properties.get("reproduce_record"))?;
    let answer_id = value
        .get("answer_id")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let recorded_digest = value
        .get("recorded_digest")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let current_digest = value
        .get("current_digest")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let drift_microunits = value.get("drift_microunits").and_then(Value::as_u64);
    let drift_bound_microunits = value.get("drift_bound_microunits").and_then(Value::as_u64);
    let ledger = value.get("ledger").and_then(ledger_pointer_from_value);
    let (
        Some(answer_id),
        Some(recorded_digest),
        Some(current_digest),
        Some(drift_microunits),
        Some(drift_bound_microunits),
        Some(ledger),
    ) = (
        answer_id,
        recorded_digest,
        current_digest,
        drift_microunits,
        drift_bound_microunits,
        ledger,
    )
    else {
        *skipped_properties += 1;
        return None;
    };
    Some(ReproduceRecord {
        answer_id: answer_id.to_string(),
        recorded_digest: recorded_digest.to_string(),
        current_digest: current_digest.to_string(),
        drift_microunits,
        drift_bound_microunits,
        ledger,
    })
}

pub(crate) fn pack_manifest_from_properties(
    properties: &Value,
    skipped_properties: &mut usize,
) -> Option<PackManifest> {
    let value = properties
        .get("provenance_manifest")
        .or_else(|| properties.get("pack_manifest"))?;
    let pack_id = value
        .get("pack_id")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let ledger_ref = value.get("ledger_ref").and_then(ledger_pointer_from_value);
    let member_hash = value
        .get("member_hash")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    // `vault_fingerprint` is one of the four checks a manifest is verified against, so it
    // is required, not defaulted. A manifest declaring no fingerprint used to be stamped
    // with the store default — letting a fingerprint-less manifest "verify". It is now a
    // required field: absent/empty means the manifest is skipped (counted), not fabricated.
    let vault_fingerprint = value
        .get("vault_fingerprint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (Some(pack_id), Some(ledger_ref), Some(member_hash), Some(vault_fingerprint)) =
        (pack_id, ledger_ref, member_hash, vault_fingerprint)
    else {
        *skipped_properties += 1;
        return None;
    };
    Some(PackManifest {
        pack_id: pack_id.to_string(),
        ledger_ref,
        vault_fingerprint: vault_fingerprint.to_string(),
        member_hash: member_hash.to_string(),
    })
}

pub(crate) fn optional_ledger_pointer_field(
    value: &Value,
    field: &str,
    skipped_properties: &mut usize,
) -> Option<LedgerPointer> {
    let raw = value.get(field)?;
    let pointer = ledger_pointer_from_value(raw);
    if pointer.is_none() {
        *skipped_properties += 1;
    }
    pointer
}

pub(crate) fn ledger_pointer_from_value(value: &Value) -> Option<LedgerPointer> {
    let seq = value
        .get("seq")
        .or_else(|| value.get("ledger_seq"))
        .and_then(Value::as_u64)?;
    let chain_hash = value
        .get("chain_hash")
        .or_else(|| value.get("ledger_hash"))
        .or_else(|| value.get("hash"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(LedgerPointer::new(seq, chain_hash))
}

pub(crate) fn freshness_from_value(value: &Value) -> Option<Freshness> {
    let seq = value.get("seq").and_then(Value::as_u64)?;
    let stale_by = value
        .get("stale_by")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Some(Freshness { seq, stale_by })
}

pub(crate) fn provenance_surface_with_chain(
    mut surface: Value,
    vault_fingerprint: &str,
    ledger_seq: u64,
    verify: &astrolabe_ingest::VerifyChainReport,
) -> Value {
    if surface.get("status").and_then(Value::as_str) == Some("unavailable") {
        return surface;
    }
    let ledger_head = LedgerPointer::new(ledger_seq, vault_fingerprint);
    let chain = chain_verification_from_report(verify, ledger_head.clone());
    if let Some(store) = surface.get_mut("store").and_then(Value::as_object_mut) {
        store.insert(
            "vault_fingerprint".to_string(),
            Value::String(vault_fingerprint.to_string()),
        );
        store.insert("ledger_head".to_string(), ledger_pointer_json(&ledger_head));
        store.insert("chain".to_string(), chain_verification_json(&chain));
        refresh_manifest_vault_fingerprints(store, vault_fingerprint);
    }
    surface["vault_fingerprint"] = Value::String(vault_fingerprint.to_string());
    surface["ledger_head"] = ledger_pointer_json(&ledger_head);
    surface["chain"] = chain_verification_json(&chain);
    if let Some(store) = surface.get("store") {
        surface["artifact_sha256"] = Value::String(hex_lower(&Sha256::digest(
            provenance_store_artifact_bytes(store),
        )));
    }
    surface
}

pub(crate) fn refresh_manifest_vault_fingerprints(
    store: &mut Map<String, Value>,
    vault_fingerprint: &str,
) {
    let Some(manifests) = store.get_mut("manifests").and_then(Value::as_object_mut) else {
        return;
    };
    for manifest in manifests.values_mut() {
        let should_replace = manifest
            .get("vault_fingerprint")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.starts_with("row-sink:"));
        if should_replace && let Some(manifest_obj) = manifest.as_object_mut() {
            manifest_obj.insert(
                "vault_fingerprint".to_string(),
                Value::String(vault_fingerprint.to_string()),
            );
        }
    }
}

pub(crate) fn chain_verification_from_report(
    verify: &astrolabe_ingest::VerifyChainReport,
    provenance: LedgerPointer,
) -> ChainVerification {
    let status = match verify.status.as_str() {
        "intact" => ChainStatus::Intact,
        "broken" => ChainStatus::Broken {
            seq: verify.at_seq.unwrap_or(verify.checked_range_end),
        },
        "corrupt" => ChainStatus::Corrupt {
            seq: verify.at_seq.unwrap_or(verify.checked_range_end),
            reason: verify
                .reason
                .clone()
                .unwrap_or_else(|| "ledger verifier reported corruption".to_string()),
        },
        other => ChainStatus::Corrupt {
            seq: verify.at_seq.unwrap_or(verify.checked_range_end),
            reason: format!("unknown ledger verifier status {other}"),
        },
    };
    ChainVerification {
        status,
        checked_from: verify.checked_range_start,
        // `checked_range_end` is already the exclusive upper bound. Passing it straight
        // through (instead of the former `end - 1`) removes the empty-range off-by-one:
        // an unchecked ledger (`end == 0`) now reports an empty range rather than falsely
        // claiming seq 0 was verified.
        checked_end: verify.checked_range_end,
        provenance,
    }
}

pub(crate) fn provenance_surface_json(store: &ProvenanceStore, skipped_properties: usize) -> Value {
    let store_json = provenance_store_json(store);
    let artifact_bytes = provenance_store_artifact_bytes(&store_json);
    let total_records = store.symbols.len()
        + store.answers.len()
        + store.reproductions.len()
        + store.manifests.len();
    json!({
        "schema": PROVENANCE_SURFACE_SCHEMA,
        "tool_schema": GET_PROVENANCE_SCHEMA,
        "status": if skipped_properties == 0 { "built" } else { "partial" },
        "record_count": total_records,
        "symbol_count": store.symbols.len(),
        "answer_count": store.answers.len(),
        "reproduce_count": store.reproductions.len(),
        "manifest_count": store.manifests.len(),
        "metadata_skipped_count": skipped_properties,
        "vault_fingerprint": store.vault_fingerprint,
        "ledger_head": ledger_pointer_json(&store.ledger_head),
        "chain": chain_verification_json(&store.chain),
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "store": store_json,
        "freshness": "fresh",
        "trust": if skipped_properties == 0 { "verified" } else { "provisional" },
    })
}

pub(crate) fn provenance_store_artifact_bytes(store_json: &Value) -> Vec<u8> {
    serde_json::to_vec(store_json).unwrap_or_default()
}

pub(crate) fn provenance_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": PROVENANCE_SURFACE_SCHEMA,
        "tool_schema": GET_PROVENANCE_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with explicit provenance metadata before using get_provenance",
    })
}

pub(crate) fn read_provenance_metadata(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "provenance_json"))? else {
        return Ok(provenance_unavailable_json(
            "provenance metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(provenance_unavailable_json(&format!(
            "stored provenance_json invalid: {error}"
        ))),
    }
}

pub(crate) fn provenance_store_for_project(
    cache_dir: &Path,
    project: &str,
) -> Result<ProvenanceStore, DynError> {
    let surface = read_provenance_metadata(cache_dir, project)?;
    if surface.get("status").and_then(Value::as_str) == Some("unavailable") {
        let reason = surface
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("provenance metadata unavailable");
        let remediation = surface
            .get("remediation")
            .and_then(Value::as_str)
            .unwrap_or("rerun index_repository with explicit provenance metadata");
        return Err(format!("{reason}; remediation: {remediation}").into());
    }
    let mut store = provenance_store_from_json(
        surface
            .get("store")
            .ok_or("stored provenance_json missing store")?,
    )?;
    let configured_vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    if !configured_vault_dir.exists() {
        return Err(format!(
            "get_provenance cannot verify shadow vault bytes; vault dir missing: {}",
            configured_vault_dir.display()
        )
        .into());
    }
    let verify = astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir)?;
    // Verify-relevant metadata must be present and well-formed. A missing fingerprint
    // used to silently fall back to the ledger chain hash and a corrupt `ledger_seq`
    // silently fell back to the persisted head seq, fabricating verification inputs and
    // a freshness watermark. Both now fail closed with a coded `{code,message,remediation}`
    // error rather than reading as verified/fresh.
    let chain_hash = astrolabe_provenance::require_verify_metadata(
        "lowered_vault_fingerprint_sha256",
        read_config_value(
            cache_dir,
            &metadata_key(project, "lowered_vault_fingerprint_sha256"),
        )?
        .as_deref(),
    )?;
    let ledger_seq = astrolabe_provenance::require_ledger_seq(
        "ledger_seq",
        read_config_value(cache_dir, &metadata_key(project, "ledger_seq"))?.as_deref(),
    )?;
    let ledger_head = LedgerPointer::new(ledger_seq, chain_hash.clone());
    store.vault_fingerprint = chain_hash;
    store.ledger_head = ledger_head.clone();
    store.chain = chain_verification_from_report(&verify, ledger_head);
    Ok(store)
}

pub(crate) fn provenance_store_json(store: &ProvenanceStore) -> Value {
    json!({
        "vault_fingerprint": store.vault_fingerprint,
        "ledger_head": ledger_pointer_json(&store.ledger_head),
        "chain": chain_verification_json(&store.chain),
        "symbols": value_map(store.symbols.iter().map(|(key, lineage)| {
            (key.clone(), symbol_lineage_json(lineage))
        })),
        "answers": value_map(store.answers.iter().map(|(key, trace)| {
            (key.clone(), answer_trace_json(trace))
        })),
        "reproductions": value_map(store.reproductions.iter().map(|(key, record)| {
            (key.clone(), reproduce_record_json(record))
        })),
        "manifests": value_map(store.manifests.iter().map(|(key, manifest)| {
            (key.clone(), pack_manifest_json(manifest))
        })),
    })
}

pub(crate) fn provenance_store_from_json(value: &Value) -> Result<ProvenanceStore, DynError> {
    let object = required_object(value, "provenance store")?;
    let symbols = object
        .get("symbols")
        .and_then(Value::as_object)
        .ok_or("provenance store missing symbols")?
        .iter()
        .map(|(key, value)| Ok((key.clone(), symbol_lineage_from_json(value)?)))
        .collect::<Result<BTreeMap<_, _>, DynError>>()?;
    let answers = object
        .get("answers")
        .and_then(Value::as_object)
        .ok_or("provenance store missing answers")?
        .iter()
        .map(|(key, value)| Ok((key.clone(), answer_trace_from_json(value)?)))
        .collect::<Result<BTreeMap<_, _>, DynError>>()?;
    let reproductions = object
        .get("reproductions")
        .and_then(Value::as_object)
        .ok_or("provenance store missing reproductions")?
        .iter()
        .map(|(key, value)| Ok((key.clone(), reproduce_record_from_json(value)?)))
        .collect::<Result<BTreeMap<_, _>, DynError>>()?;
    let manifests = object
        .get("manifests")
        .and_then(Value::as_object)
        .ok_or("provenance store missing manifests")?
        .iter()
        .map(|(key, value)| Ok((key.clone(), pack_manifest_from_json(value)?)))
        .collect::<Result<BTreeMap<_, _>, DynError>>()?;
    Ok(ProvenanceStore {
        vault_fingerprint: required_string_field(value, "vault_fingerprint")?,
        ledger_head: ledger_pointer_from_json(required_value_field(value, "ledger_head")?)?,
        chain: chain_verification_from_json(required_value_field(value, "chain")?)?,
        symbols,
        answers,
        reproductions,
        manifests,
    })
}

pub(crate) fn provenance_response_json(project: &str, response: &ProvenanceResponse) -> Value {
    let artifact_bytes = provenance_response_artifact_bytes(response);
    json!({
        "schema": response.schema,
        "project": project,
        "status": "built",
        "mode": response.mode.as_str(),
        "trust": response.trust,
        "freshness": freshness_json(&response.freshness),
        "provenance": ledger_pointer_json(&response.provenance),
        "warning_count": response.warnings.len(),
        "warnings": response.warnings.iter().map(|warning| {
            json!({
                "code": warning.code,
                "message": warning.message,
            })
        }).collect::<Vec<_>>(),
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "payload": provenance_payload_json(&response.payload),
    })
}

pub(crate) fn provenance_payload_json(payload: &ProvenancePayload) -> Value {
    match payload {
        ProvenancePayload::Lineage(lineage) => {
            json!({
                "kind": "lineage",
                "lineage": symbol_lineage_json(lineage),
            })
        }
        ProvenancePayload::AnswerTrace(trace) => {
            json!({
                "kind": "answer_trace",
                "answer_trace": answer_trace_json(trace),
            })
        }
        ProvenancePayload::VerifyChain(chain) => {
            json!({
                "kind": "verify_chain",
                "verify_chain": chain_verification_json(chain),
            })
        }
        ProvenancePayload::Reproduce(report) => {
            json!({
                "kind": "reproduce",
                "reproduce": {
                    "answer_id": report.answer_id,
                    "bit_exact": report.bit_exact,
                    "drift_microunits": report.drift_microunits,
                    "drift_bound_microunits": report.drift_bound_microunits,
                    "recorded_digest": report.recorded_digest,
                    "current_digest": report.current_digest,
                },
            })
        }
    }
}

pub(crate) fn symbol_lineage_json(lineage: &SymbolLineage) -> Value {
    json!({
        "symbol_id": lineage.symbol_id,
        "versions": lineage.versions.iter().map(|event| {
            json!({
                "kind": event.kind,
                "ledger": ledger_pointer_json(&event.ledger),
                "summary": event.summary,
            })
        }).collect::<Vec<_>>(),
    })
}

pub(crate) fn symbol_lineage_from_json(value: &Value) -> Result<SymbolLineage, DynError> {
    Ok(SymbolLineage {
        symbol_id: required_string_field(value, "symbol_id")?,
        versions: required_value_field(value, "versions")?
            .as_array()
            .ok_or("symbol lineage versions must be an array")?
            .iter()
            .map(lineage_event_from_json)
            .collect::<Result<Vec<_>, DynError>>()?,
    })
}

pub(crate) fn lineage_event_from_json(
    value: &Value,
) -> Result<astrolabe_provenance::LineageEvent, DynError> {
    Ok(astrolabe_provenance::LineageEvent {
        kind: required_string_field(value, "kind")?,
        ledger: ledger_pointer_from_json(required_value_field(value, "ledger")?)?,
        summary: required_string_field(value, "summary")?,
    })
}

pub(crate) fn answer_trace_json(trace: &AnswerTrace) -> Value {
    json!({
        "answer_id": trace.answer_id,
        "kernel_entry": trace.kernel_entry.as_ref().map(ledger_pointer_json),
        "hops": trace.hops.iter().map(answer_hop_json).collect::<Vec<_>>(),
        "fusion_weights_ref": trace.fusion_weights_ref.as_ref().map(ledger_pointer_json),
        "guard_verdict_ref": trace.guard_verdict_ref.as_ref().map(ledger_pointer_json),
        "freshness": freshness_json(&trace.freshness),
    })
}

pub(crate) fn answer_trace_from_json(value: &Value) -> Result<AnswerTrace, DynError> {
    Ok(AnswerTrace {
        answer_id: required_string_field(value, "answer_id")?,
        kernel_entry: optional_ledger_pointer_from_json(value.get("kernel_entry"))?,
        hops: required_value_field(value, "hops")?
            .as_array()
            .ok_or("answer trace hops must be an array")?
            .iter()
            .map(answer_hop_from_json)
            .collect::<Result<Vec<_>, DynError>>()?,
        fusion_weights_ref: optional_ledger_pointer_from_json(value.get("fusion_weights_ref"))?,
        guard_verdict_ref: optional_ledger_pointer_from_json(value.get("guard_verdict_ref"))?,
        freshness: freshness_from_json(required_value_field(value, "freshness")?)?,
    })
}

pub(crate) fn answer_hop_json(hop: &AnswerHop) -> Value {
    json!({
        "from_symbol": hop.from_symbol,
        "to_symbol": hop.to_symbol,
        "ledger": ledger_pointer_json(&hop.ledger),
    })
}

pub(crate) fn answer_hop_from_json(value: &Value) -> Result<AnswerHop, DynError> {
    Ok(AnswerHop {
        from_symbol: required_string_field(value, "from_symbol")?,
        to_symbol: required_string_field(value, "to_symbol")?,
        ledger: ledger_pointer_from_json(required_value_field(value, "ledger")?)?,
    })
}

pub(crate) fn reproduce_record_json(record: &ReproduceRecord) -> Value {
    json!({
        "answer_id": record.answer_id,
        "recorded_digest": record.recorded_digest,
        "current_digest": record.current_digest,
        "drift_microunits": record.drift_microunits,
        "drift_bound_microunits": record.drift_bound_microunits,
        "ledger": ledger_pointer_json(&record.ledger),
    })
}

pub(crate) fn reproduce_record_from_json(value: &Value) -> Result<ReproduceRecord, DynError> {
    Ok(ReproduceRecord {
        answer_id: required_string_field(value, "answer_id")?,
        recorded_digest: required_string_field(value, "recorded_digest")?,
        current_digest: required_string_field(value, "current_digest")?,
        drift_microunits: required_u64_field(value, "drift_microunits")?,
        drift_bound_microunits: required_u64_field(value, "drift_bound_microunits")?,
        ledger: ledger_pointer_from_json(required_value_field(value, "ledger")?)?,
    })
}

pub(crate) fn pack_manifest_json(manifest: &PackManifest) -> Value {
    json!({
        "pack_id": manifest.pack_id,
        "ledger_ref": ledger_pointer_json(&manifest.ledger_ref),
        "vault_fingerprint": manifest.vault_fingerprint,
        "member_hash": manifest.member_hash,
    })
}

pub(crate) fn pack_manifest_from_json(value: &Value) -> Result<PackManifest, DynError> {
    Ok(PackManifest {
        pack_id: required_string_field(value, "pack_id")?,
        ledger_ref: ledger_pointer_from_json(required_value_field(value, "ledger_ref")?)?,
        vault_fingerprint: required_string_field(value, "vault_fingerprint")?,
        member_hash: required_string_field(value, "member_hash")?,
    })
}

pub(crate) fn ledger_pointer_json(pointer: &LedgerPointer) -> Value {
    json!({
        "seq": pointer.seq,
        "chain_hash": pointer.chain_hash,
    })
}

pub(crate) fn ledger_pointer_from_json(value: &Value) -> Result<LedgerPointer, DynError> {
    Ok(LedgerPointer::new(
        required_u64_field(value, "seq")?,
        required_string_field(value, "chain_hash")?,
    ))
}

pub(crate) fn optional_ledger_pointer_from_json(
    value: Option<&Value>,
) -> Result<Option<LedgerPointer>, DynError> {
    match value {
        Some(Value::Null) | None => Ok(None),
        Some(value) => ledger_pointer_from_json(value).map(Some),
    }
}

pub(crate) fn freshness_json(freshness: &Freshness) -> Value {
    json!({
        "seq": freshness.seq,
        "stale_by": freshness.stale_by,
    })
}

pub(crate) fn freshness_from_json(value: &Value) -> Result<Freshness, DynError> {
    let stale_by = value
        .get("stale_by")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(Freshness {
        seq: required_u64_field(value, "seq")?,
        stale_by,
    })
}

pub(crate) fn chain_verification_json(chain: &ChainVerification) -> Value {
    let mut status = json!({
        "status": chain.status.as_str(),
    });
    if let Some(status_obj) = status.as_object_mut() {
        match &chain.status {
            ChainStatus::Intact => {}
            ChainStatus::Broken { seq } => {
                status_obj.insert("seq".to_string(), json!(seq));
            }
            ChainStatus::Corrupt { seq, reason } => {
                status_obj.insert("seq".to_string(), json!(seq));
                status_obj.insert("reason".to_string(), json!(reason));
            }
        }
    }
    json!({
        "status": status,
        "checked_from": chain.checked_from,
        "checked_end": chain.checked_end,
        // Inclusive last checked seq, or null for an empty attested range: never a
        // fabricated seq 0 for an unchecked ledger.
        "last_checked_seq": chain.last_checked_seq(),
        "provenance": ledger_pointer_json(&chain.provenance),
    })
}

pub(crate) fn chain_verification_from_json(value: &Value) -> Result<ChainVerification, DynError> {
    let status_value = required_value_field(value, "status")?;
    let status = match required_string_field(status_value, "status")?.as_str() {
        "intact" => ChainStatus::Intact,
        "broken" => ChainStatus::Broken {
            seq: required_u64_field(status_value, "seq")?,
        },
        "corrupt" => ChainStatus::Corrupt {
            seq: required_u64_field(status_value, "seq")?,
            reason: required_string_field(status_value, "reason")?,
        },
        other => return Err(format!("unknown provenance chain status {other}").into()),
    };
    Ok(ChainVerification {
        status,
        checked_from: required_u64_field(value, "checked_from")?,
        checked_end: required_u64_field(value, "checked_end")?,
        provenance: ledger_pointer_from_json(required_value_field(value, "provenance")?)?,
    })
}
