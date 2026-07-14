use super::*;
pub(crate) const PROVENANCE_SURFACE_SCHEMA: &str = "astrolabe.provenance_surface.v1";

/// Config metadata field holding the per-project reproduce fixtures: a JSON map of
/// `answer_id -> { recorded_artifact, graph }` written when a kernel answer is
/// served and recorded (#40/#343). `recorded_artifact` is the canonical
/// [`astrolabe_provenance::recorded_kernel_answer_bytes`] text; `graph` is the
/// frozen-lens current vault association graph the reproduce re-executes against.
pub(crate) const PROVENANCE_REPRODUCE_FIXTURE_FIELD: &str = "provenance_reproduce_fixture_json";

/// Wires `get_provenance(mode="reproduce")` to **live re-execution** of the #40
/// kernel answer engine against the persisted current vault graph (#67 DoD 1).
///
/// When a recorded reproduce fixture is persisted for `subject`, this re-runs the
/// answer engine with the recorded answer's frozen lenses/seeds against the
/// current graph and rewrites `store.reproductions[subject]` with the
/// live-measured digests and drift, so the served reproduce report reflects a real
/// re-derivation rather than two stored digests. A drift beyond the (tightening-
/// only) bound, or a current vault that no longer grounds the answer, propagates
/// the answer engine's coded [`astrolabe_provenance::REPRODUCE_DRIFT_EXCEEDED`]
/// refusal to the caller — never a verified-looking report.
///
/// It is a no-op for every other mode, when `subject` is absent, and when no
/// reproduce fixture is persisted yet (the pre-#343 state, in which reproduce
/// still serves the recorded digest/drift metadata path unchanged). The current
/// graph is produced by the `GraphProjectionCsr -> KernelGraph` vault adapter
/// (#343); until the kernel-answer server surface persists a fixture, no live
/// re-execution engages and existing behavior is preserved.
pub(crate) fn apply_live_reproduce(
    store: &mut ProvenanceStore,
    cache_dir: &Path,
    project: &str,
    mode: &str,
    subject: Option<&str>,
    drift_bound_override: Option<u64>,
) -> Result<(), DynError> {
    if mode != "reproduce" {
        return Ok(());
    }
    let Some(subject) = subject.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let Some(raw) = read_config_value(
        cache_dir,
        &metadata_key(project, PROVENANCE_REPRODUCE_FIXTURE_FIELD),
    )?
    else {
        return Ok(());
    };
    let fixtures = serde_json::from_str::<Value>(&raw)?;
    let Some(fixture) = fixtures.get(subject) else {
        return Ok(());
    };

    let recorded_text = fixture
        .get("recorded_artifact")
        .and_then(Value::as_str)
        .ok_or("reproduce fixture missing recorded_artifact bytes")?;
    let recorded = astrolabe_provenance::parse_recorded_kernel_answer(recorded_text.as_bytes())
        .map_err(domain_error_to_dyn)?;
    let graph = fixture
        .get("graph")
        .ok_or("reproduce fixture missing current vault graph")?;
    let (nodes, edges, matched_ids) = parse_reproduce_graph(graph)?;

    let bound = astrolabe_provenance::resolve_drift_bound(drift_bound_override)
        .map_err(domain_error_to_dyn)?;
    let report = astrolabe_provenance::reproduce_kernel_answer(
        &recorded,
        &nodes,
        &edges,
        &matched_ids,
        bound,
    )
    .map_err(domain_error_to_dyn)?;

    // The live re-derivation stayed within the drift bound: serve the live-measured
    // digests/drift through the existing reproduce envelope (the crate re-derives
    // bit_exact and re-checks the bound over these values).
    store.reproductions.insert(
        subject.to_string(),
        ReproduceRecord {
            answer_id: report.answer_id,
            recorded_digest: report.recorded_digest,
            current_digest: report.current_digest,
            drift_microunits: report.drift_microunits,
            drift_bound_microunits: report.drift_bound_microunits,
            ledger: recorded.ledger,
        },
    );
    Ok(())
}

/// Parsed reproduce-fixture graph: the answer-engine inputs (`nodes`, `edges`,
/// `matched_ids`) decoded from a persisted fixture.
type ReproduceGraphParts = (
    Vec<astrolabe_kernel::AnswerNode>,
    Vec<astrolabe_kernel::AnswerEdge>,
    Vec<astrolabe_domain::calyx::CxId>,
);

/// Parses a persisted reproduce-fixture `graph` object into the answer-engine
/// inputs (`nodes`, `edges`, `matched_ids`), failing closed on a malformed graph.
fn parse_reproduce_graph(graph: &Value) -> Result<ReproduceGraphParts, DynError> {
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or("reproduce fixture graph missing nodes array")?
        .iter()
        .map(parse_reproduce_node)
        .collect::<Result<Vec<_>, DynError>>()?;
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or("reproduce fixture graph missing edges array")?
        .iter()
        .map(parse_reproduce_edge)
        .collect::<Result<Vec<_>, DynError>>()?;
    let matched_ids = graph
        .get("matched_ids")
        .and_then(Value::as_array)
        .ok_or("reproduce fixture graph missing matched_ids array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| DynError::from("matched id must be a hex string"))
                .and_then(|hex| parse_cx_id(hex))
        })
        .collect::<Result<Vec<_>, DynError>>()?;
    Ok((nodes, edges, matched_ids))
}

fn parse_reproduce_node(value: &Value) -> Result<astrolabe_kernel::AnswerNode, DynError> {
    let id = parse_cx_id(
        value
            .get("id")
            .and_then(Value::as_str)
            .ok_or("reproduce node missing id")?,
    )?;
    let qualified_name = value
        .get("qualified_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let grounded = value
        .get("grounded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let provenance_ref = value
        .get("provenance_ref")
        .and_then(Value::as_str)
        .map(str::to_string);
    let kernel_weight_permille = value
        .get("kernel_weight_permille")
        .and_then(Value::as_u64)
        .ok_or("reproduce node missing kernel_weight_permille")?;
    Ok(astrolabe_kernel::AnswerNode::new(
        id,
        qualified_name,
        grounded,
        provenance_ref,
        kernel_weight_permille,
    ))
}

fn parse_reproduce_edge(value: &Value) -> Result<astrolabe_kernel::AnswerEdge, DynError> {
    let src = parse_cx_id(
        value
            .get("src")
            .and_then(Value::as_str)
            .ok_or("reproduce edge missing src")?,
    )?;
    let dst = parse_cx_id(
        value
            .get("dst")
            .and_then(Value::as_str)
            .ok_or("reproduce edge missing dst")?,
    )?;
    let weight_permille = value
        .get("weight_permille")
        .and_then(Value::as_u64)
        .ok_or("reproduce edge missing weight_permille")?;
    let ledger_ref = value
        .get("ledger_ref")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(astrolabe_kernel::AnswerEdge::new(
        src,
        dst,
        weight_permille,
        ledger_ref,
    ))
}

fn parse_cx_id(hex: &str) -> Result<astrolabe_domain::calyx::CxId, DynError> {
    hex.trim()
        .parse::<astrolabe_domain::calyx::CxId>()
        .map_err(|_| DynError::from(format!("invalid CxId hex {hex:?}")))
}

/// Formats a coded [`astrolabe_domain::DomainError`] into a `{code}: {message};
/// remediation: {remediation}` boxed error so the reproduce handler surfaces the
/// engine's fail-closed refusal (e.g. `REPRODUCE_DRIFT_EXCEEDED`) verbatim.
fn domain_error_to_dyn(error: astrolabe_domain::DomainError) -> DynError {
    format!(
        "{}: {}; remediation: {}",
        error.code(),
        error.message(),
        error.remediation()
    )
    .into()
}

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
        } else if let Some(derived) = derived_symbol_lineage(node, &properties) {
            store.symbols.insert(derived.symbol_id.clone(), derived);
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

/// Chain-hash sentinel for a derived-at-index lineage event whose real ledger
/// pointer is not known until the import writes its ledger entry. Any lineage
/// ledger pointer carrying this prefix is rewritten to the real import head by
/// [`provenance_surface_with_chain`] (post-import), the same way manifest vault
/// fingerprints are refreshed. It must remain distinct from every real chain hash.
pub(crate) const DERIVED_LINEAGE_PENDING_CHAIN_HASH: &str = "row-sink:pending";

/// Derives a truthful minimal lineage for a real symbol node that declared no
/// explicit `provenance_lineage` block (#389).
///
/// Real-corpus nodes never carry provenance metadata, so the provenance surface
/// had no symbol producer and served unavailable forever. Every symbol a real
/// import materializes is attested by that import's single ledger entry, so the
/// honest minimal lineage is one `indexed` event pointing at the import ledger
/// head. The head is unknown at row-sink time, so the event is stamped with the
/// [`DERIVED_LINEAGE_PENDING_CHAIN_HASH`] sentinel and rewritten to the real head
/// post-import (see [`refresh_derived_lineage_ledgers`]).
///
/// Returns `None` for project/anonymous nodes (a truthful "no symbol") and for any
/// node that *declared* a lineage block (even a malformed one) — that node is the
/// explicit path's responsibility and must not be papered over with a derived
/// stub. So a project-only corpus keeps the surface labeled unavailable.
pub(crate) fn derived_symbol_lineage(
    node: &astrolabe_bridge::CbmPipelineNodeRow,
    properties: &Value,
) -> Option<SymbolLineage> {
    if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
        return None;
    }
    if properties.get("provenance_lineage").is_some() || properties.get("lineage_events").is_some()
    {
        return None;
    }
    let symbol_id = properties
        .get("provenance_symbol_id")
        .or_else(|| properties.get("symbol_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&node.qualified_name);
    let location = if node.file_path.trim().is_empty() {
        node.qualified_name.clone()
    } else {
        format!("{}:{}", node.file_path.trim(), node.start_line)
    };
    Some(SymbolLineage {
        symbol_id: symbol_id.to_string(),
        versions: vec![astrolabe_provenance::LineageEvent {
            kind: "indexed".to_string(),
            ledger: LedgerPointer::new(0, DERIVED_LINEAGE_PENDING_CHAIN_HASH),
            summary: format!("indexed {} from {location}", node.qualified_name),
        }],
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
        refresh_derived_lineage_ledgers(store, &ledger_head);
    }
    surface["vault_fingerprint"] = Value::String(vault_fingerprint.to_string());
    surface["ledger_head"] = ledger_pointer_json(&ledger_head);
    surface["chain"] = chain_verification_json(&chain);
    // #209: the chain just swapped in is a *different* verification result from the one the
    // surface was originally labeled against — this is the surface that gets persisted, so
    // it is the fail-open path that actually reaches disk. Without re-deriving the labels, a
    // surface built over the row-sink's `Intact`-but-empty chain would keep riding
    // `trust: "verified"` even after a `Broken`/`Corrupt` post-import chain replaced it.
    let metadata_complete = provenance_surface_metadata_complete(&surface);
    let labels = provenance_surface_labels(&chain, metadata_complete);
    surface["warnings"] = Value::Array(labels.warnings);
    surface["remediation"] = labels.remediation;
    surface["freshness"] = Value::String(labels.freshness.to_string());
    surface["trust"] = Value::String(labels.trust.to_string());
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

/// Rewrites every derived-at-index lineage event's placeholder ledger pointer to
/// the real import ledger head, post-import (#389).
///
/// A lineage version stamped with [`DERIVED_LINEAGE_PENDING_CHAIN_HASH`] was
/// produced by [`derived_symbol_lineage`] before the import wrote its ledger
/// entry; the real `ledger_head` (seq + lowered vault fingerprint) is exactly the
/// entry that attests the import that materialized the symbol, so pointing the
/// event at it makes the lineage truthful rather than fabricated. Explicit lineage
/// events carry real chain hashes and are left untouched.
pub(crate) fn refresh_derived_lineage_ledgers(
    store: &mut Map<String, Value>,
    ledger_head: &LedgerPointer,
) {
    let Some(symbols) = store.get_mut("symbols").and_then(Value::as_object_mut) else {
        return;
    };
    let head_json = ledger_pointer_json(ledger_head);
    for lineage in symbols.values_mut() {
        let Some(versions) = lineage.get_mut("versions").and_then(Value::as_array_mut) else {
            continue;
        };
        for version in versions {
            let is_derived = version
                .get("ledger")
                .and_then(|ledger| ledger.get("chain_hash"))
                .and_then(Value::as_str)
                .is_some_and(|hash| hash == DERIVED_LINEAGE_PENDING_CHAIN_HASH);
            if is_derived {
                version["ledger"] = head_json.clone();
            }
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

/// Envelope labels for a provenance surface, derived jointly from the metadata build and
/// the ledger chain the surface embeds.
pub(crate) struct ProvenanceSurfaceLabels {
    pub(crate) trust: &'static str,
    pub(crate) freshness: &'static str,
    pub(crate) warnings: Vec<Value>,
    pub(crate) remediation: Value,
}

/// Derives a provenance surface's `trust`/`freshness` from **both** the completeness of the
/// metadata build and the ledger chain the surface publishes (#209).
///
/// This is the build-surface counterpart of the `get_provenance` envelope rule fixed in
/// #109: an envelope label may never out-rank the weakest verification the envelope carries.
/// A surface that embeds a `Broken` or `Corrupt` chain — or an `Intact` chain whose attested
/// range is empty, which verified nothing at all — is therefore never labeled
/// `trust: "verified"`, no matter how completely its metadata built. Labeling such a surface
/// `verified` is the fail-open pattern: a consumer gating on the top-level label would treat
/// a store with a broken embedded chain as trustworthy.
pub(crate) fn provenance_surface_labels(
    chain: &ChainVerification,
    metadata_complete: bool,
) -> ProvenanceSurfaceLabels {
    let warnings = provenance_surface_chain_warnings(chain);
    let chain_verified = warnings.is_empty();
    ProvenanceSurfaceLabels {
        // Both conjuncts must hold. A complete metadata build over an unverified chain is
        // still unverified, and a verified chain under a partial build is still partial.
        trust: if chain_verified && metadata_complete {
            "verified"
        } else {
            "provisional"
        },
        // The surface's currency claim is anchored in the ledger head it reports. When the
        // chain backing that head is broken, corrupt, or attested nothing, the currency of
        // the surface was never established, so it is not labeled `fresh`.
        freshness: if chain_verified {
            "fresh"
        } else {
            "not_evaluated"
        },
        remediation: if chain_verified {
            Value::Null
        } else {
            Value::String(
                "the embedded ledger chain is not intact over a non-empty range; run \
                 get_provenance mode=\"verify_chain\", then repair or re-import the ledger \
                 before treating this surface as verified"
                    .to_string(),
            )
        },
        warnings,
    }
}

/// Coded chain-integrity warnings that force a provenance surface off `trust: "verified"`.
///
/// Reuses the `astrolabe-provenance` warning vocabulary so the build surface and the
/// `get_provenance` envelope name the same conditions with the same codes.
pub(crate) fn provenance_surface_chain_warnings(chain: &ChainVerification) -> Vec<Value> {
    match &chain.status {
        ChainStatus::Intact => {
            if chain.is_empty_range() {
                // An empty attested range verified nothing. Absence of evidence is not
                // evidence of integrity, so the envelope must never read `verified`.
                vec![json!({
                    "code": PROVENANCE_WARN_CHAIN_EMPTY,
                    "message": format!(
                        "the surface embeds an empty attested ledger range [{}, {}); zero \
                         entries were checked, so chain integrity is unverified",
                        chain.checked_from, chain.checked_end
                    ),
                })]
            } else {
                Vec::new()
            }
        }
        ChainStatus::Broken { seq } => vec![json!({
            "code": PROVENANCE_WARN_CHAIN_BROKEN,
            "message": format!(
                "ledger chain broken at seq {seq}; provenance is not trustworthy at or past \
                 this entry"
            ),
        })],
        ChainStatus::Corrupt { seq, reason } => vec![json!({
            "code": PROVENANCE_WARN_CHAIN_CORRUPT,
            "message": format!("ledger chain corrupt at seq {seq}: {reason}"),
        })],
    }
}

/// True only when a surface can *prove* its metadata build skipped nothing.
///
/// A surface missing the counter cannot prove completeness, so it is treated as incomplete:
/// absence of the counter is not evidence of zero skips.
pub(crate) fn provenance_surface_metadata_complete(surface: &Value) -> bool {
    surface
        .get("metadata_skipped_count")
        .and_then(Value::as_u64)
        == Some(0)
}

pub(crate) fn provenance_surface_json(store: &ProvenanceStore, skipped_properties: usize) -> Value {
    let store_json = provenance_store_json(store);
    let artifact_bytes = provenance_store_artifact_bytes(&store_json);
    let total_records = store.symbols.len()
        + store.answers.len()
        + store.reproductions.len()
        + store.manifests.len();
    // #209: the envelope is labeled against the chain it actually embeds, not against the
    // metadata build alone.
    let labels = provenance_surface_labels(&store.chain, skipped_properties == 0);
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
        "warnings": labels.warnings,
        "remediation": labels.remediation,
        "freshness": labels.freshness,
        "trust": labels.trust,
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

/// Ledger-subject-key tags emitted by [`astrolabe_ingest::ledger_subject_key`].
///
/// A `get_provenance(mode="lineage")` subject that carries one of these tags is a
/// request for the *real persisted ledger* history of that subject, so it is
/// served from the physical `ledger` column family (#284) rather than the
/// row-sink symbol metadata. A subject without one of these tags (for example a
/// bare qualified name like `auth.login`) is a row-sink symbol query and is left
/// to the existing `store.symbols` path untouched.
const LEDGER_SUBJECT_KEY_TAGS: [&str; 5] = ["cx:", "lens:", "kernel:", "guard:", "query:"];

/// True when `subject` is a canonical ledger subject key (see
/// [`astrolabe_ingest::ledger_subject_key`]), and therefore a request for real
/// persisted-ledger lineage rather than row-sink symbol metadata.
pub(crate) fn is_ledger_subject_key(subject: &str) -> bool {
    LEDGER_SUBJECT_KEY_TAGS
        .iter()
        .any(|tag| subject.starts_with(tag))
}

/// Overrides `store.symbols[subject]` with the honest lineage decoded from the
/// real persisted ledger when this is a ledger-subject lineage query (#284).
///
/// This is the exact wiring `handle_get_provenance` performs before serving a
/// `mode="lineage"` response: `get_provenance(mode="lineage")` for a ledger
/// subject key must be built from the persisted `ledger` column family, not from
/// row-sink JSON metadata. The scan
/// ([`astrolabe_ingest::scan_subject_ledger_rows_vault_path`]) verifies the whole
/// hash-chain before serving anything and fails **closed** on a non-intact chain
/// or an undecodable row; those refusals propagate to the caller as coded errors
/// rather than degrading into a row-sink answer.
///
/// A non-ledger subject (bare qualified name) is left untouched, so existing
/// row-sink symbol lineage is unaffected. A ledger subject with no persisted rows
/// is also left untouched, so `get_provenance`'s own fail-closed "not found"
/// still fires rather than fabricating an empty lineage.
pub(crate) fn apply_ledger_backed_lineage(
    store: &mut ProvenanceStore,
    cache_dir: &Path,
    project: &str,
    mode: &str,
    subject: Option<&str>,
) -> Result<(), DynError> {
    if mode != "lineage" {
        return Ok(());
    }
    let Some(subject) = subject.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !is_ledger_subject_key(subject) {
        return Ok(());
    }
    if let Some(lineage) = subject_lineage_from_ledger(cache_dir, project, subject)? {
        store.symbols.insert(subject.to_string(), lineage);
    }
    Ok(())
}

/// Scans the project's persisted ledger for `subject` and builds its
/// [`SymbolLineage`] straight from the decoded ledger rows (#284).
///
/// Resolves the same physical vault directory the rest of the provenance surface
/// verifies against, then delegates to
/// [`astrolabe_ingest::scan_subject_ledger_rows_vault_path`]. Returns `None` when
/// the intact ledger holds no row for `subject` (a truthful "no history"), and an
/// `Err` carrying the scan's coded refusal when the chain is not intact or a row
/// cannot be decoded — never a fabricated or partial lineage.
pub(crate) fn subject_lineage_from_ledger(
    cache_dir: &Path,
    project: &str,
    subject: &str,
) -> Result<Option<SymbolLineage>, DynError> {
    let configured_vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let rows =
        astrolabe_ingest::scan_subject_ledger_rows_vault_path(&configured_vault_dir, subject)?;
    Ok(symbol_lineage_from_scan_rows(subject, rows))
}

/// Maps subject-scoped [`astrolabe_ingest::LedgerScanRow`]s one-to-one onto a
/// [`SymbolLineage`] whose versions carry the rows' real persisted entry hashes as
/// their ledger chain pointers, in ascending sequence order.
///
/// Returns `None` for an empty row set so callers fall through to the
/// fail-closed "no lineage" path rather than serving an empty history.
pub(crate) fn symbol_lineage_from_scan_rows(
    subject: &str,
    rows: Vec<astrolabe_ingest::LedgerScanRow>,
) -> Option<SymbolLineage> {
    if rows.is_empty() {
        return None;
    }
    let versions = rows
        .into_iter()
        .map(|row| LineageEvent {
            kind: row.kind,
            ledger: LedgerPointer::new(row.seq, row.entry_hash),
            summary: row.summary,
        })
        .collect();
    Some(SymbolLineage {
        symbol_id: subject.to_string(),
        versions,
    })
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

/// Renders the labeled inter-agent trust envelope a verifying agent (agent B)
/// receives for a `get_provenance(mode="inter_agent_trust")` call (blueprint 9.5).
///
/// Every field is derived from [`verify_pack_manifest_claim`] against the serving
/// vault's persisted manifest — the report is only produced when the claim's
/// pack_id, ledger_ref, vault_fingerprint, and member_hash all match, so `trust`
/// is `verified` and `verified_checks` names exactly the confirmed checks. A
/// tampered claim never reaches this renderer: it fails closed with a coded
/// `ASTRO_PROVENANCE_MANIFEST_TAMPERED` (or attestation-corrupt) error naming the
/// failing check, surfaced by the handler as a tool error.
pub(crate) fn inter_agent_trust_report_json(
    project: &str,
    report: &InterAgentTrustReport,
) -> Value {
    json!({
        "schema": report.schema,
        "project": project,
        "status": "verified",
        "mode": "inter_agent_trust",
        "pack_id": report.pack_id,
        "ledger_ref": ledger_pointer_json(&report.ledger_ref),
        "vault_fingerprint": report.vault_fingerprint,
        "member_hash": report.member_hash,
        "verified_checks": report.verified_checks,
        "trust": report.trust,
        "freshness": freshness_json(&report.freshness),
        "provenance": ledger_pointer_json(&report.provenance),
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
