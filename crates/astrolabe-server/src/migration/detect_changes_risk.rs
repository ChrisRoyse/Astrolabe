use super::*;

use std::cmp::Reverse;

use astrolabe_kernel::{
    PreparedChangeReachGraph, ReachConfig, change_reach_artifact_blake3, reach_risk_permille,
};
use astrolabe_oracle::{OracleEvidence, PredictConfig, grounded_risk_required};
use calyx_core::CxId;

/// Envelope schema for the grounded-risk block layered onto `detect_changes`.
pub(crate) const DETECT_CHANGES_RISK_SCHEMA: &str = "astrolabe.detect_changes_grounded_risk.v2";
const ASTRO_DETECT_CHANGES_RESULT_INVALID: &str = "ASTRO_DETECT_CHANGES_RESULT_INVALID";
const ASTRO_DETECT_CHANGES_ARGUMENT_INVALID: &str = "ASTRO_DETECT_CHANGES_ARGUMENT_INVALID";
const ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED: &str = "ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED";
const ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT: &str = "ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT";
const ASTRO_DETECT_CHANGES_IDENTITY_MISMATCH: &str = "ASTRO_DETECT_CHANGES_IDENTITY_MISMATCH";
const ASTRO_DETECT_CHANGES_RESULT_BOUND_EXCEEDED: &str =
    "ASTRO_DETECT_CHANGES_RESULT_BOUND_EXCEEDED";

/// Runs the closed native CBM `detect_changes` v2 producer and layers
/// oracle-backed grounded risk onto its exact impacted constellation roster.
///
/// The augmentation is strictly additive: the complete CBM result is preserved
/// verbatim and a `grounded_risk` block is merged alongside it. For each impacted
/// symbol the oracle change→outcome corpus provides a probability-based risk when
/// grounded evidence exists. Malformed arguments, source envelopes, persisted
/// state, or augmentation output are coded hard refusals; the wrapper never
/// substitutes an ungrounded success for a failed measurement.
pub(crate) fn handle_detect_changes_grounded_risk(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    // Always run the real CBM tool first; grounded risk is layered on additively.
    let raw = runner.handle_tool_raw("detect_changes", args_json)?;

    let parsed = parse_detect_changes_result(&raw)?;

    // A valid CBM error result carries no symbols to ground: return it untouched.
    if parsed.is_error {
        return Ok(raw);
    }

    // Resolve the project so we can open its grounded-change vault.
    let args_value: Value = serde_json::from_str(args_json).map_err(|error| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_ARGUMENT_INVALID,
            "arguments_decode",
            format!("detect_changes arguments are not valid JSON: {error}"),
            "send one JSON object containing the exact project identity accepted by detect_changes",
        )
    })?;
    let args = args_value.as_object().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_ARGUMENT_INVALID,
            "arguments_shape",
            "detect_changes arguments are not a JSON object",
            "send one JSON object containing the exact project identity accepted by detect_changes",
        )
    })?;
    let project = status_project_from_args(args)?.ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_ARGUMENT_INVALID,
            "project_identity",
            "detect_changes arguments contain no nonempty project identity",
            "provide project, project_name, project_id, or projectName exactly as indexed",
        )
    })?;
    let contract = validate_detect_changes_contract(&parsed.inner)?;
    validate_detect_changes_request_echo(args, &contract)?;
    if contract.scope == "files" {
        return augment_detect_changes_result(
            parsed,
            json!({
                "grounded_risk": {
                    "schema": DETECT_CHANGES_RISK_SCHEMA,
                    "status": "not_applicable",
                    "reason": "scope_files",
                    "grounded_symbol_count": 0,
                    "symbol_count": 0,
                    "symbols": [],
                    "trust": "not_applicable",
                    "freshness": "fresh",
                    "provenance": [
                        "git:four-source-shell-free-canonical-roster",
                        format!(
                            "git:base_ref={} base_oid={} head_oid={} observation_passes=2",
                            contract.resolved_base_ref,
                            contract.resolved_base_oid,
                            contract.resolved_head_oid,
                        ),
                    ],
                }
            }),
            contract.result_max_bytes,
        );
    }
    if contract.changed_files.is_empty() {
        return augment_detect_changes_result(
            parsed,
            json!({
                "grounded_risk": {
                    "schema": DETECT_CHANGES_RISK_SCHEMA,
                    "status": "no_changes",
                    "grounded_symbol_count": 0,
                    "symbol_count": 0,
                    "symbols": [],
                    "trust": "not_applicable",
                    "freshness": "fresh",
                    "provenance": [
                        "git:four-source-shell-free-canonical-empty-roster",
                        format!(
                            "git:base_ref={} base_oid={} head_oid={} observation_passes=2",
                            contract.resolved_base_ref,
                            contract.resolved_base_oid,
                            contract.resolved_head_oid,
                        ),
                    ],
                }
            }),
            contract.result_max_bytes,
        );
    }
    let cache_dir = astrolabe_bridge::cbm_cache_dir().map_err(|error| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
            "cache_directory",
            format!("the CBM cache directory could not be resolved: {error}"),
            "repair the canonical CBM cache configuration and retry the unchanged request",
        )
    })?;
    let block = grounded_risk_block(&cache_dir, &project, &contract)?;
    augment_detect_changes_result(parsed, block, contract.result_max_bytes)
}

struct ParsedDetectChangesResult {
    envelope: Value,
    inner: Value,
    is_error: bool,
}

fn parse_detect_changes_result(raw: &str) -> Result<ParsedDetectChangesResult, DynError> {
    let envelope: Value = serde_json::from_str(raw).map_err(|error| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "envelope_decode",
            format!("detect_changes returned invalid JSON: {error}"),
            "repair the CBM detect_changes result envelope; malformed output is never treated as an empty impact roster",
        )
    })?;
    let object = envelope.as_object().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "envelope_shape",
            "detect_changes returned a non-object MCP envelope",
            "repair the CBM detect_changes result serializer and retry",
        )
    })?;
    let is_error = object
        .get("isError")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "is_error",
                "detect_changes result is missing the boolean isError field",
                "repair the CBM MCP envelope serializer and retry",
            )
        })?;
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "content_envelope",
                "detect_changes result must contain exactly one text content item",
                "repair the CBM MCP envelope serializer and retry",
            )
        })?;
    if content.get("type").and_then(Value::as_str) != Some("text") {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "content_type",
            "detect_changes result content item is not type=text",
            "repair the CBM MCP envelope serializer and retry",
        ));
    }
    let text = content.get("text").and_then(Value::as_str).ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "content_text",
            "detect_changes result text item has no string text field",
            "repair the CBM MCP envelope serializer and retry",
        )
    })?;
    if is_error {
        let structured = object
            .get("structuredContent")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "error_structured_content",
                    "detect_changes error result has no object-shaped structuredContent mirror",
                    "repair the native detect_changes error serializer; text-only refusals are not admissible",
                )
            })?;
        let parsed_text: Value = serde_json::from_str(text).map_err(|error| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "error_text_decode",
                format!("detect_changes error text is not valid JSON: {error}"),
                "repair the native detect_changes error serializer",
            )
        })?;
        if parsed_text != structured {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "error_response_mirror",
                "detect_changes error text and structuredContent mirrors differ",
                "repair the native error serializer; no representation is selected as a fallback",
            ));
        }
        validate_detect_changes_error_payload(&structured)?;
        return Ok(ParsedDetectChangesResult {
            envelope,
            inner: Value::Null,
            is_error,
        });
    }
    let structured = object
        .get("structuredContent")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "structured_content",
                "successful detect_changes result has no object-shaped structuredContent mirror",
                "repair the CBM result mirror; both success representations must be present and equal",
            )
        })?;
    let parsed_text: Value = serde_json::from_str(text).map_err(|error| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "content_text_decode",
            format!("detect_changes text payload is invalid JSON: {error}"),
            "repair the CBM detect_changes payload serializer and retry",
        )
    })?;
    if !parsed_text.is_object() || parsed_text != structured {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "response_mirror",
            "detect_changes text payload and structuredContent are not equal objects",
            "repair the CBM response mirror; no representation is selected as a fallback",
        ));
    }
    Ok(ParsedDetectChangesResult {
        envelope,
        inner: structured,
        is_error,
    })
}

fn augment_detect_changes_result(
    mut parsed: ParsedDetectChangesResult,
    additions: Value,
    result_max_bytes: usize,
) -> Result<String, DynError> {
    let additions = additions.as_object().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
            "augmentation_shape",
            "grounded-risk augmentation is not a JSON object",
            "repair the grounded-risk response builder and retry",
        )
    })?;
    let mut inner = parsed.inner;
    let inner_object = inner.as_object_mut().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
            "augmentation_target",
            "validated detect_changes inner payload stopped being an object",
            "preserve the raw result and repair the augmentation boundary",
        )
    })?;
    for key in additions.keys() {
        if inner_object.contains_key(key) {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
                "augmentation_collision",
                format!("detect_changes payload already contains augmentation key {key:?}"),
                "version the upstream/result contract explicitly; an existing field is never overwritten",
            ));
        }
    }
    merge_object(inner_object, additions);
    let serialized_inner = serde_json::to_string(&inner)?;
    let envelope = parsed.envelope.as_object_mut().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
            "augmentation_envelope",
            "validated detect_changes envelope stopped being an object",
            "preserve the raw result and repair the augmentation boundary",
        )
    })?;
    envelope.insert("structuredContent".to_string(), inner);
    let text = envelope
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(Value::as_object_mut)
        .and_then(|item| item.get_mut("text"))
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
                "augmentation_text",
                "validated detect_changes text mirror disappeared during augmentation",
                "preserve the raw result and repair the augmentation boundary",
            )
        })?;
    *text = Value::String(serialized_inner);
    let final_result = serde_json::to_string(&parsed.envelope)?;
    if final_result.len() > result_max_bytes {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_BOUND_EXCEEDED,
            "final_public_mcp_result_bytes",
            format!(
                "complete detect_changes result is {} UTF-8 bytes, above result_max_bytes={result_max_bytes}",
                final_result.len()
            ),
            "raise result_max_bytes only when the complete grounded result is intentionally admissible; no row is truncated",
        ));
    }
    Ok(final_result)
}

fn validate_detect_changes_error_payload(value: &Value) -> Result<(), DynError> {
    let object = value.as_object().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "error_payload_shape",
            "detect_changes error payload is not an object",
            "repair the native detect_changes error serializer",
        )
    })?;
    const FIELDS: [&str; 6] = [
        "schema",
        "status",
        "code",
        "stage",
        "message",
        "remediation",
    ];
    if object.len() != FIELDS.len()
        || object.keys().any(|field| !FIELDS.contains(&field.as_str()))
        || object.get("schema").and_then(Value::as_str) != Some("cbm.detect_changes.error.v1")
        || object.get("status").and_then(Value::as_str) != Some("error")
        || ["code", "stage", "message", "remediation"]
            .iter()
            .any(|field| {
                object
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            })
    {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "error_payload_contract",
            "detect_changes refusal differs from the exact coded error-v1 contract",
            "repair the native error schema/field roster before returning the refusal",
        ));
    }
    Ok(())
}

fn detect_changes_fault(
    code: &'static str,
    stage: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> DynError {
    Box::new(
        ToolFault::new(code, message, remediation)
            .with_detail("failed_stage", stage)
            .with_detail("tool", "detect_changes"),
    )
}

/// Builds the grounded-risk block from exact persisted identities. The CBM
/// result carries node id + stable atom id; one Graph point read must reproduce
/// that complete identity before its CxId is admitted. Oracle v5 rows are then
/// read only under those exact CxId prefixes. No name matching, corpus scan, or
/// provisional numeric substitution is part of this serving path.
///
/// # Cost contract (#1064)
///
/// With measured production `N=192,873`, `E=328,899`, `F` changed files, `M`
/// impacted symbols, `R_M` occurrence rows belonging to them, and caller-bound
/// final result bytes `B`,
/// identity/evidence work is
/// `O(M + R_M)` point/range reads. Kernel reach requires one `O(N+E)` bound CSR
/// decode and the current ordered-map reach index costs
/// `O(N log N + E log N)` construction / `O(N+E)` space. For each of the
/// caller-bounded `M` impacted symbols, traversal is bounded by the declared hop
/// policy and complete reachable roster; selecting the caller-bounded top `K`
/// display rows is `O(R log K)` / `O(K)` while full counts, masses, and digest
/// remain bound. Native Git capture, compact identity retention, and final
/// serialization are `O(B)` and refuse rather than truncate. The former
/// additional `O(N)` CBM snapshot and `O(Kv)` Oracle
/// scan are absent. The retained vault sequence, exact CBM node/atom roster,
/// subject set, complete-generation pointer, graph source binding, and explicit
/// `F/M/K/B` request bounds are invariant across the operation
/// (PC-02/03/07/16/35/38/40/41/43). The manual fixture is not production cost
/// evidence.
pub(crate) fn grounded_risk_block(
    cache_dir: &Path,
    project: &str,
    detect_changes: &ValidatedDetectChanges,
) -> Result<Value, DynError> {
    let config = PredictConfig {
        advertise_grounded: true,
        ..PredictConfig::default()
    };
    let scope_id = kernel_artifact_scope_id(project);
    let (vault_dir, vault_id, vault_salt) =
        shadow_vault_config_at(cache_dir, project).map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_vault_config",
                None,
                error.to_string(),
                None,
                "repair the shadow vault identity/config binding before requesting kernel-backed change reach",
            )
        })?;
    match vault_dir.try_exists() {
        Ok(true) => {}
        Ok(false) => {
            return Err(kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_vault_open",
                Some(astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE),
                format!(
                    "the mandatory shadow vault is absent at {}",
                    vault_dir.display()
                ),
                Some(
                    "publish one admitted complete shadow/kernel generation before requesting change reach",
                ),
                "publish one admitted complete shadow/kernel generation before requesting change reach",
            ));
        }
        Err(error) => {
            return Err(kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_vault_classification",
                Some(ASTRO_KERNEL_VAULT_STATE_UNREADABLE),
                format!(
                    "cannot classify mandatory shadow vault {}: {error}",
                    vault_dir.display()
                ),
                Some("repair the named vault path so its physical presence can be read exactly"),
                "repair the physical vault path and retry the unchanged change-reach request",
            ));
        }
    }

    // Production read path: exact impacted node ids become Graph point reads;
    // Oracle v5 occurrence keys become subject-prefix reads. The only
    // corpus-scale materialization retained here is the KernelGraph required to
    // compute blast-radius reach itself.
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Kv,
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Anchors,
            ColumnFamily::Compression,
            ColumnFamily::Slot(astrolabe_weave::search::SLOT_NAME_SEMANTIC),
            // Composite reach verification refuses SIM rows whose source
            // ledger attestation is unavailable on this handle.
            ColumnFamily::Ledger,
        ],
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "detect_changes_vault_open",
            None,
            error.to_string(),
            None,
            "repair the mandatory shadow vault/current generation before requesting kernel-backed change reach",
        )
    })?;
    let read_lease = vault.retain_latest_snapshot();
    let read_seq = read_lease.seq();
    let impacted = &detect_changes.impacted;
    let node_ids = impacted
        .iter()
        .map(|symbol| symbol.node_id)
        .collect::<BTreeSet<_>>();
    if node_ids.len() != impacted.len() {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "impacted_duplicate",
            "detect_changes returned duplicate impacted node ids",
            "canonicalize the native impacted roster by exact node id before serialization",
        ));
    }
    let node_ids = node_ids.into_iter().collect::<Vec<_>>();
    let identities = astrolabe_ingest::read_node_map_identities_at(
        &vault, read_seq, project, &node_ids,
    )
    .map_err(|error| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_IDENTITY_MISMATCH,
            "node_map_batch_read",
            format!("impacted node-map batch could not be read exactly: {error}"),
            "repair or reindex the CBM/Graph node identities and retry the unchanged request",
        )
    })?;
    let identities = node_ids
        .into_iter()
        .zip(identities)
        .collect::<BTreeMap<_, _>>();
    let mut resolved = Vec::with_capacity(impacted.len());
    let mut subjects = BTreeSet::new();
    for symbol in impacted {
        let identity = identities
            .get(&symbol.node_id)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_IDENTITY_MISMATCH,
                    "node_map_point_read",
                    format!(
                        "impacted node {} ({:?}) has no exact persisted node-map row",
                        symbol.node_id, symbol.atom_id
                    ),
                    "reindex the project so every CBM node has one exact Graph node-map row",
                )
            })?;
        if identity.atom_id != symbol.atom_id
            || identity.qualified_name != symbol.qualified_name
            || identity.label != symbol.label
            || identity.name != symbol.name
            || identity.file_path != symbol.file
        {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_IDENTITY_MISMATCH,
                "node_map_identity_readback",
                format!(
                    "impacted node {} identity differs from persisted Graph state: cbm_atom={:?} graph_atom={:?} cbm_qn={:?} graph_qn={:?} cbm_label={:?} graph_label={:?} cbm_name={:?} graph_name={:?} cbm_file={:?} graph_file={:?}",
                    symbol.node_id,
                    symbol.atom_id,
                    identity.atom_id,
                    symbol.qualified_name,
                    identity.qualified_name,
                    symbol.label,
                    identity.label,
                    symbol.name,
                    identity.name,
                    symbol.file,
                    identity.file_path,
                ),
                "reindex the project from the authoritative SQLite state; no name-based guess is used",
            ));
        }
        subjects.insert(identity.cx_id);
        resolved.push((symbol, identity.cx_id));
    }
    // #366: the answer-path blast-radius reach term resolves one mandatory
    // complete generation through its pointer. Missing/corrupt generation state
    // is a hard refusal; it is never hidden behind the legacy risk-only result.
    let reach_state =
        ChangeReachState::from_vault_at(&vault, read_seq, project, detect_changes.depth)?;
    let oracle_gate = require_current_oracle_gate_at(
        &vault,
        read_seq,
        project,
        reach_state.kernel_manifest(),
        reach_state.kernel_pointer(),
    )
    .map_err(|error| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT,
            "oracle_gate_attestation",
            format!(
                "project {project:?} has no exact passing Oracle gate attestation for the retained corpus/graph/kernel generation: {error}"
            ),
            "publish one new generation from real Git archaeology and source-backed CI outcome anchors; no stale or manual gate is admitted",
        )
    })?;
    let oracle_gate = oracle_gate_summary(&oracle_gate);
    let evidence = OracleEvidence::from_vault_subjects_at(&vault, read_seq, &subjects)?;
    if vault.latest_seq() != read_seq {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT,
            "oracle_generation_stability",
            format!(
                "vault advanced from retained sequence {read_seq} to {} while reading exact Oracle evidence",
                vault.latest_seq()
            ),
            "retry the unchanged request against one stable retained generation",
        ));
    }
    read_lease.record_progress();
    drop(read_lease);
    drop(vault);

    let mut symbols = Vec::new();
    let mut grounded_count = 0usize;
    let mut reach_symbol_count = 0usize;
    let mut all_trusted = true;
    for (symbol, cx) in resolved {
        let mut entry = json!({
            "symbol": symbol.name,
            "file": symbol.file,
        });
        let obj = entry.as_object_mut().ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_AUGMENTATION_FAILED,
                "symbol_result_shape",
                "the in-memory grounded symbol result is not an object",
                "repair the grounded-risk result builder; no partial symbol result is returned",
            )
        })?;
        let risk = grounded_risk_required(&evidence, cx, &config).map_err(|error| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT,
                "oracle_evidence_readback",
                format!(
                    "impacted symbol {:?} ({cx}) has no admissible persisted change-to-outcome measurement: {error}",
                    symbol.name
                ),
                "ingest real outcome evidence for the exact impacted constellation, then retry; no heuristic risk is served",
            )
        })?;
        grounded_count += 1;
        let trust = risk.trust.as_str();
        if trust != "trusted" {
            all_trusted = false;
        }
        obj.insert(
            "resolution".to_string(),
            json!("cbm_node_id_atom_id_point_read"),
        );
        obj.insert("node_id".to_string(), json!(symbol.node_id));
        obj.insert("atom_id".to_string(), json!(symbol.atom_id));
        obj.insert("cx".to_string(), json!(hex_lower(cx.as_bytes())));
        obj.insert("risk".to_string(), json!(risk.risk));
        obj.insert("ceiling".to_string(), json!(risk.ceiling));
        obj.insert("trust".to_string(), json!(trust));
        obj.insert("grounded".to_string(), json!(risk.grounded));
        obj.insert("evidence_occurrences".to_string(), json!(risk.evidence_n));
        let reach_block = reach_state
            .reach_for(
                cx,
                risk.risk,
                detect_changes.reach_max_nodes_per_symbol,
            )
            .map_err(|error| {
            kernel_generation_fault(
                project,
                &kernel_artifact_scope_id(project),
                "detect_changes_reach",
                None,
                error.to_string(),
                None,
                "repair the complete graph/generation identity or the named reach input; no risk-only fallback is served",
            )
            })?;
        reach_symbol_count += 1;
        obj.insert("reach".to_string(), reach_block);
        symbols.push(entry);
    }

    let status = if grounded_count > 0 {
        "grounded"
    } else {
        "empty"
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
            // #366: generation-bound reach component. A shadow project without
            // one readable complete generation has already refused above.
            "reach_component": reach_state.summary(
                reach_symbol_count,
                detect_changes.changed_file_max,
                detect_changes.impact_max_symbols,
                detect_changes.reach_max_nodes_per_symbol,
            ),
            "oracle_gate": oracle_gate,
            "trust": block_trust,
            "freshness": "fresh",
            "provenance": [
                format!("oracle-corpus:project={project}"),
                "vault:ColumnFamily::Kv+Graph+Kernel+Anchors+Compression+Ledger+S20"
                    .to_string(),
                "resolver:cbm-node-id+atom-id-vs-Graph-point-row".to_string(),
                "kernel:answer-path-reach(#366)".to_string(),
                format!(
                    "git:base_ref={} base_oid={} head_oid={} observation_passes=2",
                    detect_changes.resolved_base_ref,
                    detect_changes.resolved_base_oid,
                    detect_changes.resolved_head_oid,
                ),
            ],
        }
    }))
}

/// The current complete kernel generation used to measure each changed symbol's
/// blast-radius reach (#366). It is mandatory for a shadow-indexed project.
struct ChangeReachState {
    inner: ChangeReachInner,
    generation_id: String,
    kernel_manifest: astrolabe_weave::KernelGenerationManifest,
    kernel_pointer: astrolabe_weave::KernelGenerationPointer,
}

struct ChangeReachInner {
    graph: PreparedChangeReachGraph,
    kernel_members: BTreeSet<CxId>,
    gap_members: BTreeSet<CxId>,
    config: ReachConfig,
}

impl ChangeReachState {
    /// Resolves the current complete kernel generation and its graph through one
    /// read-only vault snapshot. Any missing, corrupt, or stale source is a typed
    /// hard refusal; reach never falls back to an unbound legacy artifact alias.
    fn from_vault_at<C>(
        vault: &AsterVault<C>,
        read_seq: Seq,
        project: &str,
        max_hops: u64,
    ) -> Result<Self, DynError>
    where
        C: Clock,
    {
        let scope_id = kernel_artifact_scope_id(project);
        let generation = astrolabe_weave::read_current_kernel_generation_artifact_at(
            vault, read_seq, project, &scope_id,
        )
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_generation_read",
                Some(error.code()),
                error.message().to_string(),
                Some(error.remediation()),
                "repair and republish the current complete kernel generation before requesting kernel-backed change reach",
            )
        })?
        .ok_or_else(|| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_generation_read",
                Some(astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE),
                "no current complete kernel generation exists for this shadow-indexed project",
                Some("publish an admitted complete kernel generation before requesting kernel-backed change reach"),
                "publish an admitted complete kernel generation before requesting kernel-backed change reach",
            )
        })?;
        let csr = astrolabe_ingest::read_graph_projection_csr_bound_at(
            vault,
            astrolabe_ingest::GraphProjectionKind::KernelGraph,
            read_seq,
            &astrolabe_ingest::GraphProjectionReadBinding {
                graph_content_generation: generation
                    .manifest
                    .generation_source_binding
                    .graph_content_generation,
                manifest: generation
                    .manifest
                    .generation_source_binding
                    .projection_manifest
                    .clone(),
            },
        )
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_projection_read",
                error.code(),
                error.message(),
                error.remediation(),
                "repair the composite graph projection and republish the complete kernel generation",
            )
        })?;
        bounded_kernel_source_evidence(
            &csr,
            &generation.artifact,
            &generation.manifest,
            read_seq,
        )
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_source_verify",
                None,
                error.to_string(),
                None,
                "rebuild the complete generation from the current graph, anchor roster, and kernel configuration",
            )
        })?;
        let graph = PreparedChangeReachGraph::from_rosters(
            csr.nodes.iter().map(|node| node.id),
            csr.nodes.iter().enumerate().flat_map(|(index, node)| {
                csr.edges[csr.offsets[index]..csr.offsets[index + 1]]
                    .iter()
                    .map(move |edge| (node.id, edge.dst, edge.weight))
            }),
        )
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_reach_index",
                error.code(),
                error.message(),
                error.remediation(),
                "repair the retained composite projection before computing change reach",
            )
        })?;
        let kernel_members: BTreeSet<CxId> =
            generation.artifact.members.iter().map(|m| m.id).collect();
        let gap_members: BTreeSet<CxId> = generation
            .artifact
            .members
            .iter()
            .filter(|m| !m.grounded)
            .map(|m| m.id)
            .collect();
        if vault.latest_seq() != read_seq {
            return Err(kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_generation_stability",
                None,
                format!(
                    "vault moved from retained sequence {read_seq} to {} while resolving change reach",
                    vault.latest_seq()
                ),
                None,
                "retry against one stable current complete generation",
            ));
        }
        let config = ReachConfig {
            max_hops,
            ..ReachConfig::with_registry_defaults()
        };
        config.validate().map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "detect_changes_reach_config",
                error.code(),
                error.message(),
                error.remediation(),
                "set detect_changes depth within the declared reach-knob bounds",
            )
        })?;
        let generation_id = generation.manifest.generation_id.clone();
        Ok(Self {
            inner: ChangeReachInner {
                graph,
                kernel_members,
                gap_members,
                config,
            },
            generation_id,
            kernel_manifest: generation.manifest,
            kernel_pointer: generation.pointer,
        })
    }

    fn kernel_manifest(&self) -> &astrolabe_weave::KernelGenerationManifest {
        &self.kernel_manifest
    }

    fn kernel_pointer(&self) -> &astrolabe_weave::KernelGenerationPointer {
        &self.kernel_pointer
    }

    /// The measured reach block for one changed symbol. `base_risk` is
    /// the oracle's grounded consequence probability (`[0, 1]`), elevated by the
    /// blast radius into a composed `blast_risk_permille` (never below the oracle
    /// base, never above `1000`).
    fn reach_for(
        &self,
        cx: CxId,
        base_risk: f64,
        max_returned_nodes: usize,
    ) -> Result<Value, DynError> {
        let inner = &self.inner;
        let reach =
            inner
                .graph
                .measure(cx, &inner.kernel_members, &inner.gap_members, &inner.config)?;
        if !base_risk.is_finite() || !(0.0..=1.0).contains(&base_risk) {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT,
                "oracle_risk_range",
                format!("Oracle returned an invalid grounded risk {base_risk}"),
                "repair and rederive the persisted Oracle evidence; risk is never clamped into range",
            ));
        }
        let base_permille = (base_risk * 1000.0).round() as u64;
        let composed = reach_risk_permille(base_permille, &reach, &inner.config)?;
        let full_inventory_blake3 = hex_lower(&change_reach_artifact_blake3(&reach));
        // Keep only the caller-bounded display roster while binding the complete
        // measured reach above. The ordered set retains the best K rows by
        // (reach descending, hop ascending, CxId ascending) in O(R log K) time
        // and O(K) additional memory; it never changes full counts or masses.
        let mut returned = BTreeSet::new();
        for node in &reach.reached {
            returned.insert((
                Reverse(node.reach_permille),
                node.hop,
                node.id,
                node.kernel_member,
                node.gap,
            ));
            if returned.len() > max_returned_nodes {
                returned.pop_last();
            }
        }
        let returned_count = returned.len();
        let omitted_count = reach.reached.len() - returned_count;
        Ok(json!({
            "schema": astrolabe_kernel::CHANGE_REACH_SCHEMA,
            "from_is_kernel_member": reach.from_is_kernel_member,
            "from_is_gap": reach.from_is_gap,
            "reached_count": reach.reached_count,
            "reach_mass_permille": reach.reach_mass_permille,
            "kernel_member_reach_permille": reach.kernel_member_reach_permille,
            "gap_reach_permille": reach.gap_reach_permille,
            "base_risk_permille": composed.grounded_consequence_permille,
            "gap_exposure_permille": composed.gap_exposure_permille,
            "elevation_permille": composed.elevation_permille,
            "blast_risk_permille": composed.risk_permille,
            "returned_count": returned_count,
            "omitted_count": omitted_count,
            "reach_max_nodes_per_symbol": max_returned_nodes,
            "full_inventory_blake3": full_inventory_blake3,
            "reached": returned.into_iter().map(|(Reverse(reach_permille), hop, id, kernel_member, gap)| json!({
                "symbol_id": hex_lower(id.as_bytes()),
                "hop": hop,
                "reach_permille": reach_permille,
                "kernel_member": kernel_member,
                "gap": gap,
            })).collect::<Vec<_>>(),
        }))
    }

    /// A labeled summary of the reach component for the top-level block.
    fn summary(
        &self,
        applied_count: usize,
        changed_file_max: usize,
        impact_max_symbols: usize,
        reach_max_nodes_per_symbol: usize,
    ) -> Value {
        json!({
            "status": "applied",
            "generation_id": self.generation_id,
            "reach_symbol_count": applied_count,
            "changed_file_max": changed_file_max,
            "impact_max_symbols": impact_max_symbols,
            "reach_max_nodes_per_symbol": reach_max_nodes_per_symbol,
            "knob_registry_version": astrolabe_kernel::CHANGE_REACH_KNOB_REGISTRY_VERSION,
            "trust": "provisional",
        })
    }
}

/// One exact impacted node identity extracted from a CBM `detect_changes`
/// result. `node_id` is the point-read key and `atom_id` plus the descriptive
/// fields are independent equality witnesses against the persisted Graph row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ImpactedSymbol {
    node_id: i64,
    atom_id: String,
    name: String,
    qualified_name: String,
    label: String,
    file: String,
}

struct ValidatedDetectChanges {
    project: String,
    resolved_base_ref: String,
    resolved_base_oid: String,
    resolved_head_oid: String,
    scope: String,
    depth: u64,
    changed_file_max: usize,
    impact_max_symbols: usize,
    reach_max_nodes_per_symbol: usize,
    result_max_bytes: usize,
    changed_files: Vec<String>,
    impacted: Vec<ImpactedSymbol>,
}

fn validate_detect_changes_contract(inner: &Value) -> Result<ValidatedDetectChanges, DynError> {
    let object = inner.as_object().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "payload_shape",
            "successful detect_changes payload is not an object",
            "repair the native detect_changes serializer",
        )
    })?;
    const DETECT_RESULT_FIELDS: [&str; 16] = [
        "schema",
        "project",
        "resolved_base_ref",
        "resolved_base_oid",
        "resolved_head_oid",
        "git_observation_passes",
        "changed_file_max",
        "changed_files",
        "changed_count",
        "impacted_symbols",
        "changed_file_mappings",
        "depth",
        "impact_max_symbols",
        "reach_max_nodes_per_symbol",
        "result_max_bytes",
        "scope",
    ];
    if object.len() != DETECT_RESULT_FIELDS.len()
        || object
            .keys()
            .any(|field| !DETECT_RESULT_FIELDS.contains(&field.as_str()))
    {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "payload_fields",
            "detect_changes payload differs from the exact closed v2 result field roster",
            "repair the native v2 serializer before serving grounded reach",
        ));
    }
    if object.get("schema").and_then(Value::as_str) != Some("cbm.detect_changes.v2") {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "schema",
            "detect_changes payload does not carry cbm.detect_changes.v2",
            "rebuild the native worker and retry against the exact v2 result contract",
        ));
    }
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .filter(|project| !project.is_empty())
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "project",
                "detect_changes payload has no nonempty project identity",
                "repair the native project/result binding",
            )
        })?
        .to_string();
    let resolved_base_ref = object
        .get("resolved_base_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "resolved_base_ref",
                "detect_changes payload has no resolved Git base ref",
                "repair the native Git observation receipt",
            )
        })?
        .to_string();
    let resolved_base_oid = canonical_git_oid(object, "resolved_base_oid")?;
    let resolved_head_oid = canonical_git_oid(object, "resolved_head_oid")?;
    if object.get("git_observation_passes").and_then(Value::as_u64) != Some(2) {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "git_observation_passes",
            "detect_changes payload does not prove two equal Git observations",
            "repair the native double-observation Git boundary before serving impact",
        ));
    }
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .filter(|scope| matches!(*scope, "files" | "symbols"))
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "scope",
                "detect_changes payload has no canonical files/symbols scope",
                "repair the native scope admission/echo contract",
            )
        })?
        .to_string();
    let depth = object
        .get("depth")
        .and_then(Value::as_u64)
        .filter(|depth| *depth > 0)
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "depth",
                "detect_changes payload has no positive integer depth",
                "repair the native depth admission/echo contract",
            )
        })?;
    let changed_file_max = positive_detect_bound(object, "changed_file_max")?;
    let impact_max_symbols = positive_detect_bound(object, "impact_max_symbols")?;
    let reach_max_nodes_per_symbol = positive_detect_bound(object, "reach_max_nodes_per_symbol")?;
    let result_max_bytes = positive_detect_result_byte_bound(object, "result_max_bytes")?;
    let changed_values = object
        .get("changed_files")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "changed_files",
                "detect_changes payload has no changed_files array",
                "repair the native canonical changed-file serializer",
            )
        })?;
    let mut changed_files = Vec::with_capacity(changed_values.len());
    for value in changed_values {
        let path = value
            .as_str()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "changed_file_item",
                    "detect_changes changed_files contains a non-string or empty path",
                    "repair the native NUL-delimited Git path decoder",
                )
            })?;
        if changed_files
            .last()
            .is_some_and(|previous: &String| previous.as_str() >= path)
        {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "changed_file_order",
                "detect_changes changed_files is not strictly byte-sorted and unique",
                "canonicalize the merged Git roster before serialization",
            ));
        }
        changed_files.push(path.to_string());
    }
    let changed_count = object
        .get("changed_count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "changed_count",
                "detect_changes changed_count is not a representable nonnegative integer",
                "repair the native changed-file accounting",
            )
        })?;
    if changed_count != changed_files.len() {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "changed_count",
            format!(
                "detect_changes changed_count {changed_count} differs from roster length {}",
                changed_files.len()
            ),
            "repair the native changed-file accounting",
        ));
    }
    if changed_files.len() > changed_file_max {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "changed_file_max",
            format!(
                "detect_changes returned {} changed files above its echoed caller bound {changed_file_max}",
                changed_files.len()
            ),
            "repair native admission so the complete changed-file roster never exceeds the exact caller bound",
        ));
    }
    let impacted = impacted_symbols(inner)?;
    if impacted.len() > impact_max_symbols {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "impact_max_symbols",
            format!(
                "detect_changes returned {} impacted symbols above its echoed caller bound {impact_max_symbols}",
                impacted.len()
            ),
            "repair native admission so the complete impacted roster never exceeds the exact caller bound",
        ));
    }
    let mappings = object
        .get("changed_file_mappings")
        .and_then(Value::as_array)
        .filter(|mappings| mappings.len() == changed_files.len())
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "changed_file_mappings",
                "detect_changes mapping roster is absent or differs in length from changed_files",
                "emit exactly one mapping receipt per canonical changed file",
            )
        })?;
    let mut expected_by_file = BTreeMap::new();
    let symbols_requested = scope == "symbols";
    for (expected_file, mapping) in changed_files.iter().zip(mappings) {
        let mapping = mapping.as_object().ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "changed_file_mapping_item",
                "detect_changes mapping item is not an object",
                "repair the native per-file mapping serializer",
            )
        })?;
        if mapping.len() != 3
            || mapping.get("file").and_then(Value::as_str) != Some(expected_file.as_str())
            || mapping.get("symbols_requested").and_then(Value::as_bool) != Some(symbols_requested)
        {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "changed_file_mapping_identity",
                format!("mapping receipt does not match changed file {expected_file:?}"),
                "emit the exact closed file/node_count/symbols_requested mapping receipt",
            ));
        }
        let node_count = mapping
            .get("node_count")
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "changed_file_mapping_count",
                    format!("mapping receipt for {expected_file:?} has invalid node_count"),
                    "repair the native per-file node accounting",
                )
            })?;
        if symbols_requested && node_count == 0 {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT,
                "unmapped_changed_file",
                format!(
                    "changed file {expected_file:?} maps to zero indexed constellations; zero impact is not established"
                ),
                "reindex the changed file or request scope=files; no numeric impact is served for an unmapped change",
            ));
        }
        expected_by_file.insert(expected_file.clone(), node_count);
    }
    let mut observed_by_file: BTreeMap<String, usize> = BTreeMap::new();
    for symbol in &impacted {
        if !expected_by_file.contains_key(&symbol.file) {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_file_membership",
                format!(
                    "impacted node {} references file {:?} outside changed_files",
                    symbol.node_id, symbol.file
                ),
                "repair the native file-to-node query and exact membership accounting",
            ));
        }
        *observed_by_file.entry(symbol.file.clone()).or_default() += 1;
    }
    for (file, expected) in expected_by_file {
        let observed = observed_by_file.get(&file).copied().unwrap_or(0);
        if observed != expected {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_file_count",
                format!(
                    "changed file {file:?} declares {expected} mapped nodes but impacted roster contains {observed}"
                ),
                "repair the native per-file mapping/impacted roster atomic serializer",
            ));
        }
    }
    Ok(ValidatedDetectChanges {
        project,
        resolved_base_ref,
        resolved_base_oid,
        resolved_head_oid,
        scope,
        depth,
        changed_file_max,
        impact_max_symbols,
        reach_max_nodes_per_symbol,
        result_max_bytes,
        changed_files,
        impacted,
    })
}

fn canonical_git_oid(
    object: &serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<String, DynError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| {
            matches!(value.len(), 40 | 64)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(str::to_string)
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                name,
                format!("detect_changes payload has no canonical Git object id in {name}"),
                "repair the native resolved Git object observation",
            )
        })
}

fn positive_detect_bound(
    object: &serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<usize, DynError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= i32::MAX as u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                name,
                format!("detect_changes payload has no positive INT_MAX-bounded {name}"),
                "repair native caller-bound admission and exact result echo",
            )
        })
}

fn positive_detect_result_byte_bound(
    object: &serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<usize, DynError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                name,
                format!("detect_changes payload has no positive SIZE_MAX-bounded {name} integer"),
                "repair native caller-bound admission and exact result echo",
            )
        })
}

fn validate_detect_changes_request_echo(
    args: &serde_json::Map<String, Value>,
    observed: &ValidatedDetectChanges,
) -> Result<(), DynError> {
    let requested_scope = args
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("symbols");
    let requested_depth = args.get("depth").and_then(Value::as_u64).unwrap_or(2);
    let requested_project = args.get("project").and_then(Value::as_str).ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_ARGUMENT_INVALID,
            "project_identity",
            "detect_changes request has no exact project string",
            "send the required project field exactly as indexed",
        )
    })?;
    let requested_base_ref = args
        .get("since")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| args.get("base_branch").and_then(Value::as_str))
        .unwrap_or("main");
    let requested_impact = positive_detect_bound(args, "impact_max_symbols")?;
    let requested_reach = positive_detect_bound(args, "reach_max_nodes_per_symbol")?;
    let requested_files = positive_detect_bound(args, "changed_file_max")?;
    let requested_result_bytes = positive_detect_result_byte_bound(args, "result_max_bytes")?;
    if observed.project != requested_project
        || observed.resolved_base_ref != requested_base_ref
        || observed.scope != requested_scope
        || observed.depth != requested_depth
        || observed.changed_file_max != requested_files
        || observed.impact_max_symbols != requested_impact
        || observed.reach_max_nodes_per_symbol != requested_reach
        || observed.result_max_bytes != requested_result_bytes
    {
        return Err(detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "request_echo",
            format!(
                "detect_changes result controls differ from admitted arguments: requested project={requested_project:?} base_ref={requested_base_ref:?} scope={requested_scope:?} depth={requested_depth} changed_file_max={requested_files} impact_max_symbols={requested_impact} reach_max_nodes_per_symbol={requested_reach} result_max_bytes={requested_result_bytes}; observed project={:?} base_ref={:?} scope={:?} depth={} changed_file_max={} impact_max_symbols={} reach_max_nodes_per_symbol={} result_max_bytes={}",
                observed.project,
                observed.resolved_base_ref,
                observed.scope,
                observed.depth,
                observed.changed_file_max,
                observed.impact_max_symbols,
                observed.reach_max_nodes_per_symbol,
                observed.result_max_bytes,
            ),
            "repair the native argument/result control binding before serving grounded reach",
        ));
    }
    Ok(())
}

/// Extracts the impacted symbols from a CBM `detect_changes` result.
///
/// The caller already proved the MCP text and structured mirrors are equal.
/// Only an explicitly present valid empty array means there are no impacted
/// symbols; malformed rows are never converted to that state.
fn impacted_symbols(inner: &Value) -> Result<Vec<ImpactedSymbol>, DynError> {
    let object = inner.as_object().ok_or_else(|| {
        detect_changes_fault(
            ASTRO_DETECT_CHANGES_RESULT_INVALID,
            "impacted_symbols_parent",
            "detect_changes inner payload is not an object",
            "repair the CBM detect_changes payload serializer and retry",
        )
    })?;
    let array = object
        .get("impacted_symbols")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_symbols",
                "detect_changes inner payload has no impacted_symbols array",
                "repair the CBM detect_changes payload serializer; only an explicit empty array proves no impacted symbols",
            )
        })?;
    let mut symbols = Vec::new();
    for (index, item) in array.iter().enumerate() {
        let item = item.as_object().ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_symbol_item",
                format!("impacted_symbols[{index}] is not an object"),
                "repair the CBM detect_changes payload serializer and retry",
            )
        })?;
        if item.len() != 6 {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_symbol_fields",
                format!(
                    "impacted_symbols[{index}] does not carry the exact six-field identity contract"
                ),
                "repair the native closed node identity serializer and retry",
            ));
        }
        let node_id = item.get("node_id").and_then(Value::as_i64).ok_or_else(|| {
            detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_symbol_node_id",
                format!("impacted_symbols[{index}].node_id is missing or is not an i64"),
                "repair the CBM detect_changes identity serializer and retry",
            )
        })?;
        if node_id <= 0 {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_symbol_node_id",
                format!("impacted_symbols[{index}].node_id is not positive: {node_id}"),
                "repair the CBM detect_changes identity serializer and retry",
            ));
        }
        let atom_id = item
            .get("atom_id")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "impacted_symbol_atom_id",
                    format!("impacted_symbols[{index}].atom_id is not canonical lowercase SHA-256"),
                    "repair the CBM detect_changes identity serializer and retry",
                )
            })?;
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "impacted_symbol_name",
                    format!("impacted_symbols[{index}].name is missing or empty"),
                    "repair the CBM detect_changes payload serializer and retry",
                )
            })?;
        let qualified_name = item
            .get("qualified_name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "impacted_symbol_qualified_name",
                    format!("impacted_symbols[{index}].qualified_name is missing or empty"),
                    "repair the CBM detect_changes identity serializer and retry",
                )
            })?;
        let label = item
            .get("label")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "impacted_symbol_label",
                    format!("impacted_symbols[{index}].label is missing or empty"),
                    "repair the CBM detect_changes identity serializer and retry",
                )
            })?;
        let file = item
            .get("file")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                detect_changes_fault(
                    ASTRO_DETECT_CHANGES_RESULT_INVALID,
                    "impacted_symbol_file",
                    format!("impacted_symbols[{index}].file is missing or empty"),
                    "repair the CBM detect_changes payload serializer and retry",
                )
            })?;
        let symbol = ImpactedSymbol {
            node_id,
            atom_id: atom_id.to_string(),
            name: name.to_string(),
            qualified_name: qualified_name.to_string(),
            label: label.to_string(),
            file: file.to_string(),
        };
        if symbols.last().is_some_and(|previous: &ImpactedSymbol| {
            previous.file.as_str() > symbol.file.as_str()
                || (previous.file == symbol.file && previous.node_id >= symbol.node_id)
        }) {
            return Err(detect_changes_fault(
                ASTRO_DETECT_CHANGES_RESULT_INVALID,
                "impacted_symbol_order",
                format!("impacted_symbols[{index}] is not in strict (changed-file,node-id) order"),
                "repair the native ordered identity query; host validation never sorts away drift",
            ));
        }
        symbols.push(symbol);
    }
    Ok(symbols)
}
