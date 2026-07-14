//! Server wiring for the per-repo lens capability gate (P5.5, #35 server residue).
//!
//! The assay crate (`astrolabe_assay::gate`) owns the *decision* core — capability
//! cards, the Admit/Park/Retire branches with the stratified override, and the
//! serving-admission fold. This module owns the *persistence + surfacing*: instead
//! of the crate's filesystem-backed `GateJournal`, every gate decision and every
//! reversal is appended to the project's **real Ledger column family**
//! (`EntryKind::Assay`, hash-chained, durable), and the serving state (Admit/Park/
//! Retire buckets + the `serving_view` mask) is folded from those CF rows and
//! surfaced through the `assay_gate` MCP tool.
//!
//! # Persistence model (real CF, not a filesystem journal)
//!
//! * Each decision/reversal is one Ledger CF row (`EntryKind::Assay`, subject
//!   `SubjectId::Guard(b"assay-gate:<project>")`), carrying a canonical JSON
//!   payload. This is the per-repo gate journal, living in a real CF.
//! * The config store holds only a per-project **seq index** (the ascending list
//!   of Ledger seqs that belong to this repo's gate journal) plus a mirror of the
//!   current folded serving state. The decision *bytes* live in the CF; the index
//!   is a pointer set so the fold is tractable without a full-ledger scan.
//! * **CF-level as_of readback**: any journal entry is read back by its Ledger seq
//!   via [`calyx_aster::ledger_view::read_ledger_seq`] — the persisted CF bytes,
//!   not the caller's echo, are what a reader compares against.
//! * **Reversibility**: a `revert` appends a neutralizing CF row naming the target
//!   Ledger seq; re-folding restores the prior serving state byte-for-byte
//!   (proven against [`astrolabe_assay::ServingAdmission::to_bytes`]).
//!
//! Every mutation is FSV-checked: the appended Ledger row is read back and its
//! payload compared, and the mirrored serving state is read back and compared to
//! the freshly-folded bytes before the call returns.

use super::*;

use astrolabe_assay::{
    GateConfig, GateDecision, GateEvaluation, GateVerdict, LensCapabilityCard, ServingAdmission,
    gate_lens,
};

/// Actor recorded on every assay-gate Ledger entry.
pub(crate) const ASSAY_GATE_ACTOR: &str = "astrolabe-server-assay-gate";
/// Schema tag on the surfaced gate-state envelope.
pub(crate) const ASSAY_GATE_SURFACE_SCHEMA: &str = "astro.assay.gate_surface.v1";
/// Config-store key (per project) holding the ascending Ledger-seq index.
const ASSAY_GATE_INDEX_KEY: &str = "assay_gate_index_json";
/// Config-store key (per project) holding the mirrored folded serving state.
const ASSAY_GATE_SERVING_KEY: &str = "assay_gate_serving_json";

/// Ledger subject bytes for a project's gate journal (`SubjectId::Guard`).
fn assay_gate_subject(project: &str) -> Vec<u8> {
    format!("assay-gate:{project}").into_bytes()
}

/// One folded/decoded gate journal action (mirrors `astrolabe_assay::GateAction`
/// but keyed by the persisted Ledger seq rather than a filesystem line number).
#[derive(Debug, Clone)]
enum GateJournalAction {
    Decide { lens: String, verdict: GateVerdict },
    Revert { reverts_seq: u64 },
}

/// A decoded gate journal entry: its Ledger seq plus the action it recorded.
#[derive(Debug, Clone)]
struct GateJournalRow {
    ledger_seq: u64,
    action: GateJournalAction,
}

/// MCP entry point: `assay_gate` with modes `decide`, `revert`, `status`.
pub(crate) fn handle_assay_gate(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result(
            "ASTRO_ASSAY_GATE_INVALID: assay_gate arguments must be a JSON object; remediation: pass a JSON object with project and mode",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    assay_gate_at(&cache_dir, args_obj)
}

/// Cache-dir-explicit entry point for `assay_gate` (shared by the MCP handler and
/// in-process FSV tests, avoiding the process-global cbm cache dir).
pub(crate) fn assay_gate_at(
    cache_dir: &Path,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result(
            "ASTRO_ASSAY_GATE_INVALID: assay_gate requires project; remediation: pass the shadow-indexed project whose lens gate is consulted",
        );
    };
    if read_dial_at(cache_dir, &project)? != MigrationDial::Shadow {
        return tool_error_result(
            "ASTRO_ASSAY_GATE_NOT_SHADOW: assay_gate requires calyx shadow indexing; remediation: run index_repository with calyx=\"shadow\" before gating lenses",
        );
    }
    let mode = string_arg(args_obj, "mode").unwrap_or("status");
    match mode {
        "decide" => assay_gate_decide_at(cache_dir, &project, args_obj),
        "revert" => assay_gate_revert_at(cache_dir, &project, args_obj),
        "status" => assay_gate_status_at(cache_dir, &project, args_obj),
        other => tool_error_result(format!(
            "ASTRO_ASSAY_GATE_MODE_UNSUPPORTED: assay_gate mode {other:?} is not available; remediation: use mode=\"decide\", mode=\"revert\", or mode=\"status\""
        )),
    }
}

/// Gate one candidate lens and persist the verdict to the Ledger CF.
fn assay_gate_decide_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let Some(card_value) = args_obj.get("card") else {
        return tool_error_result(
            "ASTRO_ASSAY_GATE_INVALID: assay_gate mode=\"decide\" requires a card object; remediation: pass card as a measured LensCapabilityCard (lens, axis_bits, signal_bits, coverage, spread, separation, cost_units, n)",
        );
    };
    let card: LensCapabilityCard = match serde_json::from_value(card_value.clone()) {
        Ok(card) => card,
        Err(error) => {
            return tool_error_result(format!(
                "ASTRO_ASSAY_GATE_CARD_INVALID: assay_gate card did not parse as a capability card: {error}; remediation: pass every measured card field (lens, axis_bits, signal_bits, coverage, spread, separation, cost_units, n)"
            ));
        }
    };
    let Some(max_admitted_correlation) = args_obj
        .get("max_admitted_correlation")
        .and_then(Value::as_f64)
    else {
        return tool_error_result(
            "ASTRO_ASSAY_GATE_INVALID: assay_gate mode=\"decide\" requires max_admitted_correlation; remediation: pass the measured max absolute correlation of the candidate with any admitted lens (0.0..=1.0)",
        );
    };
    let sole_critical_carrier = args_obj
        .get("sole_critical_carrier")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let cfg = GateConfig::from_defaults().map_err(assay_error_to_dyn)?;
    let evaluation = GateEvaluation {
        card: &card,
        max_admitted_correlation,
        sole_critical_carrier,
    };
    let decision = gate_lens(&evaluation, &cfg).map_err(assay_error_to_dyn)?;

    // Append the decision to the real Ledger CF and index its seq.
    let payload = decide_payload_bytes(project, &decision);
    let ledger_ref = append_assay_gate_entry(cache_dir, project, payload.clone())?;
    let seq = ledger_ref.seq;
    push_gate_index(cache_dir, project, seq)?;

    // Re-fold the serving admission from the CF rows and mirror it (readback-verified).
    let admission = fold_serving_admission(cache_dir, project)?;
    persist_serving_mirror(cache_dir, project, &admission)?;

    // FSV: read the just-written Ledger row back and confirm its payload bytes.
    let readback = read_gate_entry_payload(cache_dir, project, seq)?;
    if readback.as_deref() != Some(payload.as_slice()) {
        return tool_error_result(format!(
            "ASTRO_ASSAY_GATE_READBACK_MISMATCH: gate decision at seq {seq} did not read back byte-identically from the Ledger CF; remediation: the persisted journal diverges from the committed entry; quarantine the vault"
        ));
    }

    tool_json_result(json!({
        "schema": ASSAY_GATE_SURFACE_SCHEMA,
        "status": "decided",
        "project": project,
        "decision": decision_json(&decision),
        "ledger_ref": {
            "seq": seq,
            "entry_hash": hex_lower(&ledger_ref.hash),
            "kind": "assay",
        },
        "serving": serving_json(&admission),
        "decision_readback": serde_json::from_slice::<Value>(&readback.unwrap_or_default()).unwrap_or(Value::Null),
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [format!("assay_gate:decide:{seq}")],
        "source": format!("AsterVault:ColumnFamily::Ledger seq={seq}"),
    }))
}

/// Reverse a prior gate decision (reversible, ledgered), restoring the prior
/// serving state.
fn assay_gate_revert_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let Some(reverts_seq) = args_obj.get("reverts_seq").and_then(Value::as_u64) else {
        return tool_error_result(
            "ASTRO_ASSAY_GATE_INVALID: assay_gate mode=\"revert\" requires reverts_seq; remediation: pass the Ledger seq of the decision to reverse (read it from assay_gate mode=\"status\")",
        );
    };
    let rows = read_gate_journal(cache_dir, project)?;

    // Serving state BEFORE the revert, folded to the prior active decision — the
    // reversibility baseline is the state the reverted decision itself displaced.
    let target = rows.iter().find(|row| row.ledger_seq == reverts_seq);
    let Some(target) = target else {
        return tool_error_result(format!(
            "ASTRO_ASSAY_GATE_REVERT_INVALID: no gate journal entry at Ledger seq {reverts_seq} for project {project:?}; remediation: revert a decision seq listed in assay_gate mode=\"status\""
        ));
    };
    if !matches!(target.action, GateJournalAction::Decide { .. }) {
        return tool_error_result(format!(
            "ASTRO_ASSAY_GATE_REVERT_INVALID: Ledger seq {reverts_seq} is a reversal, not a decision, and cannot be reverted; remediation: revert a Decide entry, not a Revert entry"
        ));
    }
    if rows.iter().any(|row| {
        matches!(row.action, GateJournalAction::Revert { reverts_seq: r } if r == reverts_seq)
    }) {
        return tool_error_result(format!(
            "ASTRO_ASSAY_GATE_REVERT_INVALID: Ledger seq {reverts_seq} is already reverted; remediation: a decision may be reverted at most once — issue a fresh decision instead"
        ));
    }

    let payload = revert_payload_bytes(project, reverts_seq);
    let ledger_ref = append_assay_gate_entry(cache_dir, project, payload.clone())?;
    let seq = ledger_ref.seq;
    push_gate_index(cache_dir, project, seq)?;

    let admission = fold_serving_admission(cache_dir, project)?;
    persist_serving_mirror(cache_dir, project, &admission)?;

    let readback = read_gate_entry_payload(cache_dir, project, seq)?;
    if readback.as_deref() != Some(payload.as_slice()) {
        return tool_error_result(format!(
            "ASTRO_ASSAY_GATE_READBACK_MISMATCH: gate reversal at seq {seq} did not read back byte-identically from the Ledger CF; remediation: quarantine the vault"
        ));
    }

    tool_json_result(json!({
        "schema": ASSAY_GATE_SURFACE_SCHEMA,
        "status": "reverted",
        "project": project,
        "reverts_seq": reverts_seq,
        "ledger_ref": {
            "seq": seq,
            "entry_hash": hex_lower(&ledger_ref.hash),
            "kind": "assay",
        },
        "serving": serving_json(&admission),
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [format!("assay_gate:revert:{seq}->{reverts_seq}")],
        "source": format!("AsterVault:ColumnFamily::Ledger seq={seq}"),
    }))
}

/// Surface the current serving state (Admit/Park/Retire + serving_view mask note),
/// optionally reading a specific journal entry back by its Ledger seq (as_of).
fn assay_gate_status_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let admission = fold_serving_admission(cache_dir, project)?;
    // Mirror-vs-fold FSV: the persisted mirror (if any) must equal the freshly
    // folded bytes; a divergence is a stale mirror, so re-mirror from the
    // authoritative fold rather than serving a stale copy.
    let folded_bytes = admission.to_bytes().map_err(assay_error_to_dyn)?;
    let mirror = read_config_value(cache_dir, &metadata_key(project, ASSAY_GATE_SERVING_KEY))?;
    if mirror.map(String::into_bytes).as_deref() != Some(folded_bytes.as_slice()) {
        persist_serving_mirror(cache_dir, project, &admission)?;
    }

    let as_of = match args_obj.get("as_of_seq").and_then(Value::as_u64) {
        Some(seq) => {
            let payload = read_gate_entry_payload(cache_dir, project, seq)?;
            match payload {
                Some(bytes) => serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
                None => {
                    return tool_error_result(format!(
                        "ASTRO_ASSAY_GATE_AS_OF_MISSING: no Ledger entry at seq {seq} for project {project:?}; remediation: pass an as_of_seq listed in this project's gate journal"
                    ));
                }
            }
        }
        None => Value::Null,
    };

    tool_json_result(json!({
        "schema": ASSAY_GATE_SURFACE_SCHEMA,
        "status": "served",
        "project": project,
        "serving": serving_json(&admission),
        "serving_view": {
            "note": "parked/retired lenses are masked out of serving paths via PanelReadout::serving_view; the frozen roster and historical slot bytes are untouched (non-destructive overlay)",
            "active_lenses": admission.admitted.clone(),
        },
        "as_of": as_of,
        "trust": "verified",
        "freshness": "fresh",
        "provenance": ["assay_gate:status"],
        "source": "AsterVault:ColumnFamily::Ledger (assay gate journal)",
    }))
}

// ---- persistence helpers -------------------------------------------------------

/// Append one gate journal entry to the project's Ledger CF.
fn append_assay_gate_entry(
    cache_dir: &Path,
    project: &str,
    payload: Vec<u8>,
) -> Result<LedgerRef, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Err(format!(
            "ASTRO_ASSAY_GATE_VAULT_MISSING: shadow vault dir missing: {}; remediation: rerun index_repository with calyx=\"shadow\" before gating lenses",
            vault_dir.display()
        )
        .into());
    }
    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger],
    )?;
    let ledger_ref = vault.append_ledger_entry(
        calyx_ledger::EntryKind::Assay,
        SubjectId::Guard(assay_gate_subject(project)),
        payload,
        ActorId::Service(ASSAY_GATE_ACTOR.to_string()),
    )?;
    drop(vault);
    Ok(ledger_ref)
}

/// Read one gate journal entry's persisted payload back from the Ledger CF by seq.
fn read_gate_entry_payload(
    cache_dir: &Path,
    project: &str,
    seq: u64,
) -> Result<Option<Vec<u8>>, DynError> {
    let (vault_dir, _, _) = shadow_vault_config_at(cache_dir, project)?;
    match calyx_aster::ledger_view::read_ledger_seq(&vault_dir, seq)? {
        Some(row) => {
            let entry = decode_ledger(&row.bytes)?;
            Ok(Some(entry.payload))
        }
        None => Ok(None),
    }
}

/// Append a Ledger seq to the per-project ascending gate index.
fn push_gate_index(cache_dir: &Path, project: &str, seq: u64) -> Result<(), DynError> {
    let mut index = read_gate_index(cache_dir, project)?;
    index.push(seq);
    let json = serde_json::to_string(&index)?;
    write_config_value(
        cache_dir,
        &metadata_key(project, ASSAY_GATE_INDEX_KEY),
        &json,
    )?;
    Ok(())
}

/// Read the per-project ascending gate index (empty when unset).
fn read_gate_index(cache_dir: &Path, project: &str) -> Result<Vec<u64>, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, ASSAY_GATE_INDEX_KEY))?
    else {
        return Ok(Vec::new());
    };
    Ok(serde_json::from_str(&raw)?)
}

/// Decode the whole gate journal (all indexed CF rows), in seq order.
fn read_gate_journal(cache_dir: &Path, project: &str) -> Result<Vec<GateJournalRow>, DynError> {
    let index = read_gate_index(cache_dir, project)?;
    let mut rows = Vec::with_capacity(index.len());
    for seq in index {
        let Some(bytes) = read_gate_entry_payload(cache_dir, project, seq)? else {
            return Err(format!(
                "ASTRO_ASSAY_GATE_INDEX_STALE: indexed Ledger seq {seq} is missing for project {project:?}; remediation: the gate index points past the persisted journal — quarantine and rebuild the gate state"
            )
            .into());
        };
        let value: Value = serde_json::from_slice(&bytes)?;
        let action = decode_gate_action(&value).ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ASSAY_GATE_ENTRY_CORRUPT: gate journal entry at seq {seq} is malformed; remediation: quarantine the corrupt gate journal"
            )
            .into()
        })?;
        rows.push(GateJournalRow {
            ledger_seq: seq,
            action,
        });
    }
    Ok(rows)
}

/// Fold the gate journal into the per-repo serving admission (latest active
/// verdict per lens; a decision is active unless a later Revert names its seq).
fn fold_serving_admission(cache_dir: &Path, project: &str) -> Result<ServingAdmission, DynError> {
    let rows = read_gate_journal(cache_dir, project)?;
    let reverted: BTreeSet<u64> = rows
        .iter()
        .filter_map(|row| match row.action {
            GateJournalAction::Revert { reverts_seq } => Some(reverts_seq),
            GateJournalAction::Decide { .. } => None,
        })
        .collect();
    let mut latest: BTreeMap<String, GateVerdict> = BTreeMap::new();
    for row in &rows {
        if let GateJournalAction::Decide { lens, verdict } = &row.action
            && !reverted.contains(&row.ledger_seq)
        {
            latest.insert(lens.clone(), *verdict);
        }
    }
    let mut admitted = Vec::new();
    let mut parked = Vec::new();
    let mut retired = Vec::new();
    for (lens, verdict) in latest {
        match verdict {
            GateVerdict::Admit => admitted.push(lens),
            GateVerdict::Park => parked.push(lens),
            GateVerdict::Retire => retired.push(lens),
        }
    }
    admitted.sort();
    parked.sort();
    retired.sort();
    Ok(ServingAdmission {
        repo: project.to_string(),
        admitted,
        parked,
        retired,
    })
}

/// Mirror the folded serving state into the config store, verified by readback.
fn persist_serving_mirror(
    cache_dir: &Path,
    project: &str,
    admission: &ServingAdmission,
) -> Result<(), DynError> {
    let bytes = admission.to_bytes().map_err(assay_error_to_dyn)?;
    let text = String::from_utf8(bytes.clone())?;
    write_config_value(
        cache_dir,
        &metadata_key(project, ASSAY_GATE_SERVING_KEY),
        &text,
    )?;
    let readback = read_config_value(cache_dir, &metadata_key(project, ASSAY_GATE_SERVING_KEY))?;
    if readback.map(String::into_bytes).as_deref() != Some(bytes.as_slice()) {
        return Err(format!(
            "ASTRO_ASSAY_GATE_MIRROR_MISMATCH: serving-state mirror for project {project:?} did not read back byte-identically; remediation: the config store diverged from the committed serving state"
        )
        .into());
    }
    Ok(())
}

// ---- payload (canonical CF row bytes) ------------------------------------------

fn decide_payload_bytes(project: &str, decision: &GateDecision) -> Vec<u8> {
    // Canonical, stable-key JSON (BTreeMap ordering via serde_json::Value::Object
    // is insertion-order, so build explicitly and sort by using a fixed order).
    let value = json!({
        "card_hash": decision.card_hash,
        "kind": "decide",
        "lens": decision.lens,
        "reason_code": decision.reason_code,
        "repo": project,
        "verdict": decision.verdict.as_str(),
    });
    serde_json::to_vec(&value).expect("gate decide payload serializes")
}

fn revert_payload_bytes(project: &str, reverts_seq: u64) -> Vec<u8> {
    let value = json!({
        "kind": "revert",
        "repo": project,
        "reverts_seq": reverts_seq,
    });
    serde_json::to_vec(&value).expect("gate revert payload serializes")
}

fn decode_gate_action(value: &Value) -> Option<GateJournalAction> {
    match value.get("kind").and_then(Value::as_str)? {
        "decide" => {
            let lens = value.get("lens").and_then(Value::as_str)?.to_string();
            let verdict = match value.get("verdict").and_then(Value::as_str)? {
                "admit" => GateVerdict::Admit,
                "park" => GateVerdict::Park,
                "retire" => GateVerdict::Retire,
                _ => return None,
            };
            Some(GateJournalAction::Decide { lens, verdict })
        }
        "revert" => {
            let reverts_seq = value.get("reverts_seq").and_then(Value::as_u64)?;
            Some(GateJournalAction::Revert { reverts_seq })
        }
        _ => None,
    }
}

// ---- json shaping --------------------------------------------------------------

fn decision_json(decision: &GateDecision) -> Value {
    json!({
        "lens": decision.lens,
        "verdict": decision.verdict.as_str(),
        "reason_code": decision.reason_code,
        "card_hash": decision.card_hash,
    })
}

fn serving_json(admission: &ServingAdmission) -> Value {
    json!({
        "repo": admission.repo,
        "admitted": admission.admitted,
        "parked": admission.parked,
        "retired": admission.retired,
        "admitted_count": admission.admitted.len(),
        "parked_count": admission.parked.len(),
        "retired_count": admission.retired.len(),
    })
}

fn assay_error_to_dyn(error: astrolabe_assay::error::AssayError) -> DynError {
    format!(
        "{}: {}; remediation: {}",
        error.code(),
        error.message(),
        error.remediation()
    )
    .into()
}
