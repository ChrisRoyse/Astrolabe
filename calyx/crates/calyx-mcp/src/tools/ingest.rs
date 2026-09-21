//! Ingest, anchor, and measure MCP tools for PH63 T03.

mod anchor;
mod derived_text;
mod input_retention;
mod media;
mod report;

use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::{ColumnFamily, base_key};
use calyx_aster::vault::input_store::{self, InputRetention};
use calyx_aster::vault::{AsterVault, ExistingBaseAnchorMerge, VaultOptions, encode};
use calyx_core::{
    AbsentReason, Anchor, CalyxError, Constellation, CxFlags, CxId, Input, InputRef, LedgerRef,
    Modality, Slot, SlotState, SlotVector, VaultStore,
};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use calyx_registry::measure::input_hash;
use calyx_registry::{VaultPanelState, load_vault_panel_state};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::protocol::ToolDef;
use crate::schema::{array_schema, boolean_schema, number_schema, object_schema, string_schema};
use crate::server::{McpServer, Tool, ToolError, ToolResult};

use self::anchor::{
    append_anchor_ledger, parse_anchor_kind, parse_anchor_value, validate_confidence,
};
use self::report::constellation_report;
use super::vault::now_ms;
use super::vault::store::{ResolvedVault, home_dir, resolve_vault_info, vault_salt};

const DEFAULT_ANCHOR_SOURCE: &str = "calyx-mcp";

pub fn register(server: &mut McpServer) -> Result<(), CalyxError> {
    server.register(Box::new(IngestTool))?;
    media::register(server)?;
    server.register(Box::new(AnchorTool))?;
    server.register(Box::new(MeasureTool))?;
    Ok(())
}

struct IngestTool;
struct AnchorTool;
struct MeasureTool;

impl Tool for IngestTool {
    fn def(&self) -> ToolDef {
        def(
            "calyx.ingest",
            "ingest text into a Calyx vault",
            "store data -> constellation (auto multi-lens, idempotent)",
            object_schema(&[
                ("vault", string_schema(), true),
                ("input", string_schema(), false),
                ("batch", array_schema(string_schema()), false),
            ]),
        )
    }

    fn call(&self, params: Value) -> ToolResult<Value> {
        let args: IngestArgs = decode("calyx.ingest", params)?;
        let texts = ingest_texts_arg(args.input, args.batch)?;
        let resolved = resolve_requested_vault(&args.vault)?;
        let reports = ingest_texts(&resolved, &texts)?;
        if reports.len() == 1 {
            Ok(serde_json::to_value(&reports[0])
                .map_err(|err| CalyxError::aster_corrupt_shard(format!("encode ingest: {err}")))?)
        } else {
            Ok(json!({ "results": reports }))
        }
    }

    fn requires_authn(&self) -> bool {
        true
    }
}

impl Tool for AnchorTool {
    fn def(&self) -> ToolDef {
        def(
            "calyx.anchor",
            "attach a grounded outcome",
            "attach a grounded outcome (test pass, thumbs, label)",
            object_schema(&[
                ("vault", string_schema(), true),
                ("cx_id", string_schema(), true),
                (
                    "kind",
                    enum_string(&[
                        "test_pass",
                        "thumbs_up",
                        "thumbs_down",
                        "speaker_match",
                        "style_hold",
                        "label",
                    ]),
                    true,
                ),
                ("label", string_schema(), false),
                ("value", value_schema(), true),
                ("confidence", number_schema(), false),
                ("source", string_schema(), false),
            ]),
        )
    }

    fn call(&self, params: Value) -> ToolResult<Value> {
        let args: AnchorArgs = decode("calyx.anchor", params)?;
        let resolved = resolve_requested_vault(&args.vault)?;
        let vault = open_vault(&resolved)?;
        let cx_id = parse_cx_id(&args.cx_id)?;
        ensure_base_exists(&vault, cx_id)?;
        let kind = parse_anchor_kind(&args.kind, args.label.as_deref())?;
        let anchor = Anchor {
            value: parse_anchor_value(&args.kind, &args.value)?,
            kind: kind.clone(),
            source: args
                .source
                .unwrap_or_else(|| DEFAULT_ANCHOR_SOURCE.to_string()),
            observed_at: now_ms(),
            confidence: args.confidence.unwrap_or(1.0),
        };
        validate_confidence(anchor.confidence)?;
        let ledger_seq = append_anchor_ledger(&vault, cx_id, &kind, anchor)?;
        vault.flush()?;
        Ok(json!({
            "status": "anchored",
            "cx_id": cx_id.to_string(),
            "ledger_seq": ledger_seq,
        }))
    }

    fn requires_authn(&self) -> bool {
        true
    }
}

impl Tool for MeasureTool {
    fn def(&self) -> ToolDef {
        def(
            "calyx.measure",
            "measure text without storing it",
            "get the constellation without storing (for guarding a candidate)",
            object_schema(&[
                ("vault", string_schema(), true),
                ("input", string_schema(), true),
            ]),
        )
    }

    fn call(&self, params: Value) -> ToolResult<Value> {
        let args: MeasureArgs = decode("calyx.measure", params)?;
        validate_text(&args.input)?;
        let resolved = resolve_requested_vault(&args.vault)?;
        let vault = open_vault(&resolved)?;
        let state = load_vault_panel_state(&resolved.path)?;
        let measured = measure_constellation(&vault, &state, text_input(args.input), now_ms())?;
        Ok(constellation_report(&measured.constellation, &state))
    }

    fn requires_authn(&self) -> bool {
        false
    }
}

#[derive(Deserialize)]
struct IngestArgs {
    vault: String,
    input: Option<String>,
    batch: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AnchorArgs {
    vault: String,
    cx_id: String,
    kind: String,
    label: Option<String>,
    value: Value,
    confidence: Option<f32>,
    source: Option<String>,
}

#[derive(Deserialize)]
struct MeasureArgs {
    vault: String,
    input: String,
}

#[derive(serde::Serialize)]
struct IngestReport {
    cx_id: String,
    new: bool,
    ledger_seq: u64,
}

struct MeasuredConstellation {
    constellation: Constellation,
}

struct PreparedInput {
    input: Input,
    metadata: BTreeMap<String, String>,
}

fn ingest_texts_arg(input: Option<String>, batch: Option<Vec<String>>) -> ToolResult<Vec<String>> {
    match (input, batch) {
        (Some(_), Some(_)) => Err(ToolError::invalid_params(
            "input and batch are mutually exclusive",
        )),
        (Some(input), None) => {
            validate_text(&input)?;
            Ok(vec![input])
        }
        (None, Some(batch)) if batch.is_empty() => {
            Err(ToolError::invalid_params("batch must not be empty"))
        }
        (None, Some(batch)) => {
            for item in &batch {
                validate_text(item)?;
            }
            Ok(batch)
        }
        (None, None) => Err(ToolError::invalid_params(
            "calyx.ingest requires input or batch",
        )),
    }
}

fn ingest_texts(resolved: &ResolvedVault, texts: &[String]) -> ToolResult<Vec<IngestReport>> {
    let inputs = texts
        .iter()
        .map(|text| PreparedInput {
            input: text_input(text.clone()),
            metadata: BTreeMap::new(),
        })
        .collect::<Vec<_>>();
    ingest_prepared_inputs(resolved, inputs)
}

fn ingest_prepared_inputs(
    resolved: &ResolvedVault,
    inputs: Vec<PreparedInput>,
) -> ToolResult<Vec<IngestReport>> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let vault = open_vault(resolved)?;
    let retention = vault.input_retention()?;
    let state = load_vault_panel_state(&resolved.path)?;

    struct TextPlan {
        input: Option<Input>,
        input_ref: InputRef,
        modality: Modality,
        metadata: BTreeMap<String, String>,
        existing: Option<encode::BaseRecord>,
    }

    let mut staged = Vec::new();
    let mut staged_inputs: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut new_expected = BTreeMap::<CxId, Constellation>::new();
    let mut plans = BTreeMap::<CxId, TextPlan>::new();
    let mut plan_order = Vec::new();
    let mut occurrences = Vec::with_capacity(inputs.len());
    for PreparedInput { input, metadata } in inputs {
        let modality = input.modality;
        let cx_id = vault.cx_id_for_input(&input.bytes, state.panel.version);
        let incoming_ref = InputRef {
            hash: input_hash(&input.bytes),
            pointer: input.pointer.clone(),
            redacted: false,
        };
        if let Some(plan) = plans.get(&cx_id) {
            if plan.input_ref != incoming_ref
                || plan.modality != modality
                || plan.metadata != metadata
            {
                return Err(ToolError::invalid_params(format!(
                    "duplicate MCP ingest for cx {cx_id} changed its non-anchor identity"
                )));
            }
            occurrences.push(cx_id);
            continue;
        }
        plan_order.push(cx_id);
        plans.insert(
            cx_id,
            TextPlan {
                input: Some(input),
                input_ref: incoming_ref,
                modality,
                metadata,
                existing: None,
            },
        );
        occurrences.push(cx_id);
    }

    let preflight_lease = vault.retain_latest_snapshot();
    let preflight_snapshot = preflight_lease.seq();
    let base_records = read_optional_base_record_batch(&vault, preflight_snapshot, &plan_order)?;
    preflight_lease.record_progress();
    let mut new_ids = BTreeSet::new();
    for (cx_id, existing) in plan_order.iter().copied().zip(base_records) {
        let plan = plans.get_mut(&cx_id).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "MCP Base preflight returned unplanned cx {cx_id}"
            ))
        })?;
        if let Some(record) = existing {
            let stored = record.constellation();
            verify_text_identity_fields(TextIdentityVerification {
                cx_id,
                stored: TextIdentityFields {
                    panel_version: stored.panel_version,
                    input_ref: &stored.input_ref,
                    modality: stored.modality,
                    metadata: &stored.metadata,
                },
                incoming: TextIdentityFields {
                    panel_version: state.panel.version,
                    input_ref: &plan.input_ref,
                    modality: plan.modality,
                    metadata: &plan.metadata,
                },
                context: "idempotent MCP ingest replay",
            })?;
            plan.existing = Some(record);
            drop(plan.input.take());
        } else {
            new_ids.insert(cx_id);
            let input = plan.input.take().ok_or_else(|| {
                CalyxError::aster_corrupt_shard(format!(
                    "MCP new-row plan for cx {cx_id} omitted its measurement input"
                ))
            })?;
            let input_bytes = input.bytes.clone();
            let mut measured = measure_constellation(&vault, &state, input, now_ms())?;
            if measured.constellation.cx_id != cx_id {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "MCP text measurement returned cx {} after preflight derived {cx_id}",
                    measured.constellation.cx_id
                ))
                .into());
            }
            measured.constellation.metadata = plan.metadata.clone();
            ensure_content_panel_floor(&measured.constellation, &state)?;
            match retention {
                InputRetention::Persist => {
                    measured.constellation.input_ref.pointer = Some(input_store::input_pointer(
                        &measured.constellation.input_ref.hash,
                    ));
                    measured.constellation.input_ref.redacted = false;
                    staged_inputs.push((measured.constellation.input_ref.hash, input_bytes));
                }
                InputRetention::Redact => {
                    measured.constellation.input_ref.redacted = true;
                    measured.constellation.flags.redacted_input = true;
                }
            }
            new_expected.insert(cx_id, measured.constellation.clone());
            staged.push(measured.constellation);
        }
        preflight_lease.record_progress();
    }
    drop(preflight_lease);
    let mut reported_new = BTreeSet::new();
    let prepared = occurrences
        .into_iter()
        .map(|cx_id| {
            let new = new_ids.contains(&cx_id) && reported_new.insert(cx_id);
            (cx_id, new)
        })
        .collect::<Vec<_>>();

    let mut input_rows = Vec::new();
    for (input_hash, bytes) in &staged_inputs {
        input_rows.extend(input_store::encode_input_rows(input_hash, bytes)?);
    }
    let existing_requests = plan_order
        .iter()
        .filter_map(|cx_id| {
            plans
                .get(cx_id)
                .and_then(|plan| plan.existing.clone())
                .map(|expected| ExistingBaseAnchorMerge {
                    expected,
                    incoming: Vec::new(),
                })
        })
        .collect::<Vec<_>>();
    let commit = vault.put_batch_with_input_rows_and_existing_base_anchor_merges(
        staged,
        input_rows,
        existing_requests,
    )?;
    let readback_seq = commit.readback_seq;
    let commit_seq = commit.commit_seq;

    let mut committed_new_records = BTreeMap::<CxId, encode::BaseRecord>::new();
    for record in commit.new_records {
        let cx_id = record.cx_id();
        let expected = new_expected.get_mut(&cx_id).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "MCP atomic ingest returned unplanned new Base record for cx {cx_id}"
            ))
        })?;
        expected.provenance = record.constellation().provenance.clone();
        if record.encode()? != encode::encode_constellation_base(expected)? {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP atomic ingest returned a different final Base record for new cx {cx_id}"
            ))
            .into());
        }
        if committed_new_records.insert(cx_id, record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP atomic ingest returned duplicate new Base record for cx {cx_id}"
            ))
            .into());
        }
    }
    let mut existing_records = BTreeMap::<CxId, encode::BaseRecord>::new();
    for result in commit.existing_results {
        let cx_id = result.record.cx_id();
        if plans.get(&cx_id).is_none_or(|plan| plan.existing.is_none()) {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP atomic ingest returned unplanned existing Base record for cx {cx_id}"
            ))
            .into());
        }
        if !result.added.is_empty() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP no-anchor replay unexpectedly added anchors to cx {cx_id}"
            ))
            .into());
        }
        if committed_new_records.contains_key(&cx_id)
            || existing_records.insert(cx_id, result.record).is_some()
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP atomic ingest returned duplicate existing Base record for cx {cx_id}"
            ))
            .into());
        }
    }
    if committed_new_records.len() + existing_records.len() != plans.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "MCP atomic ingest returned {} Base records for {} planned CxIds",
            committed_new_records.len() + existing_records.len(),
            plans.len()
        ))
        .into());
    }
    if !commit.marker_ledger_receipts.is_empty() {
        return Err(CalyxError::aster_corrupt_shard(
            "MCP no-anchor ingest returned anchor marker Ledger receipts",
        )
        .into());
    }

    let readback_lease = vault.retain_snapshot_at(readback_seq);
    let flush_report = vault.flush_with_report()?;
    flush_report.verify_commit_base_records(commit_seq, &committed_new_records)?;
    let mut final_records = committed_new_records;
    for (cx_id, record) in existing_records {
        if final_records.insert(cx_id, record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP atomic ingest produced overlapping new/existing record for cx {cx_id}"
            ))
            .into());
        }
    }
    verify_base_record_batch_readback(&vault, readback_seq, &plan_order, &final_records)?;
    readback_lease.record_progress();
    verify_hydrated_new_batch_readback(&vault, readback_seq, &plan_order, &new_expected)?;
    readback_lease.record_progress();
    for cx_id in &plan_order {
        let record = final_records.get(cx_id).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "MCP post-commit readback plan omitted final record for cx {cx_id}"
            ))
        })?;
        verify_stored_text_input_state(&vault, record.constellation())?;
        readback_lease.record_progress();
    }
    verify_persisted_inputs(&vault, &staged_inputs)?;
    readback_lease.record_progress();
    drop(readback_lease);

    let retry_ids = prepared
        .iter()
        .filter(|(_, new)| !new)
        .map(|(cx_id, _)| *cx_id)
        .collect::<Vec<_>>();
    let retry_ledger_seq = append_ingest_retry_batch_ledger(&vault, &retry_ids)?;
    let mut reports = Vec::with_capacity(prepared.len());
    for (cx_id, new) in prepared {
        let ledger_seq = if new {
            final_records
                .get(&cx_id)
                .ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "MCP ingest report omitted committed Base record for cx {cx_id}"
                    ))
                })?
                .constellation()
                .provenance
                .seq
        } else {
            retry_ledger_seq.ok_or_else(|| {
                CalyxError::ledger_group_commit_failed(format!(
                    "MCP retry report for cx {cx_id} has no batch retry Ledger ref"
                ))
            })?
        };
        reports.push(IngestReport {
            cx_id: cx_id.to_string(),
            new,
            ledger_seq,
        });
    }
    vault.flush()?;
    let final_snapshot = vault.snapshot();
    verify_base_record_batch_readback(&vault, final_snapshot, &plan_order, &final_records)?;
    Ok(reports)
}

struct TextIdentityFields<'a> {
    panel_version: u32,
    input_ref: &'a InputRef,
    modality: Modality,
    metadata: &'a BTreeMap<String, String>,
}

struct TextIdentityVerification<'a> {
    cx_id: CxId,
    stored: TextIdentityFields<'a>,
    incoming: TextIdentityFields<'a>,
    context: &'a str,
}

fn verify_text_identity_fields(verification: TextIdentityVerification<'_>) -> ToolResult<()> {
    let TextIdentityVerification {
        cx_id,
        stored,
        incoming,
        context,
    } = verification;
    let mut changed = Vec::new();
    if stored.panel_version != incoming.panel_version {
        changed.push("panel_version");
    }
    if !input_ref_matches_replay(stored.input_ref, incoming.input_ref) {
        changed.push("input_ref");
    }
    if stored.modality != incoming.modality {
        changed.push("modality");
    }
    if stored.metadata != incoming.metadata {
        changed.push("metadata");
    }
    if changed.is_empty() {
        return Ok(());
    }
    Err(ToolError::invalid_params(format!(
        "{context} for cx {cx_id} changed stored non-anchor fields: {}",
        changed.join(",")
    )))
}

fn input_ref_matches_replay(stored: &InputRef, incoming: &InputRef) -> bool {
    if stored == incoming {
        return true;
    }
    if stored.hash != incoming.hash {
        return false;
    }
    if !stored.redacted
        && !incoming.redacted
        && incoming.pointer.is_none()
        && stored.pointer.as_deref() == Some(input_store::input_pointer(&stored.hash).as_str())
    {
        return true;
    }
    stored.redacted && !incoming.redacted && stored.pointer == incoming.pointer
}

fn read_optional_base_record_batch(
    vault: &AsterVault,
    snapshot: u64,
    cx_ids: &[CxId],
) -> ToolResult<Vec<Option<encode::BaseRecord>>> {
    let reads = cx_ids
        .iter()
        .map(|cx_id| (ColumnFamily::Base, base_key(*cx_id)))
        .collect::<Vec<_>>();
    let values = vault.read_cf_batch_at(snapshot, reads)?;
    if values.len() != cx_ids.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "ordered MCP Base preflight returned {} rows for {} requested CxIds",
            values.len(),
            cx_ids.len()
        ))
        .into());
    }
    let mut records = Vec::with_capacity(cx_ids.len());
    for (cx_id, value) in cx_ids.iter().copied().zip(values) {
        let Some(bytes) = value else {
            records.push(None);
            continue;
        };
        let record = encode::BaseRecord::decode_for_key(cx_id, &bytes)?;
        if bytes != record.encode()? {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable MCP Base row for cx {cx_id} is not canonically encoded"
            ))
            .into());
        }
        if record.vault_id() != vault.vault_id() {
            return Err(CalyxError::vault_access_denied(format!(
                "durable MCP Base row for cx {cx_id} belongs to another vault"
            ))
            .into());
        }
        records.push(Some(record));
    }
    Ok(records)
}

fn verify_base_record_batch_readback(
    vault: &AsterVault,
    snapshot: u64,
    cx_ids: &[CxId],
    expected: &BTreeMap<CxId, encode::BaseRecord>,
) -> ToolResult<()> {
    if expected.len() != cx_ids.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "ordered MCP Base readback has {} expected rows for {} requested CxIds",
            expected.len(),
            cx_ids.len()
        ))
        .into());
    }
    let reads = cx_ids
        .iter()
        .map(|cx_id| (ColumnFamily::Base, base_key(*cx_id)))
        .collect::<Vec<_>>();
    let values = vault.read_cf_batch_at(snapshot, reads)?;
    if values.len() != cx_ids.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "ordered MCP Base readback returned {} rows for {} requested CxIds",
            values.len(),
            cx_ids.len()
        ))
        .into());
    }
    for (cx_id, value) in cx_ids.iter().copied().zip(values) {
        let bytes = value.ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "durable MCP Base row for cx {cx_id} is missing at snapshot {snapshot}"
            ))
        })?;
        let observed = encode::BaseRecord::decode_for_key(cx_id, &bytes)?;
        if bytes != observed.encode()? {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable MCP Base row for cx {cx_id} is not canonically encoded"
            ))
            .into());
        }
        if observed.vault_id() != vault.vault_id() {
            return Err(CalyxError::vault_access_denied(format!(
                "durable MCP Base row for cx {cx_id} belongs to another vault"
            ))
            .into());
        }
        let expected = expected.get(&cx_id).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "ordered MCP Base readback omitted expected record for cx {cx_id}"
            ))
        })?;
        if bytes != expected.encode()? {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable MCP ingest Base readback mismatch for cx {cx_id}"
            ))
            .into());
        }
    }
    Ok(())
}

fn verify_hydrated_new_batch_readback(
    vault: &AsterVault,
    snapshot: u64,
    plan_order: &[CxId],
    expected: &BTreeMap<CxId, Constellation>,
) -> ToolResult<()> {
    let new_order = plan_order
        .iter()
        .copied()
        .filter(|cx_id| expected.contains_key(cx_id))
        .collect::<Vec<_>>();
    let stored = vault.get_many_at(snapshot, &new_order)?;
    if stored.len() != new_order.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "ordered MCP hydrated readback returned {} rows for {} new CxIds",
            stored.len(),
            new_order.len()
        ))
        .into());
    }
    for (cx_id, stored) in new_order.into_iter().zip(stored) {
        let expected = expected.get(&cx_id).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "ordered MCP hydrated readback omitted expected new cx {cx_id}"
            ))
        })?;
        if stored != *expected {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable MCP ingest hydrated readback mismatch for new cx {cx_id}"
            ))
            .into());
        }
    }
    Ok(())
}

fn ensure_content_panel_floor(
    constellation: &Constellation,
    state: &VaultPanelState,
) -> ToolResult<()> {
    let mut declared = 0_usize;
    let mut present = 0_usize;
    for slot in &state.panel.slots {
        if !slot.counts_toward_degraded(constellation.modality) {
            continue;
        }
        declared += 1;
        if constellation
            .slots
            .get(&slot.slot_id)
            .is_some_and(|vector| !vector.is_absent())
        {
            present += 1;
        }
    }
    if declared > 0 && present == 0 {
        return Err(CalyxError::lens_unreachable(format!(
            "MCP ingest refused cx {} because none of its {declared} declared content slots materialized",
            constellation.cx_id
        ))
        .into());
    }
    Ok(())
}

fn verify_persisted_inputs(
    vault: &AsterVault,
    persisted: &[([u8; 32], Vec<u8>)],
) -> ToolResult<()> {
    for (expected_hash, expected_bytes) in persisted {
        let readback = input_store::read_input_bytes(vault, expected_hash)?;
        if &readback != expected_bytes {
            return Err(CalyxError {
                code: input_store::CALYX_INPUT_STORE_CORRUPT,
                message: format!(
                    "post-commit MCP input-store readback of {} returned {} bytes, expected {} bytes",
                    hex_hash(expected_hash),
                    readback.len(),
                    expected_bytes.len()
                ),
                remediation:
                    "the MCP input-store commit path is inconsistent; do not trust this vault",
            }
            .into());
        }
    }
    Ok(())
}

fn verify_stored_text_input_state(vault: &AsterVault, stored: &Constellation) -> ToolResult<()> {
    if stored.input_ref.redacted || stored.flags.redacted_input {
        if stored.input_ref.redacted && stored.flags.redacted_input {
            return Ok(());
        }
        return Err(CalyxError {
            code: "CALYX_MCP_INPUT_RETENTION_INCONSISTENT",
            message: format!(
                "cx {} has inconsistent redaction labels: input_ref.redacted={} flags.redacted_input={}",
                stored.cx_id, stored.input_ref.redacted, stored.flags.redacted_input
            ),
            remediation:
                "repair or rebuild the vault record so redaction is explicit on both stored labels",
        }
        .into());
    }

    let expected_pointer = input_store::input_pointer(&stored.input_ref.hash);
    if stored.input_ref.pointer.as_deref() != Some(expected_pointer.as_str()) {
        return Err(CalyxError {
            code: "CALYX_MCP_INPUT_RETENTION_INCONSISTENT",
            message: format!(
                "cx {} text input pointer {:?} does not resolve to the required {expected_pointer}",
                stored.cx_id, stored.input_ref.pointer
            ),
            remediation:
                "re-ingest from a source vault that writes cxinput rows, or run a dedicated input-store backfill before treating this record as retained",
        }
        .into());
    }
    let _ = input_store::read_input_bytes(vault, &stored.input_ref.hash)?;
    Ok(())
}

fn measure_constellation(
    vault: &AsterVault,
    state: &VaultPanelState,
    input: Input,
    now: u64,
) -> ToolResult<MeasuredConstellation> {
    let cx_id = vault.cx_id_for_input(&input.bytes, state.panel.version);
    let mut slots = BTreeMap::new();
    let mut degraded = false;
    let mut applicable = 0_usize;
    let mut produced = 0_usize;
    let mut unavailable = 0_usize;
    for slot in &state.panel.slots {
        let vector = measure_slot(
            slot,
            state,
            &input,
            &mut applicable,
            &mut produced,
            &mut unavailable,
        )?;
        degraded |= slot.counts_toward_degraded(input.modality) && vector.is_absent();
        slots.insert(slot.slot_id, vector);
    }
    if applicable == 0 {
        return Err(ToolError::invalid_params(format!(
            "panel has no active {:?}-compatible slots",
            input.modality
        )));
    }
    if produced == 0 && unavailable == applicable {
        return Err(
            CalyxError::lens_unreachable("all applicable lens runtimes unreachable").into(),
        );
    }
    Ok(MeasuredConstellation {
        constellation: Constellation {
            cx_id,
            vault_id: vault.vault_id(),
            panel_version: state.panel.version,
            created_at: now,
            input_ref: InputRef {
                hash: input_hash(&input.bytes),
                pointer: input.pointer,
                redacted: false,
            },
            modality: input.modality,
            slots,
            scalars: BTreeMap::new(),
            metadata: BTreeMap::new(),
            anchors: Vec::new(),
            provenance: LedgerRef {
                seq: vault.latest_seq().saturating_add(1),
                hash: [0; 32],
            },
            flags: CxFlags {
                ungrounded: true,
                degraded,
                novel_region: false,
                redacted_input: false,
            },
        },
    })
}

fn measure_slot(
    slot: &Slot,
    state: &VaultPanelState,
    input: &Input,
    applicable: &mut usize,
    produced: &mut usize,
    unavailable: &mut usize,
) -> ToolResult<SlotVector> {
    if slot.state != SlotState::Active {
        return Ok(absent(AbsentReason::LensInactive));
    }
    if slot.modality != input.modality {
        return Ok(absent(AbsentReason::NotApplicable));
    }
    *applicable += 1;
    if !state.registry.contains(slot.lens_id) {
        *unavailable += 1;
        return Ok(absent(AbsentReason::LensUnavailable));
    }
    match state.registry.measure(slot.lens_id, input) {
        Ok(vector) => {
            *produced += 1;
            Ok(vector)
        }
        Err(error) if error.code == "CALYX_LENS_UNREACHABLE" => {
            *unavailable += 1;
            Ok(absent(AbsentReason::LensUnavailable))
        }
        Err(error) => Err(error.into()),
    }
}

fn append_ingest_retry_batch_ledger(
    vault: &AsterVault,
    cx_ids: &[CxId],
) -> ToolResult<Option<u64>> {
    let Some(first_cx_id) = cx_ids.first().copied() else {
        return Ok(None);
    };
    let ordered_ids = cx_ids.iter().map(CxId::to_string).collect::<Vec<_>>();
    let first = first_cx_id.to_string();
    let last = cx_ids
        .last()
        .copied()
        .ok_or_else(|| {
            CalyxError::ledger_group_commit_failed(
                "non-empty MCP retry batch omitted its final CxId",
            )
        })?
        .to_string();
    let bytes = serde_json::to_vec(&json!({
        "mode": "mcp-idempotent-ingest-batch",
        "count": ordered_ids.len(),
        "cx_ids": ordered_ids,
        "first_cx_id": first,
        "last_cx_id": last,
    }))
    .map_err(|err| CalyxError::aster_corrupt_shard(format!("encode retry ledger: {err}")))?;
    append_ledger_payload(vault, EntryKind::Ingest, first_cx_id, bytes).map(Some)
}

fn append_ledger_payload(
    vault: &AsterVault,
    kind: EntryKind,
    cx_id: CxId,
    bytes: Vec<u8>,
) -> ToolResult<u64> {
    Ok(vault
        .append_ledger_entry(
            kind,
            SubjectId::Cx(cx_id),
            bytes,
            ActorId::Service(DEFAULT_ANCHOR_SOURCE.to_string()),
        )?
        .seq)
}

fn resolve_requested_vault(vault: &str) -> ToolResult<ResolvedVault> {
    let home = home_dir()?;
    resolve_vault_info(&home, vault)
}

fn open_vault(resolved: &ResolvedVault) -> ToolResult<AsterVault> {
    Ok(AsterVault::open(
        &resolved.path,
        resolved.vault_id,
        vault_salt(resolved.vault_id, &resolved.name),
        VaultOptions {
            restore_mvcc_rows: false,
            ..VaultOptions::default()
        },
    )?)
}

fn ensure_base_exists(vault: &AsterVault, cx_id: CxId) -> ToolResult<()> {
    if base_exists(vault, cx_id)? {
        return Ok(());
    }
    Err(CalyxError::vault_access_denied(format!("cx_id {cx_id} does not exist in vault")).into())
}

fn base_exists(vault: &AsterVault, cx_id: CxId) -> ToolResult<bool> {
    Ok(vault
        .read_cf_at(vault.snapshot(), ColumnFamily::Base, &base_key(cx_id))?
        .is_some())
}

fn parse_cx_id(value: &str) -> ToolResult<CxId> {
    value
        .parse::<CxId>()
        .map_err(|err| ToolError::invalid_params(format!("parse cx_id {value}: {err}")))
}

fn validate_text(value: &str) -> ToolResult<()> {
    if value.is_empty() {
        return Err(ToolError::invalid_params("input must not be empty"));
    }
    Ok(())
}

fn text_input(text: String) -> Input {
    Input::new(Modality::Text, text.into_bytes())
}

fn hex_hash(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn absent(reason: AbsentReason) -> SlotVector {
    SlotVector::Absent { reason }
}

fn decode<T: DeserializeOwned>(tool: &str, params: Value) -> ToolResult<T> {
    serde_json::from_value(params)
        .map_err(|err| ToolError::invalid_params(format!("{tool} invalid arguments: {err}")))
}

fn def(name: &str, description: &str, use_when: &str, input_schema: Value) -> ToolDef {
    ToolDef {
        name: name.to_string(),
        description: description.to_string(),
        use_when: use_when.to_string(),
        input_schema,
    }
}

fn enum_string(values: &[&str]) -> Value {
    json!({ "type": "string", "enum": values })
}

fn value_schema() -> Value {
    json!({ "oneOf": [boolean_schema(), number_schema()] })
}
