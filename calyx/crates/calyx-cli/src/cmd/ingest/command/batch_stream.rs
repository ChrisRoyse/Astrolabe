use super::super::ledger::anchor_marker_ledger_draft;
use super::super::session::BatchIngestSession;
use super::batch_physical::{
    batch_base_state, reconcile_summary_with_verified_base, reject_tombstoned_batch_ids,
};
use super::batch_support::{
    BatchBaseReadback, BatchOrderRow, append_idempotent_batch_ledger, append_oracle_events,
    plan_existing_batch_anchor_merges, same_anchor_observation,
    verify_anchor_marker_ledger_readback, verify_batch_base_readback,
};
use super::replay::{
    existing_batch_replay_rows, existing_plain_batch_replay_rows, flush_existing_batch_replay,
    flush_plain_existing_batch_replay, preflight_batch,
};
use super::*;

type BatchSummaryEmitter<'a> = &'a mut dyn FnMut(&BatchIngestSummary) -> CliResult<()>;

/// Per-invocation parameters of the streaming batch ingest.
#[derive(Clone, Copy)]
pub(crate) struct BatchStreamRequest {
    pub(crate) output: IngestOutput,
    pub(crate) validated_row_count: usize,
    pub(crate) gpu_route: IngestGpuRoute,
    /// Per-ingest override of the vault's raw-input retention policy (#446).
    pub(crate) retention_override: Option<InputRetention>,
}

pub(crate) fn ingest_validated_batch_streaming_with_output(
    resolved: &ResolvedVault,
    path: &std::path::Path,
    request: BatchStreamRequest,
    mut summary_emitter: Option<BatchSummaryEmitter<'_>>,
    mut session: Option<&mut BatchIngestSession>,
) -> CliResult<BatchIngestSummary> {
    let BatchStreamRequest {
        output,
        validated_row_count,
        gpu_route,
        retention_override,
    } = request;
    use std::io::BufRead;
    let file = std::fs::File::open(path)
        .map_err(|err| CliError::io(format!("open batch {}: {err}", path.display())))?;
    let reader = std::io::BufReader::new(file);
    let open_started = std::time::Instant::now();
    if let Some(session) = session.as_deref_mut() {
        session.record_phase("open_vault_start")?;
    }
    ingest_runtime_log(format_args!(
        "phase=open_vault_start vault={} rows={validated_row_count}",
        resolved.path.display()
    ));
    let vault = match open_vault(resolved) {
        Ok(vault) => {
            let recovery = vault.recovery_report();
            ingest_runtime_log(format_args!(
                "phase=open_vault_ok vault={} last_recovered_seq={} torn_tail={} elapsed_ms={}",
                resolved.path.display(),
                recovery.last_recovered_seq,
                recovery.torn_tail.is_some(),
                open_started.elapsed().as_millis()
            ));
            if let Some(session) = session.as_deref_mut() {
                session.record_phase("open_vault_ok")?;
            }
            vault
        }
        Err(error) => {
            ingest_runtime_log(format_args!(
                "phase=open_vault_error vault={} error_code={} error_message_json={} elapsed_ms={}",
                resolved.path.display(),
                error.code(),
                json_string(error.message()),
                open_started.elapsed().as_millis()
            ));
            return Err(error);
        }
    };
    ingest_runtime_log(format_args!(
        "phase=load_vault_panel_state_start vault={}",
        resolved.path.display()
    ));
    let state = load_vault_panel_state(&resolved.path)?;
    let derived_content_before = vault.derived_content_seq();
    ingest_runtime_log(format_args!(
        "phase=load_vault_panel_state_ok vault={} panel_version={} slots={}",
        resolved.path.display(),
        state.panel.version,
        state.panel.slots.len()
    ));
    if let Some(session) = session.as_deref_mut() {
        session.record_phase("load_vault_panel_state_ok")?;
    }
    let mut seen = BTreeSet::new();
    let runtime_batch_limit = measure_batch_size();
    let measure_window = measure_window_size(runtime_batch_limit);
    let flush_options = BatchFlushOptions {
        output,
        runtime_batch_limit,
        gpu_route,
        input_retention: resolve_input_retention(&vault, retention_override)?,
    };
    ingest_runtime_log(format_args!(
        "phase=batch_ingest_plan rows={} runtime_batch_limit={} measure_window={} put_chunk={} output={:?} resident_addr={:?} allow_cold_gpu_workers={}",
        validated_row_count,
        runtime_batch_limit,
        measure_window,
        PUT_CHUNK,
        output,
        gpu_route.resident_addr,
        gpu_route.allow_cold_gpu_workers
    ));
    let preflight = preflight_batch(&vault, &state, path, validated_row_count)?;
    let before_lease = vault.retain_latest_snapshot();
    let base_before = batch_base_state(&vault, before_lease.seq(), &preflight.cx_ids)?;
    reject_tombstoned_batch_ids(&base_before)?;
    before_lease.record_progress();
    drop(before_lease);
    ingest_runtime_log(format_args!(
        "phase=batch_base_key_preflight distinct_cx={} visible={} tombstoned={}",
        preflight.cx_ids.len(),
        base_before.visible.len(),
        base_before.tombstoned.len()
    ));
    if let Some(session) = session.as_deref_mut() {
        session.record_phase("batch_base_key_preflight")?;
    }
    stake_rebuild_required_marker(
        &resolved.path,
        "batch_ingest",
        format!(
            "batch ingest of {validated_row_count} planned rows ({} distinct constellations) from {}; derived search indexes are unproven until the post-commit rebuild republishes the manifest",
            preflight.cx_ids.len(),
            path.display()
        ),
        session.as_deref().map(|session| session.session_id()),
        Some(path),
    )?;
    let mut chunk: Vec<BatchRow> = Vec::with_capacity(measure_window);
    let mut summary = BatchIngestSummary::empty();
    for (index, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|err| CliError::io(format!("read batch line {}: {err}", index + 1)))?;
        if let Some(row) = parse_batch_line(index, &line)? {
            chunk.push(row);
            if chunk.len() >= measure_window {
                if let Some(session) = session.as_deref_mut() {
                    session.record_rows_started(
                        summary.row_count + chunk.len(),
                        "batch_flush_start",
                    )?;
                }
                flush_measure_batch(
                    &vault,
                    &state,
                    &resolved.path,
                    &mut chunk,
                    &mut seen,
                    &preflight.existing,
                    &mut summary,
                    flush_options,
                )?;
                if let Some(session) = session.as_deref_mut() {
                    session.record_summary_progress(&summary, "batch_flush_committed")?;
                }
            }
        }
    }
    if !chunk.is_empty() {
        if let Some(session) = session.as_deref_mut() {
            session.record_rows_started(summary.row_count + chunk.len(), "batch_flush_start")?;
        }
        flush_measure_batch(
            &vault,
            &state,
            &resolved.path,
            &mut chunk,
            &mut seen,
            &preflight.existing,
            &mut summary,
            flush_options,
        )?;
        if let Some(session) = session.as_deref_mut() {
            session.record_summary_progress(&summary, "batch_flush_committed")?;
        }
    }
    let after_lease = vault.retain_latest_snapshot();
    let base_after = batch_base_state(&vault, after_lease.seq(), &preflight.cx_ids)?;
    after_lease.record_progress();
    drop(after_lease);
    reconcile_summary_with_verified_base(
        &mut summary,
        &base_before,
        &base_after,
        &preflight.cx_ids,
        validated_row_count,
    )?;
    if let Some(session) = session.as_deref_mut() {
        session.record_summary_progress(&summary, "batch_base_receipt_readback_complete")?;
    }
    let summary_emit_error = emit_batch_summary_if_requested(&mut summary_emitter, &summary)?;
    batch_rebuild::run_post_commit_index_rebuild(
        resolved,
        &vault,
        &state,
        &summary,
        derived_content_before,
        &mut session,
    )?;
    if let Some(session) = session {
        session.complete(&summary, vault.snapshot())?;
    }
    if let Some(error) = summary_emit_error {
        return Err(error);
    }
    Ok(summary)
}

fn emit_batch_summary_if_requested(
    summary_emitter: &mut Option<BatchSummaryEmitter<'_>>,
    summary: &BatchIngestSummary,
) -> CliResult<Option<CliError>> {
    let Some(emitter) = summary_emitter.as_mut() else {
        return Ok(None);
    };
    match (*emitter)(summary) {
        Ok(()) => {
            ingest_runtime_log(format_args!(
                "phase=batch_summary_emitted row_count={} new_count={} already_count={} verified_base_rows={}",
                summary.row_count,
                summary.new_count,
                summary.already_count,
                summary.verified_base_rows
            ));
            Ok(None)
        }
        Err(error) => {
            ingest_runtime_log(format_args!(
                "phase=batch_summary_emit_error error_code={} error_message_json={} row_count={} new_count={} already_count={}",
                error.code(),
                json_string(error.message()),
                summary.row_count,
                summary.new_count,
                summary.already_count
            ));
            Ok(Some(error))
        }
    }
}

fn flush_measure_batch(
    vault: &AsterVault,
    state: &VaultPanelState,
    vault_path: &std::path::Path,
    chunk: &mut Vec<BatchRow>,
    seen: &mut BTreeSet<CxId>,
    preexisting: &BTreeSet<CxId>,
    summary: &mut BatchIngestSummary,
    options: BatchFlushOptions,
) -> CliResult<()> {
    let rows: Vec<BatchRow> = std::mem::take(chunk);
    struct PreparedRow {
        cx_id: CxId,
        anchors: Vec<Anchor>,
        oracle: Option<OracleEvent>,
    }

    struct UniqueRowPlan {
        input: Input,
        input_ref: InputRef,
        metadata: BTreeMap<String, String>,
        anchors: Vec<Anchor>,
        anchor_indexes: BTreeMap<AnchorKind, usize>,
        existing: Option<encode::BaseRecord>,
    }

    let row_count = rows.len();
    let mut prepared_rows = Vec::with_capacity(row_count);
    let mut unique_order = Vec::<CxId>::new();
    let mut unique = BTreeMap::<CxId, UniqueRowPlan>::new();
    for (text, metadata, anchors, oracle) in &rows {
        let mut metadata = metadata.clone();
        if let Some(event) = oracle {
            event.apply_metadata(&mut metadata)?;
        }
        let input = text_input(text.clone());
        let cx_id = vault.cx_id_for_input(&input.bytes, state.panel.version);
        let input_ref = InputRef {
            hash: input_hash(&input.bytes),
            pointer: input.pointer.clone(),
            redacted: false,
        };
        let plan = match unique.entry(cx_id) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let plan = entry.into_mut();
                if plan.input_ref != input_ref
                    || plan.input.modality != input.modality
                    || plan.metadata != metadata
                {
                    return Err(CliError::usage(format!(
                        "batch contains duplicate cx {cx_id} with changed non-anchor identity: {}",
                        super::batch_support::identity_mismatch_reason(
                            super::batch_support::IdentityFields {
                                panel_version: state.panel.version,
                                input_ref: &plan.input_ref,
                                modality: plan.input.modality,
                                metadata: &plan.metadata,
                            },
                            super::batch_support::IdentityFields {
                                panel_version: state.panel.version,
                                input_ref: &input_ref,
                                modality: input.modality,
                                metadata: &metadata,
                            },
                        )
                    )));
                }
                plan
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                unique_order.push(cx_id);
                entry.insert(UniqueRowPlan {
                    input,
                    input_ref,
                    metadata,
                    anchors: Vec::new(),
                    anchor_indexes: BTreeMap::new(),
                    existing: None,
                })
            }
        };
        for anchor in anchors {
            match plan.anchor_indexes.get(&anchor.kind).copied() {
                Some(index) if same_anchor_observation(&plan.anchors[index], anchor) => {}
                Some(_) => {
                    return Err(CliError::usage(format!(
                        "batch contains duplicate cx {cx_id} with different observations for anchor kind {:?}",
                        anchor.kind
                    )));
                }
                None => {
                    plan.anchor_indexes
                        .insert(anchor.kind.clone(), plan.anchors.len());
                    plan.anchors.push(anchor.clone());
                }
            }
        }
        prepared_rows.push(PreparedRow {
            cx_id,
            anchors: anchors.clone(),
            oracle: oracle.clone(),
        });
    }

    let all_preexisting = unique_order.iter().all(|cx_id| preexisting.contains(cx_id));
    if all_preexisting
        && rows.iter().all(|(_, _, _, oracle)| oracle.is_none())
        && let Some(existing_rows) = existing_plain_batch_replay_rows(vault, state, &rows)?
    {
        ingest_runtime_log(format_args!(
            "phase=batch_existing_replay_base_only_fast_path rows={} runtime_batch_limit={} measurement_skipped=true slot_decode_skipped=true",
            existing_rows.len(),
            options.runtime_batch_limit
        ));
        flush_plain_existing_batch_replay(
            vault,
            vault_path,
            existing_rows,
            summary,
            options.output,
        )?;
        return Ok(());
    }
    if all_preexisting && let Some(existing_rows) = existing_batch_replay_rows(vault, state, &rows)?
    {
        ingest_runtime_log(format_args!(
            "phase=batch_existing_replay_fast_path rows={} runtime_batch_limit={} measurement_skipped=true slot_decode_skipped=true",
            existing_rows.len(),
            options.runtime_batch_limit
        ));
        flush_existing_batch_replay(vault, state, existing_rows, summary, options.output)?;
        return Ok(());
    }

    // Derived identity and first-occurrence order stay invariant while Base
    // witnesses are classified before any model work.
    let preflight = vault.retain_latest_snapshot();
    let preflight_snapshot = preflight.seq();
    for cx_id in &unique_order {
        let plan = unique.get_mut(cx_id).ok_or_else(|| {
            calyx_core::CalyxError::aster_corrupt_shard(format!(
                "mixed batch unique order omitted its plan for cx {cx_id}"
            ))
        })?;
        let Some(existing) = read_optional_base_record(vault, preflight_snapshot, *cx_id)? else {
            preflight.record_progress();
            continue;
        };
        let stored = existing.constellation();
        if stored.panel_version != state.panel.version
            || !super::batch_support::input_ref_matches_replay(&stored.input_ref, &plan.input_ref)
            || stored.modality != plan.input.modality
            || stored.metadata != plan.metadata
        {
            return Err(CliError::usage(format!(
                "idempotent batch replay for cx {cx_id} changed stored non-anchor identity: {}",
                super::batch_support::identity_mismatch_reason(
                    super::batch_support::IdentityFields {
                        panel_version: stored.panel_version,
                        input_ref: &stored.input_ref,
                        modality: stored.modality,
                        metadata: &stored.metadata,
                    },
                    super::batch_support::IdentityFields {
                        panel_version: state.panel.version,
                        input_ref: &plan.input_ref,
                        modality: plan.input.modality,
                        metadata: &plan.metadata,
                    },
                )
            )));
        }
        let mut proposed = stored.clone();
        proposed.anchors = plan.anchors.clone();
        if let AnchorConflictResult::Conflicting {
            anchor_type,
            reason,
        } = check_anchor_conflict(&proposed, stored)
        {
            return Err(CliError::usage(format!(
                "idempotent batch replay for cx {cx_id} has conflicting {anchor_type:?} anchor: {reason:?}"
            )));
        }
        for anchor in &plan.anchors {
            if let Some(stored_anchor) = stored
                .anchors
                .iter()
                .find(|stored_anchor| stored_anchor.kind == anchor.kind)
                && !same_anchor_observation(stored_anchor, anchor)
            {
                return Err(CliError::usage(format!(
                    "idempotent batch replay for cx {cx_id} changed the persisted observation for anchor {:?}",
                    anchor.kind
                )));
            }
        }
        plan.existing = Some(existing);
        preflight.record_progress();
    }
    drop(preflight);

    let missing_ids = unique_order
        .iter()
        .copied()
        .filter(|cx_id| {
            unique
                .get(cx_id)
                .is_some_and(|plan| plan.existing.is_none())
        })
        .collect::<Vec<_>>();
    let measurement_inputs = missing_ids
        .iter()
        .map(|cx_id| {
            unique
                .get(cx_id)
                .map(|plan| plan.input.clone())
                .ok_or_else(|| {
                    CliError::from(calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "mixed batch measurement order omitted its plan for cx {cx_id}"
                    )))
                })
        })
        .collect::<CliResult<Vec<_>>>()?;
    let constellations = if measurement_inputs.is_empty() {
        Vec::new()
    } else {
        measure_constellation_microbatch_with_runtime_limit(
            vault,
            state,
            &measurement_inputs,
            now_ms(),
            Some(options.runtime_batch_limit),
            options.gpu_route,
        )?
    };
    if constellations.len() != missing_ids.len() {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "mixed batch measured {} constellations for {} absent unique CxIds",
            constellations.len(),
            missing_ids.len()
        ))
        .into());
    }
    let mut measured = BTreeMap::<CxId, Constellation>::new();
    for (cx_id, mut cx) in missing_ids.into_iter().zip(constellations) {
        if cx.cx_id != cx_id {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "mixed batch measurement returned cx {} after preflight derived {cx_id}",
                cx.cx_id
            ))
            .into());
        }
        let plan = unique.get(&cx_id).ok_or_else(|| {
            calyx_core::CalyxError::aster_corrupt_shard(format!(
                "mixed batch measurement result omitted its plan for cx {cx_id}"
            ))
        })?;
        cx.metadata = plan.metadata.clone();
        ensure_content_panel_floor(&cx, state)?;
        if measured.insert(cx_id, cx).is_some() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "mixed batch measurement returned duplicate cx {cx_id}"
            ))
            .into());
        }
    }
    ingest_runtime_log(format_args!(
        "phase=batch_mixed_base_preflight rows={} distinct_cx={} existing={} base_point_reads={} measurement_inputs={} slot_decode_skipped={}",
        row_count,
        unique.len(),
        unique.len() - measured.len(),
        unique.len(),
        measured.len(),
        !unique.values().all(|plan| plan.existing.is_none())
    ));

    let mut current_records = unique
        .iter()
        .filter_map(|(cx_id, plan)| plan.existing.clone().map(|record| (*cx_id, record)))
        .collect::<BTreeMap<_, _>>();
    for sub in prepared_rows.chunks(PUT_CHUNK) {
        struct PendingRow {
            cx_id: CxId,
            new: bool,
            existing: bool,
            anchors: Vec<Anchor>,
            oracle: Option<OracleEvent>,
        }

        let mut staged = Vec::new();
        let mut staged_inputs: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut pending = Vec::with_capacity(sub.len());
        let mut existing_merges = Vec::new();
        let mut new_final = BTreeMap::<CxId, Constellation>::new();
        let mut new_anchor_indexes = BTreeMap::<CxId, BTreeMap<AnchorKind, usize>>::new();
        for row in sub {
            let existing = current_records.get(&row.cx_id).cloned();
            let exists = existing.is_some();
            let new = if exists || new_final.contains_key(&row.cx_id) {
                false
            } else {
                if !seen.insert(row.cx_id) {
                    return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "mixed batch found cx {} absent after an earlier flush reported it new",
                        row.cx_id
                    ))
                    .into());
                }
                true
            };
            if let Some(existing) = existing {
                existing_merges.push((existing, row.anchors.clone()));
            } else {
                let plan = unique.get(&row.cx_id).ok_or_else(|| {
                    calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "mixed batch staging omitted its unique plan for cx {}",
                        row.cx_id
                    ))
                })?;
                // #446: every duplicate-new occurrence receives the identical
                // retention projection and is passed to Aster's atomic duplicate
                // merge. Input bytes are staged once, on the first occurrence.
                let mut cx_new = measured.get(&row.cx_id).cloned().ok_or_else(|| {
                    calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "mixed batch staging omitted its measurement for absent cx {}",
                        row.cx_id
                    ))
                })?;
                cx_new.anchors = row.anchors.clone();
                cx_new.flags.ungrounded = cx_new.anchors.is_empty();
                match options.input_retention {
                    InputRetention::Persist => {
                        cx_new.input_ref.pointer =
                            Some(input_store::input_pointer(&cx_new.input_ref.hash));
                        cx_new.input_ref.redacted = false;
                        if new {
                            staged_inputs.push((cx_new.input_ref.hash, plan.input.bytes.clone()));
                        }
                    }
                    InputRetention::Redact => {
                        cx_new.input_ref.redacted = true;
                        cx_new.flags.redacted_input = true;
                    }
                }
                staged.push(cx_new.clone());
                match new_final.entry(cx_new.cx_id) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let indexes = cx_new
                            .anchors
                            .iter()
                            .enumerate()
                            .map(|(index, anchor)| (anchor.kind.clone(), index))
                            .collect();
                        new_anchor_indexes.insert(cx_new.cx_id, indexes);
                        entry.insert(cx_new);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        let indexes =
                            new_anchor_indexes.get_mut(&cx_new.cx_id).ok_or_else(|| {
                                calyx_core::CalyxError::aster_corrupt_shard(format!(
                                    "duplicate-new batch planning omitted anchor index for cx {}",
                                    cx_new.cx_id
                                ))
                            })?;
                        for anchor in &cx_new.anchors {
                            match indexes.get(&anchor.kind).copied() {
                                Some(index)
                                    if same_anchor_observation(
                                        &entry.get().anchors[index],
                                        anchor,
                                    ) => {}
                                Some(_) => {
                                    return Err(CliError::usage(format!(
                                        "batch contains duplicate cx {} with different observations for anchor kind {:?}",
                                        cx_new.cx_id, anchor.kind
                                    )));
                                }
                                None => {
                                    indexes.insert(anchor.kind.clone(), entry.get().anchors.len());
                                    entry.get_mut().anchors.push(anchor.clone());
                                }
                            }
                        }
                        let ungrounded = entry.get().anchors.is_empty();
                        entry.get_mut().flags.ungrounded = ungrounded;
                    }
                }
            }
            pending.push(PendingRow {
                cx_id: row.cx_id,
                new,
                existing: exists,
                anchors: row.anchors.clone(),
                oracle: row.oracle.clone(),
            });
        }
        let mut input_rows = Vec::new();
        for (input_hash, bytes) in &staged_inputs {
            input_rows.extend(input_store::encode_input_rows(input_hash, bytes)?);
        }
        let marker_drafts = pending
            .iter()
            .flat_map(|row| {
                row.anchors
                    .iter()
                    .map(|anchor| anchor_marker_ledger_draft(row.cx_id, anchor))
            })
            .collect::<CliResult<Vec<_>>>()?;
        let existing_requests = plan_existing_batch_anchor_merges(existing_merges)?;
        let commit = vault.put_batch_with_input_rows_existing_anchor_merges_and_marker_ledgers(
            staged,
            input_rows,
            existing_requests,
            marker_drafts,
        )?;
        let readback_seq = commit.readback_seq;
        let commit_seq = commit.commit_seq;
        let readback = vault.retain_snapshot_at(readback_seq);
        let marker_receipt_readback = commit.marker_ledger_receipts.clone();
        let mut merged_results = BTreeMap::new();
        for result in commit.existing_results {
            let cx_id = result.record.cx_id();
            if merged_results.insert(cx_id, result).is_some() {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned duplicate existing result for cx {cx_id}"
                ))
                .into());
            }
        }
        let mut new_records = BTreeMap::new();
        for record in commit.new_records {
            let cx_id = record.cx_id();
            let mut expected = new_final.get(&cx_id).cloned().ok_or_else(|| {
                calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned unplanned new cx {cx_id}"
                ))
            })?;
            expected.provenance = record.constellation().provenance.clone();
            if record.encode()? != encode::encode_constellation_base(&expected)? {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned a different final Base record for new cx {cx_id}"
                ))
                .into());
            }
            if new_records.insert(cx_id, record).is_some() {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned duplicate new result for cx {cx_id}"
                ))
                .into());
            }
        }
        if new_records.len() != new_final.len() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "atomic mixed batch returned {} new Base records for {} planned CxIds",
                new_records.len(),
                new_final.len()
            ))
            .into());
        }
        let mut changed_records = new_records.clone();
        for (cx_id, result) in &merged_results {
            if !result.added.is_empty()
                && changed_records
                    .insert(*cx_id, result.record.clone())
                    .is_some()
            {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned duplicate changed Base record for cx {cx_id}"
                ))
                .into());
            }
        }
        for (cx_id, result) in &merged_results {
            if current_records
                .insert(*cx_id, result.record.clone())
                .is_none()
            {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned an existing result without a Base witness for cx {cx_id}"
                ))
                .into());
            }
        }
        for (cx_id, record) in &new_records {
            if current_records.insert(*cx_id, record.clone()).is_some() {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned a new result for witnessed existing cx {cx_id}"
                ))
                .into());
            }
        }
        if !merged_results.is_empty() {
            ingest_runtime_log(format_args!(
                "phase=batch_existing_anchor_merge rows={} distinct_cx={} readback_seq={} commit_seq={}",
                pending.iter().filter(|row| row.existing).count(),
                merged_results.len(),
                readback_seq,
                commit_seq
                    .map(|seq| seq.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
        }
        let mut expected_markers = BTreeMap::new();
        for (cx_id, result) in &merged_results {
            for anchor in &result.added {
                expected_markers.insert((*cx_id, anchor.kind.clone()), anchor.clone());
            }
        }
        for (cx_id, cx) in &new_final {
            for anchor in &cx.anchors {
                expected_markers.insert((*cx_id, anchor.kind.clone()), anchor.clone());
            }
        }
        let mut available_markers = BTreeMap::<
            CxId,
            BTreeMap<AnchorKind, calyx_aster::vault::AnchorMarkerLedgerReceipt>,
        >::new();
        for receipt in commit.marker_ledger_receipts {
            let key = (receipt.cx_id, receipt.anchor.kind.clone());
            let expected = expected_markers.remove(&key).ok_or_else(|| {
                calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned an unplanned anchor marker for cx {} kind {:?}",
                    receipt.cx_id, receipt.anchor.kind
                ))
            })?;
            if expected != receipt.anchor {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch anchor marker changed the committed anchor for cx {} kind {:?}",
                    receipt.cx_id, receipt.anchor.kind
                ))
                .into());
            }
            if available_markers
                .entry(receipt.cx_id)
                .or_default()
                .insert(receipt.anchor.kind.clone(), receipt)
                .is_some()
            {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic mixed batch returned a duplicate anchor marker for cx {}",
                    key.0
                ))
                .into());
            }
        }
        if let Some(((cx_id, kind), _)) = expected_markers.first_key_value() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "atomic mixed batch omitted the anchor marker for cx {cx_id} kind {kind:?}"
            ))
            .into());
        }
        let mut order = Vec::with_capacity(pending.len());
        for row in pending {
            let expected_readback = if row.existing {
                let result = merged_results.get(&row.cx_id).ok_or_else(|| {
                    calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "mixed batch anchor merge omitted existing cx {}",
                        row.cx_id
                    ))
                })?;
                BatchBaseReadback::Persisted(result.record.clone())
            } else {
                let expected = new_final.get(&row.cx_id).ok_or_else(|| {
                    calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "mixed batch planning omitted new cx {}",
                        row.cx_id
                    ))
                })?;
                let record = new_records.get(&row.cx_id).ok_or_else(|| {
                    calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "atomic mixed batch omitted new Base result for cx {}",
                        row.cx_id
                    ))
                })?;
                let mut expected = expected.clone();
                expected.provenance = record.constellation().provenance.clone();
                BatchBaseReadback::Hydrated(expected)
            };
            let marker_anchors = row
                .anchors
                .iter()
                .filter_map(|anchor| {
                    available_markers
                        .get_mut(&row.cx_id)
                        .and_then(|available| available.remove(&anchor.kind))
                        .map(|receipt| receipt.anchor)
                })
                .collect();
            order.push(BatchOrderRow {
                cx_id: row.cx_id,
                expected_readback,
                new: row.new,
                marker_anchors,
                oracle: row.oracle,
            });
        }
        if available_markers
            .values()
            .any(|receipts| !receipts.is_empty())
        {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(
                "batch anchor marker receipt has no proposing row",
            )
            .into());
        }
        let flush_report = vault.flush_with_report()?;
        verify_flushed_base_records(&flush_report, commit_seq, &changed_records)?;
        // FSV in the write path (#446): persisted input bytes are read back and
        // byte-compared before this chunk's reports are emitted.
        verify_persisted_inputs(vault, &staged_inputs)?;
        let snapshot = readback.seq();
        verify_batch_base_readback(vault, snapshot, &order)?;
        verify_anchor_marker_ledger_readback(vault, snapshot, marker_receipt_readback.iter())?;
        for record in new_records.values() {
            verify_base_record_readback(vault, snapshot, record)?;
        }
        drop(readback);
        append_oracle_events(vault, &order)?;
        let idempotent_ledger_seq = append_idempotent_batch_ledger(vault, &order)?;
        for row in order {
            let cx_id = row.cx_id;
            let ledger_seq = if row.new {
                new_records
                    .get(&cx_id)
                    .ok_or_else(|| {
                        calyx_core::CalyxError::aster_corrupt_shard(format!(
                            "atomic mixed batch omitted new ledger receipt for cx {cx_id}"
                        ))
                    })?
                    .constellation()
                    .provenance
                    .seq
            } else {
                idempotent_ledger_seq.ok_or_else(|| {
                    CliError::usage("missing idempotent batch ledger seq for replay row")
                })?
            };
            let report = IngestReport {
                cx_id: cx_id.to_string(),
                new: row.new,
                ledger_seq,
            };
            summary.record(cx_id, &report);
            if options.output == IngestOutput::Rows {
                print_json(&report)?;
            }
        }
        vault.flush()?;
    }
    Ok(())
}
