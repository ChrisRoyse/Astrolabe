use super::super::ledger::anchor_marker_ledger_draft;
use super::batch_support::{
    BatchBaseReadback, BatchOrderRow, IdentityFields, append_idempotent_batch_ledger,
    append_oracle_events, identity_mismatch_reason, input_ref_matches_replay,
    merge_existing_batch_anchors, plan_existing_batch_anchor_merges,
    verify_anchor_marker_ledger_readback, verify_batch_base_readback,
    verify_existing_batch_replay_identity,
};
use super::*;

pub(crate) struct BatchPreflight {
    pub(crate) cx_ids: BTreeSet<CxId>,
    pub(crate) existing: BTreeSet<CxId>,
}

pub(crate) fn preflight_batch(
    vault: &AsterVault,
    state: &VaultPanelState,
    path: &std::path::Path,
    validated_row_count: usize,
) -> CliResult<BatchPreflight> {
    use std::io::BufRead;

    let started = std::time::Instant::now();
    ingest_runtime_log(format_args!(
        "phase=batch_existing_identity_preflight_start rows={validated_row_count}"
    ));
    let file = std::fs::File::open(path)
        .map_err(|err| CliError::io(format!("open batch {}: {err}", path.display())))?;
    let reader = std::io::BufReader::new(file);
    let snapshot = vault.snapshot();
    let mut checked_existing = 0_usize;
    let mut not_existing_or_incomplete = 0_usize;
    let mut parsed_rows = 0_usize;
    let mut witnesses = BTreeMap::<CxId, ExistingPlainReplayRow>::new();
    for (index, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|err| CliError::io(format!("read batch line {}: {err}", index + 1)))?;
        let Some((text, mut metadata, anchors, oracle)) = parse_batch_line(index, &line)? else {
            continue;
        };
        parsed_rows += 1;
        if let Some(event) = &oracle {
            event.apply_metadata(&mut metadata)?;
        }
        let input = text_input(text);
        let row = ExistingPlainReplayRow {
            cx_id: vault.cx_id_for_input(&input.bytes, state.panel.version),
            panel_version: state.panel.version,
            input_ref: InputRef {
                hash: input_hash(&input.bytes),
                pointer: input.pointer,
                redacted: false,
            },
            modality: input.modality,
            metadata,
            anchors,
            oracle,
            expected_base: None,
        };
        match witnesses.entry(row.cx_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(row);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                merge_preflight_witness(entry.get_mut(), row)?;
            }
        }
    }
    if parsed_rows != validated_row_count {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "batch preflight parsed {parsed_rows} rows after validation recorded {validated_row_count}"
        ))
        .into());
    }
    let mut existing = BTreeSet::new();
    for row in witnesses.values() {
        match read_existing_base_replay_row(vault, snapshot, row)? {
            Some((_, true)) => {
                existing.insert(row.cx_id);
                checked_existing += 1;
            }
            Some((_, false)) => {
                existing.insert(row.cx_id);
                not_existing_or_incomplete += 1;
            }
            None => not_existing_or_incomplete += 1,
        }
    }
    ingest_runtime_log(format_args!(
        "phase=batch_existing_identity_preflight_ok rows={} existing_checked={} not_existing_or_incomplete={} elapsed_ms={}",
        validated_row_count,
        checked_existing,
        not_existing_or_incomplete,
        started.elapsed().as_millis()
    ));
    Ok(BatchPreflight {
        cx_ids: witnesses.into_keys().collect(),
        existing,
    })
}

#[derive(Clone)]
pub(crate) struct ExistingPlainReplayRow {
    cx_id: CxId,
    panel_version: u32,
    input_ref: InputRef,
    modality: Modality,
    metadata: BTreeMap<String, String>,
    anchors: Vec<Anchor>,
    oracle: Option<OracleEvent>,
    expected_base: Option<encode::BaseRecord>,
}

pub(crate) struct ExistingBatchReplayRow {
    pub(crate) cx_id: CxId,
    pub(crate) input_ref: InputRef,
    pub(crate) modality: Modality,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) anchors: Vec<Anchor>,
    pub(crate) oracle: Option<OracleEvent>,
}

fn merge_preflight_witness(
    existing: &mut ExistingPlainReplayRow,
    incoming: ExistingPlainReplayRow,
) -> CliResult<()> {
    if existing.panel_version != incoming.panel_version
        || !input_ref_matches_replay(&existing.input_ref, &incoming.input_ref)
        || existing.modality != incoming.modality
        || existing.metadata != incoming.metadata
    {
        return Err(CliError::usage(format!(
            "batch contains duplicate cx {} with changed non-anchor identity: {}",
            incoming.cx_id,
            identity_mismatch_reason(
                IdentityFields {
                    panel_version: existing.panel_version,
                    input_ref: &existing.input_ref,
                    modality: existing.modality,
                    metadata: &existing.metadata,
                },
                IdentityFields {
                    panel_version: incoming.panel_version,
                    input_ref: &incoming.input_ref,
                    modality: incoming.modality,
                    metadata: &incoming.metadata,
                },
            )
        )));
    }
    if existing.oracle != incoming.oracle {
        return Err(CliError::usage(format!(
            "batch contains duplicate cx {} with different oracle events",
            incoming.cx_id
        )));
    }
    let mut anchors = existing
        .anchors
        .iter()
        .map(|anchor| (anchor.kind.clone(), anchor.clone()))
        .collect::<BTreeMap<_, _>>();
    for anchor in incoming.anchors {
        match anchors.get(&anchor.kind) {
            Some(prior) if same_anchor_observation(prior, &anchor) => {}
            Some(_) => {
                return Err(CliError::usage(format!(
                    "batch contains duplicate cx {} with different observations for anchor kind {:?}",
                    incoming.cx_id, anchor.kind
                )));
            }
            None => {
                anchors.insert(anchor.kind.clone(), anchor.clone());
                existing.anchors.push(anchor);
            }
        }
    }
    Ok(())
}

fn same_anchor_observation(left: &Anchor, right: &Anchor) -> bool {
    left.kind == right.kind
        && left.value == right.value
        && left.source == right.source
        && left.confidence.to_bits() == right.confidence.to_bits()
}

pub(crate) fn existing_plain_batch_replay_rows(
    vault: &AsterVault,
    state: &VaultPanelState,
    rows: &[BatchRow],
) -> CliResult<Option<Vec<ExistingPlainReplayRow>>> {
    let mut out = Vec::with_capacity(rows.len());
    let snapshot = vault.snapshot();
    let mut all_materialized = true;
    let mut checked_existing = 0_usize;
    for (text, metadata, anchors, oracle) in rows {
        let input = text_input(text.clone());
        let cx_id = vault.cx_id_for_input(&input.bytes, state.panel.version);
        let input_ref = InputRef {
            hash: input_hash(&input.bytes),
            pointer: input.pointer,
            redacted: false,
        };
        let mut metadata = metadata.clone();
        if let Some(event) = oracle {
            event.apply_metadata(&mut metadata)?;
        }
        let row = ExistingPlainReplayRow {
            cx_id,
            panel_version: state.panel.version,
            input_ref,
            modality: input.modality,
            metadata,
            anchors: anchors.clone(),
            oracle: oracle.clone(),
            expected_base: None,
        };
        match read_existing_base_replay_row(vault, snapshot, &row)? {
            Some((record, true)) => {
                checked_existing += 1;
                out.push(ExistingPlainReplayRow {
                    expected_base: Some(record),
                    ..row
                });
            }
            Some((_, false)) | None => {
                all_materialized = false;
            }
        }
    }
    if all_materialized {
        Ok(Some(out))
    } else {
        ingest_runtime_log(format_args!(
            "phase=batch_existing_replay_base_only_preflight_mixed rows={} existing_materialized={} measurement_required=true slot_decode_skipped=true",
            rows.len(),
            checked_existing
        ));
        Ok(None)
    }
}

pub(crate) fn flush_plain_existing_batch_replay(
    vault: &AsterVault,
    vault_path: &std::path::Path,
    rows: Vec<ExistingPlainReplayRow>,
    summary: &mut BatchIngestSummary,
    output: IngestOutput,
) -> CliResult<()> {
    for sub in rows.chunks(EXISTING_REPLAY_CHUNK) {
        let merged = merge_existing_batch_anchors(
            vault,
            sub.iter()
                .map(|row| {
                    row.expected_base
                        .clone()
                        .map(|expected| (expected, Vec::new()))
                        .ok_or_else(|| {
                            CliError::from(calyx_core::CalyxError::aster_corrupt_shard(format!(
                                "idempotent batch replay lost its Base readback witness for cx {}",
                                row.cx_id
                            )))
                        })
                })
                .collect::<CliResult<Vec<_>>>()?,
        )?;
        let readback_lease = vault.retain_snapshot_at(merged.readback_seq);
        for result in merged.results.values() {
            if !result.added.is_empty() {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(
                    "plain existing batch replay unexpectedly added an anchor",
                )
                .into());
            }
            verify_base_record_readback(vault, merged.readback_seq, &result.record)?;
            readback_lease.record_progress();
        }
        drop(readback_lease);
        let ids = sub.iter().map(|row| row.cx_id).collect::<Vec<_>>();
        let ledger_seq = append_cli_batch_ledger(
            vault,
            EntryKind::Ingest,
            &ids,
            "cli-idempotent-ingest-batch",
        )?;
        vault.flush()?;
        calyx_aster::base_page_index::advance_base_page_index_head_if_base_unchanged(vault_path)?;
        let snapshot = vault.snapshot();
        for row in sub {
            let expected = merged.results.get(&row.cx_id).ok_or_else(|| {
                calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "idempotent batch replay atomic validation omitted cx {}",
                    row.cx_id
                ))
            })?;
            verify_base_record_readback(vault, snapshot, &expected.record)?;
            let report = IngestReport {
                cx_id: row.cx_id.to_string(),
                new: false,
                ledger_seq,
            };
            summary.record(row.cx_id, &report);
            if output == IngestOutput::Rows {
                print_json(&report)?;
            }
        }
    }
    Ok(())
}

fn read_existing_base_replay_row(
    vault: &AsterVault,
    snapshot: u64,
    row: &ExistingPlainReplayRow,
) -> CliResult<Option<(encode::BaseRecord, bool)>> {
    let Some(record) = read_optional_base_record(vault, snapshot, row.cx_id)? else {
        return Ok(None);
    };
    let existing = record.constellation();
    if existing.panel_version != row.panel_version
        || !input_ref_matches_replay(&existing.input_ref, &row.input_ref)
        || existing.modality != row.modality
        || existing.metadata != row.metadata
    {
        return Err(CliError::usage(format!(
            "idempotent batch replay for cx {} changed stored non-anchor identity: {}",
            row.cx_id,
            identity_mismatch_reason(
                IdentityFields {
                    panel_version: existing.panel_version,
                    input_ref: &existing.input_ref,
                    modality: existing.modality,
                    metadata: &existing.metadata,
                },
                IdentityFields {
                    panel_version: row.panel_version,
                    input_ref: &row.input_ref,
                    modality: row.modality,
                    metadata: &row.metadata,
                },
            )
        )));
    }
    if !incoming_anchors_already_materialized(vault, snapshot, row.cx_id, &row.anchors, &existing)?
    {
        return Ok(Some((record, false)));
    }
    Ok(Some((record, true)))
}

fn incoming_anchors_already_materialized(
    vault: &AsterVault,
    snapshot: u64,
    cx_id: CxId,
    incoming_anchors: &[Anchor],
    existing_base: &Constellation,
) -> CliResult<bool> {
    if incoming_anchors.is_empty() {
        return Ok(true);
    }
    let mut incoming = existing_base.clone();
    incoming.anchors = incoming_anchors.to_vec();
    if let AnchorConflictResult::Conflicting {
        anchor_type,
        reason,
    } = check_anchor_conflict(&incoming, existing_base)
    {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "idempotent batch replay for cx {cx_id} has conflicting {anchor_type:?} anchor: {reason:?}"
        ))
        .into());
    }
    for anchor in incoming_anchors {
        let Some(base_anchor) = existing_base
            .anchors
            .iter()
            .find(|existing| existing.kind == anchor.kind)
        else {
            return Ok(false);
        };
        let Some(bytes) = vault.read_cf_at(
            snapshot,
            ColumnFamily::Anchors,
            &anchor_key(cx_id, &anchor.kind),
        )?
        else {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "idempotent batch replay for cx {cx_id} found anchor {:?} in Base CF but missing from Anchors CF",
                anchor.kind
            ))
            .into());
        };
        if bytes != encode::encode_anchor(base_anchor)? {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "idempotent batch replay for cx {cx_id} found Base/Anchors CF byte disagreement for {:?}",
                anchor.kind
            ))
            .into());
        }
        if !super::batch_support::same_anchor_observation(base_anchor, anchor) {
            return Err(CliError::usage(format!(
                "idempotent batch replay for cx {cx_id} changed source or confidence for anchor {:?}",
                anchor.kind
            )));
        }
    }
    Ok(true)
}

pub(crate) fn existing_batch_replay_rows(
    vault: &AsterVault,
    state: &VaultPanelState,
    rows: &[BatchRow],
) -> CliResult<Option<Vec<ExistingBatchReplayRow>>> {
    let mut out = Vec::with_capacity(rows.len());
    let mut all_exist = true;
    let mut checked_existing = 0_usize;
    for (text, metadata, anchors, oracle) in rows {
        let input = text_input(text.clone());
        let cx_id = vault.cx_id_for_input(&input.bytes, state.panel.version);
        if !base_exists(vault, cx_id)? {
            all_exist = false;
            continue;
        }
        let input_ref = InputRef {
            hash: input_hash(&input.bytes),
            pointer: input.pointer,
            redacted: false,
        };
        let mut metadata = metadata.clone();
        if let Some(event) = oracle {
            event.apply_metadata(&mut metadata)?;
        }
        let row = ExistingBatchReplayRow {
            cx_id,
            input_ref,
            modality: input.modality,
            metadata,
            anchors: anchors.clone(),
            oracle: oracle.clone(),
        };
        verify_existing_batch_replay_identity(vault, state, &row)?;
        checked_existing += 1;
        out.push(row);
    }
    if all_exist {
        Ok(Some(out))
    } else {
        ingest_runtime_log(format_args!(
            "phase=batch_existing_replay_preflight_mixed rows={} existing_checked={} measurement_required=true slot_decode_skipped=true",
            rows.len(),
            checked_existing
        ));
        Ok(None)
    }
}

pub(crate) fn flush_existing_batch_replay(
    vault: &AsterVault,
    state: &VaultPanelState,
    rows: Vec<ExistingBatchReplayRow>,
    summary: &mut BatchIngestSummary,
    output: IngestOutput,
) -> CliResult<()> {
    for sub in rows.chunks(EXISTING_REPLAY_CHUNK) {
        let mut prepared = Vec::with_capacity(sub.len());
        for row in sub {
            let existing = verify_existing_batch_replay_identity(vault, state, row)?;
            prepared.push((row, existing));
        }
        let existing_requests = plan_existing_batch_anchor_merges(
            prepared
                .iter()
                .map(|(row, existing)| (existing.clone(), row.anchors.clone())),
        )?;
        let marker_drafts = prepared
            .iter()
            .flat_map(|(row, _)| {
                row.anchors
                    .iter()
                    .map(|anchor| anchor_marker_ledger_draft(row.cx_id, anchor))
            })
            .collect::<CliResult<Vec<_>>>()?;
        let commit = vault.put_batch_with_input_rows_existing_anchor_merges_and_marker_ledgers(
            Vec::<Constellation>::new(),
            Vec::new(),
            existing_requests,
            marker_drafts,
        )?;
        if !commit.new_records.is_empty() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(
                "existing batch replay unexpectedly returned a new Base record",
            )
            .into());
        }
        let commit_seq = commit.commit_seq;
        let readback = vault.retain_snapshot_at(commit.readback_seq);
        ingest_runtime_log(format_args!(
            "phase=batch_existing_anchor_merge rows={} distinct_cx={} readback_seq={} commit_seq={}",
            sub.len(),
            commit.existing_results.len(),
            commit.readback_seq,
            commit_seq
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
        let marker_receipt_readback = commit.marker_ledger_receipts.clone();
        let mut merged_results = BTreeMap::new();
        for result in commit.existing_results {
            let cx_id = result.record.cx_id();
            if merged_results.insert(cx_id, result).is_some() {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "existing batch replay returned duplicate merge result for cx {cx_id}"
                ))
                .into());
            }
        }
        let changed_records = merged_results
            .iter()
            .filter(|(_, result)| !result.added.is_empty())
            .map(|(cx_id, result)| (*cx_id, result.record.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut expected_markers = merged_results
            .iter()
            .flat_map(|(cx_id, result)| {
                result
                    .added
                    .iter()
                    .map(|anchor| ((*cx_id, anchor.kind.clone()), anchor.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut available_markers = BTreeMap::<
            CxId,
            BTreeMap<AnchorKind, calyx_aster::vault::AnchorMarkerLedgerReceipt>,
        >::new();
        for receipt in commit.marker_ledger_receipts {
            let key = (receipt.cx_id, receipt.anchor.kind.clone());
            let expected = expected_markers.remove(&key).ok_or_else(|| {
                calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "existing batch replay returned an unplanned marker for cx {} kind {:?}",
                    receipt.cx_id, receipt.anchor.kind
                ))
            })?;
            if expected != receipt.anchor {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "existing batch replay marker changed the committed anchor for cx {} kind {:?}",
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
                    "existing batch replay returned a duplicate marker for cx {}",
                    key.0
                ))
                .into());
            }
        }
        if let Some(((cx_id, kind), _)) = expected_markers.first_key_value() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "existing batch replay omitted the marker for cx {cx_id} kind {kind:?}"
            ))
            .into());
        }
        let mut order = Vec::with_capacity(sub.len());
        for (row, _) in prepared {
            let result = merged_results.get(&row.cx_id).ok_or_else(|| {
                calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "existing batch anchor merge omitted cx {}",
                    row.cx_id
                ))
            })?;
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
                expected_readback: BatchBaseReadback::Persisted(result.record.clone()),
                new: false,
                marker_anchors,
                oracle: row.oracle.clone(),
            });
        }
        if available_markers
            .values()
            .any(|receipts| !receipts.is_empty())
        {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(
                "existing batch anchor marker receipt has no proposing row",
            )
            .into());
        }
        let flush_report = vault.flush_with_report()?;
        verify_flushed_base_records(&flush_report, commit_seq, &changed_records)?;
        verify_batch_base_readback(vault, readback.seq(), &order)?;
        verify_anchor_marker_ledger_readback(
            vault,
            readback.seq(),
            marker_receipt_readback.iter(),
        )?;
        drop(readback);
        append_oracle_events(vault, &order)?;
        let idempotent_ledger_seq = append_idempotent_batch_ledger(vault, &order)?;
        for row in order {
            let cx_id = row.cx_id;
            let ledger_seq = idempotent_ledger_seq.ok_or_else(|| {
                CliError::usage("missing idempotent batch ledger seq for replay row")
            })?;
            let report = IngestReport {
                cx_id: cx_id.to_string(),
                new: false,
                ledger_seq,
            };
            summary.record(cx_id, &report);
            if output == IngestOutput::Rows {
                print_json(&report)?;
            }
        }
        vault.flush()?;
    }
    Ok(())
}
