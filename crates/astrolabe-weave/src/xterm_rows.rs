//! XTerm CF persistence for the six specialized agreement comparators.
//!
//! These six rows serve anomaly and architecture consumers. They do not claim
//! active-panel completeness: `complete_xterms` independently persists every
//! applicable unordered base pair plus an exact completion witness. Absent
//! specialized comparisons are never written as zeros.
//!
//! Rows are loom-native [`XtermRow`] JSON at `xterm_key(cx, left, right,
//! Agreement)` — the exact shape `live_anomaly_inputs_from_vault` already
//! reads back — so the doc-drift and name-truth detectors run off persisted
//! state, not planner echoes.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, XTermKind, prefix_range, xterm_key};
use calyx_aster::mvcc::{LatestOnlyReadbackStatus, tombstone_value};
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, CxId, LedgerRef, SlotId, VaultStore};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use calyx_loom::agreement_graph::XtermRow;
use calyx_loom::{
    CrossTermKey, CrossTermKind as LoomCrossTermKind, CrossTermValue as LoomCrossTermValue,
    SignalProvenanceTag,
};
use serde::Serialize;

use crate::bounded_run::{
    MAX_MUTATION_BYTES_PER_COMMIT, MAX_MUTATION_ROWS_PER_COMMIT, RunReceipt, RunWorkspace,
    run_content_hasher, update_run_content_hash,
};
use crate::{
    CrossTermValue, EagerAgreementKind, EagerCrossTermRow, EagerCrossTermStreamReport,
    SimilarityNode, hex_lower_bytes, stream_eager_cross_term_kind,
    stream_eager_cross_term_kind_for_symbols,
};

/// Ledger payload schema for an eager cross-term persistence group commit.
pub const XTERM_EAGER_LEDGER_SCHEMA: &str = "astrolabe.eager_xterm.v2";
/// Stable schema for the `get_architecture` agreement-graph aspect payload.
pub const AGREEMENT_GRAPH_ASPECT_SCHEMA: &str = "astrolabe.agreement_graph_aspect.v1";
/// Provenance label naming the physical source of the agreement-graph aspect.
pub const AGREEMENT_GRAPH_ASPECT_PROVENANCE: &str = "AsterVault:ColumnFamily::XTerm:agreement";
/// Stable failure code for corrupt or inconsistent persisted xterm rows.
pub const ASTRO_XTERM_ROW_CORRUPT: &str = "ASTRO_XTERM_ROW_CORRUPT";
/// Stable failure code for a plan row whose symbol has no CxId mapping.
pub const ASTRO_XTERM_CX_ID_MISSING: &str = "ASTRO_XTERM_CX_ID_MISSING";
/// Stable failure code for a stale, drifting, or unbounded XTerm run source.
pub const ASTRO_XTERM_RUN_SOURCE_INVALID: &str = "ASTRO_XTERM_RUN_SOURCE_INVALID";

const XTERM_SCAN_PAGE_ROWS: usize = 1_024;

const XTERM_REMEDIATION: &str = "regenerate eager cross-term rows with the bounded kind-run planner and persistence API from a fresh source-bound plan";

/// Report for one eager cross-term persistence group commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EagerCrossTermPersistReport {
    /// Symbols covered by the persisted plan.
    pub symbol_count: usize,
    /// Scalar rows written or rewritten in this commit.
    pub rows_written: usize,
    /// Scalar rows already byte-identical and left untouched.
    pub rows_unchanged: usize,
    /// Owned stale rows tombstoned in this commit.
    pub rows_tombstoned: usize,
    /// Absent cross-terms per designed kind — counted, never persisted, never
    /// zero-filled.
    pub absent_by_kind: BTreeMap<EagerAgreementKind, usize>,
    /// Lowercase-hex blake3 of the canonical scalar-row dump, as ledgered.
    pub xterm_dump_hash: String,
    /// Ledger entries paired with bounded mutation groups, or the one no-delta
    /// audit entry.
    pub ledger_refs: Vec<LedgerRef>,
    /// Unforgeable exact readback witness per changed mutation group.
    pub fsv: Vec<FsvAck>,
    pub run: EagerCrossTermRunTelemetry,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EagerCrossTermRunTelemetry {
    pub desired_rows: u64,
    pub desired_bytes: u64,
    pub existing_rows: u64,
    pub existing_bytes: u64,
    pub chunk_runs: usize,
    pub mutation_groups: usize,
    pub mutation_rows_high_water: usize,
    pub mutation_bytes_high_water: usize,
    pub final_rows_read_back: usize,
    pub final_bytes_read_back: u64,
}

pub struct BoundedEagerCrossTermKindPlan {
    kind: EagerAgreementKind,
    xterm_snapshot_seq: u64,
    xterm_generation: u64,
    xterm_dump_hash: String,
    stream: EagerCrossTermStreamReport,
    desired: RunReceipt,
    chunk_receipts: Vec<RunReceipt>,
    workspace: RunWorkspace,
}

impl BoundedEagerCrossTermKindPlan {
    pub fn stream_report(&self) -> &EagerCrossTermStreamReport {
        &self.stream
    }
}

fn ensure_bounded_xterm_storage(
    status: &LatestOnlyReadbackStatus,
    phase: &str,
) -> calyx_core::Result<()> {
    let invalid_cf = status.memtable.per_cf.iter().find(|cf| {
        cf.cap_bytes != status.memtable_byte_cap
            || cf.used_bytes > cf.cap_bytes
            || cf.high_water_bytes > cf.cap_bytes
    });
    if !status.latest_only
        || status.overlay_keys != 0
        || status.overlay_versions != 0
        || status.overlay_bytes != 0
        || status.memtable_byte_cap == 0
        || invalid_cf.is_some()
    {
        return Err(CalyxError {
            code: ASTRO_XTERM_RUN_SOURCE_INVALID,
            message: format!(
                "{phase} requires latest-only storage, an empty MVCC overlay, and every active memtable inside one positive hard cap; observed latest_only={}, overlay_keys={}, overlay_versions={}, overlay_bytes={}, memtable_byte_cap={}, invalid_cf={invalid_cf:?}",
                status.latest_only,
                status.overlay_keys,
                status.overlay_versions,
                status.overlay_bytes,
                status.memtable_byte_cap,
            ),
            remediation: "preserve the staged generation and rebuild it through latest-only shadow import before planning or persisting an eager XTerm run",
        });
    }
    Ok(())
}

/// One designed-pair agreement edge recomputed from persisted XTerm CF rows
/// (the `get_architecture` agreement-graph aspect substrate).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PersistedAgreementEdge {
    /// Designed pair wire name (for example `DOC_DRIFT`).
    pub kind: String,
    /// Left designed slot.
    pub left_slot: u16,
    /// Right designed slot.
    pub right_slot: u16,
    /// Mean of the persisted scalar agreements, absent when no scalar row
    /// exists (never zero-filled).
    pub mean_agreement: Option<f32>,
    /// Number of persisted scalar rows contributing to the mean.
    pub scalar_count: usize,
    /// Provenance label for the aspect consumer.
    pub provenance: &'static str,
}

pub fn plan_eager_cross_term_kind_run<C, F>(
    vault: &AsterVault<C>,
    run_directory: impl Into<PathBuf>,
    source_binding: impl Into<String>,
    nodes: &[SimilarityNode],
    kind: EagerAgreementKind,
    cx_ids: &BTreeMap<String, CxId>,
    active_slot_count: usize,
    mut observe: F,
) -> calyx_core::Result<BoundedEagerCrossTermKindPlan>
where
    C: Clock,
    F: FnMut(&EagerCrossTermRow) -> calyx_core::Result<()>,
{
    plan_eager_cross_term_kind_run_owned(
        vault,
        run_directory,
        source_binding,
        nodes,
        kind,
        None,
        cx_ids,
        active_slot_count,
        &mut observe,
    )
}

pub fn plan_eager_cross_term_kind_run_delta<C, F>(
    vault: &AsterVault<C>,
    run_directory: impl Into<PathBuf>,
    source_binding: impl Into<String>,
    nodes: &[SimilarityNode],
    kind: EagerAgreementKind,
    symbol_ids: &BTreeSet<String>,
    cx_ids: &BTreeMap<String, CxId>,
    active_slot_count: usize,
    mut observe: F,
) -> calyx_core::Result<BoundedEagerCrossTermKindPlan>
where
    C: Clock,
    F: FnMut(&EagerCrossTermRow) -> calyx_core::Result<()>,
{
    plan_eager_cross_term_kind_run_owned(
        vault,
        run_directory,
        source_binding,
        nodes,
        kind,
        Some(symbol_ids),
        cx_ids,
        active_slot_count,
        &mut observe,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the source-generation, ownership, and observer bindings must remain explicit at the run boundary"
)]
fn plan_eager_cross_term_kind_run_owned<C, F>(
    vault: &AsterVault<C>,
    run_directory: impl Into<PathBuf>,
    source_binding: impl Into<String>,
    nodes: &[SimilarityNode],
    kind: EagerAgreementKind,
    symbol_ids: Option<&BTreeSet<String>>,
    cx_ids: &BTreeMap<String, CxId>,
    active_slot_count: usize,
    observe: &mut F,
) -> calyx_core::Result<BoundedEagerCrossTermKindPlan>
where
    C: Clock,
    F: FnMut(&EagerCrossTermRow) -> calyx_core::Result<()>,
{
    let xterm_snapshot_seq = vault.snapshot();
    let xterm_generation = vault.cf_content_generation(ColumnFamily::XTerm)?;
    let workspace = RunWorkspace::create(
        run_directory,
        format!("eager-xterm:{}", kind.wire_name()),
        format!(
            "{};xterm_snapshot_seq={xterm_snapshot_seq};xterm_generation={xterm_generation}",
            source_binding.into()
        ),
    )?;
    let mut chunks = Vec::new();
    let mut pending = Vec::<(Vec<u8>, Vec<u8>)>::new();
    let mut pending_bytes = 0usize;
    let mut dump_hasher = blake3::Hasher::new();
    let mut emit = |row: EagerCrossTermRow| -> calyx_core::Result<()> {
        observe(&row)?;
        let Some(&cx_id) = cx_ids.get(&row.symbol_id) else {
            return Err(CalyxError {
                code: ASTRO_XTERM_CX_ID_MISSING,
                message: format!(
                    "no CxId mapping for planned stable symbol {:?} ({:?})",
                    row.symbol_id, row.qualified_name
                ),
                remediation: "pass a cx_ids map covering every planned stable source-atom id",
            });
        };
        let CrossTermValue::Scalar(value) = &row.value else {
            return Ok(());
        };
        let value = *value;
        update_xterm_dump_hasher(&mut dump_hasher, &row, cx_id, value);
        let key = eager_xterm_key(cx_id, kind);
        let encoded = encode_xterm_row(cx_id, &row, value)?;
        let row_bytes = key
            .len()
            .checked_add(encoded.len())
            .ok_or_else(|| xterm_run_resource_exhausted("desired XTerm row byte overflow"))?;
        if row_bytes > MAX_MUTATION_BYTES_PER_COMMIT {
            return Err(xterm_run_resource_exhausted(format!(
                "one {} desired row retains {row_bytes} bytes, exceeding the run/commit limit {MAX_MUTATION_BYTES_PER_COMMIT}",
                kind.wire_name()
            )));
        }
        if !pending.is_empty()
            && (pending.len() == MAX_MUTATION_ROWS_PER_COMMIT
                || pending_bytes.saturating_add(row_bytes) > MAX_MUTATION_BYTES_PER_COMMIT)
        {
            chunks.push(flush_xterm_chunk(&workspace, chunks.len(), &mut pending)?);
            pending_bytes = 0;
        }
        pending_bytes = pending_bytes.saturating_add(row_bytes);
        pending.push((key, encoded));
        Ok(())
    };
    let stream = match symbol_ids {
        Some(symbol_ids) => stream_eager_cross_term_kind_for_symbols(
            nodes,
            kind,
            symbol_ids,
            active_slot_count,
            &mut emit,
        )?,
        None => stream_eager_cross_term_kind(nodes, kind, active_slot_count, &mut emit)?,
    };
    if !pending.is_empty() {
        chunks.push(flush_xterm_chunk(&workspace, chunks.len(), &mut pending)?);
    }
    let desired = merge_xterm_chunks(&workspace, &chunks)?;
    if desired.record_count != stream.abundance.scalar_count as u64 {
        return Err(xterm_corrupt(format!(
            "{} stream reported {} scalar rows but sealed {} desired rows",
            kind.wire_name(),
            stream.abundance.scalar_count,
            desired.record_count
        )));
    }
    Ok(BoundedEagerCrossTermKindPlan {
        kind,
        xterm_snapshot_seq,
        xterm_generation,
        xterm_dump_hash: dump_hasher.finalize().to_hex().to_string(),
        stream,
        desired,
        chunk_receipts: chunks,
        workspace,
    })
}

fn flush_xterm_chunk(
    workspace: &RunWorkspace,
    index: usize,
    pending: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> calyx_core::Result<RunReceipt> {
    pending.sort_by(|left, right| left.0.cmp(&right.0));
    if pending.windows(2).any(|rows| rows[0].0 == rows[1].0) {
        return Err(xterm_corrupt(format!(
            "desired XTerm chunk {index} contains a duplicate physical key"
        )));
    }
    let file_name = format!("desired-chunk-{index:06}.run");
    let path = workspace.directory().join(&file_name);
    let mut writer = workspace.writer(&file_name, MAX_MUTATION_BYTES_PER_COMMIT as u64)?;
    for (key, value) in pending.drain(..) {
        writer.push(&key, &value)?;
    }
    writer.finish(&path)
}

fn merge_xterm_chunks(
    workspace: &RunWorkspace,
    chunks: &[RunReceipt],
) -> calyx_core::Result<RunReceipt> {
    let final_path = workspace.directory().join("desired.run");
    let mut writer = workspace.writer("desired.run", MAX_MUTATION_BYTES_PER_COMMIT as u64)?;
    let mut readers = chunks
        .iter()
        .map(|receipt| {
            let mut reader = workspace.open_unsealed_reader(receipt)?;
            let head = reader.next_record()?;
            Ok((receipt.clone(), reader, head))
        })
        .collect::<calyx_core::Result<Vec<_>>>()?;
    let mut last_key = None::<Vec<u8>>;
    loop {
        let next_index = readers
            .iter()
            .enumerate()
            .filter_map(|(index, (_, _, head))| head.as_ref().map(|(key, _)| (index, key)))
            .min_by(|left, right| left.1.cmp(right.1))
            .map(|(index, _)| index);
        let Some(next_index) = next_index else {
            break;
        };
        let (key, value) = readers[next_index]
            .2
            .take()
            .expect("selected chunk head is present");
        if last_key.as_ref() == Some(&key) {
            return Err(xterm_corrupt(
                "desired XTerm chunks contain a duplicate physical key".to_string(),
            ));
        }
        writer.push(&key, &value)?;
        last_key = Some(key);
        readers[next_index].2 = readers[next_index].1.next_record()?;
    }
    for (receipt, reader, head) in readers {
        if head.is_some() || reader.finish()? != receipt {
            return Err(xterm_corrupt(
                "desired XTerm chunk merge did not consume an exact sealed receipt".to_string(),
            ));
        }
    }
    writer.finish(&final_path)
}

pub fn persist_eager_cross_term_kind_run<C>(
    vault: &AsterVault<C>,
    plan: BoundedEagerCrossTermKindPlan,
    actor: impl Into<String>,
) -> calyx_core::Result<EagerCrossTermPersistReport>
where
    C: Clock,
{
    persist_eager_cross_term_kind_run_owned(vault, plan, None, actor.into())
}

pub fn persist_eager_cross_term_kind_run_delta<C>(
    vault: &AsterVault<C>,
    plan: BoundedEagerCrossTermKindPlan,
    current_cx_ids: &BTreeMap<String, CxId>,
    removed_cx_ids: &BTreeSet<CxId>,
    actor: impl Into<String>,
) -> calyx_core::Result<EagerCrossTermPersistReport>
where
    C: Clock,
{
    persist_eager_cross_term_kind_run_owned(
        vault,
        plan,
        Some((current_cx_ids, removed_cx_ids)),
        actor.into(),
    )
}

fn persist_eager_cross_term_kind_run_owned<C>(
    vault: &AsterVault<C>,
    mut plan: BoundedEagerCrossTermKindPlan,
    ownership: Option<(&BTreeMap<String, CxId>, &BTreeSet<CxId>)>,
    actor: String,
) -> calyx_core::Result<EagerCrossTermPersistReport>
where
    C: Clock,
{
    ensure_xterm_source_unchanged(vault, &plan, "before existing-row scan")?;
    let existing_path = plan.workspace.directory().join("existing.run");
    let mut existing_writer = plan
        .workspace
        .writer("existing.run", MAX_MUTATION_BYTES_PER_COMMIT as u64)?;
    scan_owned_eager_xterm_rows(
        vault,
        plan.xterm_snapshot_seq,
        plan.kind,
        ownership,
        |key, value| existing_writer.push(key, value),
    )?;
    ensure_xterm_source_unchanged(vault, &plan, "after existing-row scan")?;
    let existing = existing_writer.finish(&existing_path)?;
    let mut manifest_runs = plan.chunk_receipts.clone();
    manifest_runs.push(plan.desired.clone());
    manifest_runs.push(existing.clone());
    plan.workspace.seal(manifest_runs)?;
    for receipt in &plan.chunk_receipts {
        plan.workspace.mark_consumed(receipt.clone())?;
    }
    verify_complete_xterm_run(&plan.workspace, &plan.desired)?;
    verify_complete_xterm_run(&plan.workspace, &existing)?;

    let mut desired_reader = plan.workspace.open_reader(&plan.desired)?;
    let mut existing_reader = plan.workspace.open_reader(&existing)?;
    let mut desired_row = desired_reader.next_record()?;
    let mut existing_row = existing_reader.next_record()?;
    let tombstone = tombstone_value();
    let mut batch = Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new();
    let mut batch_bytes = 0usize;
    let mut ledger_refs = Vec::new();
    let mut fsv = Vec::new();
    let mut rows_written = 0usize;
    let mut rows_unchanged = 0usize;
    let mut rows_tombstoned = 0usize;
    let mut batch_index = 0usize;
    let mut run = EagerCrossTermRunTelemetry {
        desired_rows: plan.desired.record_count,
        desired_bytes: plan.desired.content_bytes,
        existing_rows: existing.record_count,
        existing_bytes: existing.content_bytes,
        chunk_runs: plan.chunk_receipts.len(),
        ..EagerCrossTermRunTelemetry::default()
    };
    while desired_row.is_some() || existing_row.is_some() {
        let ordering = match (&desired_row, &existing_row) {
            (Some((desired_key, _)), Some((existing_key, _))) => desired_key.cmp(existing_key),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        let mutation = match ordering {
            Ordering::Less => {
                let (key, value) = desired_row.take().expect("desired row present");
                desired_row = desired_reader.next_record()?;
                rows_written = rows_written.saturating_add(1);
                Some((ColumnFamily::XTerm, key, value))
            }
            Ordering::Equal => {
                let (key, value) = desired_row.take().expect("desired row present");
                let (_, existing_value) = existing_row.take().expect("existing row present");
                desired_row = desired_reader.next_record()?;
                existing_row = existing_reader.next_record()?;
                if value == existing_value {
                    rows_unchanged = rows_unchanged.saturating_add(1);
                    None
                } else {
                    rows_written = rows_written.saturating_add(1);
                    Some((ColumnFamily::XTerm, key, value))
                }
            }
            Ordering::Greater => {
                let (key, _) = existing_row.take().expect("existing row present");
                existing_row = existing_reader.next_record()?;
                rows_tombstoned = rows_tombstoned.saturating_add(1);
                Some((ColumnFamily::XTerm, key, tombstone.clone()))
            }
        };
        if let Some(mutation) = mutation {
            let mutation_bytes = xterm_mutation_retained_bytes(&mutation)?;
            if mutation_bytes > MAX_MUTATION_BYTES_PER_COMMIT {
                return Err(xterm_run_resource_exhausted(format!(
                    "one {} mutation retains {mutation_bytes} bytes, exceeding the atomic group limit {MAX_MUTATION_BYTES_PER_COMMIT}",
                    plan.kind.wire_name()
                )));
            }
            if !batch.is_empty()
                && (batch.len() == MAX_MUTATION_ROWS_PER_COMMIT
                    || batch_bytes.saturating_add(mutation_bytes) > MAX_MUTATION_BYTES_PER_COMMIT)
            {
                let (ledger_ref, ack) = commit_eager_xterm_batch(
                    vault,
                    plan.kind,
                    &plan.xterm_dump_hash,
                    batch_index,
                    &actor,
                    std::mem::take(&mut batch),
                )?;
                ledger_refs.push(ledger_ref);
                fsv.push(ack);
                run.mutation_groups = run.mutation_groups.saturating_add(1);
                batch_index = batch_index.saturating_add(1);
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes.saturating_add(mutation_bytes);
            batch.push(mutation);
            run.mutation_rows_high_water = run.mutation_rows_high_water.max(batch.len());
            run.mutation_bytes_high_water = run.mutation_bytes_high_water.max(batch_bytes);
        }
    }
    let consumed_desired = desired_reader.finish()?;
    let consumed_existing = existing_reader.finish()?;
    plan.workspace.mark_consumed(consumed_desired)?;
    plan.workspace.mark_consumed(consumed_existing)?;
    if !batch.is_empty() {
        let (ledger_ref, ack) = commit_eager_xterm_batch(
            vault,
            plan.kind,
            &plan.xterm_dump_hash,
            batch_index,
            &actor,
            batch,
        )?;
        ledger_refs.push(ledger_ref);
        fsv.push(ack);
        run.mutation_groups = run.mutation_groups.saturating_add(1);
    }
    if ledger_refs.is_empty() {
        let payload = eager_xterm_audit_payload(
            plan.kind,
            plan.stream.abundance.scalar_count,
            &plan.xterm_dump_hash,
            None,
        )?;
        let subject = SubjectId::Query(
            format!("astrolabe-eager-xterm:{}:no-delta", plan.xterm_dump_hash).into_bytes(),
        );
        ledger_refs.push(vault.append_ledger_entry(
            EntryKind::Measure,
            subject,
            payload,
            ActorId::Service(actor),
        )?);
        vault.flush()?;
    }
    let (final_rows, final_bytes, final_hash) =
        read_back_owned_xterm_state(vault, plan.kind, ownership)?;
    run.final_rows_read_back = final_rows;
    run.final_bytes_read_back = final_bytes;
    if final_rows != plan.stream.abundance.scalar_count || final_hash != plan.desired.content_blake3
    {
        return Err(xterm_corrupt(format!(
            "{} final physical readback differs from the desired run: expected_rows={}, observed_rows={final_rows}, expected_hash={}, observed_hash={final_hash}",
            plan.kind.wire_name(),
            plan.stream.abundance.scalar_count,
            plan.desired.content_blake3
        )));
    }
    plan.workspace.cleanup()?;
    let absent_by_kind = BTreeMap::from([(plan.kind, plan.stream.abundance.absent_count)]);
    Ok(EagerCrossTermPersistReport {
        symbol_count: plan.stream.abundance.symbol_count,
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        absent_by_kind,
        xterm_dump_hash: plan.xterm_dump_hash,
        ledger_refs,
        fsv,
        run,
    })
}

fn verify_complete_xterm_run(
    workspace: &RunWorkspace,
    receipt: &RunReceipt,
) -> calyx_core::Result<()> {
    let mut reader = workspace.open_reader(receipt)?;
    while reader.next_record()?.is_some() {}
    if reader.finish()? != *receipt {
        return Err(xterm_corrupt(format!(
            "run {:?} receipt changed during pre-mutation verification",
            receipt.file_name
        )));
    }
    Ok(())
}

fn ensure_xterm_source_unchanged<C>(
    vault: &AsterVault<C>,
    plan: &BoundedEagerCrossTermKindPlan,
    phase: &str,
) -> calyx_core::Result<()>
where
    C: Clock,
{
    ensure_bounded_xterm_storage(&vault.latest_only_readback_status(), phase)?;
    let observed_snapshot = vault.snapshot();
    let observed_generation = vault.cf_content_generation(ColumnFamily::XTerm)?;
    if observed_snapshot != plan.xterm_snapshot_seq || observed_generation != plan.xterm_generation
    {
        return Err(xterm_corrupt(format!(
            "{} source changed at {phase}: expected_snapshot={}, observed_snapshot={observed_snapshot}, expected_xterm_generation={}, observed_xterm_generation={observed_generation}",
            plan.kind.wire_name(),
            plan.xterm_snapshot_seq,
            plan.xterm_generation
        )));
    }
    Ok(())
}

fn scan_owned_eager_xterm_rows<C, F>(
    vault: &AsterVault<C>,
    snapshot: u64,
    kind: EagerAgreementKind,
    ownership: Option<(&BTreeMap<String, CxId>, &BTreeSet<CxId>)>,
    mut emit: F,
) -> calyx_core::Result<()>
where
    C: Clock,
    F: FnMut(&[u8], &[u8]) -> calyx_core::Result<()>,
{
    match ownership {
        Some((current, removed)) => {
            let keys = current
                .values()
                .copied()
                .chain(removed.iter().copied())
                .map(|cx_id| eager_xterm_key(cx_id, kind))
                .collect::<BTreeSet<_>>();
            for key in keys {
                if let Some(value) = vault.read_cf_at(snapshot, ColumnFamily::XTerm, &key)? {
                    validate_designed_xterm_row(&key, &value, Some(kind))?;
                    emit(&key, &value)?;
                }
            }
        }
        None => {
            let accepted_cotenants = crate::accepted_xterm_cotenant_schemas();
            vault.scan_cf_range_pages_at(
                snapshot,
                ColumnFamily::XTerm,
                &prefix_range(&[]),
                XTERM_SCAN_PAGE_ROWS,
                |page| {
                    for (key, value) in page {
                        let row: XtermRow = match serde_json::from_slice(&value) {
                            Ok(row) => row,
                            Err(error) => {
                                if crate::is_accepted_xterm_cotenant(&value, &accepted_cotenants) {
                                    continue;
                                }
                                return Err(xterm_corrupt(format!(
                                    "decode XTerm row {} during bounded kind scan: {error}",
                                    hex_lower_bytes(&key)
                                )));
                            }
                        };
                        validate_xterm_key(&key, &row)?;
                        if row.key.kind == LoomCrossTermKind::Agreement
                            && designed_kind_for_slots(row.key.a, row.key.b) == Some(kind)
                        {
                            emit(&key, &value)?;
                        }
                    }
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

fn read_back_owned_xterm_state<C>(
    vault: &AsterVault<C>,
    kind: EagerAgreementKind,
    ownership: Option<(&BTreeMap<String, CxId>, &BTreeSet<CxId>)>,
) -> calyx_core::Result<(usize, u64, String)>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = 0usize;
    let mut bytes = 0u64;
    let mut hasher = run_content_hasher();
    scan_owned_eager_xterm_rows(vault, snapshot, kind, ownership, |key, value| {
        update_run_content_hash(&mut hasher, key, value);
        rows = rows
            .checked_add(1)
            .ok_or_else(|| xterm_run_resource_exhausted("final XTerm row count overflow"))?;
        bytes = bytes
            .checked_add(key.len() as u64)
            .and_then(|total| total.checked_add(value.len() as u64))
            .ok_or_else(|| xterm_run_resource_exhausted("final XTerm byte count overflow"))?;
        Ok(())
    })?;
    Ok((rows, bytes, hasher.finalize().to_hex().to_string()))
}

fn commit_eager_xterm_batch<C>(
    vault: &AsterVault<C>,
    kind: EagerAgreementKind,
    xterm_dump_hash: &str,
    batch_index: usize,
    actor: &str,
    batch: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
) -> calyx_core::Result<(LedgerRef, FsvAck)>
where
    C: Clock,
{
    let retained_bytes = xterm_mutation_batch_retained_bytes(&batch)?;
    if batch.is_empty()
        || batch.len() > MAX_MUTATION_ROWS_PER_COMMIT
        || retained_bytes > MAX_MUTATION_BYTES_PER_COMMIT
    {
        return Err(xterm_run_resource_exhausted(format!(
            "{} mutation group {batch_index} violates the bounded commit contract: rows={}, bytes={retained_bytes}",
            kind.wire_name(),
            batch.len()
        )));
    }
    let mutation_hash = xterm_mutation_batch_hash(&batch);
    let payload = eager_xterm_audit_payload(
        kind,
        0,
        xterm_dump_hash,
        Some((batch_index, batch.len(), &mutation_hash)),
    )?;
    let subject = SubjectId::Query(
        format!("astrolabe-eager-xterm:{xterm_dump_hash}:batch:{batch_index}:{mutation_hash}")
            .into_bytes(),
    );
    let actor = ActorId::Service(actor.to_string());
    let commit = vault.write_cf_batch_with_ledger_entry_with_row_digests(
        batch,
        EntryKind::Measure,
        subject.clone(),
        payload,
        actor.clone(),
    )?;
    let mut fsv_plan = VaultMutationPlan::new(
        "persist_eager_cross_terms_bounded",
        EntryKind::Measure,
        &actor,
        &subject,
    );
    for row in commit.data_row_digests {
        if row.tombstoned {
            fsv_plan.push_tombstoned_hash(row.cf, row.key, row.value_blake3);
        } else {
            fsv_plan.push_content_hash(row.cf, row.key, row.value_blake3);
        }
    }
    vault.flush()?;
    let ack = fsv_plan.verify_committed_with_ledger_ref(vault, commit.seq, &commit.ledger_ref)?;
    Ok((commit.ledger_ref, ack))
}

fn eager_xterm_audit_payload(
    kind: EagerAgreementKind,
    scalar_count: usize,
    xterm_dump_hash: &str,
    batch: Option<(usize, usize, &str)>,
) -> calyx_core::Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "schema": XTERM_EAGER_LEDGER_SCHEMA,
        "kind": kind.wire_name(),
        "scalar_count": scalar_count,
        "xterm_dump_hash": xterm_dump_hash,
        "batch": batch.map(|(index, rows, mutation_hash)| serde_json::json!({
            "index": index,
            "rows": rows,
            "mutation_hash": mutation_hash,
        })),
    }))
    .map_err(|error| xterm_corrupt(format!("encode eager xterm ledger payload: {error}")))
}

fn xterm_mutation_retained_bytes(
    mutation: &(ColumnFamily, Vec<u8>, Vec<u8>),
) -> calyx_core::Result<usize> {
    mutation
        .0
        .name()
        .len()
        .checked_add(mutation.1.len())
        .and_then(|total| total.checked_add(mutation.2.len()))
        .ok_or_else(|| xterm_run_resource_exhausted("XTerm mutation byte overflow"))
}

fn xterm_mutation_batch_retained_bytes(
    batch: &[(ColumnFamily, Vec<u8>, Vec<u8>)],
) -> calyx_core::Result<usize> {
    batch.iter().try_fold(0usize, |total, mutation| {
        total
            .checked_add(xterm_mutation_retained_bytes(mutation)?)
            .ok_or_else(|| xterm_run_resource_exhausted("XTerm mutation-group byte overflow"))
    })
}

fn xterm_mutation_batch_hash(batch: &[(ColumnFamily, Vec<u8>, Vec<u8>)]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrolabe.eager-xterm.mutation-batch.v1");
    for (cf, key, value) in batch {
        update_xterm_hash_part(&mut hasher, cf.name().as_bytes());
        update_xterm_hash_part(&mut hasher, key);
        update_xterm_hash_part(&mut hasher, value);
    }
    hasher.finalize().to_hex().to_string()
}

fn update_xterm_hash_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn update_xterm_dump_hasher(
    hasher: &mut blake3::Hasher,
    row: &EagerCrossTermRow,
    cx_id: CxId,
    value: f32,
) {
    let line = format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{:08x}\n",
        row.kind.wire_name(),
        row.symbol_id,
        row.qualified_name,
        cx_id,
        row.left_slot.get(),
        row.right_slot.get(),
        value.to_bits(),
    );
    hasher.update(line.as_bytes());
}

fn validate_designed_xterm_row(
    key: &[u8],
    value: &[u8],
    expected_kind: Option<EagerAgreementKind>,
) -> calyx_core::Result<XtermRow> {
    let row: XtermRow = serde_json::from_slice(value).map_err(|error| {
        xterm_corrupt(format!(
            "decode designed XTerm row {}: {error}",
            hex_lower_bytes(key)
        ))
    })?;
    validate_xterm_key(key, &row)?;
    if row.key.kind != LoomCrossTermKind::Agreement
        || expected_kind
            .is_some_and(|kind| designed_kind_for_slots(row.key.a, row.key.b) != Some(kind))
    {
        return Err(xterm_corrupt(format!(
            "XTerm row {} does not belong to the expected designed agreement kind",
            hex_lower_bytes(key)
        )));
    }
    Ok(row)
}

fn validate_xterm_key(key: &[u8], row: &XtermRow) -> calyx_core::Result<()> {
    let expected_key = xterm_key(
        row.key.cx_id,
        row.key.a,
        row.key.b,
        xterm_kind_wire(row.key.kind),
    );
    if key != expected_key {
        return Err(xterm_corrupt(format!(
            "XTerm row key {} does not match its decoded fields",
            hex_lower_bytes(key)
        )));
    }
    Ok(())
}

fn xterm_run_resource_exhausted(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "ASTRO_XTERM_RUN_RESOURCE_EXHAUSTED",
        message: message.into(),
        remediation: "preserve the unpublished shadow generation and inspect the exact row/group byte measurement; do not raise the bound, drop a row, or substitute an absent value",
    }
}

/// Physical receipt for one bounded, generation-stable XTerm CF scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EagerCrossTermPhysicalScan {
    /// Vault sequence held for the complete scan.
    pub snapshot_seq: u64,
    /// XTerm-CF generation proved unchanged across the scan.
    pub xterm_generation: u64,
    /// Number of bounded page callbacks.
    pub pages: usize,
    /// Largest number of rows retained by one page callback.
    pub page_rows_high_water: usize,
    /// Largest encoded key/value byte total retained by one page callback.
    pub page_bytes_high_water: u64,
    /// Total rows decoded or classified in the shared XTerm CF.
    pub rows_scanned: usize,
    /// Total encoded key/value bytes scanned in the shared XTerm CF.
    pub bytes_scanned: u64,
    /// Designed scalar agreement rows delivered to the caller.
    pub designed_rows: usize,
    /// Accepted non-XTerm co-tenant rows classified and skipped.
    pub cotenant_rows_skipped: usize,
}

/// Streams every key-verified designed scalar agreement from one stable
/// physical XTerm generation. Accepted co-tenant rows are counted and skipped;
/// malformed, non-scalar, or drifting designed state refuses.
pub fn stream_eager_cross_term_rows<C, F>(
    vault: &AsterVault<C>,
    mut emit: F,
) -> calyx_core::Result<EagerCrossTermPhysicalScan>
where
    C: Clock,
    F: FnMut(EagerAgreementKind, CxId, f32) -> calyx_core::Result<()>,
{
    let storage_before = vault.latest_only_readback_status();
    ensure_bounded_xterm_storage(&storage_before, "global XTerm pre-scan")?;
    let snapshot = vault.snapshot();
    let xterm_generation = vault.cf_content_generation(ColumnFamily::XTerm)?;
    let accepted_cotenants = crate::accepted_xterm_cotenant_schemas();
    let mut receipt = EagerCrossTermPhysicalScan {
        snapshot_seq: snapshot,
        xterm_generation,
        pages: 0,
        page_rows_high_water: 0,
        page_bytes_high_water: 0,
        rows_scanned: 0,
        bytes_scanned: 0,
        designed_rows: 0,
        cotenant_rows_skipped: 0,
    };
    vault.scan_cf_range_pages_at(
        snapshot,
        ColumnFamily::XTerm,
        &prefix_range(&[]),
        XTERM_SCAN_PAGE_ROWS,
        |page| {
            receipt.pages = receipt
                .pages
                .checked_add(1)
                .ok_or_else(|| xterm_run_resource_exhausted("XTerm scan page count overflow"))?;
            receipt.page_rows_high_water = receipt.page_rows_high_water.max(page.len());
            let page_bytes = page.iter().try_fold(0u64, |total, (key, value)| {
                total
                    .checked_add(key.len() as u64)
                    .and_then(|total| total.checked_add(value.len() as u64))
                    .ok_or_else(|| xterm_run_resource_exhausted("XTerm scan byte overflow"))
            })?;
            receipt.page_bytes_high_water = receipt.page_bytes_high_water.max(page_bytes);
            receipt.bytes_scanned = receipt
                .bytes_scanned
                .checked_add(page_bytes)
                .ok_or_else(|| xterm_run_resource_exhausted("XTerm scan byte overflow"))?;
            receipt.rows_scanned = receipt
                .rows_scanned
                .checked_add(page.len())
                .ok_or_else(|| xterm_run_resource_exhausted("XTerm scan row overflow"))?;
            for (key, value) in page {
                let row: XtermRow = match serde_json::from_slice(&value) {
                    Ok(row) => row,
                    Err(error) => {
                        if crate::is_accepted_xterm_cotenant(&value, &accepted_cotenants) {
                            receipt.cotenant_rows_skipped = receipt
                                .cotenant_rows_skipped
                                .checked_add(1)
                                .ok_or_else(|| {
                                    xterm_run_resource_exhausted(
                                        "XTerm co-tenant row count overflow",
                                    )
                                })?;
                            continue;
                        }
                        return Err(xterm_corrupt(format!(
                            "decode XTerm row {}: {error}",
                            hex_lower_bytes(&key)
                        )));
                    }
                };
                validate_xterm_key(&key, &row)?;
                if row.key.kind != LoomCrossTermKind::Agreement {
                    continue;
                }
                let Some(kind) = designed_kind_for_slots(row.key.a, row.key.b) else {
                    continue;
                };
                let LoomCrossTermValue::Scalar(value) = row.value else {
                    return Err(xterm_corrupt(format!(
                        "designed agreement row {} contains a vector instead of one scalar",
                        hex_lower_bytes(&key)
                    )));
                };
                receipt.designed_rows = receipt.designed_rows.checked_add(1).ok_or_else(|| {
                    xterm_run_resource_exhausted("designed XTerm row count overflow")
                })?;
                emit(kind, row.key.cx_id, value)?;
            }
            Ok(())
        },
    )?;
    let storage_after = vault.latest_only_readback_status();
    ensure_bounded_xterm_storage(&storage_after, "global XTerm post-scan")?;
    let observed_generation = vault.cf_content_generation(ColumnFamily::XTerm)?;
    if storage_after != storage_before
        || observed_generation != xterm_generation
        || vault.snapshot() != snapshot
    {
        return Err(CalyxError {
            code: ASTRO_XTERM_RUN_SOURCE_INVALID,
            message: format!(
                "XTerm source changed during physical scan: expected_snapshot={snapshot}, observed_snapshot={}, expected_generation={xterm_generation}, observed_generation={observed_generation}, storage_before={storage_before:?}, storage_after={storage_after:?}",
                vault.snapshot(),
            ),
            remediation: "preserve the staged generation, identify the unexpected writer, and repeat the scan only from one stable XTerm generation",
        });
    }
    Ok(receipt)
}

/// Recomputes the designed-pair agreement graph from persisted XTerm CF rows.
///
/// This is the substrate for the `get_architecture` agreement-graph aspect:
/// per designed pair, the mean of the persisted scalar agreements and the
/// contributing row count, labeled with its persisted-state provenance. Pairs
/// without any persisted scalar report `mean_agreement: None` — never zero.
pub fn agreement_graph_from_persisted_rows<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<PersistedAgreementEdge>>
where
    C: Clock,
{
    Ok(agreement_graph_from_persisted_rows_with_cotenants(vault)?.0)
}

/// [`agreement_graph_from_persisted_rows`] returning the count of shared-CF
/// co-tenant rows skipped (layout `placement_truth` rows, #369) alongside the
/// edges — surfaced by [`agreement_graph_aspect`] as a labeled, counted skip.
pub fn agreement_graph_from_persisted_rows_with_cotenants<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<(Vec<PersistedAgreementEdge>, usize)>
where
    C: Clock,
{
    let mut sums = BTreeMap::<EagerAgreementKind, (f64, usize)>::new();
    let scan = stream_eager_cross_term_rows(vault, |kind, _, value| {
        let entry = sums.entry(kind).or_default();
        entry.0 += f64::from(value);
        entry.1 += 1;
        Ok(())
    })?;
    let edges = EagerAgreementKind::ALL
        .into_iter()
        .map(|kind| {
            let (sum, scalar_count) = sums.get(&kind).copied().unwrap_or_default();
            let (left_slot, right_slot) = kind.slots();
            PersistedAgreementEdge {
                kind: kind.wire_name().to_string(),
                left_slot: left_slot.get(),
                right_slot: right_slot.get(),
                mean_agreement: (scalar_count > 0).then(|| (sum / scalar_count as f64) as f32),
                scalar_count,
                provenance: AGREEMENT_GRAPH_ASPECT_PROVENANCE,
            }
        })
        .collect();
    Ok((edges, scan.cotenant_rows_skipped))
}

/// The `get_architecture` agreement-graph aspect payload.
///
/// Wraps the six designed-pair agreement edges recomputed from persisted XTerm
/// CF rows with the HONEST grounding labels every grounded response owes its
/// consumer: `provenance` (where the bytes physically live), `freshness`
/// (recomputed from persisted state at call time), and `trust` (verified,
/// because the underlying read fails closed on any corrupt or key-mismatched
/// row — a successful build means every edge came from verified persisted
/// bytes, never a planner echo). Deterministic: edges are emitted in the fixed
/// [`EagerAgreementKind::ALL`] order and each mean is the seed-independent
/// arithmetic mean of the contributing persisted scalars.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgreementGraphAspect {
    /// Stable payload schema.
    pub schema: &'static str,
    /// `empty` when no designed pair holds a persisted scalar, else `built`.
    pub status: &'static str,
    /// Count of designed edges (always the six designed pairs; never
    /// zero-filled and never fewer — an absent pair is a `None` mean, not a
    /// dropped edge).
    pub edge_count: usize,
    /// Edges with at least one persisted scalar contributing to the mean.
    pub populated_edge_count: usize,
    /// Total persisted scalar rows across all designed pairs.
    pub scalar_row_count: usize,
    /// Count of shared `ColumnFamily::XTerm` co-tenant rows (layout
    /// `placement_truth` rows, #369) skipped while reading the designed rows — a
    /// counted, labeled skip, not an error.
    pub cotenant_rows_skipped: usize,
    /// The six designed-pair edges (mean nullable, never zero-filled).
    pub edges: Vec<PersistedAgreementEdge>,
    /// Provenance label: the physical source of these bytes.
    pub provenance: &'static str,
    /// Freshness label: recomputed from persisted state at call time.
    pub freshness: &'static str,
    /// Trust label: verified — every edge is read back from persisted bytes and
    /// the read fails closed on corruption.
    pub trust: &'static str,
}

/// Builds the `get_architecture` agreement-graph aspect from persisted XTerm CF
/// rows.
///
/// Fails closed (propagating [`ASTRO_XTERM_ROW_CORRUPT`]) when any persisted
/// row is undecodable or its key does not match its decoded fields — the aspect
/// never emits a partial or silently-degraded graph. On success the payload
/// carries HONEST grounding labels bound to the persisted-state read.
pub fn agreement_graph_aspect<C>(vault: &AsterVault<C>) -> calyx_core::Result<AgreementGraphAspect>
where
    C: Clock,
{
    let (edges, cotenant_rows_skipped) = agreement_graph_from_persisted_rows_with_cotenants(vault)?;
    let populated_edge_count = edges.iter().filter(|edge| edge.scalar_count > 0).count();
    let scalar_row_count = edges.iter().map(|edge| edge.scalar_count).sum();
    let status = if scalar_row_count == 0 {
        "empty"
    } else {
        "built"
    };
    Ok(AgreementGraphAspect {
        schema: AGREEMENT_GRAPH_ASPECT_SCHEMA,
        status,
        edge_count: edges.len(),
        populated_edge_count,
        scalar_row_count,
        cotenant_rows_skipped,
        edges,
        provenance: AGREEMENT_GRAPH_ASPECT_PROVENANCE,
        freshness: "fresh",
        trust: "verified",
    })
}

/// Builds the canonical XTerm CF key for one designed pair of one symbol.
pub fn eager_xterm_key(cx_id: CxId, kind: EagerAgreementKind) -> Vec<u8> {
    let (left, right) = kind.slots();
    xterm_key(cx_id, left, right, XTermKind::Agreement)
}

/// Maps a persisted slot pair back to its designed agreement kind (order
/// sensitive: rows are written in designed `(left, right)` order).
pub fn designed_kind_for_slots(a: SlotId, b: SlotId) -> Option<EagerAgreementKind> {
    EagerAgreementKind::ALL
        .into_iter()
        .find(|kind| kind.slots() == (a, b))
}

fn encode_xterm_row(
    cx_id: CxId,
    row: &EagerCrossTermRow,
    value: f32,
) -> calyx_core::Result<Vec<u8>> {
    let xterm_row = XtermRow {
        key: CrossTermKey {
            cx_id,
            a: row.left_slot,
            b: row.right_slot,
            kind: LoomCrossTermKind::Agreement,
        },
        value: LoomCrossTermValue::Scalar(value),
        tag: SignalProvenanceTag::Derived,
    };
    serde_json::to_vec(&xterm_row)
        .map_err(|error| xterm_corrupt(format!("encode eager xterm row: {error}")))
}

fn xterm_kind_wire(kind: LoomCrossTermKind) -> XTermKind {
    match kind {
        LoomCrossTermKind::Concat => XTermKind::Concat,
        LoomCrossTermKind::Interaction => XTermKind::Interaction,
        LoomCrossTermKind::Agreement => XTermKind::Agreement,
        LoomCrossTermKind::Delta => XTermKind::Delta,
    }
}

fn xterm_corrupt(message: String) -> CalyxError {
    CalyxError {
        code: ASTRO_XTERM_ROW_CORRUPT,
        message,
        remediation: XTERM_REMEDIATION,
    }
}
