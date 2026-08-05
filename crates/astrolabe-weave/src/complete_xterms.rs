//! Exhaustive, persisted base associations for every applicable slot pair.
//!
//! The source of truth is the persisted Base row plus the exact Slot-CF bytes it
//! hashes. `NotApplicable` slots are outside the roster; every other stored slot
//! is applicable and every unordered pair receives exactly one XTerm witness:
//! an exact scalar association or an explicit typed incompatibility. Per-record
//! Kv witnesses bind the source slot hashes, applicable roster, expected key
//! stream, and exact XTerm value stream. Reconciliation validates existing bytes
//! before using their source hash to skip unchanged records.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, prefix_range};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode::{BaseRecord, decode_slot_vector};
use calyx_core::{
    AbsentReason, CalyxError, Clock, CxId, LedgerRef, SlotId, SlotVector, SparseEntry, VaultStore,
};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde::{Deserialize, Serialize};

use crate::sim_rows::ledger_ref_at_commit;
use crate::{XTERM_COMPLETE_PAIR_COTENANT_SCHEMA, hex_lower_bytes};

pub const COMPLETE_PAIR_ROW_SCHEMA: &str = XTERM_COMPLETE_PAIR_COTENANT_SCHEMA;
pub const COMPLETE_WITNESS_SCHEMA: &str = "astrolabe.complete_pair_witness.v1";
pub const COMPLETE_ASSOCIATION_LEDGER_SCHEMA: &str = "astrolabe.complete_association_commit.v1";
pub const COMPLETE_PAIR_ROW_PREFIX: &[u8] = b"astrolabe:complete-xterm:v1\0";
pub const COMPLETE_WITNESS_PREFIX: &[u8] = b"astrolabe:complete-xterm-witness:v1\0";
pub const ASTRO_XTERM_SOURCE_CORRUPT: &str = "ASTRO_XTERM_SOURCE_CORRUPT";
pub const ASTRO_XTERM_COMPLETION_CORRUPT: &str = "ASTRO_XTERM_COMPLETION_CORRUPT";
pub const ASTRO_XTERM_COMPLETION_OVERFLOW: &str = "ASTRO_XTERM_COMPLETION_OVERFLOW";

const MAX_MUTATION_ROWS_PER_COMMIT: usize = 50_000;

fn source_corrupt(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_XTERM_SOURCE_CORRUPT,
        message: message.into(),
        remediation: "re-index the repository from real source bytes and verify every Base slot hash against its Slot-CF row before mining associations",
    }
}

fn completion_corrupt(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_XTERM_COMPLETION_CORRUPT,
        message: message.into(),
        remediation: "re-run exhaustive association reconciliation from the verified Base/Slot source of truth; do not reuse or partially repair completion rows",
    }
}

fn completion_overflow(context: &str) -> CalyxError {
    CalyxError {
        code: ASTRO_XTERM_COMPLETION_OVERFLOW,
        message: format!("association count overflow while calculating {context}"),
        remediation: "partition the vault into smaller project-scoped stores without sampling or dropping any constellation or pair",
    }
}

#[derive(Debug, Clone)]
enum PreparedSlot {
    Dense {
        dim: u32,
        data: Vec<f32>,
        norm: f64,
    },
    Sparse {
        dim: u32,
        entries: Vec<SparseEntry>,
        norm: f64,
    },
    Multi {
        token_dim: u32,
        tokens: Vec<Vec<f32>>,
        norms: Vec<f64>,
    },
    Absent {
        reason: AbsentReason,
    },
}

impl PreparedSlot {
    fn shape_name(&self) -> String {
        match self {
            Self::Dense { dim, .. } => format!("dense:{dim}"),
            Self::Sparse { dim, .. } => format!("sparse:{dim}"),
            Self::Multi { token_dim, .. } => format!("multi:{token_dim}"),
            Self::Absent { reason } => format!("absent:{}", absent_reason_wire(reason)),
        }
    }
}

#[derive(Debug, Clone)]
struct AssociationConstellation {
    cx_id: CxId,
    panel_version: u32,
    source_hash: String,
    source_slot_count: usize,
    not_applicable_slot_count: usize,
    slots: BTreeMap<SlotId, PreparedSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CompletePairOutcome {
    Computed {
        metric: String,
        value_bits: u32,
    },
    TypedIncompatible {
        code: String,
        left_shape: String,
        right_shape: String,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompletePairRow {
    schema: String,
    cx_id: String,
    left_slot: u16,
    right_slot: u16,
    outcome: CompletePairOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompletionWitness {
    schema: String,
    cx_id: String,
    panel_version: u32,
    association_source_hash: String,
    source_slot_count: usize,
    not_applicable_slot_count: usize,
    applicable_slot_ids: Vec<u16>,
    expected_pair_count: usize,
    computed_pair_count: usize,
    typed_incompatible_pair_count: usize,
    metric_counts: BTreeMap<String, usize>,
    typed_reason_counts: BTreeMap<String, usize>,
    pair_key_stream_hash: String,
    pair_value_stream_hash: String,
}

#[derive(Debug, Clone)]
struct PlannedConstellation {
    cx_id: CxId,
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    witness_key: Vec<u8>,
    witness_bytes: Vec<u8>,
    witness: CompletionWitness,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairMetricCounts {
    pub cosine: usize,
    pub symmetric_mean_maxsim_cosine: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairReasonCounts {
    pub absent_slot: usize,
    pub shape_mismatch: usize,
    pub zero_norm: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteAssociationState {
    pub constellation_count: usize,
    pub source_slot_count: usize,
    pub not_applicable_slot_count: usize,
    pub applicable_slot_count: usize,
    pub expected_pair_count: usize,
    pub computed_pair_count: usize,
    pub typed_incompatible_pair_count: usize,
    pub completion_row_count: usize,
    pub panel_version_counts: BTreeMap<u32, usize>,
    pub metric_counts: PairMetricCounts,
    pub typed_reason_counts: PairReasonCounts,
    pub witness_state_hash: String,
    pub pair_key_stream_hash: String,
    pub pair_value_stream_hash: String,
}

#[derive(Debug, Clone)]
pub struct CompleteAssociationPersistReport {
    pub constellations_total: usize,
    pub constellations_recomputed: usize,
    pub constellations_unchanged: usize,
    pub constellations_removed: usize,
    pub rows_written: usize,
    pub rows_unchanged: usize,
    pub rows_tombstoned: usize,
    pub witnesses_written: usize,
    pub witnesses_tombstoned: usize,
    pub commit_count: usize,
    pub ledger_ref: Option<LedgerRef>,
    pub fsv: Vec<FsvAck>,
    pub state: CompleteAssociationState,
}

#[derive(Debug)]
struct PersistedState {
    public: CompleteAssociationState,
    witnesses: BTreeMap<CxId, (Vec<u8>, CompletionWitness)>,
    rows: BTreeMap<CxId, BTreeMap<Vec<u8>, Vec<u8>>>,
}

pub fn read_complete_association_state<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<CompleteAssociationState>
where
    C: Clock,
{
    Ok(read_persisted_state_at(vault, vault.snapshot())?.public)
}

pub fn reconcile_complete_associations<C>(
    vault: &AsterVault<C>,
    actor: impl Into<String>,
) -> calyx_core::Result<CompleteAssociationPersistReport>
where
    C: Clock,
{
    let actor = actor.into();
    let snapshot = vault.snapshot();
    let persisted = read_persisted_state_at(vault, snapshot)?;
    let records = load_constellations_at(vault, snapshot)?;
    let current_ids = records
        .iter()
        .map(|record| record.cx_id)
        .collect::<BTreeSet<_>>();

    let mut changed = Vec::new();
    let mut constellations_unchanged = 0usize;
    let mut rows_unchanged = 0usize;
    for record in records {
        match persisted.witnesses.get(&record.cx_id) {
            Some((_, witness)) if witness.association_source_hash == record.source_hash => {
                constellations_unchanged =
                    checked_add(constellations_unchanged, 1, "unchanged constellations")?;
                rows_unchanged = checked_add(
                    rows_unchanged,
                    witness.expected_pair_count,
                    "unchanged pair rows",
                )?;
            }
            _ => changed.push(record),
        }
    }
    let removed = persisted
        .witnesses
        .keys()
        .filter(|cx_id| !current_ids.contains(cx_id))
        .copied()
        .collect::<Vec<_>>();

    let mut pending = Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new();
    let mut pending_record_ids = Vec::<String>::new();
    let mut rows_written = 0usize;
    let mut rows_tombstoned = 0usize;
    let mut witnesses_written = 0usize;
    let mut witnesses_tombstoned = 0usize;
    let mut ledger_ref = None;
    let mut fsv = Vec::new();
    let mut commit_count = 0usize;
    let tombstone = tombstone_value();

    for record in &changed {
        let planned = plan_constellation(record)?;
        let existing_rows = persisted.rows.get(&record.cx_id);
        let mut record_mutations = Vec::new();
        for (key, value) in &planned.rows {
            if existing_rows.and_then(|rows| rows.get(key)) == Some(value) {
                rows_unchanged = checked_add(rows_unchanged, 1, "unchanged pair rows")?;
            } else {
                record_mutations.push((ColumnFamily::XTerm, key.clone(), value.clone()));
                rows_written = checked_add(rows_written, 1, "written pair rows")?;
            }
        }
        if let Some(existing_rows) = existing_rows {
            for key in existing_rows.keys() {
                if !planned.rows.contains_key(key) {
                    record_mutations.push((ColumnFamily::XTerm, key.clone(), tombstone.clone()));
                    rows_tombstoned = checked_add(rows_tombstoned, 1, "tombstoned pair rows")?;
                }
            }
        }
        let witness_unchanged = persisted
            .witnesses
            .get(&record.cx_id)
            .is_some_and(|(bytes, _)| *bytes == planned.witness_bytes);
        if !witness_unchanged {
            record_mutations.push((
                ColumnFamily::Kv,
                planned.witness_key.clone(),
                planned.witness_bytes.clone(),
            ));
            witnesses_written = checked_add(witnesses_written, 1, "written witnesses")?;
        }
        if !pending.is_empty()
            && pending.len().saturating_add(record_mutations.len()) > MAX_MUTATION_ROWS_PER_COMMIT
        {
            let (entry_ref, ack) = commit_mutations(vault, &actor, &pending_record_ids, &pending)?;
            ledger_ref = Some(entry_ref);
            fsv.push(ack);
            commit_count = checked_add(commit_count, 1, "association commits")?;
            pending.clear();
            pending_record_ids.clear();
        }
        if !record_mutations.is_empty() {
            pending.extend(record_mutations);
            pending_record_ids.push(planned.witness.cx_id);
        }
    }

    for cx_id in &removed {
        let mut record_mutations = Vec::new();
        if let Some(rows) = persisted.rows.get(cx_id) {
            for key in rows.keys() {
                record_mutations.push((ColumnFamily::XTerm, key.clone(), tombstone.clone()));
                rows_tombstoned = checked_add(rows_tombstoned, 1, "tombstoned removed pair rows")?;
            }
        }
        record_mutations.push((ColumnFamily::Kv, witness_key(*cx_id), tombstone.clone()));
        witnesses_tombstoned = checked_add(witnesses_tombstoned, 1, "tombstoned witnesses")?;
        if !pending.is_empty()
            && pending.len().saturating_add(record_mutations.len()) > MAX_MUTATION_ROWS_PER_COMMIT
        {
            let (entry_ref, ack) = commit_mutations(vault, &actor, &pending_record_ids, &pending)?;
            ledger_ref = Some(entry_ref);
            fsv.push(ack);
            commit_count = checked_add(commit_count, 1, "association commits")?;
            pending.clear();
            pending_record_ids.clear();
        }
        pending.extend(record_mutations);
        pending_record_ids.push(cx_hex(*cx_id));
    }
    if !pending.is_empty() {
        let (entry_ref, ack) = commit_mutations(vault, &actor, &pending_record_ids, &pending)?;
        ledger_ref = Some(entry_ref);
        fsv.push(ack);
        commit_count = checked_add(commit_count, 1, "association commits")?;
    }

    let final_state = read_persisted_state_at(vault, vault.snapshot())?;
    if final_state.witnesses.len() != current_ids.len()
        || final_state
            .witnesses
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != current_ids
    {
        return Err(completion_corrupt(
            "post-commit completion witness CxId set does not equal the live Base CxId set",
        ));
    }
    let current_sources = load_source_hashes_at(vault, vault.snapshot())?;
    for (cx_id, (_, witness)) in &final_state.witnesses {
        let Some(source_hash) = current_sources.get(cx_id) else {
            return Err(completion_corrupt(format!(
                "post-commit witness {} has no live Base source",
                cx_hex(*cx_id)
            )));
        };
        if witness.association_source_hash != *source_hash {
            return Err(completion_corrupt(format!(
                "post-commit witness {} source hash does not match persisted Base/Slot identity",
                cx_hex(*cx_id)
            )));
        }
    }

    Ok(CompleteAssociationPersistReport {
        constellations_total: current_ids.len(),
        constellations_recomputed: changed.len(),
        constellations_unchanged,
        constellations_removed: removed.len(),
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        witnesses_written,
        witnesses_tombstoned,
        commit_count,
        ledger_ref,
        fsv,
        state: final_state.public,
    })
}

fn commit_mutations<C>(
    vault: &AsterVault<C>,
    actor: &str,
    record_ids: &[String],
    mutations: &[(ColumnFamily, Vec<u8>, Vec<u8>)],
) -> calyx_core::Result<(LedgerRef, FsvAck)>
where
    C: Clock,
{
    let mut mutation_bytes = Vec::new();
    for (cf, key, value) in mutations {
        append_part(&mut mutation_bytes, cf.name().as_bytes());
        append_part(&mut mutation_bytes, key);
        append_part(&mut mutation_bytes, value);
    }
    let mutation_hash = hex_lower_bytes(blake3::hash(&mutation_bytes).as_bytes());
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": COMPLETE_ASSOCIATION_LEDGER_SCHEMA,
        "record_ids": record_ids,
        "mutation_count": mutations.len(),
        "mutation_hash": mutation_hash,
    }))
    .map_err(|error| completion_corrupt(format!("encode association ledger payload: {error}")))?;
    let subject =
        SubjectId::Query(format!("astrolabe-complete-associations:{mutation_hash}").into_bytes());
    let actor = ActorId::Service(actor.to_string());
    let mut fsv_plan = VaultMutationPlan::new(
        "reconcile_complete_associations",
        EntryKind::Measure,
        &actor,
        &subject,
    );
    let tombstone = tombstone_value();
    for (cf, key, value) in mutations {
        if *value == tombstone {
            fsv_plan.push_tombstoned(*cf, key.clone(), &tombstone);
        } else {
            fsv_plan.push_content(*cf, key.clone(), value);
        }
    }
    let seq = vault.write_cf_batch_with_ledger_entry(
        mutations.to_vec(),
        EntryKind::Measure,
        subject,
        payload,
        actor,
    )?;
    vault.flush()?;
    let ack = fsv_plan.verify_committed(vault, seq)?;
    Ok((ledger_ref_at_commit(vault, seq)?, ack))
}

fn load_constellations_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
) -> calyx_core::Result<Vec<AssociationConstellation>>
where
    C: Clock,
{
    struct SourceBase {
        cx_id: CxId,
        panel_version: u32,
        slot_hashes: BTreeMap<SlotId, [u8; 32]>,
    }

    let mut bases = Vec::new();
    let mut all_slots = BTreeSet::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Base)? {
        let cx_id = cx_from_exact_key(&key, "Base")?;
        let base = BaseRecord::decode_for_key(cx_id, &bytes)?;
        let panel_version = base.constellation().panel_version;
        let roster = astrolabe_panel::slots_for_version(panel_version).map_err(|error| {
            source_corrupt(format!(
                "Base {} names unknown panel version {panel_version}: {error}",
                cx_hex(cx_id)
            ))
        })?;
        let roster_ids = roster
            .iter()
            .map(|slot| slot.slot_id())
            .collect::<BTreeSet<_>>();
        for slot in base.slot_hashes().keys() {
            if !roster_ids.contains(slot) {
                return Err(source_corrupt(format!(
                    "Base {} carries S{} outside persisted panel version {panel_version}",
                    cx_hex(cx_id),
                    slot.get()
                )));
            }
            all_slots.insert(*slot);
        }
        bases.push(SourceBase {
            cx_id,
            panel_version,
            slot_hashes: base.slot_hashes().clone(),
        });
    }
    bases.sort_by_key(|base| base.cx_id);

    let mut slot_rows = BTreeMap::<SlotId, BTreeMap<Vec<u8>, Vec<u8>>>::new();
    for slot in all_slots {
        slot_rows.insert(
            slot,
            vault
                .scan_cf_at(snapshot, ColumnFamily::slot(slot))?
                .into_iter()
                .collect(),
        );
    }

    let mut records = Vec::with_capacity(bases.len());
    for base in bases {
        let mut source_bytes = Vec::new();
        append_part(&mut source_bytes, b"astrolabe.association_source.v1");
        append_part(&mut source_bytes, &base.panel_version.to_be_bytes());
        append_part(
            &mut source_bytes,
            &(base.slot_hashes.len() as u64).to_be_bytes(),
        );
        let mut slots = BTreeMap::new();
        let mut not_applicable_slot_count = 0usize;
        for (slot, expected_hash) in &base.slot_hashes {
            append_part(&mut source_bytes, &slot.get().to_be_bytes());
            append_part(&mut source_bytes, expected_hash);
            let key = base.cx_id.as_bytes().as_slice();
            let bytes = slot_rows
                .get(slot)
                .and_then(|rows| rows.get(key))
                .ok_or_else(|| {
                    source_corrupt(format!(
                        "Base {} hashes S{} but its Slot-CF row is absent at snapshot {snapshot}",
                        cx_hex(base.cx_id),
                        slot.get()
                    ))
                })?;
            let observed_hash = blake3::hash(bytes);
            if observed_hash.as_bytes() != expected_hash {
                return Err(source_corrupt(format!(
                    "Base {} S{} hash mismatch: expected={} observed={}",
                    cx_hex(base.cx_id),
                    slot.get(),
                    hex_lower_bytes(expected_hash),
                    hex_lower_bytes(observed_hash.as_bytes())
                )));
            }
            let vector = decode_slot_vector(bytes)?;
            if matches!(
                vector,
                SlotVector::Absent {
                    reason: AbsentReason::NotApplicable
                }
            ) {
                not_applicable_slot_count =
                    checked_add(not_applicable_slot_count, 1, "NotApplicable slot count")?;
                continue;
            }
            slots.insert(*slot, prepare_slot(*slot, vector)?);
        }
        records.push(AssociationConstellation {
            cx_id: base.cx_id,
            panel_version: base.panel_version,
            source_hash: hex_lower_bytes(blake3::hash(&source_bytes).as_bytes()),
            source_slot_count: base.slot_hashes.len(),
            not_applicable_slot_count,
            slots,
        });
    }
    Ok(records)
}

fn load_source_hashes_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
) -> calyx_core::Result<BTreeMap<CxId, String>>
where
    C: Clock,
{
    Ok(load_constellations_at(vault, snapshot)?
        .into_iter()
        .map(|record| (record.cx_id, record.source_hash))
        .collect())
}

fn prepare_slot(slot: SlotId, vector: SlotVector) -> calyx_core::Result<PreparedSlot> {
    vector.validate_schema().map_err(|error| {
        source_corrupt(format!(
            "persisted S{} vector schema is invalid: {error}",
            slot.get()
        ))
    })?;
    Ok(match vector {
        SlotVector::Dense { dim, data } => PreparedSlot::Dense {
            dim,
            norm: vector_norm(&data),
            data,
        },
        SlotVector::Sparse { dim, mut entries } => {
            entries.sort_by_key(|entry| entry.idx);
            let norm = entries
                .iter()
                .map(|entry| f64::from(entry.val) * f64::from(entry.val))
                .sum::<f64>()
                .sqrt();
            PreparedSlot::Sparse { dim, entries, norm }
        }
        SlotVector::Multi { token_dim, tokens } => {
            let norms = tokens.iter().map(|token| vector_norm(token)).collect();
            PreparedSlot::Multi {
                token_dim,
                tokens,
                norms,
            }
        }
        SlotVector::Absent { reason } => PreparedSlot::Absent { reason },
    })
}

fn plan_constellation(
    record: &AssociationConstellation,
) -> calyx_core::Result<PlannedConstellation> {
    let ids = record.slots.keys().copied().collect::<Vec<_>>();
    let expected_pair_count = choose_two(ids.len())?;
    let mut rows = BTreeMap::new();
    let mut computed_pair_count = 0usize;
    let mut typed_incompatible_pair_count = 0usize;
    let mut metric_counts = BTreeMap::<String, usize>::new();
    let mut typed_reason_counts = BTreeMap::<String, usize>::new();
    for left_index in 0..ids.len() {
        for right_index in (left_index + 1)..ids.len() {
            let left = ids[left_index];
            let right = ids[right_index];
            let outcome = pair_outcome(&record.slots[&left], &record.slots[&right])?;
            match &outcome {
                CompletePairOutcome::Computed { metric, .. } => {
                    computed_pair_count = checked_add(computed_pair_count, 1, "computed pairs")?;
                    *metric_counts.entry(metric.clone()).or_default() += 1;
                }
                CompletePairOutcome::TypedIncompatible { code, .. } => {
                    typed_incompatible_pair_count =
                        checked_add(typed_incompatible_pair_count, 1, "typed-incompatible pairs")?;
                    *typed_reason_counts.entry(code.clone()).or_default() += 1;
                }
            }
            let key = pair_row_key(record.cx_id, left, right);
            let row = CompletePairRow {
                schema: COMPLETE_PAIR_ROW_SCHEMA.to_string(),
                cx_id: cx_hex(record.cx_id),
                left_slot: left.get(),
                right_slot: right.get(),
                outcome,
            };
            let value = serde_json::to_vec(&row).map_err(|error| {
                completion_corrupt(format!("encode complete pair row: {error}"))
            })?;
            if rows.insert(key, value).is_some() {
                return Err(completion_corrupt(format!(
                    "planner generated a duplicate pair for Base {} S{}-S{}",
                    cx_hex(record.cx_id),
                    left.get(),
                    right.get()
                )));
            }
        }
    }
    if checked_add(
        computed_pair_count,
        typed_incompatible_pair_count,
        "completion equation",
    )? != expected_pair_count
    {
        return Err(completion_corrupt(format!(
            "planner completion equation failed for Base {}",
            cx_hex(record.cx_id)
        )));
    }
    let (pair_key_stream_hash, pair_value_stream_hash) = row_stream_hashes(&rows);
    let witness = CompletionWitness {
        schema: COMPLETE_WITNESS_SCHEMA.to_string(),
        cx_id: cx_hex(record.cx_id),
        panel_version: record.panel_version,
        association_source_hash: record.source_hash.clone(),
        source_slot_count: record.source_slot_count,
        not_applicable_slot_count: record.not_applicable_slot_count,
        applicable_slot_ids: ids.iter().map(|slot| slot.get()).collect(),
        expected_pair_count,
        computed_pair_count,
        typed_incompatible_pair_count,
        metric_counts,
        typed_reason_counts,
        pair_key_stream_hash,
        pair_value_stream_hash,
    };
    let witness_bytes = serde_json::to_vec(&witness)
        .map_err(|error| completion_corrupt(format!("encode completion witness: {error}")))?;
    Ok(PlannedConstellation {
        cx_id: record.cx_id,
        rows,
        witness_key: witness_key(record.cx_id),
        witness_bytes,
        witness,
    })
}

fn pair_outcome(
    left: &PreparedSlot,
    right: &PreparedSlot,
) -> calyx_core::Result<CompletePairOutcome> {
    if let PreparedSlot::Absent { reason } = left {
        return Ok(incompatible(
            "absent_slot",
            left,
            right,
            format!(
                "left slot is explicitly absent: {}",
                absent_reason_wire(reason)
            ),
        ));
    }
    if let PreparedSlot::Absent { reason } = right {
        return Ok(incompatible(
            "absent_slot",
            left,
            right,
            format!(
                "right slot is explicitly absent: {}",
                absent_reason_wire(reason)
            ),
        ));
    }
    if has_zero_norm(left) || has_zero_norm(right) {
        return Ok(incompatible(
            "zero_norm",
            left,
            right,
            "cosine is undefined because at least one vector or multi-vector token has zero L2 norm".to_string(),
        ));
    }
    let computed = match (left, right) {
        (
            PreparedSlot::Dense {
                dim: left_dim,
                data: left_data,
                norm: left_norm,
            },
            PreparedSlot::Dense {
                dim: right_dim,
                data: right_data,
                norm: right_norm,
            },
        ) if left_dim == right_dim => (
            "cosine",
            dense_dot(left_data, right_data) / (left_norm * right_norm),
        ),
        (
            PreparedSlot::Sparse {
                dim: left_dim,
                entries: left_entries,
                norm: left_norm,
            },
            PreparedSlot::Sparse {
                dim: right_dim,
                entries: right_entries,
                norm: right_norm,
            },
        ) if left_dim == right_dim => (
            "cosine",
            sparse_dot(left_entries, right_entries) / (left_norm * right_norm),
        ),
        (
            PreparedSlot::Dense {
                dim: left_dim,
                data,
                norm: left_norm,
            },
            PreparedSlot::Sparse {
                dim: right_dim,
                entries,
                norm: right_norm,
            },
        ) if left_dim == right_dim => (
            "cosine",
            dense_sparse_dot(data, entries) / (left_norm * right_norm),
        ),
        (
            PreparedSlot::Sparse {
                dim: left_dim,
                entries,
                norm: left_norm,
            },
            PreparedSlot::Dense {
                dim: right_dim,
                data,
                norm: right_norm,
            },
        ) if left_dim == right_dim => (
            "cosine",
            dense_sparse_dot(data, entries) / (left_norm * right_norm),
        ),
        (
            PreparedSlot::Multi {
                token_dim: left_dim,
                tokens: left_tokens,
                norms: left_norms,
            },
            PreparedSlot::Multi {
                token_dim: right_dim,
                tokens: right_tokens,
                norms: right_norms,
            },
        ) if left_dim == right_dim => (
            "symmetric_mean_maxsim_cosine",
            symmetric_mean_maxsim(left_tokens, left_norms, right_tokens, right_norms),
        ),
        _ => {
            return Ok(incompatible(
                "shape_mismatch",
                left,
                right,
                "no exact agreement contract exists for these vector shapes or dimensions"
                    .to_string(),
            ));
        }
    };
    let value = computed.1.clamp(-1.0, 1.0) as f32;
    if !value.is_finite() {
        return Err(source_corrupt(format!(
            "{} produced a non-finite association",
            computed.0
        )));
    }
    Ok(CompletePairOutcome::Computed {
        metric: computed.0.to_string(),
        value_bits: value.to_bits(),
    })
}

fn incompatible(
    code: &str,
    left: &PreparedSlot,
    right: &PreparedSlot,
    detail: String,
) -> CompletePairOutcome {
    CompletePairOutcome::TypedIncompatible {
        code: code.to_string(),
        left_shape: left.shape_name(),
        right_shape: right.shape_name(),
        detail,
    }
}

fn has_zero_norm(slot: &PreparedSlot) -> bool {
    match slot {
        PreparedSlot::Dense { norm, .. } | PreparedSlot::Sparse { norm, .. } => *norm == 0.0,
        PreparedSlot::Multi { norms, .. } => norms.iter().any(|norm| *norm == 0.0),
        PreparedSlot::Absent { .. } => false,
    }
}

fn vector_norm(values: &[f32]) -> f64 {
    values
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt()
}

fn dense_dot(left: &[f32], right: &[f32]) -> f64 {
    left.iter()
        .zip(right)
        .map(|(left, right)| f64::from(*left) * f64::from(*right))
        .sum()
}

fn dense_sparse_dot(dense: &[f32], sparse: &[SparseEntry]) -> f64 {
    sparse
        .iter()
        .map(|entry| f64::from(dense[entry.idx as usize]) * f64::from(entry.val))
        .sum()
}

fn sparse_dot(left: &[SparseEntry], right: &[SparseEntry]) -> f64 {
    let mut left_index = 0usize;
    let mut right_index = 0usize;
    let mut sum = 0.0f64;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].idx.cmp(&right[right_index].idx) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => {
                sum += f64::from(left[left_index].val) * f64::from(right[right_index].val);
                left_index += 1;
                right_index += 1;
            }
        }
    }
    sum
}

fn symmetric_mean_maxsim(
    left_tokens: &[Vec<f32>],
    left_norms: &[f64],
    right_tokens: &[Vec<f32>],
    right_norms: &[f64],
) -> f64 {
    fn directional(
        queries: &[Vec<f32>],
        query_norms: &[f64],
        docs: &[Vec<f32>],
        doc_norms: &[f64],
    ) -> f64 {
        queries
            .iter()
            .zip(query_norms)
            .map(|(query, query_norm)| {
                docs.iter()
                    .zip(doc_norms)
                    .map(|(doc, doc_norm)| dense_dot(query, doc) / (query_norm * doc_norm))
                    .fold(f64::NEG_INFINITY, f64::max)
            })
            .sum::<f64>()
            / queries.len() as f64
    }
    (directional(left_tokens, left_norms, right_tokens, right_norms)
        + directional(right_tokens, right_norms, left_tokens, left_norms))
        / 2.0
}

fn read_persisted_state_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
) -> calyx_core::Result<PersistedState>
where
    C: Clock,
{
    let mut witnesses = BTreeMap::<CxId, (Vec<u8>, CompletionWitness)>::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Kv,
        &prefix_range(COMPLETE_WITNESS_PREFIX),
    )? {
        let cx_id = parse_witness_key(&key)?;
        let witness: CompletionWitness = serde_json::from_slice(&value).map_err(|error| {
            completion_corrupt(format!("decode witness {}: {error}", hex_lower_bytes(&key)))
        })?;
        validate_witness_identity(cx_id, &witness)?;
        if witnesses.insert(cx_id, (value, witness)).is_some() {
            return Err(completion_corrupt(format!(
                "duplicate completion witness for {}",
                cx_hex(cx_id)
            )));
        }
    }

    let mut rows = BTreeMap::<CxId, BTreeMap<Vec<u8>, Vec<u8>>>::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::XTerm,
        &prefix_range(COMPLETE_PAIR_ROW_PREFIX),
    )? {
        let (cx_id, left, right) = parse_pair_row_key(&key)?;
        let row: CompletePairRow = serde_json::from_slice(&value).map_err(|error| {
            completion_corrupt(format!(
                "decode pair row {}: {error}",
                hex_lower_bytes(&key)
            ))
        })?;
        validate_pair_row(cx_id, left, right, &row)?;
        if rows.entry(cx_id).or_default().insert(key, value).is_some() {
            return Err(completion_corrupt(format!(
                "duplicate complete pair row for {} S{}-S{}",
                cx_hex(cx_id),
                left.get(),
                right.get()
            )));
        }
    }
    for cx_id in rows.keys() {
        if !witnesses.contains_key(cx_id) {
            return Err(completion_corrupt(format!(
                "complete pair rows for {} have no atomic completion witness",
                cx_hex(*cx_id)
            )));
        }
    }

    let mut public = CompleteAssociationState {
        constellation_count: witnesses.len(),
        source_slot_count: 0,
        not_applicable_slot_count: 0,
        applicable_slot_count: 0,
        expected_pair_count: 0,
        computed_pair_count: 0,
        typed_incompatible_pair_count: 0,
        completion_row_count: 0,
        panel_version_counts: BTreeMap::new(),
        metric_counts: PairMetricCounts::default(),
        typed_reason_counts: PairReasonCounts::default(),
        witness_state_hash: String::new(),
        pair_key_stream_hash: String::new(),
        pair_value_stream_hash: String::new(),
    };
    let mut witness_stream = Vec::new();
    let mut global_key_stream = Vec::new();
    let mut global_value_stream = Vec::new();
    for (cx_id, (witness_bytes, witness)) in &witnesses {
        let actual_rows = rows.get(cx_id).cloned().unwrap_or_default();
        validate_witness_rows(*cx_id, witness, &actual_rows)?;
        public.source_slot_count = checked_add(
            public.source_slot_count,
            witness.source_slot_count,
            "source slots",
        )?;
        public.not_applicable_slot_count = checked_add(
            public.not_applicable_slot_count,
            witness.not_applicable_slot_count,
            "NotApplicable slots",
        )?;
        public.applicable_slot_count = checked_add(
            public.applicable_slot_count,
            witness.applicable_slot_ids.len(),
            "applicable slots",
        )?;
        public.expected_pair_count = checked_add(
            public.expected_pair_count,
            witness.expected_pair_count,
            "expected pairs",
        )?;
        public.computed_pair_count = checked_add(
            public.computed_pair_count,
            witness.computed_pair_count,
            "computed pairs",
        )?;
        public.typed_incompatible_pair_count = checked_add(
            public.typed_incompatible_pair_count,
            witness.typed_incompatible_pair_count,
            "typed-incompatible pairs",
        )?;
        public.completion_row_count = checked_add(
            public.completion_row_count,
            actual_rows.len(),
            "completion rows",
        )?;
        *public
            .panel_version_counts
            .entry(witness.panel_version)
            .or_default() += 1;
        public.metric_counts.cosine += witness.metric_counts.get("cosine").copied().unwrap_or(0);
        public.metric_counts.symmetric_mean_maxsim_cosine += witness
            .metric_counts
            .get("symmetric_mean_maxsim_cosine")
            .copied()
            .unwrap_or(0);
        public.typed_reason_counts.absent_slot += witness
            .typed_reason_counts
            .get("absent_slot")
            .copied()
            .unwrap_or(0);
        public.typed_reason_counts.shape_mismatch += witness
            .typed_reason_counts
            .get("shape_mismatch")
            .copied()
            .unwrap_or(0);
        public.typed_reason_counts.zero_norm += witness
            .typed_reason_counts
            .get("zero_norm")
            .copied()
            .unwrap_or(0);
        append_part(&mut witness_stream, &witness_key(*cx_id));
        append_part(&mut witness_stream, witness_bytes);
        for (key, value) in actual_rows {
            append_part(&mut global_key_stream, &key);
            append_part(&mut global_value_stream, &key);
            append_part(&mut global_value_stream, &value);
        }
    }
    if checked_add(
        public.computed_pair_count,
        public.typed_incompatible_pair_count,
        "global completion equation",
    )? != public.expected_pair_count
        || public.completion_row_count != public.expected_pair_count
    {
        return Err(completion_corrupt(
            "global completion equation failed after persisted-state readback",
        ));
    }
    public.witness_state_hash = hex_lower_bytes(blake3::hash(&witness_stream).as_bytes());
    public.pair_key_stream_hash = hex_lower_bytes(blake3::hash(&global_key_stream).as_bytes());
    public.pair_value_stream_hash = hex_lower_bytes(blake3::hash(&global_value_stream).as_bytes());
    Ok(PersistedState {
        public,
        witnesses,
        rows,
    })
}

fn validate_witness_identity(cx_id: CxId, witness: &CompletionWitness) -> calyx_core::Result<()> {
    if witness.schema != COMPLETE_WITNESS_SCHEMA || witness.cx_id != cx_hex(cx_id) {
        return Err(completion_corrupt(format!(
            "completion witness key/identity mismatch for {}",
            cx_hex(cx_id)
        )));
    }
    if witness.association_source_hash.len() != 64 {
        return Err(completion_corrupt(format!(
            "completion witness {} carries a malformed association source hash",
            cx_hex(cx_id)
        )));
    }
    if witness
        .applicable_slot_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(completion_corrupt(format!(
            "completion witness {} applicable slot ids are not strictly increasing",
            cx_hex(cx_id)
        )));
    }
    if witness.source_slot_count
        != checked_add(
            witness.applicable_slot_ids.len(),
            witness.not_applicable_slot_count,
            "witness source slot equation",
        )?
    {
        return Err(completion_corrupt(format!(
            "completion witness {} source_slot_count does not equal applicable + NotApplicable",
            cx_hex(cx_id)
        )));
    }
    let expected = choose_two(witness.applicable_slot_ids.len())?;
    if witness.expected_pair_count != expected
        || checked_add(
            witness.computed_pair_count,
            witness.typed_incompatible_pair_count,
            "witness completion equation",
        )? != expected
    {
        return Err(completion_corrupt(format!(
            "completion witness {} does not prove computed + typed_incompatible = C(N_applicable,2)",
            cx_hex(cx_id)
        )));
    }
    Ok(())
}

fn validate_witness_rows(
    cx_id: CxId,
    witness: &CompletionWitness,
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> calyx_core::Result<()> {
    if rows.len() != witness.expected_pair_count {
        return Err(completion_corrupt(format!(
            "completion witness {} expects {} rows but XTerm contains {}",
            cx_hex(cx_id),
            witness.expected_pair_count,
            rows.len()
        )));
    }
    let ids = witness
        .applicable_slot_ids
        .iter()
        .map(|slot| SlotId::new(*slot))
        .collect::<Vec<_>>();
    let mut expected_keys = BTreeSet::new();
    for left_index in 0..ids.len() {
        for right_index in (left_index + 1)..ids.len() {
            expected_keys.insert(pair_row_key(cx_id, ids[left_index], ids[right_index]));
        }
    }
    if rows.keys().cloned().collect::<BTreeSet<_>>() != expected_keys {
        return Err(completion_corrupt(format!(
            "completion witness {} exact pair key set differs from C(applicable slots,2)",
            cx_hex(cx_id)
        )));
    }
    let mut computed = 0usize;
    let mut incompatible = 0usize;
    for value in rows.values() {
        let row: CompletePairRow = serde_json::from_slice(value)
            .map_err(|error| completion_corrupt(format!("decode witnessed pair row: {error}")))?;
        match row.outcome {
            CompletePairOutcome::Computed { value_bits, .. } => {
                if !f32::from_bits(value_bits).is_finite() {
                    return Err(completion_corrupt(format!(
                        "completion witness {} contains non-finite computed bits",
                        cx_hex(cx_id)
                    )));
                }
                computed += 1;
            }
            CompletePairOutcome::TypedIncompatible { .. } => incompatible += 1,
        }
    }
    let (key_hash, value_hash) = row_stream_hashes(rows);
    if computed != witness.computed_pair_count
        || incompatible != witness.typed_incompatible_pair_count
        || key_hash != witness.pair_key_stream_hash
        || value_hash != witness.pair_value_stream_hash
    {
        return Err(completion_corrupt(format!(
            "completion witness {} counts or stream hashes differ from raw XTerm bytes",
            cx_hex(cx_id)
        )));
    }
    Ok(())
}

fn validate_pair_row(
    cx_id: CxId,
    left: SlotId,
    right: SlotId,
    row: &CompletePairRow,
) -> calyx_core::Result<()> {
    if row.schema != COMPLETE_PAIR_ROW_SCHEMA
        || row.cx_id != cx_hex(cx_id)
        || row.left_slot != left.get()
        || row.right_slot != right.get()
    {
        return Err(completion_corrupt(format!(
            "complete pair row key/fields mismatch for {} S{}-S{}",
            cx_hex(cx_id),
            left.get(),
            right.get()
        )));
    }
    if let CompletePairOutcome::Computed { value_bits, .. } = row.outcome
        && !f32::from_bits(value_bits).is_finite()
    {
        return Err(completion_corrupt(format!(
            "complete pair row {} S{}-S{} contains a non-finite scalar",
            cx_hex(cx_id),
            left.get(),
            right.get()
        )));
    }
    Ok(())
}

fn row_stream_hashes(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> (String, String) {
    let mut key_stream = Vec::new();
    let mut value_stream = Vec::new();
    for (key, value) in rows {
        append_part(&mut key_stream, key);
        append_part(&mut value_stream, key);
        append_part(&mut value_stream, value);
    }
    (
        hex_lower_bytes(blake3::hash(&key_stream).as_bytes()),
        hex_lower_bytes(blake3::hash(&value_stream).as_bytes()),
    )
}

fn pair_row_key(cx_id: CxId, left: SlotId, right: SlotId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMPLETE_PAIR_ROW_PREFIX.len() + 20);
    key.extend_from_slice(COMPLETE_PAIR_ROW_PREFIX);
    key.extend_from_slice(cx_id.as_bytes());
    key.extend_from_slice(&left.get().to_be_bytes());
    key.extend_from_slice(&right.get().to_be_bytes());
    key
}

fn parse_pair_row_key(key: &[u8]) -> calyx_core::Result<(CxId, SlotId, SlotId)> {
    let expected_len = COMPLETE_PAIR_ROW_PREFIX.len() + 20;
    if key.len() != expected_len || !key.starts_with(COMPLETE_PAIR_ROW_PREFIX) {
        return Err(completion_corrupt(format!(
            "malformed complete pair key {}",
            hex_lower_bytes(key)
        )));
    }
    let offset = COMPLETE_PAIR_ROW_PREFIX.len();
    let mut cx_bytes = [0u8; 16];
    cx_bytes.copy_from_slice(&key[offset..offset + 16]);
    let left = SlotId::new(u16::from_be_bytes([key[offset + 16], key[offset + 17]]));
    let right = SlotId::new(u16::from_be_bytes([key[offset + 18], key[offset + 19]]));
    if left >= right {
        return Err(completion_corrupt(format!(
            "complete pair key is not canonical: S{}-S{}",
            left.get(),
            right.get()
        )));
    }
    Ok((CxId::from_bytes(cx_bytes), left, right))
}

fn witness_key(cx_id: CxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMPLETE_WITNESS_PREFIX.len() + 16);
    key.extend_from_slice(COMPLETE_WITNESS_PREFIX);
    key.extend_from_slice(cx_id.as_bytes());
    key
}

fn parse_witness_key(key: &[u8]) -> calyx_core::Result<CxId> {
    if key.len() != COMPLETE_WITNESS_PREFIX.len() + 16 || !key.starts_with(COMPLETE_WITNESS_PREFIX)
    {
        return Err(completion_corrupt(format!(
            "malformed completion witness key {}",
            hex_lower_bytes(key)
        )));
    }
    let mut cx_bytes = [0u8; 16];
    cx_bytes.copy_from_slice(&key[COMPLETE_WITNESS_PREFIX.len()..]);
    Ok(CxId::from_bytes(cx_bytes))
}

fn cx_from_exact_key(key: &[u8], family: &str) -> calyx_core::Result<CxId> {
    if key.len() != 16 {
        return Err(source_corrupt(format!(
            "{family} row key must be exactly 16 CxId bytes, observed {}",
            key.len()
        )));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(key);
    Ok(CxId::from_bytes(bytes))
}

fn cx_hex(cx_id: CxId) -> String {
    hex_lower_bytes(cx_id.as_bytes())
}

fn absent_reason_wire(reason: &AbsentReason) -> String {
    match reason {
        AbsentReason::NotApplicable => "not_applicable".to_string(),
        AbsentReason::Redacted => "redacted".to_string(),
        AbsentReason::LensUnavailable => "lens_unavailable".to_string(),
        AbsentReason::Deferred => "deferred".to_string(),
        AbsentReason::LensInactive => "lens_inactive".to_string(),
        AbsentReason::Error(message) => format!("error:{message}"),
    }
}

fn append_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_be_bytes());
    out.extend_from_slice(part);
}

fn choose_two(count: usize) -> calyx_core::Result<usize> {
    if count < 2 {
        return Ok(0);
    }
    count
        .checked_mul(count - 1)
        .and_then(|value| value.checked_div(2))
        .ok_or_else(|| completion_overflow("C(N_applicable,2)"))
}

fn checked_add(left: usize, right: usize, context: &str) -> calyx_core::Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| completion_overflow(context))
}
