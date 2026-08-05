//! Exhaustive, persisted base associations for every applicable slot pair.
//!
//! The source of truth is the persisted Base row plus the exact Slot-CF bytes it
//! hashes. `NotApplicable` slots are outside the roster; every other stored slot
//! is applicable and every unordered pair receives exactly one logical outcome:
//! an exact scalar association or an explicit typed incompatibility. Outcomes
//! are stored in one compact binary XTerm block per constellation; SlotIds stay
//! separate and deterministically reconstruct every virtual pair. Per-record Kv
//! witnesses bind the source slot hashes, applicable roster, block bytes, virtual
//! key stream, and exact outcome stream. Reconciliation validates existing bytes
//! before using their source hash to skip unchanged records.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, prefix_range};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::encode::{BaseRecord, decode_slot_vector};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{
    AbsentReason, CalyxError, Clock, CxId, LedgerRef, SlotId, SlotVector, SparseEntry, VaultId,
    VaultStore,
};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::hex_lower_bytes;
use crate::sim_rows::ledger_ref_at_commit;
use crate::xterm_cotenant::{
    XTERM_COMPLETE_PAIR_BLOCK_COTENANT_SCHEMA, XTERM_COMPLETE_PAIR_BLOCK_MAGIC,
    XTERM_COMPLETE_PAIR_COTENANT_SCHEMA,
};

const LEGACY_COMPLETE_PAIR_ROW_SCHEMA: &str = XTERM_COMPLETE_PAIR_COTENANT_SCHEMA;
const LEGACY_COMPLETE_WITNESS_SCHEMA: &str = "astrolabe.complete_pair_witness.v1";
const LEGACY_COMPLETE_PAIR_ROW_PREFIX: &[u8] = b"astrolabe:complete-xterm:v1\0";
const LEGACY_COMPLETE_WITNESS_PREFIX: &[u8] = b"astrolabe:complete-xterm-witness:v1\0";

pub const COMPLETE_PAIR_BLOCK_SCHEMA: &str = XTERM_COMPLETE_PAIR_BLOCK_COTENANT_SCHEMA;
pub const COMPLETE_WITNESS_SCHEMA: &str = "astrolabe.complete_pair_witness.v2";
pub const COMPLETE_ASSOCIATION_LEDGER_SCHEMA: &str = "astrolabe.complete_association_commit.v2";
pub const COMPLETE_PAIR_BLOCK_PREFIX: &[u8] = b"astrolabe:complete-xterm-block:v2\0";
pub const COMPLETE_WITNESS_PREFIX: &[u8] = b"astrolabe:complete-xterm-witness:v2\0";
/// Binary schema discriminator understood by every full-XTerm co-tenant scan.
pub const COMPLETE_PAIR_BLOCK_MAGIC: &[u8; 8] = XTERM_COMPLETE_PAIR_BLOCK_MAGIC;
pub const ASTRO_XTERM_SOURCE_CORRUPT: &str = "ASTRO_XTERM_SOURCE_CORRUPT";
pub const ASTRO_XTERM_COMPLETION_CORRUPT: &str = "ASTRO_XTERM_COMPLETION_CORRUPT";
pub const ASTRO_XTERM_COMPLETION_OVERFLOW: &str = "ASTRO_XTERM_COMPLETION_OVERFLOW";

const MAX_MUTATION_ROWS_PER_COMMIT: usize = 50_000;
/// Bound planned records retained at once. The Rayon global pool work-steals
/// within each batch; indexed parallel iteration preserves CxId input order.
const PLANNING_RECORD_BATCH: usize = 8;

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum SlotDescriptor {
    Dense { dim: u32, zero_norm: bool },
    Sparse { dim: u32, zero_norm: bool },
    Multi { token_dim: u32, zero_norm: bool },
    Absent { reason: AbsentReason },
}

impl SlotDescriptor {
    fn absent_reason(&self) -> Option<&AbsentReason> {
        match self {
            Self::Absent { reason } => Some(reason),
            _ => None,
        }
    }

    fn zero_norm(&self) -> bool {
        match self {
            Self::Dense { zero_norm, .. }
            | Self::Sparse { zero_norm, .. }
            | Self::Multi { zero_norm, .. } => *zero_norm,
            Self::Absent { .. } => false,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairMetric {
    Cosine,
    SymmetricMeanMaxsimCosine,
}

impl PairMetric {
    fn code(self) -> u8 {
        match self {
            Self::Cosine => 1,
            Self::SymmetricMeanMaxsimCosine => 2,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Cosine => "cosine",
            Self::SymmetricMeanMaxsimCosine => "symmetric_mean_maxsim_cosine",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairReason {
    AbsentSlot,
    ShapeMismatch,
    ZeroNorm,
}

impl PairReason {
    fn code(self) -> u8 {
        match self {
            Self::AbsentSlot => 3,
            Self::ShapeMismatch => 4,
            Self::ZeroNorm => 5,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::AbsentSlot => "absent_slot",
            Self::ShapeMismatch => "shape_mismatch",
            Self::ZeroNorm => "zero_norm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CompletePairOutcome {
    Computed { metric: PairMetric, value_bits: u32 },
    TypedIncompatible { reason: PairReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyCompletePairRow {
    schema: String,
    cx_id: String,
    left_slot: u16,
    right_slot: u16,
    outcome: LegacyCompletePairOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum LegacyCompletePairOutcome {
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
struct LegacyCompletionWitness {
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
    absent_slot_reason_counts: BTreeMap<String, usize>,
    slot_descriptor_hash: String,
    pair_block_byte_count: usize,
    pair_block_hash: String,
    pair_key_stream_hash: String,
    pair_value_stream_hash: String,
}

#[derive(Debug, Clone)]
struct PlannedConstellation {
    cx_id: CxId,
    block_key: Vec<u8>,
    block_bytes: Vec<u8>,
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
    /// Logical pair outcomes reconstructed from the persisted blocks.
    pub completion_row_count: usize,
    /// Physical XTerm blocks. Exactly one exists per completion witness.
    pub physical_block_count: usize,
    pub panel_version_counts: BTreeMap<u32, usize>,
    pub metric_counts: PairMetricCounts,
    pub typed_reason_counts: PairReasonCounts,
    /// Exact persisted absence reasons counted once per applicable absent slot.
    pub absent_slot_reason_counts: BTreeMap<String, usize>,
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
    pub pair_outcomes_written: usize,
    pub pair_outcomes_unchanged: usize,
    pub pair_outcomes_tombstoned: usize,
    pub blocks_written: usize,
    pub blocks_unchanged: usize,
    pub blocks_tombstoned: usize,
    pub legacy_rows_tombstoned: usize,
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
    blocks: BTreeMap<CxId, Vec<u8>>,
}

#[derive(Debug)]
struct LegacyPersistedState {
    witnesses: BTreeMap<CxId, (Vec<u8>, LegacyCompletionWitness)>,
    rows: BTreeMap<CxId, BTreeMap<Vec<u8>, Vec<u8>>>,
}

pub fn read_complete_association_state<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<CompleteAssociationState>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let state = read_persisted_state_at(vault, snapshot)?;
    let legacy = read_legacy_v1_state_at(vault, snapshot)?;
    if !legacy.witnesses.is_empty() || !legacy.rows.is_empty() {
        return Err(completion_corrupt(
            "active v1 row-per-pair associations remain; run reconciliation to atomically migrate them to v2 blocks before reading completion state",
        ));
    }
    Ok(state.public)
}

/// Opens the real durable vault read-only and independently verifies every
/// completion witness and reconstructs every pair from raw XTerm block bytes.
pub fn read_complete_association_state_vault_path(
    vault_dir: impl AsRef<Path>,
    vault_id: &str,
    vault_salt: &str,
) -> calyx_core::Result<CompleteAssociationState> {
    let vault_id = VaultId::from_str(vault_id)
        .map_err(|error| source_corrupt(format!("invalid vault id: {error}")))?;
    let options = VaultOptions {
        read_only: true,
        restore_ledger_hook: false,
        selected_cfs: None,
        ..VaultOptions::default()
    };
    let vault = AsterVault::open(vault_dir, vault_id, vault_salt.as_bytes().to_vec(), options)?;
    read_complete_association_state(&vault)
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
    let legacy = read_legacy_v1_state_at(vault, snapshot)?;
    if persisted
        .witnesses
        .keys()
        .any(|cx_id| legacy.witnesses.contains_key(cx_id))
    {
        return Err(completion_corrupt(
            "a constellation has both v1 and v2 completion witnesses; refusing an ambiguous partial migration",
        ));
    }
    let records = load_constellations_at(vault, snapshot)?;
    let current_ids = records
        .iter()
        .map(|record| record.cx_id)
        .collect::<BTreeSet<_>>();
    let current_sources = records
        .iter()
        .map(|record| (record.cx_id, record.source_hash.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut changed = Vec::new();
    let mut constellations_unchanged = 0usize;
    let mut pair_outcomes_unchanged = 0usize;
    let mut blocks_unchanged = 0usize;
    for record in records {
        match persisted.witnesses.get(&record.cx_id) {
            Some((_, witness)) if witness.association_source_hash == record.source_hash => {
                constellations_unchanged =
                    checked_add(constellations_unchanged, 1, "unchanged constellations")?;
                pair_outcomes_unchanged = checked_add(
                    pair_outcomes_unchanged,
                    witness.expected_pair_count,
                    "unchanged pair outcomes",
                )?;
                blocks_unchanged = checked_add(blocks_unchanged, 1, "unchanged pair blocks")?;
            }
            _ => changed.push(record),
        }
    }
    let removed = persisted
        .witnesses
        .keys()
        .chain(legacy.witnesses.keys())
        .filter(|cx_id| !current_ids.contains(cx_id))
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut pending = Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new();
    let mut pending_record_ids = Vec::<String>::new();
    let mut pair_outcomes_written = 0usize;
    let mut pair_outcomes_tombstoned = 0usize;
    let mut blocks_written = 0usize;
    let mut blocks_tombstoned = 0usize;
    let mut legacy_rows_tombstoned = 0usize;
    let mut witnesses_written = 0usize;
    let mut witnesses_tombstoned = 0usize;
    let mut ledger_ref = None;
    let mut fsv = Vec::new();
    let mut commit_count = 0usize;
    let tombstone = tombstone_value();

    for record_batch in changed.chunks(PLANNING_RECORD_BATCH) {
        let planned_batch = record_batch
            .par_iter()
            .map(plan_constellation)
            .collect::<Vec<_>>();
        for planned in planned_batch {
            let planned = planned?;
            let mut record_mutations = Vec::new();
            if persisted.blocks.get(&planned.cx_id) == Some(&planned.block_bytes) {
                blocks_unchanged = checked_add(blocks_unchanged, 1, "unchanged pair blocks")?;
                pair_outcomes_unchanged = checked_add(
                    pair_outcomes_unchanged,
                    planned.witness.expected_pair_count,
                    "unchanged pair outcomes",
                )?;
            } else {
                record_mutations.push((
                    ColumnFamily::XTerm,
                    planned.block_key.clone(),
                    planned.block_bytes.clone(),
                ));
                blocks_written = checked_add(blocks_written, 1, "written pair blocks")?;
                pair_outcomes_written = checked_add(
                    pair_outcomes_written,
                    planned.witness.expected_pair_count,
                    "written pair outcomes",
                )?;
            }
            let witness_unchanged = persisted
                .witnesses
                .get(&planned.cx_id)
                .is_some_and(|(bytes, _)| *bytes == planned.witness_bytes);
            if !witness_unchanged {
                record_mutations.push((
                    ColumnFamily::Kv,
                    planned.witness_key.clone(),
                    planned.witness_bytes.clone(),
                ));
                witnesses_written = checked_add(witnesses_written, 1, "written witnesses")?;
            }
            if let Some(legacy_rows) = legacy.rows.get(&planned.cx_id) {
                for key in legacy_rows.keys() {
                    record_mutations.push((ColumnFamily::XTerm, key.clone(), tombstone.clone()));
                    legacy_rows_tombstoned =
                        checked_add(legacy_rows_tombstoned, 1, "tombstoned legacy pair rows")?;
                }
                pair_outcomes_tombstoned = checked_add(
                    pair_outcomes_tombstoned,
                    legacy_rows.len(),
                    "tombstoned legacy pair outcomes",
                )?;
            }
            if legacy.witnesses.contains_key(&planned.cx_id) {
                record_mutations.push((
                    ColumnFamily::Kv,
                    legacy_witness_key(planned.cx_id),
                    tombstone.clone(),
                ));
                witnesses_tombstoned =
                    checked_add(witnesses_tombstoned, 1, "tombstoned legacy witnesses")?;
            }
            if !pending.is_empty()
                && pending.len().saturating_add(record_mutations.len())
                    > MAX_MUTATION_ROWS_PER_COMMIT
            {
                let (entry_ref, ack) =
                    commit_mutations(vault, &actor, &pending_record_ids, &pending)?;
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
    }

    for cx_id in &removed {
        let mut record_mutations = Vec::new();
        if persisted.blocks.contains_key(cx_id) {
            record_mutations.push((ColumnFamily::XTerm, block_key(*cx_id), tombstone.clone()));
            blocks_tombstoned = checked_add(blocks_tombstoned, 1, "tombstoned pair blocks")?;
        }
        if let Some((_, witness)) = persisted.witnesses.get(cx_id) {
            pair_outcomes_tombstoned = checked_add(
                pair_outcomes_tombstoned,
                witness.expected_pair_count,
                "tombstoned pair outcomes",
            )?;
            record_mutations.push((ColumnFamily::Kv, witness_key(*cx_id), tombstone.clone()));
            witnesses_tombstoned = checked_add(witnesses_tombstoned, 1, "tombstoned witnesses")?;
        }
        if let Some(rows) = legacy.rows.get(cx_id) {
            for key in rows.keys() {
                record_mutations.push((ColumnFamily::XTerm, key.clone(), tombstone.clone()));
                legacy_rows_tombstoned =
                    checked_add(legacy_rows_tombstoned, 1, "tombstoned legacy pair rows")?;
            }
        }
        if let Some((_, witness)) = legacy.witnesses.get(cx_id) {
            pair_outcomes_tombstoned = checked_add(
                pair_outcomes_tombstoned,
                witness.expected_pair_count,
                "tombstoned legacy pair outcomes",
            )?;
            record_mutations.push((
                ColumnFamily::Kv,
                legacy_witness_key(*cx_id),
                tombstone.clone(),
            ));
            witnesses_tombstoned = checked_add(witnesses_tombstoned, 1, "tombstoned witnesses")?;
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
    let final_legacy = read_legacy_v1_state_at(vault, vault.snapshot())?;
    if !final_legacy.witnesses.is_empty() || !final_legacy.rows.is_empty() {
        return Err(completion_corrupt(
            "post-commit readback still contains active v1 association rows or witnesses",
        ));
    }
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
        pair_outcomes_written,
        pair_outcomes_unchanged,
        pair_outcomes_tombstoned,
        blocks_written,
        blocks_unchanged,
        blocks_tombstoned,
        legacy_rows_tombstoned,
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

fn slot_descriptor(slot: &PreparedSlot) -> SlotDescriptor {
    match slot {
        PreparedSlot::Dense { dim, norm, .. } => SlotDescriptor::Dense {
            dim: *dim,
            zero_norm: *norm == 0.0,
        },
        PreparedSlot::Sparse { dim, norm, .. } => SlotDescriptor::Sparse {
            dim: *dim,
            zero_norm: *norm == 0.0,
        },
        PreparedSlot::Multi {
            token_dim, norms, ..
        } => SlotDescriptor::Multi {
            token_dim: *token_dim,
            zero_norm: norms.iter().any(|norm| *norm == 0.0),
        },
        PreparedSlot::Absent { reason } => SlotDescriptor::Absent {
            reason: reason.clone(),
        },
    }
}

fn plan_constellation(
    record: &AssociationConstellation,
) -> calyx_core::Result<PlannedConstellation> {
    let ids = record.slots.keys().copied().collect::<Vec<_>>();
    let descriptors = ids
        .iter()
        .map(|slot| slot_descriptor(&record.slots[slot]))
        .collect::<Vec<_>>();
    let expected_pair_count = choose_two(ids.len())?;
    let mut slot_descriptor_bytes = Vec::new();
    let mut absent_slot_reason_counts = BTreeMap::<String, usize>::new();
    for (slot, descriptor) in ids.iter().zip(&descriptors) {
        slot_descriptor_bytes.extend_from_slice(&slot.get().to_be_bytes());
        encode_slot_descriptor(descriptor, &mut slot_descriptor_bytes)?;
        if let Some(reason) = descriptor.absent_reason() {
            increment_map_count(
                &mut absent_slot_reason_counts,
                &absent_reason_wire(reason),
                "absent slot reason count",
            )?;
        }
    }
    let mut outcome_bytes = Vec::with_capacity(expected_pair_count.saturating_mul(2));
    let mut key_stream = Vec::new();
    let mut value_stream = Vec::new();
    let mut computed_pair_count = 0usize;
    let mut typed_incompatible_pair_count = 0usize;
    let mut metric_counts = BTreeMap::<String, usize>::new();
    let mut typed_reason_counts = BTreeMap::<String, usize>::new();
    for left_index in 0..ids.len() {
        for right_index in (left_index + 1)..ids.len() {
            let left = ids[left_index];
            let right = ids[right_index];
            let outcome = pair_outcome(&record.slots[&left], &record.slots[&right])?;
            let mut encoded_outcome = Vec::with_capacity(5);
            match &outcome {
                CompletePairOutcome::Computed { metric, .. } => {
                    computed_pair_count = checked_add(computed_pair_count, 1, "computed pairs")?;
                    increment_map_count(
                        &mut metric_counts,
                        metric.wire_name(),
                        "per-metric pair count",
                    )?;
                }
                CompletePairOutcome::TypedIncompatible { reason } => {
                    typed_incompatible_pair_count =
                        checked_add(typed_incompatible_pair_count, 1, "typed-incompatible pairs")?;
                    increment_map_count(
                        &mut typed_reason_counts,
                        reason.wire_name(),
                        "per-reason pair count",
                    )?;
                }
            }
            encode_outcome(&outcome, &mut encoded_outcome);
            let key = virtual_pair_key(record.cx_id, left, right);
            append_part(&mut key_stream, &key);
            append_part(&mut value_stream, &key);
            append_part(&mut value_stream, &encoded_outcome);
            outcome_bytes.extend_from_slice(&encoded_outcome);
        }
    }
    let mut block_bytes = Vec::with_capacity(
        COMPLETE_PAIR_BLOCK_MAGIC.len()
            + 16
            + 4
            + 32
            + 4
            + 4
            + 4
            + 8
            + slot_descriptor_bytes.len()
            + outcome_bytes.len(),
    );
    block_bytes.extend_from_slice(COMPLETE_PAIR_BLOCK_MAGIC);
    block_bytes.extend_from_slice(record.cx_id.as_bytes());
    block_bytes.extend_from_slice(&record.panel_version.to_be_bytes());
    block_bytes.extend_from_slice(&decode_hash_32(
        &record.source_hash,
        "association source hash",
    )?);
    block_bytes.extend_from_slice(
        &usize_to_u32(record.source_slot_count, "block source slot count")?.to_be_bytes(),
    );
    block_bytes.extend_from_slice(
        &usize_to_u32(
            record.not_applicable_slot_count,
            "block NotApplicable slot count",
        )?
        .to_be_bytes(),
    );
    block_bytes
        .extend_from_slice(&usize_to_u32(ids.len(), "block applicable slot count")?.to_be_bytes());
    block_bytes.extend_from_slice(
        &usize_to_u64(expected_pair_count, "block expected pair count")?.to_be_bytes(),
    );
    block_bytes.extend_from_slice(&slot_descriptor_bytes);
    block_bytes.extend_from_slice(&outcome_bytes);

    let decoded = decode_pair_block(record.cx_id, &block_bytes)?;
    if decoded.expected_pair_count != expected_pair_count
        || decoded.computed_pair_count != computed_pair_count
        || decoded.typed_incompatible_pair_count != typed_incompatible_pair_count
        || decoded.absent_slot_reason_counts != absent_slot_reason_counts
        || decoded.slot_descriptor_hash
            != hex_lower_bytes(blake3::hash(&slot_descriptor_bytes).as_bytes())
        || decoded.pair_key_stream_hash != hex_lower_bytes(blake3::hash(&key_stream).as_bytes())
        || decoded.pair_value_stream_hash != hex_lower_bytes(blake3::hash(&value_stream).as_bytes())
    {
        return Err(completion_corrupt(format!(
            "planner binary round-trip differs for Base {}",
            cx_hex(record.cx_id)
        )));
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
        absent_slot_reason_counts,
        slot_descriptor_hash: hex_lower_bytes(blake3::hash(&slot_descriptor_bytes).as_bytes()),
        pair_block_byte_count: block_bytes.len(),
        pair_block_hash: hex_lower_bytes(blake3::hash(&block_bytes).as_bytes()),
        pair_key_stream_hash: decoded.pair_key_stream_hash,
        pair_value_stream_hash: decoded.pair_value_stream_hash,
    };
    let witness_bytes = serde_json::to_vec(&witness)
        .map_err(|error| completion_corrupt(format!("encode completion witness: {error}")))?;
    Ok(PlannedConstellation {
        cx_id: record.cx_id,
        block_key: block_key(record.cx_id),
        block_bytes,
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
        let _ = reason;
        return Ok(incompatible(PairReason::AbsentSlot));
    }
    if let PreparedSlot::Absent { reason } = right {
        let _ = reason;
        return Ok(incompatible(PairReason::AbsentSlot));
    }
    if has_zero_norm(left) || has_zero_norm(right) {
        return Ok(incompatible(PairReason::ZeroNorm));
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
            PairMetric::Cosine,
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
            PairMetric::Cosine,
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
            PairMetric::Cosine,
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
            PairMetric::Cosine,
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
            PairMetric::SymmetricMeanMaxsimCosine,
            symmetric_mean_maxsim(left_tokens, left_norms, right_tokens, right_norms),
        ),
        _ => {
            return Ok(incompatible(PairReason::ShapeMismatch));
        }
    };
    let value = validated_cosine(computed.0, computed.1)? as f32;
    Ok(CompletePairOutcome::Computed {
        metric: computed.0,
        value_bits: value.to_bits(),
    })
}

fn incompatible(reason: PairReason) -> CompletePairOutcome {
    CompletePairOutcome::TypedIncompatible { reason }
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

fn encode_slot_descriptor(
    descriptor: &SlotDescriptor,
    out: &mut Vec<u8>,
) -> calyx_core::Result<()> {
    match descriptor {
        SlotDescriptor::Absent { reason } => {
            out.push(0);
            encode_applicable_absent_reason(reason, out)?;
        }
        SlotDescriptor::Dense { dim, zero_norm } => {
            out.push(1);
            out.extend_from_slice(&dim.to_be_bytes());
            out.push(u8::from(*zero_norm));
        }
        SlotDescriptor::Sparse { dim, zero_norm } => {
            out.push(2);
            out.extend_from_slice(&dim.to_be_bytes());
            out.push(u8::from(*zero_norm));
        }
        SlotDescriptor::Multi {
            token_dim,
            zero_norm,
        } => {
            out.push(3);
            out.extend_from_slice(&token_dim.to_be_bytes());
            out.push(u8::from(*zero_norm));
        }
    }
    Ok(())
}

fn encode_applicable_absent_reason(
    reason: &AbsentReason,
    out: &mut Vec<u8>,
) -> calyx_core::Result<()> {
    match reason {
        AbsentReason::NotApplicable => {
            return Err(source_corrupt(
                "NotApplicable reached the applicable slot descriptor encoder",
            ));
        }
        AbsentReason::Redacted => out.push(1),
        AbsentReason::LensUnavailable => out.push(2),
        AbsentReason::Deferred => out.push(3),
        AbsentReason::LensInactive => out.push(4),
        AbsentReason::Error(message) => {
            out.push(5);
            out.extend_from_slice(
                &usize_to_u32(message.len(), "absent error message length")?.to_be_bytes(),
            );
            out.extend_from_slice(message.as_bytes());
        }
    }
    Ok(())
}

fn decode_slot_descriptor(cursor: &mut BlockCursor<'_>) -> calyx_core::Result<SlotDescriptor> {
    let kind = cursor.u8("slot descriptor kind")?;
    if kind == 0 {
        return Ok(SlotDescriptor::Absent {
            reason: decode_applicable_absent_reason(cursor)?,
        });
    }
    let dim = cursor.u32("slot descriptor dimension")?;
    if dim == 0 {
        return Err(completion_corrupt(format!(
            "pair block {} carries a zero slot descriptor dimension",
            cx_hex(cursor.cx_id)
        )));
    }
    let zero_norm = match cursor.u8("slot descriptor zero-norm flag")? {
        0 => false,
        1 => true,
        flag => {
            return Err(completion_corrupt(format!(
                "pair block {} carries invalid zero-norm flag {flag}",
                cx_hex(cursor.cx_id)
            )));
        }
    };
    match kind {
        1 => Ok(SlotDescriptor::Dense { dim, zero_norm }),
        2 => Ok(SlotDescriptor::Sparse { dim, zero_norm }),
        3 => Ok(SlotDescriptor::Multi {
            token_dim: dim,
            zero_norm,
        }),
        _ => Err(completion_corrupt(format!(
            "pair block {} carries unknown slot descriptor kind {kind}",
            cx_hex(cursor.cx_id)
        ))),
    }
}

fn decode_applicable_absent_reason(
    cursor: &mut BlockCursor<'_>,
) -> calyx_core::Result<AbsentReason> {
    Ok(match cursor.u8("applicable absent reason")? {
        1 => AbsentReason::Redacted,
        2 => AbsentReason::LensUnavailable,
        3 => AbsentReason::Deferred,
        4 => AbsentReason::LensInactive,
        5 => {
            let len = usize::try_from(cursor.u32("absent error message length")?)
                .map_err(|_| completion_overflow("decoded absent error message length"))?;
            let bytes = cursor.take(len, "absent error message")?;
            let message = std::str::from_utf8(bytes).map_err(|error| {
                completion_corrupt(format!(
                    "pair block {} absent error message is not UTF-8: {error}",
                    cx_hex(cursor.cx_id)
                ))
            })?;
            AbsentReason::Error(message.to_string())
        }
        tag => {
            return Err(completion_corrupt(format!(
                "pair block {} carries unknown applicable absent reason tag {tag}",
                cx_hex(cursor.cx_id)
            )));
        }
    })
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

fn expected_outcome_code(left: &SlotDescriptor, right: &SlotDescriptor) -> u8 {
    if left.absent_reason().is_some() || right.absent_reason().is_some() {
        return PairReason::AbsentSlot.code();
    }
    if left.zero_norm() || right.zero_norm() {
        return PairReason::ZeroNorm.code();
    }
    match (left, right) {
        (SlotDescriptor::Dense { dim: left, .. }, SlotDescriptor::Dense { dim: right, .. })
        | (SlotDescriptor::Sparse { dim: left, .. }, SlotDescriptor::Sparse { dim: right, .. })
        | (SlotDescriptor::Dense { dim: left, .. }, SlotDescriptor::Sparse { dim: right, .. })
        | (SlotDescriptor::Sparse { dim: left, .. }, SlotDescriptor::Dense { dim: right, .. })
            if left == right =>
        {
            PairMetric::Cosine.code()
        }
        (
            SlotDescriptor::Multi {
                token_dim: left, ..
            },
            SlotDescriptor::Multi {
                token_dim: right, ..
            },
        ) if left == right => PairMetric::SymmetricMeanMaxsimCosine.code(),
        _ => PairReason::ShapeMismatch.code(),
    }
}

#[derive(Debug)]
struct DecodedPairBlock {
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
    absent_slot_reason_counts: BTreeMap<String, usize>,
    slot_descriptor_hash: String,
    pair_key_stream: Vec<u8>,
    pair_value_stream: Vec<u8>,
    pair_key_stream_hash: String,
    pair_value_stream_hash: String,
}

struct BlockCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    cx_id: CxId,
}

impl<'a> BlockCursor<'a> {
    fn new(cx_id: CxId, bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            cx_id,
        }
    }

    fn take(&mut self, count: usize, field: &str) -> calyx_core::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| completion_overflow("pair block cursor"))?;
        if end > self.bytes.len() {
            return Err(completion_corrupt(format!(
                "pair block {} is truncated while reading {field}: offset={} need={} len={}",
                cx_hex(self.cx_id),
                self.offset,
                count,
                self.bytes.len()
            )));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, field: &str) -> calyx_core::Result<u8> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &str) -> calyx_core::Result<u16> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, field: &str) -> calyx_core::Result<u32> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            completion_corrupt(format!("pair block {} invalid {field}", cx_hex(self.cx_id)))
        })?))
    }

    fn u64(&mut self, field: &str) -> calyx_core::Result<u64> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            completion_corrupt(format!("pair block {} invalid {field}", cx_hex(self.cx_id)))
        })?))
    }

    fn finish(self) -> calyx_core::Result<()> {
        if self.offset != self.bytes.len() {
            return Err(completion_corrupt(format!(
                "pair block {} has {} unexpected trailing bytes",
                cx_hex(self.cx_id),
                self.bytes.len() - self.offset
            )));
        }
        Ok(())
    }
}

fn decode_pair_block(cx_id: CxId, bytes: &[u8]) -> calyx_core::Result<DecodedPairBlock> {
    let mut cursor = BlockCursor::new(cx_id, bytes);
    if cursor.take(COMPLETE_PAIR_BLOCK_MAGIC.len(), "magic")? != COMPLETE_PAIR_BLOCK_MAGIC {
        return Err(completion_corrupt(format!(
            "pair block {} has an unknown binary schema discriminator",
            cx_hex(cx_id)
        )));
    }
    if cursor.take(16, "embedded CxId")? != cx_id.as_bytes() {
        return Err(completion_corrupt(format!(
            "pair block key/value CxId mismatch for {}",
            cx_hex(cx_id)
        )));
    }
    let panel_version = cursor.u32("panel version")?;
    if panel_version == 0 {
        return Err(completion_corrupt(format!(
            "pair block {} carries panel version zero",
            cx_hex(cx_id)
        )));
    }
    let association_source_hash = hex_lower_bytes(cursor.take(32, "source hash")?);
    let source_slot_count = usize::try_from(cursor.u32("source slot count")?)
        .map_err(|_| completion_overflow("decoded source slot count"))?;
    let not_applicable_slot_count = usize::try_from(cursor.u32("NotApplicable slot count")?)
        .map_err(|_| completion_overflow("decoded NotApplicable slot count"))?;
    let applicable_slot_count = usize::try_from(cursor.u32("applicable slot count")?)
        .map_err(|_| completion_overflow("decoded applicable slot count"))?;
    let expected_pair_count = usize::try_from(cursor.u64("expected pair count")?)
        .map_err(|_| completion_overflow("decoded expected pair count"))?;
    if source_slot_count
        != checked_add(
            applicable_slot_count,
            not_applicable_slot_count,
            "decoded block source-slot equation",
        )?
    {
        return Err(completion_corrupt(format!(
            "pair block {} source_slot_count does not equal applicable + NotApplicable",
            cx_hex(cx_id)
        )));
    }
    if choose_two(applicable_slot_count)? != expected_pair_count {
        return Err(completion_corrupt(format!(
            "pair block {} expected pair count does not equal C(N_applicable,2)",
            cx_hex(cx_id)
        )));
    }
    let descriptor_start = cursor.offset;
    let mut applicable_slot_ids = Vec::with_capacity(applicable_slot_count);
    let mut slot_descriptors = Vec::with_capacity(applicable_slot_count);
    let mut absent_slot_reason_counts = BTreeMap::new();
    for _ in 0..applicable_slot_count {
        applicable_slot_ids.push(cursor.u16("applicable SlotId")?);
        let descriptor = decode_slot_descriptor(&mut cursor)?;
        if let Some(reason) = descriptor.absent_reason() {
            increment_map_count(
                &mut absent_slot_reason_counts,
                &absent_reason_wire(reason),
                "decoded absent slot reason count",
            )?;
        }
        slot_descriptors.push(descriptor);
    }
    let slot_descriptor_hash =
        hex_lower_bytes(blake3::hash(&bytes[descriptor_start..cursor.offset]).as_bytes());
    if applicable_slot_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(completion_corrupt(format!(
            "pair block {} applicable SlotIds are not strictly increasing",
            cx_hex(cx_id)
        )));
    }

    let mut computed_pair_count = 0usize;
    let mut typed_incompatible_pair_count = 0usize;
    let mut metric_counts = BTreeMap::new();
    let mut typed_reason_counts = BTreeMap::new();
    let mut pair_key_stream = Vec::new();
    let mut pair_value_stream = Vec::new();
    for left_index in 0..applicable_slot_ids.len() {
        for right_index in (left_index + 1)..applicable_slot_ids.len() {
            let left = SlotId::new(applicable_slot_ids[left_index]);
            let right = SlotId::new(applicable_slot_ids[right_index]);
            let code = cursor.u8("pair outcome code")?;
            let expected_code = expected_outcome_code(
                &slot_descriptors[left_index],
                &slot_descriptors[right_index],
            );
            if code != expected_code {
                return Err(completion_corrupt(format!(
                    "pair block {} S{}-S{} outcome code {code} contradicts roster descriptors (expected {expected_code})",
                    cx_hex(cx_id),
                    left.get(),
                    right.get()
                )));
            }
            let mut encoded_outcome = vec![code];
            match code {
                1 | 2 => {
                    let value_bytes = cursor.take(4, "computed f32 bits")?;
                    encoded_outcome.extend_from_slice(value_bytes);
                    let bits = u32::from_be_bytes(value_bytes.try_into().map_err(|_| {
                        completion_corrupt(format!(
                            "pair block {} has invalid computed bits",
                            cx_hex(cx_id)
                        ))
                    })?);
                    if !f32::from_bits(bits).is_finite() {
                        return Err(completion_corrupt(format!(
                            "pair block {} S{}-S{} contains non-finite computed bits",
                            cx_hex(cx_id),
                            left.get(),
                            right.get()
                        )));
                    }
                    if !(-1.0..=1.0).contains(&f32::from_bits(bits)) {
                        return Err(completion_corrupt(format!(
                            "pair block {} S{}-S{} contains cosine outside [-1,1]",
                            cx_hex(cx_id),
                            left.get(),
                            right.get()
                        )));
                    }
                    computed_pair_count =
                        checked_add(computed_pair_count, 1, "decoded computed pairs")?;
                    let metric = if code == 1 {
                        PairMetric::Cosine
                    } else {
                        PairMetric::SymmetricMeanMaxsimCosine
                    };
                    increment_map_count(
                        &mut metric_counts,
                        metric.wire_name(),
                        "decoded metric count",
                    )?;
                }
                3..=5 => {
                    typed_incompatible_pair_count = checked_add(
                        typed_incompatible_pair_count,
                        1,
                        "decoded typed-incompatible pairs",
                    )?;
                    let reason = match code {
                        3 => PairReason::AbsentSlot,
                        4 => PairReason::ShapeMismatch,
                        5 => PairReason::ZeroNorm,
                        _ => unreachable!(),
                    };
                    increment_map_count(
                        &mut typed_reason_counts,
                        reason.wire_name(),
                        "decoded reason count",
                    )?;
                }
                _ => {
                    return Err(completion_corrupt(format!(
                        "pair block {} S{}-S{} has unknown outcome code {code}",
                        cx_hex(cx_id),
                        left.get(),
                        right.get()
                    )));
                }
            }
            let key = virtual_pair_key(cx_id, left, right);
            append_part(&mut pair_key_stream, &key);
            append_part(&mut pair_value_stream, &key);
            append_part(&mut pair_value_stream, &encoded_outcome);
        }
    }
    cursor.finish()?;
    if checked_add(
        computed_pair_count,
        typed_incompatible_pair_count,
        "decoded completion equation",
    )? != expected_pair_count
    {
        return Err(completion_corrupt(format!(
            "pair block {} decoded outcome count differs from expected pairs",
            cx_hex(cx_id)
        )));
    }
    let pair_key_stream_hash = hex_lower_bytes(blake3::hash(&pair_key_stream).as_bytes());
    let pair_value_stream_hash = hex_lower_bytes(blake3::hash(&pair_value_stream).as_bytes());
    Ok(DecodedPairBlock {
        panel_version,
        association_source_hash,
        source_slot_count,
        not_applicable_slot_count,
        applicable_slot_ids,
        expected_pair_count,
        computed_pair_count,
        typed_incompatible_pair_count,
        metric_counts,
        typed_reason_counts,
        absent_slot_reason_counts,
        slot_descriptor_hash,
        pair_key_stream,
        pair_value_stream,
        pair_key_stream_hash,
        pair_value_stream_hash,
    })
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
            completion_corrupt(format!(
                "decode v2 witness {}: {error}",
                hex_lower_bytes(&key)
            ))
        })?;
        validate_witness_identity(cx_id, &witness)?;
        if witnesses.insert(cx_id, (value, witness)).is_some() {
            return Err(completion_corrupt(format!(
                "duplicate v2 completion witness for {}",
                cx_hex(cx_id)
            )));
        }
    }
    let mut blocks = BTreeMap::<CxId, Vec<u8>>::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::XTerm,
        &prefix_range(COMPLETE_PAIR_BLOCK_PREFIX),
    )? {
        let cx_id = parse_block_key(&key)?;
        if blocks.insert(cx_id, value).is_some() {
            return Err(completion_corrupt(format!(
                "duplicate pair block for {}",
                cx_hex(cx_id)
            )));
        }
    }
    for cx_id in blocks.keys() {
        if !witnesses.contains_key(cx_id) {
            return Err(completion_corrupt(format!(
                "pair block {} has no atomic v2 witness",
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
        physical_block_count: blocks.len(),
        panel_version_counts: BTreeMap::new(),
        metric_counts: PairMetricCounts::default(),
        typed_reason_counts: PairReasonCounts::default(),
        absent_slot_reason_counts: BTreeMap::new(),
        witness_state_hash: String::new(),
        pair_key_stream_hash: String::new(),
        pair_value_stream_hash: String::new(),
    };
    let mut witness_stream = Vec::new();
    let mut global_key_stream = blake3::Hasher::new();
    let mut global_value_stream = blake3::Hasher::new();
    for (cx_id, (witness_bytes, witness)) in &witnesses {
        let block_bytes = blocks.get(cx_id).ok_or_else(|| {
            completion_corrupt(format!("v2 witness {} has no pair block", cx_hex(*cx_id)))
        })?;
        let decoded = decode_pair_block(*cx_id, block_bytes)?;
        validate_witness_block(*cx_id, witness, block_bytes, &decoded)?;
        public.source_slot_count = checked_add(
            public.source_slot_count,
            decoded.source_slot_count,
            "source slots",
        )?;
        public.not_applicable_slot_count = checked_add(
            public.not_applicable_slot_count,
            decoded.not_applicable_slot_count,
            "NotApplicable slots",
        )?;
        public.applicable_slot_count = checked_add(
            public.applicable_slot_count,
            decoded.applicable_slot_ids.len(),
            "applicable slots",
        )?;
        public.expected_pair_count = checked_add(
            public.expected_pair_count,
            decoded.expected_pair_count,
            "expected pairs",
        )?;
        public.computed_pair_count = checked_add(
            public.computed_pair_count,
            decoded.computed_pair_count,
            "computed pairs",
        )?;
        public.typed_incompatible_pair_count = checked_add(
            public.typed_incompatible_pair_count,
            decoded.typed_incompatible_pair_count,
            "typed-incompatible pairs",
        )?;
        public.completion_row_count = checked_add(
            public.completion_row_count,
            decoded.expected_pair_count,
            "logical completion rows",
        )?;
        increment_u32_map_count(
            &mut public.panel_version_counts,
            decoded.panel_version,
            "panel version count",
        )?;
        public.metric_counts.cosine = checked_add(
            public.metric_counts.cosine,
            decoded.metric_counts.get("cosine").copied().unwrap_or(0),
            "cosine count",
        )?;
        public.metric_counts.symmetric_mean_maxsim_cosine = checked_add(
            public.metric_counts.symmetric_mean_maxsim_cosine,
            decoded
                .metric_counts
                .get("symmetric_mean_maxsim_cosine")
                .copied()
                .unwrap_or(0),
            "symmetric MaxSim count",
        )?;
        public.typed_reason_counts.absent_slot = checked_add(
            public.typed_reason_counts.absent_slot,
            decoded
                .typed_reason_counts
                .get("absent_slot")
                .copied()
                .unwrap_or(0),
            "absent-slot count",
        )?;
        public.typed_reason_counts.shape_mismatch = checked_add(
            public.typed_reason_counts.shape_mismatch,
            decoded
                .typed_reason_counts
                .get("shape_mismatch")
                .copied()
                .unwrap_or(0),
            "shape-mismatch count",
        )?;
        public.typed_reason_counts.zero_norm = checked_add(
            public.typed_reason_counts.zero_norm,
            decoded
                .typed_reason_counts
                .get("zero_norm")
                .copied()
                .unwrap_or(0),
            "zero-norm count",
        )?;
        for (reason, count) in &decoded.absent_slot_reason_counts {
            let current = public
                .absent_slot_reason_counts
                .get(reason)
                .copied()
                .unwrap_or(0);
            public.absent_slot_reason_counts.insert(
                reason.clone(),
                checked_add(current, *count, "global absent slot reason count")?,
            );
        }
        append_part(&mut witness_stream, &witness_key(*cx_id));
        append_part(&mut witness_stream, witness_bytes);
        global_key_stream.update(&decoded.pair_key_stream);
        global_value_stream.update(&decoded.pair_value_stream);
    }
    if checked_add(
        public.computed_pair_count,
        public.typed_incompatible_pair_count,
        "global completion equation",
    )? != public.expected_pair_count
        || public.completion_row_count != public.expected_pair_count
        || public.physical_block_count != public.constellation_count
    {
        return Err(completion_corrupt(
            "global v2 completion equation or one-block-per-witness invariant failed",
        ));
    }
    public.witness_state_hash = hex_lower_bytes(blake3::hash(&witness_stream).as_bytes());
    public.pair_key_stream_hash = hex_lower_bytes(global_key_stream.finalize().as_bytes());
    public.pair_value_stream_hash = hex_lower_bytes(global_value_stream.finalize().as_bytes());
    Ok(PersistedState {
        public,
        witnesses,
        blocks,
    })
}

fn validate_witness_identity(cx_id: CxId, witness: &CompletionWitness) -> calyx_core::Result<()> {
    if witness.schema != COMPLETE_WITNESS_SCHEMA || witness.cx_id != cx_hex(cx_id) {
        return Err(completion_corrupt(format!(
            "v2 completion witness key/identity mismatch for {}",
            cx_hex(cx_id)
        )));
    }
    decode_hash_32(
        &witness.association_source_hash,
        "witness association source hash",
    )?;
    decode_hash_32(&witness.pair_block_hash, "witness pair block hash")?;
    decode_hash_32(
        &witness.slot_descriptor_hash,
        "witness slot descriptor hash",
    )?;
    decode_hash_32(
        &witness.pair_key_stream_hash,
        "witness pair key stream hash",
    )?;
    decode_hash_32(
        &witness.pair_value_stream_hash,
        "witness pair value stream hash",
    )?;
    if witness
        .applicable_slot_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(completion_corrupt(format!(
            "v2 witness {} applicable SlotIds are not strictly increasing",
            cx_hex(cx_id)
        )));
    }
    if witness.source_slot_count
        != checked_add(
            witness.applicable_slot_ids.len(),
            witness.not_applicable_slot_count,
            "v2 witness source slot equation",
        )?
    {
        return Err(completion_corrupt(format!(
            "v2 witness {} source_slot_count does not equal applicable + NotApplicable",
            cx_hex(cx_id)
        )));
    }
    let expected = choose_two(witness.applicable_slot_ids.len())?;
    if witness.expected_pair_count != expected
        || checked_add(
            witness.computed_pair_count,
            witness.typed_incompatible_pair_count,
            "v2 witness completion equation",
        )? != expected
    {
        return Err(completion_corrupt(format!(
            "v2 witness {} does not prove computed + typed_incompatible = C(N_applicable,2)",
            cx_hex(cx_id)
        )));
    }
    let absent_slot_count = witness
        .absent_slot_reason_counts
        .values()
        .try_fold(0usize, |sum, count| {
            checked_add(sum, *count, "v2 witness absent slot reason count")
        })?;
    if absent_slot_count > witness.applicable_slot_ids.len() {
        return Err(completion_corrupt(format!(
            "v2 witness {} absent slot reason count exceeds applicable slots",
            cx_hex(cx_id)
        )));
    }
    Ok(())
}

fn validate_witness_block(
    cx_id: CxId,
    witness: &CompletionWitness,
    block_bytes: &[u8],
    decoded: &DecodedPairBlock,
) -> calyx_core::Result<()> {
    let observed_block_hash = hex_lower_bytes(blake3::hash(block_bytes).as_bytes());
    if witness.panel_version != decoded.panel_version
        || witness.association_source_hash != decoded.association_source_hash
        || witness.source_slot_count != decoded.source_slot_count
        || witness.not_applicable_slot_count != decoded.not_applicable_slot_count
        || witness.applicable_slot_ids != decoded.applicable_slot_ids
        || witness.expected_pair_count != decoded.expected_pair_count
        || witness.computed_pair_count != decoded.computed_pair_count
        || witness.typed_incompatible_pair_count != decoded.typed_incompatible_pair_count
        || witness.metric_counts != decoded.metric_counts
        || witness.typed_reason_counts != decoded.typed_reason_counts
        || witness.absent_slot_reason_counts != decoded.absent_slot_reason_counts
        || witness.slot_descriptor_hash != decoded.slot_descriptor_hash
        || witness.pair_block_byte_count != block_bytes.len()
        || witness.pair_block_hash != observed_block_hash
        || witness.pair_key_stream_hash != decoded.pair_key_stream_hash
        || witness.pair_value_stream_hash != decoded.pair_value_stream_hash
    {
        return Err(completion_corrupt(format!(
            "v2 witness {} differs from independently decoded pair-block bytes",
            cx_hex(cx_id)
        )));
    }
    Ok(())
}

fn read_legacy_v1_state_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
) -> calyx_core::Result<LegacyPersistedState>
where
    C: Clock,
{
    let mut witnesses = BTreeMap::<CxId, (Vec<u8>, LegacyCompletionWitness)>::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Kv,
        &prefix_range(LEGACY_COMPLETE_WITNESS_PREFIX),
    )? {
        let cx_id = parse_legacy_witness_key(&key)?;
        let witness: LegacyCompletionWitness = serde_json::from_slice(&value).map_err(|error| {
            completion_corrupt(format!("decode witness {}: {error}", hex_lower_bytes(&key)))
        })?;
        validate_legacy_witness_identity(cx_id, &witness)?;
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
        &prefix_range(LEGACY_COMPLETE_PAIR_ROW_PREFIX),
    )? {
        let (cx_id, left, right) = parse_legacy_pair_row_key(&key)?;
        let row: LegacyCompletePairRow = serde_json::from_slice(&value).map_err(|error| {
            completion_corrupt(format!(
                "decode pair row {}: {error}",
                hex_lower_bytes(&key)
            ))
        })?;
        validate_legacy_pair_row(cx_id, left, right, &row)?;
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

    for (cx_id, (_, witness)) in &witnesses {
        let actual_rows = rows.get(cx_id).cloned().unwrap_or_default();
        validate_legacy_witness_rows(*cx_id, witness, &actual_rows)?;
    }
    Ok(LegacyPersistedState { witnesses, rows })
}

fn validate_legacy_witness_identity(
    cx_id: CxId,
    witness: &LegacyCompletionWitness,
) -> calyx_core::Result<()> {
    if witness.schema != LEGACY_COMPLETE_WITNESS_SCHEMA || witness.cx_id != cx_hex(cx_id) {
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

fn validate_legacy_witness_rows(
    cx_id: CxId,
    witness: &LegacyCompletionWitness,
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
            expected_keys.insert(legacy_pair_row_key(
                cx_id,
                ids[left_index],
                ids[right_index],
            ));
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
        let row: LegacyCompletePairRow = serde_json::from_slice(value)
            .map_err(|error| completion_corrupt(format!("decode witnessed pair row: {error}")))?;
        match row.outcome {
            LegacyCompletePairOutcome::Computed { value_bits, .. } => {
                if !f32::from_bits(value_bits).is_finite() {
                    return Err(completion_corrupt(format!(
                        "completion witness {} contains non-finite computed bits",
                        cx_hex(cx_id)
                    )));
                }
                computed += 1;
            }
            LegacyCompletePairOutcome::TypedIncompatible { .. } => incompatible += 1,
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

fn validate_legacy_pair_row(
    cx_id: CxId,
    left: SlotId,
    right: SlotId,
    row: &LegacyCompletePairRow,
) -> calyx_core::Result<()> {
    if row.schema != LEGACY_COMPLETE_PAIR_ROW_SCHEMA
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
    if let LegacyCompletePairOutcome::Computed { value_bits, .. } = row.outcome
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

fn encode_outcome(outcome: &CompletePairOutcome, out: &mut Vec<u8>) {
    match outcome {
        CompletePairOutcome::Computed { metric, value_bits } => {
            out.push(metric.code());
            out.extend_from_slice(&value_bits.to_be_bytes());
        }
        CompletePairOutcome::TypedIncompatible { reason } => out.push(reason.code()),
    }
}

fn block_key(cx_id: CxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMPLETE_PAIR_BLOCK_PREFIX.len() + 16);
    key.extend_from_slice(COMPLETE_PAIR_BLOCK_PREFIX);
    key.extend_from_slice(cx_id.as_bytes());
    key
}

fn parse_block_key(key: &[u8]) -> calyx_core::Result<CxId> {
    if key.len() != COMPLETE_PAIR_BLOCK_PREFIX.len() + 16
        || !key.starts_with(COMPLETE_PAIR_BLOCK_PREFIX)
    {
        return Err(completion_corrupt(format!(
            "malformed v2 pair-block key {}",
            hex_lower_bytes(key)
        )));
    }
    let mut cx_bytes = [0u8; 16];
    cx_bytes.copy_from_slice(&key[COMPLETE_PAIR_BLOCK_PREFIX.len()..]);
    Ok(CxId::from_bytes(cx_bytes))
}

fn virtual_pair_key(cx_id: CxId, left: SlotId, right: SlotId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMPLETE_PAIR_BLOCK_PREFIX.len() + 1 + 20);
    key.extend_from_slice(COMPLETE_PAIR_BLOCK_PREFIX);
    key.push(b'p');
    key.extend_from_slice(cx_id.as_bytes());
    key.extend_from_slice(&left.get().to_be_bytes());
    key.extend_from_slice(&right.get().to_be_bytes());
    key
}

fn parse_witness_key(key: &[u8]) -> calyx_core::Result<CxId> {
    if key.len() != COMPLETE_WITNESS_PREFIX.len() + 16 || !key.starts_with(COMPLETE_WITNESS_PREFIX)
    {
        return Err(completion_corrupt(format!(
            "malformed v2 completion witness key {}",
            hex_lower_bytes(key)
        )));
    }
    let mut cx_bytes = [0u8; 16];
    cx_bytes.copy_from_slice(&key[COMPLETE_WITNESS_PREFIX.len()..]);
    Ok(CxId::from_bytes(cx_bytes))
}

fn decode_hash_32(value: &str, field: &str) -> calyx_core::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(completion_corrupt(format!(
            "{field} must be exactly 64 hexadecimal characters"
        )));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| completion_corrupt(format!("{field} contains invalid UTF-8")))?;
        out[index] = u8::from_str_radix(text, 16)
            .map_err(|_| completion_corrupt(format!("{field} contains invalid hexadecimal")))?;
    }
    Ok(out)
}

fn usize_to_u32(value: usize, context: &str) -> calyx_core::Result<u32> {
    u32::try_from(value).map_err(|_| completion_overflow(context))
}

fn usize_to_u64(value: usize, context: &str) -> calyx_core::Result<u64> {
    u64::try_from(value).map_err(|_| completion_overflow(context))
}

fn increment_map_count(
    counts: &mut BTreeMap<String, usize>,
    key: &str,
    context: &str,
) -> calyx_core::Result<()> {
    let current = counts.get(key).copied().unwrap_or(0);
    counts.insert(key.to_string(), checked_add(current, 1, context)?);
    Ok(())
}

fn increment_u32_map_count(
    counts: &mut BTreeMap<u32, usize>,
    key: u32,
    context: &str,
) -> calyx_core::Result<()> {
    let current = counts.get(&key).copied().unwrap_or(0);
    counts.insert(key, checked_add(current, 1, context)?);
    Ok(())
}

fn validated_cosine(metric: PairMetric, value: f64) -> calyx_core::Result<f64> {
    const COSINE_ROUNDOFF_TOLERANCE: f64 = 1.0e-9;
    if !value.is_finite() {
        return Err(source_corrupt(format!(
            "{} produced a non-finite association",
            metric.wire_name()
        )));
    }
    if !(-1.0 - COSINE_ROUNDOFF_TOLERANCE..=1.0 + COSINE_ROUNDOFF_TOLERANCE).contains(&value) {
        return Err(source_corrupt(format!(
            "{} produced cosine {value}, outside [-1,1] beyond the declared numerical tolerance {COSINE_ROUNDOFF_TOLERANCE}",
            metric.wire_name()
        )));
    }
    Ok(value.clamp(-1.0, 1.0))
}

fn legacy_pair_row_key(cx_id: CxId, left: SlotId, right: SlotId) -> Vec<u8> {
    let mut key = Vec::with_capacity(LEGACY_COMPLETE_PAIR_ROW_PREFIX.len() + 20);
    key.extend_from_slice(LEGACY_COMPLETE_PAIR_ROW_PREFIX);
    key.extend_from_slice(cx_id.as_bytes());
    key.extend_from_slice(&left.get().to_be_bytes());
    key.extend_from_slice(&right.get().to_be_bytes());
    key
}

fn parse_legacy_pair_row_key(key: &[u8]) -> calyx_core::Result<(CxId, SlotId, SlotId)> {
    let expected_len = LEGACY_COMPLETE_PAIR_ROW_PREFIX.len() + 20;
    if key.len() != expected_len || !key.starts_with(LEGACY_COMPLETE_PAIR_ROW_PREFIX) {
        return Err(completion_corrupt(format!(
            "malformed complete pair key {}",
            hex_lower_bytes(key)
        )));
    }
    let offset = LEGACY_COMPLETE_PAIR_ROW_PREFIX.len();
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

fn parse_legacy_witness_key(key: &[u8]) -> calyx_core::Result<CxId> {
    if key.len() != LEGACY_COMPLETE_WITNESS_PREFIX.len() + 16
        || !key.starts_with(LEGACY_COMPLETE_WITNESS_PREFIX)
    {
        return Err(completion_corrupt(format!(
            "malformed completion witness key {}",
            hex_lower_bytes(key)
        )));
    }
    let mut cx_bytes = [0u8; 16];
    cx_bytes.copy_from_slice(&key[LEGACY_COMPLETE_WITNESS_PREFIX.len()..]);
    Ok(CxId::from_bytes(cx_bytes))
}

fn legacy_witness_key(cx_id: CxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(LEGACY_COMPLETE_WITNESS_PREFIX.len() + 16);
    key.extend_from_slice(LEGACY_COMPLETE_WITNESS_PREFIX);
    key.extend_from_slice(cx_id.as_bytes());
    key
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
