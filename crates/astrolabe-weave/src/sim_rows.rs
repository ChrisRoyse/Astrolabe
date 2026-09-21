//! Graph CF persistence for planned SIM_* similarity edges.
//!
//! Derived similarity edges are regenerable, so persistence is a full,
//! idempotent reconciliation of the `astrolabe:sim-edge:v2:` prefix: rows for
//! planned edges are written (or left untouched when byte-identical), stale
//! rows are tombstoned. Large reconciliations use bounded intermediate mutation
//! commits; after an exact sorted readback, one sequence-guarded terminal commit
//! atomically publishes the per-family raw-row digest and its exact LedgerRef.
//! Consumers refuse intermediate state whose terminal marker does not match.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, ledger_key, prefix_range};
use calyx_aster::ledger_view::parse_aster_ledger_seq;
use calyx_aster::mvcc::{LatestOnlyReadbackStatus, tombstone_value};
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, LedgerRef, VaultStore};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde::{Deserialize, Serialize};

use crate::bounded_run::{
    MAX_MUTATION_BYTES_PER_COMMIT, MAX_MUTATION_ROWS_PER_COMMIT, RunReceipt, RunWorkspace,
};
use crate::{
    SimilarityEdge, SimilarityFamily, SimilarityFamilyStreamReport, SimilarityMetric,
    SimilarityNode, SimilarityPlanError, SimilarityPlannerConfig, hex_lower_bytes,
    stream_similarity_family_edges,
};

/// Graph CF key prefix for persisted SIM_* similarity edge rows.
pub const SIM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:sim-edge:v2:";
const LEGACY_SIM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:sim-edge:v1:";
/// Row schema tag for persisted SIM_* similarity edge rows.
pub const SCHEMA_SIM_EDGE_ROW: &str = "astrolabe-sim-edge-v2";
/// Ledger payload schema for a SIM_* persistence group commit.
pub const SIM_EDGE_LEDGER_SCHEMA: &str = "astrolabe.sim_edges.v2";
const SIM_SOURCE_ATTESTATION_SCHEMA: &str = "astrolabe.sim_source_attestation.v1";
const SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA: &str = "astrolabe.sim_source_attestation_ledger.v1";
const SIM_SOURCE_ATTESTATION_PREFIX: &[u8] = b"astrolabe:sim-source-attestation:v1:";
const SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX: &str = "astrolabe-sim-source-attestation:v1";
const SIM_FAMILY_DUMP_SCHEMA: &[u8] = b"astrolabe.sim_family_persisted_dump.v1";
/// Stable failure code for corrupt or inconsistent persisted SIM_* rows.
pub const ASTRO_SIM_EDGE_ROW_CORRUPT: &str = "ASTRO_SIM_EDGE_ROW_CORRUPT";
/// Stable failure code when the paired ledger entry cannot be recovered.
pub const ASTRO_SIM_EDGE_LEDGER_MISSING: &str = "ASTRO_SIM_EDGE_LEDGER_MISSING";
pub const ASTRO_SIM_EDGE_RUN_RESOURCE_EXHAUSTED: &str = "ASTRO_SIM_EDGE_RUN_RESOURCE_EXHAUSTED";

const SIM_SCAN_PAGE_ROWS: usize = 1_024;

const SIM_EDGE_REMEDIATION: &str = "regenerate SIM_* rows with astrolabe_weave::plan_similarity_family_run from a fresh source-bound plan";
const SIM_EDGE_LEDGER_REMEDIATION: &str =
    "verify the vault Ledger CF integrity, then re-run the SIM_* persistence group commit";

/// Persisted Graph CF row for one SIM_* similarity edge.
///
/// `weight_bits` / `threshold_bits` hold the exact IEEE-754 bit patterns so a
/// readback comparison against a recomputed plan is tolerance-0 by
/// construction (the same code path must be bit-stable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimEdgeGraphRow {
    /// Always [`SCHEMA_SIM_EDGE_ROW`].
    pub schema: String,
    /// Family wire name (`SIM_STRUCT`, `SIM_SEMANTIC`, `SIM_API`, `SIM_PROFILE`).
    pub family: String,
    /// Owning (lexicographically smaller) stable source-atom identity.
    pub source_id: String,
    /// Target stable source-atom identity.
    pub target_id: String,
    /// Non-unique source display/search metadata.
    pub source_qn: String,
    /// Non-unique target display/search metadata.
    pub target_qn: String,
    /// Source panel slot the family scores on.
    pub slot: u16,
    /// Graph edge-kind vocabulary code for the family's typed edge.
    pub etype: u16,
    /// Scoring metric name (`cosine`).
    pub metric: String,
    /// `f32::to_bits` of the admitted cosine weight.
    pub weight_bits: u32,
    /// `f32::to_bits` of the admission threshold in force when admitted.
    pub threshold_bits: u32,
    /// The edge's graph properties (family, metric, slot, score, threshold).
    pub props: BTreeMap<String, String>,
}

impl SimEdgeGraphRow {
    /// Returns the admitted cosine weight.
    pub fn weight(&self) -> f32 {
        f32::from_bits(self.weight_bits)
    }

    /// Returns the admission threshold recorded on the row.
    pub fn threshold(&self) -> f32 {
        f32::from_bits(self.threshold_bits)
    }

    /// Parses the persisted family wire name.
    pub fn similarity_family(&self) -> Option<SimilarityFamily> {
        SimilarityFamily::from_wire_name(&self.family)
    }

    fn from_edge(edge: &SimilarityEdge) -> Self {
        Self {
            schema: SCHEMA_SIM_EDGE_ROW.to_string(),
            family: edge.family.wire_name().to_string(),
            source_id: edge.source_id.clone(),
            target_id: edge.target_id.clone(),
            source_qn: edge.source_qn.clone(),
            target_qn: edge.target_qn.clone(),
            slot: edge.slot.get(),
            etype: edge.graph_edge_kind.code(),
            metric: edge.metric.as_str().to_string(),
            weight_bits: edge.weight.to_bits(),
            threshold_bits: edge.threshold.to_bits(),
            props: edge.graph_properties(),
        }
    }
}

/// One decoded, key-verified SIM_* row read back from the Graph CF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedSimilarityEdgeRow {
    /// Full Graph CF key the row was stored under.
    pub key: Vec<u8>,
    /// Decoded row.
    pub row: SimEdgeGraphRow,
}

/// Report for one complete SIM_* family persistence operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityPersistReport {
    /// Edges in the persisted plan.
    pub edge_count: usize,
    /// Rows written or rewritten in this commit.
    pub rows_written: usize,
    /// Rows already byte-identical and left untouched.
    pub rows_unchanged: usize,
    /// Stale rows tombstoned in this commit.
    pub rows_tombstoned: usize,
    /// Lowercase-hex blake3 of the canonical edge dump, as ledgered.
    pub edge_dump_hash: String,
    /// Whether this operation published a new terminal Graph marker. False is
    /// possible only for a true no-delta run that strictly revalidated and
    /// reused the already-current marker and its physical Ledger row.
    pub terminal_attestation_published: bool,
    /// Complete live family row count bound by the terminal marker.
    pub terminal_family_row_count: u64,
    /// Complete live family key/value bytes bound by the terminal marker.
    pub terminal_family_bytes: u64,
    /// Lowercase-hex BLAKE3 of the exact sorted raw family key/value stream.
    pub terminal_family_content_blake3: String,
    /// Ledger entries paired with the bounded mutation groups followed by the
    /// mandatory terminal family attestation. A no-delta operation contains
    /// exactly the terminal attestation.
    pub ledger_refs: Vec<LedgerRef>,
    /// Unforgeable mutation readback witnesses. A newly published terminal has
    /// one; a strictly reused terminal is independently revalidated but creates
    /// no mutation acknowledgement.
    pub fsv: Vec<FsvAck>,
    /// Physical bounded-run and mutation-group accounting.
    pub run: SimilarityRunTelemetry,
    /// Per-phase wall-clock millis of this persist (#23 latency telemetry):
    /// stable labels, measured values.
    pub timing_ms: PhaseTimings,
}

/// Wall-clock phase telemetry (#23).
///
/// Deliberately equality-neutral so report-level equality assertions stay
/// claims about persisted state, never about wall-clock.
#[derive(Debug, Clone, Default)]
pub struct PhaseTimings(pub Vec<(&'static str, u64)>);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SimilarityRunTelemetry {
    pub desired_rows: u64,
    pub desired_bytes: u64,
    pub existing_rows: u64,
    pub existing_bytes: u64,
    pub mutation_groups: usize,
    pub mutation_rows_high_water: usize,
    pub mutation_bytes_high_water: usize,
    pub final_rows_read_back: usize,
    pub final_bytes_read_back: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimilaritySourceAttestation {
    schema: String,
    family: String,
    row_count: u64,
    total_bytes: u64,
    content_blake3: String,
    ledger_seq: u64,
    ledger_hash: String,
    actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimilaritySourceAttestationLedgerPayload {
    schema: String,
    family: String,
    row_count: u64,
    total_bytes: u64,
    content_blake3: String,
}

#[derive(Debug)]
struct SimilarityFamilyReadback {
    snapshot: u64,
    selected_rows: usize,
    selected_bytes: u64,
    selected_semantic_hash: String,
    family_rows: u64,
    family_bytes: u64,
    family_content_blake3: String,
}

struct SimilarityAttestationReadbackExpectation<'a> {
    family: SimilarityFamily,
    state: &'a SimilarityFamilyReadback,
    actor: &'a str,
    commit_seq: u64,
    ledger_ref: &'a LedgerRef,
    subject: &'a SubjectId,
    payload: &'a [u8],
    marker_bytes: &'a [u8],
}

/// One source-generation-bound family plan whose encoded Graph rows live only
/// in a sealed sorted run. The type is deliberately opaque: it can only be
/// consumed by the matching bounded persistence function.
pub struct BoundedSimilarityFamilyPlan {
    family: SimilarityFamily,
    graph_snapshot_seq: u64,
    graph_generation: u64,
    edge_dump_hash: String,
    stream: SimilarityFamilyStreamReport,
    desired: RunReceipt,
    workspace: RunWorkspace,
}

impl BoundedSimilarityFamilyPlan {
    pub fn edge_count(&self) -> usize {
        self.stream.edge_count
    }

    pub fn stream_report(&self) -> &SimilarityFamilyStreamReport {
        &self.stream
    }
}

impl PartialEq for PhaseTimings {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for PhaseTimings {}

/// Builds the canonical Graph CF key for one SIM_* edge.
pub fn sim_edge_graph_key(family: SimilarityFamily, source_id: &str, target_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        SIM_EDGE_ROW_PREFIX.len() + 1 + 4 + source_id.len() + 4 + target_id.len(),
    );
    key.extend_from_slice(SIM_EDGE_ROW_PREFIX);
    key.push(family.sort_index());
    key.extend_from_slice(&(source_id.len() as u32).to_be_bytes());
    key.extend_from_slice(source_id.as_bytes());
    key.extend_from_slice(&(target_id.len() as u32).to_be_bytes());
    key.extend_from_slice(target_id.as_bytes());
    key
}

/// Plans one family directly into a source-bound, hash-sealed sorted run.
/// No complete edge `Vec`, encoded row map, or mutation batch exists.
pub fn plan_similarity_family_run<C>(
    vault: &AsterVault<C>,
    run_directory: impl Into<PathBuf>,
    source_binding: impl Into<String>,
    nodes: &[SimilarityNode],
    family: SimilarityFamily,
    config: &SimilarityPlannerConfig,
) -> calyx_core::Result<BoundedSimilarityFamilyPlan>
where
    C: Clock,
{
    refuse_legacy_similarity_rows(vault)?;
    let graph_snapshot_seq = vault.snapshot();
    let graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let workspace = RunWorkspace::create(
        run_directory,
        format!("similarity:{}", family.wire_name()),
        format!(
            "{};graph_snapshot_seq={graph_snapshot_seq};graph_generation={graph_generation}",
            source_binding.into()
        ),
    )?;
    let desired_path = workspace.directory().join("desired.run");
    let mut writer = workspace.writer("desired.run", MAX_MUTATION_BYTES_PER_COMMIT as u64)?;
    let mut dump_hasher = blake3::Hasher::new();
    let stream = stream_similarity_family_edges(nodes, family, config, |edges| {
        for edge in edges {
            update_edge_dump_hasher(&mut dump_hasher, &edge);
            let key = sim_edge_graph_key(edge.family, &edge.source_id, &edge.target_id);
            let value =
                serde_json::to_vec(&SimEdgeGraphRow::from_edge(&edge)).map_err(|error| {
                    SimilarityPlanError::PersistenceSinkFailure {
                        family,
                        message: format!("encode SIM_* run row: {error}"),
                    }
                })?;
            writer.push(&key, &value).map_err(|error| {
                SimilarityPlanError::PersistenceSinkFailure {
                    family,
                    message: format!("{}: {}", error.code, error.message),
                }
            })?;
        }
        Ok(())
    })
    .map_err(|error| sim_plan_failed(family, error))?;
    let desired = writer.finish(&desired_path)?;
    if desired.record_count != stream.edge_count as u64 {
        return Err(sim_edge_corrupt(format!(
            "{} stream reported {} edges but sealed {} desired rows",
            family.wire_name(),
            stream.edge_count,
            desired.record_count
        )));
    }
    Ok(BoundedSimilarityFamilyPlan {
        family,
        graph_snapshot_seq,
        graph_generation,
        edge_dump_hash: dump_hasher.finalize().to_hex().to_string(),
        stream,
        desired,
        workspace,
    })
}

pub fn persist_similarity_family_run<C>(
    vault: &AsterVault<C>,
    plan: BoundedSimilarityFamilyPlan,
    global_dump_hasher: &mut blake3::Hasher,
    actor: impl Into<String>,
) -> calyx_core::Result<SimilarityPersistReport>
where
    C: Clock,
{
    persist_similarity_family_run_owned(vault, plan, None, global_dump_hasher, actor.into())
}

pub fn persist_similarity_family_run_delta<C>(
    vault: &AsterVault<C>,
    plan: BoundedSimilarityFamilyPlan,
    owned_sources: &BTreeSet<String>,
    removed_symbol_ids: &BTreeSet<String>,
    global_dump_hasher: &mut blake3::Hasher,
    actor: impl Into<String>,
) -> calyx_core::Result<SimilarityPersistReport>
where
    C: Clock,
{
    persist_similarity_family_run_owned(
        vault,
        plan,
        Some((owned_sources, removed_symbol_ids)),
        global_dump_hasher,
        actor.into(),
    )
}

fn persist_similarity_family_run_owned<C>(
    vault: &AsterVault<C>,
    mut plan: BoundedSimilarityFamilyPlan,
    ownership: Option<(&BTreeSet<String>, &BTreeSet<String>)>,
    global_dump_hasher: &mut blake3::Hasher,
    actor: String,
) -> calyx_core::Result<SimilarityPersistReport>
where
    C: Clock,
{
    let mut timing_ms = Vec::new();
    let mut phase_start = std::time::Instant::now();
    ensure_graph_source_unchanged(vault, &plan, "before existing-row scan")?;
    let existing_path = plan.workspace.directory().join("existing.run");
    let mut existing_writer = plan
        .workspace
        .writer("existing.run", MAX_MUTATION_BYTES_PER_COMMIT as u64)?;
    scan_owned_similarity_rows(
        vault,
        plan.graph_snapshot_seq,
        plan.family,
        ownership,
        |key, value| existing_writer.push(key, value),
    )?;
    ensure_graph_source_unchanged(vault, &plan, "after existing-row scan")?;
    let existing = existing_writer.finish(&existing_path)?;
    let manifest = plan
        .workspace
        .seal(vec![plan.desired.clone(), existing.clone()])?;
    if manifest.source_binding.is_empty() {
        return Err(sim_edge_corrupt(
            "sealed similarity run lost its source binding".into(),
        ));
    }
    // Prove both complete runs before the first mutation. A truncated/corrupt
    // run therefore cannot produce even a partial unpublished reconciliation.
    verify_complete_run(&plan.workspace, &plan.desired)?;
    verify_complete_run(&plan.workspace, &existing)?;
    timing_ms.push((
        "seal_and_verify_runs",
        phase_start.elapsed().as_millis() as u64,
    ));

    phase_start = std::time::Instant::now();
    let mut desired_reader = plan.workspace.open_reader(&plan.desired)?;
    let mut existing_reader = plan.workspace.open_reader(&existing)?;
    let mut desired_row = desired_reader.next_record()?;
    let mut existing_row = existing_reader.next_record()?;
    let tombstone = tombstone_value();
    let mut batch = Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new();
    let mut batch_bytes = 0usize;
    let mut ledger_refs = Vec::new();
    let mut fsv = Vec::new();
    let mut run = SimilarityRunTelemetry {
        desired_rows: plan.desired.record_count,
        desired_bytes: plan.desired.content_bytes,
        existing_rows: existing.record_count,
        existing_bytes: existing.content_bytes,
        ..SimilarityRunTelemetry::default()
    };
    let mut rows_written = 0usize;
    let mut rows_unchanged = 0usize;
    let mut rows_tombstoned = 0usize;
    let mut batch_index = 0usize;

    while desired_row.is_some() || existing_row.is_some() {
        let ordering = match (&desired_row, &existing_row) {
            (Some((desired_key, _)), Some((existing_key, _))) => desired_key.cmp(existing_key),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        let mutation = match ordering {
            Ordering::Less => {
                let (key, value) = desired_row.take().ok_or_else(|| {
                    sim_edge_corrupt(
                        "SIM merge selected desired-only ordering without a desired row"
                            .to_string(),
                    )
                })?;
                desired_row = desired_reader.next_record()?;
                rows_written = rows_written
                    .checked_add(1)
                    .ok_or_else(|| sim_run_resource_exhausted("SIM write count overflow"))?;
                Some((ColumnFamily::Graph, key, value))
            }
            Ordering::Equal => {
                let (key, value) = desired_row.take().ok_or_else(|| {
                    sim_edge_corrupt(
                        "SIM merge selected equal ordering without a desired row".to_string(),
                    )
                })?;
                let (_, existing_value) = existing_row.take().ok_or_else(|| {
                    sim_edge_corrupt(
                        "SIM merge selected equal ordering without an existing row".to_string(),
                    )
                })?;
                desired_row = desired_reader.next_record()?;
                existing_row = existing_reader.next_record()?;
                if value == existing_value {
                    rows_unchanged = rows_unchanged.checked_add(1).ok_or_else(|| {
                        sim_run_resource_exhausted("SIM unchanged count overflow")
                    })?;
                    None
                } else {
                    rows_written = rows_written
                        .checked_add(1)
                        .ok_or_else(|| sim_run_resource_exhausted("SIM write count overflow"))?;
                    Some((ColumnFamily::Graph, key, value))
                }
            }
            Ordering::Greater => {
                let (key, _) = existing_row.take().ok_or_else(|| {
                    sim_edge_corrupt(
                        "SIM merge selected existing-only ordering without an existing row"
                            .to_string(),
                    )
                })?;
                existing_row = existing_reader.next_record()?;
                rows_tombstoned = rows_tombstoned
                    .checked_add(1)
                    .ok_or_else(|| sim_run_resource_exhausted("SIM tombstone count overflow"))?;
                Some((ColumnFamily::Graph, key, tombstone.clone()))
            }
        };
        if let Some(mutation) = mutation {
            let mutation_bytes = mutation_retained_bytes(&mutation)?;
            if mutation_bytes > MAX_MUTATION_BYTES_PER_COMMIT {
                return Err(sim_run_resource_exhausted(format!(
                    "one {} mutation retains {mutation_bytes} bytes, exceeding the atomic group limit {MAX_MUTATION_BYTES_PER_COMMIT}",
                    plan.family.wire_name()
                )));
            }
            let next_batch_bytes = batch_bytes
                .checked_add(mutation_bytes)
                .ok_or_else(|| sim_run_resource_exhausted("SIM mutation byte count overflow"))?;
            if !batch.is_empty()
                && (batch.len() == MAX_MUTATION_ROWS_PER_COMMIT
                    || next_batch_bytes > MAX_MUTATION_BYTES_PER_COMMIT)
            {
                let (ledger_ref, ack) = commit_similarity_batch(
                    vault,
                    plan.family,
                    &plan.edge_dump_hash,
                    batch_index,
                    &actor,
                    std::mem::take(&mut batch),
                )?;
                ledger_refs.push(ledger_ref);
                fsv.push(ack);
                run.mutation_groups = run.mutation_groups.checked_add(1).ok_or_else(|| {
                    sim_run_resource_exhausted("SIM mutation group count overflow")
                })?;
                batch_index = batch_index
                    .checked_add(1)
                    .ok_or_else(|| sim_run_resource_exhausted("SIM batch index overflow"))?;
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes
                .checked_add(mutation_bytes)
                .ok_or_else(|| sim_run_resource_exhausted("SIM mutation byte count overflow"))?;
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
        let (ledger_ref, ack) = commit_similarity_batch(
            vault,
            plan.family,
            &plan.edge_dump_hash,
            batch_index,
            &actor,
            batch,
        )?;
        ledger_refs.push(ledger_ref);
        fsv.push(ack);
        run.mutation_groups = run
            .mutation_groups
            .checked_add(1)
            .ok_or_else(|| sim_run_resource_exhausted("SIM mutation group count overflow"))?;
    }
    timing_ms.push((
        "merge_commit_readback",
        phase_start.elapsed().as_millis() as u64,
    ));

    phase_start = std::time::Instant::now();
    // The mutation groups above are deliberately intermediate. Projection is
    // authorized only by the terminal marker published after one exact,
    // sorted readback of the complete family. Build the caller's aggregate
    // hash on a clone so a failed CAS cannot contaminate caller state.
    let mut candidate_global_dump_hasher = global_dump_hasher.clone();
    let final_state = read_back_similarity_family_state(
        vault,
        plan.family,
        ownership,
        &mut candidate_global_dump_hasher,
    )?;
    run.final_rows_read_back = final_state.selected_rows;
    run.final_bytes_read_back = final_state.selected_bytes;
    if final_state.selected_rows != plan.stream.edge_count
        || final_state.selected_semantic_hash != plan.edge_dump_hash
    {
        return Err(sim_edge_corrupt(format!(
            "{} final physical readback differs from the desired run: expected_rows={}, observed_rows={}, expected_hash={}, observed_hash={}",
            plan.family.wire_name(),
            plan.stream.edge_count,
            final_state.selected_rows,
            plan.edge_dump_hash,
            final_state.selected_semantic_hash,
        )));
    }
    let had_mutations = !ledger_refs.is_empty();
    let (terminal_ref, terminal_ack, terminal_attestation_published) = if had_mutations {
        let (reference, ack) =
            publish_similarity_source_attestation(vault, plan.family, &final_state, &actor)?;
        (reference, Some(ack), true)
    } else if let Some(reference) =
        read_existing_similarity_source_attestation(vault, plan.family, &final_state)?
    {
        (reference, None, false)
    } else {
        let (reference, ack) =
            publish_similarity_source_attestation(vault, plan.family, &final_state, &actor)?;
        (reference, Some(ack), true)
    };
    ledger_refs.push(terminal_ref);
    if let Some(ack) = terminal_ack {
        fsv.push(ack);
    }
    plan.workspace.cleanup()?;
    *global_dump_hasher = candidate_global_dump_hasher;
    timing_ms.push((
        "final_state_and_run_cleanup",
        phase_start.elapsed().as_millis() as u64,
    ));

    Ok(SimilarityPersistReport {
        edge_count: plan.stream.edge_count,
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        edge_dump_hash: plan.edge_dump_hash,
        terminal_attestation_published,
        terminal_family_row_count: final_state.family_rows,
        terminal_family_bytes: final_state.family_bytes,
        terminal_family_content_blake3: final_state.family_content_blake3,
        ledger_refs,
        fsv,
        run,
        timing_ms: PhaseTimings(timing_ms),
    })
}

fn similarity_source_attestation_key(family: SimilarityFamily) -> Vec<u8> {
    let mut key = SIM_SOURCE_ATTESTATION_PREFIX.to_vec();
    key.extend_from_slice(family.wire_name().as_bytes());
    key
}

fn verify_complete_run(workspace: &RunWorkspace, receipt: &RunReceipt) -> calyx_core::Result<()> {
    let mut reader = workspace.open_reader(receipt)?;
    while reader.next_record()?.is_some() {}
    let observed = reader.finish()?;
    if observed != *receipt {
        return Err(sim_edge_corrupt(format!(
            "run {:?} receipt changed during pre-mutation verification",
            receipt.file_name
        )));
    }
    Ok(())
}

fn ensure_graph_source_unchanged<C>(
    vault: &AsterVault<C>,
    plan: &BoundedSimilarityFamilyPlan,
    phase: &str,
) -> calyx_core::Result<()>
where
    C: Clock,
{
    ensure_bounded_sim_storage(&vault.latest_only_readback_status(), phase)?;
    let observed_snapshot = vault.snapshot();
    let observed_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    if observed_snapshot != plan.graph_snapshot_seq || observed_generation != plan.graph_generation
    {
        return Err(sim_edge_corrupt(format!(
            "{} source changed at {phase}: expected_snapshot={}, observed_snapshot={observed_snapshot}, expected_graph_generation={}, observed_graph_generation={observed_generation}",
            plan.family.wire_name(),
            plan.graph_snapshot_seq,
            plan.graph_generation,
        )));
    }
    Ok(())
}

fn ensure_bounded_sim_storage(
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
        return Err(sim_edge_corrupt(format!(
            "{phase} requires latest-only storage, an empty MVCC overlay, and every active memtable inside one positive hard cap; observed latest_only={}, overlay_keys={}, overlay_versions={}, overlay_bytes={}, memtable_byte_cap={}, invalid_cf={invalid_cf:?}",
            status.latest_only,
            status.overlay_keys,
            status.overlay_versions,
            status.overlay_bytes,
            status.memtable_byte_cap,
        )));
    }
    Ok(())
}

fn scan_owned_similarity_rows<C, F>(
    vault: &AsterVault<C>,
    snapshot: u64,
    family: SimilarityFamily,
    ownership: Option<(&BTreeSet<String>, &BTreeSet<String>)>,
    mut emit: F,
) -> calyx_core::Result<()>
where
    C: Clock,
    F: FnMut(&[u8], &[u8]) -> calyx_core::Result<()>,
{
    match ownership {
        Some((owned_sources, removed)) if removed.is_empty() => {
            for source in owned_sources {
                let prefix = sim_edge_source_prefix(family, source);
                vault.scan_cf_range_pages_at(
                    snapshot,
                    ColumnFamily::Graph,
                    &prefix_range(&prefix),
                    SIM_SCAN_PAGE_ROWS,
                    |page| {
                        for (key, value) in page {
                            let row = decode_similarity_row(&key, &value, Some(family))?;
                            if row.source_id != *source {
                                return Err(sim_edge_corrupt(format!(
                                    "source-prefix scan for {source:?} returned {} -> {}",
                                    row.source_id, row.target_id
                                )));
                            }
                            emit(&key, &value)?;
                        }
                        Ok(())
                    },
                )?;
            }
        }
        ownership => {
            let mut prefix = SIM_EDGE_ROW_PREFIX.to_vec();
            prefix.push(family.sort_index());
            vault.scan_cf_range_pages_at(
                snapshot,
                ColumnFamily::Graph,
                &prefix_range(&prefix),
                SIM_SCAN_PAGE_ROWS,
                |page| {
                    for (key, value) in page {
                        let row = decode_similarity_row(&key, &value, Some(family))?;
                        let selected = ownership.is_none_or(|(owned_sources, removed)| {
                            owned_sources.contains(&row.source_id)
                                || removed.contains(&row.source_id)
                                || removed.contains(&row.target_id)
                        });
                        if selected {
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

fn read_back_similarity_family_state<C>(
    vault: &AsterVault<C>,
    family: SimilarityFamily,
    ownership: Option<(&BTreeSet<String>, &BTreeSet<String>)>,
    global_dump_hasher: &mut blake3::Hasher,
) -> calyx_core::Result<SimilarityFamilyReadback>
where
    C: Clock,
{
    ensure_bounded_sim_storage(
        &vault.latest_only_readback_status(),
        "terminal family pre-scan",
    )?;
    let snapshot = vault.latest_seq();
    let mut prefix = SIM_EDGE_ROW_PREFIX.to_vec();
    prefix.push(family.sort_index());
    let mut selected_rows = 0usize;
    let mut selected_bytes = 0u64;
    let mut selected_hasher = blake3::Hasher::new();
    let mut family_rows = 0u64;
    let mut family_bytes = 0u64;
    let mut family_hasher = blake3::Hasher::new();
    update_hash_part(&mut family_hasher, SIM_FAMILY_DUMP_SCHEMA);
    let mut previous_key = None::<Vec<u8>>;
    vault.scan_cf_range_pages_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(&prefix),
        SIM_SCAN_PAGE_ROWS,
        |page| {
            for (key, value) in page {
                if previous_key
                    .as_deref()
                    .is_some_and(|previous| previous >= key.as_slice())
                {
                    return Err(sim_edge_corrupt(format!(
                        "{} final family scan is not strictly key-sorted at {}",
                        family.wire_name(),
                        hex_lower_bytes(&key)
                    )));
                }
                previous_key = Some(key.clone());
                let row = decode_similarity_row(&key, &value, Some(family))?;
                update_hash_part(&mut family_hasher, &key);
                update_hash_part(&mut family_hasher, &value);
                family_rows = family_rows
                    .checked_add(1)
                    .ok_or_else(|| sim_run_resource_exhausted("family SIM row count overflow"))?;
                family_bytes = family_bytes
                    .checked_add(key.len() as u64)
                    .and_then(|total| total.checked_add(value.len() as u64))
                    .ok_or_else(|| sim_run_resource_exhausted("family SIM byte count overflow"))?;
                let selected = ownership.is_none_or(|(owned_sources, removed)| {
                    owned_sources.contains(&row.source_id)
                        || removed.contains(&row.source_id)
                        || removed.contains(&row.target_id)
                });
                if selected {
                    update_row_dump_hasher(&mut selected_hasher, &row)?;
                    update_row_dump_hasher(global_dump_hasher, &row)?;
                    selected_rows = selected_rows.checked_add(1).ok_or_else(|| {
                        sim_run_resource_exhausted("selected SIM row count overflow")
                    })?;
                    selected_bytes = selected_bytes
                        .checked_add(key.len() as u64)
                        .and_then(|total| total.checked_add(value.len() as u64))
                        .ok_or_else(|| {
                            sim_run_resource_exhausted("selected SIM byte count overflow")
                        })?;
                }
            }
            Ok(())
        },
    )?;
    ensure_bounded_sim_storage(
        &vault.latest_only_readback_status(),
        "terminal family post-scan",
    )?;
    Ok(SimilarityFamilyReadback {
        snapshot,
        selected_rows,
        selected_bytes,
        selected_semantic_hash: selected_hasher.finalize().to_hex().to_string(),
        family_rows,
        family_bytes,
        family_content_blake3: family_hasher.finalize().to_hex().to_string(),
    })
}

fn read_existing_similarity_source_attestation<C>(
    vault: &AsterVault<C>,
    family: SimilarityFamily,
    state: &SimilarityFamilyReadback,
) -> calyx_core::Result<Option<LedgerRef>>
where
    C: Clock,
{
    let marker_key = similarity_source_attestation_key(family);
    let Some(marker_bytes) = vault.read_cf_at(state.snapshot, ColumnFamily::Graph, &marker_key)?
    else {
        if vault.latest_seq() != state.snapshot {
            return Err(sim_edge_corrupt(format!(
                "{} source changed while confirming terminal-marker absence: expected_snapshot={}, observed_snapshot={}",
                family.wire_name(),
                state.snapshot,
                vault.latest_seq()
            )));
        }
        return Ok(None);
    };
    let marker: SimilaritySourceAttestation =
        serde_json::from_slice(&marker_bytes).map_err(|error| {
            sim_edge_corrupt(format!(
                "decode existing {} terminal source marker: {error}",
                family.wire_name()
            ))
        })?;
    let canonical_marker_bytes = serde_json::to_vec(&marker).map_err(|error| {
        sim_edge_corrupt(format!(
            "encode canonical existing {} terminal source marker: {error}",
            family.wire_name()
        ))
    })?;
    if canonical_marker_bytes != marker_bytes
        || marker.schema != SIM_SOURCE_ATTESTATION_SCHEMA
        || marker.family != family.wire_name()
        || marker.row_count != state.family_rows
        || marker.total_bytes != state.family_bytes
        || marker.content_blake3 != state.family_content_blake3
    {
        return Err(sim_edge_corrupt(format!(
            "{} existing terminal source marker does not exactly match the current full-family readback",
            family.wire_name()
        )));
    }
    let ledger_bytes = vault
        .read_cf_at(
            state.snapshot,
            ColumnFamily::Ledger,
            &ledger_key(marker.ledger_seq),
        )?
        .ok_or_else(|| {
            sim_edge_corrupt(format!(
                "{} existing terminal marker names absent Ledger row {}",
                family.wire_name(),
                marker.ledger_seq
            ))
        })?;
    let entry = decode_ledger(&ledger_bytes)?;
    let expected_payload_model = SimilaritySourceAttestationLedgerPayload {
        schema: SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA.to_string(),
        family: family.wire_name().to_string(),
        row_count: state.family_rows,
        total_bytes: state.family_bytes,
        content_blake3: state.family_content_blake3.clone(),
    };
    let expected_payload = serde_json::to_vec(&expected_payload_model).map_err(|error| {
        sim_edge_corrupt(format!(
            "encode expected existing {} terminal Ledger payload: {error}",
            family.wire_name()
        ))
    })?;
    let subject = similarity_source_attestation_subject(family, state);
    if entry.seq != marker.ledger_seq
        || marker.ledger_hash != hex_lower_bytes(&entry.entry_hash)
        || entry.kind != EntryKind::Ingest
        || entry.subject != subject
        || entry.payload != expected_payload
        || entry.actor != ActorId::Service(marker.actor)
    {
        return Err(sim_edge_corrupt(format!(
            "{} existing terminal Ledger row disagrees with marker kind/subject/payload/actor/ref",
            family.wire_name()
        )));
    }
    let observed_snapshot = vault.latest_seq();
    if observed_snapshot != state.snapshot {
        return Err(sim_edge_corrupt(format!(
            "{} source changed during terminal-marker reuse validation: expected_snapshot={}, observed_snapshot={observed_snapshot}",
            family.wire_name(),
            state.snapshot
        )));
    }
    Ok(Some(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    }))
}

fn publish_similarity_source_attestation<C>(
    vault: &AsterVault<C>,
    family: SimilarityFamily,
    state: &SimilarityFamilyReadback,
    actor: &str,
) -> calyx_core::Result<(LedgerRef, FsvAck)>
where
    C: Clock,
{
    let payload_model = SimilaritySourceAttestationLedgerPayload {
        schema: SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA.to_string(),
        family: family.wire_name().to_string(),
        row_count: state.family_rows,
        total_bytes: state.family_bytes,
        content_blake3: state.family_content_blake3.clone(),
    };
    let payload = serde_json::to_vec(&payload_model).map_err(|error| {
        sim_edge_corrupt(format!("encode terminal SIM attestation payload: {error}"))
    })?;
    let subject = similarity_source_attestation_subject(family, state);
    let ledger_actor = ActorId::Service(actor.to_string());
    let marker_key = similarity_source_attestation_key(family);
    let marker_family = family.wire_name().to_string();
    let marker_actor = actor.to_string();
    let marker_content_blake3 = state.family_content_blake3.clone();
    let marker_rows = state.family_rows;
    let marker_bytes = state.family_bytes;
    let (commit, expected_marker_bytes) = vault
        .write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
            state.snapshot,
            Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new(),
            EntryKind::Ingest,
            subject.clone(),
            payload.clone(),
            ledger_actor.clone(),
            move |ledger_ref, _| {
                let marker = SimilaritySourceAttestation {
                    schema: SIM_SOURCE_ATTESTATION_SCHEMA.to_string(),
                    family: marker_family,
                    row_count: marker_rows,
                    total_bytes: marker_bytes,
                    content_blake3: marker_content_blake3,
                    ledger_seq: ledger_ref.seq,
                    ledger_hash: hex_lower_bytes(&ledger_ref.hash),
                    actor: marker_actor,
                };
                let value = serde_json::to_vec(&marker).map_err(|error| {
                    sim_edge_corrupt(format!("encode terminal SIM source marker: {error}"))
                })?;
                Ok((
                    vec![(ColumnFamily::Graph, marker_key, value.clone())],
                    value,
                ))
            },
        )?;
    if commit.data_row_digests.len() != 1
        || commit.data_row_digests[0].cf != ColumnFamily::Graph
        || commit.data_row_digests[0].key != similarity_source_attestation_key(family)
        || commit.data_row_digests[0].tombstoned
    {
        return Err(sim_edge_corrupt(format!(
            "{} terminal attestation commit returned an unexpected derived-row receipt",
            family.wire_name()
        )));
    }
    vault.flush()?;
    verify_similarity_source_attestation_publication(
        vault,
        &SimilarityAttestationReadbackExpectation {
            family,
            state,
            actor,
            commit_seq: commit.seq,
            ledger_ref: &commit.ledger_ref,
            subject: &subject,
            payload: &payload,
            marker_bytes: &expected_marker_bytes,
        },
    )?;
    let mut fsv_plan = VaultMutationPlan::new(
        "persist_similarity_edges_terminal_attestation",
        EntryKind::Ingest,
        &ledger_actor,
        &subject,
    );
    for row in &commit.data_row_digests {
        fsv_plan.push_content_hash(row.cf, row.key.clone(), row.value_blake3);
    }
    let ack = fsv_plan.verify_committed_with_ledger_ref(vault, commit.seq, &commit.ledger_ref)?;
    Ok((commit.ledger_ref, ack))
}

fn verify_similarity_source_attestation_publication<C>(
    vault: &AsterVault<C>,
    expected: &SimilarityAttestationReadbackExpectation<'_>,
) -> calyx_core::Result<()>
where
    C: Clock,
{
    let family = expected.family;
    let state = expected.state;
    let actor = expected.actor;
    let commit_seq = expected.commit_seq;
    let ledger_ref = expected.ledger_ref;
    let subject = expected.subject;
    let payload = expected.payload;
    let expected_marker_bytes = expected.marker_bytes;
    let marker_key = similarity_source_attestation_key(family);
    let observed_marker = vault
        .read_cf_at(commit_seq, ColumnFamily::Graph, &marker_key)?
        .ok_or_else(|| {
            sim_edge_corrupt(format!(
                "{} terminal source marker is absent at commit readback",
                family.wire_name()
            ))
        })?;
    if observed_marker.as_slice() != expected_marker_bytes {
        return Err(sim_edge_corrupt(format!(
            "{} terminal source marker differs at commit readback",
            family.wire_name()
        )));
    }
    let marker: SimilaritySourceAttestation = serde_json::from_slice(&observed_marker)
        .map_err(|error| sim_edge_corrupt(format!("decode terminal SIM marker: {error}")))?;
    if marker.schema != SIM_SOURCE_ATTESTATION_SCHEMA
        || marker.family != family.wire_name()
        || marker.row_count != state.family_rows
        || marker.total_bytes != state.family_bytes
        || marker.content_blake3 != state.family_content_blake3
        || marker.ledger_seq != ledger_ref.seq
        || marker.ledger_hash != hex_lower_bytes(&ledger_ref.hash)
        || marker.actor != actor
    {
        return Err(sim_edge_corrupt(format!(
            "{} terminal source marker fields differ from the exact readback/ledger receipt",
            family.wire_name()
        )));
    }
    let ledger_bytes = vault
        .read_cf_at(
            commit_seq,
            ColumnFamily::Ledger,
            &ledger_key(ledger_ref.seq),
        )?
        .ok_or_else(|| {
            sim_edge_corrupt(format!(
                "{} terminal attestation Ledger row {} is absent",
                family.wire_name(),
                ledger_ref.seq
            ))
        })?;
    let entry = decode_ledger(&ledger_bytes)?;
    if entry.seq != ledger_ref.seq
        || entry.entry_hash != ledger_ref.hash
        || entry.kind != EntryKind::Ingest
        || &entry.subject != subject
        || entry.payload.as_slice() != payload
        || entry.actor != ActorId::Service(actor.to_string())
    {
        return Err(sim_edge_corrupt(format!(
            "{} terminal attestation Ledger row differs from its exact publication receipt",
            family.wire_name()
        )));
    }
    Ok(())
}

fn similarity_source_attestation_subject(
    family: SimilarityFamily,
    state: &SimilarityFamilyReadback,
) -> SubjectId {
    SubjectId::Query(
        format!(
            "{SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX}:{}:{}:{}:{}",
            family.wire_name(),
            state.family_rows,
            state.family_bytes,
            state.family_content_blake3
        )
        .into_bytes(),
    )
}

fn commit_similarity_batch<C>(
    vault: &AsterVault<C>,
    family: SimilarityFamily,
    edge_dump_hash: &str,
    batch_index: usize,
    actor: &str,
    batch: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
) -> calyx_core::Result<(LedgerRef, FsvAck)>
where
    C: Clock,
{
    if batch.is_empty()
        || batch.len() > MAX_MUTATION_ROWS_PER_COMMIT
        || mutation_batch_retained_bytes(&batch)? > MAX_MUTATION_BYTES_PER_COMMIT
    {
        return Err(sim_run_resource_exhausted(format!(
            "{} mutation group {batch_index} violates the bounded commit contract: rows={}, bytes={}",
            family.wire_name(),
            batch.len(),
            mutation_batch_retained_bytes(&batch)?
        )));
    }
    let mutation_hash = mutation_batch_hash(&batch);
    let payload = similarity_audit_payload(
        family,
        0,
        0,
        0,
        0,
        edge_dump_hash,
        Some((batch_index, batch.len(), &mutation_hash)),
    )?;
    let subject = SubjectId::Query(
        format!("astrolabe-sim-edges:{edge_dump_hash}:batch:{batch_index}:{mutation_hash}")
            .into_bytes(),
    );
    let actor = ActorId::Service(actor.to_string());
    let commit = vault.write_cf_batch_with_ledger_entry_with_row_digests(
        batch,
        EntryKind::Ingest,
        subject.clone(),
        payload,
        actor.clone(),
    )?;
    let mut fsv_plan = VaultMutationPlan::new(
        "persist_similarity_edges_bounded",
        EntryKind::Ingest,
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

fn similarity_audit_payload(
    family: SimilarityFamily,
    edge_count: usize,
    rows_written: usize,
    rows_unchanged: usize,
    rows_tombstoned: usize,
    edge_dump_hash: &str,
    batch: Option<(usize, usize, &str)>,
) -> calyx_core::Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "schema": SIM_EDGE_LEDGER_SCHEMA,
        "family": family.wire_name(),
        "edge_count": edge_count,
        "rows_written": rows_written,
        "rows_unchanged": rows_unchanged,
        "rows_tombstoned": rows_tombstoned,
        "edge_dump_hash": edge_dump_hash,
        "batch": batch.map(|(index, rows, mutation_hash)| serde_json::json!({
            "index": index,
            "rows": rows,
            "mutation_hash": mutation_hash,
        })),
    }))
    .map_err(|error| sim_edge_corrupt(format!("encode SIM_* ledger payload: {error}")))
}

fn mutation_retained_bytes(
    mutation: &(ColumnFamily, Vec<u8>, Vec<u8>),
) -> calyx_core::Result<usize> {
    mutation
        .0
        .name()
        .len()
        .checked_add(mutation.1.len())
        .and_then(|total| total.checked_add(mutation.2.len()))
        .ok_or_else(|| sim_run_resource_exhausted("SIM mutation retained-byte overflow"))
}

fn mutation_batch_retained_bytes(
    batch: &[(ColumnFamily, Vec<u8>, Vec<u8>)],
) -> calyx_core::Result<usize> {
    batch.iter().try_fold(0usize, |total, mutation| {
        total
            .checked_add(mutation_retained_bytes(mutation)?)
            .ok_or_else(|| sim_run_resource_exhausted("SIM mutation-group byte overflow"))
    })
}

fn mutation_batch_hash(batch: &[(ColumnFamily, Vec<u8>, Vec<u8>)]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrolabe.sim.mutation-batch.v1");
    for (cf, key, value) in batch {
        update_hash_part(&mut hasher, cf.name().as_bytes());
        update_hash_part(&mut hasher, key);
        update_hash_part(&mut hasher, value);
    }
    hasher.finalize().to_hex().to_string()
}

fn update_hash_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn sim_edge_source_prefix(family: SimilarityFamily, source_id: &str) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(SIM_EDGE_ROW_PREFIX.len() + 1 + 4 + source_id.len());
    prefix.extend_from_slice(SIM_EDGE_ROW_PREFIX);
    prefix.push(family.sort_index());
    prefix.extend_from_slice(&(source_id.len() as u32).to_be_bytes());
    prefix.extend_from_slice(source_id.as_bytes());
    prefix
}

fn update_edge_dump_hasher(hasher: &mut blake3::Hasher, edge: &SimilarityEdge) {
    let line = format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:08x}\t{:08x}\n",
        edge.family.wire_name(),
        edge.source_id,
        edge.target_id,
        edge.source_qn,
        edge.target_qn,
        edge.slot.get(),
        edge.graph_edge_kind.as_str(),
        edge.metric.as_str(),
        edge.weight.to_bits(),
        edge.threshold.to_bits(),
    );
    hasher.update(line.as_bytes());
}

fn update_row_dump_hasher(hasher: &mut blake3::Hasher, row: &SimEdgeGraphRow) -> Result<()> {
    let family = row.similarity_family().ok_or_else(|| {
        sim_edge_corrupt(format!(
            "validated SIM row contains unknown family {:?}",
            row.family
        ))
    })?;
    let line = format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:08x}\t{:08x}\n",
        row.family,
        row.source_id,
        row.target_id,
        row.source_qn,
        row.target_qn,
        row.slot,
        family.graph_edge_kind().as_str(),
        row.metric,
        row.weight_bits,
        row.threshold_bits,
    );
    hasher.update(line.as_bytes());
    Ok(())
}

fn decode_similarity_row(
    key: &[u8],
    value: &[u8],
    expected_family: Option<SimilarityFamily>,
) -> calyx_core::Result<SimEdgeGraphRow> {
    let row: SimEdgeGraphRow = serde_json::from_slice(value).map_err(|error| {
        sim_edge_corrupt(format!(
            "decode SIM_* row {}: {error}",
            hex_lower_bytes(key)
        ))
    })?;
    if row.schema != SCHEMA_SIM_EDGE_ROW {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row {} carries schema {:?}",
            hex_lower_bytes(key),
            row.schema
        )));
    }
    let Some(family) = row.similarity_family() else {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row {} names unknown family {:?}",
            hex_lower_bytes(key),
            row.family
        )));
    };
    if expected_family.is_some_and(|expected| expected != family)
        || row.slot != family.slot().get()
        || row.etype != family.graph_edge_kind().code()
        || row.metric != SimilarityMetric::Cosine.as_str()
    {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row {} disagrees with family {} metadata",
            hex_lower_bytes(key),
            family
        )));
    }
    let weight = row.weight();
    let threshold = row.threshold();
    if !weight.is_finite()
        || !(0.0..=1.0).contains(&weight)
        || !threshold.is_finite()
        || !(0.0..=1.0).contains(&threshold)
    {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row {} carries a non-finite or out-of-range score/threshold",
            hex_lower_bytes(key)
        )));
    }
    if row.source_id.trim().is_empty() || row.target_id.trim().is_empty() {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row {} carries an empty stable endpoint identity",
            hex_lower_bytes(key)
        )));
    }
    if key != sim_edge_graph_key(family, &row.source_id, &row.target_id) {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row key {} does not match its decoded fields",
            hex_lower_bytes(key)
        )));
    }
    let expected_props = BTreeMap::from([
        ("family".to_string(), family.wire_name().to_string()),
        (
            "metric".to_string(),
            SimilarityMetric::Cosine.as_str().to_string(),
        ),
        ("source_atom_id".to_string(), row.source_id.clone()),
        ("target_atom_id".to_string(), row.target_id.clone()),
        ("slot_id".to_string(), row.slot.to_string()),
        ("score".to_string(), crate::format_score(weight)),
        ("threshold".to_string(), crate::format_score(threshold)),
    ]);
    if row.props != expected_props {
        return Err(sim_edge_corrupt(format!(
            "SIM_* row {} properties disagree with its exact typed fields",
            hex_lower_bytes(key)
        )));
    }
    Ok(row)
}

fn sim_plan_failed(family: SimilarityFamily, error: SimilarityPlanError) -> CalyxError {
    CalyxError {
        code: "ASTRO_WEAVE_SIM_PLAN_FAILED",
        message: format!("{} bounded plan failed: {error}", family.wire_name()),
        remediation: "preserve the unpublished shadow generation and inspect the exact ANN/planner/run diagnostic; do not substitute an in-memory plan or another candidate strategy",
    }
}

fn sim_run_resource_exhausted(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_SIM_EDGE_RUN_RESOURCE_EXHAUSTED,
        message: message.into(),
        remediation: "preserve the unpublished shadow generation and inspect the exact row/group byte measurement; do not raise the bound or split one logical row",
    }
}

/// Two-pass physical SIM scan that expands a changed-symbol set through exactly
/// two persisted neighbor hops without retaining the corpus edge table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedSimilarityRegionScan {
    /// Changed symbols plus their persisted neighbors through two hops.
    pub region: BTreeSet<String>,
    /// Physical page callbacks observed across both passes.
    pub pages: usize,
    /// Physical SIM rows decoded across both passes.
    pub rows_scanned: usize,
    /// Largest physical page delivered by the bounded scanner.
    pub page_rows_high_water: usize,
}

/// Physical receipt for one bounded, generation-stable scan of every SIM_* row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimilarityPhysicalScan {
    /// Vault sequence held for the complete scan.
    pub snapshot_seq: u64,
    /// Graph-CF generation proved unchanged across the scan.
    pub graph_generation: u64,
    /// Number of bounded page callbacks.
    pub pages: usize,
    /// Largest number of rows retained by one page callback.
    pub page_rows_high_water: usize,
    /// Largest encoded key/value byte total retained by one page callback.
    pub page_bytes_high_water: u64,
    /// Total decoded SIM_* rows.
    pub rows_scanned: usize,
    /// Total encoded SIM_* key/value bytes.
    pub bytes_scanned: u64,
    /// Canonical semantic dump digest of the complete physical SIM_* surface.
    pub edge_dump_hash: String,
}

/// Reads and key-verifies the complete persisted SIM_* surface without
/// materializing it, returning the same canonical dump hash used by planning.
pub fn scan_similarity_physical_state<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<SimilarityPhysicalScan>
where
    C: Clock,
{
    refuse_legacy_similarity_rows(vault)?;
    let storage_before = vault.latest_only_readback_status();
    ensure_bounded_sim_storage(&storage_before, "global similarity pre-scan")?;
    let snapshot = vault.snapshot();
    let graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let mut pages = 0usize;
    let mut page_rows_high_water = 0usize;
    let mut page_bytes_high_water = 0u64;
    let mut rows_scanned = 0usize;
    let mut bytes_scanned = 0u64;
    let mut dump_hasher = blake3::Hasher::new();
    vault.scan_cf_range_pages_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_EDGE_ROW_PREFIX),
        SIM_SCAN_PAGE_ROWS,
        |page| {
            pages = pages
                .checked_add(1)
                .ok_or_else(|| sim_run_resource_exhausted("global SIM page count overflow"))?;
            page_rows_high_water = page_rows_high_water.max(page.len());
            let page_bytes = page.iter().try_fold(0u64, |total, (key, value)| {
                total
                    .checked_add(key.len() as u64)
                    .and_then(|total| total.checked_add(value.len() as u64))
                    .ok_or_else(|| sim_run_resource_exhausted("global SIM byte count overflow"))
            })?;
            page_bytes_high_water = page_bytes_high_water.max(page_bytes);
            bytes_scanned = bytes_scanned
                .checked_add(page_bytes)
                .ok_or_else(|| sim_run_resource_exhausted("global SIM byte count overflow"))?;
            rows_scanned = rows_scanned
                .checked_add(page.len())
                .ok_or_else(|| sim_run_resource_exhausted("global SIM row count overflow"))?;
            for (key, value) in page {
                let row = decode_similarity_row(&key, &value, None)?;
                update_row_dump_hasher(&mut dump_hasher, &row)?;
            }
            Ok(())
        },
    )?;
    let storage_after = vault.latest_only_readback_status();
    ensure_bounded_sim_storage(&storage_after, "global similarity post-scan")?;
    let observed_snapshot = vault.snapshot();
    let observed_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    if storage_after != storage_before
        || observed_snapshot != snapshot
        || observed_generation != graph_generation
    {
        return Err(sim_edge_corrupt(format!(
            "Graph source changed during global SIM scan: expected_snapshot={snapshot}, observed_snapshot={observed_snapshot}, expected_generation={graph_generation}, observed_generation={observed_generation}, storage_before={storage_before:?}, storage_after={storage_after:?}"
        )));
    }
    Ok(SimilarityPhysicalScan {
        snapshot_seq: snapshot,
        graph_generation,
        pages,
        page_rows_high_water,
        page_bytes_high_water,
        rows_scanned,
        bytes_scanned,
        edge_dump_hash: dump_hasher.finalize().to_hex().to_string(),
    })
}

/// Expands a changed-symbol set through exactly two persisted SIM hops while
/// retaining only the evolving identity set and one physical scan page.
pub fn expand_persisted_similarity_region_from_vault<C>(
    vault: &AsterVault<C>,
    changed: &BTreeSet<String>,
) -> calyx_core::Result<PersistedSimilarityRegionScan>
where
    C: Clock,
{
    refuse_legacy_similarity_rows(vault)?;
    let storage_before = vault.latest_only_readback_status();
    ensure_bounded_sim_storage(&storage_before, "similarity-region pre-scan")?;
    let snapshot = vault.snapshot();
    let graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let mut region = changed.clone();
    let mut pages = 0usize;
    let mut rows_scanned = 0usize;
    let mut page_rows_high_water = 0usize;
    for _ in 0..2 {
        let frontier = region.clone();
        vault.scan_cf_range_pages_at(
            snapshot,
            ColumnFamily::Graph,
            &prefix_range(SIM_EDGE_ROW_PREFIX),
            SIM_SCAN_PAGE_ROWS,
            |page| {
                pages = pages
                    .checked_add(1)
                    .ok_or_else(|| sim_run_resource_exhausted("SIM region page count overflow"))?;
                rows_scanned = rows_scanned
                    .checked_add(page.len())
                    .ok_or_else(|| sim_run_resource_exhausted("SIM region row count overflow"))?;
                page_rows_high_water = page_rows_high_water.max(page.len());
                for (key, value) in page {
                    let row = decode_similarity_row(&key, &value, None)?;
                    if frontier.contains(&row.source_id) || frontier.contains(&row.target_id) {
                        region.insert(row.source_id);
                        region.insert(row.target_id);
                    }
                }
                Ok(())
            },
        )?;
    }
    let storage_after = vault.latest_only_readback_status();
    ensure_bounded_sim_storage(&storage_after, "similarity-region post-scan")?;
    let observed_snapshot = vault.snapshot();
    let observed_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    if storage_after != storage_before
        || observed_snapshot != snapshot
        || observed_generation != graph_generation
    {
        return Err(sim_edge_corrupt(format!(
            "Graph source changed during bounded SIM region expansion: expected_snapshot={snapshot}, observed_snapshot={observed_snapshot}, expected_generation={graph_generation}, observed_generation={observed_generation}, storage_before={storage_before:?}, storage_after={storage_after:?}"
        )));
    }
    Ok(PersistedSimilarityRegionScan {
        region,
        pages,
        rows_scanned,
        page_rows_high_water,
    })
}

/// Reads back and key-verifies every persisted SIM_* row.
///
/// Fails closed on any undecodable row, schema mismatch, unknown family, or a
/// row whose stored key disagrees with the key recomputed from its fields —
/// a corrupt row is never silently dropped.
pub fn read_similarity_edge_rows<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<PersistedSimilarityEdgeRow>>
where
    C: Clock,
{
    refuse_legacy_similarity_rows(vault)?;
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    vault.scan_cf_range_pages_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_EDGE_ROW_PREFIX),
        SIM_SCAN_PAGE_ROWS,
        |page| {
            for (key, value) in page {
                let row = decode_similarity_row(&key, &value, None)?;
                rows.push(PersistedSimilarityEdgeRow { key, row });
            }
            Ok(())
        },
    )?;
    Ok(rows)
}

fn refuse_legacy_similarity_rows<C>(vault: &AsterVault<C>) -> calyx_core::Result<()>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut legacy_count = 0usize;
    vault.scan_cf_range_pages_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(LEGACY_SIM_EDGE_ROW_PREFIX),
        SIM_SCAN_PAGE_ROWS,
        |page| {
            legacy_count = legacy_count
                .checked_add(page.len())
                .ok_or_else(|| sim_run_resource_exhausted("legacy SIM row count overflow"))?;
            Ok(())
        },
    )?;
    if legacy_count == 0 {
        return Ok(());
    }
    Err(CalyxError {
        code: ASTRO_SIM_EDGE_ROW_CORRUPT,
        message: format!(
            "vault contains {} legacy qualified-name-keyed SIM edge rows",
            legacy_count
        ),
        remediation: "rebuild the shadow vault from the current CBM atom schema; legacy SIM rows cannot represent same-qualified-name definitions",
    })
}

/// Recovers the ledger reference for the group commit that produced
/// `commit_seq` (read pinned to that snapshot, so concurrent later appends are
/// invisible; same TOCTOU-safe pattern as the ingest importer).
pub(crate) fn ledger_ref_at_commit<C>(
    vault: &AsterVault<C>,
    commit_seq: u64,
) -> calyx_core::Result<LedgerRef>
where
    C: Clock,
{
    let (key, value) = vault
        .scan_cf_at(commit_seq, ColumnFamily::Ledger)?
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0))
        .ok_or_else(|| CalyxError {
            code: ASTRO_SIM_EDGE_LEDGER_MISSING,
            message: "Ledger CF empty at SIM_* persistence commit snapshot".to_string(),
            remediation: SIM_EDGE_LEDGER_REMEDIATION,
        })?;
    let key_seq = parse_aster_ledger_seq(&key)?;
    let entry = decode_ledger(&value)?;
    if entry.seq != key_seq {
        return Err(CalyxError {
            code: ASTRO_SIM_EDGE_LEDGER_MISSING,
            message: format!(
                "Ledger CF key seq {key_seq} does not match encoded entry seq {}",
                entry.seq
            ),
            remediation: SIM_EDGE_LEDGER_REMEDIATION,
        });
    }
    // Sanity: the ledger key codec round-trips (guards against a prefix-scan
    // picking up a foreign key shape).
    debug_assert_eq!(key, ledger_key(key_seq));
    Ok(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    })
}

fn sim_edge_corrupt(message: String) -> CalyxError {
    CalyxError {
        code: ASTRO_SIM_EDGE_ROW_CORRUPT,
        message,
        remediation: SIM_EDGE_REMEDIATION,
    }
}
