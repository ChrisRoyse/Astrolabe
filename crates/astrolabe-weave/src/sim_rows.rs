//! Graph CF persistence for planned SIM_* similarity edges.
//!
//! Derived similarity edges are regenerable, so persistence is a full,
//! idempotent reconciliation of the `astrolabe:sim-edge:v1:` prefix: rows for
//! planned edges are written (or left untouched when byte-identical), stale
//! rows are tombstoned, and the whole batch lands in one atomic group commit
//! paired with a Ledger entry whose payload carries the blake3 hash of the
//! canonical edge dump — pairing the mutation with its ledger record and
//! making the persisted set byte-verifiable on readback.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, ledger_key, prefix_range};
use calyx_aster::ledger_view::parse_aster_ledger_seq;
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, LedgerRef, VaultStore};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::{Deserialize, Serialize};

use crate::{
    SimilarityEdge, SimilarityFamily, SimilarityMetric, SimilarityPlan, hex_lower_bytes,
    similarity_edge_dump_bytes,
};

/// Graph CF key prefix for persisted SIM_* similarity edge rows.
pub const SIM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:sim-edge:v1:";
/// Row schema tag for persisted SIM_* similarity edge rows.
pub const SCHEMA_SIM_EDGE_ROW: &str = "astrolabe-sim-edge-v1";
/// Ledger payload schema for a SIM_* persistence group commit.
pub const SIM_EDGE_LEDGER_SCHEMA: &str = "astrolabe.sim_edges.v1";
/// Stable failure code for corrupt or inconsistent persisted SIM_* rows.
pub const ASTRO_SIM_EDGE_ROW_CORRUPT: &str = "ASTRO_SIM_EDGE_ROW_CORRUPT";
/// Stable failure code when the paired ledger entry cannot be recovered.
pub const ASTRO_SIM_EDGE_LEDGER_MISSING: &str = "ASTRO_SIM_EDGE_LEDGER_MISSING";

const SIM_EDGE_REMEDIATION: &str =
    "regenerate SIM_* rows with astrolabe_weave::persist_similarity_edges from a fresh plan";
const SIM_EDGE_LEDGER_REMEDIATION: &str =
    "verify the vault Ledger CF integrity, then re-run the SIM_* persistence group commit";

/// Persisted Graph CF row for one SIM_* similarity edge.
///
/// `weight_bits` / `threshold_bits` hold the exact IEEE-754 bit patterns so a
/// readback comparison against a recomputed plan is tolerance-0 by
/// construction (the same code path must be bit-stable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimEdgeGraphRow {
    /// Always [`SCHEMA_SIM_EDGE_ROW`].
    pub schema: String,
    /// Family wire name (`SIM_STRUCT`, `SIM_SEMANTIC`, `SIM_API`, `SIM_PROFILE`).
    pub family: String,
    /// Owning (lexicographically smaller) qualified name.
    pub source_qn: String,
    /// Target qualified name.
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

/// Report for one SIM_* persistence group commit.
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
    /// Ledger entry paired with this mutation batch.
    pub ledger_ref: LedgerRef,
    /// Unforgeable full-readback witness when Graph rows changed.
    /// A ledger-only no-delta replay carries labeled absence (`None`).
    pub fsv: Option<FsvAck>,
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

impl PartialEq for PhaseTimings {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for PhaseTimings {}

/// Builds the canonical Graph CF key for one SIM_* edge.
pub fn sim_edge_graph_key(family: SimilarityFamily, source_qn: &str, target_qn: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        SIM_EDGE_ROW_PREFIX.len() + 1 + 4 + source_qn.len() + 4 + target_qn.len(),
    );
    key.extend_from_slice(SIM_EDGE_ROW_PREFIX);
    key.push(family.sort_index());
    key.extend_from_slice(&(source_qn.len() as u32).to_be_bytes());
    key.extend_from_slice(source_qn.as_bytes());
    key.extend_from_slice(&(target_qn.len() as u32).to_be_bytes());
    key.extend_from_slice(target_qn.as_bytes());
    key
}

/// Persists a similarity plan's SIM_* edges to the Graph CF.
///
/// Reconciles the persisted prefix against the plan (write / keep / tombstone)
/// in a single atomic group commit paired with a Ledger entry whose payload
/// records the counts and the canonical edge dump hash. A no-delta persist
/// still appends the ledger record so re-runs remain audited.
pub fn persist_similarity_edges<C>(
    vault: &AsterVault<C>,
    plan: &SimilarityPlan,
    actor: impl Into<String>,
) -> calyx_core::Result<SimilarityPersistReport>
where
    C: Clock,
{
    persist_similarity_edges_owned(vault, plan, None, actor.into())
}

/// Reconciles only the named dirty-region source ownership plus rows touching
/// removed qualified names. Clean-clean SIM rows remain byte-identical.
pub fn persist_similarity_edges_delta<C>(
    vault: &AsterVault<C>,
    plan: &SimilarityPlan,
    owned_sources: &BTreeSet<String>,
    removed_qualified_names: &BTreeSet<String>,
    actor: impl Into<String>,
) -> calyx_core::Result<SimilarityPersistReport>
where
    C: Clock,
{
    persist_similarity_edges_owned(
        vault,
        plan,
        Some((owned_sources, removed_qualified_names)),
        actor.into(),
    )
}

fn persist_similarity_edges_owned<C>(
    vault: &AsterVault<C>,
    plan: &SimilarityPlan,
    ownership: Option<(&BTreeSet<String>, &BTreeSet<String>)>,
    actor: String,
) -> calyx_core::Result<SimilarityPersistReport>
where
    C: Clock,
{
    let mut timing_ms: Vec<(&'static str, u64)> = Vec::new();
    let mut phase_start = std::time::Instant::now();
    let dump = similarity_edge_dump_bytes(&plan.edges);
    let edge_dump_hash = hex_lower_bytes(blake3::hash(&dump).as_bytes());

    let mut new_rows = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut family_counts = BTreeMap::<&'static str, usize>::new();
    for edge in &plan.edges {
        let key = sim_edge_graph_key(edge.family, &edge.source_qn, &edge.target_qn);
        let value = serde_json::to_vec(&SimEdgeGraphRow::from_edge(edge))
            .map_err(|error| sim_edge_corrupt(format!("encode SIM_* row: {error}")))?;
        if new_rows.insert(key, value).is_some() {
            return Err(sim_edge_corrupt(format!(
                "similarity plan holds duplicate edge {} {} -> {}",
                edge.family.wire_name(),
                edge.source_qn,
                edge.target_qn
            )));
        }
        *family_counts.entry(edge.family.wire_name()).or_default() += 1;
    }

    timing_ms.push(("encode_plan", phase_start.elapsed().as_millis() as u64));
    phase_start = std::time::Instant::now();
    let snapshot = vault.snapshot();
    let mut existing: BTreeMap<Vec<u8>, Vec<u8>> = vault
        .scan_cf_range_at(
            snapshot,
            ColumnFamily::Graph,
            &prefix_range(SIM_EDGE_ROW_PREFIX),
        )?
        .into_iter()
        .collect();
    timing_ms.push(("scan_existing", phase_start.elapsed().as_millis() as u64));
    phase_start = std::time::Instant::now();
    if let Some((owned_sources, removed)) = ownership {
        let mut owned_existing = BTreeMap::new();
        for (key, value) in existing {
            let row = serde_json::from_slice::<SimEdgeGraphRow>(&value)
                .map_err(|error| sim_edge_corrupt(format!("decode owned SIM_* row: {error}")))?;
            if owned_sources.contains(&row.source_qn)
                || removed.contains(&row.source_qn)
                || removed.contains(&row.target_qn)
            {
                owned_existing.insert(key, value);
            }
        }
        existing = owned_existing;
    }

    let mut batch = Vec::new();
    let mut rows_written = 0usize;
    let mut rows_unchanged = 0usize;
    for (key, value) in &new_rows {
        if existing.get(key) == Some(value) {
            rows_unchanged += 1;
        } else {
            batch.push((ColumnFamily::Graph, key.clone(), value.clone()));
            rows_written += 1;
        }
    }
    let mut rows_tombstoned = 0usize;
    let tombstone = tombstone_value();
    for key in existing.keys() {
        if !new_rows.contains_key(key) {
            batch.push((ColumnFamily::Graph, key.clone(), tombstone.clone()));
            rows_tombstoned += 1;
        }
    }

    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": SIM_EDGE_LEDGER_SCHEMA,
        "edge_count": plan.edges.len(),
        "families": family_counts,
        "rows_written": rows_written,
        "rows_unchanged": rows_unchanged,
        "rows_tombstoned": rows_tombstoned,
        "edge_dump_hash": edge_dump_hash,
    }))
    .map_err(|error| sim_edge_corrupt(format!("encode SIM_* ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;

    let subject = SubjectId::Query(format!("astrolabe-sim-edges:{edge_dump_hash}").into_bytes());
    let actor = ActorId::Service(actor);
    let mut fsv_plan = VaultMutationPlan::new(
        "persist_similarity_edges",
        EntryKind::Ingest,
        &actor,
        &subject,
    );
    for (cf, key, value) in &batch {
        if *value == tombstone {
            fsv_plan.push_tombstoned(*cf, key.clone(), &tombstone);
        } else {
            fsv_plan.push_content(*cf, key.clone(), value);
        }
    }
    timing_ms.push(("reconcile", phase_start.elapsed().as_millis() as u64));
    phase_start = std::time::Instant::now();
    let (ledger_ref, commit_seq) = if batch.is_empty() {
        (
            vault.append_ledger_entry(EntryKind::Ingest, subject, payload, actor)?,
            None,
        )
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Ingest,
            subject,
            payload,
            actor,
        )?;
        (ledger_ref_at_commit(vault, commit_seq)?, Some(commit_seq))
    };
    timing_ms.push(("commit", phase_start.elapsed().as_millis() as u64));
    phase_start = std::time::Instant::now();
    vault.flush()?;
    timing_ms.push(("flush", phase_start.elapsed().as_millis() as u64));
    phase_start = std::time::Instant::now();
    let fsv = commit_seq
        .map(|commit_seq| fsv_plan.verify_committed(vault, commit_seq))
        .transpose()?;
    timing_ms.push(("fsv_readback", phase_start.elapsed().as_millis() as u64));

    Ok(SimilarityPersistReport {
        edge_count: plan.edges.len(),
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        edge_dump_hash,
        ledger_ref,
        fsv,
        timing_ms: PhaseTimings(timing_ms),
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
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_EDGE_ROW_PREFIX),
    )? {
        let row: SimEdgeGraphRow = serde_json::from_slice(&value).map_err(|error| {
            sim_edge_corrupt(format!(
                "decode SIM_* row {}: {error}",
                hex_lower_bytes(&key)
            ))
        })?;
        if row.schema != SCHEMA_SIM_EDGE_ROW {
            return Err(sim_edge_corrupt(format!(
                "SIM_* row {} carries schema {:?}",
                hex_lower_bytes(&key),
                row.schema
            )));
        }
        let Some(family) = row.similarity_family() else {
            return Err(sim_edge_corrupt(format!(
                "SIM_* row {} names unknown family {:?}",
                hex_lower_bytes(&key),
                row.family
            )));
        };
        if row.slot != family.slot().get()
            || row.etype != family.graph_edge_kind().code()
            || row.metric != SimilarityMetric::Cosine.as_str()
        {
            return Err(sim_edge_corrupt(format!(
                "SIM_* row {} disagrees with family {} metadata",
                hex_lower_bytes(&key),
                family
            )));
        }
        if key != sim_edge_graph_key(family, &row.source_qn, &row.target_qn) {
            return Err(sim_edge_corrupt(format!(
                "SIM_* row key {} does not match its decoded fields",
                hex_lower_bytes(&key)
            )));
        }
        rows.push(PersistedSimilarityEdgeRow { key, row });
    }
    Ok(rows)
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
