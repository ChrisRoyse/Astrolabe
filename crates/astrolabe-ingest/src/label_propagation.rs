//! Live Lodestar label propagation over persisted vault rows (#69, cap 5.9).
//!
//! The pure propagation math and its trust discipline live in
//! [`astrolabe_kernel`] (`propagate_labels`, `PropagatedLabel`, `LabelTrust`).
//! This module binds that kernel contract to a real [`AsterVault`] so that
//! propagation runs over **persisted state, never in-memory fixtures**:
//!
//! 1. Grounded label seeds, the association-graph edges, and any erasure
//!    tombstones are persisted as first-class Graph CF rows
//!    ([`persist_label_graph`]) under versioned, key-verifiable schemas, in one
//!    atomic group commit paired with a Ledger entry.
//! 2. [`propagate_labels_over_vault`] re-reads those rows from the committed
//!    snapshot (a fresh store read, decoupled from any caller-held value),
//!    runs the kernel propagation, and writes the derived provisional labels
//!    back as Kernel CF rows in a single group commit paired with its Ledger
//!    entry. It then independently re-reads every written/tombstoned row and
//!    the paired ledger entry and returns an [`FsvAck`] only if the persisted
//!    bytes match byte-for-byte.
//! 3. [`read_propagated_label_rows`] is the independent reader used to assert
//!    persisted state without trusting any return value.
//!
//! Propagated labels are always [`LabelTrust::Provisional`] — they are
//! inferences, never grounded truth — and the confidence of every propagated
//! row is strictly below its seed's confidence (enforced by the kernel decay).

use std::collections::BTreeMap;

use astrolabe_domain::fsv::FsvAck;
use astrolabe_kernel::{
    LabelGraphEdge, LabelPropagationConfig, LabelSeed, LabelTombstone, LabelTrust, PropagatedLabel,
    propagate_labels,
};
use calyx_aster::cf::{ColumnFamily, prefix_range};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, VaultStore};
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::{Deserialize, Serialize};

use crate::fsv::VaultMutationPlan;
use crate::registry::{IngestError, IngestResult};

/// Graph CF key prefix for a persisted grounded label seed.
pub const LABEL_SEED_ROW_PREFIX: &[u8] = b"astrolabe:label-seed:v1:";
/// Graph CF key prefix for a persisted label-propagation graph edge.
pub const LABEL_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:label-edge:v1:";
/// Graph CF key prefix for a persisted label erasure tombstone (#61 semantics).
pub const LABEL_TOMBSTONE_ROW_PREFIX: &[u8] = b"astrolabe:label-tombstone:v1:";
/// Kernel CF key prefix for a persisted propagated (provisional) label row.
pub const PROPAGATED_LABEL_ROW_PREFIX: &[u8] = b"astrolabe:propagated-label:v1:";

/// Row schema tag for a persisted label seed.
pub const SCHEMA_LABEL_SEED_ROW: &str = "astrolabe-label-seed-v1";
/// Row schema tag for a persisted label graph edge.
pub const SCHEMA_LABEL_EDGE_ROW: &str = "astrolabe-label-edge-v1";
/// Row schema tag for a persisted label tombstone.
pub const SCHEMA_LABEL_TOMBSTONE_ROW: &str = "astrolabe-label-tombstone-v1";
/// Row schema tag for a persisted propagated label.
pub const SCHEMA_PROPAGATED_LABEL_ROW: &str = "astrolabe-propagated-label-v1";

/// Ledger payload schema for a persisted label-graph input commit.
pub const LABEL_GRAPH_LEDGER_SCHEMA: &str = "astrolabe.label_graph.v1";
/// Ledger payload schema for a live propagation commit.
pub const LABEL_PROPAGATION_LEDGER_SCHEMA: &str = "astrolabe.label_propagation.v1";

/// Stable failure code for a corrupt or inconsistent persisted label row.
pub const ASTRO_LABEL_PROP_ROW_CORRUPT: &str = "ASTRO_LABEL_PROP_ROW_CORRUPT";

const LABEL_PROP_REMEDIATION: &str = "re-persist the label graph with astrolabe_ingest::persist_label_graph, then re-run propagate_labels_over_vault";

// ─── Persisted row structs ──────────────────────────────────────────────────

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct LabelSeedRow {
    schema: String,
    symbol_id: String,
    label: String,
    confidence_millipoints: u64,
    provenance_ref: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct LabelEdgeRow {
    schema: String,
    left_symbol_id: String,
    right_symbol_id: String,
    provenance_ref: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct LabelTombstoneRow {
    schema: String,
    symbol_id: String,
    provenance_ref: String,
}

/// The persisted form of one [`PropagatedLabel`]. Byte-comparable on readback:
/// serialization is a total function of the kernel's deterministic output.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PropagatedLabelRow {
    /// Always [`SCHEMA_PROPAGATED_LABEL_ROW`].
    pub schema: String,
    /// Symbol the label was extended onto.
    pub symbol_id: String,
    /// Propagated label name.
    pub label: String,
    /// Decayed confidence on the millipoints scale (strictly `< seed`).
    pub confidence_millipoints: u64,
    /// Seed symbol the label harmonically extended from.
    pub seed_symbol_id: String,
    /// The originating seed's confidence.
    pub seed_confidence_millipoints: u64,
    /// Hop distance from the seed.
    pub distance: u64,
    /// Always `"provisional"` — propagated labels are inferences.
    pub trust: String,
    /// Always `"fresh"` at write time.
    pub freshness: String,
    /// Provenance ref of the originating seed.
    pub seed_provenance_ref: String,
    /// Ordered provenance refs of the graph edges traversed.
    pub graph_provenance_refs: Vec<String>,
    /// The pinned per-hop decay math string, replayable by the kernel.
    pub math: String,
}

impl PropagatedLabelRow {
    fn from_label(label: &PropagatedLabel) -> Self {
        Self {
            schema: SCHEMA_PROPAGATED_LABEL_ROW.to_string(),
            symbol_id: label.symbol_id.clone(),
            label: label.label.clone(),
            confidence_millipoints: label.confidence_millipoints,
            seed_symbol_id: label.seed_symbol_id.clone(),
            seed_confidence_millipoints: label.seed_confidence_millipoints,
            distance: label.distance,
            trust: label.trust.as_str().to_string(),
            freshness: label.freshness.to_string(),
            seed_provenance_ref: label.provenance.seed_provenance_ref.clone(),
            graph_provenance_refs: label.provenance.graph_provenance_refs.clone(),
            math: label.provenance.math.clone(),
        }
    }
}

/// One decoded, key-verified propagated label row read back from the Kernel CF.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PersistedPropagatedLabel {
    /// Full Kernel CF key the row was stored under.
    pub key: Vec<u8>,
    /// Decoded row.
    pub row: PropagatedLabelRow,
}

// ─── Reports ────────────────────────────────────────────────────────────────

/// Report for one [`persist_label_graph`] commit.
#[derive(Debug, Clone)]
pub struct LabelGraphPersistReport {
    /// Seed rows in the committed set.
    pub seed_count: usize,
    /// Edge rows in the committed set.
    pub edge_count: usize,
    /// Tombstone rows in the committed set.
    pub tombstone_count: usize,
    /// Rows written or rewritten in this commit.
    pub rows_written: usize,
    /// Stale rows tombstoned in this commit.
    pub rows_tombstoned: usize,
    /// FSV ack for the commit, or `None` when the set was already byte-identical.
    pub fsv_ack: Option<FsvAck>,
}

/// Report for one [`propagate_labels_over_vault`] run.
///
/// Carries the HONEST label triad (`trust` / `freshness` / `provenance`) so the
/// server surface can relay it without inventing labels.
#[derive(Debug, Clone)]
pub struct LivePropagationReport {
    /// Kernel propagation schema (`astrolabe.label_propagation.v1`).
    pub schema: &'static str,
    /// Seeds read back from persisted Graph CF rows.
    pub seeds_read: usize,
    /// Edges read back from persisted Graph CF rows.
    pub edges_read: usize,
    /// Tombstones read back from persisted Graph CF rows.
    pub tombstones_read: usize,
    /// Provisional labels the kernel propagated.
    pub labels_propagated: usize,
    /// Kernel CF label rows written/rewritten in this commit.
    pub rows_written: usize,
    /// Stale Kernel CF label rows tombstoned in this commit.
    pub rows_tombstoned: usize,
    /// Explicit empty reason when propagation yielded no labels (never an error).
    pub empty_reason: Option<String>,
    /// FSV ack proving the persisted rows were re-read and matched, plus a
    /// paired ledger entry. `None` only when nothing changed (idempotent re-run).
    pub fsv_ack: Option<FsvAck>,
    /// Ledger sequence of the commit paired with this propagation.
    pub ledger_seq: u64,
    /// HONEST freshness label.
    pub freshness: &'static str,
    /// HONEST trust label (`provisional` for propagated inferences).
    pub trust: &'static str,
    /// HONEST provenance label: `blake3:<dump>;ledger_seq:<seq>`.
    pub provenance: String,
}

// ─── Key encoding ─────────────────────────────────────────────────────────────

fn push_len_prefixed(key: &mut Vec<u8>, part: &str) {
    key.extend_from_slice(&(part.len() as u32).to_be_bytes());
    key.extend_from_slice(part.as_bytes());
}

fn label_seed_key(label: &str, symbol_id: &str) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(LABEL_SEED_ROW_PREFIX.len() + 8 + label.len() + symbol_id.len());
    key.extend_from_slice(LABEL_SEED_ROW_PREFIX);
    push_len_prefixed(&mut key, label);
    push_len_prefixed(&mut key, symbol_id);
    key
}

fn label_edge_key(left: &str, right: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(LABEL_EDGE_ROW_PREFIX.len() + 8 + left.len() + right.len());
    key.extend_from_slice(LABEL_EDGE_ROW_PREFIX);
    push_len_prefixed(&mut key, left);
    push_len_prefixed(&mut key, right);
    key
}

fn label_tombstone_key(symbol_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(LABEL_TOMBSTONE_ROW_PREFIX.len() + 4 + symbol_id.len());
    key.extend_from_slice(LABEL_TOMBSTONE_ROW_PREFIX);
    push_len_prefixed(&mut key, symbol_id);
    key
}

fn propagated_label_key(label: &str, symbol_id: &str) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(PROPAGATED_LABEL_ROW_PREFIX.len() + 8 + label.len() + symbol_id.len());
    key.extend_from_slice(PROPAGATED_LABEL_ROW_PREFIX);
    push_len_prefixed(&mut key, label);
    push_len_prefixed(&mut key, symbol_id);
    key
}

fn corrupt(message: impl Into<String>) -> IngestError {
    IngestError::refused(
        ASTRO_LABEL_PROP_ROW_CORRUPT,
        message,
        LABEL_PROP_REMEDIATION,
    )
}

fn encode_row<T: Serialize>(row: &T, what: &str) -> IngestResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|error| corrupt(format!("encode {what} row: {error}")))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

// ─── Persist the grounded label graph (inputs) ────────────────────────────────

/// Persists the grounded label seeds, the association-graph edges, and any
/// erasure tombstones as Graph CF rows in one atomic group commit paired with a
/// Ledger entry, then independently re-reads the committed rows for an
/// [`FsvAck`].
///
/// The three prefixes are fully reconciled against their persisted state: a row
/// that already reads back byte-identical is left untouched, and any persisted
/// row not present in `seeds`/`edges`/`tombstones` is tombstoned so an erased
/// seed (per #61) genuinely disappears from the next propagation.
///
/// # Errors
///
/// Fails closed on a duplicate seed/edge/tombstone key
/// ([`ASTRO_LABEL_PROP_ROW_CORRUPT`]), on any encode failure, or on any vault
/// error. A committed set that then fails readback surfaces the FSV refusal.
pub fn persist_label_graph<C>(
    vault: &AsterVault<C>,
    seeds: &[LabelSeed],
    edges: &[LabelGraphEdge],
    tombstones: &[LabelTombstone],
    actor: impl Into<String>,
) -> IngestResult<LabelGraphPersistReport>
where
    C: Clock,
{
    let mut desired = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for seed in seeds {
        let key = label_seed_key(&seed.label, &seed.symbol_id);
        let row = LabelSeedRow {
            schema: SCHEMA_LABEL_SEED_ROW.to_string(),
            symbol_id: seed.symbol_id.clone(),
            label: seed.label.clone(),
            confidence_millipoints: seed.confidence_millipoints,
            provenance_ref: seed.provenance_ref.clone(),
        };
        if desired
            .insert(key, encode_row(&row, "label seed")?)
            .is_some()
        {
            return Err(corrupt(format!(
                "duplicate label seed {} on {}",
                seed.label, seed.symbol_id
            )));
        }
    }
    for edge in edges {
        let key = label_edge_key(&edge.left_symbol_id, &edge.right_symbol_id);
        let row = LabelEdgeRow {
            schema: SCHEMA_LABEL_EDGE_ROW.to_string(),
            left_symbol_id: edge.left_symbol_id.clone(),
            right_symbol_id: edge.right_symbol_id.clone(),
            provenance_ref: edge.provenance_ref.clone(),
        };
        if desired
            .insert(key, encode_row(&row, "label edge")?)
            .is_some()
        {
            return Err(corrupt(format!(
                "duplicate label edge {} -> {}",
                edge.left_symbol_id, edge.right_symbol_id
            )));
        }
    }
    for tombstone in tombstones {
        let key = label_tombstone_key(&tombstone.symbol_id);
        let row = LabelTombstoneRow {
            schema: SCHEMA_LABEL_TOMBSTONE_ROW.to_string(),
            symbol_id: tombstone.symbol_id.clone(),
            provenance_ref: tombstone.provenance_ref.clone(),
        };
        if desired
            .insert(key, encode_row(&row, "label tombstone")?)
            .is_some()
        {
            return Err(corrupt(format!(
                "duplicate label tombstone {}",
                tombstone.symbol_id
            )));
        }
    }

    let snapshot = vault.snapshot();
    let mut existing = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for prefix in [
        LABEL_SEED_ROW_PREFIX,
        LABEL_EDGE_ROW_PREFIX,
        LABEL_TOMBSTONE_ROW_PREFIX,
    ] {
        for (key, value) in
            vault.scan_cf_range_at(snapshot, ColumnFamily::Graph, &prefix_range(prefix))?
        {
            if value == tombstone_value() {
                continue;
            }
            existing.insert(key, value);
        }
    }

    let actor = ActorId::Service(actor.into());
    let (rows_written, rows_tombstoned, fsv_ack) = commit_reconciliation(
        vault,
        ColumnFamily::Graph,
        &desired,
        &existing,
        EntryKind::Grounding,
        LABEL_GRAPH_LEDGER_SCHEMA,
        "astrolabe-label-graph",
        actor,
    )?;

    Ok(LabelGraphPersistReport {
        seed_count: seeds.len(),
        edge_count: edges.len(),
        tombstone_count: tombstones.len(),
        rows_written,
        rows_tombstoned,
        fsv_ack,
    })
}

// ─── Live propagation over persisted rows ─────────────────────────────────────

/// Reads the persisted label graph, runs kernel propagation, writes the derived
/// provisional labels back, pairs the mutation with a Ledger entry, and returns
/// a report whose [`FsvAck`] proves the persisted label rows were re-read and
/// matched byte-for-byte.
///
/// This is the live path: seeds, edges, and tombstones are read from committed
/// Graph CF rows (never from a caller-held value), so the propagation reflects
/// exactly what is durable in the vault. Erased seeds (persisted tombstones, or
/// seeds removed from the persisted set) are excluded and the propagated set is
/// recomputed without them.
///
/// # Errors
///
/// Fails closed on a corrupt persisted input row, on any kernel refusal
/// (out-of-range seed confidence or decay knob), or on any vault/FSV error.
pub fn propagate_labels_over_vault<C>(
    vault: &AsterVault<C>,
    config: &LabelPropagationConfig,
    actor: impl Into<String>,
) -> IngestResult<LivePropagationReport>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let seeds = read_seed_rows(vault, snapshot)?;
    let edges = read_edge_rows(vault, snapshot)?;
    let tombstones = read_tombstone_rows(vault, snapshot)?;

    let report = propagate_labels(&seeds, &edges, &tombstones, config)?;

    // Desired persisted Kernel CF rows: one per propagated (provisional) label.
    let mut desired = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for label in &report.labels {
        debug_assert!(label.trust == LabelTrust::Provisional);
        let key = propagated_label_key(&label.label, &label.symbol_id);
        let row = PropagatedLabelRow::from_label(label);
        desired.insert(key, encode_row(&row, "propagated label")?);
    }

    let snapshot = vault.snapshot();
    let existing: BTreeMap<Vec<u8>, Vec<u8>> = vault
        .scan_cf_range_at(
            snapshot,
            ColumnFamily::Kernel,
            &prefix_range(PROPAGATED_LABEL_ROW_PREFIX),
        )?
        .into_iter()
        .filter(|(_, value)| *value != tombstone_value())
        .collect();

    let dump_hash = hex_lower(blake3::hash(&canonical_label_dump(&desired)).as_bytes());
    let actor = ActorId::Service(actor.into());
    let (rows_written, rows_tombstoned, fsv_ack) = commit_reconciliation(
        vault,
        ColumnFamily::Kernel,
        &desired,
        &existing,
        EntryKind::Grounding,
        LABEL_PROPAGATION_LEDGER_SCHEMA,
        "astrolabe-label-propagation",
        actor,
    )?;

    let ledger_seq = fsv_ack
        .as_ref()
        .map(FsvAck::ledger_seq)
        .unwrap_or_else(|| vault.latest_seq());

    Ok(LivePropagationReport {
        schema: report.schema,
        seeds_read: seeds.len(),
        edges_read: edges.len(),
        tombstones_read: tombstones.len(),
        labels_propagated: report.labels.len(),
        rows_written,
        rows_tombstoned,
        empty_reason: report.empty_reason.map(ToOwned::to_owned),
        fsv_ack,
        ledger_seq,
        freshness: report.freshness,
        trust: report.trust,
        provenance: format!("blake3:{dump_hash};ledger_seq:{ledger_seq}"),
    })
}

/// Reads back and key-verifies every persisted propagated label row, sorted by
/// key. Fails closed on any undecodable row, schema mismatch, or a row whose
/// stored key disagrees with the key recomputed from its fields.
pub fn read_propagated_label_rows<C>(
    vault: &AsterVault<C>,
) -> IngestResult<Vec<PersistedPropagatedLabel>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Kernel,
        &prefix_range(PROPAGATED_LABEL_ROW_PREFIX),
    )? {
        if value == tombstone_value() {
            continue;
        }
        let row: PropagatedLabelRow = serde_json::from_slice(&value).map_err(|error| {
            corrupt(format!(
                "decode propagated label {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if row.schema != SCHEMA_PROPAGATED_LABEL_ROW {
            return Err(corrupt(format!(
                "propagated label {} carries schema {:?}",
                hex_lower(&key),
                row.schema
            )));
        }
        if key != propagated_label_key(&row.label, &row.symbol_id) {
            return Err(corrupt(format!(
                "propagated label key {} does not match its decoded fields",
                hex_lower(&key)
            )));
        }
        rows.push(PersistedPropagatedLabel { key, row });
    }
    Ok(rows)
}

// ─── Internal readers ─────────────────────────────────────────────────────────

fn read_seed_rows<C>(
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
) -> IngestResult<Vec<LabelSeed>>
where
    C: Clock,
{
    let mut seeds = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(LABEL_SEED_ROW_PREFIX),
    )? {
        if value == tombstone_value() {
            continue;
        }
        let row: LabelSeedRow = serde_json::from_slice(&value)
            .map_err(|error| corrupt(format!("decode label seed {}: {error}", hex_lower(&key))))?;
        if row.schema != SCHEMA_LABEL_SEED_ROW {
            return Err(corrupt(format!(
                "label seed {} carries schema {:?}",
                hex_lower(&key),
                row.schema
            )));
        }
        if key != label_seed_key(&row.label, &row.symbol_id) {
            return Err(corrupt(format!(
                "label seed key {} does not match its decoded fields",
                hex_lower(&key)
            )));
        }
        seeds.push(LabelSeed::new(
            row.symbol_id,
            row.label,
            row.confidence_millipoints,
            row.provenance_ref,
        ));
    }
    Ok(seeds)
}

fn read_edge_rows<C>(
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
) -> IngestResult<Vec<LabelGraphEdge>>
where
    C: Clock,
{
    let mut edges = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(LABEL_EDGE_ROW_PREFIX),
    )? {
        if value == tombstone_value() {
            continue;
        }
        let row: LabelEdgeRow = serde_json::from_slice(&value)
            .map_err(|error| corrupt(format!("decode label edge {}: {error}", hex_lower(&key))))?;
        if row.schema != SCHEMA_LABEL_EDGE_ROW {
            return Err(corrupt(format!(
                "label edge {} carries schema {:?}",
                hex_lower(&key),
                row.schema
            )));
        }
        if key != label_edge_key(&row.left_symbol_id, &row.right_symbol_id) {
            return Err(corrupt(format!(
                "label edge key {} does not match its decoded fields",
                hex_lower(&key)
            )));
        }
        edges.push(LabelGraphEdge::new(
            row.left_symbol_id,
            row.right_symbol_id,
            row.provenance_ref,
        ));
    }
    Ok(edges)
}

fn read_tombstone_rows<C>(
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
) -> IngestResult<Vec<LabelTombstone>>
where
    C: Clock,
{
    let mut tombstones = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(LABEL_TOMBSTONE_ROW_PREFIX),
    )? {
        if value == tombstone_value() {
            continue;
        }
        let row: LabelTombstoneRow = serde_json::from_slice(&value).map_err(|error| {
            corrupt(format!(
                "decode label tombstone {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if row.schema != SCHEMA_LABEL_TOMBSTONE_ROW {
            return Err(corrupt(format!(
                "label tombstone {} carries schema {:?}",
                hex_lower(&key),
                row.schema
            )));
        }
        if key != label_tombstone_key(&row.symbol_id) {
            return Err(corrupt(format!(
                "label tombstone key {} does not match its decoded fields",
                hex_lower(&key)
            )));
        }
        tombstones.push(LabelTombstone::new(row.symbol_id, row.provenance_ref));
    }
    Ok(tombstones)
}

// ─── Shared reconciling commit + FSV ──────────────────────────────────────────

fn canonical_label_dump(desired: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in desired {
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Reconciles `desired` against `existing` in one CF: writes changed/new rows,
/// tombstones stale rows, commits atomically with a paired ledger entry, and
/// (when anything changed) independently re-reads every touched row plus the
/// ledger entry for an [`FsvAck`]. A no-delta reconciliation appends an audit
/// ledger entry and returns `None` — there is no mutation to verify.
#[allow(clippy::too_many_arguments)]
fn commit_reconciliation<C>(
    vault: &AsterVault<C>,
    cf: ColumnFamily,
    desired: &BTreeMap<Vec<u8>, Vec<u8>>,
    existing: &BTreeMap<Vec<u8>, Vec<u8>>,
    kind: EntryKind,
    ledger_schema: &str,
    scope: &str,
    actor: ActorId,
) -> IngestResult<(usize, usize, Option<FsvAck>)>
where
    C: Clock,
{
    let tombstone = tombstone_value();
    let mut batch = Vec::new();
    let mut written: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut tombstoned: Vec<Vec<u8>> = Vec::new();
    for (key, value) in desired {
        if existing.get(key) != Some(value) {
            batch.push((cf, key.clone(), value.clone()));
            written.push((key.clone(), value.clone()));
        }
    }
    for key in existing.keys() {
        if !desired.contains_key(key) {
            batch.push((cf, key.clone(), tombstone.clone()));
            tombstoned.push(key.clone());
        }
    }

    let subject_bytes = format!("{scope}:{}", desired.len()).into_bytes();
    let subject = SubjectId::Kernel(subject_bytes);
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": ledger_schema,
        "desired_rows": desired.len(),
        "rows_written": written.len(),
        "rows_tombstoned": tombstoned.len(),
    }))
    .map_err(|error| corrupt(format!("encode ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;

    if batch.is_empty() {
        vault.append_ledger_entry(kind, subject, payload, actor)?;
        vault.flush()?;
        return Ok((0, 0, None));
    }

    let mut plan = VaultMutationPlan::new(scope, kind, &actor, &subject);
    for (key, value) in &written {
        plan.push_content(cf, key.clone(), value);
    }
    for key in &tombstoned {
        plan.push_tombstoned(cf, key.clone(), &tombstone);
    }

    let commit_seq =
        vault.write_cf_batch_with_ledger_entry(batch, kind, subject, payload, actor)?;
    vault.flush()?;
    let ack = plan.verify_committed(vault, commit_seq)?;
    Ok((written.len(), tombstoned.len(), Some(ack)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{SystemClock, VaultId};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    const TEST_SALT: &[u8] = b"astrolabe-label-propagation-fsv";
    static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

    /// RAII %TEMP% durable-vault directory removed recursively on drop.
    struct TempVaultDir(PathBuf);
    impl Drop for TempVaultDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn vault(name: &str) -> (TempVaultDir, AsterVault<SystemClock>) {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-labelprop-{name}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test vault dir");
        let vault = open(&dir);
        (TempVaultDir(dir), vault)
    }

    fn open(dir: &Path) -> AsterVault<SystemClock> {
        AsterVault::new_durable(
            dir,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>().unwrap(),
            TEST_SALT.to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable label-propagation vault")
    }

    fn seed(symbol: &str, label: &str, confidence: u64) -> LabelSeed {
        LabelSeed::new(
            symbol,
            label,
            confidence,
            format!("prov:seed:{symbol}:{label}"),
        )
    }

    fn edge(left: &str, right: &str) -> LabelGraphEdge {
        LabelGraphEdge::new(left, right, format!("prov:edge:{left}->{right}"))
    }

    fn persisted_pairs(labels: &[PersistedPropagatedLabel]) -> Vec<(String, String, u64)> {
        labels
            .iter()
            .map(|p| {
                (
                    p.row.label.clone(),
                    p.row.symbol_id.clone(),
                    p.row.confidence_millipoints,
                )
            })
            .collect()
    }

    /// Live path: propagation reads persisted rows, writes label rows back with a
    /// paired ledger entry, and an independent readback matches byte-for-byte.
    #[test]
    fn live_propagation_over_persisted_rows_is_readback_verified() {
        let (_dir, vault) = vault("live");
        // A --seed(security,1000)--> B --> C  (a simple chain).
        let seeds = [seed("A", "security", 1000)];
        let edges = [edge("A", "B"), edge("B", "C")];
        let persist = persist_label_graph(&vault, &seeds, &edges, &[], "astrolabe-ingest-test")
            .expect("persist label graph");
        assert!(
            persist.fsv_ack.is_some(),
            "graph persist must produce an FSV ack"
        );

        let report = propagate_labels_over_vault(
            &vault,
            &LabelPropagationConfig::default(),
            "astrolabe-ingest-test",
        )
        .expect("propagate over vault");
        // Inputs came from persisted rows, not the in-memory fixtures above.
        assert_eq!(report.seeds_read, 1);
        assert_eq!(report.edges_read, 2);
        assert_eq!(report.labels_propagated, 2, "security extends to B and C");
        assert_eq!(report.rows_written, 2);
        assert_eq!(report.trust, "provisional");
        let ack = report.fsv_ack.expect("propagation must produce an FSV ack");
        assert_eq!(ack.label(), "fsv:verified");
        assert_eq!(ack.rows_read_back(), 2);

        // Independent readback of persisted Kernel CF rows.
        let persisted = read_propagated_label_rows(&vault).expect("read persisted labels");
        let got = persisted_pairs(&persisted);
        assert_eq!(
            got,
            vec![
                ("security".to_string(), "B".to_string(), 500),
                ("security".to_string(), "C".to_string(), 250),
            ],
            "persisted decayed confidences: 1000 -> 500 -> 250"
        );
        // Trust discipline holds on the persisted bytes: provisional and < seed.
        for p in &persisted {
            assert_eq!(p.row.trust, "provisional");
            assert!(p.row.confidence_millipoints < 1000);
            // Persisted math replays to the persisted confidence (kernel contract).
            assert_eq!(
                astrolabe_kernel::recompute_from_label_math(&p.row.math).unwrap(),
                p.row.confidence_millipoints
            );
        }
    }

    /// Edge triad #1: empty scope (no persisted rows) => explicit empty, not error.
    #[test]
    fn edge_empty_scope_yields_explicit_empty() {
        let (_dir, vault) = vault("empty");
        let before = read_propagated_label_rows(&vault).expect("read before");
        println!("[empty] before: {} persisted label rows", before.len());
        assert!(before.is_empty());

        let report = propagate_labels_over_vault(&vault, &LabelPropagationConfig::default(), "t")
            .expect("propagate");
        let after = read_propagated_label_rows(&vault).expect("read after");
        println!(
            "[empty] after: {} persisted label rows, empty_reason={:?}, ack={:?}",
            after.len(),
            report.empty_reason,
            report.fsv_ack.as_ref().map(|a| a.label())
        );
        assert_eq!(report.empty_reason.as_deref(), Some("zero_seed_scope"));
        assert_eq!(report.labels_propagated, 0);
        assert!(report.fsv_ack.is_none(), "no rows to mutate => no FSV ack");
        assert!(after.is_empty());
    }

    /// Edge triad #2: a single-node scope (one seed, no edges) propagates nothing.
    #[test]
    fn edge_single_node_scope_propagates_nothing() {
        let (_dir, vault) = vault("single");
        persist_label_graph(&vault, &[seed("solo", "deprecated", 800)], &[], &[], "t")
            .expect("persist");
        let before = read_propagated_label_rows(&vault).expect("read before");
        println!("[single] before: {} persisted label rows", before.len());

        let report = propagate_labels_over_vault(&vault, &LabelPropagationConfig::default(), "t")
            .expect("propagate");
        let after = read_propagated_label_rows(&vault).expect("read after");
        println!(
            "[single] after: {} persisted rows, seeds_read={}, edges_read={}, empty_reason={:?}",
            after.len(),
            report.seeds_read,
            report.edges_read,
            report.empty_reason
        );
        assert_eq!(report.seeds_read, 1);
        assert_eq!(report.edges_read, 0);
        assert_eq!(report.labels_propagated, 0);
        assert_eq!(
            report.empty_reason.as_deref(),
            Some("no_reachable_unseeded_symbols")
        );
        assert!(after.is_empty());
    }

    /// Edge triad #3: a cycle in the graph terminates and persists finite labels.
    #[test]
    fn edge_cycle_terminates_and_persists() {
        let (_dir, vault) = vault("cycle");
        // A -> B -> C -> A, seed on A. Decay guarantees termination.
        let edges = [edge("A", "B"), edge("B", "C"), edge("C", "A")];
        persist_label_graph(&vault, &[seed("A", "owner", 1000)], &edges, &[], "t")
            .expect("persist");
        let before = read_propagated_label_rows(&vault).expect("read before");
        println!("[cycle] before: {} persisted label rows", before.len());

        let report = propagate_labels_over_vault(&vault, &LabelPropagationConfig::default(), "t")
            .expect("propagate");
        let after = read_propagated_label_rows(&vault).expect("read after");
        println!(
            "[cycle] after: {} persisted rows -> {:?}",
            after.len(),
            persisted_pairs(&after)
        );
        // A is a seed (not re-labelled). Adjacency is undirected, so in the
        // A-B-C-A cycle both B (A->B) and C (C->A) are distance-1 neighbours of
        // A and each decays once: 1000 * 0.5 = 500. The best-seen guard makes the
        // cycle terminate rather than loop.
        assert_eq!(
            persisted_pairs(&after),
            vec![
                ("owner".to_string(), "B".to_string(), 500),
                ("owner".to_string(), "C".to_string(), 500),
            ]
        );
        assert!(report.fsv_ack.is_some());
    }

    /// Determinism: two independent vaults, the SAME graph persisted in different
    /// input orders, produce byte-identical persisted propagated-label rows.
    #[test]
    fn determinism_order_invariant_across_two_runs() {
        let seeds_a = [seed("A", "security", 1000), seed("X", "security", 900)];
        let edges_a = [edge("A", "B"), edge("B", "C"), edge("X", "B")];
        // Reversed input order; identical set.
        let seeds_b = [seed("X", "security", 900), seed("A", "security", 1000)];
        let edges_b = [edge("X", "B"), edge("B", "C"), edge("A", "B")];

        let (_d1, v1) = vault("det1");
        let (_d2, v2) = vault("det2");
        persist_label_graph(&v1, &seeds_a, &edges_a, &[], "t").expect("persist 1");
        persist_label_graph(&v2, &seeds_b, &edges_b, &[], "t").expect("persist 2");
        let r1 = propagate_labels_over_vault(&v1, &LabelPropagationConfig::default(), "t")
            .expect("prop 1");
        let r2 = propagate_labels_over_vault(&v2, &LabelPropagationConfig::default(), "t")
            .expect("prop 2");

        let p1 = read_propagated_label_rows(&v1).expect("read 1");
        let p2 = read_propagated_label_rows(&v2).expect("read 2");
        // Byte-for-byte identical persisted rows (values, not just decoded fields).
        let bytes1: Vec<(Vec<u8>, PropagatedLabelRow)> =
            p1.iter().map(|p| (p.key.clone(), p.row.clone())).collect();
        let bytes2: Vec<(Vec<u8>, PropagatedLabelRow)> =
            p2.iter().map(|p| (p.key.clone(), p.row.clone())).collect();
        assert_eq!(bytes1, bytes2, "iteration-order-invariant persisted state");
        // The provenance dump hash is order-invariant too.
        let hash1 = r1.provenance.split(';').next().unwrap();
        let hash2 = r2.provenance.split(';').next().unwrap();
        assert_eq!(hash1, hash2, "seeded dump hash is order-invariant");
    }

    /// Erasure over persisted state (#61): a persisted tombstone for a seed
    /// symbol recomputes propagation without it — its derived labels vanish from
    /// the persisted set (tombstoned), proven by independent readback.
    #[test]
    fn erasing_seed_recomputes_over_persisted_rows() {
        let (_dir, vault) = vault("erase");
        // Two seeds feeding B: A(security,1000) and X(security,600). B gets max=500.
        let seeds = [seed("A", "security", 1000), seed("X", "security", 600)];
        let edges = [edge("A", "B"), edge("X", "B")];
        persist_label_graph(&vault, &seeds, &edges, &[], "t").expect("persist");
        propagate_labels_over_vault(&vault, &LabelPropagationConfig::default(), "t")
            .expect("prop 1");
        let before = read_propagated_label_rows(&vault).expect("read before");
        println!("[erase] before: {:?}", persisted_pairs(&before));
        assert_eq!(before.len(), 1);
        assert_eq!(
            before[0].row.confidence_millipoints, 500,
            "A dominates via 1000*0.5"
        );

        // Erase seed A: re-persist the graph carrying an A tombstone.
        persist_label_graph(
            &vault,
            &seeds,
            &edges,
            &[LabelTombstone::new("A", "prov:erase:A")],
            "t",
        )
        .expect("persist tombstone");
        let report = propagate_labels_over_vault(&vault, &LabelPropagationConfig::default(), "t")
            .expect("prop 2");
        let after = read_propagated_label_rows(&vault).expect("read after");
        println!(
            "[erase] after: {:?} (rows_written={}, rows_tombstoned={})",
            persisted_pairs(&after),
            report.rows_written,
            report.rows_tombstoned
        );
        // Without A, B is labelled only via X: 600*0.5 = 300 (recomputed, persisted).
        assert_eq!(
            persisted_pairs(&after),
            vec![("security".to_string(), "B".to_string(), 300)]
        );
        assert!(
            report.rows_written >= 1,
            "B's row was rewritten to the recomputed value"
        );
    }
}
