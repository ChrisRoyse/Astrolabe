//! XTerm CF persistence for the six designed eager agreement cross-terms.
//!
//! Materialization policy (blueprint 07 §4): of the 231 possible slot pairs
//! per symbol, exactly the six designed agreement pairs are persisted eagerly;
//! every other pair stays lazy (computed on demand, never persisted
//! per-record — the pair-gain interaction gate lands in P5). Absent
//! cross-terms are never written as zeros: a row is persisted only for a
//! scalar value, and every absent row is counted per reason in the persist
//! report and its paired ledger entry.
//!
//! Rows are loom-native [`XtermRow`] JSON at `xterm_key(cx, left, right,
//! Agreement)` — the exact shape `live_anomaly_inputs_from_vault` already
//! reads back — so the doc-drift and name-truth detectors run off persisted
//! state, not planner echoes.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, XTermKind, xterm_key};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, CxId, LedgerRef, SlotId, VaultStore};
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use calyx_loom::agreement_graph::XtermRow;
use calyx_loom::{
    CrossTermKey, CrossTermKind as LoomCrossTermKind, CrossTermValue as LoomCrossTermValue,
    SignalProvenanceTag,
};
use serde::Serialize;

use crate::sim_rows::ledger_ref_at_commit;
use crate::{
    CrossTermValue, EagerAgreementKind, EagerCrossTermPlan, EagerCrossTermRow, hex_lower_bytes,
};

/// Ledger payload schema for an eager cross-term persistence group commit.
pub const XTERM_EAGER_LEDGER_SCHEMA: &str = "astrolabe.eager_xterm.v1";
/// Stable schema for the `get_architecture` agreement-graph aspect payload.
pub const AGREEMENT_GRAPH_ASPECT_SCHEMA: &str = "astrolabe.agreement_graph_aspect.v1";
/// Provenance label naming the physical source of the agreement-graph aspect.
pub const AGREEMENT_GRAPH_ASPECT_PROVENANCE: &str = "AsterVault:ColumnFamily::XTerm:agreement";
/// Stable failure code for corrupt or inconsistent persisted xterm rows.
pub const ASTRO_XTERM_ROW_CORRUPT: &str = "ASTRO_XTERM_ROW_CORRUPT";
/// Stable failure code for a plan row whose symbol has no CxId mapping.
pub const ASTRO_XTERM_CX_ID_MISSING: &str = "ASTRO_XTERM_CX_ID_MISSING";

const XTERM_REMEDIATION: &str = "regenerate eager cross-term rows with astrolabe_weave::persist_eager_cross_terms from a fresh plan";

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
    /// Ledger entry paired with this mutation batch.
    pub ledger_ref: LedgerRef,
    /// Unforgeable full-readback witness when XTerm rows changed.
    /// A ledger-only no-delta replay carries labeled absence (`None`).
    pub fsv: Option<FsvAck>,
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

/// Persists the six designed eager agreement cross-terms for a plan.
///
/// `cx_ids` maps each planned qualified name to its constellation id; a plan
/// row without a mapping refuses fail-closed (`ASTRO_XTERM_CX_ID_MISSING`) —
/// persistence never silently drops a symbol. Scalar rows reconcile against
/// the owned key set (all six designed kinds for every mapped CxId): rows are
/// written when new or changed, kept when byte-identical, and tombstoned when
/// the fresh plan no longer produces a scalar for that key. The batch and its
/// ledger entry land in one atomic group commit.
pub fn persist_eager_cross_terms<C>(
    vault: &AsterVault<C>,
    plan: &EagerCrossTermPlan,
    cx_ids: &BTreeMap<String, CxId>,
    actor: impl Into<String>,
) -> calyx_core::Result<EagerCrossTermPersistReport>
where
    C: Clock,
{
    persist_eager_cross_terms_owned(vault, plan, cx_ids, None, actor.into())
}

/// Persists a dirty-symbol eager cross-term delta without touching clean symbols.
///
/// `plan` and `cx_ids` cover the current changed symbols. `removed_cx_ids`
/// contributes all six designed ownership keys so stale rows for deleted or
/// superseded versions are tombstoned. Clean CxIds are neither scanned nor
/// rewritten; prior MVCC versions remain readable.
pub fn persist_eager_cross_terms_delta<C>(
    vault: &AsterVault<C>,
    plan: &EagerCrossTermPlan,
    cx_ids: &BTreeMap<String, CxId>,
    removed_cx_ids: &BTreeSet<CxId>,
    actor: impl Into<String>,
) -> calyx_core::Result<EagerCrossTermPersistReport>
where
    C: Clock,
{
    persist_eager_cross_terms_owned(vault, plan, cx_ids, Some(removed_cx_ids), actor.into())
}

fn persist_eager_cross_terms_owned<C>(
    vault: &AsterVault<C>,
    plan: &EagerCrossTermPlan,
    cx_ids: &BTreeMap<String, CxId>,
    removed_cx_ids: Option<&BTreeSet<CxId>>,
    actor: String,
) -> calyx_core::Result<EagerCrossTermPersistReport>
where
    C: Clock,
{
    let mut new_rows = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut owned_keys = BTreeSet::<Vec<u8>>::new();
    let mut absent_by_kind = BTreeMap::<EagerAgreementKind, usize>::new();
    let mut symbols = BTreeSet::<&str>::new();

    for row in &plan.rows {
        let Some(&cx_id) = cx_ids.get(&row.qualified_name) else {
            return Err(CalyxError {
                code: ASTRO_XTERM_CX_ID_MISSING,
                message: format!(
                    "no CxId mapping for planned symbol {:?}",
                    row.qualified_name
                ),
                remediation: "pass a cx_ids map covering every planned qualified name",
            });
        };
        symbols.insert(row.qualified_name.as_str());
        let key = eager_xterm_key(cx_id, row.kind);
        owned_keys.insert(key.clone());
        match &row.value {
            CrossTermValue::Scalar(value) => {
                let encoded = encode_xterm_row(cx_id, row, *value)?;
                if new_rows.insert(key, encoded).is_some() {
                    return Err(xterm_corrupt(format!(
                        "plan holds duplicate {} row for {:?}",
                        row.kind.wire_name(),
                        row.qualified_name
                    )));
                }
            }
            CrossTermValue::Absent { .. } => {
                *absent_by_kind.entry(row.kind).or_default() += 1;
            }
        }
    }
    // Reconcile the entire designed-pair ownership domain, not only CxIds in
    // the fresh plan. A removed live symbol is absent from `cx_ids`; retaining
    // its old XTerm row would make the live agreement/anomaly projection stale.
    // MVCC still preserves the tombstoned row at prior snapshots.
    match removed_cx_ids {
        None => {
            for persisted in read_eager_cross_term_rows(vault)? {
                owned_keys.insert(persisted.key);
            }
        }
        Some(removed) => {
            for cx_id in removed {
                for kind in EagerAgreementKind::ALL {
                    owned_keys.insert(eager_xterm_key(*cx_id, kind));
                }
            }
        }
    }

    let dump = eager_xterm_dump_bytes(plan, cx_ids)?;
    let xterm_dump_hash = hex_lower_bytes(blake3::hash(&dump).as_bytes());

    let snapshot = vault.snapshot();
    let mut batch = Vec::new();
    let mut rows_written = 0usize;
    let mut rows_unchanged = 0usize;
    let mut rows_tombstoned = 0usize;
    let tombstone = tombstone_value();
    for key in &owned_keys {
        let existing = vault.read_cf_at(snapshot, ColumnFamily::XTerm, key)?;
        match (new_rows.get(key), existing) {
            (Some(value), Some(existing_value)) if existing_value == *value => {
                rows_unchanged += 1;
            }
            (Some(value), _) => {
                batch.push((ColumnFamily::XTerm, key.clone(), value.clone()));
                rows_written += 1;
            }
            (None, Some(_)) => {
                batch.push((ColumnFamily::XTerm, key.clone(), tombstone.clone()));
                rows_tombstoned += 1;
            }
            (None, None) => {}
        }
    }

    let absent_counts: BTreeMap<&'static str, usize> = absent_by_kind
        .iter()
        .map(|(kind, count)| (kind.wire_name(), *count))
        .collect();
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": XTERM_EAGER_LEDGER_SCHEMA,
        "symbol_count": symbols.len(),
        "designed_pair_count": EagerAgreementKind::ALL.len(),
        "rows_written": rows_written,
        "rows_unchanged": rows_unchanged,
        "rows_tombstoned": rows_tombstoned,
        "absent_by_kind": absent_counts,
        "abundance": {
            "symbol_count": plan.abundance.symbol_count,
            "panel_slot_count": plan.abundance.panel_slot_count,
            "possible_pair_count_per_symbol": plan.abundance.possible_pair_count_per_symbol,
            "raw_yield": plan.abundance.raw_yield,
            "eager_pair_count_per_symbol": plan.abundance.eager_pair_count_per_symbol,
            "materialized_count": plan.abundance.materialized_count,
            "scalar_count": plan.abundance.scalar_count,
            "absent_count": plan.abundance.absent_count,
            "lazy_pair_count": plan.abundance.lazy_pair_count,
        },
        "xterm_dump_hash": xterm_dump_hash,
    }))
    .map_err(|error| xterm_corrupt(format!("encode eager xterm ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;

    let subject = SubjectId::Query(format!("astrolabe-eager-xterm:{xterm_dump_hash}").into_bytes());
    let actor = ActorId::Service(actor);
    let mut fsv_plan = VaultMutationPlan::new(
        "persist_eager_cross_terms",
        EntryKind::Measure,
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
    let (ledger_ref, commit_seq) = if batch.is_empty() {
        (
            vault.append_ledger_entry(EntryKind::Measure, subject, payload, actor)?,
            None,
        )
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Measure,
            subject,
            payload,
            actor,
        )?;
        (ledger_ref_at_commit(vault, commit_seq)?, Some(commit_seq))
    };
    vault.flush()?;
    let fsv = commit_seq
        .map(|commit_seq| fsv_plan.verify_committed(vault, commit_seq))
        .transpose()?;

    Ok(EagerCrossTermPersistReport {
        symbol_count: symbols.len(),
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        absent_by_kind,
        xterm_dump_hash,
        ledger_ref,
        fsv,
    })
}

/// One decoded, key-verified designed-pair agreement row from the XTerm CF.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedEagerCrossTermRow {
    /// Full XTerm CF key the row was stored under.
    pub key: Vec<u8>,
    /// Designed pair this row belongs to.
    pub kind: EagerAgreementKind,
    /// Decoded loom row.
    pub row: XtermRow,
}

/// Reads back every persisted designed-pair agreement row.
///
/// Scans the whole XTerm CF, fails closed on undecodable rows or key/field
/// mismatches (the CF-wide `XtermRow` JSON shape is already the contract the
/// live anomaly reader enforces), and returns exactly the rows whose slot pair
/// and kind match one of the six designed agreements.
///
/// `ColumnFamily::XTerm` is shared with the layout lane's `placement_truth`
/// co-tenant rows (#369); those are skipped (co-tenant-aware) exactly as the
/// live-anomaly reader does. Use [`read_eager_cross_term_rows_with_cotenants`]
/// when the count of skipped co-tenant rows must be surfaced.
pub fn read_eager_cross_term_rows<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<PersistedEagerCrossTermRow>>
where
    C: Clock,
{
    Ok(read_eager_cross_term_rows_with_cotenants(vault)?.0)
}

/// [`read_eager_cross_term_rows`] returning the count of shared-CF co-tenant
/// rows skipped (layout `placement_truth` rows, #369) alongside the designed
/// rows — a counted, labeled skip, not an error. A genuinely corrupt xterm row
/// (undecodable, no accepted co-tenant schema marker) still fails closed.
pub fn read_eager_cross_term_rows_with_cotenants<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<(Vec<PersistedEagerCrossTermRow>, usize)>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let accepted_cotenants = crate::accepted_xterm_cotenant_schemas();
    let mut rows = Vec::new();
    let mut cotenant_skipped = 0usize;
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::XTerm)? {
        let row: XtermRow = match serde_json::from_slice(&value) {
            Ok(row) => row,
            Err(error) => {
                if crate::is_accepted_xterm_cotenant(&value, &accepted_cotenants) {
                    cotenant_skipped += 1;
                    continue;
                }
                return Err(xterm_corrupt(format!(
                    "decode XTerm row {}: {error}",
                    hex_lower_bytes(&key)
                )));
            }
        };
        let expected_key = xterm_key(
            row.key.cx_id,
            row.key.a,
            row.key.b,
            xterm_kind_wire(row.key.kind),
        );
        if key != expected_key {
            return Err(xterm_corrupt(format!(
                "XTerm row key {} does not match its decoded fields",
                hex_lower_bytes(&key)
            )));
        }
        if row.key.kind != LoomCrossTermKind::Agreement {
            continue;
        }
        let Some(kind) = designed_kind_for_slots(row.key.a, row.key.b) else {
            continue;
        };
        rows.push(PersistedEagerCrossTermRow { key, kind, row });
    }
    Ok((rows, cotenant_skipped))
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
    let (rows, cotenant_skipped) = read_eager_cross_term_rows_with_cotenants(vault)?;
    for persisted in rows {
        if let LoomCrossTermValue::Scalar(value) = persisted.row.value {
            let entry = sums.entry(persisted.kind).or_default();
            entry.0 += f64::from(value);
            entry.1 += 1;
        }
    }
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
    Ok((edges, cotenant_skipped))
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

/// Computes one lazy (non-designed) agreement on demand.
///
/// Lazy pairs are never persisted per-record; this recomputes the direct
/// agreement between two slots of one symbol from its in-memory slot vectors,
/// returning the same absent-aware [`CrossTermValue`] semantics as the eager
/// planner. Corpus-wide lazy assay caching lands with the P5 pair-gain gate.
pub fn lazy_agreement(
    node: &crate::SimilarityNode,
    left_slot: SlotId,
    right_slot: SlotId,
) -> CrossTermValue {
    crate::lazy_direct_agreement(node, left_slot, right_slot)
}

/// Canonical byte dump of a plan's persisted scalar rows (for the ledger
/// content hash and determinism probes). One line per scalar row in plan
/// order: kind, qualified name, cx id, slots, and the exact IEEE-754 bit
/// pattern of the scalar.
pub fn eager_xterm_dump_bytes(
    plan: &EagerCrossTermPlan,
    cx_ids: &BTreeMap<String, CxId>,
) -> calyx_core::Result<Vec<u8>> {
    let mut out = String::new();
    for row in &plan.rows {
        let CrossTermValue::Scalar(value) = &row.value else {
            continue;
        };
        let Some(cx_id) = cx_ids.get(&row.qualified_name) else {
            return Err(CalyxError {
                code: ASTRO_XTERM_CX_ID_MISSING,
                message: format!(
                    "no CxId mapping for planned symbol {:?}",
                    row.qualified_name
                ),
                remediation: "pass a cx_ids map covering every planned qualified name",
            });
        };
        out.push_str(row.kind.wire_name());
        out.push('\t');
        out.push_str(&row.qualified_name);
        out.push('\t');
        out.push_str(&cx_id.to_string());
        out.push('\t');
        out.push_str(&row.left_slot.get().to_string());
        out.push('\t');
        out.push_str(&row.right_slot.get().to_string());
        out.push('\t');
        out.push_str(&format!("{:08x}", value.to_bits()));
        out.push('\n');
    }
    Ok(out.into_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use calyx_aster::vault::VaultOptions;
    use calyx_core::{SystemClock, VaultId};

    use crate::CrossTermAbundance;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    const TEST_SALT: &[u8] = b"astrolabe-weave-xterm-aspect-fsv";

    fn vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn fresh_vault(name: &str) -> (PathBuf, AsterVault<SystemClock>) {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-weave-xterm-aspect-{name}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test vault dir");
        let vault = AsterVault::new_durable(
            &dir,
            vault_id(),
            TEST_SALT.to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable test vault");
        (dir, vault)
    }

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }

    fn scalar_row(name: &str, kind: EagerAgreementKind, value: f32) -> EagerCrossTermRow {
        let (left_slot, right_slot) = kind.slots();
        EagerCrossTermRow {
            qualified_name: name.to_string(),
            kind,
            left_slot,
            right_slot,
            value: CrossTermValue::Scalar(value),
            persisted: true,
        }
    }

    fn plan_with(rows: Vec<EagerCrossTermRow>) -> EagerCrossTermPlan {
        EagerCrossTermPlan {
            rows,
            agreement_graph: Vec::new(),
            abundance: CrossTermAbundance {
                symbol_count: 0,
                panel_slot_count: 0,
                possible_pair_count_per_symbol: 0,
                raw_yield: 0,
                eager_pair_count_per_symbol: 0,
                materialized_count: 0,
                scalar_count: 0,
                absent_count: 0,
                lazy_pair_count: 0,
            },
        }
    }

    fn edge<'a>(aspect: &'a AgreementGraphAspect, wire: &str) -> &'a PersistedAgreementEdge {
        aspect
            .edges
            .iter()
            .find(|edge| edge.kind.as_str() == wire)
            .expect("designed edge present in aspect")
    }

    // Empty-graph edge of the triad: a vault with no persisted XTerm rows yields
    // all six designed edges with `None` means (never zero-filled), status
    // `empty`, and the full HONEST label set; the aspect equals an independent
    // persisted-state readback.
    #[test]
    fn agreement_graph_aspect_empty_vault_reports_empty_with_labels() {
        let (dir, vault) = fresh_vault("empty");
        let aspect = agreement_graph_aspect(&vault).expect("aspect from empty vault");

        assert_eq!(aspect.schema, AGREEMENT_GRAPH_ASPECT_SCHEMA);
        assert_eq!(aspect.status, "empty");
        assert_eq!(aspect.provenance, AGREEMENT_GRAPH_ASPECT_PROVENANCE);
        assert_eq!(aspect.freshness, "fresh");
        assert_eq!(aspect.trust, "verified");
        assert_eq!(aspect.edge_count, EagerAgreementKind::ALL.len());
        assert_eq!(aspect.populated_edge_count, 0);
        assert_eq!(aspect.scalar_row_count, 0);
        for designed in &aspect.edges {
            assert_eq!(designed.mean_agreement, None);
            assert_eq!(designed.scalar_count, 0);
        }

        let independent =
            agreement_graph_from_persisted_rows(&vault).expect("independent readback");
        assert_eq!(aspect.edges, independent);

        drop(vault);
        let _ = fs::remove_dir_all(&dir);
    }

    // Single-node/built edge of the triad: persist real scalar rows through the
    // production `persist_eager_cross_terms` path, then prove the aspect is the
    // independent persisted-state readback (not a planner echo), that means are
    // the seed-independent arithmetic mean of the contributing scalars, that
    // absent designed pairs stay `None`, and that the payload is deterministic.
    #[test]
    fn agreement_graph_aspect_built_matches_persisted_readback_deterministically() {
        let (dir, vault) = fresh_vault("built");
        let cx_ids = BTreeMap::from([("sym::a".to_string(), cx(1)), ("sym::b".to_string(), cx(2))]);
        let plan = plan_with(vec![
            scalar_row("sym::a", EagerAgreementKind::DocDrift, 0.8),
            scalar_row("sym::b", EagerAgreementKind::DocDrift, 0.4),
            scalar_row("sym::a", EagerAgreementKind::NameTruth, 0.5),
        ]);
        let report =
            persist_eager_cross_terms(&vault, &plan, &cx_ids, "test-actor").expect("persist");
        assert_eq!(report.rows_written, 3);

        let aspect = agreement_graph_aspect(&vault).expect("aspect over persisted rows");
        assert_eq!(aspect.status, "built");
        assert_eq!(aspect.populated_edge_count, 2);
        assert_eq!(aspect.scalar_row_count, 3);

        // Mean matches the implementation's f64-accumulate-then-cast semantics.
        let expected_doc = ((f64::from(0.8f32) + f64::from(0.4f32)) / 2.0) as f32;
        let doc = edge(&aspect, "DOC_DRIFT");
        assert_eq!(doc.scalar_count, 2);
        assert_eq!(doc.mean_agreement, Some(expected_doc));
        let name = edge(&aspect, "NAME_TRUTH");
        assert_eq!(name.scalar_count, 1);
        assert_eq!(name.mean_agreement, Some(0.5));
        for wire in [
            "CLONE_TAXONOMY",
            "COMPLEXITY_CHURN",
            "CENTRALITY_COVERAGE",
            "ROUTE_MATCH",
        ] {
            let absent = edge(&aspect, wire);
            assert_eq!(absent.mean_agreement, None, "{wire} must stay None");
            assert_eq!(absent.scalar_count, 0, "{wire} must have no scalars");
        }

        let independent =
            agreement_graph_from_persisted_rows(&vault).expect("independent readback");
        assert_eq!(
            aspect.edges, independent,
            "aspect must be the persisted-state readback, not a planner echo"
        );

        // Determinism: a second recompute over the same persisted bytes is
        // byte-identical serialized JSON.
        let again = agreement_graph_aspect(&vault).expect("second aspect");
        assert_eq!(
            serde_json::to_vec(&aspect).unwrap(),
            serde_json::to_vec(&again).unwrap(),
        );

        drop(vault);
        let _ = fs::remove_dir_all(&dir);
    }

    // Invalid-input edge of the triad: a persisted XTerm row missing its lens
    // columns (undecodable as an `XtermRow`) makes the aspect fail closed with
    // the stable `ASTRO_XTERM_ROW_CORRUPT` code, message, and remediation — no
    // partial or silently-degraded graph is emitted.
    #[test]
    fn agreement_graph_aspect_fails_closed_on_row_missing_lens_columns() {
        let (dir, vault) = fresh_vault("corrupt");
        let key = eager_xterm_key(cx(7), EagerAgreementKind::DocDrift);
        vault
            .write_cf(ColumnFamily::XTerm, key, b"{}".to_vec())
            .expect("inject corrupt row");
        vault.flush().expect("flush corrupt row");

        let err = agreement_graph_aspect(&vault).expect_err("must fail closed on corrupt row");
        assert_eq!(err.code, ASTRO_XTERM_ROW_CORRUPT);
        assert!(
            !err.message.is_empty(),
            "fail-closed error carries a message"
        );
        assert!(
            !err.remediation.is_empty(),
            "fail-closed error carries a remediation"
        );

        drop(vault);
        let _ = fs::remove_dir_all(&dir);
    }
}
