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
    let actor = ActorId::Service(actor.into());
    let ledger_ref = if batch.is_empty() {
        vault.append_ledger_entry(EntryKind::Measure, subject, payload, actor)?
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Measure,
            subject,
            payload,
            actor,
        )?;
        ledger_ref_at_commit(vault, commit_seq)?
    };
    vault.flush()?;

    Ok(EagerCrossTermPersistReport {
        symbol_count: symbols.len(),
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        absent_by_kind,
        xterm_dump_hash,
        ledger_ref,
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
pub fn read_eager_cross_term_rows<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<PersistedEagerCrossTermRow>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::XTerm)? {
        let row: XtermRow = serde_json::from_slice(&value).map_err(|error| {
            xterm_corrupt(format!(
                "decode XTerm row {}: {error}",
                hex_lower_bytes(&key)
            ))
        })?;
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
    Ok(rows)
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
    let mut sums = BTreeMap::<EagerAgreementKind, (f64, usize)>::new();
    for persisted in read_eager_cross_term_rows(vault)? {
        if let LoomCrossTermValue::Scalar(value) = persisted.row.value {
            let entry = sums.entry(persisted.kind).or_default();
            entry.0 += f64::from(value);
            entry.1 += 1;
        }
    }
    Ok(EagerAgreementKind::ALL
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
                provenance: "AsterVault:ColumnFamily::XTerm:agreement",
            }
        })
        .collect())
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
