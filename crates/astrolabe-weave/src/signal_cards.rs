//! Index-time per-axis signal-ranking producer (#379) — the write counterpart of
//! the `get_architecture` `signal_ranking` aspect
//! (`astrolabe-server` `read_signal_ranking_aspect`).
//!
//! Wave-14 landed the aspect reader (it enumerates persisted
//! `assay_card.signals.axis:*` config rows), but nothing on a real corpus ever
//! produced those cards, so the aspect served labeled-`unavailable` forever
//! (#379). This module is the producer: at index time it derives a small set of
//! **real, per-symbol structural axes** from the persisted graph snapshot and
//! measures every dense panel slot's mutual information about each axis with the
//! assay bits machinery ([`astrolabe_assay::measure_slot_bits`]), yielding one
//! [`SignalRankingCard`] per axis. The server hook persists each card to the
//! config store (keyed `assay_card.signals.axis:{axis}`) and ledger-pairs it via
//! [`astrolabe_assay::CardLedger`], so the aspect then serves real measured bits.
//!
//! The axes are graph-structural, so every indexed symbol has a ground-truth
//! value with no external labels required:
//!
//! * **`symbol_kind`** (discrete) — the symbol's node label as a class; a slot's
//!   bits about it measure how much that lens separates symbol kinds.
//! * **`structural_degree`** (continuous) — the symbol's incident-edge count; a
//!   slot's bits about it measure how much that lens tracks graph connectivity.
//!
//! Honest degradation: an axis with fewer than two distinct values across the
//! sample (a constant axis carries no information to measure) and a slot with no
//! dense vectors are **labeled absences** counted in [`SignalCardProduction`],
//! never a fabricated card. When no axis yields a card, nothing is persisted and
//! the aspect stays labeled-`unavailable` — genuinely absent, not faked.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_assay::{
    AxisValues, BitsConfig, SignalBits, SignalRankingCard, SlotObservations, SlotValues,
    measure_slot_bits,
};
use astrolabe_ingest::{CbmGraphSnapshot, read_cbm_graph_snapshot};
use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::mvcc::{OrderedReadbackMetrics, is_tombstone_value};
use calyx_aster::vault::encode::decode_slot_vector;
use calyx_aster::vault::{AsterVault, OrderedCfRead, SstReadSession};
use calyx_core::{CalyxError, Clock, CxId, Result, SlotId, SlotVector};

/// Axis name for the discrete symbol-kind (node-label) axis.
pub const SIGNAL_AXIS_SYMBOL_KIND: &str = "symbol_kind";
/// Axis name for the continuous structural-degree (incident-edge count) axis.
pub const SIGNAL_AXIS_STRUCTURAL_DEGREE: &str = "structural_degree";

/// One indexed symbol's ground-truth values on the index-time structural axes.
#[derive(Clone, Debug, PartialEq)]
pub struct SymbolAxes {
    /// The symbol's canonical identity (its slot rows key on this).
    pub cx_id: CxId,
    /// The symbol's node-label class id for the discrete `symbol_kind` axis.
    pub kind_class: i64,
    /// The symbol's incident-edge count for the continuous `structural_degree` axis.
    pub degree: f64,
}

/// Labeled outcome of one index-time signal-card production pass. Every axis and
/// slot that did not yield a measured signal is accounted for here so an absence
/// reads as honest silence, not a fabricated card (invariant 3).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignalCardProduction {
    /// The measured per-axis cards (one per axis that carried information).
    pub cards: Vec<SignalRankingCard>,
    /// Non-structural symbols with a canonical identity the pass measured over.
    pub symbols_measured: usize,
    /// Axes skipped because they carried fewer than two distinct values across
    /// the sample (a constant axis has no information to measure) — labeled.
    pub axes_skipped_degenerate: usize,
    /// Slots skipped because they had no dense vector across the sample — labeled.
    pub slots_skipped_no_dense: usize,
    /// Exact physical accounting for every Slot-CF key requested by this pass.
    pub readback: OrderedReadbackMetrics,
}

/// Derives each non-structural symbol's structural axis values from a persisted
/// graph snapshot. The `symbol_kind` class id is the symbol's node label's rank
/// in the sorted set of distinct labels (deterministic, worker-count invariant);
/// the `structural_degree` is the count of graph edges incident on the symbol.
/// Only nodes that are non-structural and carry a canonical `cx_id` are symbols;
/// the result is ordered by `cx_id` for deterministic downstream alignment.
pub fn derive_symbol_axes(snapshot: &CbmGraphSnapshot) -> Vec<SymbolAxes> {
    // Distinct node labels among the measured symbols → deterministic class ids.
    let mut labels: BTreeSet<&str> = BTreeSet::new();
    for node in &snapshot.nodes {
        if !node.structural && node.cx_id.is_some() {
            labels.insert(node.label.as_str());
        }
    }
    let class_of: BTreeMap<&str, i64> = labels
        .into_iter()
        .enumerate()
        .map(|(index, label)| (label, index as i64))
        .collect();

    // Incident-edge counts by symbol.
    let mut degree: BTreeMap<CxId, f64> = BTreeMap::new();
    for edge in &snapshot.edges {
        if let Some(src) = edge.src {
            *degree.entry(src).or_default() += 1.0;
        }
        if let Some(dst) = edge.dst {
            *degree.entry(dst).or_default() += 1.0;
        }
    }

    let mut symbols: BTreeMap<CxId, SymbolAxes> = BTreeMap::new();
    for node in &snapshot.nodes {
        if node.structural {
            continue;
        }
        let Some(cx_id) = node.cx_id else {
            continue;
        };
        let kind_class = *class_of.get(node.label.as_str()).unwrap_or(&0);
        symbols.entry(cx_id).or_insert(SymbolAxes {
            cx_id,
            kind_class,
            degree: degree.get(&cx_id).copied().unwrap_or(0.0),
        });
    }
    symbols.into_values().collect()
}

/// The aligned observation matrix for one slot: every measured symbol that has a
/// dense vector for the slot contributes one row, together with that symbol's
/// axis values (kept in lockstep so `values[i]` ↔ `kind[i]` ↔ `degree[i]`).
struct SlotAlignment {
    dim: usize,
    rows: Vec<Vec<f64>>,
    kind: Vec<i64>,
    degree: Vec<f64>,
}

/// Reads one slot's dense vectors for the given symbols, aligned with each
/// symbol's axis values. A symbol with no dense vector for the slot, or a vector
/// whose width differs from the slot's modal width, is simply not sampled (MMD
/// and the bits estimator both need equal-dimension points); alignment across the
/// row, kind, and degree vectors is preserved.
fn align_slot<C>(
    session: &SstReadSession<'_, C>,
    slot: SlotId,
    symbols: &[SymbolAxes],
) -> Result<(Option<SlotAlignment>, OrderedReadbackMetrics)>
where
    C: Clock,
{
    let keys = symbols
        .iter()
        .map(|symbol| slot_key(symbol.cx_id))
        .collect::<Vec<_>>();
    let reads = keys
        .iter()
        .enumerate()
        .map(|(ordinal, key)| OrderedCfRead::new(ordinal, ColumnFamily::slot(slot), key))
        .collect::<Vec<_>>();
    let mut dense_by_symbol: Vec<Option<Vec<f64>>> = vec![None; symbols.len()];
    let metrics =
        session.visit_ordered_cf_plan::<CalyxError, _>(&reads, |ordinal, _, _, persisted| {
            let Some(bytes) = persisted.filter(|bytes| !is_tombstone_value(bytes)) else {
                return Ok(());
            };
            if let SlotVector::Dense { data, .. } = decode_slot_vector(bytes)? {
                dense_by_symbol[ordinal] = Some(data.into_iter().map(f64::from).collect());
            }
            Ok(())
        })?;
    let mut rows: Vec<Vec<f64>> = Vec::new();
    let mut kind: Vec<i64> = Vec::new();
    let mut degree: Vec<f64> = Vec::new();
    let mut dim: Option<usize> = None;
    for (symbol, dense) in symbols.iter().zip(dense_by_symbol) {
        let Some(data) = dense else {
            continue;
        };
        let width = data.len();
        match dim {
            None => dim = Some(width),
            // A slot's dense vectors are fixed-width; a stray mismatch is not
            // sampled rather than corrupting the equal-dimension contract.
            Some(expected) if expected != width => continue,
            Some(_) => {}
        }
        rows.push(data);
        kind.push(symbol.kind_class);
        degree.push(symbol.degree);
    }
    match dim {
        Some(dim) if !rows.is_empty() => Ok((
            Some(SlotAlignment {
                dim,
                rows,
                kind,
                degree,
            }),
            metrics,
        )),
        _ => Ok((None, metrics)),
    }
}

/// True when an integer axis carries at least two distinct values (else it is a
/// constant axis with no information to measure — a labeled degenerate absence).
fn discrete_axis_informative(values: &[i64]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() >= 2
}

/// True when a continuous axis carries at least two distinct values.
fn continuous_axis_informative(values: &[f64]) -> bool {
    values
        .iter()
        .map(|value| value.to_bits())
        .collect::<BTreeSet<_>>()
        .len()
        >= 2
}

/// Sorts per-slot signals into a [`SignalRankingCard`] the same way
/// [`astrolabe_assay::build_signal_ranking`] does: descending bits, then
/// ascending slot name for a deterministic tie-break.
fn ranking_card(axis: &str, mut signals: Vec<SignalBits>) -> SignalRankingCard {
    signals.sort_by(|a, b| {
        b.bits
            .partial_cmp(&a.bits)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.slot.cmp(&b.slot))
    });
    SignalRankingCard {
        axis: axis.to_string(),
        signals,
    }
}

/// Measures every slot's bits about each index-time axis over the given symbols,
/// assembling one [`SignalRankingCard`] per informative axis. The slot rows are
/// read from the vault at `vault.latest_seq()`; the ranking is a pure function of
/// the persisted vectors, the derived axes, `seed`, and the declared bits config.
pub fn signal_cards_from_symbol_axes<C>(
    vault: &AsterVault<C>,
    symbols: &[SymbolAxes],
    slots: &[SlotId],
    seed: u64,
) -> Result<SignalCardProduction>
where
    C: Clock,
{
    let cfg = BitsConfig::from_defaults().map_err(|error| {
        CalyxError::aster_corrupt_shard(format!("bits config unavailable: {error}"))
    })?;
    let at_seq = vault.latest_seq();
    let session = vault.sst_read_session_at(at_seq)?;

    let mut kind_signals: Vec<SignalBits> = Vec::new();
    let mut degree_signals: Vec<SignalBits> = Vec::new();
    let mut report = SignalCardProduction {
        symbols_measured: symbols.len(),
        readback: OrderedReadbackMetrics {
            session_snapshot_seq: at_seq,
            ..OrderedReadbackMetrics::default()
        },
        ..SignalCardProduction::default()
    };

    for slot in slots {
        let (alignment, readback) = align_slot(&session, *slot, symbols)?;
        report.readback.checked_merge(readback)?;
        let Some(alignment) = alignment else {
            report.slots_skipped_no_dense += 1;
            continue;
        };
        let slot_name = format!("S{}", slot.get());
        let observations = SlotObservations {
            slot: slot_name.clone(),
            values: SlotValues::Embedding {
                dim: alignment.dim,
                rows: alignment.rows,
            },
        };
        if discrete_axis_informative(&alignment.kind) {
            let axis = AxisValues::Discrete(alignment.kind.clone());
            kind_signals.push(measure_slot_bits(&observations, &axis, seed, &cfg).map_err(
                |error| {
                    CalyxError::aster_corrupt_shard(format!(
                        "measure {slot_name} bits about {SIGNAL_AXIS_SYMBOL_KIND}: {error}"
                    ))
                },
            )?);
        }
        if continuous_axis_informative(&alignment.degree) {
            let axis = AxisValues::Continuous(alignment.degree.clone());
            degree_signals.push(measure_slot_bits(&observations, &axis, seed, &cfg).map_err(
                |error| {
                    CalyxError::aster_corrupt_shard(format!(
                        "measure {slot_name} bits about {SIGNAL_AXIS_STRUCTURAL_DEGREE}: {error}"
                    ))
                },
            )?);
        }
    }

    if kind_signals.is_empty() {
        report.axes_skipped_degenerate += 1;
    } else {
        report
            .cards
            .push(ranking_card(SIGNAL_AXIS_SYMBOL_KIND, kind_signals));
    }
    if degree_signals.is_empty() {
        report.axes_skipped_degenerate += 1;
    } else {
        report
            .cards
            .push(ranking_card(SIGNAL_AXIS_STRUCTURAL_DEGREE, degree_signals));
    }
    Ok(report)
}

/// Full index-time signal-card pass over a real shadow vault: read the graph
/// snapshot, derive each symbol's structural axes, and measure every dense slot's
/// bits about each axis. Returns the measured cards plus labeled absences; the
/// server hook persists the cards to the config store and ledger-pairs them.
pub fn measure_index_time_signal_cards<C>(
    vault: &AsterVault<C>,
    project: &str,
    slots: &[SlotId],
    seed: u64,
) -> Result<SignalCardProduction>
where
    C: Clock,
{
    let snapshot = read_cbm_graph_snapshot(vault, project).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!("read graph snapshot: {error}"))
    })?;
    let symbols = derive_symbol_axes(&snapshot);
    signal_cards_from_symbol_axes(vault, &symbols, slots, seed)
}
