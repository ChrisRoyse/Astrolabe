//! Index-time MMD drift producer (issue #356) — the write counterpart of the
//! live drift read path in [`crate::live_anomaly_inputs_from_vault`] ->
//! [`crate::detect_anomalies`].
//!
//! The `drift` anomaly kind gained a complete read side in wave-12 (#68 on
//! #33's substrate): a persisted Assay-CF payload tagged
//! [`crate::ASSAY_ANOMALY_PAYLOAD_SCHEMA`] carrying a `drift_cards` array is
//! decoded into `Drift` substrates and a measured calibration. Nothing produced
//! those cards on a real project, so live drift detection could never fire. This
//! module is that producer: at index time it compares each slot's **reference
//! window** (the prior import's persisted per-symbol samples) against the
//! **current** import's samples via [`measure_drift`], writes the resulting
//! cards as the recognized anomaly payload, ledger-pairs each card into the
//! assay differentiation-card ledger, and snapshots the current samples as the
//! next import's reference window.
//!
//! Honest degradation: a slot with no reference counterpart (first import, or a
//! newly appearing slot) or with fewer than the two points MMD requires per side
//! is a **labeled absence** — counted in [`DriftProductionReport`], never a
//! fabricated baseline.

use std::collections::BTreeMap;

use astrolabe_assay::{DiffConfig, DiffLedger, DifferentiationCard, DriftCard, measure_drift};
use astrolabe_ingest::read_cbm_graph_snapshot;
use calyx_assay::{AssayCacheKey, AssayStore, AssaySubject, EstimatorKind, MiEstimate, TrustTag};
use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode::decode_slot_vector;
use calyx_core::{CalyxError, Clock, Result, SlotId, SlotVector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ASSAY_ANOMALY_PAYLOAD_SCHEMA;

/// Schema tag for a persisted per-slot reference window: the prior import's slot
/// sample distributions, held so the next import can measure MMD drift against
/// them. It shares the Assay CF with the anomaly payload but carries a distinct
/// schema so the anomaly read path
/// ([`crate::live_anomaly_inputs_from_vault`]) ignores it (that path only
/// consumes rows whose schema is [`crate::ASSAY_ANOMALY_PAYLOAD_SCHEMA`]).
pub const DRIFT_REFERENCE_PAYLOAD_SCHEMA: &str = "astrolabe.drift_reference.v1";

/// One slot's sample: the set of that slot's per-symbol vectors at one import
/// (a scalar slot is a set of 1-vectors), exactly the shape
/// [`measure_drift`] consumes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DriftSlotSamples {
    /// Slot label; surfaces as the `slot:{name}` drift-finding subject.
    pub slot: String,
    /// Per-symbol sample vectors for this slot at this import.
    pub samples: Vec<Vec<f64>>,
}

/// Labeled outcome of one index-time drift production pass. Every slot that did
/// not yield a card is accounted for here so a too-short history reads as
/// honest silence, not a fabricated card (invariant 3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DriftProductionReport {
    /// Slots for which a real MMD card was measured and persisted.
    pub cards_written: usize,
    /// Slots present in the current import but absent from the reference window
    /// (first import, or a newly appearing slot): a labeled absence.
    pub slots_missing_reference: usize,
    /// Slots whose reference or current window was below the two-point MMD
    /// minimum: a labeled absence (`measure_drift`'s own input contract).
    pub slots_short_history: usize,
    /// Whether the recognized anomaly payload was persisted to the Assay CF.
    pub cards_payload_persisted: bool,
    /// Whether the current samples were persisted as the next reference window.
    pub reference_persisted: bool,
    /// Differentiation-card ledger entries appended (one per card), each
    /// hash-chain verified by [`DiffLedger::append`] on write.
    pub cards_ledgered: usize,
}

/// Reads the current import's per-slot samples from the persisted Slot column
/// families, one dense sample vector per non-structural symbol. Only
/// `SlotVector::Dense` rows contribute (MMD needs equal-dimension points);
/// sparse/absent/missing slot rows are simply not sampled. The slot label is
/// `S{n}` for slot id `n`, so a produced card surfaces as `slot:S{n}`.
pub fn read_slot_samples_from_vault<C>(
    vault: &AsterVault<C>,
    project: &str,
    slots: &[SlotId],
) -> Result<Vec<DriftSlotSamples>>
where
    C: Clock,
{
    let snapshot = read_cbm_graph_snapshot(vault, project).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!("read graph snapshot: {error}"))
    })?;
    let at_seq = vault.latest_seq();
    let mut per_slot: BTreeMap<SlotId, Vec<Vec<f64>>> =
        slots.iter().map(|slot| (*slot, Vec::new())).collect();
    for node in snapshot.nodes.into_iter().filter(|node| !node.structural) {
        let Some(cx_id) = node.cx_id else {
            continue;
        };
        for slot in slots {
            let Some(bytes) =
                vault.read_cf_at(at_seq, ColumnFamily::slot(*slot), &slot_key(cx_id))?
            else {
                continue;
            };
            if let SlotVector::Dense { data, .. } = decode_slot_vector(&bytes)? {
                per_slot
                    .get_mut(slot)
                    .expect("slot present in initialized map")
                    .push(data.into_iter().map(f64::from).collect());
            }
        }
    }
    Ok(per_slot
        .into_iter()
        .map(|(slot, samples)| DriftSlotSamples {
            slot: format!("S{}", slot.get()),
            samples,
        })
        .collect())
}

/// Loads the persisted reference window (the prior import's slot samples), or an
/// empty vec when none has been written yet (first import → honest absence).
pub fn load_drift_reference<C>(vault: &AsterVault<C>) -> Result<Vec<DriftSlotSamples>>
where
    C: Clock,
{
    let assay = AssayStore::load_from_vault(vault)?;
    for row in assay.rows() {
        let Some(payload) = row.payload.as_ref() else {
            continue;
        };
        if payload.get("schema").and_then(Value::as_str) != Some(DRIFT_REFERENCE_PAYLOAD_SCHEMA) {
            continue;
        }
        let Some(values) = payload.get("slots").and_then(Value::as_array) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(values.len());
        for value in values {
            let slot: DriftSlotSamples =
                serde_json::from_value(value.clone()).map_err(|error| {
                    CalyxError::aster_corrupt_shard(format!("decode drift reference slot: {error}"))
                })?;
            out.push(slot);
        }
        return Ok(out);
    }
    Ok(Vec::new())
}

/// Persists `slots` as the reference window for the next import. Uses the
/// [`AssaySubject::EnsembleCard`] subject so it coexists with the anomaly
/// payload (written under [`AssaySubject::Panel`]) under the same cache key.
pub fn persist_drift_reference<C>(
    vault: &AsterVault<C>,
    cache_key: AssayCacheKey,
    provenance: impl Into<String>,
    slots: &[DriftSlotSamples],
) -> Result<()>
where
    C: Clock,
{
    let payload = json!({
        "schema": DRIFT_REFERENCE_PAYLOAD_SCHEMA,
        "slots": slots,
    });
    let sample_points: usize = slots.iter().map(|slot| slot.samples.len()).sum();
    let mut assay = AssayStore::load_from_vault(vault)?;
    assay.put_with_payload(
        cache_key,
        AssaySubject::EnsembleCard,
        MiEstimate::point(
            0.0,
            sample_points,
            EstimatorKind::PanelSufficiency,
            TrustTag::Provisional,
        ),
        provenance,
        vault.latest_seq(),
        payload,
    );
    assay.persist_to_vault(vault)?;
    Ok(())
}

/// Measures per-slot MMD drift (reference window vs current import), ledger-pairs
/// each card, and persists the cards as the recognized anomaly payload. Slots
/// with no reference counterpart or below the two-point MMD minimum are a
/// labeled absence in the returned report — never a fabricated card.
#[allow(clippy::too_many_arguments)]
pub fn produce_drift_cards<C>(
    vault: &AsterVault<C>,
    cache_key: AssayCacheKey,
    provenance: impl Into<String>,
    reference: &[DriftSlotSamples],
    current: &[DriftSlotSamples],
    seed: u64,
    config: &DiffConfig,
    ledger: Option<&DiffLedger>,
) -> Result<DriftProductionReport>
where
    C: Clock,
{
    let reference_by_slot: BTreeMap<&str, &Vec<Vec<f64>>> = reference
        .iter()
        .map(|slot| (slot.slot.as_str(), &slot.samples))
        .collect();
    let mut report = DriftProductionReport::default();
    let mut cards: Vec<DriftCard> = Vec::new();
    for cur in current {
        let Some(ref_samples) = reference_by_slot.get(cur.slot.as_str()) else {
            if !cur.samples.is_empty() {
                report.slots_missing_reference += 1;
            }
            continue;
        };
        if ref_samples.len() < 2 || cur.samples.len() < 2 {
            report.slots_short_history += 1;
            continue;
        }
        match measure_drift(cur.slot.clone(), ref_samples, &cur.samples, seed, config) {
            Ok(card) => {
                if let Some(ledger) = ledger {
                    ledger
                        .append(&DifferentiationCard::Drift(card.clone()), seed)
                        .map_err(|error| {
                            CalyxError::disk_pressure(format!("ledger drift card: {error}"))
                        })?;
                    report.cards_ledgered += 1;
                }
                cards.push(card);
            }
            // measure_drift rejects a below-minimum / degenerate-dimension sample:
            // a labeled short-history absence, not a fabricated card.
            Err(_) => report.slots_short_history += 1,
        }
    }
    report.cards_written = cards.len();
    if cards.is_empty() {
        return Ok(report);
    }
    let drift_cards: Vec<Value> = cards
        .iter()
        .map(|card| {
            serde_json::to_value(card)
                .map_err(|error| CalyxError::disk_pressure(format!("encode drift card: {error}")))
        })
        .collect::<Result<_>>()?;
    let payload = json!({
        "schema": ASSAY_ANOMALY_PAYLOAD_SCHEMA,
        "drift_cards": drift_cards,
    });
    let mut assay = AssayStore::load_from_vault(vault)?;
    assay.put_with_payload(
        cache_key,
        AssaySubject::Panel,
        MiEstimate::point(
            0.0,
            cards.len(),
            EstimatorKind::PanelSufficiency,
            TrustTag::Provisional,
        ),
        provenance,
        vault.latest_seq(),
        payload,
    );
    assay.persist_to_vault(vault)?;
    report.cards_payload_persisted = true;
    Ok(report)
}

/// Full index-time drift pass over a real shadow vault: read the current import's
/// per-slot samples, load the reference window, produce+persist cards when a
/// reference exists (else a labeled first-import absence), then snapshot the
/// current samples as the next import's reference window.
#[allow(clippy::too_many_arguments)]
pub fn run_index_time_drift<C>(
    vault: &AsterVault<C>,
    project: &str,
    slots: &[SlotId],
    cache_key: AssayCacheKey,
    provenance: impl Into<String>,
    seed: u64,
    config: &DiffConfig,
    ledger: Option<&DiffLedger>,
) -> Result<DriftProductionReport>
where
    C: Clock,
{
    let provenance = provenance.into();
    let current = read_slot_samples_from_vault(vault, project, slots)?;
    let reference = load_drift_reference(vault)?;
    let mut report = if reference.is_empty() {
        // First import: no reference window at all — every populated slot is a
        // labeled absence, no card produced.
        DriftProductionReport {
            slots_missing_reference: current
                .iter()
                .filter(|slot| !slot.samples.is_empty())
                .count(),
            ..DriftProductionReport::default()
        }
    } else {
        produce_drift_cards(
            vault,
            cache_key.clone(),
            provenance.clone(),
            &reference,
            &current,
            seed,
            config,
            ledger,
        )?
    };
    persist_drift_reference(
        vault,
        cache_key,
        format!("{provenance}:reference"),
        &current,
    )?;
    report.reference_persisted = true;
    Ok(report)
}

#[cfg(test)]
mod tests;
