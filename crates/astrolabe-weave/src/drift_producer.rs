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

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_assay::rng::DeterministicRng;
use astrolabe_assay::{DiffConfig, DiffLedger, DifferentiationCard, DriftCard, measure_drift};
use astrolabe_domain::knobs::U64KnobDeclaration;
use astrolabe_ingest::read_cbm_graph_snapshot;
use calyx_assay::{AssayCacheKey, AssayStore, AssaySubject, EstimatorKind, MiEstimate, TrustTag};
use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode::decode_slot_vector;
use calyx_core::{CalyxError, Clock, Result, SlotId, SlotVector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ASSAY_ANOMALY_PAYLOAD_SCHEMA, ASSAY_DELTA_INVALIDATION_COTENANT_SCHEMA};

/// Loads the Assay store co-tenant-aware. `ColumnFamily::Assay` is shared: the
/// shadow importer co-tenants `astrolabe.delta_invalidation.v1` rows there
/// (#348), and — the wave-14 live finding on real cbm/ — the strict
/// [`AssayStore::load_from_vault`] failed the WHOLE index-time drift pass with
/// `CALYX_ASTER_CORRUPT_SHARD: decode assay row: missing field cache_key` on
/// any corpus whose import wrote invalidation rows. Accepted co-tenant rows are
/// skipped and **counted** (invariant 3); anything else still fails closed.
fn load_assay_store_cotenant_aware<C>(vault: &AsterVault<C>) -> Result<(AssayStore, usize)>
where
    C: Clock,
{
    let accepted: BTreeSet<&str> = [ASSAY_DELTA_INVALIDATION_COTENANT_SCHEMA]
        .into_iter()
        .collect();
    let (store, skips) = AssayStore::load_from_vault_with_cotenants(vault, &accepted)?;
    Ok((store, skips.skipped_rows))
}

/// Registry version tag for the drift-reference bounding knobs (invariant 4).
pub const DRIFT_REFERENCE_KNOB_REGISTRY_VERSION: &str = "astrolabe-weave-drift-reference-knobs-v1";

/// Name of the per-slot reference-window sample-cap knob.
pub const DRIFT_REFERENCE_SAMPLE_CAP_KNOB: &str = "weave_drift_reference_sample_cap";

/// Name of the per-slot current-window sample-cap knob.
///
/// The persisted graph and slot rows remain complete; this cap applies only to
/// the exact MMD telemetry window so the quadratic test cannot turn one large
/// import into an unbounded index-time CPU/RSS spike.
pub const DRIFT_CURRENT_SAMPLE_CAP_KNOB: &str = "weave_drift_current_sample_cap";

/// Default per-slot cap on the persisted reference window.
///
/// Seeded from the same Cochran fixed-precision plateau the assay scheduler's
/// sample-size knob uses (`ASSAY_DEFAULT_SAMPLE_SIZE` = 384): at a 95% confidence
/// level and a 5% margin the required sample plateaus near 385 regardless of how
/// large the population grows, so a few hundred sampled per-symbol vectors already
/// pin a slot's reference distribution to within a few percent. Capping the
/// reference window here keeps the persisted reference row O(slots × cap × dim) —
/// independent of corpus size — instead of O(corpus) (#371). It also comfortably
/// clears the `redundancy_quorum` (50) that MMD uses to tag a card `Trusted`, so
/// a full-cap reference never silently degrades a drift card's trust.
pub const DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP: u64 = 384;

/// Default per-slot cap on the current window used for exact MMD.
///
/// It deliberately mirrors [`DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP`]: MMD compares
/// two distributions, so both sides of the pairwise kernel workload must be
/// bounded symmetrically. Leaving the current side unbounded makes exact MMD
/// `O((reference + current)^2)` in corpus size and blocks fleet-scale indexing.
pub const DRIFT_CURRENT_DEFAULT_SAMPLE_CAP: u64 = DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP;

/// Smallest legal reference-window cap. MMD needs at least two points per side
/// ([`measure_drift`]'s own input contract), so a cap below two would guarantee a
/// short-history absence for every reimport — a reference window that can never
/// measure drift is illegal, not merely tight.
pub const DRIFT_REFERENCE_MIN_SAMPLE_CAP: u64 = 2;

/// Smallest legal current-window cap. Same MMD input contract as the reference
/// side: fewer than two retained current points can never produce a card.
pub const DRIFT_CURRENT_MIN_SAMPLE_CAP: u64 = DRIFT_REFERENCE_MIN_SAMPLE_CAP;

/// Largest legal reference-window cap. An upper bound keeps one persisted
/// reference row a bounded unit of storage even against a pathologically large
/// corpus; a slot with fewer samples than the cap still keeps them all, so this
/// caps the row size, never completeness of a small slot.
pub const DRIFT_REFERENCE_MAX_SAMPLE_CAP: u64 = 100_000;

/// Largest legal current-window cap. Kept equal to the reference cap so a local
/// operator can widen both windows deliberately without accidentally admitting a
/// billion-pair current-side matrix on one import.
pub const DRIFT_CURRENT_MAX_SAMPLE_CAP: u64 = DRIFT_REFERENCE_MAX_SAMPLE_CAP;

/// Name of the global per-chunk byte-budget knob.
pub const DRIFT_REFERENCE_CHUNK_BUDGET_KNOB: &str = "weave_drift_reference_chunk_budget_bytes";

/// Default byte budget for one persisted reference chunk row (#371, wave-15).
///
/// The per-slot [`DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP`] makes each slot's window
/// corpus-independent, but the *sum* across every dense slot at its cap
/// (`O(slots × cap × dim)`) is still a single JSON row, and on the real cbm/
/// corpus that row measured **18,294,630 bytes** — more than double the
/// **8,388,608-byte** (`8 * 1024 * 1024`) Calyx memtable byte cap, so the whole
/// index-time drift pass failed closed with `CALYX_BACKPRESSURE` and drift was
/// labeled unavailable (wave-14 live falsification). This knob caps the
/// serialized bytes of **one** reference chunk so the producer can split the
/// reference across as many rows as it takes to keep every row admissible.
///
/// The default (4 MiB) sits at half the 8 MiB memtable cap: even a 2× estimation
/// slack in the greedy packer cannot breach the hard cap, so a chunk that is
/// *planned* to fit the budget is guaranteed to be *admitted* by the memtable.
pub const DRIFT_REFERENCE_DEFAULT_CHUNK_BUDGET_BYTES: u64 = 4 * 1024 * 1024;

/// Smallest legal chunk byte budget. A chunk must still hold at least one
/// two-point ([`DRIFT_REFERENCE_MIN_SAMPLE_CAP`]) slot plus the payload scaffold,
/// so a budget below 64 KiB is a misconfiguration, not a tight bound.
pub const DRIFT_REFERENCE_MIN_CHUNK_BUDGET_BYTES: u64 = 64 * 1024;

/// Largest legal chunk byte budget. Held strictly below the 8 MiB memtable byte
/// cap with ~1 MiB of headroom for the Assay row envelope (cache key, subject,
/// estimate, provenance, seq) so a chunk planned to the maximum budget still
/// serializes into an admissible memtable row.
pub const DRIFT_REFERENCE_MAX_CHUNK_BUDGET_BYTES: u64 = 7 * 1024 * 1024;

/// The drift-reference bounding knob registry.
pub const DRIFT_REFERENCE_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: DRIFT_REFERENCE_KNOB_REGISTRY_VERSION,
        name: DRIFT_REFERENCE_SAMPLE_CAP_KNOB,
        default: DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP,
        min: DRIFT_REFERENCE_MIN_SAMPLE_CAP,
        max: DRIFT_REFERENCE_MAX_SAMPLE_CAP,
        unit: "samples",
        source: "Cochran fixed-precision sample-size plateau (n0 = 1.96^2 * 0.25 / 0.05^2 = 384.16), mirrored from astrolabe-assay ASSAY_DEFAULT_SAMPLE_SIZE",
        rationale: "bounds the persisted per-slot reference window so the reference row is O(slots × cap × dim), independent of corpus size (#371); replace with a measured drift-sensitivity-vs-storage policy once M-scale drift production is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: DRIFT_REFERENCE_KNOB_REGISTRY_VERSION,
        name: DRIFT_CURRENT_SAMPLE_CAP_KNOB,
        default: DRIFT_CURRENT_DEFAULT_SAMPLE_CAP,
        min: DRIFT_CURRENT_MIN_SAMPLE_CAP,
        max: DRIFT_CURRENT_MAX_SAMPLE_CAP,
        unit: "samples",
        source: "Cochran fixed-precision sample-size plateau (n0 = 1.96^2 * 0.25 / 0.05^2 = 384.16), applied symmetrically to the current side of exact MMD after the Bevy r21 FSV exposed unbounded current windows",
        rationale: "bounds the current sample passed to exact MMD so the pairwise distance/Gram/permutation workload is O((reference_cap + current_cap)^2) rather than O(corpus^2); the full slot rows remain persisted and the retained window is deterministically provenance-recorded",
    },
    U64KnobDeclaration {
        registry_version: DRIFT_REFERENCE_KNOB_REGISTRY_VERSION,
        name: DRIFT_REFERENCE_CHUNK_BUDGET_KNOB,
        default: DRIFT_REFERENCE_DEFAULT_CHUNK_BUDGET_BYTES,
        min: DRIFT_REFERENCE_MIN_CHUNK_BUDGET_BYTES,
        max: DRIFT_REFERENCE_MAX_CHUNK_BUDGET_BYTES,
        unit: "bytes",
        source: "half the 8 MiB (8_388_608 B) Calyx memtable byte cap (calyx-aster DEFAULT_MEMTABLE_BYTES); real cbm/ reference row measured 18,294,630 B (wave-14 live falsification of #371)",
        rationale: "caps the serialized bytes of one persisted reference chunk so the O(slots × cap × dim) reference is split across admissible rows instead of one over-cap row; replace with a measured chunk-size-vs-read-latency policy once M-scale drift production is benchmarked",
    },
];

/// Resolves a declared u64 knob to a `usize`, failing closed if the knob is not
/// declared or its declared default falls outside its own `[min, max]` bounds
/// (invariant 4: a knob whose default violates its own contract is corruption,
/// not a silent clamp).
fn resolve_drift_knob(name: &str) -> Result<usize> {
    let knob = DRIFT_REFERENCE_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!("drift knob {name} is not declared"))
        })?;
    if !knob.accepts(knob.default) {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "drift knob {name} default {} is outside its declared bounds [{}, {}]",
            knob.default, knob.min, knob.max
        )));
    }
    Ok(knob.default as usize)
}

/// Resolves the declared per-slot reference-window sample cap, failing closed if
/// the declared default falls outside its own bounds.
pub fn drift_reference_sample_cap() -> Result<usize> {
    resolve_drift_knob(DRIFT_REFERENCE_SAMPLE_CAP_KNOB)
}

/// Resolves the declared per-slot current-window sample cap, failing closed if
/// the declared default falls outside its own bounds.
pub fn drift_current_sample_cap() -> Result<usize> {
    resolve_drift_knob(DRIFT_CURRENT_SAMPLE_CAP_KNOB)
}

/// Resolves the declared per-chunk byte budget, failing closed if the declared
/// default falls outside its own bounds.
pub fn drift_reference_chunk_budget_bytes() -> Result<usize> {
    resolve_drift_knob(DRIFT_REFERENCE_CHUNK_BUDGET_KNOB)
}

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

/// Labeled record of how the seeded reservoir bounded one slot's reference
/// window: the population it saw this import and the count it retained (`<= cap`).
/// Persisted alongside the bounded samples so the sampling is a labeled
/// provenance fact, never a silent truncation (invariant 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSamplingProvenance {
    /// Slot label (`S{n}`), matching the bounded `DriftSlotSamples::slot`.
    pub slot: String,
    /// Number of per-symbol samples the slot carried before bounding.
    pub population: usize,
    /// Number of samples retained in the persisted reference window (`<= cap`).
    pub retained: usize,
}

/// Labeled record of one persisted reference **chunk** row: which chunk it is,
/// how many slots it carries, its serialized payload bytes, and any slot the
/// global byte budget forced a further (sub-cap) down-sample on to fit. The
/// producer splits the reference across chunks so no single row exceeds the
/// memtable byte cap (#371); each chunk is a labeled provenance fact.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DriftReferenceChunkInfo {
    /// Zero-based index of this chunk in the reference generation.
    pub chunk_index: usize,
    /// Number of slots this chunk row carries.
    pub slot_count: usize,
    /// Serialized bytes of this chunk's payload (`<= chunk_budget_bytes`).
    pub payload_bytes: usize,
    /// Slots this chunk further down-sampled below the per-slot cap because the
    /// slot alone would have exceeded the chunk byte budget — a labeled global
    /// reduction, never a silent truncation (invariant 3).
    pub budget_downsampled_slots: Vec<String>,
}

/// Labeled outcome of bounding + persisting a reference window: the cap applied,
/// the total pre-bounding population, and the total retained. `total_retained`
/// is bounded by `slots.len() * sample_cap` regardless of corpus size (#371),
/// and is split across [`DriftReferenceChunkInfo`] rows so no single persisted
/// row exceeds the memtable byte cap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DriftReferenceSamplingReport {
    /// The per-slot cap the seeded reservoir enforced.
    pub sample_cap: usize,
    /// The global per-chunk byte budget the row splitter enforced.
    pub chunk_budget_bytes: usize,
    /// Sum of every slot's pre-bounding population.
    pub total_population: usize,
    /// Sum of every slot's retained sample count (`<= slots.len() * sample_cap`).
    pub total_retained: usize,
    /// Per-slot sampling provenance, one entry per input slot (retained reflects
    /// the final persisted count, after both the per-slot cap and any global
    /// byte-budget down-sample).
    pub per_slot: Vec<SlotSamplingProvenance>,
    /// One entry per persisted reference chunk row.
    pub chunks: Vec<DriftReferenceChunkInfo>,
    /// Accepted Assay-CF co-tenant rows (delta-invalidation schema) skipped —
    /// counted, never silent — while loading the store to merge the reference
    /// row into (invariant 3).
    pub assay_cotenant_rows_skipped: usize,
}

/// Deterministically bounds each slot's samples to at most `cap` points via a
/// **seeded reservoir** (Vitter's Algorithm R). A slot with `<= cap` samples is
/// kept whole (`retained == population`); a larger slot is downsampled to exactly
/// `cap` points chosen by a per-slot [`DeterministicRng`] stream seeded from
/// `(seed, slot)`, so the retained subset is a pure function of
/// `(samples, cap, seed)` and independent of worker count or scheduling.
///
/// The bounded window is what [`persist_drift_reference`] writes, so the persisted
/// reference row is O(`slots.len()` × `cap` × dim) — independent of corpus size.
/// Because MMD is a set statistic (order-invariant), a uniform subset of the
/// reference distribution preserves the drift measurement contract: the same mean
/// shift a full reference would flag still clears the significance gate against a
/// capped reference. Returns the bounded slots and a labeled provenance record.
pub fn bound_slot_sample_window(
    slots: &[DriftSlotSamples],
    cap: usize,
    seed: u64,
) -> (Vec<DriftSlotSamples>, Vec<SlotSamplingProvenance>) {
    let mut bounded = Vec::with_capacity(slots.len());
    let mut provenance = Vec::with_capacity(slots.len());
    for slot in slots {
        let population = slot.samples.len();
        let samples = if population <= cap {
            slot.samples.clone()
        } else {
            reservoir_sample(&slot.samples, cap, seed, &slot.slot)
        };
        provenance.push(SlotSamplingProvenance {
            slot: slot.slot.clone(),
            population,
            retained: samples.len(),
        });
        bounded.push(DriftSlotSamples {
            slot: slot.slot.clone(),
            samples,
        });
    }
    (bounded, provenance)
}

/// Backward-compatible name for the persisted reference-window bounding step.
pub fn bound_reference_window(
    slots: &[DriftSlotSamples],
    cap: usize,
    seed: u64,
) -> (Vec<DriftSlotSamples>, Vec<SlotSamplingProvenance>) {
    bound_slot_sample_window(slots, cap, seed)
}

/// Vitter's Algorithm R: a uniform `cap`-point reservoir over `samples`, seeded
/// deterministically per slot. Precondition: `cap < samples.len()` (the caller
/// keeps a whole slot when `samples.len() <= cap`) and `cap >= 1`.
fn reservoir_sample(samples: &[Vec<f64>], cap: usize, seed: u64, slot: &str) -> Vec<Vec<f64>> {
    let mut rng = DeterministicRng::from_u64_labeled(seed, &format!("drift-reservoir:{slot}"));
    let mut reservoir: Vec<Vec<f64>> = samples[..cap].to_vec();
    for (i, item) in samples.iter().enumerate().skip(cap) {
        // j uniform in [0, i]; replace a reservoir slot with probability cap/(i+1).
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        if j < cap {
            reservoir[j] = item.clone();
        }
    }
    reservoir
}

/// Fixed byte reserve inside one chunk budget for the payload scaffold
/// (`schema`/`chunk`/`sampling` keys and the reservoir metadata) that is not the
/// `slots` array. Generous relative to the scaffold's true size; the chunk
/// budget default sits at half the memtable cap, so this reserve only has to
/// keep the greedy packer's estimate honest, never defend the hard cap.
const CHUNK_SCAFFOLD_RESERVE_BYTES: usize = 4096;

/// Per-slot byte reserve charged for that slot's `sampling.per_slot` provenance
/// entry (`slot`/`population`/`retained`/`chunk_index`/`budget_downsampled`).
/// Generous versus the true ~90-byte entry so the packer never underestimates.
const CHUNK_PER_SLOT_PROVENANCE_BYTES: usize = 160;

/// Final persisted provenance for one slot in a **chunked** reference: the
/// pre-cap population, the final retained count, which chunk row holds it, and
/// whether the global byte budget forced a further down-sample. Serialized into
/// the chunk payload's `sampling.per_slot` array (a superset of
/// [`SlotSamplingProvenance`], used only on the multi-chunk path so the
/// single-chunk payload stays byte-identical to the pre-chunking format).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ChunkedSlotProvenance {
    slot: String,
    population: usize,
    retained: usize,
    chunk_index: usize,
    budget_downsampled: bool,
}

/// One planned reference chunk: the slots it carries (already reservoir-bounded,
/// and possibly further budget-down-sampled) and their final provenance.
struct PlannedChunk {
    slots: Vec<DriftSlotSamples>,
    per_slot: Vec<ChunkedSlotProvenance>,
}

/// Serialized byte cost of one slot inside the `slots` array (its JSON plus a
/// separating comma).
fn slot_json_cost(slot: &DriftSlotSamples) -> Result<usize> {
    let bytes = serde_json::to_vec(slot).map_err(|error| {
        CalyxError::disk_pressure(format!("size drift reference slot: {error}"))
    })?;
    Ok(bytes.len() + 1)
}

/// Down-samples one slot deterministically until its serialized cost fits
/// `slot_allowance`, via the same seeded reservoir. Returns the (possibly
/// unchanged) slot and whether a budget-driven reduction happened. Fails closed
/// if even a two-point ([`DRIFT_REFERENCE_MIN_SAMPLE_CAP`]) slot cannot fit —
/// that is a budget misconfiguration, not a bound to silently truncate past.
fn fit_slot_to_budget(
    slot: &DriftSlotSamples,
    slot_allowance: usize,
    seed: u64,
) -> Result<(DriftSlotSamples, bool)> {
    if slot_json_cost(slot)? <= slot_allowance {
        return Ok((slot.clone(), false));
    }
    let min = DRIFT_REFERENCE_MIN_SAMPLE_CAP as usize;
    // Largest retained count in [min, len) whose serialized slot fits the
    // allowance. Monotone in the count, so a linear shrink from len-1 finds it;
    // len is bounded by the per-slot cap, so this is cheap.
    let len = slot.samples.len();
    let mut chosen: Option<Vec<Vec<f64>>> = None;
    let mut retained = len.saturating_sub(1).max(min);
    while retained >= min {
        let candidate = reservoir_sample(&slot.samples, retained, seed, &slot.slot);
        let trial = DriftSlotSamples {
            slot: slot.slot.clone(),
            samples: candidate.clone(),
        };
        if slot_json_cost(&trial)? <= slot_allowance {
            chosen = Some(candidate);
            break;
        }
        if retained == min {
            break;
        }
        // Shrink geometrically to bound the number of trial serializations, then
        // step by one near the floor for an exact-as-possible retained count.
        retained = if retained > min * 2 {
            retained / 2
        } else {
            retained - 1
        };
    }
    let samples = chosen.ok_or_else(|| {
        CalyxError::backpressure(format!(
            "drift reference chunk budget too small for slot {} (a {}-point minimum slot exceeds the {slot_allowance}-byte per-slot allowance)",
            slot.slot, min
        ))
    })?;
    Ok((
        DriftSlotSamples {
            slot: slot.slot.clone(),
            samples,
        },
        true,
    ))
}

/// Greedily packs already-bounded slots into chunks whose serialized payload
/// each fits `budget` bytes, so no persisted reference row exceeds the memtable
/// byte cap (#371). A slot too large for any chunk on its own is deterministically
/// down-sampled to fit (labeled `budget_downsampled`). Packing is a pure function
/// of `(bounded, bound_provenance, budget, seed)`, so the same inputs plan the
/// same chunks — byte-identical persistence.
fn plan_reference_chunks(
    bounded: &[DriftSlotSamples],
    bound_provenance: &[SlotSamplingProvenance],
    budget: usize,
    seed: u64,
) -> Result<Vec<PlannedChunk>> {
    let population_by_slot: BTreeMap<&str, usize> = bound_provenance
        .iter()
        .map(|prov| (prov.slot.as_str(), prov.population))
        .collect();
    let slots_budget = budget.saturating_sub(CHUNK_SCAFFOLD_RESERVE_BYTES);
    // One slot alone must leave room for its own provenance entry inside a chunk.
    let slot_allowance = slots_budget.saturating_sub(CHUNK_PER_SLOT_PROVENANCE_BYTES);

    let mut chunks: Vec<PlannedChunk> = Vec::new();
    let mut current = PlannedChunk {
        slots: Vec::new(),
        per_slot: Vec::new(),
    };
    let mut current_bytes = 0usize;

    for slot in bounded {
        let (fitted, budget_downsampled) = fit_slot_to_budget(slot, slot_allowance, seed)?;
        let cost = slot_json_cost(&fitted)? + CHUNK_PER_SLOT_PROVENANCE_BYTES;
        if !current.slots.is_empty() && current_bytes + cost > slots_budget {
            chunks.push(std::mem::replace(
                &mut current,
                PlannedChunk {
                    slots: Vec::new(),
                    per_slot: Vec::new(),
                },
            ));
            current_bytes = 0;
        }
        let chunk_index = chunks.len();
        let population = population_by_slot
            .get(slot.slot.as_str())
            .copied()
            .unwrap_or(slot.samples.len());
        current.per_slot.push(ChunkedSlotProvenance {
            slot: fitted.slot.clone(),
            population,
            retained: fitted.samples.len(),
            chunk_index,
            budget_downsampled,
        });
        current.slots.push(fitted);
        current_bytes += cost;
    }
    if !current.slots.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
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
    /// Accepted Assay-CF co-tenant rows (delta-invalidation schema) skipped —
    /// counted, never silent — across the pass's reference load, card persist,
    /// and reference persist (invariant 3).
    pub assay_cotenant_rows_skipped: usize,
    /// Per-slot cap applied to the current import before exact MMD. Zero only
    /// means drift did not reach current-window preparation.
    pub current_sample_cap: usize,
    /// Sum of every current slot's pre-bounding population.
    pub current_total_population: usize,
    /// Sum of every current slot's retained sample count used by exact MMD.
    pub current_total_retained: usize,
    /// Per-slot current-window sampling provenance. This is returned and
    /// persisted with the drift-card payload so a consumer can distinguish the
    /// full corpus population from the bounded exact-MMD window.
    pub current_sampling_per_slot: Vec<SlotSamplingProvenance>,
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
    Ok(load_drift_reference_counted(vault)?.0)
}

/// [`load_drift_reference`] with the accepted-co-tenant skip count surfaced, so
/// callers that report drift production can count the skips (invariant 3).
pub fn load_drift_reference_counted<C>(
    vault: &AsterVault<C>,
) -> Result<(Vec<DriftSlotSamples>, usize)>
where
    C: Clock,
{
    let (assay, cotenant_rows_skipped) = load_assay_store_cotenant_aware(vault)?;
    // Collect every drift-reference row, then keep only the newest generation:
    // one `persist_drift_reference` stamps all its chunk rows with a single
    // `written_at_seq`, so the newest generation is exactly the rows at the
    // maximum seq. Older chunk rows (from a prior generation that produced a
    // different chunk count) carry a strictly smaller seq and are ignored, so a
    // single-row rewrite is not corrupted by stale chunks left on disk (#371).
    let mut reference_rows: Vec<_> = assay
        .rows()
        .into_iter()
        .filter(|row| {
            row.payload
                .as_ref()
                .and_then(|payload| payload.get("schema").and_then(Value::as_str))
                == Some(DRIFT_REFERENCE_PAYLOAD_SCHEMA)
        })
        .collect();
    if reference_rows.is_empty() {
        return Ok((Vec::new(), cotenant_rows_skipped));
    }
    let max_seq = reference_rows
        .iter()
        .map(|row| row.written_at_seq)
        .max()
        .expect("non-empty reference rows");
    reference_rows.retain(|row| row.written_at_seq == max_seq);
    // Deterministic slot order across chunk rows: chunk index.
    reference_rows.sort_by_key(|row| {
        row.payload
            .as_ref()
            .and_then(|p| p.get("chunk"))
            .and_then(|c| c.get("index"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    });

    let mut out = Vec::new();
    for row in &reference_rows {
        let payload = row.payload.as_ref().expect("filtered to payload rows");
        let Some(values) = payload.get("slots").and_then(Value::as_array) else {
            continue;
        };
        for value in values {
            let slot: DriftSlotSamples =
                serde_json::from_value(value.clone()).map_err(|error| {
                    CalyxError::aster_corrupt_shard(format!("decode drift reference slot: {error}"))
                })?;
            out.push(slot);
        }
    }
    Ok((out, cotenant_rows_skipped))
}

/// Persists `slots` as the reference window for the next import in two bounding
/// stages (#371): first each slot's samples are **reservoir-bounded** to the
/// registry-declared per-slot cap ([`DRIFT_REFERENCE_SAMPLE_CAP_KNOB`]), then the
/// bounded slots are **split into chunk rows** each under the registry-declared
/// per-chunk byte budget ([`DRIFT_REFERENCE_CHUNK_BUDGET_KNOB`]) so no single
/// persisted row exceeds the memtable byte cap — the wave-14 live finding was
/// that the per-slot cap alone still summed to an 18.3 MB row on real cbm/,
/// double the 8 MB memtable cap. All rows use the [`AssaySubject::EnsembleCard`]
/// subject; a single-chunk reference keeps the base cache key and the
/// pre-chunking payload shape (byte-identical to wave-14 for small corpora),
/// while a multi-chunk reference suffixes the `corpus_shard` with the chunk index
/// and carries a self-describing `chunk` header. Every payload carries a labeled
/// `sampling` block (reservoir, cap, seed, per-slot population/retained, and — on
/// the chunked path — the chunk budget and any budget-driven down-sample) so both
/// reductions are provenance facts, never silent truncation (invariant 3).
///
/// All chunk rows of one call are stamped with a single `written_at_seq`, so the
/// [`load_drift_reference`] reader selects the newest generation by max seq and
/// ignores any smaller-count generation's leftover chunk rows.
///
/// Returns the [`DriftReferenceSamplingReport`] describing both bounding stages,
/// whose `total_retained` is `<= slots.len() * sample_cap` regardless of how many
/// symbols the corpus holds, split across `chunks` rows each `<= chunk_budget_bytes`.
pub fn persist_drift_reference<C>(
    vault: &AsterVault<C>,
    cache_key: AssayCacheKey,
    provenance: impl Into<String>,
    slots: &[DriftSlotSamples],
    seed: u64,
) -> Result<DriftReferenceSamplingReport>
where
    C: Clock,
{
    let provenance = provenance.into();
    let cap = drift_reference_sample_cap()?;
    let budget = drift_reference_chunk_budget_bytes()?;
    let (bounded, bound_provenance) = bound_reference_window(slots, cap, seed);
    let total_population: usize = bound_provenance.iter().map(|slot| slot.population).sum();
    let planned = plan_reference_chunks(&bounded, &bound_provenance, budget, seed)?;
    let chunk_count = planned.len();
    let any_budget_downsampled = planned
        .iter()
        .any(|chunk| chunk.per_slot.iter().any(|slot| slot.budget_downsampled));

    // Stamp every chunk of this generation with one captured sequence so the
    // reader can select the newest generation by `max(written_at_seq)` — a
    // reference rewrite that produces fewer chunks than a prior one leaves older
    // chunk rows on disk, but they carry a strictly smaller seq and are ignored
    // on read (the reference is bounded, so the orphan set is bounded too).
    let write_seq = vault.latest_seq();
    let (mut assay, assay_cotenant_rows_skipped) = load_assay_store_cotenant_aware(vault)?;

    let mut chunks_info = Vec::with_capacity(chunk_count);
    let mut per_slot_report: Vec<SlotSamplingProvenance> = Vec::new();
    let mut total_retained = 0usize;

    for (index, chunk) in planned.iter().enumerate() {
        let chunk_retained: usize = chunk.slots.iter().map(|slot| slot.samples.len()).sum();
        total_retained += chunk_retained;
        let budget_downsampled_slots: Vec<String> = chunk
            .per_slot
            .iter()
            .filter(|slot| slot.budget_downsampled)
            .map(|slot| slot.slot.clone())
            .collect();
        for slot in &chunk.per_slot {
            per_slot_report.push(SlotSamplingProvenance {
                slot: slot.slot.clone(),
                population: slot.population,
                retained: slot.retained,
            });
        }

        // Single-chunk, no budget down-sample → the pre-chunking payload shape
        // and the base cache key, byte-identical to the wave-14 format so a small
        // corpus is untouched. Anything else uses the self-describing chunked
        // shape under a chunk-suffixed key.
        let (row_key, row_provenance, payload) = if chunk_count == 1 && !any_budget_downsampled {
            let legacy_per_slot: Vec<SlotSamplingProvenance> = chunk
                .per_slot
                .iter()
                .map(|slot| SlotSamplingProvenance {
                    slot: slot.slot.clone(),
                    population: slot.population,
                    retained: slot.retained,
                })
                .collect();
            let payload = json!({
                "schema": DRIFT_REFERENCE_PAYLOAD_SCHEMA,
                "sampling": {
                    "reservoir": "vitter-algorithm-r",
                    "sample_cap": cap,
                    "seed": seed,
                    "per_slot": legacy_per_slot,
                },
                "slots": chunk.slots,
            });
            (cache_key.clone(), provenance.clone(), payload)
        } else {
            let mut key = cache_key.clone();
            key.corpus_shard = format!("{}#driftref-chunk-{index}", cache_key.corpus_shard);
            let payload = json!({
                "schema": DRIFT_REFERENCE_PAYLOAD_SCHEMA,
                "chunk": { "index": index, "count": chunk_count },
                "sampling": {
                    "reservoir": "vitter-algorithm-r",
                    "sample_cap": cap,
                    "chunk_budget_bytes": budget,
                    "seed": seed,
                    "per_slot": chunk.per_slot,
                },
                "slots": chunk.slots,
            });
            (
                key,
                format!("{provenance}#chunk{index}/{chunk_count}"),
                payload,
            )
        };

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|error| {
                CalyxError::disk_pressure(format!("size drift reference chunk: {error}"))
            })?
            .len();
        chunks_info.push(DriftReferenceChunkInfo {
            chunk_index: index,
            slot_count: chunk.slots.len(),
            payload_bytes,
            budget_downsampled_slots,
        });

        assay.put_with_payload(
            row_key,
            AssaySubject::EnsembleCard,
            MiEstimate::point(
                0.0,
                chunk_retained,
                EstimatorKind::PanelSufficiency,
                TrustTag::Provisional,
            ),
            row_provenance,
            write_seq,
            payload,
        );
    }
    assay.persist_to_vault(vault)?;
    Ok(DriftReferenceSamplingReport {
        sample_cap: cap,
        chunk_budget_bytes: budget,
        total_population,
        total_retained,
        per_slot: per_slot_report,
        chunks: chunks_info,
        assay_cotenant_rows_skipped,
    })
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
    current_sample_cap: usize,
    current_sampling_per_slot: &[SlotSamplingProvenance],
    seed: u64,
    config: &DiffConfig,
    ledger: Option<&DiffLedger>,
) -> Result<DriftProductionReport>
where
    C: Clock,
{
    let current_total_population: usize = current_sampling_per_slot
        .iter()
        .map(|slot| slot.population)
        .sum();
    let current_total_retained: usize = current_sampling_per_slot
        .iter()
        .map(|slot| slot.retained)
        .sum();
    let reference_by_slot: BTreeMap<&str, &Vec<Vec<f64>>> = reference
        .iter()
        .map(|slot| (slot.slot.as_str(), &slot.samples))
        .collect();
    let mut report = DriftProductionReport {
        current_sample_cap,
        current_total_population,
        current_total_retained,
        current_sampling_per_slot: current_sampling_per_slot.to_vec(),
        ..DriftProductionReport::default()
    };
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
        "sampling": {
            "current": {
                "reservoir": "vitter-algorithm-r",
                "sample_cap": current_sample_cap,
                "total_population": current_total_population,
                "total_retained": current_total_retained,
                "per_slot": current_sampling_per_slot,
            },
        },
        "drift_cards": drift_cards,
    });
    let (mut assay, assay_cotenant_rows_skipped) = load_assay_store_cotenant_aware(vault)?;
    report.assay_cotenant_rows_skipped += assay_cotenant_rows_skipped;
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
    let current_population = read_slot_samples_from_vault(vault, project, slots)?;
    let current_sample_cap = drift_current_sample_cap()?;
    let (current, current_sampling) =
        bound_slot_sample_window(&current_population, current_sample_cap, seed);
    let current_total_population: usize = current_sampling.iter().map(|slot| slot.population).sum();
    let current_total_retained: usize = current_sampling.iter().map(|slot| slot.retained).sum();
    let (reference, reference_load_skips) = load_drift_reference_counted(vault)?;
    let mut report = if reference.is_empty() {
        // First import: no reference window at all — every populated slot is a
        // labeled absence, no card produced.
        DriftProductionReport {
            slots_missing_reference: current
                .iter()
                .filter(|slot| !slot.samples.is_empty())
                .count(),
            current_sample_cap,
            current_total_population,
            current_total_retained,
            current_sampling_per_slot: current_sampling.clone(),
            ..DriftProductionReport::default()
        }
    } else {
        produce_drift_cards(
            vault,
            cache_key.clone(),
            provenance.clone(),
            &reference,
            &current,
            current_sample_cap,
            &current_sampling,
            seed,
            config,
            ledger,
        )?
    };
    let sampling = persist_drift_reference(
        vault,
        cache_key,
        format!("{provenance}:reference"),
        &current_population,
        seed,
    )?;
    report.reference_persisted = true;
    report.assay_cotenant_rows_skipped +=
        reference_load_skips + sampling.assay_cotenant_rows_skipped;
    Ok(report)
}
