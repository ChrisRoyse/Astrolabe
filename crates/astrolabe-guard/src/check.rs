//! `guard_check` (P7.3, blueprint `10_GUARD.md` §3, §6; capability 6.1, 6.6):
//! measure a candidate through the **same instruments as indexing**, resolve its
//! comparison region (enclosing scope's trusted exemplars, kernel-near first,
//! peripheral fallback), score every guard slot's cosine against the calibrated
//! `tau`, and route the per-slot outcomes into a verdict — `accept` /
//! `new_region` / `quarantine` / `refuse` — **never a flattened average**
//! ([`crate::profile::combine_verdicts`]). Every verdict is paired with a ledger
//! entry (subject = the target `CxId`) carrying the full per-slot detail
//! (HONEST invariant 5), and the served response reproduces that same detail.
//!
//! The guard measures **distributional conformance, not correctness** (stated
//! honestly on every report): a candidate can be correct and still novel for its
//! area, which is exactly what `new_region` routing surfaces for grounding.
//!
//! # Same-instruments invariant (DoD #1)
//!
//! Indexing builds trusted exemplars, and `guard_check` measures the candidate,
//! **through one function** — [`measure_symbol_slots`]. Both the indexing entry
//! ([`measure_for_index`]) and the check entry ([`measure_for_check`]) delegate
//! to it, so for identical input the two paths produce byte-identical measured
//! slots (proven by [`crate::check::tests::same_instruments_index_and_check_are_byte_identical`],
//! a byte-compare — not a code review).
//!
//! # Fail-closed
//!
//! An empty comparison region, a candidate missing a guard slot, a NaN/degenerate
//! vector, or a non-finite cosine all refuse with a structured
//! `{code, message, remediation}` [`crate::calibration::CalibrationError`] rather
//! than admitting an unmeasured candidate.

use std::collections::BTreeMap;

use calyx_core::SlotVector;

use crate::auto::guard_slot_panel_sources;
use crate::calibration::CalibrationError;
use crate::profile::{
    CombinedVerdict, GuardProfile, GuardSlot, SlotVerdict, combine_verdicts_with_lock,
};

/// Schema tag for the served/ledgered guard-check verdict payload.
pub const GUARD_VERDICT_SCHEMA: &str = "astro.guard.verdict.v1";

/// Schema tag for the new-region grounding lifecycle record.
pub const GUARD_NEW_REGION_SCHEMA: &str = "astro.guard.new_region.v1";

// ---------------------------------------------------------------------------
// Shared measurement instrument (DoD #1)
// ---------------------------------------------------------------------------

/// One guard slot's raw measured feature vector for a symbol, as produced by the
/// panel lens named in [`GuardSlot::panel_source`]. The guard consumes these
/// vectors identically at indexing time (to build exemplars) and at check time
/// (to measure the candidate).
#[derive(Debug, Clone, PartialEq)]
pub struct SlotFeature {
    pub slot: GuardSlot,
    /// Raw lens output for this slot. Not required to be unit-norm; the shared
    /// instrument normalizes it so cosine is scale-invariant and deterministic.
    pub vector: Vec<f32>,
}

/// A symbol's raw per-slot feature vectors, keyed by guard slot. This is the
/// single input type both the indexing exemplar path and the check candidate
/// path feed to [`measure_symbol_slots`].
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolSlotInput {
    pub slots: Vec<SlotFeature>,
}

/// One guard slot's measured (L2-normalized) vector plus its canonical raw byte
/// encoding — the exact bytes an independent readback reproduces.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredSlot {
    pub slot: GuardSlot,
    /// L2-normalized vector; a zero/degenerate vector fails closed upstream.
    pub unit: Vec<f32>,
    /// Big-endian IEEE-754 bits of every `unit` component, prefixed by the slot
    /// ordinal and the component count. Byte-identical for identical input.
    pub raw_bytes: Vec<u8>,
}

/// A symbol measured through the guard instrument: every guard slot present,
/// each normalized and canonically encoded.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredSymbol {
    pub slots: Vec<MeasuredSlot>,
}

impl MeasuredSymbol {
    /// The measured slot for `slot`, if present.
    pub fn slot(&self, slot: GuardSlot) -> Option<&MeasuredSlot> {
        self.slots.iter().find(|measured| measured.slot == slot)
    }

    /// Concatenated canonical bytes of every measured slot, in canonical
    /// `GuardSlot` order — the byte image an independent readback compares.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut ordered: Vec<&MeasuredSlot> = self.slots.iter().collect();
        ordered.sort_by_key(|measured| measured.slot as u8);
        let mut out = Vec::new();
        for measured in ordered {
            out.extend_from_slice(&measured.raw_bytes);
        }
        out
    }
}

/// L2 norm of a vector.
fn l2_norm(vector: &[f32]) -> f32 {
    vector.iter().map(|value| value * value).sum::<f32>().sqrt()
}

/// **The** guard measurement instrument. Normalizes each slot's raw lens vector
/// to unit length and canonically encodes it. Both indexing and check call this
/// function, so identical input yields byte-identical measured slots (DoD #1).
///
/// Fails closed on a missing guard slot, an empty/zero/degenerate vector, or a
/// non-finite component — an unmeasurable symbol is never silently measured.
pub fn measure_symbol_slots(input: &SymbolSlotInput) -> Result<MeasuredSymbol, CalibrationError> {
    let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let Some(feature) = input.slots.iter().find(|feature| feature.slot == slot) else {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_CHECK_SLOT_MISSING",
                format!(
                    "candidate measurement is missing guard slot `{}` (panel source {})",
                    slot.as_str(),
                    slot.panel_source()
                ),
                "Measure every fixed guard slot through the panel before checking; a partial \
                 measurement cannot be routed.",
            ));
        };
        if feature.vector.is_empty() {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_CHECK_EMPTY_VECTOR",
                format!("guard slot `{}` has an empty feature vector", slot.as_str()),
                "Supply a non-empty lens vector for every slot; an empty vector is unmeasurable.",
            ));
        }
        if feature.vector.iter().any(|value| !value.is_finite()) {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_CHECK_NONFINITE_VECTOR",
                format!(
                    "guard slot `{}` vector has a non-finite component",
                    slot.as_str()
                ),
                "Lens vectors must be finite; a NaN/Inf component is a measurement fault.",
            ));
        }
        let norm = l2_norm(&feature.vector);
        if !(norm.is_finite() && norm > 0.0) {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_CHECK_DEGENERATE_VECTOR",
                format!("guard slot `{}` vector has zero magnitude", slot.as_str()),
                "A zero-magnitude vector has no direction and cannot be compared by cosine.",
            ));
        }
        let unit: Vec<f32> = feature.vector.iter().map(|value| value / norm).collect();
        let mut raw_bytes = Vec::with_capacity(1 + 4 + unit.len() * 4);
        raw_bytes.push(slot as u8);
        raw_bytes.extend_from_slice(&(unit.len() as u32).to_be_bytes());
        for value in &unit {
            raw_bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        slots.push(MeasuredSlot {
            slot,
            unit,
            raw_bytes,
        });
    }
    Ok(MeasuredSymbol { slots })
}

/// Indexing-time entry: measure a trusted symbol into exemplar slots. Delegates
/// to the shared instrument (DoD #1 — indexing and check share code).
pub fn measure_for_index(input: &SymbolSlotInput) -> Result<MeasuredSymbol, CalibrationError> {
    measure_symbol_slots(input)
}

/// Check-time entry: measure the candidate. Delegates to the shared instrument
/// (DoD #1 — the candidate path and the indexing path are literally one call).
pub fn measure_for_check(input: &SymbolSlotInput) -> Result<MeasuredSymbol, CalibrationError> {
    measure_symbol_slots(input)
}

// ---------------------------------------------------------------------------
// Panel-driven candidate/exemplar measurement (#331)
// ---------------------------------------------------------------------------

/// Error code: a guard slot's required panel source was absent (or explicitly
/// [`SlotVector::Absent`]) in the panel readout, so the slot cannot be measured.
pub const ASTRO_GUARD_CHECK_PANEL_SLOT_MISSING: &str = "ASTRO_GUARD_CHECK_PANEL_SLOT_MISSING";
/// Error code: a guard slot's panel source is a `Multi` (late-interaction token)
/// vector, which has no single direction and cannot be flattened into one guard-slot
/// vector — refused rather than silently averaged.
pub const ASTRO_GUARD_CHECK_PANEL_UNSUPPORTED_SHAPE: &str =
    "ASTRO_GUARD_CHECK_PANEL_UNSUPPORTED_SHAPE";

/// Densify one panel slot vector into a plain `f32` vector for the guard instrument.
///
/// `Dense` passes through; `Sparse` is expanded to its full `dim`; `Absent` yields
/// `Ok(None)` (a genuine gap the caller must fail closed on, never a zero vector);
/// `Multi` fails closed (a token bundle is not a single guard-slot direction).
fn densify_panel_vector(
    slot: GuardSlot,
    panel_slot: u16,
    vector: &SlotVector,
) -> Result<Option<Vec<f32>>, CalibrationError> {
    match vector {
        SlotVector::Absent { .. } => Ok(None),
        SlotVector::Dense { data, .. } => Ok(Some(data.clone())),
        SlotVector::Sparse { dim, entries } => {
            let mut dense = vec![0.0f32; *dim as usize];
            for entry in entries {
                if let Some(slot_ref) = dense.get_mut(entry.idx as usize) {
                    *slot_ref = entry.val;
                }
            }
            Ok(Some(dense))
        }
        SlotVector::Multi { .. } => Err(CalibrationError::new(
            ASTRO_GUARD_CHECK_PANEL_UNSUPPORTED_SHAPE,
            format!(
                "guard slot `{}` panel source S{panel_slot} is a Multi token vector, which has no \
                 single direction to compare by cosine",
                slot.as_str()
            ),
            "Guard slots measure Dense/Sparse panel sources; do not route the token_multi slot \
             into guard_check.",
        )),
    }
}

/// Derive a guard-check [`SymbolSlotInput`] from a panel readout of the candidate's
/// (or an exemplar's) guard panel-source slots, keyed by panel slot id.
///
/// This is the panel-driven measurement path (#331): instead of accepting
/// caller-supplied per-slot vectors, the server measures the candidate's source text
/// through the real libcbm + panel pipeline (the same instruments as indexing) and
/// hands the resulting per-panel-slot vectors here. Each guard slot's vector is the
/// densified panel source, and a multi-source guard slot (`PublicApiSignature` = S5 +
/// S17) is the **concatenation** of its source vectors in canonical source order — a
/// structural, assumption-free combiner that is byte-identical for identical input, so
/// the candidate and exemplar paths stay a shared instrument.
///
/// Fails closed when a required panel source is absent/missing
/// ([`ASTRO_GUARD_CHECK_PANEL_SLOT_MISSING`]) or is an unsupported `Multi` shape — a
/// candidate the panel could not fully measure is refused, never partially measured.
pub fn slot_input_from_panel(
    sources: &BTreeMap<u16, SlotVector>,
) -> Result<SymbolSlotInput, CalibrationError> {
    let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let mut vector: Vec<f32> = Vec::new();
        for &panel_slot in guard_slot_panel_sources(slot) {
            let measured = sources
                .get(&panel_slot)
                .and_then(|vector| densify_panel_vector(slot, panel_slot, vector).transpose());
            match measured {
                Some(Ok(dense)) => vector.extend_from_slice(&dense),
                Some(Err(error)) => return Err(error),
                None => {
                    return Err(CalibrationError::new(
                        ASTRO_GUARD_CHECK_PANEL_SLOT_MISSING,
                        format!(
                            "guard slot `{}` panel source S{panel_slot} was not measured in the \
                             panel readout; the candidate cannot be scored on this slot",
                            slot.as_str()
                        ),
                        "Measure every guard panel source through the panel before checking; a \
                         partially-measured candidate is refused, never partially scored.",
                    ));
                }
            }
        }
        slots.push(SlotFeature { slot, vector });
    }
    Ok(SymbolSlotInput { slots })
}

/// Panel-driven candidate/exemplar measurement (#331): densify a panel readout into a
/// guard-check [`SymbolSlotInput`] and run it through the shared instrument
/// ([`measure_symbol_slots`]) so a panel-derived symbol is byte-identical to one built
/// from the same vectors supplied directly. Fails closed on a missing/absent/`Multi`
/// panel source or a degenerate vector.
pub fn measure_from_panel(
    sources: &BTreeMap<u16, SlotVector>,
) -> Result<MeasuredSymbol, CalibrationError> {
    measure_symbol_slots(&slot_input_from_panel(sources)?)
}

/// Cosine of two equal-length finite vectors. The inputs are already unit-norm
/// (from [`measure_symbol_slots`]), so this is their dot product, clamped to
/// `[-1, 1]` against floating-point drift. Length mismatch fails closed.
pub fn cosine(a: &[f32], b: &[f32]) -> Result<f32, CalibrationError> {
    if a.len() != b.len() {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_CHECK_DIM_MISMATCH",
            format!("cosine dimension mismatch: {} vs {}", a.len(), b.len()),
            "Candidate and exemplar slot vectors must share a dimension; recheck the panel lens.",
        ));
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    if !dot.is_finite() {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_CHECK_NONFINITE_COSINE",
            "cosine evaluated to a non-finite value",
            "A non-finite cosine is a measurement fault; refuse rather than route it.",
        ));
    }
    Ok(dot.clamp(-1.0, 1.0))
}

// ---------------------------------------------------------------------------
// Comparison-region resolution (Scope step 3)
// ---------------------------------------------------------------------------

/// A trusted exemplar in the candidate's enclosing scope: its measured slots and
/// whether it sits in the scope kernel (kernel-near) or on the periphery.
#[derive(Debug, Clone, PartialEq)]
pub struct Exemplar {
    /// Hex CxId of the exemplar symbol (provenance on the served report).
    pub cx_id_hex: String,
    /// `true` when the exemplar is kernel-near (central, high-centrality) for the
    /// enclosing scope; kernel-near exemplars are the primary comparison set.
    pub kernel_near: bool,
    pub measured: MeasuredSymbol,
}

/// Which tier of the enclosing scope supplied the resolved comparison region.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RegionClass {
    /// Kernel-near trusted exemplars (the preferred comparison set).
    KernelNear,
    /// Peripheral fallback: no kernel-near exemplar exists for this scope.
    Peripheral,
}

impl RegionClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelNear => "kernel_near",
            Self::Peripheral => "peripheral",
        }
    }
}

/// The resolved comparison region: the exemplars the candidate is measured
/// against and which tier they came from.
#[derive(Debug, Clone, PartialEq)]
pub struct ComparisonRegion<'a> {
    pub class: RegionClass,
    pub exemplars: Vec<&'a Exemplar>,
}

/// Resolve the comparison region from the enclosing scope's trusted exemplars:
/// **kernel-near first, peripheral fallback**. Fails closed when the scope has no
/// trusted exemplar at all — a candidate with no comparison region cannot be
/// measured, so it is refused rather than accepted by default.
pub fn resolve_region(exemplars: &[Exemplar]) -> Result<ComparisonRegion<'_>, CalibrationError> {
    if exemplars.is_empty() {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_CHECK_NO_REGION",
            "the candidate's enclosing scope has no trusted exemplars to compare against",
            "Index and ground trusted exemplars for this scope before checking; the guard refuses \
             to accept an unmeasurable candidate by default.",
        ));
    }
    let kernel_near: Vec<&Exemplar> = exemplars
        .iter()
        .filter(|exemplar| exemplar.kernel_near)
        .collect();
    if !kernel_near.is_empty() {
        return Ok(ComparisonRegion {
            class: RegionClass::KernelNear,
            exemplars: kernel_near,
        });
    }
    Ok(ComparisonRegion {
        class: RegionClass::Peripheral,
        exemplars: exemplars.iter().collect(),
    })
}

// ---------------------------------------------------------------------------
// Per-slot scoring + verdict (Scope steps 4-5, response contract)
// ---------------------------------------------------------------------------

/// The nearest exemplar to the candidate (highest mean per-slot cosine), served
/// for imitation guidance.
#[derive(Debug, Clone, PartialEq)]
pub struct NearestExemplar {
    pub cx_id_hex: String,
    pub kernel_near: bool,
    /// Mean per-slot cosine of the candidate to this exemplar.
    pub mean_cosine: f32,
}

/// The full guard-check report (response contract): the per-slot table, the
/// combined verdict, the provisional flag, the region tier, the nearest exemplar
/// for imitation, and remediation text. The per-slot detail is never discarded.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckReport {
    pub schema: &'static str,
    pub combined: CombinedVerdict,
    pub region_class: RegionClass,
    pub nearest_exemplar: NearestExemplar,
    /// Honest scope note: the guard measures distributional conformance, not
    /// correctness.
    pub measures: &'static str,
    /// Actionable remediation derived from the verdict class + failing slots.
    pub remediation: String,
    pub trust: &'static str,
    pub freshness: &'static str,
}

impl CheckReport {
    pub fn verdict_str(&self) -> &'static str {
        self.combined.verdict.as_str()
    }
}

/// Per-slot cosine of the candidate to the region: the **max** cosine over the
/// region's exemplars for that slot (nearest-neighbor conformance — a candidate
/// is in-distribution if it resembles *any* trusted exemplar on that slot).
fn slot_cosine_to_region(
    candidate: &MeasuredSymbol,
    slot: GuardSlot,
    region: &ComparisonRegion<'_>,
) -> Result<f32, CalibrationError> {
    let Some(candidate_slot) = candidate.slot(slot) else {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_CHECK_SLOT_MISSING",
            format!(
                "candidate is missing measured guard slot `{}`",
                slot.as_str()
            ),
            "Measure every guard slot before scoring.",
        ));
    };
    let mut best = f32::NEG_INFINITY;
    for exemplar in &region.exemplars {
        let Some(exemplar_slot) = exemplar.measured.slot(slot) else {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_CHECK_EXEMPLAR_SLOT_MISSING",
                format!(
                    "exemplar {} is missing guard slot `{}`",
                    exemplar.cx_id_hex,
                    slot.as_str()
                ),
                "Every exemplar must be measured on the same guard slots as the candidate.",
            ));
        };
        let cos = cosine(&candidate_slot.unit, &exemplar_slot.unit)?;
        if cos > best {
            best = cos;
        }
    }
    Ok(best)
}

/// Route a measured candidate against a calibrated profile and its comparison
/// region into a full [`CheckReport`]. Per-slot cosines are scored against the
/// profile's calibrated `tau`, combined **per-slot never averaged** via
/// [`combine_verdicts_with_lock`], and turned into a verdict-class remediation.
///
/// The candidate's target is treated as identity-locked (exported/public);
/// callers holding a per-target lock decision use [`check_candidate_with_lock`]
/// to downgrade the identity slot to content-class for a non-exported target.
pub fn check_candidate(
    candidate: &MeasuredSymbol,
    profile: &GuardProfile,
    region: &ComparisonRegion<'_>,
) -> Result<CheckReport, CalibrationError> {
    check_candidate_with_lock(candidate, profile, region, true)
}

/// Route a measured candidate with an explicit **identity-lock** decision (P7.4).
/// An exported/public target (`identity_locked = true`) enforces the public-API
/// signature slot `AllRequired` at the identity FAR — breaking-change drift on a
/// locked surface refuses. A non-exported target (`identity_locked = false`)
/// folds the same slot into the content `KofN` set (content-class handling), so
/// signature drift on a private symbol routes to `new_region`, not an identity
/// refuse. Per-slot detail is preserved either way (A3 no-flatten).
pub fn check_candidate_with_lock(
    candidate: &MeasuredSymbol,
    profile: &GuardProfile,
    region: &ComparisonRegion<'_>,
    identity_locked: bool,
) -> Result<CheckReport, CalibrationError> {
    // Per-slot verdicts: candidate cosine to the region vs the calibrated tau.
    let mut per_slot = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let Some(calibration) = profile.slot(slot) else {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_CHECK_PROFILE_SLOT_MISSING",
                format!(
                    "profile for {} is missing guard slot `{}`",
                    profile.domain.label(),
                    slot.as_str()
                ),
                "Recalibrate the domain profile so every fixed guard slot has a tau.",
            ));
        };
        let cos = slot_cosine_to_region(candidate, slot, region)?;
        per_slot.push(SlotVerdict {
            slot,
            cos,
            tau: calibration.tau,
        });
    }

    let combined = combine_verdicts_with_lock(
        &per_slot,
        profile.content_policy,
        profile.provisional,
        identity_locked,
    );
    let nearest = nearest_exemplar(candidate, region)?;
    let remediation = remediation_for(&combined, region.class, &nearest);

    Ok(CheckReport {
        schema: GUARD_VERDICT_SCHEMA,
        combined,
        region_class: region.class,
        nearest_exemplar: nearest,
        measures: "distributional conformance to trusted exemplars, not correctness",
        remediation,
        trust: if profile.provisional {
            "provisional"
        } else {
            "verified"
        },
        freshness: "fresh",
    })
}

/// The nearest exemplar by mean per-slot cosine (for imitation guidance).
fn nearest_exemplar(
    candidate: &MeasuredSymbol,
    region: &ComparisonRegion<'_>,
) -> Result<NearestExemplar, CalibrationError> {
    let mut best: Option<NearestExemplar> = None;
    for exemplar in &region.exemplars {
        let mut sum = 0.0f32;
        let mut count = 0u32;
        for slot in GuardSlot::ALL {
            let (Some(candidate_slot), Some(exemplar_slot)) =
                (candidate.slot(slot), exemplar.measured.slot(slot))
            else {
                continue;
            };
            sum += cosine(&candidate_slot.unit, &exemplar_slot.unit)?;
            count += 1;
        }
        if count == 0 {
            continue;
        }
        let mean = sum / count as f32;
        if best
            .as_ref()
            .map(|current| mean > current.mean_cosine)
            .unwrap_or(true)
        {
            best = Some(NearestExemplar {
                cx_id_hex: exemplar.cx_id_hex.clone(),
                kernel_near: exemplar.kernel_near,
                mean_cosine: mean,
            });
        }
    }
    best.ok_or_else(|| {
        CalibrationError::new(
            "ASTRO_GUARD_CHECK_NO_REGION",
            "no exemplar in the resolved region could be scored",
            "Ensure the region's exemplars are measured on the guard slots.",
        )
    })
}

/// Verdict-class remediation text naming the failing slot(s) and the imitation
/// target, per the response contract.
fn remediation_for(
    combined: &CombinedVerdict,
    region_class: RegionClass,
    nearest: &NearestExemplar,
) -> String {
    use crate::profile::GuardVerdict;
    let failing: Vec<&str> = combined
        .per_slot
        .iter()
        .filter(|sv| !sv.pass())
        .map(|sv| sv.slot.as_str())
        .collect();
    match combined.verdict {
        GuardVerdict::Accept => format!(
            "Accept: the candidate conforms to the {} trusted region on every guard slot. \
             Nearest exemplar {} (mean cosine {:.3}).",
            region_class.as_str(),
            nearest.cx_id_hex,
            nearest.mean_cosine
        ),
        GuardVerdict::NewRegion => format!(
            "New region: {} drift from the {} trusted region within tolerance. Recorded awaiting \
             grounding; ack it or ground it with a real outcome. Imitate nearest exemplar {} \
             (mean cosine {:.3}).",
            slot_list(&failing),
            region_class.as_str(),
            nearest.cx_id_hex,
            nearest.mean_cosine
        ),
        GuardVerdict::Quarantine => format!(
            "Quarantine: identity near-miss on {} (held for review). Align the candidate's public \
             surface with nearest exemplar {} before re-checking.",
            slot_list(&failing),
            nearest.cx_id_hex
        ),
        GuardVerdict::Refuse => format!(
            "Refuse: {} out-of-distribution for this area ({}). {} Rework toward nearest exemplar \
             {} (mean cosine {:.3}) or ground a new trusted region first.",
            slot_list(&failing),
            region_class.as_str(),
            combined.reason,
            nearest.cx_id_hex,
            nearest.mean_cosine
        ),
    }
}

fn slot_list(slots: &[&str]) -> String {
    if slots.is_empty() {
        "no slot".to_string()
    } else {
        format!("slot(s) {}", slots.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Verdict ledger payload (Scope step 6, DoD #5)
// ---------------------------------------------------------------------------

/// Canonical UTF-8 JSON bytes of the guard-check verdict, subject = the target
/// `CxId` (hex). Carries the full per-slot `cos`/`tau`/`pass` detail so a raw
/// ledger read reproduces exactly what the response served (DoD #5). The server
/// appends these bytes (kind = `Guard`, subject = `Cx(target)`) so every verdict
/// is auditably paired with its ledger entry (HONEST invariant 5).
///
/// Hand-built canonical JSON (stable key order, finite floats) so the server can
/// both hash it and read it back byte-for-byte.
pub fn verdict_ledger_payload_bytes(report: &CheckReport, target_cx_hex: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"schema\":\"{}\",", GUARD_VERDICT_SCHEMA));
    out.push_str(&format!(
        "\"subject_cx\":\"{}\",",
        json_escape(target_cx_hex)
    ));
    out.push_str(&format!(
        "\"verdict\":\"{}\",",
        report.combined.verdict.as_str()
    ));
    out.push_str(&format!("\"provisional\":{},", report.combined.provisional));
    out.push_str(&format!(
        "\"region_class\":\"{}\",",
        report.region_class.as_str()
    ));
    out.push_str(&format!(
        "\"nearest_exemplar\":{{\"cx\":\"{}\",\"kernel_near\":{},\"mean_cosine\":{}}},",
        json_escape(&report.nearest_exemplar.cx_id_hex),
        report.nearest_exemplar.kernel_near,
        json_f32(report.nearest_exemplar.mean_cosine)
    ));
    out.push_str(&format!(
        "\"reason\":\"{}\",",
        json_escape(&report.combined.reason)
    ));
    out.push_str("\"slots\":[");
    // Per-slot detail in canonical GuardSlot order.
    let mut ordered: Vec<&SlotVerdict> = report.combined.per_slot.iter().collect();
    ordered.sort_by_key(|sv| sv.slot as u8);
    for (index, sv) in ordered.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"slot\":\"{}\",\"kind\":\"{}\",\"cos\":{},\"tau\":{},\"pass\":{}}}",
            sv.slot.as_str(),
            sv.slot.kind().as_str(),
            json_f32(sv.cos),
            json_f32(sv.tau),
            sv.pass()
        ));
    }
    out.push_str("]}");
    out.into_bytes()
}

/// Canonical JSON number form for a measured `f32`: the value a reader gets
/// back when parsing the shortest-decimal encoding
/// [`verdict_ledger_payload_bytes`] writes. Serving any other widening (e.g. a
/// bare `as f64`) makes a served report and its persisted verdict compare
/// unequal on identical measurements.
pub fn canonical_slot_number(value: f32) -> f64 {
    json_f32(value).parse().unwrap_or(0.0)
}

/// Emit an `f32` as a finite JSON number (never `NaN`/`Infinity`).
fn json_f32(value: f32) -> String {
    if value.is_nan() {
        "0".to_string()
    } else if value.is_infinite() {
        if value > 0.0 {
            "1e38".to_string()
        } else {
            "-1e38".to_string()
        }
    } else {
        let text = format!("{value}");
        if text.contains('.') || text.contains('e') || text.contains('E') {
            text
        } else {
            format!("{text}.0")
        }
    }
}

/// Minimal JSON string escaping for the hand-built payload (quotes, backslashes,
/// and control characters). CxIds are lowercase hex, but reasons are free text.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// New-region grounding lifecycle (DoD #4)
// ---------------------------------------------------------------------------

/// The lifecycle state of a `new_region`-routed candidate. A novel-but-plausible
/// candidate is recorded [`AwaitingGrounding`](GroundingState::AwaitingGrounding),
/// surfaced for a human ack ([`Acked`](GroundingState::Acked)), and promotable to
/// a trusted region only once real grounding evidence arrives
/// ([`Grounded`](GroundingState::Grounded)).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GroundingState {
    AwaitingGrounding,
    Acked,
    Grounded,
}

impl GroundingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingGrounding => "awaiting_grounding",
            Self::Acked => "acked",
            Self::Grounded => "grounded",
        }
    }
}

/// A recorded new-region candidate awaiting grounding. The state machine is
/// strictly forward: `AwaitingGrounding -> Acked -> Grounded`; skipping the ack
/// or grounding without evidence fails closed.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRegionRecord {
    pub schema: &'static str,
    pub subject_cx_hex: String,
    pub state: GroundingState,
    /// Ledger seq of the verdict entry that routed this candidate (set by the
    /// server when the verdict is ledgered).
    pub verdict_ledger_seq: Option<u64>,
    /// Grounding evidence reference recorded on promotion (e.g. a Grounding
    /// ledger seq or an anchor id).
    pub grounding_ref: Option<String>,
}

impl NewRegionRecord {
    /// Record a `new_region`-routed candidate as `AwaitingGrounding`. Refuses if
    /// the report's verdict is not `new_region` — only novel-but-plausible
    /// candidates enter the grounding lifecycle.
    pub fn record(report: &CheckReport, subject_cx_hex: &str) -> Result<Self, CalibrationError> {
        use crate::profile::GuardVerdict;
        if report.combined.verdict != GuardVerdict::NewRegion {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_NEW_REGION_WRONG_VERDICT",
                format!(
                    "cannot record a new-region for a `{}` verdict; only `new_region` candidates \
                     enter the grounding lifecycle",
                    report.combined.verdict.as_str()
                ),
                "Only route new_region verdicts into the grounding lifecycle; accept/quarantine/\
                 refuse are terminal.",
            ));
        }
        Ok(Self {
            schema: GUARD_NEW_REGION_SCHEMA,
            subject_cx_hex: subject_cx_hex.to_string(),
            state: GroundingState::AwaitingGrounding,
            verdict_ledger_seq: None,
            grounding_ref: None,
        })
    }

    /// Human acknowledgement: `AwaitingGrounding -> Acked`. Fails closed if the
    /// record is not awaiting grounding (double-ack / out-of-order).
    pub fn ack(&mut self) -> Result<(), CalibrationError> {
        if self.state != GroundingState::AwaitingGrounding {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_NEW_REGION_NOT_AWAITING",
                format!(
                    "record is `{}`, not awaiting grounding; cannot ack",
                    self.state.as_str()
                ),
                "Ack only a record that is awaiting grounding.",
            ));
        }
        self.state = GroundingState::Acked;
        Ok(())
    }

    /// Promote on real grounding: `Acked -> Grounded`, recording the grounding
    /// evidence reference. Fails closed if the record was not acked first or the
    /// evidence reference is empty — a new region is never promoted on a guess.
    pub fn promote_on_grounding(&mut self, grounding_ref: &str) -> Result<(), CalibrationError> {
        if self.state != GroundingState::Acked {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_NEW_REGION_NOT_ACKED",
                format!(
                    "record is `{}`; a new region must be acked before it can be promoted on \
                     grounding",
                    self.state.as_str()
                ),
                "Ack the new region, then promote it once real grounding evidence arrives.",
            ));
        }
        if grounding_ref.trim().is_empty() {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_NEW_REGION_NO_EVIDENCE",
                "promotion requires a non-empty grounding evidence reference",
                "Promote only with a real grounding reference (a Grounding ledger seq or anchor \
                 id); never promote on an empty guess.",
            ));
        }
        self.grounding_ref = Some(grounding_ref.to_string());
        self.state = GroundingState::Grounded;
        Ok(())
    }

    /// `true` once the candidate has been grounded and can be promoted into the
    /// trusted region (surfaced for exemplar promotion).
    pub fn is_promotable(&self) -> bool {
        self.state == GroundingState::Grounded && self.grounding_ref.is_some()
    }
}

// ---------------------------------------------------------------------------
// Determinism (DoD #6)
// ---------------------------------------------------------------------------

/// Deterministic verdict fingerprint: the canonical verdict payload bytes are a
/// pure function of the candidate + region + profile, so the same inputs yield
/// byte-identical payloads (DoD #6, proven in tests).
pub fn verdict_is_deterministic(
    candidate: &MeasuredSymbol,
    profile: &GuardProfile,
    region: &ComparisonRegion<'_>,
    target_cx_hex: &str,
) -> Result<Vec<u8>, CalibrationError> {
    let report = check_candidate(candidate, profile, region)?;
    Ok(verdict_ledger_payload_bytes(&report, target_cx_hex))
}
