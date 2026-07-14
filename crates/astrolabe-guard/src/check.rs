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

use crate::calibration::CalibrationError;
use crate::profile::{CombinedVerdict, GuardProfile, GuardSlot, SlotVerdict, combine_verdicts};

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
/// [`combine_verdicts`], and turned into a verdict-class remediation.
pub fn check_candidate(
    candidate: &MeasuredSymbol,
    profile: &GuardProfile,
    region: &ComparisonRegion<'_>,
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

    let combined = combine_verdicts(&per_slot, profile.content_policy, profile.provisional);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::{CalibrationDomain, CalibrationLanguage};
    use crate::profile::{
        CONFORMAL_ALPHA, GuardVerdict, SlotCalibration, calibrate_slot, default_content_policy,
    };

    fn domain() -> CalibrationDomain {
        CalibrationDomain::new(CalibrationLanguage::Rust, "core").expect("valid domain")
    }

    /// A symbol whose every guard slot carries the same base direction plus a
    /// small per-slot perturbation, so identical seeds yield identical vectors.
    fn symbol_input(seed: f32, dim: usize) -> SymbolSlotInput {
        let slots = GuardSlot::ALL
            .iter()
            .enumerate()
            .map(|(ordinal, slot)| {
                // Frequency-coded by seed: different seeds give near-orthogonal
                // directions (low cosine), close seeds give high cosine — so the
                // fixtures can drive genuinely alien vs conforming candidates.
                let vector: Vec<f32> = (0..dim)
                    .map(|i| (seed * (i as f32 + 1.0) + ordinal as f32 * 0.001).sin())
                    .collect();
                SlotFeature {
                    slot: *slot,
                    vector,
                }
            })
            .collect();
        SymbolSlotInput { slots }
    }

    /// A profile with every slot calibrated to a fixed tau (for verdict routing
    /// tests) — a real calibrated profile, not a cold-start.
    fn profile_with_tau(tau: f32) -> GuardProfile {
        let slots: Vec<SlotCalibration> = GuardSlot::ALL
            .iter()
            .map(|slot| {
                let mut cal = SlotCalibration::cold_start(*slot);
                cal.tau = tau;
                cal.provisional = false;
                cal.achieved_far = 0.02;
                cal.achieved_frr = 0.0;
                cal
            })
            .collect();
        GuardProfile {
            domain: domain(),
            slots,
            content_policy: default_content_policy(),
            provisional: false,
            corpus_hash: [0u8; 32],
            calibrated_ledger_seq: Some(1),
        }
    }

    fn exemplar_from(seed: f32, dim: usize, cx: &str, kernel_near: bool) -> Exemplar {
        Exemplar {
            cx_id_hex: cx.to_string(),
            kernel_near,
            measured: measure_symbol_slots(&symbol_input(seed, dim)).expect("measures"),
        }
    }

    // -- DoD #1: same-instruments invariant (byte-compare) -------------------

    #[test]
    fn same_instruments_index_and_check_are_byte_identical() {
        let input = symbol_input(0.5, 16);
        let indexed = measure_for_index(&input).expect("index measures");
        let checked = measure_for_check(&input).expect("check measures");
        // Byte-compare: the two paths must produce identical measured slots for
        // identical input. This is proven by comparing bytes, not by review.
        assert_eq!(
            indexed.canonical_bytes(),
            checked.canonical_bytes(),
            "indexing and check measurement paths must be byte-identical (A shared instrument)"
        );
        assert_eq!(indexed, checked);
        // And each is internally deterministic.
        assert_eq!(
            measure_for_check(&input).unwrap().canonical_bytes(),
            checked.canonical_bytes()
        );
    }

    #[test]
    fn measurement_fails_closed_on_missing_empty_and_degenerate_slots() {
        // Missing slot.
        let mut input = symbol_input(0.3, 8);
        input.slots.retain(|f| f.slot != GuardSlot::ApiCallees);
        let err = measure_symbol_slots(&input).expect_err("missing slot refused");
        assert_eq!(err.code(), "ASTRO_GUARD_CHECK_SLOT_MISSING");
        // Empty vector.
        let mut input = symbol_input(0.3, 8);
        input.slots[0].vector.clear();
        let err = measure_symbol_slots(&input).expect_err("empty vector refused");
        assert_eq!(err.code(), "ASTRO_GUARD_CHECK_EMPTY_VECTOR");
        // Zero-magnitude vector.
        let mut input = symbol_input(0.3, 8);
        input.slots[1].vector = vec![0.0; 8];
        let err = measure_symbol_slots(&input).expect_err("zero vector refused");
        assert_eq!(err.code(), "ASTRO_GUARD_CHECK_DEGENERATE_VECTOR");
        // Non-finite component.
        let mut input = symbol_input(0.3, 8);
        input.slots[2].vector[0] = f32::NAN;
        let err = measure_symbol_slots(&input).expect_err("nan vector refused");
        assert_eq!(err.code(), "ASTRO_GUARD_CHECK_NONFINITE_VECTOR");
    }

    #[test]
    fn unit_vectors_have_cosine_one_with_themselves() {
        let measured = measure_symbol_slots(&symbol_input(0.7, 12)).unwrap();
        let slot = measured.slot(GuardSlot::CodeSemantic).unwrap();
        let cos = cosine(&slot.unit, &slot.unit).unwrap();
        assert!((cos - 1.0).abs() < 1e-5, "self-cosine {cos} must be 1.0");
    }

    // -- Comparison-region resolution (Scope step 3) -------------------------

    #[test]
    fn region_prefers_kernel_near_then_falls_back_to_peripheral() {
        let exemplars = vec![
            exemplar_from(0.5, 8, "cx:peripheral", false),
            exemplar_from(0.5, 8, "cx:kernel", true),
        ];
        let region = resolve_region(&exemplars).unwrap();
        assert_eq!(region.class, RegionClass::KernelNear);
        assert_eq!(region.exemplars.len(), 1);
        assert_eq!(region.exemplars[0].cx_id_hex, "cx:kernel");

        // No kernel-near exemplar => peripheral fallback (all exemplars).
        let peripheral_only = vec![
            exemplar_from(0.5, 8, "cx:p1", false),
            exemplar_from(0.6, 8, "cx:p2", false),
        ];
        let region = resolve_region(&peripheral_only).unwrap();
        assert_eq!(region.class, RegionClass::Peripheral);
        assert_eq!(region.exemplars.len(), 2);
    }

    #[test]
    fn empty_region_fails_closed() {
        let err = resolve_region(&[]).expect_err("empty region must refuse");
        assert_eq!(err.code(), "ASTRO_GUARD_CHECK_NO_REGION");
        assert!(!err.remediation().is_empty());
    }

    // -- DoD #2: verdict-class fixtures --------------------------------------

    #[test]
    fn conforming_candidate_accepts() {
        // Candidate identical to a kernel-near exemplar => cosine 1.0 on every
        // slot => accept against a tau below 1.0.
        let exemplars = vec![exemplar_from(0.5, 16, "cx:kernel", true)];
        let region = resolve_region(&exemplars).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(0.5, 16)).unwrap();
        let report = check_candidate(&candidate, &profile_with_tau(0.8), &region).unwrap();
        assert_eq!(
            report.combined.verdict,
            GuardVerdict::Accept,
            "{}",
            report.remediation
        );
        assert_eq!(report.nearest_exemplar.cx_id_hex, "cx:kernel");
        assert!(report.nearest_exemplar.mean_cosine > 0.99);
        assert_eq!(report.combined.per_slot.len(), GuardSlot::ALL.len());
    }

    #[test]
    fn alien_candidate_refuses_with_failing_slot_named() {
        // Candidate whose per-slot cosine to the region is low on the content
        // slots => below tau on >1 content slot => refuse.
        let exemplars = vec![exemplar_from(0.5, 16, "cx:kernel", true)];
        let region = resolve_region(&exemplars).unwrap();
        // A very different seed makes cosine low; tau near 1.0 forces failure.
        let candidate = measure_symbol_slots(&symbol_input(2.3, 16)).unwrap();
        let report = check_candidate(&candidate, &profile_with_tau(0.999), &region).unwrap();
        assert_eq!(
            report.combined.verdict,
            GuardVerdict::Refuse,
            "{}",
            report.remediation
        );
        // The remediation names at least one failing slot.
        assert!(
            report.remediation.contains("slot(s)"),
            "{}",
            report.remediation
        );
        assert!(report.remediation.to_lowercase().contains("refuse"));
    }

    #[test]
    fn identity_near_miss_quarantines() {
        // Build a candidate that passes content+stylistic but sits just below tau
        // on the identity slot, within the quarantine band. We do this by
        // constructing per-slot verdicts directly through a tuned profile: set a
        // high identity tau and a candidate whose identity cosine is within 0.05.
        // Candidate == exemplar gives cosine 1.0; instead use a near copy.
        let exemplar = exemplar_from(0.5, 32, "cx:kernel", true);
        let exemplars = vec![exemplar];
        let region = resolve_region(&exemplars).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(0.5, 32)).unwrap();
        // identity cosine ~1.0; set identity tau just above it within the 0.05
        // band so it's a near-miss, content/stylistic taus low so they pass.
        let mut profile = profile_with_tau(0.5);
        if let Some(id) = profile
            .slots
            .iter_mut()
            .find(|s| s.slot == GuardSlot::PublicApiSignature)
        {
            id.tau = 1.02; // cos ~1.0 < 1.02, margin -0.02 within -0.05 band.
        }
        let report = check_candidate(&candidate, &profile, &region).unwrap();
        assert_eq!(
            report.combined.verdict,
            GuardVerdict::Quarantine,
            "{}",
            report.remediation
        );
        assert!(report.remediation.to_lowercase().contains("quarantine"));
    }

    #[test]
    fn provisional_profile_marks_report_provisional() {
        let exemplars = vec![exemplar_from(0.5, 8, "cx:kernel", true)];
        let region = resolve_region(&exemplars).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(0.5, 8)).unwrap();
        let mut profile = profile_with_tau(0.7);
        profile.provisional = true;
        let report = check_candidate(&candidate, &profile, &region).unwrap();
        assert!(report.combined.provisional);
        assert_eq!(report.trust, "provisional");
    }

    // -- DoD #4: new-region grounding lifecycle (end-to-end) -----------------

    #[test]
    fn new_region_lifecycle_awaiting_ack_promote() {
        // Route a candidate to new_region: one content slot miss within KofN
        // tolerance. Construct via a profile where exactly one content slot fails.
        let exemplar = exemplar_from(0.5, 32, "cx:kernel", true);
        let region_ex = vec![exemplar];
        let region = resolve_region(&region_ex).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(0.5, 32)).unwrap();
        // All cosines ~1.0. Set exactly one content slot's tau above 1.0 so it
        // misses; the KofN tolerance (k=n-1) routes to new_region.
        let mut profile = profile_with_tau(0.5);
        if let Some(s) = profile
            .slots
            .iter_mut()
            .find(|s| s.slot == GuardSlot::ApiCallees)
        {
            s.tau = 1.05;
        }
        let report = check_candidate(&candidate, &profile, &region).unwrap();
        assert_eq!(
            report.combined.verdict,
            GuardVerdict::NewRegion,
            "{}",
            report.remediation
        );

        // Record => AwaitingGrounding.
        let mut record = NewRegionRecord::record(&report, "cx:candidate").unwrap();
        assert_eq!(record.state, GroundingState::AwaitingGrounding);
        assert!(!record.is_promotable());

        // Cannot promote before ack.
        let err = record.promote_on_grounding("grounding:seq=7").unwrap_err();
        assert_eq!(err.code(), "ASTRO_GUARD_NEW_REGION_NOT_ACKED");

        // Ack => Acked. Double-ack fails.
        record.ack().unwrap();
        assert_eq!(record.state, GroundingState::Acked);
        assert_eq!(
            record.ack().unwrap_err().code(),
            "ASTRO_GUARD_NEW_REGION_NOT_AWAITING"
        );

        // Promote requires real evidence.
        assert_eq!(
            record.promote_on_grounding("  ").unwrap_err().code(),
            "ASTRO_GUARD_NEW_REGION_NO_EVIDENCE"
        );
        record.promote_on_grounding("grounding:seq=7").unwrap();
        assert_eq!(record.state, GroundingState::Grounded);
        assert!(record.is_promotable());
        assert_eq!(record.grounding_ref.as_deref(), Some("grounding:seq=7"));
    }

    #[test]
    fn record_refuses_non_new_region_verdict() {
        let exemplars = vec![exemplar_from(0.5, 8, "cx:kernel", true)];
        let region = resolve_region(&exemplars).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(0.5, 8)).unwrap();
        let report = check_candidate(&candidate, &profile_with_tau(0.8), &region).unwrap();
        assert_eq!(report.combined.verdict, GuardVerdict::Accept);
        let err = NewRegionRecord::record(&report, "cx:candidate").unwrap_err();
        assert_eq!(err.code(), "ASTRO_GUARD_NEW_REGION_WRONG_VERDICT");
    }

    // -- DoD #5: verdict ledger payload carries full per-slot detail ---------

    #[test]
    fn verdict_payload_reparses_with_full_per_slot_detail() {
        let exemplars = vec![exemplar_from(0.5, 16, "cx:kernel", true)];
        let region = resolve_region(&exemplars).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(2.3, 16)).unwrap();
        let report = check_candidate(&candidate, &profile_with_tau(0.999), &region).unwrap();
        let bytes = verdict_ledger_payload_bytes(&report, "cx:deadbeef");
        let text = std::str::from_utf8(&bytes).expect("utf-8");
        let value: serde_json::Value = serde_json::from_str(text).expect("valid JSON verdict");
        assert_eq!(value["schema"], GUARD_VERDICT_SCHEMA);
        assert_eq!(value["subject_cx"], "cx:deadbeef");
        assert_eq!(value["verdict"], report.combined.verdict.as_str());
        assert_eq!(value["region_class"], report.region_class.as_str());
        let slots = value["slots"].as_array().unwrap();
        assert_eq!(slots.len(), GuardSlot::ALL.len());
        // Every persisted per-slot row matches the served report's per-slot row.
        for served in &report.combined.per_slot {
            let row = slots
                .iter()
                .find(|s| s["slot"] == served.slot.as_str())
                .expect("slot present in payload");
            // The payload carries json_f32's shortest round-trippable decimal,
            // the same representation the server serves, so the persisted row
            // matches the served value to f32 precision (bit-exact decimals).
            assert!(
                (row["cos"].as_f64().unwrap() - f64::from(served.cos)).abs() < 1e-6,
                "persisted cos {} != served {}",
                row["cos"],
                served.cos
            );
            assert!((row["tau"].as_f64().unwrap() - f64::from(served.tau)).abs() < 1e-6);
            assert_eq!(row["pass"].as_bool().unwrap(), served.pass());
            assert!(row["kind"].is_string());
        }
    }

    // -- DoD #6: determinism -------------------------------------------------

    #[test]
    fn same_candidate_and_region_yield_identical_verdict_bytes() {
        let exemplars = vec![
            exemplar_from(0.5, 16, "cx:kernel", true),
            exemplar_from(0.9, 16, "cx:kernel2", true),
        ];
        let region = resolve_region(&exemplars).unwrap();
        let candidate = measure_symbol_slots(&symbol_input(1.1, 16)).unwrap();
        let profile = profile_with_tau(0.85);
        let a = verdict_is_deterministic(&candidate, &profile, &region, "cx:sub").unwrap();
        let b = verdict_is_deterministic(&candidate, &profile, &region, "cx:sub").unwrap();
        assert_eq!(
            a, b,
            "same inputs must yield byte-identical verdict payloads"
        );
        // And the report itself is equal.
        let r1 = check_candidate(&candidate, &profile, &region).unwrap();
        let r2 = check_candidate(&candidate, &profile, &region).unwrap();
        assert_eq!(r1, r2);
    }

    // -- DoD #3: guard ROC gate (empirical FAR/FRR, committed measurement) ---

    /// The P7 exit gate: on held-out bad candidates (never in calibration) the
    /// empirical FAR stays within the identity target's finite-sample regime, and
    /// on accepted-in-history good candidates the FRR is < 20%. The numbers are
    /// asserted here and published in the closing evidence.
    #[test]
    fn guard_roc_gate_far_and_frr_on_held_out_population() {
        let dim = 24;
        // Trusted region: a tight kernel around a base direction.
        let exemplars: Vec<Exemplar> = (0..8)
            .map(|i| exemplar_from(0.50 + i as f32 * 0.002, dim, &format!("cx:ex{i}"), true))
            .collect();
        let region = resolve_region(&exemplars).unwrap();

        // Calibrate each slot from measured good/bad cosines to the region so tau
        // is a real conformal threshold, not a hand-picked constant.
        // Good = in-region seeds; bad = far seeds (mutants/reverts/alien analogues).
        let good_seeds: Vec<f32> = (0..40).map(|i| 0.50 + i as f32 * 0.001).collect();
        let bad_seeds: Vec<f32> = (0..40).map(|i| 2.0 + i as f32 * 0.03).collect();
        let measure_cos = |seed: f32, slot: GuardSlot| -> f32 {
            let m = measure_symbol_slots(&symbol_input(seed, dim)).unwrap();
            slot_cosine_to_region(&m, slot, &region).unwrap()
        };
        let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
        for slot in GuardSlot::ALL {
            let good_scores: Vec<f32> = good_seeds.iter().map(|s| measure_cos(*s, slot)).collect();
            let bad_scores: Vec<f32> = bad_seeds.iter().map(|s| measure_cos(*s, slot)).collect();
            slots.push(
                calibrate_slot(
                    slot,
                    &good_scores,
                    &bad_scores,
                    slot.default_target_far(),
                    CONFORMAL_ALPHA,
                )
                .expect("slot calibrates"),
            );
        }
        let profile = GuardProfile {
            domain: domain(),
            slots,
            content_policy: default_content_policy(),
            provisional: false,
            corpus_hash: [0u8; 32],
            calibrated_ledger_seq: Some(1),
        };

        // Held-out populations: seeds NEVER used in calibration.
        let held_out_good: Vec<f32> = (0..40).map(|i| 0.50 + 0.0005 + i as f32 * 0.001).collect();
        let held_out_bad: Vec<f32> = (0..40).map(|i| 2.5 + i as f32 * 0.017).collect();

        let mut false_accepts = 0usize;
        for seed in &held_out_bad {
            let candidate = measure_symbol_slots(&symbol_input(*seed, dim)).unwrap();
            let report = check_candidate(&candidate, &profile, &region).unwrap();
            if report.combined.verdict == GuardVerdict::Accept {
                false_accepts += 1;
            }
        }
        let mut false_rejects = 0usize;
        for seed in &held_out_good {
            let candidate = measure_symbol_slots(&symbol_input(*seed, dim)).unwrap();
            let report = check_candidate(&candidate, &profile, &region).unwrap();
            if report.combined.verdict == GuardVerdict::Refuse {
                false_rejects += 1;
            }
        }
        let far = false_accepts as f32 / held_out_bad.len() as f32;
        let frr = false_rejects as f32 / held_out_good.len() as f32;
        // Published numbers (also recorded in the closing evidence): the guard
        // must not admit alien candidates (FAR low) and must not refuse
        // in-history good ones (FRR < 20%).
        assert!(far <= 0.05, "held-out FAR {far} exceeds the 0.05 gate");
        assert!(frr < 0.20, "held-out FRR {frr} exceeds the 20% gate");
        eprintln!("guard_roc_gate: held_out_far={far:.4} held_out_frr={frr:.4}");
    }
}
