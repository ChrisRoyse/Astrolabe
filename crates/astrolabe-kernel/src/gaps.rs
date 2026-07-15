//! Grounding-gap report and coverage-vs-importance quadrant (#39).
//!
//! The "here be dragons" map (blueprint 09 §5, capability 5.7): kernel members
//! that sit far from any Trusted anchor — no anchor within the build's
//! groundedness hop limit (default 3 hops) — ranked by `kernel_score × churn`.
//! A member that is both *important* (high kernel score) and *unverified* (no
//! nearby anchor) is the single most actionable QA target, so the gap report is
//! the ranked list of those members and the coverage-vs-importance quadrant is
//! the scatter that isolates the "critical & unverified" quadrant feeding
//! readiness and the UI overlay (capability 5.12).
//!
//! Both artifacts are pure functions of a persisted [`KernelArtifact`]: gap
//! membership is exactly `!KernelMember::grounded` (the build already computed
//! Trusted-anchor reachability at `config.groundedness_hop_limit`), the
//! importance axis is `KernelMember::score_permille`, the anchor-density axis is
//! `KernelMember::groundedness_permille`, and churn is `KernelMember::frequency`
//! (= `change_count + 1`). Every quadrant split is a registry-declared knob
//! (invariant 4); every ordering is total and deterministic; and the canonical
//! artifact bytes are integer-only so a recompute is byte-identical (invariant
//! 5).

use std::cmp::Ordering;

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result};

use crate::U64KnobDeclaration;
use crate::kernel_build::KernelArtifact;

/// Schema tag for a grounding-gap report.
pub const GROUNDING_GAP_SCHEMA: &str = "astrolabe.grounding_gap_report.v1";
/// Schema tag for a coverage-vs-importance quadrant.
pub const COVERAGE_QUADRANT_SCHEMA: &str = "astrolabe.coverage_importance_quadrant.v1";
/// Knob registry version for the gap-quadrant split thresholds.
pub const GAP_QUADRANT_KNOB_REGISTRY_VERSION: &str = "astro.kernel.gap_quadrant_knobs.v1";

/// Knob: kernel-score permille at or above which a member is *important*.
pub const KNOB_IMPORTANCE_THRESHOLD: &str = "kernel.gap.importance_threshold_permille";
/// Knob: anchor-density (groundedness) permille at or above which a member is
/// *covered* (verified enough by anchor proximity).
pub const KNOB_ANCHOR_DENSITY_THRESHOLD: &str = "kernel.gap.anchor_density_threshold_permille";

/// Refusal raised when a gap-quadrant knob is outside its declared bounds.
pub const ASTRO_GAP_QUADRANT_KNOB_RANGE: &str = "ASTRO_GAP_QUADRANT_KNOB_RANGE";

const SOURCE: &str = "docs/astrolabe-blueprint.md#09-the-kernel--context-engine";

/// The gap-quadrant split thresholds, registry-declared (invariant 4).
pub const GAP_QUADRANT_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: GAP_QUADRANT_KNOB_REGISTRY_VERSION,
        name: KNOB_IMPORTANCE_THRESHOLD,
        default: 500,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "kernel-score permille splitting the importance axis of the coverage-vs-importance quadrant; a member at or above is 'critical', feeding the critical-and-unverified QA quadrant",
    },
    U64KnobDeclaration {
        registry_version: GAP_QUADRANT_KNOB_REGISTRY_VERSION,
        name: KNOB_ANCHOR_DENSITY_THRESHOLD,
        default: 500,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "groundedness (anchor-density) permille splitting the coverage axis; below this a member is 'unverified' — too far from a Trusted anchor to be QA-covered",
    },
];

/// Resolved gap-quadrant split configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuadrantConfig {
    /// Kernel-score permille at or above which a member is important.
    pub importance_threshold_permille: u64,
    /// Anchor-density permille at or above which a member is covered.
    pub anchor_density_threshold_permille: u64,
}

impl QuadrantConfig {
    /// Returns the registry-default split configuration.
    pub fn with_registry_defaults() -> Self {
        Self {
            importance_threshold_permille: knob_default(KNOB_IMPORTANCE_THRESHOLD),
            anchor_density_threshold_permille: knob_default(KNOB_ANCHOR_DENSITY_THRESHOLD),
        }
    }

    /// Validates every threshold against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<()> {
        check_range(
            KNOB_IMPORTANCE_THRESHOLD,
            self.importance_threshold_permille,
        )?;
        check_range(
            KNOB_ANCHOR_DENSITY_THRESHOLD,
            self.anchor_density_threshold_permille,
        )?;
        Ok(())
    }
}

fn knob_default(name: &str) -> u64 {
    GAP_QUADRANT_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("gap quadrant knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<()> {
    let knob = GAP_QUADRANT_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("gap quadrant knob is declared");
    if value < knob.min || value > knob.max {
        return Err(DomainError::new(
            ASTRO_GAP_QUADRANT_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the gap quadrant threshold within its registered bounds",
        ));
    }
    Ok(())
}

/// One kernel member with no Trusted anchor within the groundedness hop limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroundingGap {
    /// Symbol-version identity of the ungrounded kernel member.
    pub id: CxId,
    /// Kernel-score permille (importance).
    pub kernel_score_permille: u64,
    /// Churn = `change_count + 1` (the member frequency).
    pub churn: u64,
    /// Rank key = `kernel_score_permille × churn`, widened so the product never
    /// overflows (score ≤ 1000, churn ≤ u64::MAX).
    pub rank_score: u128,
    /// Anchor-density permille (groundedness) this member reached — always below
    /// the reachability floor for a gap, but surfaced so the caller sees how far
    /// off the map it is.
    pub groundedness_permille: u64,
    /// Whether the member came from the feedback-vertex-set core (a structural
    /// cut vertex the change is most likely to fan out through).
    pub in_fvs: bool,
}

/// The ranked grounding-gap report over a persisted kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundingGapReport {
    /// Report schema tag.
    pub schema: &'static str,
    /// Scope the source kernel was built for.
    pub scope_id: String,
    /// Groundedness hop limit the source build used (the boundary: a member with
    /// a Trusted anchor at exactly this hop count is grounded and excluded; one
    /// hop further is a gap).
    pub hop_limit: u64,
    /// Whether any Trusted anchor exists in scope at all. When `false` every
    /// member is a gap (the whole kernel is anchor-ungrounded).
    pub has_trusted_anchor: bool,
    /// Total kernel members considered.
    pub member_count: usize,
    /// Number of gap members.
    pub gap_count: usize,
    /// Gaps, ranked by `kernel_score × churn` descending, `CxId` ascending on a
    /// tie — a total order, so the ranking is deterministic.
    pub gaps: Vec<GroundingGap>,
    /// Freshness label.
    pub freshness: &'static str,
    /// Trust label — always provisional: a gap is by definition unverified.
    pub trust: &'static str,
}

/// Builds the grounding-gap report from a persisted kernel artifact.
///
/// A gap is exactly a kernel member whose `grounded` flag is `false` — the build
/// pipeline already computed Trusted-anchor reachability at
/// `config.groundedness_hop_limit`, so gap membership is pinned to that hop
/// boundary with no recomputation. Gaps are ranked by `kernel_score × churn`
/// (blueprint 09 §5): the members that are both important and hot are the most
/// urgent to anchor.
pub fn grounding_gap_report(artifact: &KernelArtifact) -> GroundingGapReport {
    let hop_limit = artifact.config.groundedness_hop_limit;
    let mut gaps: Vec<GroundingGap> = artifact
        .members
        .iter()
        .filter(|member| !member.grounded)
        .map(|member| GroundingGap {
            id: member.id,
            kernel_score_permille: member.score_permille,
            churn: member.frequency,
            rank_score: (member.score_permille as u128) * (member.frequency as u128),
            groundedness_permille: member.groundedness_permille,
            in_fvs: member.in_fvs,
        })
        .collect();
    gaps.sort_by(gap_rank);

    GroundingGapReport {
        schema: GROUNDING_GAP_SCHEMA,
        scope_id: artifact.scope_id.clone(),
        hop_limit,
        has_trusted_anchor: artifact.anchor_grounded,
        member_count: artifact.members.len(),
        gap_count: gaps.len(),
        gaps,
        freshness: "fresh",
        trust: "provisional",
    }
}

/// Total order over gaps: `kernel_score × churn` descending, `CxId` ascending on
/// a tie.
fn gap_rank(left: &GroundingGap, right: &GroundingGap) -> Ordering {
    right
        .rank_score
        .cmp(&left.rank_score)
        .then_with(|| left.id.cmp(&right.id))
}

/// The four quadrants of the coverage-vs-importance plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapQuadrant {
    /// Important and unverified — the "here be dragons" QA quadrant.
    CriticalUnverified,
    /// Important and covered — load-bearing and anchored.
    CriticalCovered,
    /// Peripheral and unverified — untested but low-importance.
    PeripheralUnverified,
    /// Peripheral and covered — low-importance and anchored.
    PeripheralCovered,
}

impl GapQuadrant {
    /// A stable machine label for the quadrant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CriticalUnverified => "critical_unverified",
            Self::CriticalCovered => "critical_covered",
            Self::PeripheralUnverified => "peripheral_unverified",
            Self::PeripheralCovered => "peripheral_covered",
        }
    }

    /// A deterministic ordinal used to group quadrant points; the dragons
    /// quadrant sorts first so the most actionable rows lead the scatter.
    fn ordinal(self) -> u8 {
        match self {
            Self::CriticalUnverified => 0,
            Self::CriticalCovered => 1,
            Self::PeripheralUnverified => 2,
            Self::PeripheralCovered => 3,
        }
    }
}

/// One kernel member placed on the coverage-vs-importance plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuadrantPoint {
    /// Symbol-version identity.
    pub id: CxId,
    /// Importance axis: kernel-score permille.
    pub kernel_score_permille: u64,
    /// Coverage axis: anchor-density (groundedness) permille.
    pub anchor_density_permille: u64,
    /// Churn = `change_count + 1`.
    pub churn: u64,
    /// Whether a Trusted anchor is within the hop limit.
    pub grounded: bool,
    /// The quadrant this member falls in.
    pub quadrant: GapQuadrant,
}

/// The coverage-vs-importance quadrant scatter over a persisted kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageImportanceQuadrant {
    /// Quadrant schema tag.
    pub schema: &'static str,
    /// Scope the source kernel was built for.
    pub scope_id: String,
    /// The split thresholds in force.
    pub config: QuadrantConfig,
    /// Whether any Trusted anchor exists in scope.
    pub has_trusted_anchor: bool,
    /// Total kernel members placed.
    pub member_count: usize,
    /// Count in the critical-and-unverified (dragons) quadrant.
    pub critical_unverified_count: usize,
    /// Count in the critical-and-covered quadrant.
    pub critical_covered_count: usize,
    /// Count in the peripheral-and-unverified quadrant.
    pub peripheral_unverified_count: usize,
    /// Count in the peripheral-and-covered quadrant.
    pub peripheral_covered_count: usize,
    /// Every member placed, ordered by (quadrant ordinal, `kernel_score × churn`
    /// descending, `CxId` ascending) — a total order.
    pub points: Vec<QuadrantPoint>,
    /// Freshness label.
    pub freshness: &'static str,
    /// Trust label — verified when the scope has a Trusted anchor (the coverage
    /// axis is meaningful), provisional otherwise.
    pub trust: &'static str,
}

impl CoverageImportanceQuadrant {
    /// The critical-and-unverified members, in scatter order — the exact set that
    /// feeds readiness and the UI "here be dragons" overlay.
    pub fn critical_unverified(&self) -> impl Iterator<Item = &QuadrantPoint> {
        self.points
            .iter()
            .filter(|point| point.quadrant == GapQuadrant::CriticalUnverified)
    }
}

/// Classifies a member into a quadrant from its importance and anchor-density.
///
/// A member is *important* when its kernel score is at or above the importance
/// threshold, and *covered* when its anchor-density is at or above the density
/// threshold. The thresholds are the registry-declared split knobs.
pub fn classify_quadrant(
    kernel_score_permille: u64,
    anchor_density_permille: u64,
    config: &QuadrantConfig,
) -> GapQuadrant {
    let important = kernel_score_permille >= config.importance_threshold_permille;
    let covered = anchor_density_permille >= config.anchor_density_threshold_permille;
    match (important, covered) {
        (true, false) => GapQuadrant::CriticalUnverified,
        (true, true) => GapQuadrant::CriticalCovered,
        (false, false) => GapQuadrant::PeripheralUnverified,
        (false, true) => GapQuadrant::PeripheralCovered,
    }
}

/// Builds the coverage-vs-importance quadrant from a persisted kernel artifact.
///
/// Fails closed when a split threshold is out of bounds. Each member is placed by
/// its kernel score (importance) and groundedness permille (anchor density); the
/// four quadrant counts and the ordered scatter are pure functions of the
/// persisted member rows, so an independent recompute reproduces the artifact
/// byte-for-byte.
pub fn coverage_importance_quadrant(
    artifact: &KernelArtifact,
    config: &QuadrantConfig,
) -> Result<CoverageImportanceQuadrant> {
    config.validate()?;

    let mut points: Vec<QuadrantPoint> = artifact
        .members
        .iter()
        .map(|member| {
            let quadrant =
                classify_quadrant(member.score_permille, member.groundedness_permille, config);
            QuadrantPoint {
                id: member.id,
                kernel_score_permille: member.score_permille,
                anchor_density_permille: member.groundedness_permille,
                churn: member.frequency,
                grounded: member.grounded,
                quadrant,
            }
        })
        .collect();
    points.sort_by(quadrant_rank);

    let count_in = |quadrant: GapQuadrant| {
        points
            .iter()
            .filter(|point| point.quadrant == quadrant)
            .count()
    };
    let critical_unverified_count = count_in(GapQuadrant::CriticalUnverified);
    let critical_covered_count = count_in(GapQuadrant::CriticalCovered);
    let peripheral_unverified_count = count_in(GapQuadrant::PeripheralUnverified);
    let peripheral_covered_count = count_in(GapQuadrant::PeripheralCovered);

    Ok(CoverageImportanceQuadrant {
        schema: COVERAGE_QUADRANT_SCHEMA,
        scope_id: artifact.scope_id.clone(),
        config: *config,
        has_trusted_anchor: artifact.anchor_grounded,
        member_count: artifact.members.len(),
        critical_unverified_count,
        critical_covered_count,
        peripheral_unverified_count,
        peripheral_covered_count,
        points,
        freshness: "fresh",
        trust: if artifact.anchor_grounded {
            "verified"
        } else {
            "provisional"
        },
    })
}

/// Total order over quadrant points: quadrant ordinal ascending (dragons first),
/// then `kernel_score × churn` descending, then `CxId` ascending.
fn quadrant_rank(left: &QuadrantPoint, right: &QuadrantPoint) -> Ordering {
    let left_rank = (left.kernel_score_permille as u128) * (left.churn as u128);
    let right_rank = (right.kernel_score_permille as u128) * (right.churn as u128);
    left.quadrant
        .ordinal()
        .cmp(&right.quadrant.ordinal())
        .then_with(|| right_rank.cmp(&left_rank))
        .then_with(|| left.id.cmp(&right.id))
}

/// Canonical, integer-only bytes for a grounding-gap report. Byte-identical
/// across runs (invariant 5): a recompute of the report re-serializes to the
/// same bytes, which is the FSV readback anchor for the served product.
pub fn grounding_gap_report_artifact_bytes(report: &GroundingGapReport) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(report.schema);
    out.push('\n');
    out.push_str("scope=");
    out.push_str(&report.scope_id);
    out.push('\n');
    out.push_str("hop_limit=");
    out.push_str(&report.hop_limit.to_string());
    out.push('\n');
    out.push_str("has_trusted_anchor=");
    out.push_str(if report.has_trusted_anchor { "1" } else { "0" });
    out.push('\n');
    out.push_str("member_count=");
    out.push_str(&report.member_count.to_string());
    out.push('\n');
    out.push_str("gap_count=");
    out.push_str(&report.gap_count.to_string());
    out.push('\n');
    for gap in &report.gaps {
        out.push_str("gap\t");
        out.push_str(&hex_lower(gap.id.as_bytes()));
        out.push('\t');
        out.push_str(&gap.kernel_score_permille.to_string());
        out.push('\t');
        out.push_str(&gap.churn.to_string());
        out.push('\t');
        out.push_str(&gap.rank_score.to_string());
        out.push('\t');
        out.push_str(&gap.groundedness_permille.to_string());
        out.push('\t');
        out.push_str(if gap.in_fvs { "fvs" } else { "support" });
        out.push('\n');
    }
    out.into_bytes()
}

/// Canonical, integer-only bytes for a coverage-vs-importance quadrant.
pub fn coverage_importance_quadrant_artifact_bytes(
    quadrant: &CoverageImportanceQuadrant,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(quadrant.schema);
    out.push('\n');
    out.push_str("scope=");
    out.push_str(&quadrant.scope_id);
    out.push('\n');
    out.push_str("importance_threshold=");
    out.push_str(&quadrant.config.importance_threshold_permille.to_string());
    out.push('\n');
    out.push_str("anchor_density_threshold=");
    out.push_str(
        &quadrant
            .config
            .anchor_density_threshold_permille
            .to_string(),
    );
    out.push('\n');
    out.push_str("member_count=");
    out.push_str(&quadrant.member_count.to_string());
    out.push('\n');
    out.push_str("critical_unverified=");
    out.push_str(&quadrant.critical_unverified_count.to_string());
    out.push('\n');
    out.push_str("critical_covered=");
    out.push_str(&quadrant.critical_covered_count.to_string());
    out.push('\n');
    out.push_str("peripheral_unverified=");
    out.push_str(&quadrant.peripheral_unverified_count.to_string());
    out.push('\n');
    out.push_str("peripheral_covered=");
    out.push_str(&quadrant.peripheral_covered_count.to_string());
    out.push('\n');
    for point in &quadrant.points {
        out.push_str("point\t");
        out.push_str(&hex_lower(point.id.as_bytes()));
        out.push('\t');
        out.push_str(point.quadrant.as_str());
        out.push('\t');
        out.push_str(&point.kernel_score_permille.to_string());
        out.push('\t');
        out.push_str(&point.anchor_density_permille.to_string());
        out.push('\t');
        out.push_str(&point.churn.to_string());
        out.push('\t');
        out.push_str(if point.grounded { "grounded" } else { "gap" });
        out.push('\n');
    }
    out.into_bytes()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}
