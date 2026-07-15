//! Change blast-radius reach through the kernel graph (#366, blueprint 09 §4/§5).
//!
//! `detect_changes` grounds per-symbol risk in an oracle consequence
//! probability (#339/#52), but that number is blind to *where the change fans
//! out*: a one-line edit to a feedback-vertex-set cut symbol whose association
//! edges reach a cluster of unverified kernel members is far riskier than the
//! same edit on a leaf. This module measures that fan-out — the answer-path
//! *reach* of a changed symbol through the kernel graph's measured association
//! edges — and folds it into risk.
//!
//! The reach walk mirrors the [`crate::answer`] engine: it propagates outward
//! from the changed symbol along directed weighted edges, attenuating each hop by
//! the pinned per-hop factor (`0.9`), so a node reached over the strongest path is
//! scored `reach = product(edge_weight) · 0.9^hops` in permille. Every value that
//! reaches the served risk is an integer permille, so the reach term is
//! byte-identical across runs and worker counts (invariant 5), and every knob is
//! registry-declared (invariant 4).
//!
//! Risk composition (`reach_risk_permille`) is fail-closed monotone: the graph
//! reach can only *raise* the oracle's grounded consequence probability toward
//! `1000`, never lower it and never exceed `1000`. The elevation is driven by
//! **gap exposure** (reach mass landing on ungrounded kernel members — the change
//! propagating into unverified territory) and **kernel membership** (the changed
//! symbol is itself a load-bearing kernel member). When the persisted kernel
//! artifact is absent the caller skips this term entirely and serves today's
//! per-symbol risk unchanged (the server labels that path); this module never
//! fabricates a graph.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result};

use crate::U64KnobDeclaration;
use crate::answer::weight_to_permille;
use crate::kernel_graph::KernelGraph;

/// Schema tag for a served change-reach (blast-radius) term.
pub const CHANGE_REACH_SCHEMA: &str = "astrolabe.change_reach.v1";
/// Knob registry version for the change-reach knobs.
pub const CHANGE_REACH_KNOB_REGISTRY_VERSION: &str = "astro.kernel.change_reach_knobs.v1";

/// Full permille scale: `1000` permille denotes `1.0`.
pub const REACH_PERMILLE_SCALE: u64 = 1_000;

/// Refusal raised when a change-reach knob is outside its declared bounds.
pub const ASTRO_CHANGE_REACH_KNOB_RANGE: &str = "ASTRO_CHANGE_REACH_KNOB_RANGE";
/// Refusal raised when the changed symbol has no node row in the kernel graph.
pub const ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL: &str = "ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL";

const SOURCE: &str = "docs/astrolabe-blueprint.md#09-the-kernel--context-engine";

/// Knob name: per-hop reach attenuation in permille (pinned `0.9`).
pub const KNOB_REACH_ATTENUATION_PERMILLE: &str = "kernel.reach.hop_attenuation_permille";
/// Knob name: maximum reach hop budget from the changed symbol.
pub const KNOB_REACH_MAX_HOPS: &str = "kernel.reach.max_hops";
/// Knob name: minimum reach (permille) below which a reached node is pruned.
pub const KNOB_REACH_MIN_PERMILLE: &str = "kernel.reach.min_reach_permille";
/// Knob name: weight (permille) of gap exposure in the risk elevation.
pub const KNOB_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE: &str =
    "kernel.reach.gap_exposure_weight_permille";
/// Knob name: risk-elevation bonus (permille) when the changed symbol is itself a
/// kernel member.
pub const KNOB_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE: &str =
    "kernel.reach.kernel_membership_bonus_permille";

/// All change-reach knobs with their declared bounds.
pub const CHANGE_REACH_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_ATTENUATION_PERMILLE,
        default: 900,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "per-hop reach attenuation; pinned at 0.9 (900 permille) so reach = product(edge_weight) * 0.9^hop, matching the answer-path engine (blueprint 09 §4)",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_MAX_HOPS,
        default: 4,
        min: 1,
        max: 16,
        unit: "hops",
        source: SOURCE,
        rationale: "reach hop budget from the changed symbol before the blast-radius walk stops",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_MIN_PERMILLE,
        default: 1,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "reach floor; a node reached below this attenuated permille adds no measurable blast signal and is pruned",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE,
        default: 700,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "weight of gap exposure (reach landing on ungrounded kernel members) in the risk elevation; the blueprint's here-be-dragons axis dominates blast risk",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE,
        default: 300,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "risk-elevation bonus when the changed symbol is itself a kernel member (a load-bearing cut symbol the change originates at)",
    },
];

/// Fully resolved change-reach knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReachConfig {
    /// Per-hop attenuation in permille (pinned `900` = `0.9`).
    pub attenuation_permille: u64,
    /// Maximum hop budget.
    pub max_hops: u64,
    /// Minimum reach in permille below which a reached node is pruned.
    pub min_reach_permille: u64,
    /// Weight of gap exposure in the risk elevation (permille).
    pub gap_exposure_weight_permille: u64,
    /// Kernel-membership risk bonus (permille).
    pub kernel_membership_bonus_permille: u64,
}

impl ReachConfig {
    /// Returns the registry-default reach configuration.
    pub fn with_registry_defaults() -> Self {
        Self {
            attenuation_permille: knob_default(KNOB_REACH_ATTENUATION_PERMILLE),
            max_hops: knob_default(KNOB_REACH_MAX_HOPS),
            min_reach_permille: knob_default(KNOB_REACH_MIN_PERMILLE),
            gap_exposure_weight_permille: knob_default(KNOB_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE),
            kernel_membership_bonus_permille: knob_default(
                KNOB_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE,
            ),
        }
    }

    /// Validates every knob against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<()> {
        check_range(KNOB_REACH_ATTENUATION_PERMILLE, self.attenuation_permille)?;
        check_range(KNOB_REACH_MAX_HOPS, self.max_hops)?;
        check_range(KNOB_REACH_MIN_PERMILLE, self.min_reach_permille)?;
        check_range(
            KNOB_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE,
            self.gap_exposure_weight_permille,
        )?;
        check_range(
            KNOB_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE,
            self.kernel_membership_bonus_permille,
        )?;
        Ok(())
    }
}

fn knob_default(name: &str) -> u64 {
    CHANGE_REACH_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("change-reach knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<()> {
    let knob = CHANGE_REACH_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("change-reach knob is declared");
    if value < knob.min || value > knob.max {
        return Err(DomainError::new(
            ASTRO_CHANGE_REACH_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the change-reach knob within its registered bounds",
        ));
    }
    Ok(())
}

/// One node reached from the changed symbol, with its attenuated reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReachedNode {
    /// Symbol-version identity of the reached node.
    pub id: CxId,
    /// Hop distance from the changed symbol along its strongest reaching path.
    pub hop: u64,
    /// Attenuated reach in permille = `product(edge_weight) · 0.9^hop` over the
    /// strongest path (always in `[min_reach, 1000]`).
    pub reach_permille: u64,
    /// Whether the reached node is a kernel member.
    pub kernel_member: bool,
    /// Whether the reached node is an ungrounded kernel member (a gap).
    pub gap: bool,
}

/// The measured blast radius of a changed symbol through the kernel graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeReach {
    /// Reach term schema tag.
    pub schema: &'static str,
    /// Knob registry version in force.
    pub knob_registry_version: &'static str,
    /// The changed symbol the reach was measured from.
    pub from_id: CxId,
    /// Whether the changed symbol is itself a kernel member.
    pub from_is_kernel_member: bool,
    /// Whether the changed symbol is itself an ungrounded kernel member (a gap).
    pub from_is_gap: bool,
    /// Reached nodes (excluding the changed symbol), ascending by `CxId`.
    pub reached: Vec<ReachedNode>,
    /// Number of distinct nodes reached within the hop budget.
    pub reached_count: usize,
    /// Total reach mass in permille (sum of reached-node reach).
    pub reach_mass_permille: u64,
    /// Reach mass landing on kernel members (permille).
    pub kernel_member_reach_permille: u64,
    /// Reach mass landing on ungrounded kernel members — gap exposure (permille).
    pub gap_reach_permille: u64,
}

/// Measures the blast-radius reach of a changed symbol through the kernel graph.
///
/// Propagates outward from `from_id` along directed weighted edges up to the hop
/// budget, scoring each reached node by the strongest attenuated path
/// `reach = product(edge_weight/1000) · 0.9^hop`, pruning any node whose best
/// reach falls below the reach floor. `kernel_members` and `gap_members` (the
/// ungrounded subset, `gap_members ⊆ kernel_members`) come from the persisted
/// kernel artifact; they classify each reached node so the risk composition can
/// weight gap exposure. Refuses fail-closed
/// ([`ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL`]) when `from_id` has no node row — the
/// caller must map a changed file to a live kernel-graph symbol first.
pub fn change_reach(
    graph: &KernelGraph,
    from_id: CxId,
    kernel_members: &BTreeSet<CxId>,
    gap_members: &BTreeSet<CxId>,
    config: &ReachConfig,
) -> Result<ChangeReach> {
    config.validate()?;

    let node_ids: BTreeSet<CxId> = graph.nodes().iter().map(|node| node.id).collect();
    if !node_ids.contains(&from_id) {
        return Err(DomainError::new(
            ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL,
            format!("changed symbol {from_id} has no node in the kernel graph"),
            "map the changed file/symbol to a live kernel-graph symbol version before measuring its blast radius",
        ));
    }

    // Out-adjacency, strongest edge per (src, dst): parallel edges collapse to the
    // maximum weight so the reach uses the strongest association between two nodes.
    let mut out: BTreeMap<CxId, BTreeMap<CxId, u64>> = BTreeMap::new();
    for edge in graph.edges() {
        if edge.src == edge.dst {
            continue; // a self-loop never carries reach outward
        }
        let weight = weight_to_permille(edge.weight);
        let slot = out
            .entry(edge.src)
            .or_default()
            .entry(edge.dst)
            .or_insert(0);
        if weight > *slot {
            *slot = weight;
        }
    }

    // Best reach per node, hop-bounded frontier propagation. reach[from] = 1000
    // and never re-emitted (a change does not blast into itself).
    let mut best: BTreeMap<CxId, (u64, u64)> = BTreeMap::new(); // id -> (reach, hop)
    let mut frontier: Vec<(CxId, u64)> = vec![(from_id, REACH_PERMILLE_SCALE)];

    for hop in 1..=config.max_hops {
        let mut next: BTreeMap<CxId, u64> = BTreeMap::new();
        for (src, src_reach) in &frontier {
            let Some(neighbors) = out.get(src) else {
                continue;
            };
            for (dst, edge_weight) in neighbors {
                if *dst == from_id {
                    continue;
                }
                // reach = src_reach · edge_weight/1000 · attenuation/1000.
                let via_edge = src_reach.saturating_mul(*edge_weight) / REACH_PERMILLE_SCALE;
                let reach =
                    via_edge.saturating_mul(config.attenuation_permille) / REACH_PERMILLE_SCALE;
                if reach < config.min_reach_permille {
                    continue;
                }
                if best.get(dst).map(|(r, _)| *r).unwrap_or(0) >= reach {
                    continue;
                }
                let slot = next.entry(*dst).or_insert(0);
                if reach > *slot {
                    *slot = reach;
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next
            .into_iter()
            .filter_map(|(id, reach)| {
                let improved = best.get(&id).map(|(r, _)| reach > *r).unwrap_or(true);
                if improved {
                    best.insert(id, (reach, hop));
                    Some((id, reach))
                } else {
                    None
                }
            })
            .collect();
    }

    let mut reached: Vec<ReachedNode> = best
        .into_iter()
        .map(|(id, (reach_permille, hop))| ReachedNode {
            id,
            hop,
            reach_permille,
            kernel_member: kernel_members.contains(&id),
            gap: gap_members.contains(&id),
        })
        .collect();
    reached.sort_by_key(|node| node.id);

    let reach_mass_permille = reached.iter().map(|node| node.reach_permille).sum();
    let kernel_member_reach_permille = reached
        .iter()
        .filter(|node| node.kernel_member)
        .map(|node| node.reach_permille)
        .sum();
    let gap_reach_permille = reached
        .iter()
        .filter(|node| node.gap)
        .map(|node| node.reach_permille)
        .sum();

    Ok(ChangeReach {
        schema: CHANGE_REACH_SCHEMA,
        knob_registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        from_id,
        from_is_kernel_member: kernel_members.contains(&from_id),
        from_is_gap: gap_members.contains(&from_id),
        reached_count: reached.len(),
        reach_mass_permille,
        kernel_member_reach_permille,
        gap_reach_permille,
        reached,
    })
}

/// The composed risk permille for a change: the oracle's grounded consequence
/// probability elevated by the graph blast radius, clamped to `[base, 1000]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReachRisk {
    /// The oracle-grounded per-symbol consequence probability (permille) fed in.
    pub grounded_consequence_permille: u64,
    /// Gap exposure used in the elevation (permille, capped at 1000).
    pub gap_exposure_permille: u64,
    /// Whether the kernel-membership bonus was applied.
    pub kernel_membership_applied: bool,
    /// The blended elevation factor (permille, capped at 1000).
    pub elevation_permille: u64,
    /// The final composed risk (permille), always in `[base, 1000]`.
    pub risk_permille: u64,
}

/// Composes the final blast-radius risk from the oracle consequence probability
/// and the measured kernel-graph reach.
///
/// Fail-closed monotone: the reach can only raise risk toward `1000`, never lower
/// the oracle base and never exceed `1000`. The elevation blends **gap exposure**
/// (reach mass on ungrounded kernel members, capped to permille) at
/// `gap_exposure_weight_permille` with a **kernel-membership** bonus when the
/// changed symbol is itself a kernel member; the blend is capped at `1000`, then
/// `risk = base + floor((1000 - base) · blend / 1000)`.
pub fn reach_risk_permille(
    grounded_consequence_permille: u64,
    reach: &ChangeReach,
    config: &ReachConfig,
) -> Result<ReachRisk> {
    config.validate()?;
    let base = grounded_consequence_permille.min(REACH_PERMILLE_SCALE);

    let gap_exposure_permille = reach.gap_reach_permille.min(REACH_PERMILLE_SCALE);
    let gap_term = gap_exposure_permille.saturating_mul(config.gap_exposure_weight_permille)
        / REACH_PERMILLE_SCALE;
    let membership_term = if reach.from_is_kernel_member {
        config.kernel_membership_bonus_permille
    } else {
        0
    };
    let elevation_permille = gap_term
        .saturating_add(membership_term)
        .min(REACH_PERMILLE_SCALE);

    let headroom = REACH_PERMILLE_SCALE - base;
    let risk_permille = base + headroom.saturating_mul(elevation_permille) / REACH_PERMILLE_SCALE;

    Ok(ReachRisk {
        grounded_consequence_permille: base,
        gap_exposure_permille,
        kernel_membership_applied: reach.from_is_kernel_member,
        elevation_permille,
        risk_permille,
    })
}

/// Canonical, integer-only bytes for a change-reach term. Byte-identical across
/// runs (invariant 5): a recompute re-serializes to the same bytes, the FSV
/// readback anchor for the served reach component.
pub fn change_reach_artifact_bytes(reach: &ChangeReach) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(reach.schema);
    out.push('\n');
    out.push_str("from=");
    out.push_str(&hex_lower(reach.from_id.as_bytes()));
    out.push('\n');
    out.push_str("from_kernel_member=");
    out.push_str(if reach.from_is_kernel_member {
        "1"
    } else {
        "0"
    });
    out.push('\n');
    out.push_str("from_gap=");
    out.push_str(if reach.from_is_gap { "1" } else { "0" });
    out.push('\n');
    out.push_str("reached_count=");
    out.push_str(&reach.reached_count.to_string());
    out.push('\n');
    out.push_str("reach_mass=");
    out.push_str(&reach.reach_mass_permille.to_string());
    out.push('\n');
    out.push_str("kernel_member_reach=");
    out.push_str(&reach.kernel_member_reach_permille.to_string());
    out.push('\n');
    out.push_str("gap_reach=");
    out.push_str(&reach.gap_reach_permille.to_string());
    out.push('\n');
    for node in &reach.reached {
        out.push_str("reached\t");
        out.push_str(&hex_lower(node.id.as_bytes()));
        out.push('\t');
        out.push_str(&node.hop.to_string());
        out.push('\t');
        out.push_str(&node.reach_permille.to_string());
        out.push('\t');
        out.push_str(if node.kernel_member {
            "member"
        } else {
            "external"
        });
        out.push('\t');
        out.push_str(if node.gap { "gap" } else { "grounded" });
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
