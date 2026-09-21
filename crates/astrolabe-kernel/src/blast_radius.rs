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
/// Refusal raised when a complete reach aggregate cannot be represented.
pub const ASTRO_CHANGE_REACH_ARITHMETIC: &str = "ASTRO_CHANGE_REACH_ARITHMETIC";

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

const DEFAULT_REACH_ATTENUATION_PERMILLE: u64 = 900;
const DEFAULT_REACH_MAX_HOPS: u64 = 4;
const DEFAULT_REACH_MIN_PERMILLE: u64 = 1;
const DEFAULT_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE: u64 = 700;
const DEFAULT_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE: u64 = 300;

/// All change-reach knobs with their declared bounds.
pub const CHANGE_REACH_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_ATTENUATION_PERMILLE,
        default: DEFAULT_REACH_ATTENUATION_PERMILLE,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "per-hop reach attenuation; pinned at 0.9 (900 permille) so reach = product(edge_weight) * 0.9^hop, matching the answer-path engine (blueprint 09 §4)",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_MAX_HOPS,
        default: DEFAULT_REACH_MAX_HOPS,
        min: 1,
        max: 16,
        unit: "hops",
        source: SOURCE,
        rationale: "reach hop budget from the changed symbol before the blast-radius walk stops",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_MIN_PERMILLE,
        default: DEFAULT_REACH_MIN_PERMILLE,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "reach floor; a node reached below this attenuated permille adds no measurable blast signal and is pruned",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE,
        default: DEFAULT_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "weight of gap exposure (reach landing on ungrounded kernel members) in the risk elevation; the blueprint's here-be-dragons axis dominates blast risk",
    },
    U64KnobDeclaration {
        registry_version: CHANGE_REACH_KNOB_REGISTRY_VERSION,
        name: KNOB_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE,
        default: DEFAULT_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE,
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
            attenuation_permille: DEFAULT_REACH_ATTENUATION_PERMILLE,
            max_hops: DEFAULT_REACH_MAX_HOPS,
            min_reach_permille: DEFAULT_REACH_MIN_PERMILLE,
            gap_exposure_weight_permille: DEFAULT_REACH_GAP_EXPOSURE_WEIGHT_PERMILLE,
            kernel_membership_bonus_permille: DEFAULT_REACH_KERNEL_MEMBERSHIP_BONUS_PERMILLE,
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

fn check_range(name: &str, value: u64) -> Result<()> {
    let knob = CHANGE_REACH_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .ok_or_else(|| {
            DomainError::new(
                ASTRO_CHANGE_REACH_KNOB_RANGE,
                format!("change-reach knob {name:?} has no registry declaration"),
                "repair the static change-reach knob registry before measuring reach",
            )
        })?;
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

/// Canonical reach index compiled once from one immutable graph projection.
///
/// This ordered-map implementation constructs in
/// `O(N log N + E log N)` time and `O(N + E)` space. Each changed-symbol
/// measurement then reuses the same node roster and strongest-edge adjacency
/// instead of rebuilding them, so a request covering `M` impacted symbols pays
/// one graph compilation plus the actually traversed hop-bounded work per
/// symbol. Production CSR replacement of these trees remains a tracked cost
/// optimization; no fixture run is cited as production evidence (#1064 PC-41).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChangeReachGraph {
    node_ids: BTreeSet<CxId>,
    out: BTreeMap<CxId, BTreeMap<CxId, u64>>,
}

impl PreparedChangeReachGraph {
    /// Compiles an independently supplied canonical node/edge roster. Duplicate
    /// nodes, missing endpoints, and invalid weights refuse rather than being
    /// collapsed or clamped.
    pub fn from_rosters<N, E>(nodes: N, edges: E) -> Result<Self>
    where
        N: IntoIterator<Item = CxId>,
        E: IntoIterator<Item = (CxId, CxId, f32)>,
    {
        let mut node_ids = BTreeSet::new();
        for id in nodes {
            if !node_ids.insert(id) {
                return Err(DomainError::new(
                    ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL,
                    format!("change-reach graph contains duplicate node {id}"),
                    "rebuild the canonical projection with exactly one row per CxId",
                ));
            }
        }
        let mut out: BTreeMap<CxId, BTreeMap<CxId, u64>> = BTreeMap::new();
        for (src, dst, weight) in edges {
            if !node_ids.contains(&src) || !node_ids.contains(&dst) {
                return Err(DomainError::new(
                    ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL,
                    format!("change-reach edge {src}->{dst} references a missing endpoint"),
                    "repair and rebuild the canonical graph projection before measuring reach",
                ));
            }
            if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
                return Err(DomainError::new(
                    ASTRO_CHANGE_REACH_KNOB_RANGE,
                    format!("change-reach edge {src}->{dst} has invalid weight {weight}"),
                    "repair the persisted projection edge weight into the finite [0,1] interval",
                ));
            }
            if src == dst {
                continue;
            }
            let weight = weight_to_permille(weight);
            let slot = out.entry(src).or_default().entry(dst).or_insert(0);
            if weight > *slot {
                *slot = weight;
            }
        }
        Ok(Self { node_ids, out })
    }

    /// Compiles one validated [`KernelGraph`].
    pub fn from_kernel_graph(graph: &KernelGraph) -> Result<Self> {
        Self::from_rosters(
            graph.nodes().iter().map(|node| node.id),
            graph
                .edges()
                .iter()
                .map(|edge| (edge.src, edge.dst, edge.weight)),
        )
    }

    /// Measures one changed symbol through this already-compiled graph.
    pub fn measure(
        &self,
        from_id: CxId,
        kernel_members: &BTreeSet<CxId>,
        gap_members: &BTreeSet<CxId>,
        config: &ReachConfig,
    ) -> Result<ChangeReach> {
        change_reach_prepared(self, from_id, kernel_members, gap_members, config)
    }
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
    let prepared = PreparedChangeReachGraph::from_kernel_graph(graph)?;
    change_reach_prepared(&prepared, from_id, kernel_members, gap_members, config)
}

/// Measures reach using a graph compiled once by
/// [`PreparedChangeReachGraph::from_rosters`].
pub fn change_reach_prepared(
    graph: &PreparedChangeReachGraph,
    from_id: CxId,
    kernel_members: &BTreeSet<CxId>,
    gap_members: &BTreeSet<CxId>,
    config: &ReachConfig,
) -> Result<ChangeReach> {
    config.validate()?;

    if !graph.node_ids.contains(&from_id) {
        return Err(DomainError::new(
            ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL,
            format!("changed symbol {from_id} has no node in the kernel graph"),
            "map the changed file/symbol to a live kernel-graph symbol version before measuring its blast radius",
        ));
    }

    // Best reach per node, hop-bounded frontier propagation. reach[from] = 1000
    // and never re-emitted (a change does not blast into itself).
    let mut best: BTreeMap<CxId, (u64, u64)> = BTreeMap::new(); // id -> (reach, hop)
    let mut frontier: Vec<(CxId, u64)> = vec![(from_id, REACH_PERMILLE_SCALE)];

    for hop in 1..=config.max_hops {
        let mut next: BTreeMap<CxId, u64> = BTreeMap::new();
        for (src, src_reach) in &frontier {
            let Some(neighbors) = graph.out.get(src) else {
                continue;
            };
            for (dst, edge_weight) in neighbors {
                if *dst == from_id {
                    continue;
                }
                // reach = src_reach · edge_weight/1000 · attenuation/1000.
                let via_edge = src_reach.checked_mul(*edge_weight).ok_or_else(|| {
                    DomainError::new(
                        ASTRO_CHANGE_REACH_ARITHMETIC,
                        format!(
                            "reach multiplication overflowed for source {src}: {src_reach} * {edge_weight}"
                        ),
                        "repair the bounded permille graph weights and retry the exact reach measurement",
                    )
                })? / REACH_PERMILLE_SCALE;
                let reach = via_edge
                    .checked_mul(config.attenuation_permille)
                    .ok_or_else(|| {
                        DomainError::new(
                            ASTRO_CHANGE_REACH_ARITHMETIC,
                            format!(
                                "reach attenuation overflowed for source {src}: {via_edge} * {}",
                                config.attenuation_permille
                            ),
                            "repair the bounded reach-knob registry and retry the exact measurement",
                        )
                    })?
                    / REACH_PERMILLE_SCALE;
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

    let checked_sum = |label: &str, values: &mut dyn Iterator<Item = u64>| {
        values
            .try_fold(0_u64, |sum, value| sum.checked_add(value))
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_CHANGE_REACH_ARITHMETIC,
                    format!("change-reach {label} is not representable as u64"),
                    "reduce the admitted graph/reach roster or widen the declared persisted aggregate type",
                )
            })
    };
    let reach_mass_permille = checked_sum(
        "total reach mass",
        &mut reached.iter().map(|node| node.reach_permille),
    )?;
    let kernel_member_reach_permille = checked_sum(
        "kernel-member reach mass",
        &mut reached
            .iter()
            .filter(|node| node.kernel_member)
            .map(|node| node.reach_permille),
    )?;
    let gap_reach_permille = checked_sum(
        "gap reach mass",
        &mut reached
            .iter()
            .filter(|node| node.gap)
            .map(|node| node.reach_permille),
    )?;

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
/// probability elevated by the graph blast radius, bounded to `[base, 1000]`.
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
    if grounded_consequence_permille > REACH_PERMILLE_SCALE {
        return Err(DomainError::new(
            ASTRO_CHANGE_REACH_ARITHMETIC,
            format!(
                "grounded consequence {grounded_consequence_permille} exceeds the {REACH_PERMILLE_SCALE}-permille scale"
            ),
            "supply the exact measured grounded consequence without clamping",
        ));
    }
    let base = grounded_consequence_permille;

    // The complete gap reach is an additive mass and may legitimately exceed
    // one unit across several nodes. The model's declared exposure transform is
    // therefore `min(total_mass, 1000)`, not a repair of malformed input.
    let gap_exposure_permille = reach.gap_reach_permille.min(REACH_PERMILLE_SCALE);
    let gap_term = gap_exposure_permille
        .checked_mul(config.gap_exposure_weight_permille)
        .ok_or_else(|| {
            DomainError::new(
                ASTRO_CHANGE_REACH_ARITHMETIC,
                "gap-exposure weighting overflowed",
                "repair the bounded permille measurement and knob registry",
            )
        })?
        / REACH_PERMILLE_SCALE;
    let membership_term = if reach.from_is_kernel_member {
        config.kernel_membership_bonus_permille
    } else {
        0
    };
    let elevation_permille = gap_term
        .checked_add(membership_term)
        .ok_or_else(|| {
            DomainError::new(
                ASTRO_CHANGE_REACH_ARITHMETIC,
                "reach elevation addition overflowed",
                "repair the bounded permille measurement and knob registry",
            )
        })?
        .min(REACH_PERMILLE_SCALE);

    let headroom = REACH_PERMILLE_SCALE - base;
    let elevated = headroom.checked_mul(elevation_permille).ok_or_else(|| {
        DomainError::new(
            ASTRO_CHANGE_REACH_ARITHMETIC,
            "reach risk multiplication overflowed",
            "repair the bounded permille measurement and knob registry",
        )
    })? / REACH_PERMILLE_SCALE;
    let risk_permille = base.checked_add(elevated).ok_or_else(|| {
        DomainError::new(
            ASTRO_CHANGE_REACH_ARITHMETIC,
            "reach risk addition overflowed",
            "repair the bounded permille measurement and knob registry",
        )
    })?;

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
    let mut out = Vec::new();
    write_change_reach_artifact(reach, |bytes| out.extend_from_slice(bytes));
    out
}

/// BLAKE3 of the exact canonical change-reach bytes, computed in one streaming
/// pass without retaining a second corpus-sized serialization buffer.
pub fn change_reach_artifact_blake3(reach: &ChangeReach) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    write_change_reach_artifact(reach, |bytes| {
        hasher.update(bytes);
    });
    *hasher.finalize().as_bytes()
}

fn write_change_reach_artifact(reach: &ChangeReach, mut write: impl FnMut(&[u8])) {
    write(b"schema=");
    write(reach.schema.as_bytes());
    write(b"\nfrom=");
    write_cx_hex(reach.from_id, &mut write);
    write(b"\nfrom_kernel_member=");
    write(if reach.from_is_kernel_member {
        b"1"
    } else {
        b"0"
    });
    write(b"\nfrom_gap=");
    write(if reach.from_is_gap { b"1" } else { b"0" });
    write(b"\nreached_count=");
    write_usize_decimal(reach.reached_count, &mut write);
    write(b"\nreach_mass=");
    write_u64_decimal(reach.reach_mass_permille, &mut write);
    write(b"\nkernel_member_reach=");
    write_u64_decimal(reach.kernel_member_reach_permille, &mut write);
    write(b"\ngap_reach=");
    write_u64_decimal(reach.gap_reach_permille, &mut write);
    write(b"\n");
    for node in &reach.reached {
        write(b"reached\t");
        write_cx_hex(node.id, &mut write);
        write(b"\t");
        write_u64_decimal(node.hop, &mut write);
        write(b"\t");
        write_u64_decimal(node.reach_permille, &mut write);
        write(b"\t");
        write(if node.kernel_member {
            b"member"
        } else {
            b"external"
        });
        write(b"\t");
        write(if node.gap { b"gap" } else { b"grounded" });
        write(b"\n");
    }
}

fn write_cx_hex(id: CxId, write: &mut impl FnMut(&[u8])) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 32];
    for (index, byte) in id.as_bytes().iter().copied().enumerate() {
        encoded[index * 2] = HEX[(byte >> 4) as usize];
        encoded[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    write(&encoded);
}

fn write_u64_decimal(mut value: u64, write: &mut impl FnMut(&[u8])) {
    let mut encoded = [0u8; 20];
    let mut cursor = encoded.len();
    loop {
        cursor -= 1;
        encoded[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write(&encoded[cursor..]);
}

fn write_usize_decimal(mut value: usize, write: &mut impl FnMut(&[u8])) {
    let mut encoded = [0u8; 20];
    let mut cursor = encoded.len();
    loop {
        cursor -= 1;
        encoded[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write(&encoded[cursor..]);
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
