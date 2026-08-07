//! L5 — latent (indirect) associations over the composite association graph (#1009).
//!
//! Every association layer that exists today materializes a pair *because direct
//! evidence for that pair exists*: L1 because CBM extracted an edge, L2 because
//! two slot vectors are close, L3 because two slots belong to one symbol, L4
//! because two series co-occurred. None of them can propose an association in the
//! **absence** of direct evidence.
//!
//! This module adds that layer, on Swanson's ABC model: when `A—B` and `B—C` are
//! both recorded and `A—C` is not, the absence of the direct link is exactly what
//! makes `A—C` worth surfacing. In the code domain the `A—C` hypothesis is the
//! hidden-coupling / duplicated-concept / missing-abstraction finding — the
//! incomplete-refactor class that blast radius structurally cannot reach, because
//! blast radius only walks edges that exist.
//!
//! # Why shared intermediaries must be weighted by rarity
//!
//! Raw shared-neighbour counting is unusable on a real code graph. Measured over
//! the persisted Astrolabe graph (96,721 nodes / 176,221 edges), seven `CALLS`
//! targets carry 2,587 edges between them — `CliError::usage` alone has in-degree
//! 526, yielding C(526,2) = 138,075 spurious pairs from a single intermediary.
//! Meanwhile 13,942 targets have in-degree 1 and carry no pairing signal at all.
//!
//! An intermediary's evidentiary value is therefore inverse to how many symbols
//! reach it, which is the same correction Swanson applies when he discards
//! over-broad B-terms ("hormone", "pressure", "lipid") and the same one the
//! link-prediction literature encodes as Adamic-Adar (`1/ln d`) and Resource
//! Allocation (`1/d`). Both are computed here, alongside Swanson's original
//! linking-term count, and intermediaries above a knob-declared breadth ceiling
//! are gated out **and counted** — never silently dropped (invariant 3).
//!
//! # What this layer claims
//!
//! Nothing, on its own. A latent pair is a *hypothesis*: an association the graph
//! implies but does not record. Every served pair is labeled `provisional`
//! (invariants 1 and 2) and carries the intermediaries that produced it, so the
//! caller can judge the evidence rather than trust a score.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result};

use crate::U64KnobDeclaration;
use crate::kernel_graph::IndexedGraph;

/// Schema tag for a latent-discovery report (open discovery and corpus sweep).
pub const LATENT_DISCOVERY_SCHEMA: &str = "astrolabe.latent_discovery.v1";
/// Schema tag for a closed-discovery explanation of one candidate pair.
pub const LATENT_EXPLANATION_SCHEMA: &str = "astrolabe.latent_explanation.v1";
/// Knob registry version for the latent-association gates.
pub const LATENT_KNOB_REGISTRY_VERSION: &str = "astro.kernel.latent_knobs.v1";

/// Knob: highest intermediary degree that still carries pairing evidence. An
/// intermediary above this is over-broad — it is gated out and disclosed.
pub const KNOB_MAX_INTERMEDIARY_DEGREE: &str = "kernel.latent.max_intermediary_degree";
/// Knob: fewest shared intermediaries a pair needs before it is reported.
pub const KNOB_MIN_SHARED_INTERMEDIARIES: &str = "kernel.latent.min_shared_intermediaries";
/// Knob: ceiling on candidate pairs a corpus sweep may materialize.
pub const KNOB_PAIR_BUDGET: &str = "kernel.latent.pair_budget";
/// Knob: how many ranked pairs a report serves.
pub const KNOB_TOP_K: &str = "kernel.latent.top_k";
/// Knob: how many per-pair intermediaries are listed as evidence.
pub const KNOB_LISTED_INTERMEDIARIES: &str = "kernel.latent.listed_intermediaries";

/// Refusal raised when a latent-discovery knob is outside its declared bounds.
pub const ASTRO_LATENT_KNOB_RANGE: &str = "ASTRO_LATENT_KNOB_RANGE";
/// Refusal raised when a seed/endpoint identity is not a node of the graph.
pub const ASTRO_LATENT_NODE_UNKNOWN: &str = "ASTRO_LATENT_NODE_UNKNOWN";
/// Refusal raised when a corpus sweep would materialize more candidate pairs
/// than the declared budget permits.
pub const ASTRO_LATENT_PAIR_BUDGET_EXCEEDED: &str = "ASTRO_LATENT_PAIR_BUDGET_EXCEEDED";

const SOURCE: &str = "docs/astrolabe-blueprint.md#07-the-association-weave";

/// The latent-association gates, registry-declared (invariant 4).
pub const LATENT_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: LATENT_KNOB_REGISTRY_VERSION,
        name: KNOB_MAX_INTERMEDIARY_DEGREE,
        default: 50,
        min: 2,
        max: 1_000_000,
        unit: "edges",
        source: SOURCE,
        rationale: "an intermediary reached by more symbols than this is over-broad and carries no pairing evidence — measured over the persisted Astrolabe graph, degree>50 covers 20 of 19,635 CALLS targets but 3,781 edges, and a single degree-526 target alone would emit 138,075 spurious pairs; replace with a per-repo measured breadth ceiling once latent-pair precision is benchmarked against co-change",
    },
    U64KnobDeclaration {
        registry_version: LATENT_KNOB_REGISTRY_VERSION,
        name: KNOB_MIN_SHARED_INTERMEDIARIES,
        default: 2,
        min: 1,
        max: 1024,
        unit: "intermediaries",
        source: SOURCE,
        rationale: "a pair joined through a single intermediary is a coincidence of one call site; requiring two independent linking symbols is the weakest non-trivial corroboration, matching Swanson's linking-term-count floor; replace with a measured precision floor once latent-pair outcomes are anchored",
    },
    U64KnobDeclaration {
        registry_version: LATENT_KNOB_REGISTRY_VERSION,
        name: KNOB_PAIR_BUDGET,
        default: 4_000_000,
        min: 1_024,
        max: 1_000_000_000,
        unit: "pairs",
        source: SOURCE,
        rationale: "ceiling on candidate pairs a corpus sweep materializes, so sweep cost stays bounded and declared rather than quadratic in a hub degree; exceeding it refuses with the breadth ceiling that would fit instead of silently truncating the ranking",
    },
    U64KnobDeclaration {
        registry_version: LATENT_KNOB_REGISTRY_VERSION,
        name: KNOB_TOP_K,
        default: 100,
        min: 1,
        max: 100_000,
        unit: "pairs",
        source: SOURCE,
        rationale: "how many ranked latent pairs a report serves; the pre-truncation pair count is always disclosed alongside so the cut is visible (invariant 3)",
    },
    U64KnobDeclaration {
        registry_version: LATENT_KNOB_REGISTRY_VERSION,
        name: KNOB_LISTED_INTERMEDIARIES,
        default: 8,
        min: 1,
        max: 1024,
        unit: "intermediaries",
        source: SOURCE,
        rationale: "how many of a pair's linking intermediaries are listed as evidence, highest rarity weight first; the pair's full shared count is always served alongside so the listing cut is visible",
    },
];

/// Which directed relation the shared intermediary is reached through.
///
/// The choice fixes both the expansion and the rarity denominator: an
/// intermediary's evidentiary value is inverse to how many symbols can reach it
/// *the same way*, so the degree used for weighting is always the degree of the
/// arc that made it shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LatentRelation {
    /// Shared successors: `A -> B <- C`. Rarity denominator is `B`'s in-degree.
    /// The "these two do the same work" signal.
    Coupling,
    /// Shared predecessors: `A <- B -> C`. Rarity denominator is `B`'s
    /// out-degree. The "these two are used by the same work" signal.
    CoCitation,
    /// Shared neighbours in either direction. Rarity denominator is `B`'s
    /// undirected degree.
    Undirected,
}

impl LatentRelation {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coupling => "coupling",
            Self::CoCitation => "co_citation",
            Self::Undirected => "undirected",
        }
    }

    /// Parses a wire name.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "coupling" => Some(Self::Coupling),
            "co_citation" => Some(Self::CoCitation),
            "undirected" => Some(Self::Undirected),
            _ => None,
        }
    }

    /// Intermediaries reachable from a node under this relation.
    fn expand<'g>(self, graph: &'g IndexedGraph, index: usize) -> &'g [usize] {
        match self {
            Self::Coupling => graph.out_neighbors(index),
            Self::CoCitation => graph.in_neighbors(index),
            Self::Undirected => graph.undirected_neighbors(index),
        }
    }

    /// Nodes that share an intermediary under this relation. This is the set the
    /// rarity denominator counts.
    fn sharers<'g>(self, graph: &'g IndexedGraph, intermediary: usize) -> &'g [usize] {
        match self {
            Self::Coupling => graph.in_neighbors(intermediary),
            Self::CoCitation => graph.out_neighbors(intermediary),
            Self::Undirected => graph.undirected_neighbors(intermediary),
        }
    }
}

/// Resolved latent-discovery gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatentConfig {
    /// Highest intermediary degree that still carries pairing evidence.
    pub max_intermediary_degree: u64,
    /// Fewest shared intermediaries a reported pair needs.
    pub min_shared_intermediaries: u64,
    /// Ceiling on candidate pairs a corpus sweep may materialize.
    pub pair_budget: u64,
    /// How many ranked pairs the report serves.
    pub top_k: u64,
    /// How many per-pair intermediaries are listed as evidence.
    pub listed_intermediaries: u64,
}

impl LatentConfig {
    /// Returns the registry-default gates.
    pub fn with_registry_defaults() -> Self {
        Self {
            max_intermediary_degree: knob_default(KNOB_MAX_INTERMEDIARY_DEGREE),
            min_shared_intermediaries: knob_default(KNOB_MIN_SHARED_INTERMEDIARIES),
            pair_budget: knob_default(KNOB_PAIR_BUDGET),
            top_k: knob_default(KNOB_TOP_K),
            listed_intermediaries: knob_default(KNOB_LISTED_INTERMEDIARIES),
        }
    }

    /// Validates every gate against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<()> {
        check_range(KNOB_MAX_INTERMEDIARY_DEGREE, self.max_intermediary_degree)?;
        check_range(
            KNOB_MIN_SHARED_INTERMEDIARIES,
            self.min_shared_intermediaries,
        )?;
        check_range(KNOB_PAIR_BUDGET, self.pair_budget)?;
        check_range(KNOB_TOP_K, self.top_k)?;
        check_range(KNOB_LISTED_INTERMEDIARIES, self.listed_intermediaries)?;
        Ok(())
    }
}

fn knob(name: &str) -> &'static U64KnobDeclaration {
    LATENT_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("latent knob is declared")
}

fn knob_default(name: &str) -> u64 {
    knob(name).default
}

fn check_range(name: &str, value: u64) -> Result<()> {
    let knob = knob(name);
    if value < knob.min || value > knob.max {
        return Err(DomainError::new(
            ASTRO_LATENT_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the latent-discovery gate within its registered bounds",
        ));
    }
    Ok(())
}

/// One linking intermediary: a `B` that both endpoints reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatentIntermediary {
    /// Identity of the intermediary symbol version.
    pub id: CxId,
    /// How many symbols reach it under the report's relation — the rarity
    /// denominator. Low is strong evidence; high is a hub.
    pub degree: u64,
    /// Resource-Allocation weight `1/degree`, in millionths.
    pub resource_allocation_micro: u64,
    /// Adamic-Adar weight `1/ln(degree)`, in millionths.
    pub adamic_adar_micro: u64,
}

/// One latent association: a pair the graph implies but does not record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatentPair {
    /// Lower endpoint identity (pair ownership is canonical: `a < c`).
    pub a: CxId,
    /// Higher endpoint identity.
    pub c: CxId,
    /// Swanson's linking-term count: how many intermediaries join the pair.
    pub shared_count: u64,
    /// Summed Resource-Allocation weight `Σ 1/degree(B)`, in millionths. The
    /// primary ranking key — it suppresses hubs hardest, which is what a sparse
    /// code graph needs.
    pub resource_allocation_micro: u64,
    /// Summed Adamic-Adar weight `Σ 1/ln(degree(B))`, in millionths.
    pub adamic_adar_micro: u64,
    /// The strongest linking intermediaries, rarest first, truncated to the
    /// listing gate. `shared_count` always discloses the full total.
    pub intermediaries: Vec<LatentIntermediary>,
}

/// What a latent-discovery report was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatentMode {
    /// Ranked targets reachable from one seed through shared intermediaries.
    OpenDiscovery,
    /// Ranked latent pairs across the whole graph.
    CorpusSweep,
}

impl LatentMode {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenDiscovery => "open_discovery",
            Self::CorpusSweep => "corpus_sweep",
        }
    }
}

/// Counts for every gate a candidate can be dropped by. Nothing is dropped
/// silently (invariant 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatentDisclosure {
    /// Intermediaries inspected before any gate.
    pub intermediaries_considered: u64,
    /// Intermediaries gated out as over-broad (degree above the ceiling).
    pub intermediaries_over_broad: u64,
    /// Intermediaries reached by fewer than two symbols, so unable to join a
    /// pair at all.
    pub intermediaries_unshared: u64,
    /// Candidate pairs suppressed because a direct association already exists —
    /// the novelty gate. These are *known* associations, not discoveries.
    pub pairs_direct_edge: u64,
    /// Distinct candidate pairs accumulated before the shared-count floor.
    pub pairs_accumulated: u64,
    /// Pairs dropped for carrying fewer intermediaries than the floor.
    pub pairs_below_min_shared: u64,
    /// Pairs dropped by the top-K cut.
    pub pairs_truncated: u64,
}

/// A ranked set of latent associations with every gate disclosed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatentDiscoveryReport {
    /// Report schema tag.
    pub schema: &'static str,
    /// Which query produced it.
    pub mode: LatentMode,
    /// Which relation the intermediaries were reached through.
    pub relation: LatentRelation,
    /// The gates in force.
    pub config: LatentConfig,
    /// Nodes in the source graph.
    pub node_count: usize,
    /// Seed identity, for open discovery.
    pub seed: Option<CxId>,
    /// Ranked pairs, strongest first. A total order, so the ranking is
    /// reproducible byte-for-byte across runs (invariant 5).
    pub pairs: Vec<LatentPair>,
    /// Per-gate drop counts.
    pub disclosure: LatentDisclosure,
    /// Freshness label.
    pub freshness: &'static str,
    /// Trust label. Always `provisional`: a latent pair is a hypothesis the
    /// graph implies, never an observed association (invariants 1 and 2).
    pub trust: &'static str,
}

/// The linking intermediaries that explain one candidate pair (closed discovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatentExplanation {
    /// Report schema tag.
    pub schema: &'static str,
    /// Which relation the intermediaries were reached through.
    pub relation: LatentRelation,
    /// The gates in force.
    pub config: LatentConfig,
    /// Lower endpoint identity.
    pub a: CxId,
    /// Higher endpoint identity.
    pub c: CxId,
    /// Whether a direct association already joins the endpoints. When `true`
    /// this is an explanation of a *known* association, not a discovery — the
    /// caller is told rather than refused.
    pub direct_edge_present: bool,
    /// Every linking intermediary that passed the breadth ceiling, rarest first.
    pub intermediaries: Vec<LatentIntermediary>,
    /// Swanson linking-term count.
    pub shared_count: u64,
    /// Summed Resource-Allocation weight, in millionths.
    pub resource_allocation_micro: u64,
    /// Summed Adamic-Adar weight, in millionths.
    pub adamic_adar_micro: u64,
    /// Per-gate drop counts.
    pub disclosure: LatentDisclosure,
    /// Freshness label.
    pub freshness: &'static str,
    /// Trust label — always `provisional`.
    pub trust: &'static str,
}

/// Accumulator for one candidate pair while a scan is in flight.
#[derive(Default)]
struct PairAccumulator {
    shared_count: u64,
    resource_allocation: f64,
    adamic_adar: f64,
    intermediaries: Vec<LatentIntermediary>,
}

/// Converts a weight to millionths. Deterministic: the summation order is fixed
/// by ascending node index, and the rounding is a single terminal operation.
fn micro(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    (value * 1_000_000.0).round() as u64
}

/// Rarity weights of one intermediary. `degree >= 2` always holds for an
/// intermediary that actually joins a pair, which keeps `ln(degree)` positive;
/// the guard makes that explicit rather than assumed.
fn rarity(degree: u64) -> (f64, f64) {
    let degree_f = degree as f64;
    let resource_allocation = if degree_f > 0.0 { 1.0 / degree_f } else { 0.0 };
    let log_degree = degree_f.ln();
    let adamic_adar = if log_degree > 0.0 {
        1.0 / log_degree
    } else {
        0.0
    };
    (resource_allocation, adamic_adar)
}

/// Whether a direct association already joins two nodes, in either direction.
/// The novelty gate is direction-agnostic: Swanson's condition is the absence of
/// *any* known direct relationship.
fn direct_edge(graph: &IndexedGraph, left: usize, right: usize) -> bool {
    graph
        .undirected_neighbors(left)
        .binary_search(&right)
        .is_ok()
}

fn resolve_node(graph: &IndexedGraph, id: CxId, role: &str) -> Result<usize> {
    graph.ids().binary_search(&id).map_err(|_| {
        DomainError::new(
            ASTRO_LATENT_NODE_UNKNOWN,
            format!(
                "latent discovery {role} {id} is not a node of the association graph"
            ),
            "pass an identity that exists in the persisted kernel-graph projection, or re-index the project so the symbol is present",
        )
    })
}

/// Total order over latent pairs: Resource-Allocation descending, then shared
/// count descending, then Adamic-Adar descending, then endpoint identities
/// ascending. Every key is an integer, so the order is exact and reproducible.
fn pair_order(left: &LatentPair, right: &LatentPair) -> Ordering {
    right
        .resource_allocation_micro
        .cmp(&left.resource_allocation_micro)
        .then_with(|| right.shared_count.cmp(&left.shared_count))
        .then_with(|| right.adamic_adar_micro.cmp(&left.adamic_adar_micro))
        .then_with(|| left.a.cmp(&right.a))
        .then_with(|| left.c.cmp(&right.c))
}

/// Total order over intermediaries: rarest (lowest degree) first, then identity.
fn intermediary_order(left: &LatentIntermediary, right: &LatentIntermediary) -> Ordering {
    left.degree
        .cmp(&right.degree)
        .then_with(|| left.id.cmp(&right.id))
}

fn finish_intermediaries(
    mut intermediaries: Vec<LatentIntermediary>,
    listed: u64,
) -> Vec<LatentIntermediary> {
    intermediaries.sort_by(intermediary_order);
    intermediaries.truncate(listed as usize);
    intermediaries
}

/// Open discovery: from one seed `A`, the ranked targets `C` that share
/// intermediaries with it and carry **no** direct association to it.
///
/// Cost is `Σ degree(B)` over the seed's own intermediaries, each bounded by the
/// breadth ceiling — so a seeded query is bounded by construction and needs no
/// pair budget.
pub fn latent_open_discovery(
    graph: &IndexedGraph,
    seed: CxId,
    relation: LatentRelation,
    config: &LatentConfig,
) -> Result<LatentDiscoveryReport> {
    config.validate()?;
    let seed_index = resolve_node(graph, seed, "seed")?;

    let mut disclosure = LatentDisclosure::default();
    let mut accumulators: BTreeMap<usize, PairAccumulator> = BTreeMap::new();

    for &intermediary in relation.expand(graph, seed_index) {
        if intermediary == seed_index {
            continue;
        }
        disclosure.intermediaries_considered += 1;
        let sharers = relation.sharers(graph, intermediary);
        let degree = sharers.len() as u64;
        if degree < 2 {
            disclosure.intermediaries_unshared += 1;
            continue;
        }
        if degree > config.max_intermediary_degree {
            disclosure.intermediaries_over_broad += 1;
            continue;
        }
        let (resource_allocation, adamic_adar) = rarity(degree);
        let intermediary_id = graph.id(intermediary);
        for &target in sharers {
            if target == seed_index {
                continue;
            }
            if direct_edge(graph, seed_index, target) {
                disclosure.pairs_direct_edge += 1;
                continue;
            }
            let entry = accumulators.entry(target).or_default();
            entry.shared_count += 1;
            entry.resource_allocation += resource_allocation;
            entry.adamic_adar += adamic_adar;
            entry.intermediaries.push(LatentIntermediary {
                id: intermediary_id,
                degree,
                resource_allocation_micro: micro(resource_allocation),
                adamic_adar_micro: micro(adamic_adar),
            });
        }
    }

    disclosure.pairs_accumulated = accumulators.len() as u64;
    let mut pairs = Vec::new();
    for (target, accumulator) in accumulators {
        if accumulator.shared_count < config.min_shared_intermediaries {
            disclosure.pairs_below_min_shared += 1;
            continue;
        }
        let target_id = graph.id(target);
        let (a, c) = if seed <= target_id {
            (seed, target_id)
        } else {
            (target_id, seed)
        };
        pairs.push(LatentPair {
            a,
            c,
            shared_count: accumulator.shared_count,
            resource_allocation_micro: micro(accumulator.resource_allocation),
            adamic_adar_micro: micro(accumulator.adamic_adar),
            intermediaries: finish_intermediaries(
                accumulator.intermediaries,
                config.listed_intermediaries,
            ),
        });
    }

    pairs.sort_by(pair_order);
    let before_top_k = pairs.len();
    pairs.truncate(config.top_k as usize);
    disclosure.pairs_truncated = (before_top_k - pairs.len()) as u64;

    Ok(LatentDiscoveryReport {
        schema: LATENT_DISCOVERY_SCHEMA,
        mode: LatentMode::OpenDiscovery,
        relation,
        config: *config,
        node_count: graph.len(),
        seed: Some(seed),
        pairs,
        disclosure,
        freshness: "fresh",
        trust: "provisional",
    })
}

/// Closed discovery: given two endpoints, the ranked linking intermediaries that
/// explain the connection between them.
///
/// Unlike open discovery this does not refuse an already-associated pair — it
/// reports `direct_edge_present` and serves the explanation, because "why are
/// these two related" is a legitimate question about a known association too.
pub fn latent_closed_discovery(
    graph: &IndexedGraph,
    left: CxId,
    right: CxId,
    relation: LatentRelation,
    config: &LatentConfig,
) -> Result<LatentExplanation> {
    config.validate()?;
    let left_index = resolve_node(graph, left, "endpoint")?;
    let right_index = resolve_node(graph, right, "endpoint")?;
    if left_index == right_index {
        return Err(DomainError::new(
            ASTRO_LATENT_NODE_UNKNOWN,
            format!("closed latent discovery needs two distinct endpoints, both were {left}"),
            "pass two different symbol identities",
        ));
    }

    let (a_index, c_index) = if left <= right {
        (left_index, right_index)
    } else {
        (right_index, left_index)
    };
    let (a, c) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };

    let mut disclosure = LatentDisclosure::default();
    let right_set = relation.expand(graph, c_index);
    let mut intermediaries = Vec::new();
    let mut resource_allocation_total = 0.0_f64;
    let mut adamic_adar_total = 0.0_f64;

    for &intermediary in relation.expand(graph, a_index) {
        if intermediary == a_index || intermediary == c_index {
            continue;
        }
        if right_set.binary_search(&intermediary).is_err() {
            continue;
        }
        disclosure.intermediaries_considered += 1;
        let degree = relation.sharers(graph, intermediary).len() as u64;
        if degree < 2 {
            disclosure.intermediaries_unshared += 1;
            continue;
        }
        if degree > config.max_intermediary_degree {
            disclosure.intermediaries_over_broad += 1;
            continue;
        }
        let (resource_allocation, adamic_adar) = rarity(degree);
        resource_allocation_total += resource_allocation;
        adamic_adar_total += adamic_adar;
        intermediaries.push(LatentIntermediary {
            id: graph.id(intermediary),
            degree,
            resource_allocation_micro: micro(resource_allocation),
            adamic_adar_micro: micro(adamic_adar),
        });
    }

    let shared_count = intermediaries.len() as u64;
    disclosure.pairs_accumulated = u64::from(shared_count > 0);
    intermediaries.sort_by(intermediary_order);

    Ok(LatentExplanation {
        schema: LATENT_EXPLANATION_SCHEMA,
        relation,
        config: *config,
        a,
        c,
        direct_edge_present: direct_edge(graph, a_index, c_index),
        intermediaries,
        shared_count,
        resource_allocation_micro: micro(resource_allocation_total),
        adamic_adar_micro: micro(adamic_adar_total),
        disclosure,
        freshness: "fresh",
        trust: "provisional",
    })
}

/// Counts the candidate pairs a corpus sweep would materialize, and the
/// intermediaries each gate would drop. Runs in `O(nodes)` — cheap enough to
/// decide admission before committing to the sweep itself.
pub fn latent_sweep_pair_cost(
    graph: &IndexedGraph,
    relation: LatentRelation,
    config: &LatentConfig,
) -> Result<(u128, LatentDisclosure)> {
    config.validate()?;
    let mut disclosure = LatentDisclosure::default();
    let mut pair_cost = 0_u128;
    for index in 0..graph.len() {
        disclosure.intermediaries_considered += 1;
        let degree = relation.sharers(graph, index).len() as u64;
        if degree < 2 {
            disclosure.intermediaries_unshared += 1;
            continue;
        }
        if degree > config.max_intermediary_degree {
            disclosure.intermediaries_over_broad += 1;
            continue;
        }
        let degree = degree as u128;
        pair_cost += degree * (degree - 1) / 2;
    }
    Ok((pair_cost, disclosure))
}

/// Corpus sweep: the ranked latent pairs across the whole graph.
///
/// Refuses rather than truncates when the sweep would exceed the declared pair
/// budget, and the refusal names the breadth ceiling that would fit — a silently
/// truncated ranking would misreport the top of the list, which is the only part
/// anyone reads.
pub fn latent_corpus_sweep(
    graph: &IndexedGraph,
    relation: LatentRelation,
    config: &LatentConfig,
) -> Result<LatentDiscoveryReport> {
    config.validate()?;
    let (pair_cost, mut disclosure) = latent_sweep_pair_cost(graph, relation, config)?;
    if pair_cost > u128::from(config.pair_budget) {
        return Err(DomainError::new(
            ASTRO_LATENT_PAIR_BUDGET_EXCEEDED,
            format!(
                "corpus sweep over {} nodes would materialize {pair_cost} candidate pairs, above the declared budget of {} ({}={}, {} intermediaries already gated out as over-broad)",
                graph.len(),
                config.pair_budget,
                KNOB_MAX_INTERMEDIARY_DEGREE,
                config.max_intermediary_degree,
                disclosure.intermediaries_over_broad,
            ),
            "lower kernel.latent.max_intermediary_degree until the sweep fits, raise kernel.latent.pair_budget within its declared bounds, or run seeded open discovery instead — a seeded query is bounded by construction",
        ));
    }

    let mut accumulators: BTreeMap<(usize, usize), PairAccumulator> = BTreeMap::new();
    for index in 0..graph.len() {
        let sharers = relation.sharers(graph, index);
        let degree = sharers.len() as u64;
        if degree < 2 || degree > config.max_intermediary_degree {
            continue;
        }
        let (resource_allocation, adamic_adar) = rarity(degree);
        let intermediary_id = graph.id(index);
        for (offset, &left) in sharers.iter().enumerate() {
            if left == index {
                continue;
            }
            for &right in &sharers[offset + 1..] {
                if right == index || left == right {
                    continue;
                }
                if direct_edge(graph, left, right) {
                    disclosure.pairs_direct_edge += 1;
                    continue;
                }
                let entry = accumulators.entry((left, right)).or_default();
                entry.shared_count += 1;
                entry.resource_allocation += resource_allocation;
                entry.adamic_adar += adamic_adar;
                entry.intermediaries.push(LatentIntermediary {
                    id: intermediary_id,
                    degree,
                    resource_allocation_micro: micro(resource_allocation),
                    adamic_adar_micro: micro(adamic_adar),
                });
            }
        }
    }

    disclosure.pairs_accumulated = accumulators.len() as u64;
    let mut pairs = Vec::new();
    for ((left, right), accumulator) in accumulators {
        if accumulator.shared_count < config.min_shared_intermediaries {
            disclosure.pairs_below_min_shared += 1;
            continue;
        }
        let left_id = graph.id(left);
        let right_id = graph.id(right);
        let (a, c) = if left_id <= right_id {
            (left_id, right_id)
        } else {
            (right_id, left_id)
        };
        pairs.push(LatentPair {
            a,
            c,
            shared_count: accumulator.shared_count,
            resource_allocation_micro: micro(accumulator.resource_allocation),
            adamic_adar_micro: micro(accumulator.adamic_adar),
            intermediaries: finish_intermediaries(
                accumulator.intermediaries,
                config.listed_intermediaries,
            ),
        });
    }

    pairs.sort_by(pair_order);
    let before_top_k = pairs.len();
    pairs.truncate(config.top_k as usize);
    disclosure.pairs_truncated = (before_top_k - pairs.len()) as u64;

    Ok(LatentDiscoveryReport {
        schema: LATENT_DISCOVERY_SCHEMA,
        mode: LatentMode::CorpusSweep,
        relation,
        config: *config,
        node_count: graph.len(),
        seed: None,
        pairs,
        disclosure,
        freshness: "fresh",
        trust: "provisional",
    })
}

/// Canonical, integer-only bytes for a latent-discovery report. Byte-identical
/// across runs (invariant 5): a recompute re-serializes to the same bytes, which
/// is the FSV readback anchor for the served product.
pub fn latent_discovery_artifact_bytes(report: &LatentDiscoveryReport) -> Vec<u8> {
    let mut out = String::new();
    push_field(&mut out, "schema", report.schema);
    push_field(&mut out, "mode", report.mode.as_str());
    push_field(&mut out, "relation", report.relation.as_str());
    push_config(&mut out, &report.config);
    push_field(&mut out, "node_count", &report.node_count.to_string());
    push_field(
        &mut out,
        "seed",
        &report
            .seed
            .map(|id| hex_lower(id.as_bytes()))
            .unwrap_or_else(|| "-".to_string()),
    );
    push_disclosure(&mut out, &report.disclosure);
    push_field(&mut out, "pair_count", &report.pairs.len().to_string());
    for pair in &report.pairs {
        push_pair(&mut out, pair);
    }
    out.into_bytes()
}

/// Canonical, integer-only bytes for a closed-discovery explanation.
pub fn latent_explanation_artifact_bytes(explanation: &LatentExplanation) -> Vec<u8> {
    let mut out = String::new();
    push_field(&mut out, "schema", explanation.schema);
    push_field(&mut out, "relation", explanation.relation.as_str());
    push_config(&mut out, &explanation.config);
    push_field(&mut out, "a", &hex_lower(explanation.a.as_bytes()));
    push_field(&mut out, "c", &hex_lower(explanation.c.as_bytes()));
    push_field(
        &mut out,
        "direct_edge_present",
        if explanation.direct_edge_present {
            "1"
        } else {
            "0"
        },
    );
    push_field(
        &mut out,
        "shared_count",
        &explanation.shared_count.to_string(),
    );
    push_field(
        &mut out,
        "resource_allocation_micro",
        &explanation.resource_allocation_micro.to_string(),
    );
    push_field(
        &mut out,
        "adamic_adar_micro",
        &explanation.adamic_adar_micro.to_string(),
    );
    push_disclosure(&mut out, &explanation.disclosure);
    for intermediary in &explanation.intermediaries {
        push_intermediary(&mut out, intermediary);
    }
    out.into_bytes()
}

fn push_field(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}

fn push_config(out: &mut String, config: &LatentConfig) {
    push_field(
        out,
        "max_intermediary_degree",
        &config.max_intermediary_degree.to_string(),
    );
    push_field(
        out,
        "min_shared_intermediaries",
        &config.min_shared_intermediaries.to_string(),
    );
    push_field(out, "pair_budget", &config.pair_budget.to_string());
    push_field(out, "top_k", &config.top_k.to_string());
    push_field(
        out,
        "listed_intermediaries",
        &config.listed_intermediaries.to_string(),
    );
}

fn push_disclosure(out: &mut String, disclosure: &LatentDisclosure) {
    push_field(
        out,
        "intermediaries_considered",
        &disclosure.intermediaries_considered.to_string(),
    );
    push_field(
        out,
        "intermediaries_over_broad",
        &disclosure.intermediaries_over_broad.to_string(),
    );
    push_field(
        out,
        "intermediaries_unshared",
        &disclosure.intermediaries_unshared.to_string(),
    );
    push_field(
        out,
        "pairs_direct_edge",
        &disclosure.pairs_direct_edge.to_string(),
    );
    push_field(
        out,
        "pairs_accumulated",
        &disclosure.pairs_accumulated.to_string(),
    );
    push_field(
        out,
        "pairs_below_min_shared",
        &disclosure.pairs_below_min_shared.to_string(),
    );
    push_field(
        out,
        "pairs_truncated",
        &disclosure.pairs_truncated.to_string(),
    );
}

fn push_pair(out: &mut String, pair: &LatentPair) {
    out.push_str("pair\t");
    out.push_str(&hex_lower(pair.a.as_bytes()));
    out.push('\t');
    out.push_str(&hex_lower(pair.c.as_bytes()));
    out.push('\t');
    out.push_str(&pair.shared_count.to_string());
    out.push('\t');
    out.push_str(&pair.resource_allocation_micro.to_string());
    out.push('\t');
    out.push_str(&pair.adamic_adar_micro.to_string());
    out.push('\n');
    for intermediary in &pair.intermediaries {
        push_intermediary(out, intermediary);
    }
}

fn push_intermediary(out: &mut String, intermediary: &LatentIntermediary) {
    out.push_str("via\t");
    out.push_str(&hex_lower(intermediary.id.as_bytes()));
    out.push('\t');
    out.push_str(&intermediary.degree.to_string());
    out.push('\t');
    out.push_str(&intermediary.resource_allocation_micro.to_string());
    out.push('\t');
    out.push_str(&intermediary.adamic_adar_micro.to_string());
    out.push('\n');
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}
