//! Incremental kernel rebuild and hierarchical region kernels (#38).
//!
//! A [`GraphDelta`] describes a change to the kernel graph. A topology-preserving
//! delta (edge-weight and node-frequency changes) is served by [`rebuild_dirty`]
//! reusing the cached betweenness vector — betweenness, degree, and SCC structure
//! are all topology-only, so the cached values are exactly what a fresh build
//! would produce. The current implementation still rebuilds the complete
//! artifact; affected SCCs are reported only as diagnostics and are never
//! misreported as the amount of work executed.
//! A structural delta (node/edge add/remove that shifts SCC structure) escalates
//! to a full rebuild. For hierarchical monorepo kernels, [`build_region_graph`]
//! folds packages into a region graph whose kernel drives drill-down.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::calyx::{CxId, content_address};
use astrolabe_domain::{DomainError, Result};

use crate::kernel_build::{
    BetweennessCache, KernelArtifact, KernelBuildConfig, build_kernel,
    build_kernel_reusing_betweenness,
};
use crate::kernel_graph::{KernelGraph, KernelGraphEdge, KernelGraphNode};
use crate::scc::all_strongly_connected_components;

/// Refusal raised when a declared incremental delta is ambiguous, unknown, or
/// inconsistent with the graph generation it claims to describe.
pub const ASTRO_KERNEL_DELTA_INVALID: &str = "ASTRO_KERNEL_DELTA_INVALID";
/// Refusal raised when the region-folding callback cannot produce a complete,
/// unambiguous region assignment for the already-validated graph.
pub const ASTRO_KERNEL_REGION_GRAPH_INVALID: &str = "ASTRO_KERNEL_REGION_GRAPH_INVALID";

/// A change to a kernel graph between two builds.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GraphDelta {
    /// Node frequency updates `(node, new_frequency)`.
    pub frequency_changes: Vec<(CxId, u64)>,
    /// Edge weight updates `(src, dst, new_weight)` — topology is preserved.
    pub weight_changes: Vec<(CxId, CxId, f32)>,
    /// `true` when nodes or edges were added/removed such that SCC structure can
    /// shift; forces a full rebuild.
    pub structural: bool,
}

impl GraphDelta {
    /// Whether this delta preserves topology (SCC structure, degree,
    /// betweenness) and can therefore reuse cached betweenness.
    pub fn is_topology_preserving(&self) -> bool {
        !self.structural
    }

    /// Applies frequency and weight changes to `graph`, returning the updated
    /// graph. Only valid for topology-preserving deltas; a structural change is
    /// supplied by the caller as an already-updated graph.
    pub fn apply(&self, graph: &KernelGraph) -> Result<KernelGraph> {
        if self.structural {
            return Err(delta_error(
                "apply was called for structural=true; node/edge topology edits are not representable by the frequency/weight-only delta",
                "supply the fully rebuilt graph directly to rebuild_dirty for a structural generation",
            ));
        }
        let node_ids = graph
            .nodes()
            .iter()
            .map(|node| node.id)
            .collect::<BTreeSet<_>>();
        let edge_ids = graph
            .edges()
            .iter()
            .map(|edge| (edge.src, edge.dst))
            .collect::<BTreeSet<_>>();
        let mut freq = BTreeMap::new();
        for &(id, frequency) in &self.frequency_changes {
            if !node_ids.contains(&id) {
                return Err(delta_error(
                    format!("frequency delta names unknown node {id}"),
                    "derive the delta from the exact prior graph identity and include only existing node IDs",
                ));
            }
            if frequency == 0 {
                return Err(delta_error(
                    format!("frequency delta for node {id} is zero"),
                    "supply the positive change_count-plus-one value persisted by the source generation",
                ));
            }
            if freq.insert(id, frequency).is_some() {
                return Err(delta_error(
                    format!("frequency delta names node {id} more than once"),
                    "emit one canonical frequency update per node; last-write-wins collapse is forbidden",
                ));
            }
        }
        let mut weight = BTreeMap::new();
        for &(src, dst, new_weight) in &self.weight_changes {
            if !edge_ids.contains(&(src, dst)) {
                return Err(delta_error(
                    format!("weight delta names unknown directed edge {src} -> {dst}"),
                    "derive the delta from the exact prior topology and mark structural=true when an edge is added or removed",
                ));
            }
            if !new_weight.is_finite() || !(0.0..=1.0).contains(&new_weight) {
                return Err(delta_error(
                    format!(
                        "weight delta for edge {src} -> {dst} is outside finite [0,1]: {new_weight}"
                    ),
                    "supply the exact finite projected edge weight without coercion",
                ));
            }
            if weight.insert((src, dst), new_weight).is_some() {
                return Err(delta_error(
                    format!("weight delta names directed edge {src} -> {dst} more than once"),
                    "emit one canonical weight update per directed endpoint pair; last-write-wins collapse is forbidden",
                ));
            }
        }
        let nodes = graph
            .nodes()
            .iter()
            .map(|node| {
                let frequency = freq.get(&node.id).copied().unwrap_or(node.frequency);
                KernelGraphNode::new(node.id, frequency, node.anchor_trust)
            })
            .collect::<Vec<_>>();
        let edges = graph
            .edges()
            .iter()
            .map(|edge| {
                let w = weight
                    .get(&(edge.src, edge.dst))
                    .copied()
                    .unwrap_or(edge.weight);
                KernelGraphEdge::new(edge.src, edge.dst, w)
            })
            .collect::<Vec<_>>();
        KernelGraph::new(nodes, edges)
    }

    fn validate_applied_to(&self, graph: &KernelGraph) -> Result<()> {
        if self.structural {
            if !self.frequency_changes.is_empty() || !self.weight_changes.is_empty() {
                return Err(delta_error(
                    format!(
                        "structural delta must carry no frequency/weight patch rows because the caller supplies the complete replacement graph: frequency_rows={} weight_rows={}",
                        self.frequency_changes.len(),
                        self.weight_changes.len(),
                    ),
                    "submit either one closed topology-preserving patch roster or structural=true with the complete replacement graph, never both",
                ));
            }
            return Ok(());
        }
        let mut frequency_by_id = BTreeMap::new();
        for node in graph.nodes() {
            frequency_by_id.insert(node.id, node.frequency);
        }
        let mut seen_frequency = BTreeSet::new();
        for &(id, expected) in &self.frequency_changes {
            if !seen_frequency.insert(id) {
                return Err(delta_error(
                    format!("frequency delta names node {id} more than once"),
                    "emit one canonical frequency update per node",
                ));
            }
            let observed = frequency_by_id.get(&id).copied().ok_or_else(|| {
                delta_error(
                    format!("frequency delta names unknown node {id}"),
                    "bind the delta and rebuilt graph to the same canonical node roster",
                )
            })?;
            if expected == 0 || observed != expected {
                return Err(delta_error(
                    format!(
                        "frequency delta/application mismatch for node {id}: expected={expected}, observed={observed}"
                    ),
                    "apply every declared delta exactly once before requesting cache reuse",
                ));
            }
        }

        let mut weights_by_edge = BTreeMap::<(CxId, CxId), Vec<u32>>::new();
        for edge in graph.edges() {
            weights_by_edge
                .entry((edge.src, edge.dst))
                .or_default()
                .push(edge.weight.to_bits());
        }
        let mut seen_weight = BTreeSet::new();
        for &(src, dst, expected) in &self.weight_changes {
            if !seen_weight.insert((src, dst)) {
                return Err(delta_error(
                    format!("weight delta names edge {src} -> {dst} more than once"),
                    "emit one canonical weight update per directed endpoint pair",
                ));
            }
            if !expected.is_finite() || !(0.0..=1.0).contains(&expected) {
                return Err(delta_error(
                    format!(
                        "weight delta for edge {src} -> {dst} is outside finite [0,1]: {expected}"
                    ),
                    "supply the exact finite projected edge weight without coercion",
                ));
            }
            let observed = weights_by_edge.get(&(src, dst)).ok_or_else(|| {
                delta_error(
                    format!("weight delta names unknown edge {src} -> {dst}"),
                    "bind the delta and rebuilt graph to the same canonical directed topology",
                )
            })?;
            if observed.iter().any(|bits| *bits != expected.to_bits()) {
                return Err(delta_error(
                    format!(
                        "weight delta/application mismatch for edge {src} -> {dst}: expected_bits={:08x}, observed_bits={observed:?}",
                        expected.to_bits(),
                    ),
                    "apply the declared weight to every parallel row for that endpoint pair before requesting cache reuse",
                ));
            }
        }
        Ok(())
    }

    fn dirty_nodes(&self) -> BTreeSet<CxId> {
        let mut dirty = BTreeSet::new();
        for (id, _) in &self.frequency_changes {
            dirty.insert(*id);
        }
        for (src, dst, _) in &self.weight_changes {
            dirty.insert(*src);
            dirty.insert(*dst);
        }
        dirty
    }
}

/// Instrumentation for an incremental rebuild.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildReport {
    /// Whether the delta escalated to a full rebuild.
    pub escalated: bool,
    /// Whether cached betweenness was reused (the incremental win).
    pub betweenness_reused: bool,
    /// SCC indices (into the new graph's SCC list) that contained a changed node.
    pub dirty_scc_ids: Vec<usize>,
    /// Number of SCCs whose nodes were affected by the declared delta.
    pub affected_scc_count: usize,
    /// Number of SCCs traversed while rebuilding the artifact. The current
    /// implementation always rebuilds the complete artifact, so this equals
    /// [`Self::total_scc_count`] and never masquerades affected-set diagnostics
    /// as measured incremental execution.
    pub reprocessed_scc_count: usize,
    /// Total SCC count in the new graph.
    pub total_scc_count: usize,
}

/// Rebuilds a kernel after a graph delta, reusing cached betweenness for a
/// topology-preserving change and escalating to a full rebuild otherwise.
///
/// The returned artifact is byte-for-byte what a from-scratch build over the new
/// graph produces (the reused betweenness equals a fresh computation because the
/// topology is unchanged); the [`RebuildReport`] records which SCCs were dirty.
///
/// # Cost contract (#1064)
///
/// Against the measured production graph `N=192,873`, `E=328,899` (2026-08-20),
/// delta validation is `O(N + E + Δ log(N+E))` time and `O(N+E+Δ)` temporary
/// identity state before the existing complete build. The exact new graph,
/// canonical node/edge rosters, cache identity, configuration, and closed delta
/// roster remain invariant for the pass. The report explicitly records that all
/// SCCs are traversed by the current complete artifact rebuild; affected SCCs
/// are diagnostics only and do not claim incremental execution.
pub fn rebuild_dirty(
    new_graph: &KernelGraph,
    delta: &GraphDelta,
    previous_betweenness: &BetweennessCache,
    config: &KernelBuildConfig,
    scope_id: &str,
) -> Result<(KernelArtifact, RebuildReport)> {
    delta.validate_applied_to(new_graph)?;
    let indexed = new_graph.compile()?;
    let sccs = all_strongly_connected_components(&indexed);
    let total_scc_count = sccs.len();

    if delta.structural {
        let artifact = build_kernel(new_graph, scope_id, config)?;
        return Ok((
            artifact,
            RebuildReport {
                escalated: true,
                betweenness_reused: false,
                dirty_scc_ids: (0..total_scc_count).collect(),
                affected_scc_count: total_scc_count,
                reprocessed_scc_count: total_scc_count,
                total_scc_count,
            },
        ));
    }

    let dirty = delta.dirty_nodes();
    let dirty_indices = dirty
        .iter()
        .map(|id| {
            indexed.ids().binary_search(id).map_err(|_| {
                delta_error(
                    format!("delta dirty roster names unknown node {id}"),
                    "bind the delta and rebuilt graph to the same canonical node roster",
                )
            })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let dirty_scc_ids: Vec<usize> = sccs
        .iter()
        .enumerate()
        .filter(|(_, component)| component.iter().any(|node| dirty_indices.contains(node)))
        .map(|(index, _)| index)
        .collect();

    let artifact =
        build_kernel_reusing_betweenness(new_graph, scope_id, config, previous_betweenness)?;
    let affected_scc_count = dirty_scc_ids.len();
    Ok((
        artifact,
        RebuildReport {
            escalated: false,
            betweenness_reused: true,
            dirty_scc_ids,
            affected_scc_count,
            reprocessed_scc_count: total_scc_count,
            total_scc_count,
        },
    ))
}

/// Maps a node identity to its region key (e.g. its top-level package).
pub type RegionOf<'a> = dyn Fn(CxId) -> String + 'a;

/// A region graph over a monorepo: one node per region, edge weight = normalized
/// cross-region edge count.
#[derive(Clone, Debug, PartialEq)]
pub struct RegionGraph {
    /// The region-level kernel graph (nodes = regions).
    pub graph: KernelGraph,
    /// Region name for each region node identity.
    pub region_names: BTreeMap<CxId, String>,
    /// Member symbol identities for each region node identity.
    pub region_members: BTreeMap<CxId, BTreeSet<CxId>>,
}

/// Region-node identity for a region name.
pub fn region_id(name: &str) -> CxId {
    CxId::from_bytes(content_address([
        b"astro.kernel.region.v1".as_slice(),
        name.as_bytes(),
    ]))
}

/// Folds a symbol graph into a region graph. Inter-region edge weight is the
/// cross-region edge count normalized by the maximum cross-region count (so it
/// lands in `(0, 1]`); a region is a Trusted anchor when it contains any Trusted
/// anchor symbol; region frequency is its member count.
///
/// At production `N=192,873`, `E=328,899` (2026-08-20), this is `O(N log R +
/// E log R)` time and `O(N+R+E_R)` memory for `R` regions and `E_R` distinct
/// cross-region pairs. The source graph, callback, stable region-name bytes, and
/// canonical node/edge rosters are invariant across the fold.
pub fn build_region_graph(graph: &KernelGraph, region_of: &RegionOf<'_>) -> Result<RegionGraph> {
    let mut region_names: BTreeMap<CxId, String> = BTreeMap::new();
    let mut members: BTreeMap<CxId, BTreeSet<CxId>> = BTreeMap::new();
    let mut region_trusted: BTreeMap<CxId, bool> = BTreeMap::new();
    let mut node_region: BTreeMap<CxId, CxId> = BTreeMap::new();

    for node in graph.nodes() {
        let name = region_of(node.id);
        if name.trim().is_empty() {
            return Err(region_error(
                format!("region callback returned a blank name for node {}", node.id),
                "return one stable nonblank region name for every graph identity",
            ));
        }
        let rid = region_id(&name);
        if let Some(existing) = region_names.insert(rid, name.clone())
            && existing != name
        {
            return Err(region_error(
                format!("region identity collision maps names {existing:?} and {name:?} to {rid}"),
                "preserve the graph and revise the versioned region identity scheme before folding",
            ));
        }
        members.entry(rid).or_default().insert(node.id);
        node_region.insert(node.id, rid);
        let trusted = region_trusted.entry(rid).or_insert(false);
        *trusted = *trusted || node.is_trusted_anchor();
    }

    // Count directed cross-region edges.
    let mut cross: BTreeMap<(CxId, CxId), u64> = BTreeMap::new();
    for edge in graph.edges() {
        let src_region = node_region.get(&edge.src).copied().ok_or_else(|| {
            region_error(
                format!(
                    "region map has no source node {} for an existing edge",
                    edge.src
                ),
                "repair the complete node-to-region assignment before folding edges",
            )
        })?;
        let dst_region = node_region.get(&edge.dst).copied().ok_or_else(|| {
            region_error(
                format!(
                    "region map has no destination node {} for an existing edge",
                    edge.dst
                ),
                "repair the complete node-to-region assignment before folding edges",
            )
        })?;
        if src_region != dst_region {
            let count = cross.entry((src_region, dst_region)).or_insert(0);
            *count = count.checked_add(1).ok_or_else(|| {
                region_error(
                    format!(
                        "cross-region edge count overflow for {src_region} -> {dst_region}"
                    ),
                    "partition the source into a representable generation without truncating edge evidence",
                )
            })?;
        }
    }
    let max_cross = cross.values().copied().max().unwrap_or(1).max(1);

    let nodes = region_names
        .keys()
        .map(|&rid| {
            let anchor = if region_trusted.get(&rid).copied().unwrap_or(false) {
                Some(astrolabe_domain::TrustTag::Trusted)
            } else {
                None
            };
            let frequency = members.get(&rid).map(BTreeSet::len).unwrap_or(0) as u64;
            KernelGraphNode::new(rid, frequency, anchor)
        })
        .collect::<Vec<_>>();
    let edges = cross
        .into_iter()
        .map(|((src, dst), count)| {
            let weight = (count as f32 / max_cross as f32).clamp(f32::MIN_POSITIVE, 1.0);
            KernelGraphEdge::new(src, dst, weight)
        })
        .collect::<Vec<_>>();

    let region_graph = KernelGraph::new(nodes, edges)?;
    Ok(RegionGraph {
        graph: region_graph,
        region_names,
        region_members: members,
    })
}

fn delta_error(message: impl Into<String>, remediation: impl Into<String>) -> DomainError {
    DomainError::new(ASTRO_KERNEL_DELTA_INVALID, message, remediation)
}

fn region_error(message: impl Into<String>, remediation: impl Into<String>) -> DomainError {
    DomainError::new(ASTRO_KERNEL_REGION_GRAPH_INVALID, message, remediation)
}
