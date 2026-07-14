//! Incremental kernel rebuild and hierarchical region kernels (#38).
//!
//! A [`GraphDelta`] describes a change to the kernel graph. A topology-preserving
//! delta (edge-weight and node-frequency changes) is served by [`rebuild_dirty`]
//! reusing the cached betweenness vector — betweenness, degree, and SCC structure
//! are all topology-only, so the cached values are exactly what a fresh build
//! would produce, and only the SCCs containing changed nodes need reprocessing.
//! A structural delta (node/edge add/remove that shifts SCC structure) escalates
//! to a full rebuild. For hierarchical monorepo kernels, [`build_region_graph`]
//! folds packages into a region graph whose kernel drives drill-down.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::Result;
use astrolabe_domain::calyx::{CxId, content_address};

use crate::kernel_build::{
    KernelArtifact, KernelBuildConfig, build_kernel, build_kernel_reusing_betweenness,
};
use crate::kernel_graph::{KernelGraph, KernelGraphEdge, KernelGraphNode};
use crate::scc::all_strongly_connected_components;

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
        let freq: BTreeMap<CxId, u64> = self.frequency_changes.iter().copied().collect();
        let weight: BTreeMap<(CxId, CxId), f32> = self
            .weight_changes
            .iter()
            .map(|(src, dst, w)| ((*src, *dst), *w))
            .collect();
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
    /// Number of SCCs reprocessed.
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
pub fn rebuild_dirty(
    new_graph: &KernelGraph,
    delta: &GraphDelta,
    previous_betweenness_permille: &[u64],
    config: &KernelBuildConfig,
    scope_id: &str,
) -> Result<(KernelArtifact, RebuildReport)> {
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
                reprocessed_scc_count: total_scc_count,
                total_scc_count,
            },
        ));
    }

    let dirty = delta.dirty_nodes();
    let dirty_indices: BTreeSet<usize> = dirty
        .iter()
        .filter_map(|id| indexed.ids().iter().position(|node_id| node_id == id))
        .collect();
    let dirty_scc_ids: Vec<usize> = sccs
        .iter()
        .enumerate()
        .filter(|(_, component)| component.iter().any(|node| dirty_indices.contains(node)))
        .map(|(index, _)| index)
        .collect();

    let artifact = build_kernel_reusing_betweenness(
        new_graph,
        scope_id,
        config,
        previous_betweenness_permille,
    )?;
    let reprocessed_scc_count = dirty_scc_ids.len();
    Ok((
        artifact,
        RebuildReport {
            escalated: false,
            betweenness_reused: true,
            dirty_scc_ids,
            reprocessed_scc_count,
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
pub fn build_region_graph(graph: &KernelGraph, region_of: &RegionOf<'_>) -> Result<RegionGraph> {
    let mut region_names: BTreeMap<CxId, String> = BTreeMap::new();
    let mut members: BTreeMap<CxId, BTreeSet<CxId>> = BTreeMap::new();
    let mut region_trusted: BTreeMap<CxId, bool> = BTreeMap::new();
    let mut node_region: BTreeMap<CxId, CxId> = BTreeMap::new();

    for node in graph.nodes() {
        let name = region_of(node.id);
        let rid = region_id(&name);
        region_names.insert(rid, name);
        members.entry(rid).or_default().insert(node.id);
        node_region.insert(node.id, rid);
        let trusted = region_trusted.entry(rid).or_insert(false);
        *trusted = *trusted || node.is_trusted_anchor();
    }

    // Count directed cross-region edges.
    let mut cross: BTreeMap<(CxId, CxId), u64> = BTreeMap::new();
    for edge in graph.edges() {
        let (Some(&src_region), Some(&dst_region)) =
            (node_region.get(&edge.src), node_region.get(&edge.dst))
        else {
            continue;
        };
        if src_region != dst_region {
            *cross.entry((src_region, dst_region)).or_insert(0) += 1;
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
