//! Input substrate for the kernel build pipeline (#37).
//!
//! The pipeline consumes the composite `kernel_graph` projection (P2.2,
//! `astrolabe-ingest::graph_projection`). That projection crate depends on this
//! kernel crate, so this crate cannot depend on it in return without a
//! dependency cycle. The pipeline therefore accepts a kernel-owned
//! [`KernelGraph`] built from plain graph data — node identities, directed
//! weighted edges, per-node change frequency, and per-node anchor trust. A
//! caller that owns both a decoded `GraphProjectionCsr` and the anchor rollup
//! (the ingest/server layer, which already depends on this crate) constructs a
//! [`KernelGraph`] from that data; the algorithms below never reach back into
//! the projection wire format.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::calyx::CxId;
use astrolabe_domain::{DomainError, Result, TrustTag};

/// Refusal raised when a kernel build is requested over a graph with no nodes.
pub const ASTRO_KERNEL_EMPTY_GRAPH: &str = "ASTRO_KERNEL_EMPTY_GRAPH";
/// Refusal raised when the supplied kernel graph is internally inconsistent.
pub const ASTRO_KERNEL_GRAPH_INVALID: &str = "ASTRO_KERNEL_GRAPH_INVALID";

/// One node of a [`KernelGraph`]: a current symbol version.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelGraphNode {
    /// Calyx content identity of the symbol version.
    pub id: CxId,
    /// Node frequency weight = `change_count + 1` (blueprint 09 §1). Hot symbols
    /// are stronger kernel candidates through the groundedness frequency bonus.
    pub frequency: u64,
    /// Anchor trust of this node, if it carries a grounding anchor at all.
    /// `Some(Trusted)` marks a Trusted anchor (test-covered, trace-confirmed, or
    /// review-approved) — the BFS target for groundedness. `Some(Provisional)`
    /// is a proxy anchor. `None` means the node carries no anchor.
    pub anchor_trust: Option<TrustTag>,
}

impl KernelGraphNode {
    /// Builds a graph node from its identity, frequency, and anchor trust.
    pub fn new(id: CxId, frequency: u64, anchor_trust: Option<TrustTag>) -> Self {
        Self {
            id,
            frequency,
            anchor_trust,
        }
    }

    /// Whether this node is a Trusted grounding anchor.
    pub fn is_trusted_anchor(&self) -> bool {
        self.anchor_trust == Some(TrustTag::Trusted)
    }
}

/// One directed, weighted edge of a [`KernelGraph`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KernelGraphEdge {
    /// Source node identity.
    pub src: CxId,
    /// Destination node identity.
    pub dst: CxId,
    /// Projected edge weight in `[0, 1]` (annealed type weight × confidence).
    pub weight: f32,
}

impl KernelGraphEdge {
    /// Builds a directed weighted edge.
    pub fn new(src: CxId, dst: CxId, weight: f32) -> Self {
        Self { src, dst, weight }
    }
}

/// The composite kernel build graph handed to the pipeline.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelGraph {
    nodes: Vec<KernelGraphNode>,
    edges: Vec<KernelGraphEdge>,
}

impl KernelGraph {
    /// Builds and validates a kernel graph from nodes and directed edges.
    ///
    /// Fails closed when a node identity is duplicated, an edge references an
    /// unknown node, or an edge weight is non-finite or outside `[0, 1]`. An
    /// empty node set is permitted here (it is a valid, if degenerate, graph);
    /// [`crate::build_kernel`] is the layer that refuses to build a kernel over
    /// zero nodes with [`ASTRO_KERNEL_EMPTY_GRAPH`].
    pub fn new(nodes: Vec<KernelGraphNode>, edges: Vec<KernelGraphEdge>) -> Result<Self> {
        let mut seen = BTreeSet::new();
        for node in &nodes {
            if !seen.insert(node.id) {
                return Err(DomainError::new(
                    ASTRO_KERNEL_GRAPH_INVALID,
                    format!("kernel graph node {} is declared more than once", node.id),
                    "deduplicate symbol versions before building the kernel graph",
                ));
            }
        }
        for edge in &edges {
            if !edge.weight.is_finite() || !(0.0..=1.0).contains(&edge.weight) {
                return Err(DomainError::new(
                    ASTRO_KERNEL_GRAPH_INVALID,
                    format!(
                        "kernel graph edge {} -> {} has weight {} outside finite [0, 1]",
                        edge.src, edge.dst, edge.weight
                    ),
                    "project edge weights as finite confidences within [0, 1]",
                ));
            }
            if !seen.contains(&edge.src) {
                return Err(DomainError::new(
                    ASTRO_KERNEL_GRAPH_INVALID,
                    format!("kernel graph edge source {} has no node row", edge.src),
                    "add every edge endpoint as a node before building the kernel graph",
                ));
            }
            if !seen.contains(&edge.dst) {
                return Err(DomainError::new(
                    ASTRO_KERNEL_GRAPH_INVALID,
                    format!("kernel graph edge destination {} has no node row", edge.dst),
                    "add every edge endpoint as a node before building the kernel graph",
                ));
            }
        }
        Ok(Self { nodes, edges })
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of directed edges as supplied (before parallel-edge collapse).
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Nodes as supplied.
    pub fn nodes(&self) -> &[KernelGraphNode] {
        &self.nodes
    }

    /// Compiles this graph into the index-addressed representation the pipeline
    /// algorithms operate on. Nodes are ordered by `CxId`, so the index of a
    /// node — and therefore every downstream artifact ordering — is a pure
    /// function of the identity set, independent of insertion order.
    pub fn compile(&self) -> Result<IndexedGraph> {
        let mut ids: Vec<CxId> = self.nodes.iter().map(|node| node.id).collect();
        ids.sort_unstable();
        let mut index_of = BTreeMap::new();
        for (index, id) in ids.iter().enumerate() {
            index_of.insert(*id, index);
        }
        let n = ids.len();
        let mut frequency = vec![0_u64; n];
        let mut trusted_anchor = vec![false; n];
        for node in &self.nodes {
            let index = index_of[&node.id];
            frequency[index] = node.frequency;
            trusted_anchor[index] = node.is_trusted_anchor();
        }

        let mut out_sets = vec![BTreeSet::<usize>::new(); n];
        let mut in_sets = vec![BTreeSet::<usize>::new(); n];
        let mut undirected_sets = vec![BTreeSet::<usize>::new(); n];
        let mut self_loop = vec![false; n];
        for edge in &self.edges {
            let src = index_of[&edge.src];
            let dst = index_of[&edge.dst];
            if src == dst {
                self_loop[src] = true;
                continue;
            }
            out_sets[src].insert(dst);
            in_sets[dst].insert(src);
            undirected_sets[src].insert(dst);
            undirected_sets[dst].insert(src);
        }

        let out_adj = out_sets.into_iter().map(sorted_vec).collect();
        let in_adj = in_sets.into_iter().map(sorted_vec).collect();
        let undirected_adj = undirected_sets.into_iter().map(sorted_vec).collect();

        Ok(IndexedGraph {
            ids,
            out_adj,
            in_adj,
            undirected_adj,
            frequency,
            trusted_anchor,
            self_loop,
        })
    }
}

fn sorted_vec(set: BTreeSet<usize>) -> Vec<usize> {
    set.into_iter().collect()
}

/// Index-addressed compilation of a [`KernelGraph`].
///
/// Every collection is keyed by a dense node index `0..n`, where index order is
/// ascending `CxId`. Parallel edges are collapsed and self-loops are recorded
/// separately (they never appear in the neighbour lists but do force their node
/// into any feedback vertex set).
#[derive(Clone, Debug, PartialEq)]
pub struct IndexedGraph {
    ids: Vec<CxId>,
    out_adj: Vec<Vec<usize>>,
    in_adj: Vec<Vec<usize>>,
    undirected_adj: Vec<Vec<usize>>,
    frequency: Vec<u64>,
    trusted_anchor: Vec<bool>,
    self_loop: Vec<bool>,
}

impl IndexedGraph {
    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether the graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// The `CxId` at a node index.
    pub fn id(&self, index: usize) -> CxId {
        self.ids[index]
    }

    /// All node identities in ascending order.
    pub fn ids(&self) -> &[CxId] {
        &self.ids
    }

    /// Out-neighbours of a node (ascending index order, parallel edges collapsed).
    pub fn out_neighbors(&self, index: usize) -> &[usize] {
        &self.out_adj[index]
    }

    /// In-neighbours of a node (ascending index order).
    pub fn in_neighbors(&self, index: usize) -> &[usize] {
        &self.in_adj[index]
    }

    /// Undirected neighbours of a node (ascending index order).
    pub fn undirected_neighbors(&self, index: usize) -> &[usize] {
        &self.undirected_adj[index]
    }

    /// Directed degree of a node: distinct in-neighbours + out-neighbours +
    /// one for a self-loop when present.
    pub fn degree(&self, index: usize) -> u64 {
        let self_loop = u64::from(self.self_loop[index]);
        self.out_adj[index].len() as u64 + self.in_adj[index].len() as u64 + self_loop
    }

    /// Node frequency weight (`change_count + 1`).
    pub fn frequency(&self, index: usize) -> u64 {
        self.frequency[index]
    }

    /// Whether the node carries a Trusted grounding anchor.
    pub fn is_trusted_anchor(&self, index: usize) -> bool {
        self.trusted_anchor[index]
    }

    /// Whether the node has a self-loop (a length-one cycle).
    pub fn has_self_loop(&self, index: usize) -> bool {
        self.self_loop[index]
    }
}
