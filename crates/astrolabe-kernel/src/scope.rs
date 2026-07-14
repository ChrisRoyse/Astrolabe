//! Scope algebra for scoped and hierarchical kernels (#38).
//!
//! A [`Scope`] selects a subset of symbol versions by a stable predicate over
//! per-node scope attributes and the graph topology: `Collection` by path
//! prefix, `Domain` by anchor kind, `Subgraph` by BFS radius from a symbol,
//! `TimeWindow` by timestamp, `Tenant` by repo, plus `Union`/`Intersect`
//! set-combinators (blueprint 09 §2). A scope resolves to an exact member set
//! and carries a stable `scope_hash` that is a pure function of the scope tree —
//! the first key component of the kernel cache.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use astrolabe_domain::calyx::{CxId, content_address};

use crate::kernel_graph::{IndexedGraph, KernelGraph};

/// Framing tag for the scope-hash preimage.
const SCOPE_HASH_TAG: &[u8] = b"astro.kernel.scope.v1";

/// Per-node scope attributes consulted by [`Scope::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeScope {
    /// Directory/package path of the symbol (e.g. `crates/astrolabe-kernel/src/scc.rs`).
    pub path: String,
    /// Grounding anchor kind, when the node carries an anchor (the `Domain` key).
    pub anchor_kind: Option<String>,
    /// Symbol timestamp used by `TimeWindow` (e.g. last-change epoch seconds).
    pub timestamp: u64,
    /// Owning repository/tenant identifier used by `Tenant`.
    pub tenant: String,
}

impl NodeScope {
    /// Builds node scope attributes.
    pub fn new(
        path: impl Into<String>,
        anchor_kind: Option<String>,
        timestamp: u64,
        tenant: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            anchor_kind,
            timestamp,
            tenant: tenant.into(),
        }
    }
}

/// A scope-attribute table keyed by node identity.
pub type ScopeAttributes = BTreeMap<CxId, NodeScope>;

/// A scope selecting a subset of the graph's symbol versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Everything in scope (the whole-repo standing kernel scope).
    All,
    /// Symbols whose path starts with the given prefix (a directory/package).
    Collection(String),
    /// Symbols whose anchor kind equals the given kind (an incident domain).
    Domain(String),
    /// Symbols within `radius` undirected hops of the focus symbol.
    Subgraph {
        /// Focus symbol identity.
        symbol: CxId,
        /// Undirected hop radius.
        radius: u64,
    },
    /// Symbols whose timestamp is within the inclusive `[t0, t1]` window.
    TimeWindow {
        /// Inclusive lower bound.
        t0: u64,
        /// Inclusive upper bound.
        t1: u64,
    },
    /// Symbols owned by the given repository/tenant.
    Tenant(String),
    /// Union of two scopes.
    Union(Box<Scope>, Box<Scope>),
    /// Intersection of two scopes.
    Intersect(Box<Scope>, Box<Scope>),
}

impl Scope {
    /// Convenience constructor for a union.
    pub fn union(left: Scope, right: Scope) -> Scope {
        Scope::Union(Box::new(left), Box::new(right))
    }

    /// Convenience constructor for an intersection.
    pub fn intersect(left: Scope, right: Scope) -> Scope {
        Scope::Intersect(Box::new(left), Box::new(right))
    }

    /// Resolves this scope to an exact, ascending member identity set.
    ///
    /// `graph` supplies topology for `Subgraph` radius expansion; `attrs`
    /// supplies path/anchor/time/tenant attributes. A node missing from `attrs`
    /// contributes only to `All` and topological (`Subgraph`) selection.
    pub fn resolve(&self, graph: &IndexedGraph, attrs: &ScopeAttributes) -> BTreeSet<CxId> {
        match self {
            Scope::All => graph.ids().iter().copied().collect(),
            Scope::Collection(prefix) => attrs
                .iter()
                .filter(|(_, scope)| scope.path.starts_with(prefix.as_str()))
                .map(|(id, _)| *id)
                .collect(),
            Scope::Domain(kind) => attrs
                .iter()
                .filter(|(_, scope)| scope.anchor_kind.as_deref() == Some(kind.as_str()))
                .map(|(id, _)| *id)
                .collect(),
            Scope::Subgraph { symbol, radius } => subgraph_members(graph, *symbol, *radius),
            Scope::TimeWindow { t0, t1 } => attrs
                .iter()
                .filter(|(_, scope)| scope.timestamp >= *t0 && scope.timestamp <= *t1)
                .map(|(id, _)| *id)
                .collect(),
            Scope::Tenant(tenant) => attrs
                .iter()
                .filter(|(_, scope)| scope.tenant == *tenant)
                .map(|(id, _)| *id)
                .collect(),
            Scope::Union(left, right) => {
                let mut members = left.resolve(graph, attrs);
                members.extend(right.resolve(graph, attrs));
                members
            }
            Scope::Intersect(left, right) => {
                let left_members = left.resolve(graph, attrs);
                let right_members = right.resolve(graph, attrs);
                left_members.intersection(&right_members).copied().collect()
            }
        }
    }

    /// Stable hex `scope_hash` — a pure function of the scope tree, independent
    /// of run, graph, or attribute contents. The first component of a cache key.
    pub fn scope_hash(&self) -> String {
        let mut preimage = Vec::new();
        self.encode(&mut preimage);
        hex_lower(&content_address([SCOPE_HASH_TAG, preimage.as_slice()]))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Scope::All => out.push(0),
            Scope::Collection(prefix) => {
                out.push(1);
                encode_str(out, prefix);
            }
            Scope::Domain(kind) => {
                out.push(2);
                encode_str(out, kind);
            }
            Scope::Subgraph { symbol, radius } => {
                out.push(3);
                out.extend_from_slice(symbol.as_bytes());
                out.extend_from_slice(&radius.to_be_bytes());
            }
            Scope::TimeWindow { t0, t1 } => {
                out.push(4);
                out.extend_from_slice(&t0.to_be_bytes());
                out.extend_from_slice(&t1.to_be_bytes());
            }
            Scope::Tenant(tenant) => {
                out.push(5);
                encode_str(out, tenant);
            }
            Scope::Union(left, right) => {
                out.push(6);
                left.encode(out);
                right.encode(out);
            }
            Scope::Intersect(left, right) => {
                out.push(7);
                left.encode(out);
                right.encode(out);
            }
        }
    }
}

fn encode_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn subgraph_members(graph: &IndexedGraph, symbol: CxId, radius: u64) -> BTreeSet<CxId> {
    let Some(start) = graph.ids().iter().position(|&id| id == symbol) else {
        return BTreeSet::new();
    };
    let mut visited = vec![false; graph.len()];
    let mut depth = vec![0_u64; graph.len()];
    let mut queue: VecDeque<usize> = VecDeque::new();
    visited[start] = true;
    queue.push_back(start);
    let mut members = BTreeSet::new();
    members.insert(symbol);
    while let Some(node) = queue.pop_front() {
        if depth[node] >= radius {
            continue;
        }
        for &neighbor in graph.undirected_neighbors(node) {
            if !visited[neighbor] {
                visited[neighbor] = true;
                depth[neighbor] = depth[node] + 1;
                members.insert(graph.id(neighbor));
                queue.push_back(neighbor);
            }
        }
    }
    members
}

/// Restricts a graph to a member set, keeping only edges with both endpoints in
/// the set. Node frequency and anchor trust are preserved. The induced subgraph
/// is the substrate a scoped kernel is built over.
pub fn induced_subgraph(
    graph: &KernelGraph,
    members: &BTreeSet<CxId>,
) -> astrolabe_domain::Result<KernelGraph> {
    let nodes = graph
        .nodes()
        .iter()
        .filter(|node| members.contains(&node.id))
        .cloned()
        .collect::<Vec<_>>();
    let edges = graph
        .edges()
        .iter()
        .filter(|edge| members.contains(&edge.src) && members.contains(&edge.dst))
        .copied()
        .collect::<Vec<_>>();
    KernelGraph::new(nodes, edges)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}
