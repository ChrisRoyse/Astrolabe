//! Deterministic directed feedback vertex set over the complete graph (#1148).
//!
//! The member set is produced by one declared algorithm: iterative directed DFS
//! from roots in ascending `CxId` order, visiting each node's outgoing edges in
//! ascending destination-`CxId` order and selecting the source of every edge to
//! a gray ancestor. Self-loops occupy their destination's canonical position in
//! that same edge order. There is no exact/heuristic switch and no minimum-FVS
//! claim. A separate canonical Kahn traversal then proves that removing those
//! members leaves the complete residual graph acyclic.

use std::collections::{BTreeSet, VecDeque};

use astrolabe_domain::{DomainError, Result};
use sha2::{Digest, Sha256};

use crate::kernel_graph::IndexedGraph;
use crate::scc::all_strongly_connected_components;

/// Refusal raised when the canonical full-graph DFS proof cannot be completed.
pub const ASTRO_KERNEL_FVS_TRAVERSAL_INVALID: &str = "ASTRO_KERNEL_FVS_TRAVERSAL_INVALID";
/// Refusal raised when the complete residual graph is not proven acyclic.
pub const ASTRO_KERNEL_FVS_RESIDUAL_CYCLE: &str = "ASTRO_KERNEL_FVS_RESIDUAL_CYCLE";
/// Canonical member-selection algorithm bound into the kernel source identity.
pub const FVS_SELECTION_SCHEMA: &str =
    "canonical_ascending_cxid_iterative_dfs_gray_edge_sources.v1";
/// Independent complete-residual proof algorithm bound into source identity.
pub const FVS_RESIDUAL_PROOF_SCHEMA: &str = "canonical_fifo_kahn_full_residual_dag.v1";
/// Persisted discriminator for the composed selection plus validity contract.
pub const FVS_VALIDITY_METHOD: &str = "canonical_dfs_backedge_sources_then_full_residual_dag.v1";

const BACK_EDGE_ROSTER_HASH_TAG: &[u8] = b"astro.kernel.fvs.canonical_dfs_back_edge_roster.v1";
const RESIDUAL_ORDER_HASH_TAG: &[u8] = b"astro.kernel.fvs.canonical_kahn_topological_order.v1";

/// Result of canonical DFS member selection plus the independent full-graph
/// residual-DAG proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackVertexSet {
    /// Selected full-graph vertex indices, ascending.
    pub members: Vec<usize>,
    /// Number of cyclic SCCs in the complete source graph (diagnostic only).
    pub cyclic_scc_count: usize,
    /// Node count of the largest cyclic SCC in the complete source graph.
    pub largest_cyclic_scc_node_count: usize,
    /// Number of canonical directed edges inspected by DFS, including self-loops.
    pub dfs_checked_edge_count: usize,
    /// Number of inspected edges whose destination was gray.
    pub dfs_back_edge_count: usize,
    /// SHA-256 of the back-edge roster in canonical DFS encounter order.
    pub dfs_back_edge_roster_hash: String,
    /// Nodes left in the residual DAG.
    pub residual_node_count: usize,
    /// SHA-256 of the canonical Kahn order over every residual node.
    pub residual_topological_order_hash: String,
}

/// Computes one deterministic full-graph directed FVS and independently proves
/// its residual graph is a DAG.
///
/// Nodes and adjacency in [`IndexedGraph`] are already canonical ascending
/// `CxId` order. The DFS below preserves that order with an explicit stack, so
/// deep production graphs cannot overflow the native stack. Selecting every
/// gray-edge source hits every directed cycle encountered by DFS; success is
/// nevertheless contingent on a separate whole-graph Kahn proof rather than on
/// that property alone. This algorithm is deterministic but does not claim the
/// returned feedback vertex set is minimum or an approximation of a minimum.
pub fn canonical_dfs_feedback_vertex_set(graph: &IndexedGraph) -> Result<FeedbackVertexSet> {
    let (cyclic_scc_count, largest_cyclic_scc_node_count) = cyclic_scc_diagnostics(graph);
    let n = graph.len();
    let mut color = vec![Color::White; n];
    let mut selected = vec![false; n];
    let mut stack = Vec::<DfsFrame>::new();
    let mut dfs_checked_edge_count = 0_usize;
    let mut dfs_back_edge_count = 0_usize;
    let mut back_edge_hasher = domain_hasher(BACK_EDGE_ROSTER_HASH_TAG);
    update_framed_hash(&mut back_edge_hasher, &(n as u64).to_be_bytes());

    for root in 0..n {
        if color[root] != Color::White {
            continue;
        }
        color[root] = Color::Gray;
        stack.push(DfsFrame::new(root));

        while !stack.is_empty() {
            let next_edge = {
                let frame = stack.last_mut().ok_or_else(|| {
                    traversal_internal_error(
                        graph,
                        "DFS loop observed an empty work stack while reading its active frame",
                    )
                })?;
                next_canonical_edge(graph, frame)
            };
            let src = stack.last().map(|frame| frame.node).ok_or_else(|| {
                traversal_internal_error(
                    graph,
                    "DFS work stack disappeared between edge selection and source inspection",
                )
            })?;
            let Some(dst) = next_edge else {
                color[src] = Color::Black;
                stack.pop();
                continue;
            };

            dfs_checked_edge_count = dfs_checked_edge_count.checked_add(1).ok_or_else(|| {
                traversal_count_overflow(graph, "checked directed-edge", src, dst)
            })?;
            match color[dst] {
                Color::White => {
                    color[dst] = Color::Gray;
                    stack.push(DfsFrame::new(dst));
                }
                Color::Gray => {
                    dfs_back_edge_count = dfs_back_edge_count.checked_add(1).ok_or_else(|| {
                        traversal_count_overflow(graph, "gray/back-edge", src, dst)
                    })?;
                    selected[src] = true;
                    update_framed_hash(&mut back_edge_hasher, graph.id(src).as_bytes());
                    update_framed_hash(&mut back_edge_hasher, graph.id(dst).as_bytes());
                }
                Color::Black => {}
            }
        }
    }

    update_framed_hash(
        &mut back_edge_hasher,
        &(dfs_checked_edge_count as u64).to_be_bytes(),
    );
    update_framed_hash(
        &mut back_edge_hasher,
        &(dfs_back_edge_count as u64).to_be_bytes(),
    );
    let dfs_back_edge_roster_hash = finish_hash(back_edge_hasher);

    // The scan is ascending, so the ordered set and the final persisted roster
    // are independent of DFS encounter order while requiring only O(N) proof
    // workspace in addition to the already-materialized O(N+E) graph.
    let members = selected
        .iter()
        .enumerate()
        .filter(|(_, is_selected)| **is_selected)
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    let (residual_node_count, residual_topological_order_hash) =
        prove_residual_dag(graph, &members)?;

    Ok(FeedbackVertexSet {
        members: members.into_iter().collect(),
        cyclic_scc_count,
        largest_cyclic_scc_node_count,
        dfs_checked_edge_count,
        dfs_back_edge_count,
        dfs_back_edge_roster_hash,
        residual_node_count,
        residual_topological_order_hash,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Color {
    White,
    Gray,
    Black,
}

struct DfsFrame {
    node: usize,
    next_neighbor: usize,
    self_loop_consumed: bool,
}

impl DfsFrame {
    fn new(node: usize) -> Self {
        Self {
            node,
            next_neighbor: 0,
            self_loop_consumed: false,
        }
    }
}

/// Returns the next outgoing destination in ascending canonical node order.
/// `IndexedGraph` stores a self-loop separately, so this cursor merges it into
/// the already-sorted out-neighbor slice without allocating an edge list.
fn next_canonical_edge(graph: &IndexedGraph, frame: &mut DfsFrame) -> Option<usize> {
    let neighbors = graph.out_neighbors(frame.node);
    let next_neighbor = neighbors.get(frame.next_neighbor).copied();
    if graph.has_self_loop(frame.node)
        && !frame.self_loop_consumed
        && next_neighbor.is_none_or(|neighbor| frame.node < neighbor)
    {
        frame.self_loop_consumed = true;
        return Some(frame.node);
    }
    if let Some(neighbor) = next_neighbor {
        frame.next_neighbor += 1;
        return Some(neighbor);
    }
    if graph.has_self_loop(frame.node) && !frame.self_loop_consumed {
        frame.self_loop_consumed = true;
        return Some(frame.node);
    }
    None
}

fn cyclic_scc_diagnostics(graph: &IndexedGraph) -> (usize, usize) {
    let mut cyclic_scc_count = 0_usize;
    let mut largest_cyclic_scc_node_count = 0_usize;
    for component in all_strongly_connected_components(graph) {
        let cyclic = component.len() > 1
            || component
                .first()
                .is_some_and(|index| graph.has_self_loop(*index));
        if cyclic {
            cyclic_scc_count += 1;
            largest_cyclic_scc_node_count = largest_cyclic_scc_node_count.max(component.len());
        }
    }
    (cyclic_scc_count, largest_cyclic_scc_node_count)
}

fn prove_residual_dag(graph: &IndexedGraph, members: &BTreeSet<usize>) -> Result<(usize, String)> {
    let n = graph.len();
    let mut active = vec![true; n];
    for &member in members {
        active[member] = false;
    }
    let residual_node_count = active.iter().filter(|active| **active).count();
    let mut indegree = vec![0_usize; n];
    for src in 0..n {
        if !active[src] {
            continue;
        }
        if graph.has_self_loop(src) {
            return residual_cycle(graph, src, residual_node_count);
        }
        for &dst in graph.out_neighbors(src) {
            if active[dst] {
                indegree[dst] = indegree[dst].checked_add(1).ok_or_else(|| {
                    DomainError::new(
                        ASTRO_KERNEL_FVS_RESIDUAL_CYCLE,
                        format!("residual indegree overflow at node {}", graph.id(dst)),
                        "preserve the source generation and repair the full-graph residual proof",
                    )
                })?;
            }
        }
    }

    // FIFO Kahn order is canonical because the initial roots, every processed
    // node's adjacency, and therefore every enqueue event are canonical. Unlike
    // a priority queue this retains the declared O(N+E) proof cost.
    let mut ready = VecDeque::with_capacity(residual_node_count);
    for index in 0..n {
        if active[index] && indegree[index] == 0 {
            ready.push_back(index);
        }
    }
    let mut order_hasher = domain_hasher(RESIDUAL_ORDER_HASH_TAG);
    update_framed_hash(
        &mut order_hasher,
        &(residual_node_count as u64).to_be_bytes(),
    );
    let mut emitted = 0_usize;
    while let Some(node) = ready.pop_front() {
        emitted = emitted.checked_add(1).ok_or_else(|| {
            DomainError::new(
                ASTRO_KERNEL_FVS_TRAVERSAL_INVALID,
                format!("canonical Kahn emission count overflow at node {}", graph.id(node)),
                "preserve the source generation and repair the full-graph residual proof accounting",
            )
        })?;
        update_framed_hash(&mut order_hasher, graph.id(node).as_bytes());
        for &dst in graph.out_neighbors(node) {
            if !active[dst] {
                continue;
            }
            indegree[dst] = indegree[dst].checked_sub(1).ok_or_else(|| {
                DomainError::new(
                    ASTRO_KERNEL_FVS_RESIDUAL_CYCLE,
                    format!("residual indegree underflow at node {}", graph.id(dst)),
                    "preserve the source generation and repair the full-graph residual proof",
                )
            })?;
            if indegree[dst] == 0 {
                ready.push_back(dst);
            }
        }
    }
    if emitted != residual_node_count {
        let first_blocked = (0..n)
            .find(|index| active[*index] && indegree[*index] > 0)
            .ok_or_else(|| {
                traversal_internal_error(
                    graph,
                    &format!(
                        "canonical Kahn emitted {emitted}/{residual_node_count} residual nodes but no un-emitted node has positive indegree"
                    ),
                )
            })?;
        return residual_cycle(graph, first_blocked, residual_node_count);
    }
    update_framed_hash(&mut order_hasher, &(emitted as u64).to_be_bytes());
    Ok((residual_node_count, finish_hash(order_hasher)))
}

fn traversal_count_overflow(
    graph: &IndexedGraph,
    count_name: &str,
    src: usize,
    dst: usize,
) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_FVS_TRAVERSAL_INVALID,
        format!(
            "canonical DFS {count_name} count overflow at edge {} -> {}",
            graph.id(src),
            graph.id(dst),
        ),
        "preserve the source generation and repair the full-graph DFS proof accounting",
    )
}

fn traversal_internal_error(graph: &IndexedGraph, detail: &str) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_FVS_TRAVERSAL_INVALID,
        format!(
            "canonical full-graph FVS traversal invariant failed: nodes={} detail={detail}",
            graph.len(),
        ),
        "preserve the source generation and repair the deterministic DFS/Kahn implementation before retrying",
    )
}

fn residual_cycle<T>(
    graph: &IndexedGraph,
    first_blocked: usize,
    residual_node_count: usize,
) -> Result<T> {
    Err(DomainError::new(
        ASTRO_KERNEL_FVS_RESIDUAL_CYCLE,
        format!(
            "full-graph residual DAG proof failed: residual_nodes={residual_node_count} first_blocked_node={}",
            graph.id(first_blocked),
        ),
        "preserve the source generation and repair the canonical DFS member selection; candidate-induced acyclicity is not sufficient",
    ))
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    update_framed_hash(&mut hasher, domain);
    hasher
}

fn update_framed_hash(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn finish_hash(hasher: Sha256) -> String {
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}
