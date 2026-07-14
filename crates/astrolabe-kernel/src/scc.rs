//! Iterative (non-recursive) Tarjan strongly-connected-component detection (#37).
//!
//! Tarjan's algorithm is expressed with an explicit work stack rather than
//! native recursion so it survives the deep DFS chains a 10^5–10^6 node
//! monorepo graph produces without overflowing the thread stack. The output is
//! deterministic: components are returned in ascending order of their smallest
//! member index, and each component's members are ascending, so the result is a
//! pure function of the adjacency and the active-node mask.

use crate::kernel_graph::IndexedGraph;

/// One frame of the explicit DFS stack.
struct Frame {
    node: usize,
    /// Cursor into `out_neighbors(node)`: the next neighbour to visit.
    next: usize,
}

/// Computes the strongly-connected components of the subgraph induced by the
/// `active` nodes over the directed out-adjacency of `graph`.
///
/// A node with `active[i] == false` and every edge touching such a node are
/// ignored, which lets the feedback-vertex-set search recompute SCCs on the
/// graph with already-selected vertices removed without rebuilding adjacency.
/// A self-loop does not by itself enlarge a component (Tarjan places the node in
/// a singleton), so callers that treat self-loops as length-one cycles must
/// consult [`IndexedGraph::has_self_loop`] separately.
pub fn strongly_connected_components(graph: &IndexedGraph, active: &[bool]) -> Vec<Vec<usize>> {
    let n = graph.len();
    debug_assert_eq!(active.len(), n);

    const UNVISITED: usize = usize::MAX;
    let mut index_of = vec![UNVISITED; n];
    let mut lowlink = vec![0_usize; n];
    let mut on_stack = vec![false; n];
    let mut tarjan_stack: Vec<usize> = Vec::new();
    let mut work: Vec<Frame> = Vec::new();
    let mut next_index = 0_usize;
    let mut components: Vec<Vec<usize>> = Vec::new();

    for root in 0..n {
        if !active[root] || index_of[root] != UNVISITED {
            continue;
        }
        work.push(Frame {
            node: root,
            next: 0,
        });
        while let Some(frame) = work.last_mut() {
            let node = frame.node;
            if frame.next == 0 && index_of[node] == UNVISITED {
                index_of[node] = next_index;
                lowlink[node] = next_index;
                next_index += 1;
                tarjan_stack.push(node);
                on_stack[node] = true;
            }

            let neighbors = graph.out_neighbors(node);
            let mut recursed = false;
            while frame.next < neighbors.len() {
                let neighbor = neighbors[frame.next];
                frame.next += 1;
                if !active[neighbor] {
                    continue;
                }
                if index_of[neighbor] == UNVISITED {
                    work.push(Frame {
                        node: neighbor,
                        next: 0,
                    });
                    recursed = true;
                    break;
                } else if on_stack[neighbor] {
                    lowlink[node] = lowlink[node].min(index_of[neighbor]);
                }
            }
            if recursed {
                continue;
            }

            // All neighbours exhausted: node is fully explored.
            if lowlink[node] == index_of[node] {
                let mut component = Vec::new();
                loop {
                    let member = tarjan_stack.pop().expect("tarjan stack underflow");
                    on_stack[member] = false;
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                component.sort_unstable();
                components.push(component);
            }
            work.pop();
            if let Some(parent) = work.last() {
                let parent_node = parent.node;
                lowlink[parent_node] = lowlink[parent_node].min(lowlink[node]);
            }
        }
    }

    components.sort_by_key(|component| component[0]);
    components
}

/// Convenience wrapper computing SCCs over the whole graph (all nodes active).
pub fn all_strongly_connected_components(graph: &IndexedGraph) -> Vec<Vec<usize>> {
    strongly_connected_components(graph, &vec![true; graph.len()])
}
