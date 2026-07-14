//! Approximate directed feedback vertex set over the candidate subgraph (#37).
//!
//! A directed feedback vertex set (FVS) is a set of vertices whose removal makes
//! the graph acyclic. Exact minimum directed FVS is NP-hard, so the pipeline
//! uses a deterministic greedy approximation: repeatedly take the
//! highest-kernel-score vertex that still lies on a cycle, add it to the set,
//! remove it, and recompute. Removing the most load-bearing cycle vertex is
//! exactly the intent — those vertices *are* the kernel core (the ~1% from which
//! the corpus is reconstructable). The search runs only over the
//! candidate-induced subgraph (the top-scored ~10%), never the whole graph.

use std::collections::BTreeSet;

use crate::kernel_graph::IndexedGraph;
use crate::scc::strongly_connected_components;

/// Result of the approximate FVS search.
#[derive(Clone, Debug, PartialEq)]
pub struct FeedbackVertexSet {
    /// Selected vertex indices, ascending. Removing these from the candidate
    /// subgraph leaves a directed acyclic graph.
    pub members: Vec<usize>,
    /// Number of greedy rounds run (each round removes exactly one vertex).
    pub rounds: usize,
}

/// Computes an approximate directed FVS of the subgraph induced by `candidates`,
/// breaking score ties by ascending `CxId`.
///
/// `score_permille` is indexed by node index over the whole graph; only the
/// candidate entries are consulted. A self-loop is a length-one cycle, so any
/// candidate with a self-loop is forced into the set on the first round it is
/// still active.
pub fn approximate_directed_fvs(
    graph: &IndexedGraph,
    candidates: &BTreeSet<usize>,
    score_permille: &[usize],
) -> FeedbackVertexSet {
    let n = graph.len();
    let mut active = vec![false; n];
    for &candidate in candidates {
        active[candidate] = true;
    }

    let mut members: BTreeSet<usize> = BTreeSet::new();
    let mut rounds = 0;
    loop {
        // Self-loops first: they are length-one cycles that SCC singletons hide.
        let mut cycle_vertices: BTreeSet<usize> = candidates
            .iter()
            .copied()
            .filter(|&index| active[index] && graph.has_self_loop(index))
            .collect();

        for component in strongly_connected_components(graph, &active) {
            if component.len() > 1 {
                cycle_vertices.extend(component);
            }
        }
        if cycle_vertices.is_empty() {
            break;
        }

        let chosen = cycle_vertices
            .into_iter()
            .max_by(|&left, &right| {
                score_permille[left]
                    .cmp(&score_permille[right])
                    .then_with(|| graph.id(right).cmp(&graph.id(left)))
            })
            .expect("non-empty cycle vertex set");
        active[chosen] = false;
        members.insert(chosen);
        rounds += 1;
    }

    FeedbackVertexSet {
        members: members.into_iter().collect(),
        rounds,
    }
}
