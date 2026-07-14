//! Betweenness centrality with an exact/sampled auto-switch (#37).
//!
//! [`betweenness_auto`] runs exact Brandes betweenness when the graph is at or
//! below the exact-node knob, and otherwise estimates it from a fixed number of
//! deterministically chosen source pivots. Both paths are single-threaded and
//! order-independent, so the result is byte-identical across repeated runs and
//! independent of any ambient worker count (invariant 5). Betweenness is
//! computed on the unweighted directed graph — shortest path = fewest hops —
//! which is the structural "load-bearing" measure the kernel score wants.

use std::collections::VecDeque;

use astrolabe_domain::calyx::{CxId, content_address};

use crate::kernel_graph::IndexedGraph;

/// Deterministic pivot-selection tag framed into the pivot hash preimage.
const PIVOT_HASH_TAG: &[u8] = b"astro.kernel.betweenness.pivot.v1";

/// Raw and normalized betweenness of every node, plus how it was measured.
#[derive(Clone, Debug, PartialEq)]
pub struct BetweennessResult {
    /// Raw Brandes dependency accumulation per node index.
    pub raw: Vec<f64>,
    /// Betweenness normalized into permille `[0, 1000]` by the per-run maximum.
    /// Normalizing by the maximum cancels the uniform `V / pivots` estimator
    /// scale, so the sampled and exact permille rankings share one scale.
    pub permille: Vec<u64>,
    /// `true` when computed exactly (all nodes were sources), `false` when
    /// estimated from a pivot sample.
    pub exact: bool,
    /// Number of source nodes actually used (all nodes, or the pivot count).
    pub sources_used: usize,
}

/// Runs exact or sampled betweenness according to the exact-node threshold.
pub fn betweenness_auto(
    graph: &IndexedGraph,
    exact_max_nodes: u64,
    sample_pivots: u64,
    sample_seed: u64,
) -> BetweennessResult {
    let n = graph.len();
    if n == 0 {
        return BetweennessResult {
            raw: Vec::new(),
            permille: Vec::new(),
            exact: true,
            sources_used: 0,
        };
    }
    let exact = (n as u64) <= exact_max_nodes;
    let sources: Vec<usize> = if exact {
        (0..n).collect()
    } else {
        select_pivots(graph, sample_pivots, sample_seed)
    };
    let raw = brandes(graph, &sources);
    let permille = normalize_permille(&raw);
    BetweennessResult {
        raw,
        permille,
        exact,
        sources_used: sources.len(),
    }
}

/// Selects up to `count` deterministic source pivots.
///
/// Each node is ranked by `(hash(seed, id), id)` where the hash is a framed
/// BLAKE3 content address over the seed and the node identity; the `count`
/// lowest-ranked nodes are the pivots. The ranking depends only on the seed and
/// the identity set, so the pivot set is seed-pinned and worker-count invariant,
/// and changing the seed reproducibly reselects the sample.
pub fn select_pivots(graph: &IndexedGraph, count: u64, seed: u64) -> Vec<usize> {
    let n = graph.len();
    let take = (count as usize).min(n);
    let mut ranked: Vec<(u64, CxId, usize)> = (0..n)
        .map(|index| {
            let id = graph.id(index);
            (pivot_hash(seed, id), id, index)
        })
        .collect();
    ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut pivots: Vec<usize> = ranked.into_iter().take(take).map(|entry| entry.2).collect();
    pivots.sort_unstable();
    pivots
}

fn pivot_hash(seed: u64, id: CxId) -> u64 {
    let digest = content_address([
        PIVOT_HASH_TAG,
        &seed.to_be_bytes(),
        id.as_bytes().as_slice(),
    ]);
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// Brandes betweenness accumulation over a directed unweighted graph from the
/// given source set. With `sources == 0..n` this is exact betweenness; a subset
/// yields the standard single-source-sampled estimator (unscaled — callers
/// normalize by the maximum, which cancels the scale).
pub fn brandes(graph: &IndexedGraph, sources: &[usize]) -> Vec<f64> {
    let n = graph.len();
    let mut centrality = vec![0.0_f64; n];
    let mut sigma = vec![0.0_f64; n];
    let mut distance = vec![-1_i64; n];
    let mut delta = vec![0.0_f64; n];
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut stack: Vec<usize> = Vec::with_capacity(n);
    let mut queue: VecDeque<usize> = VecDeque::new();

    for &source in sources {
        // Reset only the nodes touched by the previous source would require a
        // dirty list; a full reset per source keeps the code branch-free and is
        // still O(V + E) per source, matching Brandes' documented cost.
        for value in sigma.iter_mut() {
            *value = 0.0;
        }
        for value in distance.iter_mut() {
            *value = -1;
        }
        for value in delta.iter_mut() {
            *value = 0.0;
        }
        for list in predecessors.iter_mut() {
            list.clear();
        }
        stack.clear();
        queue.clear();

        sigma[source] = 1.0;
        distance[source] = 0;
        queue.push_back(source);

        while let Some(node) = queue.pop_front() {
            stack.push(node);
            for &neighbor in graph.out_neighbors(node) {
                if distance[neighbor] < 0 {
                    distance[neighbor] = distance[node] + 1;
                    queue.push_back(neighbor);
                }
                if distance[neighbor] == distance[node] + 1 {
                    sigma[neighbor] += sigma[node];
                    predecessors[neighbor].push(node);
                }
            }
        }

        while let Some(node) = stack.pop() {
            for &predecessor in &predecessors[node] {
                let contribution = (sigma[predecessor] / sigma[node]) * (1.0 + delta[node]);
                delta[predecessor] += contribution;
            }
            if node != source {
                centrality[node] += delta[node];
            }
        }
    }
    centrality
}

fn normalize_permille(raw: &[f64]) -> Vec<u64> {
    let max = raw.iter().copied().fold(0.0_f64, f64::max);
    if max <= 0.0 {
        return vec![0_u64; raw.len()];
    }
    raw.iter()
        .map(|&value| ((value / max) * 1000.0).round() as u64)
        .collect()
}
