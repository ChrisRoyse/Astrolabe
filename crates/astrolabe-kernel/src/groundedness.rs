//! Groundedness scoring: proximity to Trusted anchors plus a frequency bonus (#37).
//!
//! Groundedness for code (blueprint 09 §1) = BFS distance (≤ `hop_limit` hops)
//! to any Trusted anchor, combined with a hot-symbol frequency bonus
//! `ln(min(freq, freq_cap) + 1) / ln(freq_cap + 1) × freq_bonus`. Both parts are
//! quantized to permille immediately so the score that flows into the kernel
//! artifact is an integer — no float ever reaches the persisted bytes, which is
//! what makes the artifact byte-identical across runs.

use std::collections::VecDeque;

use crate::kernel_graph::IndexedGraph;

/// Per-node groundedness measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct GroundednessResult {
    /// Hop distance to the nearest Trusted anchor within `hop_limit`, or `None`
    /// when no Trusted anchor is reachable within the limit.
    pub distance: Vec<Option<u64>>,
    /// Groundedness score per node in permille `[0, 1000]`: the reachability
    /// term plus the frequency bonus, clamped to 1000.
    pub permille: Vec<u64>,
    /// Whether any Trusted anchor exists in the graph at all. When `false`,
    /// every reachability term is zero and the kernel is anchor-ungrounded.
    pub has_trusted_anchor: bool,
}

/// Computes groundedness for every node.
///
/// The reachability BFS is undirected: a symbol is grounded when it sits near a
/// tested/verified region regardless of call direction. The reachability term
/// decays linearly with hop distance — distance 0 (the anchor itself) scores a
/// full `1000`, and each hop out to `hop_limit` steps down evenly, with
/// unreachable nodes scoring `0`.
pub fn score_groundedness(
    graph: &IndexedGraph,
    hop_limit: u64,
    freq_cap: u64,
    freq_bonus_permille: u64,
) -> GroundednessResult {
    let n = graph.len();
    let distance = trusted_anchor_distance(graph, hop_limit);
    let has_trusted_anchor =
        distance.iter().any(Option::is_some) || (0..n).any(|index| graph.is_trusted_anchor(index));

    let permille = (0..n)
        .map(|index| {
            let reach = reachability_permille(distance[index], hop_limit);
            let bonus =
                frequency_bonus_permille(graph.frequency(index), freq_cap, freq_bonus_permille);
            (reach + bonus).min(1000)
        })
        .collect();

    GroundednessResult {
        distance,
        permille,
        has_trusted_anchor,
    }
}

/// Multi-source BFS from every Trusted anchor over the undirected graph, capped
/// at `hop_limit`. Returns the hop distance to the nearest anchor per node.
fn trusted_anchor_distance(graph: &IndexedGraph, hop_limit: u64) -> Vec<Option<u64>> {
    let n = graph.len();
    let mut distance = vec![None; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (index, dist) in distance.iter_mut().enumerate() {
        if graph.is_trusted_anchor(index) {
            *dist = Some(0);
            queue.push_back(index);
        }
    }
    while let Some(node) = queue.pop_front() {
        let node_distance = distance[node].expect("queued node has a distance");
        if node_distance >= hop_limit {
            continue;
        }
        for &neighbor in graph.undirected_neighbors(node) {
            if distance[neighbor].is_none() {
                distance[neighbor] = Some(node_distance + 1);
                queue.push_back(neighbor);
            }
        }
    }
    distance
}

fn reachability_permille(distance: Option<u64>, hop_limit: u64) -> u64 {
    match distance {
        Some(d) if d <= hop_limit => {
            let span = hop_limit + 1;
            (span - d).saturating_mul(1000) / span
        }
        _ => 0,
    }
}

fn frequency_bonus_permille(frequency: u64, freq_cap: u64, freq_bonus_permille: u64) -> u64 {
    if freq_bonus_permille == 0 || freq_cap == 0 {
        return 0;
    }
    let capped = frequency.min(freq_cap);
    let numerator = ((capped as f64) + 1.0).ln();
    let denominator = ((freq_cap as f64) + 1.0).ln();
    if denominator <= 0.0 {
        return 0;
    }
    let ratio = (numerator / denominator).clamp(0.0, 1.0);
    (ratio * freq_bonus_permille as f64).round() as u64
}
