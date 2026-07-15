//! Corpus-scale Loom weave acceptance report (#870).
//!
//! Pure, fail-closed measurement over the **between-document** directed
//! association graph the corpus `weave-loom` command builds: nodes are
//! constellations, directed edges are the panel-measured k-NN associations. A
//! node is *grounded* when it reaches an anchored node within
//! `max_groundedness_distance` hops (BFS over [`groundedness_distance`]). This is
//! the `groundedness_fraction > 0` acceptance metric for #870 — computed from the
//! real graph topology, never assumed.

use std::collections::HashSet;

use calyx_core::CxId;
use calyx_paths::AssocGraph;
use serde::{Deserialize, Serialize};

use crate::{LodestarError, Result, groundedness_distance};

pub const CORPUS_WEAVE_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CorpusWeaveReportParams {
    /// Max BFS hops from a node to an anchor for the node to count as grounded.
    pub max_groundedness_distance: usize,
    /// Acceptance gate: report passes when `groundedness_fraction >= this`.
    pub min_groundedness_fraction: f32,
}

impl Default for CorpusWeaveReportParams {
    fn default() -> Self {
        Self {
            max_groundedness_distance: 3,
            // #870 acceptance is "groundedness_fraction > 0"; the smallest
            // strictly-positive fraction on any non-empty corpus is 1/N, so any
            // positive threshold below that would always pass. Require at least
            // one grounded node (the gate is a real, non-trivial floor only when
            // the caller raises it).
            min_groundedness_fraction: f32::MIN_POSITIVE,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CorpusWeaveReport {
    pub schema_version: u32,
    pub node_count: usize,
    pub edge_count: usize,
    pub graph_density: f32,
    pub anchor_count: usize,
    pub grounded_node_count: usize,
    pub groundedness_fraction: f32,
    pub max_groundedness_distance: usize,
    pub min_groundedness_fraction: f32,
    pub gate_passed: bool,
}

/// Measure the between-doc association graph for #870 acceptance.
///
/// Fails closed on an empty graph ([`LodestarError::KernelEmptyGraph`]) and on
/// invalid params ([`LodestarError::KernelInvalidParams`]). `anchors` may contain
/// ids not present in the graph (they are ignored); a node is grounded iff it is
/// itself an anchor or reaches one within `max_groundedness_distance` hops.
pub fn corpus_weave_report(
    graph: &AssocGraph,
    anchors: &[CxId],
    params: &CorpusWeaveReportParams,
) -> Result<CorpusWeaveReport> {
    validate(graph, params)?;
    let node_count = graph.node_count();
    let edge_count = graph.edge_count();

    // Anchor membership is the common, hottest case (a corpus can be fully
    // anchored). Resolve it in O(1) via a set so the report is O(N) overall; fall
    // back to the BFS reachability walk only for non-anchor nodes. (A linear
    // `anchors.contains` per node would be O(N*anchors) ~ O(N^2) at corpus scale.)
    let anchor_set: HashSet<CxId> = anchors.iter().copied().collect();
    let mut grounded_node_count = 0_usize;
    for id in graph.node_ids() {
        let grounded = anchor_set.contains(&id)
            || groundedness_distance(graph, id, anchors, params.max_groundedness_distance)?
                .is_some();
        if grounded {
            grounded_node_count += 1;
        }
    }
    let groundedness_fraction = grounded_node_count as f32 / node_count as f32;

    Ok(CorpusWeaveReport {
        schema_version: CORPUS_WEAVE_REPORT_SCHEMA_VERSION,
        node_count,
        edge_count,
        graph_density: graph_density(node_count, edge_count),
        anchor_count: anchors.len(),
        grounded_node_count,
        groundedness_fraction,
        max_groundedness_distance: params.max_groundedness_distance,
        min_groundedness_fraction: params.min_groundedness_fraction,
        gate_passed: groundedness_fraction >= params.min_groundedness_fraction,
    })
}

fn validate(graph: &AssocGraph, params: &CorpusWeaveReportParams) -> Result<()> {
    if graph.is_empty() {
        return Err(LodestarError::KernelEmptyGraph);
    }
    if params.max_groundedness_distance == 0 {
        return invalid("max_groundedness_distance must be greater than zero");
    }
    if !params.min_groundedness_fraction.is_finite()
        || !(0.0..=1.0).contains(&params.min_groundedness_fraction)
    {
        return invalid("min_groundedness_fraction must be finite and in [0,1]");
    }
    Ok(())
}

fn graph_density(node_count: usize, edge_count: usize) -> f32 {
    let max_edges = node_count.saturating_mul(node_count.saturating_sub(1));
    if max_edges == 0 {
        0.0
    } else {
        edge_count as f32 / max_edges as f32
    }
}

fn invalid<T>(detail: &str) -> Result<T> {
    Err(LodestarError::KernelInvalidParams {
        detail: detail.to_string(),
    })
}
