//! Index-time grounded-label **seed producer** for live label propagation (#390).
//!
//! The propagation machinery in [`crate::label_propagation`] reads its seeds,
//! edges, and tombstones from persisted Graph CF rows. Nothing produced those
//! rows at index time, so on a real corpus (the `cbm/` tree) propagation always
//! starved: `propagate_labels_over_vault` read zero seed rows and reported the
//! honest but useless `zero_seed_scope`, and `kernel_context` stayed partial.
//!
//! This module closes that gap by deriving grounded label **seeds from real
//! persisted data** — never invented labels:
//!
//! 1. **Kernel membership** (blueprint 5.9 / P7 "grounded labels harmonically
//!    extended over the association graph"). The kernel build already persists a
//!    [`KernelArtifact`] at index time (`persist_index_time_kernel_artifact` →
//!    `build_and_persist_kernel`). Its members are the measured core of the
//!    codebase: each is a grounded, provenance-carrying architectural property.
//!    Every kernel member becomes a [`KERNEL_CORE_LABEL`] seed whose confidence
//!    is the member's own measured combined score (permille, clamped into the
//!    seed domain — a measurement, not a magic constant, invariant 4), and whose
//!    provenance references the exact persisted kernel artifact + member id.
//! 2. **Caller-supplied grounded labels** (`extra_seeds`) — e.g. the server
//!    folding in `AnchorKind::Label(..)` anchors. Kept decoupled so this crate
//!    does not depend on `astrolabe-anchors`. Deduplicated against the kernel
//!    seeds on `(label, symbol_id)`; kernel seeds win a collision.
//!
//! The label **graph** is the persisted composite kernel graph projection
//! (`ensure_graph_projection_csr`): the same association graph the kernel was
//! built over, so seeds and edges share one `CxId`-hex symbol space. Seeds and
//! edges are persisted through [`persist_label_graph`] (Graph CF rows, ledger
//! paired, readback-verified) and propagation runs through
//! [`propagate_labels_over_vault`] (Kernel CF label rows, ledger paired,
//! readback-verified) — this module adds no new persistence path, only the
//! honest seed derivation that feeds the existing verified ones.
//!
//! Honesty: a corpus with no kernel artifact and no caller seeds derives zero
//! seeds; the graph reconciles to empty and propagation reports `zero_seed_scope`
//! truthfully rather than inventing labels. Determinism: kernel members are
//! ascending by `CxId` and the CSR is deterministic, so the same vault yields
//! byte-identical seed rows, edge rows, and propagated rows.

use std::collections::BTreeSet;

use astrolabe_kernel::{
    KernelArtifact, LabelGraphEdge, LabelPropagationConfig, LabelSeed,
    MAX_SEED_CONFIDENCE_MILLIPOINTS, MIN_SEED_CONFIDENCE_MILLIPOINTS,
};
use calyx_aster::vault::AsterVault;
use calyx_core::Clock;

use crate::graph_projection::{
    GraphProjectionBuildOptions, GraphProjectionCsr, GraphProjectionKind,
    ensure_graph_projection_csr,
};
use crate::kernel_artifact::read_persisted_kernel_artifact;
use crate::label_propagation::{
    LabelGraphPersistReport, LivePropagationReport, persist_label_graph,
    propagate_labels_over_vault,
};
use crate::registry::IngestResult;

/// The grounded label name a persisted kernel member seeds. Fixed (never
/// derived from user text), so the label space is closed and auditable: a symbol
/// carries `kernel-core` provisionally exactly insofar as it is within
/// propagation reach of a real kernel member.
pub const KERNEL_CORE_LABEL: &str = "kernel-core";

/// Service actor recorded on the seed-graph and propagation ledger commits.
pub const LABEL_SEED_ACTOR: &str = "astrolabe-label-seeds";

/// Reason a scope produced no grounded seeds — surfaced so the caller can label
/// the honest empty rather than guess. Distinct from the propagation report's
/// own `zero_seed_scope` empty reason (which this then also carries).
pub const NO_GROUNDED_LABEL_SOURCE: &str = "no_grounded_label_source";

/// Outcome of one index-time seed-derive + persist + propagate pass.
#[derive(Debug, Clone)]
pub struct IndexTimeLabelReport {
    /// Kernel scope the seeds were derived for (`repo:<project>`).
    pub scope_id: String,
    /// Seeds derived from persisted kernel members.
    pub kernel_member_seed_count: usize,
    /// Caller-supplied grounded seeds actually admitted (post-dedup).
    pub extra_seed_count: usize,
    /// Distinct seeds persisted this pass.
    pub seed_count: usize,
    /// Distinct label-graph edges persisted this pass.
    pub edge_count: usize,
    /// Set when no grounded seed source was available at all
    /// ([`NO_GROUNDED_LABEL_SOURCE`]); `None` when seeds were derived.
    pub seed_source_empty_reason: Option<&'static str>,
    /// Report from persisting the reconciled label graph (seeds + edges).
    pub persist: LabelGraphPersistReport,
    /// Report from the live propagation over the persisted rows.
    pub propagation: LivePropagationReport,
}

/// Derives grounded label seeds from the persisted kernel artifact for `scope_id`
/// plus any `extra_seeds`, builds the label graph from the persisted composite
/// kernel projection, persists both through [`persist_label_graph`], then runs
/// live propagation through [`propagate_labels_over_vault`].
///
/// Every seed is traceable to real persisted state: a kernel-member seed's
/// provenance names the kernel artifact scope, the member `CxId`, and the
/// artifact members-hash; an `extra_seeds` seed carries whatever provenance the
/// caller grounded it with. No label is invented.
///
/// # Errors
///
/// Propagates any vault, projection, persistence, or kernel refusal fail-closed.
/// A scope with no kernel artifact and no caller seeds is **not** an error: it
/// reconciles the label graph to empty and returns a report whose
/// `seed_source_empty_reason` is [`NO_GROUNDED_LABEL_SOURCE`] and whose
/// propagation carries `zero_seed_scope`.
pub fn derive_and_propagate_index_time_labels<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
    extra_seeds: &[LabelSeed],
    options: &GraphProjectionBuildOptions,
    config: &LabelPropagationConfig,
    actor: impl Into<String>,
) -> IngestResult<IndexTimeLabelReport>
where
    C: Clock,
{
    let actor = actor.into();

    // #443 permanent sub-phase timing (env-gated `ASTRO_KERNEL_TIMING`): split
    // the label_propagation phase into artifact read / seed derive / projection /
    // edge extraction / graph persist / propagation (the propagation flood is
    // further sub-timed inside `propagate_labels`). Silent by default.
    let mut timing = astrolabe_kernel::KernelPhaseTiming::start("label_propagation_wrap");
    let artifact = read_persisted_kernel_artifact(vault, scope_id)?;
    let kernel_seeds = artifact
        .as_ref()
        .map(|artifact| kernel_member_seeds(artifact, scope_id))
        .unwrap_or_default();
    let kernel_member_seed_count = kernel_seeds.len();
    timing.lap("read_artifact");

    // Merge, deduplicating on (label, symbol_id). Kernel seeds are added first so
    // they win any collision with a caller seed on the same (label, symbol);
    // persist_label_graph fails closed on a duplicate key, so this dedup is a
    // correctness requirement, not a nicety.
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut seeds = Vec::with_capacity(kernel_seeds.len() + extra_seeds.len());
    for seed in kernel_seeds {
        if seen.insert((seed.label.clone(), seed.symbol_id.clone())) {
            seeds.push(seed);
        }
    }
    let mut extra_seed_count = 0;
    for seed in extra_seeds {
        if seen.insert((seed.label.clone(), seed.symbol_id.clone())) {
            seeds.push(seed.clone());
            extra_seed_count += 1;
        }
    }

    let seed_source_empty_reason = if seeds.is_empty() {
        Some(NO_GROUNDED_LABEL_SOURCE)
    } else {
        None
    };
    timing.lap("seed_derive");

    // Only materialize the projection when there is at least one seed: a seed set
    // implies a real graph (kernel members come from it), and an empty scope must
    // not pay to build a projection just to persist no edges.
    let edges = if seeds.is_empty() {
        Vec::new()
    } else {
        let csr = ensure_graph_projection_csr(vault, GraphProjectionKind::KernelGraph, options)?;
        timing.lap("projection");
        let edges = label_graph_edges_from_csr(&csr);
        timing.lap("edges");
        edges
    };

    let persist = persist_label_graph(vault, &seeds, &edges, &[], actor.clone())?;
    timing.lap("persist_graph");
    let propagation = propagate_labels_over_vault(vault, config, actor)?;
    timing.lap("propagate");

    Ok(IndexTimeLabelReport {
        scope_id: scope_id.to_string(),
        kernel_member_seed_count,
        extra_seed_count,
        seed_count: seeds.len(),
        edge_count: edges.len(),
        seed_source_empty_reason,
        persist,
        propagation,
    })
}

/// Derives one [`KERNEL_CORE_LABEL`] seed per persisted kernel member.
///
/// The symbol id is the member's `CxId` in lowercase hex (its durable version
/// identity, the same space the graph projection edges use). The confidence is
/// the member's measured combined score in permille, clamped into the seed
/// domain `[MIN_SEED_CONFIDENCE_MILLIPOINTS, MAX_SEED_CONFIDENCE_MILLIPOINTS]`.
pub fn kernel_member_seeds(artifact: &KernelArtifact, scope_id: &str) -> Vec<LabelSeed> {
    artifact
        .members
        .iter()
        .map(|member| {
            let symbol_id = member.id.to_string();
            let confidence = member.score_permille.clamp(
                MIN_SEED_CONFIDENCE_MILLIPOINTS,
                MAX_SEED_CONFIDENCE_MILLIPOINTS,
            );
            let provenance = format!(
                "kernel-artifact:scope={scope_id};member={symbol_id};members_hash={}",
                artifact.members_hash
            );
            LabelSeed::new(symbol_id, KERNEL_CORE_LABEL, confidence, provenance)
        })
        .collect()
}

/// Reads the directed composite-kernel CSR out into distinct label-graph edges.
///
/// Each `(src, dst)` window edge becomes one [`LabelGraphEdge`] keyed by the
/// endpoints' `CxId`-hex, deduplicated on `(left, right)` so persist_label_graph
/// never sees a duplicate key (the CSR can carry parallel typed edges between the
/// same pair). Propagation adjacency is undirected, so persisting one row per
/// distinct ordered pair is sufficient and deterministic.
pub fn label_graph_edges_from_csr(csr: &GraphProjectionCsr) -> Vec<LabelGraphEdge> {
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut edges = Vec::new();
    for (src_index, window) in csr.offsets.windows(2).enumerate() {
        let Some(node) = csr.nodes.get(src_index) else {
            continue;
        };
        let left = node.id.to_string();
        for edge in &csr.edges[window[0]..window[1]] {
            let right = edge.dst.to_string();
            if seen.insert((left.clone(), right.clone())) {
                let provenance = format!("graph-projection:kernel:{left}->{right}");
                edges.push(LabelGraphEdge::new(left.clone(), right, provenance));
            }
        }
    }
    edges
}
