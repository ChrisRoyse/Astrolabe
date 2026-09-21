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
//!    extended over the association graph"). The caller supplies the artifact
//!    and composite projection selected and independently read back from one
//!    atomic complete kernel generation. Its members are the measured core of the
//!    codebase: each is a grounded, provenance-carrying architectural property.
//!    Every kernel member becomes a [`KERNEL_CORE_LABEL`] seed whose confidence
//!    is the member's own measured combined score (permille). A value outside
//!    the declared seed domain is source drift and refuses before persistence;
//!    it is never clamped into a different measurement. Provenance references
//!    the exact persisted kernel artifact + member id.
//! 2. **Caller-supplied grounded labels** (`extra_seeds`) — e.g. the server
//!    folding in `AnchorKind::Label(..)` anchors. Kept decoupled so this crate
//!    does not depend on `astrolabe-anchors`. Deduplicated against the kernel
//!    seeds on `(label, symbol_id)`; kernel seeds win a collision.
//!
//! The label **graph** is that same persisted composite kernel graph projection,
//! so seeds and edges share one `CxId`-hex symbol space. Seeds and
//! edges are persisted through [`persist_label_graph`] (Graph CF rows, ledger
//! paired, readback-verified) and propagation runs through
//! [`propagate_labels_over_vault`] (Kernel CF label rows, ledger paired,
//! readback-verified) — this module adds no new persistence path, only the
//! honest seed derivation that feeds the existing verified ones.
//!
//! Honesty: an absent/empty/mismatched artifact or projection is a refusal; the
//! caller cannot substitute an empty label surface for a broken mandatory kernel
//! generation. Determinism: kernel members are
//! ascending by `CxId` and the CSR is deterministic, so the same vault yields
//! byte-identical seed rows, edge rows, and propagated rows.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_kernel::{
    KernelArtifact, LabelGraphEdge, LabelPropagationConfig, LabelSeed,
    MAX_SEED_CONFIDENCE_MILLIPOINTS, MIN_SEED_CONFIDENCE_MILLIPOINTS,
};
use calyx_aster::vault::AsterVault;
use calyx_core::Clock;

use crate::graph_projection::GraphProjectionCsr;
use crate::kernel_artifact::kernel_graph_from_projection_csr;
use crate::label_propagation::{
    LabelGraphPersistReport, LivePropagationReport, persist_label_graph,
    propagate_labels_over_vault,
};
use crate::registry::{IngestError, IngestResult};

/// The grounded label name a persisted kernel member seeds. Fixed (never
/// derived from user text), so the label space is closed and auditable: a symbol
/// carries `kernel-core` provisionally exactly insofar as it is within
/// propagation reach of a real kernel member.
pub const KERNEL_CORE_LABEL: &str = "kernel-core";

/// Service actor recorded on the seed-graph and propagation ledger commits.
pub const LABEL_SEED_ACTOR: &str = "astrolabe-label-seeds";
/// The caller supplied an absent, empty, or source-mismatched composite kernel
/// generation to the label producer.
pub const ASTRO_KERNEL_LABEL_SOURCE_INVALID: &str = "ASTRO_KERNEL_LABEL_SOURCE_INVALID";

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
/// The artifact and projection are mandatory and must reproduce the exact
/// persisted source/config identity; absence is never converted to an empty
/// label surface.
pub fn derive_and_propagate_index_time_labels<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
    artifact: &KernelArtifact,
    projection: &GraphProjectionCsr,
    extra_seeds: &[LabelSeed],
    config: &LabelPropagationConfig,
    actor: impl Into<String>,
) -> IngestResult<IndexTimeLabelReport>
where
    C: Clock,
{
    let actor = actor.into();

    // #443 permanent sub-phase timing (env-gated `ASTRO_KERNEL_TIMING`): split
    // the label_propagation phase into source validation / seed derive /
    // edge extraction / graph persist / propagation (the propagation flood is
    // further sub-timed inside `propagate_labels`). Silent by default.
    let mut timing = astrolabe_kernel::KernelPhaseTiming::start("label_propagation_wrap");
    if artifact.scope_id != scope_id || artifact.members.is_empty() {
        return Err(IngestError::refused(
            ASTRO_KERNEL_LABEL_SOURCE_INVALID,
            format!(
                "label propagation requires one nonempty composite artifact for scope {scope_id:?}; observed_scope={:?} observed_members={}",
                artifact.scope_id,
                artifact.members.len(),
            ),
            "preserve the staged publication and pass the artifact selected through the exact current composite pointer",
        ));
    }
    let graph = kernel_graph_from_projection_csr(projection, &BTreeMap::new())?;
    astrolabe_kernel::verify_kernel_source_projection_identity(
        &graph,
        &artifact.config,
        &artifact.source_identity,
    )?;
    timing.lap("validate_source");
    let kernel_seeds = kernel_member_seeds(artifact, scope_id)?;
    let kernel_member_seed_count = kernel_seeds.len();

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

    if seeds.is_empty() {
        return Err(IngestError::refused(
            ASTRO_KERNEL_LABEL_SOURCE_INVALID,
            format!(
                "validated composite artifact for scope {scope_id:?} produced no grounded label seeds"
            ),
            "repair the artifact member roster before running label propagation",
        ));
    }
    let seed_source_empty_reason = None;
    timing.lap("seed_derive");

    let edges = label_graph_edges_from_csr(projection);
    timing.lap("edges");

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
/// the member's exact measured combined score in permille. Any value outside
/// `[MIN_SEED_CONFIDENCE_MILLIPOINTS, MAX_SEED_CONFIDENCE_MILLIPOINTS]` is a
/// coded source refusal; label derivation never changes the measurement.
///
/// # Errors
///
/// Returns [`ASTRO_KERNEL_LABEL_SOURCE_INVALID`] with the exact scope, member,
/// and observed score when a persisted artifact carries an invalid confidence.
pub fn kernel_member_seeds(
    artifact: &KernelArtifact,
    scope_id: &str,
) -> IngestResult<Vec<LabelSeed>> {
    artifact
        .members
        .iter()
        .map(|member| {
            let symbol_id = member.id.to_string();
            let confidence = member.score_permille;
            if !(MIN_SEED_CONFIDENCE_MILLIPOINTS..=MAX_SEED_CONFIDENCE_MILLIPOINTS)
                .contains(&confidence)
            {
                return Err(IngestError::refused(
                    ASTRO_KERNEL_LABEL_SOURCE_INVALID,
                    format!(
                        "kernel label source for scope {scope_id:?} member {symbol_id} carries score_permille={confidence}, outside the exact seed domain {MIN_SEED_CONFIDENCE_MILLIPOINTS}..={MAX_SEED_CONFIDENCE_MILLIPOINTS}"
                    ),
                    "repair and atomically republish the kernel artifact from valid measured member scores; label propagation never clamps persisted measurements",
                ));
            }
            let provenance = format!(
                "kernel-artifact:scope={scope_id};member={symbol_id};members_hash={}",
                artifact.members_hash
            );
            Ok(LabelSeed::new(
                symbol_id,
                KERNEL_CORE_LABEL,
                confidence,
                provenance,
            ))
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
