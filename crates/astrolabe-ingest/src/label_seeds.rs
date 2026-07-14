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

    let artifact = read_persisted_kernel_artifact(vault, scope_id)?;
    let kernel_seeds = artifact
        .as_ref()
        .map(|artifact| kernel_member_seeds(artifact, scope_id))
        .unwrap_or_default();
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

    let seed_source_empty_reason = if seeds.is_empty() {
        Some(NO_GROUNDED_LABEL_SOURCE)
    } else {
        None
    };

    // Only materialize the projection when there is at least one seed: a seed set
    // implies a real graph (kernel members come from it), and an empty scope must
    // not pay to build a projection just to persist no edges.
    let edges = if seeds.is_empty() {
        Vec::new()
    } else {
        let csr = ensure_graph_projection_csr(vault, GraphProjectionKind::KernelGraph, options)?;
        label_graph_edges_from_csr(&csr)
    };

    let persist = persist_label_graph(vault, &seeds, &edges, &[], actor.clone())?;
    let propagation = propagate_labels_over_vault(vault, config, actor)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_artifact::build_and_persist_kernel;
    use crate::label_propagation::read_propagated_label_rows;
    use crate::sqlite_import::{EdgeGraphRow, SCHEMA_EDGE_ROW, edge_graph_key};
    use astrolabe_domain::{EdgeKind, TrustTag};
    use astrolabe_kernel::KernelBuildConfig;
    use calyx_aster::cf::ColumnFamily;
    use calyx_aster::vault::AsterVault;
    use calyx_core::{CxId, LedgerRef};
    use std::collections::BTreeMap;

    const SCOPE: &str = "repo:demo";

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }

    fn vault() -> AsterVault {
        AsterVault::new(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            b"label-seeds-test",
        )
    }

    fn source_row(
        id: i64,
        src: CxId,
        dst: CxId,
        kind: EdgeKind,
        weight: f32,
    ) -> (Vec<u8>, Vec<u8>) {
        let row = EdgeGraphRow {
            schema: SCHEMA_EDGE_ROW.to_string(),
            project: "demo".to_string(),
            sqlite_edge_id: id,
            source_node_id: id * 10,
            target_node_id: id * 10 + 1,
            src,
            dst,
            edge_type: kind.as_str().to_string(),
            etype: kind.code(),
            local_name_gen: String::new(),
            weight,
            props: serde_json::json!({}),
            properties_json: None,
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            commit: "commit-a".to_string(),
        };
        let key = edge_graph_key(src, dst, kind, "").expect("edge key");
        (key, serde_json::to_vec(&row).expect("edge json"))
    }

    /// The same seven-symbol corpus the kernel-artifact FSV uses, so the built
    /// kernel has real members over a real association graph.
    fn fixture_rows() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            source_row(1, cx(1), cx(2), EdgeKind::Calls, 0.8),
            source_row(2, cx(1), cx(3), EdgeKind::ResolvedCalls, 0.6),
            source_row(3, cx(2), cx(3), EdgeKind::Imports, 1.0),
            source_row(4, cx(2), cx(4), EdgeKind::DependsOn, 0.9),
            source_row(5, cx(3), cx(4), EdgeKind::UsesType, 0.75),
            source_row(6, cx(3), cx(5), EdgeKind::Instantiates, 0.5),
            source_row(7, cx(4), cx(5), EdgeKind::Reads, 0.7),
            source_row(8, cx(4), cx(6), EdgeKind::Writes, 0.65),
            source_row(9, cx(5), cx(6), EdgeKind::Usage, 0.55),
            source_row(10, cx(5), cx(7), EdgeKind::Throws, 0.45),
            source_row(11, cx(6), cx(7), EdgeKind::DataFlows, 0.5),
            source_row(12, cx(1), cx(4), EdgeKind::HttpCalls, 0.5),
            source_row(13, cx(1), cx(5), EdgeKind::Emits, 0.7),
            source_row(14, cx(2), cx(6), EdgeKind::Handles, 0.9),
            source_row(15, cx(3), cx(7), EdgeKind::CrossGrpcCalls, 0.4),
            source_row(17, cx(6), cx(1), EdgeKind::Contains, 1.0),
        ]
    }

    fn write_sources(vault: &AsterVault, rows: Vec<(Vec<u8>, Vec<u8>)>) {
        vault
            .write_cf_batch(
                rows.into_iter()
                    .map(|(key, value)| (ColumnFamily::Graph, key, value)),
            )
            .expect("write source rows");
    }

    fn seed_kernel(vault: &AsterVault) {
        let mut trust = BTreeMap::new();
        trust.insert(cx(1), TrustTag::Trusted);
        trust.insert(cx(4), TrustTag::Provisional);
        build_and_persist_kernel(
            vault,
            SCOPE,
            &trust,
            &KernelBuildConfig::with_registry_defaults(),
            &GraphProjectionBuildOptions::new(),
        )
        .expect("build+persist kernel");
    }

    /// The headline FSV: a real persisted kernel yields real seeds; propagation
    /// over the persisted graph writes real propagated-label rows, read back
    /// independently — never `zero_seed_scope`.
    #[test]
    fn kernel_membership_seeds_propagate_and_read_back() {
        let vault = vault();
        write_sources(&vault, fixture_rows());
        seed_kernel(&vault);

        let report = derive_and_propagate_index_time_labels(
            &vault,
            SCOPE,
            &[],
            &GraphProjectionBuildOptions::new(),
            &LabelPropagationConfig::default(),
            LABEL_SEED_ACTOR,
        )
        .expect("derive+propagate");

        assert!(
            report.kernel_member_seed_count > 0,
            "the persisted kernel has members to seed from"
        );
        assert_eq!(report.seed_count, report.kernel_member_seed_count);
        assert_eq!(report.extra_seed_count, 0);
        assert!(report.edge_count > 0, "the association graph has edges");
        assert!(report.seed_source_empty_reason.is_none());

        // Seeds were persisted and read back (LabelGraphPersistReport FSV ack).
        assert_eq!(report.persist.seed_count, report.seed_count);
        assert!(
            report.persist.fsv_ack.is_some(),
            "seed rows readback-verified"
        );

        // Propagation produced labels — NOT zero_seed_scope — and read them back.
        assert!(report.propagation.seeds_read > 0);
        assert_ne!(
            report.propagation.empty_reason.as_deref(),
            Some("zero_seed_scope"),
            "seeds are present, so propagation must not report a starved scope"
        );
        assert_eq!(report.propagation.trust, "provisional");

        // Independent readback of the persisted Kernel CF propagated-label rows.
        let persisted = read_propagated_label_rows(&vault).expect("read propagated rows");
        assert!(
            !persisted.is_empty(),
            "at least one non-seed symbol carries a propagated kernel-core label"
        );
        for row in &persisted {
            assert_eq!(row.row.label, KERNEL_CORE_LABEL);
            assert_eq!(row.row.trust, "provisional");
            assert!(row.row.confidence_millipoints < 1000);
            // Every propagated row traces back to a kernel-artifact seed.
            assert!(
                row.row
                    .seed_provenance_ref
                    .starts_with("kernel-artifact:scope="),
                "seed provenance is the persisted kernel artifact, got {:?}",
                row.row.seed_provenance_ref
            );
        }
    }

    /// A caller-supplied grounded label (as the server folds `AnchorKind::Label`)
    /// seeds propagation on its own symbol space and is traceable to its own
    /// provenance.
    #[test]
    fn extra_grounded_seed_is_admitted_and_propagates() {
        let vault = vault();
        write_sources(&vault, fixture_rows());
        seed_kernel(&vault);

        // Ground a "security-sensitive" label on cx(1) (the hottest symbol),
        // exactly as an anchor-derived seed would arrive from the server.
        let extra = vec![LabelSeed::new(
            cx(1).to_string(),
            "security-sensitive",
            900,
            "anchor:label:security-sensitive:cx1",
        )];

        let report = derive_and_propagate_index_time_labels(
            &vault,
            SCOPE,
            &extra,
            &GraphProjectionBuildOptions::new(),
            &LabelPropagationConfig::default(),
            LABEL_SEED_ACTOR,
        )
        .expect("derive+propagate");

        assert_eq!(
            report.extra_seed_count, 1,
            "the grounded label was admitted"
        );

        let persisted = read_propagated_label_rows(&vault).expect("read propagated rows");
        let security: Vec<_> = persisted
            .iter()
            .filter(|row| row.row.label == "security-sensitive")
            .collect();
        assert!(
            !security.is_empty(),
            "security-sensitive extends to cx(1)'s neighbours"
        );
        for row in &security {
            assert_eq!(
                row.row.seed_provenance_ref,
                "anchor:label:security-sensitive:cx1"
            );
        }
    }

    /// Edge triad #1: no kernel artifact and no caller seeds ⇒ honest
    /// `zero_seed_scope`, not an invented label.
    #[test]
    fn no_seed_source_stays_zero_seed_scope() {
        let vault = vault();
        // Note: a graph exists but NO kernel artifact was persisted.
        write_sources(&vault, fixture_rows());

        let report = derive_and_propagate_index_time_labels(
            &vault,
            SCOPE,
            &[],
            &GraphProjectionBuildOptions::new(),
            &LabelPropagationConfig::default(),
            LABEL_SEED_ACTOR,
        )
        .expect("derive+propagate");

        assert_eq!(report.seed_count, 0);
        assert_eq!(report.edge_count, 0);
        assert_eq!(
            report.seed_source_empty_reason,
            Some(NO_GROUNDED_LABEL_SOURCE)
        );
        assert_eq!(
            report.propagation.empty_reason.as_deref(),
            Some("zero_seed_scope")
        );
        let persisted = read_propagated_label_rows(&vault).expect("read propagated rows");
        assert!(persisted.is_empty(), "no labels invented from thin air");
    }

    /// Edge triad #2: determinism — two independent vaults built from the same
    /// corpus produce byte-identical persisted seed rows, edge rows, and
    /// propagated-label rows.
    #[test]
    fn same_corpus_yields_byte_identical_rows() {
        let build = || {
            let vault = vault();
            write_sources(&vault, fixture_rows());
            seed_kernel(&vault);
            derive_and_propagate_index_time_labels(
                &vault,
                SCOPE,
                &[],
                &GraphProjectionBuildOptions::new(),
                &LabelPropagationConfig::default(),
                LABEL_SEED_ACTOR,
            )
            .expect("derive+propagate");
            let propagated = read_propagated_label_rows(&vault)
                .expect("read propagated rows")
                .into_iter()
                .map(|row| (row.key, row.row))
                .collect::<Vec<_>>();
            let seed_rows = vault
                .scan_cf_range_at(
                    vault.latest_seq(),
                    ColumnFamily::Graph,
                    &calyx_aster::cf::prefix_range(crate::label_propagation::LABEL_SEED_ROW_PREFIX),
                )
                .expect("scan seed rows");
            (seed_rows, propagated)
        };
        let (seeds_a, propagated_a) = build();
        let (seeds_b, propagated_b) = build();
        assert_eq!(
            seeds_a, seeds_b,
            "seed rows are byte-identical across vaults"
        );
        assert_eq!(
            propagated_a, propagated_b,
            "propagated rows are byte-identical across vaults"
        );
        assert!(!propagated_a.is_empty());
    }

    /// Edge triad #3: a duplicate caller seed colliding with a kernel seed on
    /// `(label, symbol_id)` is deduped (kernel wins), so persistence never fails
    /// closed on a duplicate key — the merge is total.
    #[test]
    fn colliding_caller_seed_is_deduped_not_refused() {
        let vault = vault();
        write_sources(&vault, fixture_rows());
        seed_kernel(&vault);

        // Read a real member id and collide a caller seed on (kernel-core, id).
        let artifact = read_persisted_kernel_artifact(&vault, SCOPE)
            .expect("read artifact")
            .expect("artifact present");
        let member_id = artifact.members[0].id.to_string();
        let extra = vec![LabelSeed::new(
            member_id,
            KERNEL_CORE_LABEL,
            500,
            "caller:should-lose-to-kernel",
        )];

        let report = derive_and_propagate_index_time_labels(
            &vault,
            SCOPE,
            &extra,
            &GraphProjectionBuildOptions::new(),
            &LabelPropagationConfig::default(),
            LABEL_SEED_ACTOR,
        )
        .expect("derive+propagate must not fail closed on the collision");

        assert_eq!(
            report.extra_seed_count, 0,
            "colliding caller seed was dropped"
        );
        assert_eq!(report.seed_count, report.kernel_member_seed_count);
    }
}
