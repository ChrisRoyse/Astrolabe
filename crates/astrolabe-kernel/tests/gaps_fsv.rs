//! Full State Verification for the grounding-gap report and coverage-vs-
//! importance quadrant (#39).
//!
//! The gap boundary is pinned against a *real* built kernel, not a hand-stuffed
//! artifact: a line graph anchored at one end is built with a recall config that
//! forces every node into the kernel, so the persisted member set carries the
//! genuine `grounded` flag the build computed at hop_limit=3. The report is then
//! read back from that artifact and the gap set is asserted exactly — a member
//! with a Trusted anchor at exactly hop 3 is excluded, one hop further (hop 4) is
//! a gap. Boundary pinned by a hand-computable topology.

use astrolabe_domain::TrustTag;
use astrolabe_domain::calyx::CxId;
use astrolabe_kernel::gaps::{GapQuadrant, coverage_importance_quadrant, grounding_gap_report};
use astrolabe_kernel::kernel_build::KernelBuildConfig;
use astrolabe_kernel::{
    KernelGraph, KernelGraphEdge, KernelGraphNode, QuadrantConfig, build_kernel,
};

fn cx(n: u8) -> CxId {
    CxId::from_bytes([n; 16])
}

fn node(n: u8, frequency: u64, trust: Option<TrustTag>) -> KernelGraphNode {
    KernelGraphNode::new(cx(n), frequency, trust)
}

fn edge(a: u8, b: u8) -> KernelGraphEdge {
    KernelGraphEdge::new(cx(a), cx(b), 1.0)
}

/// A recall config that forces every node into the kernel: at answer radius 0 a
/// member covers only itself, so a 1000-permille recall gate is reachable only
/// when every symbol is a member. This lets the gap-boundary test observe the
/// `grounded` flag for *every* node of the fixture, including the hop-3 and hop-4
/// nodes the boundary hinges on. The groundedness hop limit stays at the
/// registry default (3).
fn force_all_members_config() -> KernelBuildConfig {
    KernelBuildConfig {
        recall_answer_radius_hops: 0,
        recall_min_permille: 1000,
        ..KernelBuildConfig::with_registry_defaults()
    }
}

#[test]
fn gap_boundary_excludes_hop3_includes_hop4() {
    // Line graph: 0 -> 1 -> 2 -> 3 -> 4 -> 5, node 0 is the only Trusted anchor.
    // Undirected anchor distance of node i is exactly i. With hop_limit=3, nodes
    // 0..=3 are grounded and nodes 4,5 are gaps. CxId = [i;16] so node index == i.
    let nodes = vec![
        node(0, 1, Some(TrustTag::Trusted)),
        node(1, 1, None),
        node(2, 1, None),
        node(3, 1, None),
        node(4, 1, None),
        node(5, 1, None),
    ];
    let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 5)];
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let config = force_all_members_config();
    let artifact = build_kernel(&graph, "line-scope", &config).unwrap();

    // Every node forced into the kernel by the radius-0 recall gate.
    assert_eq!(artifact.member_count, 6, "recall gate forces all members");
    assert!(artifact.anchor_grounded);

    let report = grounding_gap_report(&artifact);
    assert_eq!(report.hop_limit, 3);
    assert!(report.has_trusted_anchor);

    let gap_ids: std::collections::BTreeSet<CxId> = report.gaps.iter().map(|gap| gap.id).collect();
    let expected: std::collections::BTreeSet<CxId> = [cx(4), cx(5)].into_iter().collect();
    assert_eq!(
        gap_ids, expected,
        "hop-3 excluded (node 3), hop-4 included (node 4)"
    );

    // Node 3 (exactly hop 3) is a grounded member, not a gap — the boundary.
    let node3 = artifact
        .members
        .iter()
        .find(|member| member.id == cx(3))
        .expect("node 3 is a member");
    assert!(node3.grounded, "hop-3 node is grounded, excluded from gaps");
    let node4 = artifact
        .members
        .iter()
        .find(|member| member.id == cx(4))
        .expect("node 4 is a member");
    assert!(!node4.grounded, "hop-4 node is a gap");
}

#[test]
fn quadrant_isolates_critical_unverified_from_real_build() {
    // Same line topology; the quadrant places every member. The far nodes (4,5)
    // have anchor-density 0 (unreachable within 3 hops) — if their kernel score
    // clears the importance threshold they are dragons; otherwise peripheral. We
    // assert the classification is consistent with the persisted member rows.
    let nodes = vec![
        node(0, 1, Some(TrustTag::Trusted)),
        node(1, 1, None),
        node(2, 1, None),
        node(3, 1, None),
        node(4, 1, None),
        node(5, 1, None),
    ];
    let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 5)];
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let artifact = build_kernel(&graph, "line-scope", &force_all_members_config()).unwrap();

    let config = QuadrantConfig::with_registry_defaults();
    let quadrant = coverage_importance_quadrant(&artifact, &config).unwrap();
    assert_eq!(quadrant.member_count, 6);
    assert_eq!(quadrant.trust, "verified");

    // Independent recompute: every gap member (grounded == false) has anchor
    // density below the covered threshold, so it must land in an *unverified*
    // quadrant; every grounded member must land in a *covered* quadrant.
    for point in &quadrant.points {
        let member = artifact
            .members
            .iter()
            .find(|member| member.id == point.id)
            .unwrap();
        assert_eq!(point.grounded, member.grounded);
        assert_eq!(point.anchor_density_permille, member.groundedness_permille);
        let expected_covered =
            member.groundedness_permille >= config.anchor_density_threshold_permille;
        let is_covered = matches!(
            point.quadrant,
            GapQuadrant::CriticalCovered | GapQuadrant::PeripheralCovered
        );
        assert_eq!(is_covered, expected_covered);
    }

    // Counts partition the member set.
    let total = quadrant.critical_unverified_count
        + quadrant.critical_covered_count
        + quadrant.peripheral_unverified_count
        + quadrant.peripheral_covered_count;
    assert_eq!(total, 6);
}
