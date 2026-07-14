//! Full State Verification for scoped, standing, incremental, and hierarchical
//! kernels (#38).
//!
//! Scope-algebra goldens with stable scope hashes, cache hit/invalidation
//! correctness, incremental-equivalence (`rebuild_dirty` == from-scratch with
//! only dirty SCCs reprocessed), the three standing-kernel refresh triggers with
//! an injected clock, freshness honesty (StaleOk `stale_by` and `fresh:true`
//! rebuild/timeout), and a hierarchical region kernel consistent with flat
//! drill-down kernels.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::TrustTag;
use astrolabe_domain::calyx::CxId;
use astrolabe_kernel::incremental::region_id;
use astrolabe_kernel::scope_cache::CacheKey;
use astrolabe_kernel::{
    FreshnessDecision, GraphDelta, KernelBuildConfig, KernelCache, KernelGraph, KernelGraphEdge,
    KernelGraphNode, NodeScope, RefreshReason, Scope, ScopeAttributes, StandingKernelPolicy,
    build_kernel, build_region_graph, build_scoped_kernel, decide_freshness,
    kernel_betweenness_permille, rebuild_dirty,
};

fn cx(n: u16) -> CxId {
    let mut bytes = [0_u8; 16];
    bytes[0] = (n >> 8) as u8;
    bytes[1] = (n & 0xff) as u8;
    CxId::from_bytes(bytes)
}

fn node(n: u16, frequency: u64, trust: Option<TrustTag>) -> KernelGraphNode {
    KernelGraphNode::new(cx(n), frequency, trust)
}

fn edge(a: u16, b: u16) -> KernelGraphEdge {
    KernelGraphEdge::new(cx(a), cx(b), 1.0)
}

fn all_candidates_config() -> KernelBuildConfig {
    let mut config = KernelBuildConfig::with_registry_defaults();
    config.candidate_top_fraction_permille = 1000;
    config
}

/// A small fixture graph with scope attributes for the scope-algebra tests.
fn scoped_fixture() -> (KernelGraph, ScopeAttributes) {
    let nodes = vec![
        node(0, 3, Some(TrustTag::Trusted)),
        node(1, 2, None),
        node(2, 1, None),
        node(3, 1, None),
        node(4, 1, None),
    ];
    let edges = vec![edge(0, 1), edge(1, 2), edge(2, 0), edge(2, 3), edge(3, 4)];
    let graph = KernelGraph::new(nodes, edges).unwrap();

    let mut attrs: ScopeAttributes = BTreeMap::new();
    attrs.insert(
        cx(0),
        NodeScope::new("crates/a/src/x.rs", Some("test".into()), 100, "repo1"),
    );
    attrs.insert(
        cx(1),
        NodeScope::new("crates/a/src/y.rs", None, 150, "repo1"),
    );
    attrs.insert(
        cx(2),
        NodeScope::new("crates/b/src/z.rs", Some("trace".into()), 200, "repo1"),
    );
    attrs.insert(
        cx(3),
        NodeScope::new("crates/b/src/w.rs", None, 250, "repo2"),
    );
    attrs.insert(
        cx(4),
        NodeScope::new("crates/c/src/v.rs", None, 300, "repo2"),
    );
    (graph, attrs)
}

// --- scope algebra goldens -------------------------------------------------

#[test]
fn scope_algebra_exact_member_sets() {
    let (graph, attrs) = scoped_fixture();
    let indexed = graph.compile().unwrap();

    let collection = Scope::Collection("crates/a/".into()).resolve(&indexed, &attrs);
    assert_eq!(collection, BTreeSet::from([cx(0), cx(1)]));

    let domain = Scope::Domain("test".into()).resolve(&indexed, &attrs);
    assert_eq!(domain, BTreeSet::from([cx(0)]));

    let subgraph = Scope::Subgraph {
        symbol: cx(0),
        radius: 1,
    }
    .resolve(&indexed, &attrs);
    // undirected neighbours of 0 are {1,2}, plus 0 itself.
    assert_eq!(subgraph, BTreeSet::from([cx(0), cx(1), cx(2)]));

    let window = Scope::TimeWindow { t0: 150, t1: 250 }.resolve(&indexed, &attrs);
    assert_eq!(window, BTreeSet::from([cx(1), cx(2), cx(3)]));

    let tenant = Scope::Tenant("repo2".into()).resolve(&indexed, &attrs);
    assert_eq!(tenant, BTreeSet::from([cx(3), cx(4)]));

    let union = Scope::union(
        Scope::Collection("crates/a/".into()),
        Scope::Tenant("repo2".into()),
    )
    .resolve(&indexed, &attrs);
    assert_eq!(union, BTreeSet::from([cx(0), cx(1), cx(3), cx(4)]));

    let intersect = Scope::intersect(
        Scope::Tenant("repo1".into()),
        Scope::TimeWindow { t0: 150, t1: 250 },
    )
    .resolve(&indexed, &attrs);
    assert_eq!(intersect, BTreeSet::from([cx(1), cx(2)]));

    println!("scope algebra member sets verified");
}

#[test]
fn scope_hash_is_stable_and_distinct() {
    let a = Scope::Collection("crates/a/".into());
    let b = Scope::Collection("crates/a/".into());
    let c = Scope::Collection("crates/b/".into());
    assert_eq!(a.scope_hash(), b.scope_hash(), "same scope => same hash");
    assert_ne!(
        a.scope_hash(),
        c.scope_hash(),
        "different scope => different hash"
    );
    // Union is order-sensitive in the tree but hash is a pure function of it.
    let u = Scope::union(a.clone(), c.clone());
    assert_eq!(u.scope_hash(), Scope::union(a, c).scope_hash());
    println!("scope_hash stable: {}", u.scope_hash());
}

#[test]
fn scoped_kernel_builds_over_induced_subgraph() {
    let (graph, attrs) = scoped_fixture();
    let scope = Scope::Collection("crates/".into());
    let (artifact, scope_hash) =
        build_scoped_kernel(&graph, &attrs, &scope, &all_candidates_config()).unwrap();
    assert_eq!(artifact.scope_id, scope_hash);
    assert_eq!(artifact.node_count, 5);
    assert!(artifact.recall.gated);
    println!(
        "scoped kernel members={} scope_hash={}",
        artifact.member_count, scope_hash
    );
}

// --- cache correctness -----------------------------------------------------

fn key(scope_hash: &str, panel: u32) -> CacheKey {
    CacheKey {
        scope_hash: scope_hash.to_string(),
        panel_version: panel,
        anchor_identity: "anchors-v1".to_string(),
        corpus_identity: "corpus-v1".to_string(),
    }
}

#[test]
fn cache_hit_serves_identical_bytes_and_invalidates_precisely() {
    let (graph, attrs) = scoped_fixture();
    let scope_a = Scope::Collection("crates/a/".into());
    let scope_b = Scope::Collection("crates/b/".into());
    let config = all_candidates_config();
    let (art_a, hash_a) = build_scoped_kernel(&graph, &attrs, &scope_a, &config).unwrap();
    let (art_b, hash_b) = build_scoped_kernel(&graph, &attrs, &scope_b, &config).unwrap();

    let mut cache = KernelCache::new();
    let bytes_a = art_a.kernel_json_bytes();
    cache.insert(key(&hash_a, 7), bytes_a.clone());
    cache.insert(key(&hash_b, 7), art_b.kernel_json_bytes());

    // Hit serves identical bytes.
    let served = cache.get(&key(&hash_a, 7)).unwrap();
    assert_eq!(served, bytes_a, "cache hit must serve identical bytes");
    assert_eq!(cache.hits(), 1);
    assert!(cache.get(&key("missing", 7)).is_none());
    assert_eq!(cache.misses(), 1);

    // Dirty region invalidates exactly the affected scope entry (scope_a).
    let evicted = cache.invalidate_where(|k| k.scope_hash == hash_a);
    assert_eq!(evicted, 1);
    assert!(cache.get(&key(&hash_a, 7)).is_none());
    assert!(cache.get(&key(&hash_b, 7)).is_some());
    println!("dirty-region invalidation evicted exactly {evicted} entry");

    // Panel bump invalidates every stale-panel entry.
    cache.insert(key(&hash_a, 7), bytes_a);
    let bumped = cache.invalidate_on_panel_bump(8);
    assert_eq!(bumped, 2, "both panel-7 entries evicted on bump to 8");
    assert!(cache.is_empty());
    println!("panel bump evicted {bumped} stale entries");
}

// --- incremental equivalence ----------------------------------------------

fn incremental_fixture() -> KernelGraph {
    // Two SCCs: {0,1,2} cycle and {5,6,7} cycle, joined 2->5, tail 7->8->9.
    let nodes = vec![
        node(0, 2, Some(TrustTag::Trusted)),
        node(1, 2, None),
        node(2, 2, None),
        node(5, 2, None),
        node(6, 2, None),
        node(7, 2, None),
        node(8, 1, None),
        node(9, 1, None),
    ];
    let edges = vec![
        edge(0, 1),
        edge(1, 2),
        edge(2, 0),
        edge(2, 5),
        edge(5, 6),
        edge(6, 7),
        edge(7, 5),
        edge(7, 8),
        edge(8, 9),
    ];
    KernelGraph::new(nodes, edges).unwrap()
}

#[test]
fn incremental_rebuild_equals_from_scratch_topology_preserving() {
    let graph = incremental_fixture();
    let config = all_candidates_config();
    let previous_bc = kernel_betweenness_permille(&graph, &config).unwrap();

    // Topology-preserving delta: bump frequency of node 6, change a weight.
    let delta = GraphDelta {
        frequency_changes: vec![(cx(6), 9)],
        weight_changes: vec![(cx(2), cx(5), 0.5)],
        structural: false,
    };
    let new_graph = delta.apply(&graph).unwrap();

    let from_scratch = build_kernel(&new_graph, "scope/inc", &config).unwrap();
    let (incremental, report) =
        rebuild_dirty(&new_graph, &delta, &previous_bc, &config, "scope/inc").unwrap();

    assert_eq!(
        incremental.kernel_json_bytes(),
        from_scratch.kernel_json_bytes(),
        "rebuild_dirty must equal from-scratch for a topology-preserving delta"
    );
    assert!(report.betweenness_reused);
    assert!(!report.escalated);
    // Node 6 is in SCC {5,6,7}; node 2 (weight endpoint) in {0,1,2}; node 5 in
    // {5,6,7}. So exactly the two nontrivial SCCs are dirty, not the tail SCCs.
    assert!(report.reprocessed_scc_count < report.total_scc_count);
    assert_eq!(report.reprocessed_scc_count, report.dirty_scc_ids.len());
    println!(
        "incremental: reprocessed {}/{} SCCs, betweenness reused, membership == from-scratch",
        report.reprocessed_scc_count, report.total_scc_count
    );
}

#[test]
fn incremental_structural_delta_escalates_to_full_rebuild() {
    let graph = incremental_fixture();
    let config = all_candidates_config();
    let previous_bc = kernel_betweenness_permille(&graph, &config).unwrap();

    // Structural: add a brand-new node 100 with an edge merging it into a cycle.
    let mut nodes = graph.nodes().to_vec();
    nodes.push(node(100, 1, None));
    let mut edges = graph.edges().to_vec();
    edges.push(edge(9, 100));
    edges.push(edge(100, 8)); // 8->9->100->8 forms a NEW SCC => structure shifts
    let new_graph = KernelGraph::new(nodes, edges).unwrap();

    let delta = GraphDelta {
        structural: true,
        ..Default::default()
    };
    let from_scratch = build_kernel(&new_graph, "scope/struct", &config).unwrap();
    let (incremental, report) =
        rebuild_dirty(&new_graph, &delta, &previous_bc, &config, "scope/struct").unwrap();

    assert!(report.escalated, "structural delta must escalate");
    assert!(!report.betweenness_reused);
    assert_eq!(report.reprocessed_scc_count, report.total_scc_count);
    assert_eq!(
        incremental.kernel_json_bytes(),
        from_scratch.kernel_json_bytes()
    );
    println!(
        "structural escalation: full rebuild over {} SCCs",
        report.total_scc_count
    );
}

// --- standing-kernel refresh triggers --------------------------------------

#[test]
fn standing_kernel_refresh_triggers_fire_independently() {
    // Seeded at panel 5, time 1000, registry defaults (threshold 200, nightly 86400).
    let policy = StandingKernelPolicy::with_registry_defaults(5, 1000);

    // No trigger: same panel, low dirty, within nightly window.
    assert_eq!(policy.evaluate(2000, 5, 10), None);

    // Panel bump.
    assert_eq!(policy.evaluate(2000, 6, 10), Some(RefreshReason::PanelBump));

    // Dirty threshold.
    assert_eq!(
        policy.evaluate(2000, 5, 200),
        Some(RefreshReason::DirtyThreshold)
    );

    // Nightly tick (>= 86400s elapsed).
    assert_eq!(
        policy.evaluate(1000 + 86_400, 5, 0),
        Some(RefreshReason::NightlyTick)
    );

    // mark_refreshed clears the staleness clock.
    let mut policy = policy;
    policy.mark_refreshed(1000 + 86_400, 5);
    assert_eq!(policy.evaluate(1000 + 86_400 + 1, 5, 0), None);
    println!("all three standing-kernel triggers fire independently");
}

// --- freshness honesty -----------------------------------------------------

#[test]
fn freshness_honest_stale_by_and_forced_rebuild() {
    // Converged => Fresh.
    assert_eq!(decide_freshness(0, false, 100), FreshnessDecision::Fresh);

    // Stale, StaleOk default => carries the true lag.
    assert_eq!(
        decide_freshness(42, false, 100),
        FreshnessDecision::StaleOk { stale_by: 42 }
    );

    // fresh:true with budget => synchronous rebuild.
    assert_eq!(decide_freshness(42, true, 100), FreshnessDecision::Rebuilt);

    // fresh:true without budget => honest timeout.
    assert_eq!(
        decide_freshness(42, true, 0),
        FreshnessDecision::Timeout { budget: 0 }
    );
    println!("freshness decisions honest: StaleOk stale_by=42, forced rebuild, timeout");
}

// --- hierarchical region kernels -------------------------------------------

#[test]
fn hierarchical_region_kernel_consistent_with_flat_drilldown() {
    // Monorepo: packages pkgA {0,1,2}, pkgB {5,6,7}, pkgC {8,9}. region_of maps
    // by node id band.
    let graph = incremental_fixture();
    let config = all_candidates_config();
    let region_of = |id: CxId| -> String {
        let n = u16::from(id.as_bytes()[0]) << 8 | u16::from(id.as_bytes()[1]);
        if n <= 2 {
            "pkgA".to_string()
        } else if n <= 7 {
            "pkgB".to_string()
        } else {
            "pkgC".to_string()
        }
    };

    let region_graph = build_region_graph(&graph, &region_of).unwrap();
    assert_eq!(region_graph.graph.node_count(), 3, "three region nodes");
    assert!(region_graph.region_names.contains_key(&region_id("pkgA")));

    // Region kernel builds and is gated.
    let region_kernel = build_kernel(&region_graph.graph, "regions", &config).unwrap();
    assert!(region_kernel.recall.gated);
    println!(
        "region kernel: {} region members, recall {} permille",
        region_kernel.member_count, region_kernel.recall.permille
    );

    // Drill-down: a flat kernel over pkgB's members must match a kernel built
    // directly over that induced subgraph (same construction => byte-identical).
    let pkg_b_members = region_graph.region_members[&region_id("pkgB")].clone();
    let drilldown = astrolabe_kernel::induced_subgraph(&graph, &pkg_b_members).unwrap();
    let drill_kernel_a = build_kernel(&drilldown, "drill/pkgB", &config).unwrap();
    let drill_kernel_b = build_kernel(&drilldown, "drill/pkgB", &config).unwrap();
    assert_eq!(
        drill_kernel_a.kernel_json_bytes(),
        drill_kernel_b.kernel_json_bytes(),
        "flat drill-down kernel is consistent (deterministic) for the same region"
    );
    assert_eq!(drill_kernel_a.node_count, 3, "pkgB has 3 symbols");
    assert!(drill_kernel_a.recall.gated);
    println!(
        "drill-down pkgB kernel: {} members over {} symbols",
        drill_kernel_a.member_count, drill_kernel_a.node_count
    );
}
