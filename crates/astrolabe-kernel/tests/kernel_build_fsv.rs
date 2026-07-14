//! Full State Verification for the kernel build pipeline (#37).
//!
//! Golden algorithm fixtures (hand-computable SCC / betweenness / FVS), a
//! full-pipeline golden with pinned membership, the recall gate + refinement
//! proof, determinism (byte-identical artifacts + seeded-sample invariance),
//! artifact readback with a recomputed members-hash compared to the ledger
//! entry, crash-injected atomic writes, and a kernel built from this repo's own
//! real crate-dependency structure.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_domain::TrustTag;
use astrolabe_domain::calyx::CxId;
use astrolabe_kernel::betweenness::brandes;
use astrolabe_kernel::kernel_build::{
    KernelArtifact, KernelLedgerEntry, commit_staged, measure_recall, members_hash, stage_write,
};
use astrolabe_kernel::{
    KernelBuildConfig, KernelGraph, KernelGraphEdge, KernelGraphNode,
    all_strongly_connected_components, approximate_directed_fvs, betweenness_auto, build_kernel,
    select_pivots, write_kernel_artifacts,
};

// --- fixtures -------------------------------------------------------------

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

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "astro-kernel-fsv-{}-{}-{}",
        std::process::id(),
        tag,
        id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

// --- golden: SCC ----------------------------------------------------------

#[test]
fn golden_scc_separates_hand_known_components() {
    // {0,1,2} cycle, {3,4} cycle joined by 2->3, node 5 isolated.
    let nodes = (0..6).map(|n| node(n, 1, None)).collect();
    let edges = vec![
        edge(0, 1),
        edge(1, 2),
        edge(2, 0),
        edge(2, 3),
        edge(3, 4),
        edge(4, 3),
    ];
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let indexed = graph.compile().unwrap();
    let components = all_strongly_connected_components(&indexed);
    println!("SCCs: {components:?}");
    assert_eq!(components, vec![vec![0, 1, 2], vec![3, 4], vec![5]]);
}

// --- golden: betweenness --------------------------------------------------

#[test]
fn golden_betweenness_path_graph_exact() {
    // Directed path 0->1->2->3. Node 1 is on shortest paths (0,2),(0,3); node 2
    // on (0,3),(1,3). Raw betweenness = [0, 2, 2, 0].
    let nodes = (0..4).map(|n| node(n, 1, None)).collect();
    let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let indexed = graph.compile().unwrap();
    let raw = brandes(&indexed, &[0, 1, 2, 3]);
    println!("raw betweenness: {raw:?}");
    assert_eq!(raw, vec![0.0, 2.0, 2.0, 0.0]);

    let auto = betweenness_auto(&indexed, 2000, 512, 7);
    assert!(auto.exact);
    assert_eq!(auto.permille, vec![0, 1000, 1000, 0]);
}

// --- golden: FVS ----------------------------------------------------------

#[test]
fn golden_fvs_breaks_cycles() {
    // Three-cycle => FVS size 1.
    let three = KernelGraph::new(
        (0..3).map(|n| node(n, 1, None)).collect(),
        vec![edge(0, 1), edge(1, 2), edge(2, 0)],
    )
    .unwrap();
    let indexed = three.compile().unwrap();
    let candidates: BTreeSet<usize> = (0..3).collect();
    let scores = vec![0_usize; 3];
    let fvs = approximate_directed_fvs(&indexed, &candidates, &scores);
    println!("three-cycle FVS: {:?}", fvs.members);
    assert_eq!(fvs.members.len(), 1);

    // Two disjoint 2-cycles => FVS size 2.
    let two = KernelGraph::new(
        (0..4).map(|n| node(n, 1, None)).collect(),
        vec![edge(0, 1), edge(1, 0), edge(2, 3), edge(3, 2)],
    )
    .unwrap();
    let indexed = two.compile().unwrap();
    let candidates: BTreeSet<usize> = (0..4).collect();
    let fvs = approximate_directed_fvs(&indexed, &candidates, &[0_usize; 4]);
    println!("two-cycle FVS: {:?}", fvs.members);
    assert_eq!(fvs.members.len(), 2);

    // Pure DAG => empty FVS.
    let dag = KernelGraph::new(
        (0..3).map(|n| node(n, 1, None)).collect(),
        vec![edge(0, 1), edge(1, 2)],
    )
    .unwrap();
    let indexed = dag.compile().unwrap();
    let candidates: BTreeSet<usize> = (0..3).collect();
    let fvs = approximate_directed_fvs(&indexed, &candidates, &[0_usize; 3]);
    println!("dag FVS: {:?}", fvs.members);
    assert!(fvs.members.is_empty());
}

// --- golden: full pipeline membership -------------------------------------

fn all_candidates_config() -> KernelBuildConfig {
    let mut config = KernelBuildConfig::with_registry_defaults();
    config.candidate_top_fraction_permille = 1000; // all nodes are candidates
    config
}

#[test]
fn golden_pipeline_pins_membership() {
    // 2-cycle {0,1}; node 1 also gateways the tail 1->2->3 (higher degree +
    // betweenness) so the FVS deterministically selects node 1. Node 0 is a
    // Trusted anchor. All nodes are covered within radius, so no refinement.
    let nodes = vec![
        node(0, 5, Some(TrustTag::Trusted)),
        node(1, 5, None),
        node(2, 1, None),
        node(3, 1, None),
    ];
    let edges = vec![edge(0, 1), edge(1, 0), edge(1, 2), edge(2, 3)];
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let artifact = build_kernel(&graph, "golden/pipeline", &all_candidates_config()).unwrap();

    println!(
        "members={:?} fvs_count={} recall={:?} trust={}",
        artifact
            .members
            .iter()
            .map(|m| (m.id.to_string(), m.score_permille, m.in_fvs))
            .collect::<Vec<_>>(),
        artifact.fvs_count,
        artifact.recall,
        artifact.trust
    );
    assert_eq!(artifact.member_count, 1);
    assert_eq!(artifact.members[0].id, cx(1));
    assert!(artifact.members[0].in_fvs);
    assert!(!artifact.members[0].support_added);
    assert!(artifact.betweenness_exact);
    assert!(artifact.anchor_grounded);
    assert_eq!(artifact.recall.permille, 1000);
    assert!(artifact.recall.gated);
    // members-hash is a pure function of the member id set.
    assert_eq!(artifact.members_hash, members_hash(&[cx(1)]));
}

// --- edge case: empty graph refuses ---------------------------------------

#[test]
fn empty_graph_refused_labeled() {
    let graph = KernelGraph::new(Vec::new(), Vec::new()).unwrap();
    let err = build_kernel(
        &graph,
        "empty",
        &KernelBuildConfig::with_registry_defaults(),
    )
    .expect_err("empty graph must be refused");
    println!("empty refusal: {} / {}", err.code(), err.message());
    assert_eq!(err.code(), astrolabe_kernel::ASTRO_KERNEL_EMPTY_GRAPH);
    assert!(!err.remediation().is_empty());
}

// --- edge case: single-SCC cycle graph ------------------------------------

#[test]
fn single_scc_cycle_graph_builds() {
    // One big 5-cycle: a single SCC. FVS must pick >=1 vertex, recall gate met.
    let nodes = (0..5)
        .map(|n| {
            node(
                n,
                3,
                if n == 0 {
                    Some(TrustTag::Trusted)
                } else {
                    None
                },
            )
        })
        .collect();
    let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 0)];
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let indexed = graph.compile().unwrap();
    assert_eq!(all_strongly_connected_components(&indexed).len(), 1);

    let artifact = build_kernel(&graph, "single-scc", &all_candidates_config()).unwrap();
    println!(
        "single-scc member_count={} fvs_count={} recall={:?}",
        artifact.member_count, artifact.fvs_count, artifact.recall
    );
    assert!(artifact.member_count >= 1);
    assert!(artifact.fvs_count >= 1);
    assert!(artifact.recall.gated);
    assert!(artifact.recall.permille >= artifact.config.recall_min_permille);
}

// --- recall gate: crippled fails, refine restores -------------------------

#[test]
fn recall_gate_crippled_then_refined() {
    // A star of 12 leaves around a hub, plus a disconnected far chain the hub's
    // radius cannot reach. A kernel of only the hub covers the star but misses
    // the far chain, so recall sits below the gate until refinement adds a
    // support member on the far chain.
    let mut nodes = vec![node(0, 9, Some(TrustTag::Trusted))];
    let mut edges = Vec::new();
    for leaf in 1..=12 {
        nodes.push(node(leaf, 1, None));
        edges.push(edge(0, leaf));
    }
    // Far chain 100-101-102-103-104 (disconnected from the hub).
    for n in 100..=104 {
        nodes.push(node(n, 1, None));
    }
    edges.push(edge(100, 101));
    edges.push(edge(101, 102));
    edges.push(edge(102, 103));
    edges.push(edge(103, 104));
    let graph = KernelGraph::new(nodes, edges).unwrap();
    let indexed = graph.compile().unwrap();

    let config = KernelBuildConfig::with_registry_defaults();

    // Crippled kernel = hub only.
    let hub_index = indexed.ids().iter().position(|&id| id == cx(0)).unwrap();
    let mut crippled: BTreeSet<usize> = BTreeSet::new();
    crippled.insert(hub_index);
    let before = measure_recall(&indexed, &crippled, config.recall_answer_radius_hops);
    println!("crippled recall = {before:?}");
    assert!(
        before.permille < config.recall_min_permille,
        "hub-only kernel must miss the far chain"
    );

    // Full pipeline refines to the gate.
    let artifact = build_kernel(&graph, "recall/refine", &config).unwrap();
    println!(
        "refined recall = {:?} support_count={} member_count={}",
        artifact.recall, artifact.support_count, artifact.member_count
    );
    assert!(artifact.recall.gated);
    assert!(artifact.recall.permille >= config.recall_min_permille);
    assert!(
        artifact.support_count >= 1,
        "refinement must add >=1 support member to reach the far chain"
    );
}

// --- determinism ----------------------------------------------------------

fn scale_free_graph(n: u16, anchors: u16) -> KernelGraph {
    // Deterministic preferential-attachment-ish graph: node k attaches to two
    // earlier nodes chosen by a fixed hash. Structured, reproducible, no RNG.
    let mut nodes = Vec::with_capacity(n as usize);
    for k in 0..n {
        let trust = if k < anchors {
            Some(TrustTag::Trusted)
        } else {
            None
        };
        nodes.push(node(k, (k as u64 % 7) + 1, trust));
    }
    // splitmix64 to spread each node's two parents across earlier nodes (a
    // proper tree; not a degenerate star). Deterministic, no RNG.
    fn mix(mut z: u64) -> u64 {
        z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    let mut edges = Vec::new();
    for k in 1..n {
        let a = (mix(k as u64) % k as u64) as u16;
        let b = (mix(k as u64 ^ 0x0abc) % k as u64) as u16;
        edges.push(edge(k, a));
        if b != a {
            edges.push(edge(k, b));
        }
        // A few back-edges to force nontrivial SCCs.
        if k % 5 == 0 {
            edges.push(edge(a, k));
        }
    }
    KernelGraph::new(nodes, edges).unwrap()
}

#[test]
fn determinism_byte_identical_artifacts() {
    let graph = scale_free_graph(300, 8);
    let config = KernelBuildConfig::with_registry_defaults();
    let first = build_kernel(&graph, "scope/det", &config).unwrap();
    let second = build_kernel(&graph, "scope/det", &config).unwrap();
    assert_eq!(
        first.kernel_json_bytes(),
        second.kernel_json_bytes(),
        "kernel.json must be byte-identical across runs"
    );
    assert_eq!(first.members_hash, second.members_hash);
    assert!(first.recall.gated);
    println!(
        "determinism: {} members, recall {} permille, {} kernel.json bytes",
        first.member_count,
        first.recall.permille,
        first.kernel_json_bytes().len()
    );
}

#[test]
fn seeded_sampling_is_invariant_and_seed_sensitive() {
    let graph = scale_free_graph(500, 4);
    let indexed = graph.compile().unwrap();
    let a = select_pivots(&indexed, 64, 12345);
    let b = select_pivots(&indexed, 64, 12345);
    assert_eq!(a, b, "same seed => identical pivot set");
    assert_eq!(a.len(), 64);
    let c = select_pivots(&indexed, 64, 999);
    assert_ne!(a, c, "different seed => different pivot set");
    println!(
        "pivots seed12345[..5]={:?} seed999[..5]={:?}",
        &a[..5],
        &c[..5]
    );
}

#[test]
fn sampled_betweenness_path_triggers_above_threshold() {
    let graph = scale_free_graph(400, 4);
    let indexed = graph.compile().unwrap();
    // Force sampling by lowering the exact ceiling below the node count.
    let sampled = betweenness_auto(&indexed, 100, 64, 42);
    assert!(!sampled.exact);
    assert_eq!(sampled.sources_used, 64);
    let again = betweenness_auto(&indexed, 100, 64, 42);
    assert_eq!(
        sampled.permille, again.permille,
        "sampled path is deterministic"
    );
    println!("sampled sources_used={}", sampled.sources_used);
}

// --- artifact FSV: write, read back, recompute hash, compare ledger --------

#[test]
fn artifact_readback_hash_matches_ledger() {
    let graph = scale_free_graph(200, 6);
    let config = KernelBuildConfig::with_registry_defaults();
    let artifact = build_kernel(&graph, "scope/fsv", &config).unwrap();
    let dir = unique_dir("artifact");
    let paths = write_kernel_artifacts(&dir, &artifact).unwrap();

    // Independently read the persisted kernel.json bytes back and parse them.
    let kernel_bytes = std::fs::read(&paths.kernel_json).unwrap();
    let readback: KernelArtifact = serde_json::from_slice(&kernel_bytes).unwrap();
    assert_eq!(readback, artifact, "persisted kernel.json must round-trip");

    // Recompute the members-hash from the persisted member ids.
    let member_ids: Vec<CxId> = readback.members.iter().map(|m| m.id).collect();
    let recomputed = members_hash(&member_ids);
    assert_eq!(recomputed, readback.members_hash);

    // Read the ledger back and compare its members-hash to the recomputed one.
    let ledger_text = std::fs::read_to_string(&paths.ledger).unwrap();
    let last_line = ledger_text.lines().last().unwrap();
    let entry: KernelLedgerEntry = serde_json::from_str(last_line).unwrap();
    println!(
        "artifact hash={} ledger hash={} members={} recall={:?}",
        recomputed, entry.members_hash, entry.member_count, entry.recall
    );
    assert_eq!(entry.members_hash, recomputed);
    assert_eq!(entry.member_count, readback.member_count);
    assert_eq!(entry.recall, readback.recall);

    // index.json is content-addressed by the same members-hash.
    let index_bytes = std::fs::read(&paths.index_json).unwrap();
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["members_hash"], serde_json::json!(recomputed));

    std::fs::remove_dir_all(&dir).unwrap();
}

// --- atomic write: crash injection ----------------------------------------

#[test]
fn atomic_write_crash_leaves_old_artifact_intact() {
    let graph = scale_free_graph(120, 4);
    let config = KernelBuildConfig::with_registry_defaults();
    let old = build_kernel(&graph, "scope/old", &config).unwrap();
    let dir = unique_dir("atomic");
    let paths = write_kernel_artifacts(&dir, &old).unwrap();
    let old_bytes = std::fs::read(&paths.kernel_json).unwrap();

    // A different artifact (different scope => different bytes).
    let new = build_kernel(&graph, "scope/new", &config).unwrap();
    let new_bytes = new.kernel_json_bytes();
    assert_ne!(old_bytes, new_bytes);

    // Stage the new bytes but "crash" before committing the rename.
    let tmp = stage_write(&paths.kernel_json, &new_bytes).unwrap();
    let after_crash = std::fs::read(&paths.kernel_json).unwrap();
    assert_eq!(
        after_crash, old_bytes,
        "final kernel.json must still hold the old, complete artifact after a crash mid-write"
    );
    assert!(
        tmp.exists(),
        "staged temp exists but is not the observable artifact"
    );

    // Now commit and observe the atomic swap to the new complete artifact.
    commit_staged(&tmp, &paths.kernel_json).unwrap();
    let after_commit = std::fs::read(&paths.kernel_json).unwrap();
    assert_eq!(after_commit, new_bytes);
    println!(
        "atomic: old={} bytes preserved through crash, committed new={} bytes",
        old_bytes.len(),
        new_bytes.len()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- real data: this repo's own crate-dependency structure ----------------

#[test]
fn real_repo_crate_graph_builds_grounded_kernel() {
    // Mine the actual astrolabe crate dependency graph from Cargo.toml files.
    let crates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mut crate_names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&crates_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().join("Cargo.toml").is_file() {
            crate_names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    crate_names.sort();
    assert!(
        crate_names.len() >= 8,
        "expected the real astrolabe crate set, found {crate_names:?}"
    );

    // Node per crate; id = content address of the crate name.
    let name_id = |name: &str| -> CxId {
        CxId::from_bytes({
            let mut bytes = [0_u8; 16];
            let digest = astrolabe_domain::calyx::content_address([
                b"astro.crate".as_slice(),
                name.as_bytes(),
            ]);
            bytes.copy_from_slice(&digest);
            bytes
        })
    };

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for name in &crate_names {
        let manifest = std::fs::read_to_string(crates_dir.join(name).join("Cargo.toml")).unwrap();
        // A dependency count proxies change frequency; the identity spine crate
        // (astrolabe-domain) is the real Trusted anchor everything grounds on.
        let deps = crate_names
            .iter()
            .filter(|dep| *dep != name && manifest.contains(dep.as_str()))
            .count();
        let trust = if name == "astrolabe-domain" {
            Some(TrustTag::Trusted)
        } else {
            None
        };
        nodes.push(KernelGraphNode::new(name_id(name), deps as u64 + 1, trust));
        for dep in &crate_names {
            if dep != name && manifest.contains(dep.as_str()) {
                edges.push(KernelGraphEdge::new(name_id(name), name_id(dep), 1.0));
            }
        }
    }
    let graph = KernelGraph::new(nodes, edges).unwrap();
    println!(
        "real crate graph: {} nodes, {} edges",
        graph.node_count(),
        graph.edge_count()
    );

    let config = KernelBuildConfig::with_registry_defaults();
    let artifact = build_kernel(&graph, "repo/crates", &config).unwrap();
    println!(
        "real kernel: members={} fvs_count={} support={} recall={:?} anchor_grounded={} trust={}",
        artifact.member_count,
        artifact.fvs_count,
        artifact.support_count,
        artifact.recall,
        artifact.anchor_grounded,
        artifact.trust
    );
    assert!(artifact.recall.gated);
    assert!(artifact.recall.permille >= config.recall_min_permille);
    assert!(
        artifact.anchor_grounded,
        "astrolabe-domain anchors the graph"
    );

    // Round-trip the real artifact through disk.
    let dir = unique_dir("real");
    let paths = write_kernel_artifacts(&dir, &artifact).unwrap();
    let readback: KernelArtifact =
        serde_json::from_slice(&std::fs::read(&paths.kernel_json).unwrap()).unwrap();
    assert_eq!(readback, artifact);
    let ids: Vec<CxId> = readback.members.iter().map(|m| m.id).collect();
    assert_eq!(members_hash(&ids), readback.members_hash);
    std::fs::remove_dir_all(&dir).unwrap();
}
