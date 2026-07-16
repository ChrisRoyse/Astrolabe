//! Kernel-of-kernels composition (issue #456): compose per-repo kernels into
//! the growing language-level fleet kernel (`fleet:rust:v1`).
//!
//! # Design (research-grounded)
//!
//! This is the **composable core-sets** pattern (Indyk/Mahdian/Mirrokni et al.,
//! PODS'14 / STOC'15): solve per-partition (the per-repo FVS kernels already
//! persisted by the pipeline), then run the same optimization over the *union*
//! of the per-partition solutions. Coverage-style objectives are known to lose
//! their guarantees under plain composition, which is exactly why the fleet
//! recall gate below is **measured per repo** against the composed graph and
//! never assumed from the per-repo gates.
//!
//! # The fleet graph
//!
//! - **Nodes** = per-repo kernel members, merged into one node per #455
//!   content-equivalence class (`blake3(frame(label) ‖ frame(language) ‖
//!   frame(snippet))`) — same content = same node, weighted by repo count.
//!   Content-free members (`File` label or empty snippet — the #473 property
//!   fingerprint proxy) never merge: each stays a unique per-(project, member)
//!   node, explicitly counted.
//! - **Edges** = cross-member S18 code-semantic cosine similarity over member
//!   centroids (top-k + declared min-similarity knob, both registry-declared
//!   in [`FLEET_COMPOSE_KNOBS`] — invariant 4), deterministic ordering.
//! - **Groundedness** = any-occurrence anchor rollup: a fleet node carries a
//!   Trusted anchor iff some constituent member was grounded in its home repo.
//! - **Frequency** = summed occurrence frequency (repo count and per-repo heat
//!   both weigh in, declared in the sidecar).
//!
//! The existing `build_kernel` FVS pipeline runs over that graph at the fleet
//! scope; the artifact persists into the **fleet catalog vault** Kernel CF via
//! `persist_kernel_artifact` (kernel.json + index.json + members-hash + paired
//! Kernel ledger entry, byte readback), plus a `fleet-kernel` sidecar report
//! (Blob row + Admin ledger entry) carrying per-member provenance, the gate
//! record, and the compose input hash.
//!
//! # Growth semantics
//!
//! The compose input hash is `blake3` over the sorted `(project, members_hash)`
//! pairs. An unchanged hash is a topology-preserving no-op (explicit
//! `unchanged` verdict, no writes); any repo-set or member-set change is a
//! structural [`GraphDelta`] and escalates to an explicit full rebuild — the
//! LSM/segment doctrine: incremental until structural debt, then rebuild, both
//! explicit and recorded.
//!
//! # #473 proxy caveat (declared, never silent)
//!
//! libcbm retains no raw source bytes, so content keys derive from the #413
//! body-derived property fingerprints — a content *proxy* that undercounts
//! cross-repo equality (measured 60% overlap on a byte-identical tree pair,
//! #455 evidence). Dedup weighting therefore undercounts; the mechanism
//! upgrades transparently when #473 lands. Recorded in every sidecar.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use astrolabe_domain::{TrustTag, cx_id_from_canonical, frame, rollup_trust};
use astrolabe_ingest::{persist_kernel_artifact, read_persisted_kernel_artifact};
use astrolabe_kernel::kernel_graph::IndexedGraph;
use astrolabe_kernel::{
    GraphDelta, KERNEL_ARTIFACT_SCHEMA, KERNEL_BUILD_KNOB_REGISTRY_VERSION, KernelArtifact,
    KernelBuildConfig, KernelGraph, KernelGraphEdge, KernelGraphNode, KernelMember,
    U64KnobDeclaration, build_kernel, measure_recall, members_hash,
};
use astrolabe_panel::PANEL_V2_VERSION;
use astrolabe_weave::search::SLOT_CODE_SEMANTIC;
use astrolabe_weave::search_production::read_search_corpus_from_vault;
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::input_store::{self, read_input_bytes};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, CxId, VaultId};
use serde_json::{Value, json};

use crate::catalog::FleetCatalog;
use crate::dedup::{AtomFrames, parse_atom_frames};
use crate::orchestrator::{SHADOW_VAULT_ID, kernel_scope_id, shadow_vault_salt};

/// Report kind under which the compose sidecar persists in the fleet catalog.
pub const FLEET_KERNEL_REPORT_KIND: &str = "fleet-kernel";
/// Sidecar artifact schema tag.
pub const FLEET_KERNEL_SIDECAR_SCHEMA: &str = "fleet-kernel-compose/v1";
/// Knob registry version for fleet composition.
pub const FLEET_COMPOSE_KNOB_REGISTRY_VERSION: &str = "astro.fleet.compose_knobs.v1";
/// Framing tag for a fleet node identity preimage.
pub const FLEET_NODE_CANONICAL_TAG: &[u8] = b"astrolabe.fleet.node.v1";

/// Refusal: no repo contributed a persisted kernel to compose over.
pub const ASTRO_FLEET_COMPOSE_NO_KERNELS: &str = "ASTRO_FLEET_COMPOSE_NO_KERNELS";
/// Refusal: a per-repo kernel member has no stored #446 input record.
pub const ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED: &str = "ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED";
/// Refusal: S18 vectors disagree on dimension across members.
pub const ASTRO_FLEET_COMPOSE_DIM_MISMATCH: &str = "ASTRO_FLEET_COMPOSE_DIM_MISMATCH";
/// Refusal: a compose knob is outside its declared bounds.
pub const ASTRO_FLEET_COMPOSE_KNOB_RANGE: &str = "ASTRO_FLEET_COMPOSE_KNOB_RANGE";
/// Refusal: an inner kernel/ingest/domain operation failed (message carries it).
pub const ASTRO_FLEET_COMPOSE_INNER: &str = "ASTRO_FLEET_COMPOSE_INNER";
/// Refusal: no fleet kernel artifact persisted at the requested scope.
pub const ASTRO_FLEET_KERNEL_MISSING: &str = "ASTRO_FLEET_KERNEL_MISSING";
/// Refusal: fleet kernel readback diverged (members-hash / ledger pairing).
pub const ASTRO_FLEET_KERNEL_READBACK: &str = "ASTRO_FLEET_KERNEL_READBACK";
/// Refusal: provenance verification found a sidecar claim reality contradicts.
pub const ASTRO_FLEET_PROVENANCE_MISMATCH: &str = "ASTRO_FLEET_PROVENANCE_MISMATCH";

// Knob names.
pub const KNOB_SIMILARITY_MIN: &str = "fleet.compose.similarity_min_permille";
pub const KNOB_SIMILARITY_TOP_K: &str = "fleet.compose.similarity_top_k";
pub const KNOB_PER_REPO_RECALL_MIN: &str = "fleet.compose.per_repo_recall_min_permille";

const SOURCE: &str = "https://github.com/ChrisRoyse/Astrolabe/issues/456";

/// All fleet compose knobs with their declared bounds (invariant 4).
pub const FLEET_COMPOSE_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
        name: KNOB_SIMILARITY_MIN,
        default: 800,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "minimum S18 cosine similarity for a cross-member fleet edge; \
                    high-precision cutoff, distribution measured on the pilot fleet (#456 FSV)",
    },
    U64KnobDeclaration {
        registry_version: FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
        name: KNOB_SIMILARITY_TOP_K,
        default: 8,
        min: 1,
        max: 64,
        unit: "neighbors",
        source: SOURCE,
        rationale: "per-node cap on similarity neighbors, bounding fleet-graph degree",
    },
    U64KnobDeclaration {
        registry_version: FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
        name: KNOB_PER_REPO_RECALL_MIN,
        default: 950,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "per-repo held-out recall gate: every repo's members must be covered \
                    by the fleet kernel within the answer radius (mirrors the #37 gate); \
                    a fleet kernel below gate persists only as provisional",
    },
];

/// Fully resolved fleet compose knobs.
#[derive(Clone, Copy, Debug)]
pub struct ComposeConfig {
    /// Minimum cosine similarity for an edge, in permille.
    pub similarity_min_permille: u64,
    /// Per-node similarity neighbor cap.
    pub similarity_top_k: u64,
    /// Per-repo held-out recall gate in permille.
    pub per_repo_recall_min_permille: u64,
}

impl ComposeConfig {
    /// Returns the registry-default configuration.
    pub fn with_registry_defaults() -> Self {
        Self {
            similarity_min_permille: knob_default(KNOB_SIMILARITY_MIN),
            similarity_top_k: knob_default(KNOB_SIMILARITY_TOP_K),
            per_repo_recall_min_permille: knob_default(KNOB_PER_REPO_RECALL_MIN),
        }
    }

    /// Validates every knob against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<(), CalyxError> {
        check_range(KNOB_SIMILARITY_MIN, self.similarity_min_permille)?;
        check_range(KNOB_SIMILARITY_TOP_K, self.similarity_top_k)?;
        check_range(KNOB_PER_REPO_RECALL_MIN, self.per_repo_recall_min_permille)?;
        Ok(())
    }
}

fn knob_default(name: &str) -> u64 {
    FLEET_COMPOSE_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("fleet compose knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<(), CalyxError> {
    let knob = FLEET_COMPOSE_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("fleet compose knob is declared");
    if value < knob.min || value > knob.max {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_KNOB_RANGE,
            message: format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            remediation: "set the fleet compose knob within its registered bounds",
        });
    }
    Ok(())
}

fn inner_err(what: &str, error: impl std::fmt::Display) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_COMPOSE_INNER,
        message: format!("{what}: {error}"),
        remediation: "the inner error carries its own code; fix that condition and re-run compose",
    }
}

/// One per-repo kernel member resolved against its vault's stores.
#[derive(Clone, Debug)]
pub struct MemberOccurrence {
    /// Catalog project (`org__repo`).
    pub project: String,
    /// The member's per-repo CxId.
    pub cx: CxId,
    /// Qualified symbol name (from the stored canonical frames).
    pub qualified_name: String,
    /// Repo-relative file path.
    pub rel_file_path: String,
    /// Symbol label.
    pub label: String,
    /// Language tag.
    pub language: String,
    /// #455 content-only key.
    pub content_key: [u8; 32],
    /// True for File-label or snippetless atoms (#473 proxy) — never merged.
    pub content_free: bool,
    /// Whether the member was grounded (Trusted anchor within hop limit) at home.
    pub grounded: bool,
    /// Per-repo measured member stats, carried for provenance + degenerate path.
    pub score_permille: u64,
    pub degree: u64,
    pub betweenness_permille: u64,
    pub groundedness_permille: u64,
    pub frequency: u64,
    pub in_fvs: bool,
    pub support_added: bool,
    /// Persisted S18 code-semantic vector, when the member carries one.
    pub vector: Option<Vec<f32>>,
}

/// One repo's loaded kernel, resolved and vector-joined.
#[derive(Clone, Debug)]
pub struct RepoKernelLoad {
    /// Catalog project.
    pub project: String,
    /// The repo kernel's members-hash (composition input identity).
    pub members_hash: String,
    /// Source-graph node count of the repo kernel build.
    pub node_count: usize,
    /// Repo kernel recall in permille.
    pub recall_permille: u64,
    /// Whether the repo build's betweenness was exact.
    pub betweenness_exact: bool,
    /// Resolved members.
    pub occurrences: Vec<MemberOccurrence>,
    /// Members without a persisted S18 vector (labeled, counted, never zeroed).
    pub missing_vector: usize,
}

fn open_shadow_vault(store_root: &Path, project: &str) -> Result<AsterVault, CalyxError> {
    let vault_dir = store_root
        .join(project)
        .join(format!("{project}.astrolabe-vault"));
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID).map_err(|error| CalyxError {
        code: ASTRO_FLEET_COMPOSE_INNER,
        message: format!("shadow vault id failed to parse: {error:?}"),
        remediation: "internal defect: SHADOW_VAULT_ID must be a valid ULID",
    })?;
    AsterVault::open(
        &vault_dir,
        vault_id,
        shadow_vault_salt(project).into_bytes(),
        VaultOptions {
            read_only: true,
            ..VaultOptions::default()
        },
    )
}

/// Scans a project vault's #446 input store into `(CxId, AtomFrames)` pairs.
///
/// The CxId is recomputed from the stored canonical bytes with the shadow panel
/// version and the project's shadow salt — the exact derivation the import used
/// — so the mapping to kernel-member identities is exact, never heuristic.
fn input_atoms_by_cx(
    vault: &AsterVault,
    project: &str,
) -> Result<BTreeMap<CxId, AtomFrames>, CalyxError> {
    let probe = input_store::input_manifest_key(&[0_u8; 32]);
    let prefix = probe[..probe.len() - 32].to_vec();
    let snapshot = vault.latest_seq();
    // Symbol CxIds derive from the DOMAIN identity salt (`astrolabe-v1:<project>`,
    // `SymbolRecord::identity`), not the shadow vault-open salt
    // (`astrolabe-shadow-v1:<project>`) — two distinct salts by design.
    let salt = astrolabe_domain::vault_salt(project)
        .map_err(|error| inner_err("derive domain identity salt", error))?
        .into_bytes();
    let mut by_cx = BTreeMap::new();
    for (key, _value) in vault.scan_cf_at(snapshot, ColumnFamily::Blob)? {
        if !key.starts_with(&prefix) || key.len() != prefix.len() + 32 {
            continue;
        }
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&key[prefix.len()..]);
        let bytes = read_input_bytes(vault, &hash)?;
        let frames = parse_atom_frames(&bytes)?;
        let cx = cx_id_from_canonical(&bytes, PANEL_V2_VERSION, &salt)
            .map_err(|error| inner_err("derive CxId from stored input", error))?;
        by_cx.insert(cx, frames);
    }
    Ok(by_cx)
}

/// Loads one repo's persisted kernel and resolves every member against the
/// vault's input store (provenance + content key) and S18 corpus (vectors).
///
/// Returns `Ok(None)` when the repo has no persisted kernel artifact — the
/// caller counts it as a labeled skip (issue #456 DoD: "skipped with count"),
/// never a silent omission. Every other failure is fail-closed.
pub fn load_repo_kernel(
    store_root: &Path,
    project: &str,
) -> Result<Option<RepoKernelLoad>, CalyxError> {
    let vault_dir = store_root
        .join(project)
        .join(format!("{project}.astrolabe-vault"));
    if !vault_dir.exists() {
        return Ok(None);
    }
    let vault = open_shadow_vault(store_root, project)?;
    let scope = kernel_scope_id(project);
    let artifact = read_persisted_kernel_artifact(&vault, &scope)
        .map_err(|error| inner_err("read per-repo kernel artifact", error))?;
    let Some(artifact) = artifact else {
        return Ok(None);
    };

    let by_cx = input_atoms_by_cx(&vault, project)?;

    let corpus = read_search_corpus_from_vault(&vault, project, &[SLOT_CODE_SEMANTIC])
        .map_err(|error| inner_err("read S18 corpus", error))?;
    let mut vec_by_name: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for symbol in corpus.symbols {
        if let Some(vector) = symbol.vectors.get(&SLOT_CODE_SEMANTIC) {
            vec_by_name.insert(symbol.symbol_id, vector.clone());
        }
    }

    let mut occurrences = Vec::with_capacity(artifact.members.len());
    let mut missing_vector = 0_usize;
    for member in &artifact.members {
        let Some(frames) = by_cx.get(&member.id) else {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
                message: format!(
                    "kernel member {} of project {project} has no stored #446 input record",
                    member.id
                ),
                remediation: "re-run index_repository for the repo so the input store covers \
                              every symbol, then re-run compose",
            });
        };
        let vector = vec_by_name.get(&frames.qualified_name).cloned();
        if vector.is_none() {
            missing_vector += 1;
        }
        occurrences.push(MemberOccurrence {
            project: project.to_string(),
            cx: member.id,
            qualified_name: frames.qualified_name.clone(),
            rel_file_path: frames.rel_file_path.clone(),
            label: frames.label.clone(),
            language: frames.language.clone(),
            content_key: frames.content_key,
            content_free: frames.snippet_empty || frames.label == "File",
            grounded: member.grounded,
            score_permille: member.score_permille,
            degree: member.degree,
            betweenness_permille: member.betweenness_permille,
            groundedness_permille: member.groundedness_permille,
            frequency: member.frequency,
            in_fvs: member.in_fvs,
            support_added: member.support_added,
            vector,
        });
    }

    Ok(Some(RepoKernelLoad {
        project: project.to_string(),
        members_hash: artifact.members_hash.clone(),
        node_count: artifact.node_count,
        recall_permille: artifact.recall.permille,
        betweenness_exact: artifact.betweenness_exact,
        occurrences,
        missing_vector,
    }))
}

/// One fleet-graph node: a content-equivalence class of per-repo members.
#[derive(Clone, Debug)]
struct FleetNode {
    fleet_cx: CxId,
    content_key: Option<[u8; 32]>,
    occurrences: Vec<MemberOccurrence>,
    grounded_any: bool,
    frequency_sum: u64,
    centroid: Option<Vec<f32>>,
}

fn fleet_node_cx(scope: &str, key_bytes: &[u8]) -> Result<CxId, CalyxError> {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&frame(FLEET_NODE_CANONICAL_TAG));
    canonical.extend_from_slice(&frame(scope.as_bytes()));
    canonical.extend_from_slice(&frame(key_bytes));
    let salt = format!("astrolabe-fleet-v1:{scope}");
    cx_id_from_canonical(&canonical, PANEL_V2_VERSION, salt.as_bytes())
        .map_err(|error| inner_err("derive fleet node CxId", error))
}

fn unit_vector(vector: &[f32]) -> Option<Vec<f32>> {
    let norm: f32 = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return None;
    }
    Some(vector.iter().map(|value| value / norm).collect())
}

/// Builds the fleet nodes: content-bearing members merge per content key
/// (`same content = same node`); content-free members stay unique per
/// (project, member) — the #473 proxy makes them content-free, so merging them
/// would fabricate equivalence (the degenerate `mod.rs` class found on #455).
fn build_fleet_nodes(scope: &str, loads: &[RepoKernelLoad]) -> Result<Vec<FleetNode>, CalyxError> {
    let mut grouped: BTreeMap<Vec<u8>, Vec<MemberOccurrence>> = BTreeMap::new();
    for load in loads {
        for occurrence in &load.occurrences {
            let key = if occurrence.content_free {
                let mut key = vec![0x02_u8];
                key.extend_from_slice(&frame(occurrence.project.as_bytes()));
                key.extend_from_slice(occurrence.cx.as_bytes());
                key
            } else {
                let mut key = vec![0x01_u8];
                key.extend_from_slice(&occurrence.content_key);
                key
            };
            grouped.entry(key).or_default().push(occurrence.clone());
        }
    }

    let mut nodes = Vec::with_capacity(grouped.len());
    let mut dim: Option<usize> = None;
    for (key, mut occurrences) in grouped {
        occurrences.sort_by(|left, right| {
            left.project
                .cmp(&right.project)
                .then_with(|| left.cx.cmp(&right.cx))
        });
        let fleet_cx = fleet_node_cx(scope, &key)?;
        let grounded_any = occurrences.iter().any(|occurrence| occurrence.grounded);
        let frequency_sum = occurrences
            .iter()
            .fold(0_u64, |sum, occurrence| {
                sum.saturating_add(occurrence.frequency)
            })
            .max(1);
        let mut sum: Option<Vec<f32>> = None;
        let mut counted = 0_usize;
        for occurrence in &occurrences {
            let Some(vector) = &occurrence.vector else {
                continue;
            };
            let Some(unit) = unit_vector(vector) else {
                continue;
            };
            match dim {
                None => dim = Some(unit.len()),
                Some(expected) if expected != unit.len() => {
                    return Err(CalyxError {
                        code: ASTRO_FLEET_COMPOSE_DIM_MISMATCH,
                        message: format!(
                            "S18 vector dimension {} for {}:{} disagrees with fleet dimension {expected}",
                            unit.len(),
                            occurrence.project,
                            occurrence.qualified_name
                        ),
                        remediation: "re-index the divergent repo with the current embedder so \
                                      every S18 vector shares one dimension",
                    });
                }
                Some(_) => {}
            }
            match &mut sum {
                None => sum = Some(unit),
                Some(sum) => {
                    for (slot, value) in sum.iter_mut().zip(unit.iter()) {
                        *slot += value;
                    }
                }
            }
            counted += 1;
        }
        let centroid = sum.and_then(|mut sum| {
            for value in &mut sum {
                *value /= counted as f32;
            }
            unit_vector(&sum)
        });
        let content_key = if key[0] == 0x01 {
            let mut content_key = [0_u8; 32];
            content_key.copy_from_slice(&key[1..33]);
            Some(content_key)
        } else {
            None
        };
        nodes.push(FleetNode {
            fleet_cx,
            content_key,
            occurrences,
            grounded_any,
            frequency_sum,
            centroid,
        });
    }
    nodes.sort_by_key(|node| node.fleet_cx);
    Ok(nodes)
}

/// Builds deterministic top-k min-thresholded cosine similarity edges over the
/// node centroids. Returns `(edges, similarity_permille_histogram)`.
fn build_similarity_edges(
    nodes: &[FleetNode],
    config: &ComposeConfig,
) -> (Vec<KernelGraphEdge>, BTreeMap<u64, u64>) {
    let with_vectors: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.centroid.is_some())
        .map(|(index, _)| index)
        .collect();
    let mut candidates: BTreeMap<usize, Vec<(u64, usize)>> = BTreeMap::new();
    let mut histogram: BTreeMap<u64, u64> = BTreeMap::new();
    for (position, &a) in with_vectors.iter().enumerate() {
        let centroid_a = nodes[a].centroid.as_ref().expect("filtered on centroid");
        for &b in with_vectors.iter().skip(position + 1) {
            let centroid_b = nodes[b].centroid.as_ref().expect("filtered on centroid");
            let dot: f32 = centroid_a
                .iter()
                .zip(centroid_b.iter())
                .map(|(left, right)| left * right)
                .sum();
            let permille = (dot.clamp(0.0, 1.0) * 1000.0).floor() as u64;
            *histogram.entry(permille / 100 * 100).or_default() += 1;
            if permille >= config.similarity_min_permille {
                candidates.entry(a).or_default().push((permille, b));
                candidates.entry(b).or_default().push((permille, a));
            }
        }
    }
    let mut weights: BTreeMap<(CxId, CxId), u64> = BTreeMap::new();
    for (index, mut list) in candidates {
        list.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| nodes[left.1].fleet_cx.cmp(&nodes[right.1].fleet_cx))
        });
        list.truncate(config.similarity_top_k as usize);
        for (permille, other) in list {
            let src = nodes[index].fleet_cx;
            let dst = nodes[other].fleet_cx;
            let entry = weights.entry((src, dst)).or_default();
            *entry = (*entry).max(permille);
            let entry = weights.entry((dst, src)).or_default();
            *entry = (*entry).max(permille);
        }
    }
    let edges = weights
        .into_iter()
        .map(|((src, dst), permille)| KernelGraphEdge::new(src, dst, permille as f32 / 1000.0))
        .collect();
    (edges, histogram)
}

/// Marks every node within `radius` undirected hops of any member index.
/// Mirrors the kernel crate's recall coverage BFS (private there) so the
/// per-repo gate measures the identical coverage the artifact recall carries.
fn coverage_from(indexed: &IndexedGraph, members: &BTreeSet<usize>, radius: u64) -> Vec<bool> {
    let n = indexed.len();
    let mut covered = vec![false; n];
    let mut depth = vec![0_u64; n];
    let mut queue = std::collections::VecDeque::new();
    for &member in members {
        if !covered[member] {
            covered[member] = true;
            queue.push_back(member);
        }
    }
    while let Some(node) = queue.pop_front() {
        if depth[node] >= radius {
            continue;
        }
        for &neighbor in indexed.undirected_neighbors(node) {
            if !covered[neighbor] {
                covered[neighbor] = true;
                depth[neighbor] = depth[node] + 1;
                queue.push_back(neighbor);
            }
        }
    }
    covered
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compose input hash: `blake3` over the sorted `(project, members_hash)`
/// frame pairs — the composition's exact input identity.
pub fn compose_input_hash(pairs: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&frame(b"astrolabe.fleet.compose-input.v1"));
    for (project, members_hash) in sorted {
        preimage.extend_from_slice(&frame(project.as_bytes()));
        preimage.extend_from_slice(&frame(members_hash.as_bytes()));
    }
    blake3::hash(&preimage).to_hex().to_string()
}

/// Composes the fleet kernel over `projects` and persists it at `scope` in the
/// fleet catalog vault (Kernel CF artifact + `fleet-kernel` sidecar report).
/// Returns the summary JSON the CLI prints.
#[allow(clippy::too_many_lines)]
pub fn compose_fleet_kernel(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    projects: &[String],
    compose_config: &ComposeConfig,
) -> Result<Value, CalyxError> {
    compose_config.validate()?;
    let kernel_config = KernelBuildConfig::with_registry_defaults();
    kernel_config
        .validate()
        .map_err(|error| inner_err("kernel build config", error))?;

    // Load every repo's kernel; absent kernels are labeled skips with a count.
    let mut loads: Vec<RepoKernelLoad> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    for project in projects {
        match load_repo_kernel(store_root, project)? {
            Some(load) => loads.push(load),
            None => skipped.push(json!({
                "project": project,
                "reason": "no persisted kernel artifact in the project vault",
            })),
        }
    }
    if loads.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_NO_KERNELS,
            message: format!(
                "none of the {} named repos carries a persisted kernel artifact",
                projects.len()
            ),
            remediation: "kernel at least one repo through the fleet pipeline before composing",
        });
    }
    loads.sort_by(|left, right| left.project.cmp(&right.project));

    let input_pairs: Vec<(String, String)> = loads
        .iter()
        .map(|load| (load.project.clone(), load.members_hash.clone()))
        .collect();
    let input_hash = compose_input_hash(&input_pairs);

    // Growth semantics: unchanged input is a topology-preserving no-op; any
    // change is structural and escalates to an explicit full rebuild (the
    // GraphDelta doctrine of astrolabe-kernel::incremental).
    let previous = catalog.read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?;
    let previous_input_hash = previous.as_ref().and_then(|bytes| {
        serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("compose_input_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
    });
    let delta = GraphDelta {
        structural: previous_input_hash.as_deref() != Some(input_hash.as_str()),
        ..GraphDelta::default()
    };
    if delta.is_topology_preserving() {
        let existing = read_persisted_kernel_artifact(catalog.vault(), scope)
            .map_err(|error| inner_err("read persisted fleet kernel", error))?;
        if let Some(existing) = existing {
            return Ok(json!({
                "verb": "compose",
                "scope": scope,
                "verdict": "unchanged",
                "reason": "compose input hash matches the persisted sidecar; \
                           topology-preserving no-op (GraphDelta non-structural)",
                "compose_input_hash": input_hash,
                "members_hash": existing.members_hash,
                "member_count": existing.member_count,
                "repos": loads.len(),
                "skipped_no_kernel": skipped.len(),
            }));
        }
        // Sidecar exists but the artifact row is missing: fall through to a
        // rebuild — never trust a sidecar over the primary artifact.
    }

    // Fleet graph.
    let nodes = build_fleet_nodes(scope, &loads)?;
    let (edges, sim_histogram) = build_similarity_edges(&nodes, compose_config);
    let graph_nodes: Vec<KernelGraphNode> = nodes
        .iter()
        .map(|node| {
            KernelGraphNode::new(
                node.fleet_cx,
                node.frequency_sum,
                if node.grounded_any {
                    Some(TrustTag::Trusted)
                } else {
                    None
                },
            )
        })
        .collect();
    let edge_count = edges.len();
    let graph = KernelGraph::new(graph_nodes, edges)
        .map_err(|error| inner_err("assemble fleet kernel graph", error))?;

    let single_repo = loads.len() == 1;
    let (artifact, verdict_kind) = if single_repo {
        // Explicit degenerate path (issue #456 edge triad): the fleet kernel
        // over one repo IS that repo's kernel — every member class persists as
        // a fleet member with its per-repo measured stats aggregated by the
        // declared policy (max for scores, sum for frequency, any for flags).
        (
            degenerate_single_repo_artifact(scope, &kernel_config, &graph, &nodes, &loads[0])?,
            "degenerate_single_repo",
        )
    } else {
        (
            build_kernel(&graph, scope, &kernel_config)
                .map_err(|error| inner_err("build fleet kernel", error))?,
            "composed_full_rebuild",
        )
    };

    // Per-repo held-out recall gate over the composed graph (measured, never
    // assumed — composable core-sets lose coverage guarantees under union).
    let indexed = graph
        .compile()
        .map_err(|error| inner_err("compile fleet graph", error))?;
    let member_indices: BTreeSet<usize> = artifact
        .members
        .iter()
        .filter_map(|member| indexed.ids().binary_search(&member.id).ok())
        .collect();
    let covered = coverage_from(
        &indexed,
        &member_indices,
        kernel_config.recall_answer_radius_hops,
    );
    let node_by_cx: BTreeMap<CxId, &FleetNode> =
        nodes.iter().map(|node| (node.fleet_cx, node)).collect();
    let mut per_repo_total: BTreeMap<&str, u64> = BTreeMap::new();
    let mut per_repo_covered: BTreeMap<&str, u64> = BTreeMap::new();
    for (index, id) in indexed.ids().iter().enumerate() {
        let node = node_by_cx[id];
        let mut projects_here: BTreeSet<&str> = BTreeSet::new();
        for occurrence in &node.occurrences {
            projects_here.insert(occurrence.project.as_str());
        }
        for project in projects_here {
            *per_repo_total.entry(project).or_default() += 1;
            if covered[index] {
                *per_repo_covered.entry(project).or_default() += 1;
            }
        }
    }
    let mut per_repo_recall: BTreeMap<String, u64> = BTreeMap::new();
    let mut min_recall = 1000_u64;
    for (project, total) in &per_repo_total {
        let covered = per_repo_covered.get(project).copied().unwrap_or(0);
        let permille = covered
            .saturating_mul(1000)
            .checked_div(*total)
            .unwrap_or(0);
        min_recall = min_recall.min(permille);
        per_repo_recall.insert((*project).to_string(), permille);
    }
    let gate_passed = min_recall >= compose_config.per_repo_recall_min_permille;
    let fleet_label = if gate_passed && artifact.anchor_grounded {
        "trusted"
    } else {
        "provisional"
    };
    let mut gate_reasons: Vec<String> = Vec::new();
    if !gate_passed {
        gate_reasons.push(format!(
            "per-repo recall min {min_recall} permille is below the {} gate",
            compose_config.per_repo_recall_min_permille
        ));
    }
    if !artifact.anchor_grounded {
        gate_reasons.push(
            "no Trusted anchor rollup among any constituent member (external repos are \
             provisional until anchors upgrade)"
                .to_string(),
        );
    }

    // Persist the kernel artifact (Kernel CF rows + paired ledger entry, byte
    // readback inside persist_kernel_artifact).
    let persist = persist_kernel_artifact(catalog.vault(), &artifact)
        .map_err(|error| inner_err("persist fleet kernel artifact", error))?;

    // Sidecar: provenance, gate, growth verdict — the serving surface (#459)
    // reads the label from here; a below-gate kernel is never served trusted.
    let members_provenance: Vec<Value> = artifact
        .members
        .iter()
        .map(|member| {
            let node = node_by_cx[&member.id];
            json!({
                "fleet_cx": member.id.to_string(),
                "node_kind": if node.content_key.is_some() { "content" } else { "content_free" },
                "content_key": node.content_key.as_ref().map(hex32),
                "repo_count": node.occurrences.iter().map(|o| o.project.as_str()).collect::<BTreeSet<_>>().len(),
                "grounded": node.grounded_any,
                "score_permille": member.score_permille,
                "occurrences": node.occurrences.iter().map(|occurrence| json!({
                    "project": occurrence.project,
                    "cx": occurrence.cx.to_string(),
                    "qualified_name": occurrence.qualified_name,
                    "rel_file_path": occurrence.rel_file_path,
                    "label": occurrence.label,
                    "language": occurrence.language,
                    "content_key": hex32(&occurrence.content_key),
                    "grounded": occurrence.grounded,
                    "score_permille": occurrence.score_permille,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let repos_summary: Vec<Value> = loads
        .iter()
        .map(|load| {
            json!({
                "project": load.project,
                "members_hash": load.members_hash,
                "member_count": load.occurrences.len(),
                "node_count": load.node_count,
                "repo_recall_permille": load.recall_permille,
                "missing_vector_members": load.missing_vector,
                "content_free_members": load.occurrences.iter().filter(|o| o.content_free).count(),
            })
        })
        .collect();
    let cross_repo_nodes = nodes
        .iter()
        .filter(|node| {
            node.occurrences
                .iter()
                .map(|occurrence| occurrence.project.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        })
        .count();
    let merged_class_nodes = nodes
        .iter()
        .filter(|node| node.occurrences.len() > 1)
        .count();
    let content_free_nodes = nodes
        .iter()
        .filter(|node| node.content_key.is_none())
        .count();
    let nodes_with_vectors = nodes.iter().filter(|node| node.centroid.is_some()).count();
    let sidecar = json!({
        "artifact": FLEET_KERNEL_SIDECAR_SCHEMA,
        "scope": scope,
        "compose_input_hash": input_hash,
        "verdict": {
            "kind": verdict_kind,
            "structural_delta": delta.structural,
            "previous_input_hash": previous_input_hash,
            "reason": if single_repo {
                "single-repo composition degenerates to that repo's kernel member classes \
                 (explicit; per-repo measured stats aggregated: score/degree/betweenness/\
                 groundedness=max, frequency=sum, flags=any)"
            } else if previous_input_hash.is_some() {
                "compose input changed: structural GraphDelta escalates to a full rebuild \
                 (incremental-until-structural-debt doctrine)"
            } else {
                "first composition at this scope: full build"
            },
        },
        "knobs": {
            "registry_version": FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
            KNOB_SIMILARITY_MIN: compose_config.similarity_min_permille,
            KNOB_SIMILARITY_TOP_K: compose_config.similarity_top_k,
            KNOB_PER_REPO_RECALL_MIN: compose_config.per_repo_recall_min_permille,
            "kernel_build_registry_version": KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        },
        "repos": repos_summary,
        "skipped_no_kernel": skipped,
        "skipped_no_kernel_count": skipped.len(),
        "nodes": {
            "total": nodes.len(),
            "merged_class_nodes": merged_class_nodes,
            "cross_repo_nodes": cross_repo_nodes,
            "content_free_nodes_unmerged": content_free_nodes,
            "nodes_with_vectors": nodes_with_vectors,
        },
        "edges": {
            "similarity_edges_directed": edge_count,
            "similarity_permille_histogram_by_100": sim_histogram,
        },
        "gate": {
            "per_repo_recall_permille": per_repo_recall,
            "min_recall_permille": min_recall,
            "gate_permille": compose_config.per_repo_recall_min_permille,
            "gated": gate_passed,
            "label": fleet_label,
            "reasons": gate_reasons,
        },
        "kernel": {
            "members_hash": artifact.members_hash,
            "member_count": artifact.member_count,
            "node_count": artifact.node_count,
            "fvs_count": artifact.fvs_count,
            "support_count": artifact.support_count,
            "recall_permille": artifact.recall.permille,
            "recall_gated": artifact.recall.gated,
            "trust": artifact.trust,
            "anchor_grounded": artifact.anchor_grounded,
            "commit_seq": persist.commit_seq,
        },
        "proxy_note": "#473: content keys derive from the #413 property-fingerprint proxy \
                       (libcbm retains no raw source); cross-repo dedup weighting undercounts \
                       (60% measured on a byte-identical pair, #455); mechanism upgrades \
                       transparently when raw snippets land",
        "members": members_provenance,
    });
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar).expect("sidecar serializes");
    let summary_payload = serde_json::to_vec(&json!({
        "event": "fleet_kernel_compose",
        "scope": scope,
        "compose_input_hash": input_hash,
        "members_hash": artifact.members_hash,
        "member_count": artifact.member_count,
        "label": fleet_label,
    }))
    .expect("sidecar summary serializes");
    let (sidecar_seq, sidecar_ledger_seq) = catalog.record_fleet_report(
        FLEET_KERNEL_REPORT_KIND,
        scope,
        sidecar_bytes,
        summary_payload,
    )?;

    Ok(json!({
        "verb": "compose",
        "scope": scope,
        "verdict": verdict_kind,
        "compose_input_hash": input_hash,
        "repos": loads.len(),
        "skipped_no_kernel": skipped.len(),
        "nodes_total": nodes.len(),
        "cross_repo_nodes": cross_repo_nodes,
        "similarity_edges_directed": edge_count,
        "member_count": artifact.member_count,
        "members_hash": artifact.members_hash,
        "recall_permille": artifact.recall.permille,
        "per_repo_recall_min_permille": min_recall,
        "gate": { "gated": gate_passed, "label": fleet_label },
        "kernel_commit_seq": persist.commit_seq,
        "sidecar_commit_seq": sidecar_seq,
        "sidecar_ledger_seq": sidecar_ledger_seq,
    }))
}

/// The explicit single-repo degenerate artifact: every fleet node (= the repo's
/// kernel member classes) is a member; stats are the repo's own measured values
/// aggregated by the declared policy; recall is measured for real over the
/// composed graph. All fields are measurements or declared aggregates — no
/// invented constants.
fn degenerate_single_repo_artifact(
    scope: &str,
    kernel_config: &KernelBuildConfig,
    graph: &KernelGraph,
    nodes: &[FleetNode],
    load: &RepoKernelLoad,
) -> Result<KernelArtifact, CalyxError> {
    let indexed = graph
        .compile()
        .map_err(|error| inner_err("compile degenerate fleet graph", error))?;
    let all: BTreeSet<usize> = (0..indexed.len()).collect();
    let mut recall = measure_recall(&indexed, &all, kernel_config.recall_answer_radius_hops);
    recall.gated = recall.permille >= kernel_config.recall_min_permille;

    let node_by_cx: BTreeMap<CxId, &FleetNode> =
        nodes.iter().map(|node| (node.fleet_cx, node)).collect();
    let members: Vec<KernelMember> = indexed
        .ids()
        .iter()
        .map(|id| {
            let node = node_by_cx[id];
            let occurrences = &node.occurrences;
            KernelMember {
                id: *id,
                score_permille: occurrences
                    .iter()
                    .map(|o| o.score_permille)
                    .max()
                    .unwrap_or(0),
                degree: occurrences.iter().map(|o| o.degree).max().unwrap_or(0),
                betweenness_permille: occurrences
                    .iter()
                    .map(|o| o.betweenness_permille)
                    .max()
                    .unwrap_or(0),
                groundedness_permille: occurrences
                    .iter()
                    .map(|o| o.groundedness_permille)
                    .max()
                    .unwrap_or(0),
                frequency: node.frequency_sum,
                grounded: node.grounded_any,
                in_fvs: occurrences.iter().any(|o| o.in_fvs),
                support_added: occurrences.iter().any(|o| o.support_added),
            }
        })
        .collect();
    let member_ids: Vec<CxId> = members.iter().map(|member| member.id).collect();
    let hash = members_hash(&member_ids);
    let anchor_grounded = members.iter().any(|member| member.grounded);
    let trust = rollup_trust(members.iter().map(|member| {
        if member.grounded {
            TrustTag::Trusted
        } else {
            TrustTag::Provisional
        }
    }));
    Ok(KernelArtifact {
        schema: KERNEL_ARTIFACT_SCHEMA.to_string(),
        scope_id: scope.to_string(),
        knob_registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION.to_string(),
        config: *kernel_config,
        node_count: indexed.len(),
        candidate_count: indexed.len(),
        fvs_count: 0,
        support_count: 0,
        member_count: members.len(),
        betweenness_exact: load.betweenness_exact,
        anchor_grounded,
        ungrounded_reason: if anchor_grounded {
            None
        } else {
            Some(
                "no Trusted anchor rollup among the single repo's kernel members; \
                 the degenerate fleet kernel is provisional"
                    .to_string(),
            )
        },
        recall,
        members,
        members_hash: hash,
        freshness: "fresh".to_string(),
        trust: trust.as_str().to_string(),
    })
}

/// Independent fleet-kernel readback for the `kernel-read` verb: re-reads the
/// persisted kernel.json row, re-derives the members-hash from the persisted
/// member set, verifies the paired members-hash ledger discipline via the
/// sidecar, and returns the summary JSON. `raw` instead returns the exact
/// persisted kernel.json bytes.
pub fn read_fleet_kernel(
    catalog: &FleetCatalog,
    scope: &str,
) -> Result<(Value, Vec<u8>), CalyxError> {
    let vault = catalog.vault();
    // Mirror of astrolabe-ingest::kernel_artifact::artifact_key (the prefix is
    // its exported contract) — read the raw row independently of the parser.
    let mut key = Vec::new();
    key.extend_from_slice(astrolabe_ingest::KERNEL_ARTIFACT_CF_PREFIX);
    key.extend_from_slice(scope.as_bytes());
    key.push(b':');
    key.extend_from_slice(b"kernel.json");
    let raw = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Kernel, &key)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("no fleet kernel artifact persisted at scope {scope:?}"),
            remediation: "run compose for the scope before reading it back",
        })?;
    let artifact: KernelArtifact = serde_json::from_slice(&raw).map_err(|error| CalyxError {
        code: ASTRO_FLEET_KERNEL_READBACK,
        message: format!("persisted kernel.json did not parse: {error}"),
        remediation: "the Kernel CF row is corrupt; recompose the fleet kernel",
    })?;
    let member_ids: Vec<CxId> = artifact.members.iter().map(|member| member.id).collect();
    let rederived = members_hash(&member_ids);
    if rederived != artifact.members_hash {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "re-derived members-hash {rederived} differs from persisted {}",
                artifact.members_hash
            ),
            remediation: "the persisted member set was tampered or torn; recompose",
        });
    }
    // One-serializer check: the parsed artifact must re-serialize to the exact
    // persisted bytes.
    let reserialized = artifact.kernel_json_bytes();
    let serializer_stable = reserialized == raw;

    // Independent members-hash ledger pairing (invariant 5): the Kernel CF
    // members-hash row and the latest Kernel ledger entry for this scope's
    // subject must carry the same bytes, and that entry's members_hash must
    // match the persisted artifact. Fail-closed on any divergence.
    let mut members_key = Vec::new();
    members_key.extend_from_slice(astrolabe_ingest::KERNEL_ARTIFACT_CF_PREFIX);
    members_key.extend_from_slice(scope.as_bytes());
    members_key.push(b':');
    members_key.extend_from_slice(b"members-hash");
    let members_row = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Kernel, &members_key)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("no members-hash row persisted at scope {scope:?}"),
            remediation: "recompose the fleet kernel; the artifact row set is torn",
        })?;
    let subject = format!("astrolabe-kernel:{scope}").into_bytes();
    let mut paired_payload: Option<Vec<u8>> = None;
    for (_key, bytes) in vault.scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)? {
        let entry = calyx_ledger::decode(&bytes)?;
        if entry.kind == calyx_ledger::EntryKind::Kernel
            && matches!(&entry.subject, calyx_ledger::SubjectId::Query(s) if s.as_slice() == subject.as_slice())
        {
            // Scan order is ascending; the last match is the latest entry.
            paired_payload = Some(entry.payload);
        }
    }
    let ledger_payload = paired_payload.ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_KERNEL_READBACK,
        message: format!("no Kernel ledger entry found for scope subject {scope:?}"),
        remediation: "recompose the fleet kernel; the mutation lost its ledger pairing",
    })?;
    if ledger_payload != members_row {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "Kernel ledger payload ({} bytes) differs from the members-hash row ({} bytes) for scope {scope:?}",
                ledger_payload.len(),
                members_row.len()
            ),
            remediation: "recompose the fleet kernel; row and ledger diverged",
        });
    }
    let ledger_entry: astrolabe_kernel::KernelLedgerEntry = serde_json::from_slice(&ledger_payload)
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("Kernel ledger payload did not parse: {error}"),
            remediation: "recompose the fleet kernel; the ledger payload is corrupt",
        })?;
    if ledger_entry.members_hash != artifact.members_hash {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "ledger members_hash {} differs from persisted kernel.json members_hash {}",
                ledger_entry.members_hash, artifact.members_hash
            ),
            remediation: "recompose the fleet kernel; row and ledger diverged",
        });
    }

    let sidecar = catalog
        .read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?
        .map(|bytes| {
            serde_json::from_slice::<Value>(&bytes).map_err(|error| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: format!("fleet-kernel sidecar did not parse: {error}"),
                remediation: "recompose the fleet kernel to rewrite the sidecar",
            })
        })
        .transpose()?;

    let summary = json!({
        "verb": "kernel-read",
        "scope": scope,
        "kernel_json_bytes": raw.len(),
        "kernel_json_blake3": blake3::hash(&raw).to_hex().as_str(),
        "members_hash_persisted": artifact.members_hash,
        "members_hash_rederived": rederived,
        "serializer_stable": serializer_stable,
        "ledger_paired": true,
        "ledger_members_hash": ledger_entry.members_hash,
        "ledger_member_count": ledger_entry.member_count,
        "member_count": artifact.member_count,
        "node_count": artifact.node_count,
        "recall_permille": artifact.recall.permille,
        "recall_gated": artifact.recall.gated,
        "trust": artifact.trust,
        "anchor_grounded": artifact.anchor_grounded,
        "sidecar": sidecar.as_ref().map(|value| json!({
            "compose_input_hash": value.get("compose_input_hash"),
            "verdict": value.get("verdict"),
            "gate": value.get("gate"),
            "nodes": value.get("nodes"),
            "edges": value.get("edges"),
            "skipped_no_kernel_count": value.get("skipped_no_kernel_count"),
        })),
    });
    Ok((summary, raw))
}

/// Verifies `sample_n` fleet members' provenance against reality: for each
/// sampled member every occurrence is re-resolved by re-scanning its project
/// vault's input store — the stored input's recomputed CxId, qualified name,
/// path, and content key must all match the sidecar claim. Fail-closed on any
/// divergence.
pub fn verify_member_provenance(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    sample_n: usize,
) -> Result<Value, CalyxError> {
    let sidecar_bytes = catalog
        .read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("no fleet-kernel sidecar persisted at scope {scope:?}"),
            remediation: "run compose before verifying provenance",
        })?;
    let sidecar: Value = serde_json::from_slice(&sidecar_bytes).map_err(|error| CalyxError {
        code: ASTRO_FLEET_KERNEL_READBACK,
        message: format!("fleet-kernel sidecar did not parse: {error}"),
        remediation: "recompose the fleet kernel to rewrite the sidecar",
    })?;
    let members = sidecar
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "sidecar carries no members array".to_string(),
            remediation: "recompose the fleet kernel",
        })?;
    if members.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "sidecar members array is empty".to_string(),
            remediation: "recompose the fleet kernel",
        });
    }
    let sample_n = sample_n.min(members.len()).max(1);
    let mut sampled: Vec<&Value> = Vec::with_capacity(sample_n);
    for slot in 0..sample_n {
        sampled.push(&members[slot * members.len() / sample_n]);
    }

    // Group sampled occurrences by project so each vault scans once.
    let mut by_project: BTreeMap<String, Vec<(String, Value)>> = BTreeMap::new();
    for member in &sampled {
        let fleet_cx = member
            .get("fleet_cx")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        for occurrence in member
            .get("occurrences")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let project = occurrence
                .get("project")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            by_project
                .entry(project)
                .or_default()
                .push((fleet_cx.clone(), occurrence.clone()));
        }
    }

    let mut verified = 0_usize;
    for (project, claims) in &by_project {
        let vault = open_shadow_vault(store_root, project)?;
        let by_cx = input_atoms_by_cx(&vault, project)?;
        for (fleet_cx, claim) in claims {
            let cx_str = claim.get("cx").and_then(Value::as_str).unwrap_or("");
            let cx = CxId::from_str(cx_str).map_err(|error| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: format!("sidecar occurrence cx {cx_str:?} did not parse: {error:?}"),
                remediation: "recompose the fleet kernel",
            })?;
            let Some(frames) = by_cx.get(&cx) else {
                return Err(CalyxError {
                    code: ASTRO_FLEET_PROVENANCE_MISMATCH,
                    message: format!(
                        "fleet member {fleet_cx} claims occurrence {cx} in {project}, but no \
                         stored input record recomputes to that CxId"
                    ),
                    remediation: "the sidecar diverged from the project vault; recompose",
                });
            };
            let claimed_name = claim.get("qualified_name").and_then(Value::as_str);
            let claimed_path = claim.get("rel_file_path").and_then(Value::as_str);
            let claimed_key = claim.get("content_key").and_then(Value::as_str);
            if claimed_name != Some(frames.qualified_name.as_str())
                || claimed_path != Some(frames.rel_file_path.as_str())
                || claimed_key != Some(hex32(&frames.content_key).as_str())
            {
                return Err(CalyxError {
                    code: ASTRO_FLEET_PROVENANCE_MISMATCH,
                    message: format!(
                        "fleet member {fleet_cx} occurrence {cx} in {project}: sidecar claims \
                         name={claimed_name:?} path={claimed_path:?} key={claimed_key:?} but the \
                         vault holds name={:?} path={:?} key={:?}",
                        frames.qualified_name,
                        frames.rel_file_path,
                        hex32(&frames.content_key)
                    ),
                    remediation: "the sidecar diverged from the project vault; recompose",
                });
            }
            verified += 1;
        }
    }

    Ok(json!({
        "verb": "kernel-read",
        "provenance_verified": true,
        "sampled_members": sampled.len(),
        "occurrences_verified": verified,
        "projects_scanned": by_project.len(),
    }))
}
