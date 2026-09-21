//! Kernel build pipeline: score, deterministic feedback-vertex-set core, graph-coverage
//! diagnostic, compactness admission, and canonical artifact bytes (#37).
//!
//! Pipeline (blueprint 09 §1): iterative Tarjan SCC → `betweenness_auto` →
//! canonical full-graph DFS back-edge-source FVS → member importance score
//! `0.40·degree + 0.40·betweenness + 0.20·groundedness` → strict
//! member-fraction admission plus diagnostic graph coverage. Every
//! threshold and weight is a registry-declared knob (invariant 4); every score
//! that reaches the persisted artifact is an integer permille, so `kernel.json`
//! is byte-identical across runs and worker counts (invariant 5). Durable
//! publication is owned by the composite Aster generation transaction.

use std::collections::{BTreeSet, VecDeque};

use astrolabe_domain::calyx::{CxId, content_address};
use astrolabe_domain::{DomainError, Result, TrustTag, rollup_trust};
use serde::{Deserialize, Serialize};

use crate::U64KnobDeclaration;
use crate::betweenness::betweenness_auto;
use crate::fvs::{
    FVS_RESIDUAL_PROOF_SCHEMA, FVS_SELECTION_SCHEMA, FVS_VALIDITY_METHOD,
    canonical_dfs_feedback_vertex_set,
};
use crate::groundedness::score_groundedness;
use crate::kernel_graph::{ASTRO_KERNEL_EMPTY_GRAPH, KernelGraph};

/// Schema tag for a persisted kernel artifact.
pub const KERNEL_ARTIFACT_SCHEMA: &str = "astrolabe.kernel.v3";
/// Schema tag for a persisted kernel index manifest.
pub const KERNEL_INDEX_SCHEMA: &str = "astrolabe.kernel_index.v3";
/// Schema tag for a kernel-build ledger entry.
pub const KERNEL_LEDGER_SCHEMA: &str = "astrolabe.kernel_ledger.v3";
/// Knob registry version for the kernel build pipeline.
pub const KERNEL_BUILD_KNOB_REGISTRY_VERSION: &str = "astro.kernel.build_knobs.v3";
/// Schema for a reusable betweenness vector bound to its complete identity.
pub const KERNEL_BETWEENNESS_CACHE_SCHEMA: &str = "astrolabe.kernel.betweenness_cache.v1";
/// Schema for the exact source graph/config identity bound into every artifact.
pub const KERNEL_SOURCE_IDENTITY_SCHEMA: &str = "astrolabe.kernel.source_identity.v1";
/// Algorithm identity covered by [`KernelSourceIdentity::config_hash`].
pub const KERNEL_BUILD_ALGORITHM_SCHEMA: &str = "astrolabe.kernel.build_algorithm.v3";
/// Framing tag for the members hash preimage.
pub const KERNEL_MEMBERS_HASH_TAG: &[u8] = b"astro.kernel.members.v1";

/// Refusal raised when the score weights do not sum to 1000 permille.
pub const ASTRO_KERNEL_WEIGHT_SUM: &str = "ASTRO_KERNEL_WEIGHT_SUM";
/// Refusal raised when a kernel build knob is outside its declared bounds.
pub const ASTRO_KERNEL_KNOB_RANGE: &str = "ASTRO_KERNEL_KNOB_RANGE";
/// Refusal raised when a kernel cannot remain below its member-fraction ceiling.
pub const ASTRO_KERNEL_COMPACTNESS_UNREACHABLE: &str = "ASTRO_KERNEL_COMPACTNESS_UNREACHABLE";
/// Refusal raised when an unbound, stale, or mismatched betweenness cache is supplied.
pub const ASTRO_KERNEL_BETWEENNESS_CACHE_MISMATCH: &str = "ASTRO_KERNEL_BETWEENNESS_CACHE_MISMATCH";
/// Refusal raised when a persisted kernel is stale against the current projection/config.
pub const ASTRO_KERNEL_SOURCE_IDENTITY_MISMATCH: &str = "ASTRO_KERNEL_SOURCE_IDENTITY_MISMATCH";
/// Refusal raised when an acyclic source is presented as an answer kernel.
pub const ASTRO_KERNEL_NO_CYCLIC_CORE: &str = "ASTRO_KERNEL_NO_CYCLIC_CORE";
/// Refusal raised when a canonical counter, capacity, or fixed-point score is
/// not representable without changing the persisted measurement.
pub const ASTRO_KERNEL_REPRESENTATION_OVERFLOW: &str = "ASTRO_KERNEL_REPRESENTATION_OVERFLOW";
// Knob names.
pub const KNOB_WEIGHT_DEGREE: &str = "kernel.score.weight_degree_permille";
pub const KNOB_WEIGHT_BETWEENNESS: &str = "kernel.score.weight_betweenness_permille";
pub const KNOB_WEIGHT_GROUNDEDNESS: &str = "kernel.score.weight_groundedness_permille";
pub const KNOB_GROUNDEDNESS_HOP_LIMIT: &str = "kernel.groundedness.hop_limit";
pub const KNOB_GROUNDEDNESS_FREQ_CAP: &str = "kernel.groundedness.freq_cap";
pub const KNOB_GROUNDEDNESS_FREQ_BONUS: &str = "kernel.groundedness.freq_bonus_permille";
pub const KNOB_BETWEENNESS_EXACT_MAX_NODES: &str = "kernel.betweenness.exact_max_nodes";
pub const KNOB_BETWEENNESS_SAMPLE_PIVOTS: &str = "kernel.betweenness.sample_pivots";
pub const KNOB_BETWEENNESS_SAMPLE_SEED: &str = "kernel.betweenness.sample_seed";
pub const KNOB_GRAPH_COVERAGE_MIN_PERMILLE: &str = "kernel.graph_coverage.min_permille";
pub const KNOB_GRAPH_COVERAGE_RADIUS: &str = "kernel.graph_coverage.radius_hops";
pub const KNOB_MAX_MEMBER_FRACTION: &str = "kernel.compactness.max_member_fraction_permille";

const SOURCE: &str = "docs/astrolabe-blueprint.md#09-the-kernel--context-engine";

/// All kernel build knobs with their declared bounds.
pub const KERNEL_BUILD_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_WEIGHT_DEGREE,
        default: 400,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "degree term of the selected member importance score; the three weights sum to 1000 (0.40·degree)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_WEIGHT_BETWEENNESS,
        default: 400,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "betweenness term of the selected member importance score (0.40·betweenness)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_WEIGHT_GROUNDEDNESS,
        default: 200,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "groundedness term of the selected member importance score (0.20·groundedness)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_GROUNDEDNESS_HOP_LIMIT,
        default: 3,
        min: 1,
        max: 16,
        unit: "hops",
        source: SOURCE,
        rationale: "BFS hop budget from a node to a Trusted anchor for groundedness",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_GROUNDEDNESS_FREQ_CAP,
        default: 10_000,
        min: 1,
        max: 1_000_000_000,
        unit: "changes",
        source: SOURCE,
        rationale: "saturating cap on change frequency in the ln frequency bonus (10^4)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_GROUNDEDNESS_FREQ_BONUS,
        default: 150,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "scale of the hot-symbol frequency bonus added to groundedness (0.15)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_BETWEENNESS_EXACT_MAX_NODES,
        default: 2_000,
        min: 1,
        max: 1_000_000_000,
        unit: "nodes",
        source: SOURCE,
        rationale: "exact Brandes betweenness at or below this node count, else sampled",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_BETWEENNESS_SAMPLE_PIVOTS,
        default: 512,
        min: 1,
        max: 1_000_000_000,
        unit: "pivots",
        source: SOURCE,
        rationale: "deterministic source pivots for sampled betweenness (proven number)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_BETWEENNESS_SAMPLE_SEED,
        default: 0x5445_524d_494e_5553,
        min: 0,
        max: u64::MAX,
        unit: "seed",
        source: SOURCE,
        rationale: "pinned seed for deterministic, worker-count-invariant pivot selection",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_GRAPH_COVERAGE_MIN_PERMILLE,
        default: 950,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "diagnostic undirected graph coverage floor; this is not retrieval recall",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_GRAPH_COVERAGE_RADIUS,
        default: 2,
        min: 0,
        max: 16,
        unit: "hops",
        source: SOURCE,
        rationale: "undirected radius used only by the graph-coverage diagnostic",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_MAX_MEMBER_FRACTION,
        default: 999,
        min: 1,
        max: 999,
        unit: "permille",
        source: SOURCE,
        rationale: "strict compactness ceiling; a whole-corpus member roster is never admissible",
    },
];

/// Fully resolved kernel build knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelBuildConfig {
    /// Degree weight in permille.
    pub weight_degree_permille: u64,
    /// Betweenness weight in permille.
    pub weight_betweenness_permille: u64,
    /// Groundedness weight in permille.
    pub weight_groundedness_permille: u64,
    /// Groundedness BFS hop limit.
    pub groundedness_hop_limit: u64,
    /// Frequency-bonus saturation cap.
    pub groundedness_freq_cap: u64,
    /// Frequency-bonus scale in permille.
    pub groundedness_freq_bonus_permille: u64,
    /// Exact-betweenness node ceiling.
    pub betweenness_exact_max_nodes: u64,
    /// Sampled-betweenness pivot count.
    pub betweenness_sample_pivots: u64,
    /// Sampled-betweenness pinned seed.
    pub betweenness_sample_seed: u64,
    /// Diagnostic graph-coverage floor.
    pub graph_coverage_min_permille: u64,
    /// Undirected graph-coverage radius.
    pub graph_coverage_radius_hops: u64,
    /// Strict upper bound on kernel members as a fraction of source nodes.
    pub max_member_fraction_permille: u64,
}

impl KernelBuildConfig {
    /// Returns the registry-default configuration.
    pub fn with_registry_defaults() -> Self {
        Self {
            weight_degree_permille: knob_default(KNOB_WEIGHT_DEGREE),
            weight_betweenness_permille: knob_default(KNOB_WEIGHT_BETWEENNESS),
            weight_groundedness_permille: knob_default(KNOB_WEIGHT_GROUNDEDNESS),
            groundedness_hop_limit: knob_default(KNOB_GROUNDEDNESS_HOP_LIMIT),
            groundedness_freq_cap: knob_default(KNOB_GROUNDEDNESS_FREQ_CAP),
            groundedness_freq_bonus_permille: knob_default(KNOB_GROUNDEDNESS_FREQ_BONUS),
            betweenness_exact_max_nodes: knob_default(KNOB_BETWEENNESS_EXACT_MAX_NODES),
            betweenness_sample_pivots: knob_default(KNOB_BETWEENNESS_SAMPLE_PIVOTS),
            betweenness_sample_seed: knob_default(KNOB_BETWEENNESS_SAMPLE_SEED),
            graph_coverage_min_permille: knob_default(KNOB_GRAPH_COVERAGE_MIN_PERMILLE),
            graph_coverage_radius_hops: knob_default(KNOB_GRAPH_COVERAGE_RADIUS),
            max_member_fraction_permille: knob_default(KNOB_MAX_MEMBER_FRACTION),
        }
    }

    /// Validates every knob against its declared bounds and the weight-sum
    /// invariant, fail-closed.
    pub fn validate(&self) -> Result<()> {
        check_range(KNOB_WEIGHT_DEGREE, self.weight_degree_permille)?;
        check_range(KNOB_WEIGHT_BETWEENNESS, self.weight_betweenness_permille)?;
        check_range(KNOB_WEIGHT_GROUNDEDNESS, self.weight_groundedness_permille)?;
        check_range(KNOB_GROUNDEDNESS_HOP_LIMIT, self.groundedness_hop_limit)?;
        check_range(KNOB_GROUNDEDNESS_FREQ_CAP, self.groundedness_freq_cap)?;
        check_range(
            KNOB_GROUNDEDNESS_FREQ_BONUS,
            self.groundedness_freq_bonus_permille,
        )?;
        check_range(
            KNOB_BETWEENNESS_EXACT_MAX_NODES,
            self.betweenness_exact_max_nodes,
        )?;
        check_range(
            KNOB_BETWEENNESS_SAMPLE_PIVOTS,
            self.betweenness_sample_pivots,
        )?;
        check_range(KNOB_BETWEENNESS_SAMPLE_SEED, self.betweenness_sample_seed)?;
        check_range(
            KNOB_GRAPH_COVERAGE_MIN_PERMILLE,
            self.graph_coverage_min_permille,
        )?;
        check_range(KNOB_GRAPH_COVERAGE_RADIUS, self.graph_coverage_radius_hops)?;
        check_range(KNOB_MAX_MEMBER_FRACTION, self.max_member_fraction_permille)?;
        let sum = self.weight_degree_permille
            + self.weight_betweenness_permille
            + self.weight_groundedness_permille;
        if sum != 1000 {
            return Err(DomainError::new(
                ASTRO_KERNEL_WEIGHT_SUM,
                format!(
                    "kernel score weights {}+{}+{}={} permille must sum to 1000",
                    self.weight_degree_permille,
                    self.weight_betweenness_permille,
                    self.weight_groundedness_permille,
                    sum
                ),
                "set degree/betweenness/groundedness weights that sum to 1000 permille",
            ));
        }
        Ok(())
    }
}

fn knob_default(name: &str) -> u64 {
    KERNEL_BUILD_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("kernel build knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<()> {
    let knob = KERNEL_BUILD_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("kernel build knob is declared");
    if value < knob.min || value > knob.max {
        return Err(DomainError::new(
            ASTRO_KERNEL_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the kernel build knob within its registered bounds",
        ));
    }
    Ok(())
}

/// Diagnostic undirected graph coverage at a declared radius.
///
/// This is not query recall and cannot prove answer-path quality. Its explicit
/// metric and admission-role fields survive serialization so a downstream
/// reader cannot relabel it as retrieval recall.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphCoverageMeasurement {
    /// Exact metric discriminator.
    pub metric: String,
    /// Explicitly diagnostic; graph-routed recall is tracked separately by #1148.
    pub admission_role: String,
    /// Undirected hop radius used for coverage.
    pub radius_hops: u64,
    /// Covered graph nodes.
    pub covered: u64,
    /// Total graph nodes.
    pub total: u64,
    /// `covered / total` in permille.
    pub permille: u64,
    /// Whether the diagnostic reaches its declared coverage floor.
    pub meets_coverage_floor: bool,
}

/// Full-graph validity evidence for deterministic feedback vertex selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FvsValidityProof {
    pub method: String,
    pub cyclic_scc_count: usize,
    pub largest_cyclic_scc_node_count: usize,
    pub dfs_checked_edge_count: usize,
    pub dfs_back_edge_count: usize,
    pub dfs_back_edge_roster_hash: String,
    pub residual_node_count: usize,
    pub residual_topological_order_hash: String,
}

/// Strict member-fraction admission evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCompactness {
    pub member_count: usize,
    pub source_node_count: usize,
    pub member_fraction_permille: u64,
    pub max_member_fraction_permille: u64,
    pub admitted: bool,
}

/// A reusable betweenness vector bound to canonical topology, ordinal roster,
/// and every configuration input that affects the vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetweennessCache {
    pub schema: String,
    pub node_count: usize,
    pub node_roster_hash: String,
    pub topology_hash: String,
    pub config_hash: String,
    pub exact: bool,
    pub sources_used: usize,
    pub permille: Vec<u64>,
    pub permille_hash: String,
    pub cache_hash: String,
}

/// Exact canonical source graph and algorithm-config identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSourceIdentity {
    pub schema: String,
    pub algorithm_schema: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub node_roster_hash: String,
    pub anchor_trust_roster_hash: String,
    pub directed_topology_hash: String,
    pub weighted_edge_roster_hash: String,
    pub config_hash: String,
    pub combined_hash: String,
}

/// Exact subset of [`KernelSourceIdentity`] observable from the current graph
/// projection without consulting the separate anchor-trust source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelProjectionIdentity {
    pub node_count: usize,
    pub edge_count: usize,
    pub node_roster_hash: String,
    pub directed_topology_hash: String,
    pub weighted_edge_roster_hash: String,
}

impl KernelSourceIdentity {
    /// Projection fields a serve-time CSR read must reproduce exactly.
    pub fn projection_identity(&self) -> KernelProjectionIdentity {
        KernelProjectionIdentity {
            node_count: self.node_count,
            edge_count: self.edge_count,
            node_roster_hash: self.node_roster_hash.clone(),
            directed_topology_hash: self.directed_topology_hash.clone(),
            weighted_edge_roster_hash: self.weighted_edge_roster_hash.clone(),
        }
    }
}

/// One kernel member row in a persisted artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelMember {
    /// Symbol version identity.
    pub id: CxId,
    /// Combined importance score in permille for this already-selected member.
    pub score_permille: u64,
    /// Directed degree.
    pub degree: u64,
    /// Betweenness in permille.
    pub betweenness_permille: u64,
    /// Groundedness in permille.
    pub groundedness_permille: u64,
    /// Change frequency (`change_count + 1`).
    pub frequency: u64,
    /// Whether a Trusted anchor is within the groundedness hop limit.
    pub grounded: bool,
    /// Whether the member came from the feedback-vertex-set core.
    pub in_fvs: bool,
}

/// A fully computed kernel artifact ready to persist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelArtifact {
    /// Artifact schema tag.
    pub schema: String,
    /// Scope identity this kernel was built for.
    pub scope_id: String,
    /// Knob registry version in force.
    pub knob_registry_version: String,
    /// The knobs used.
    pub config: KernelBuildConfig,
    /// Total nodes in the source graph.
    pub node_count: usize,
    /// Canonical full source graph and configuration identity.
    pub source_identity: KernelSourceIdentity,
    /// Feedback-vertex-set core size.
    pub fvs_count: usize,
    /// Deterministic DFS selection and complete residual-DAG proof.
    pub fvs_validity: FvsValidityProof,
    /// Total kernel members.
    pub member_count: usize,
    /// Whether betweenness was computed exactly.
    pub betweenness_exact: bool,
    /// Whether any Trusted anchor exists in scope.
    pub anchor_grounded: bool,
    /// Set only when the kernel has no Trusted anchor in scope.
    pub ungrounded_reason: Option<String>,
    /// Diagnostic graph coverage.
    pub graph_coverage: GraphCoverageMeasurement,
    /// Strict compactness admission carried by the persisted kernel.
    pub compactness: KernelCompactness,
    /// Members, ascending by `CxId`.
    pub members: Vec<KernelMember>,
    /// Hex members-hash over the ascending member identities.
    pub members_hash: String,
    /// Freshness label.
    pub freshness: String,
    /// Trust label rolled up from member groundedness.
    pub trust: String,
}

impl KernelArtifact {
    /// Serializes the artifact into the canonical pretty `kernel.json` bytes.
    pub fn kernel_json_bytes(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(self).expect("kernel artifact serializes");
        bytes.push(b'\n');
        bytes
    }

    /// Serializes the index membership manifest into `index.json` bytes.
    pub fn index_json_bytes(&self) -> Vec<u8> {
        let manifest = KernelIndexManifest {
            schema: KERNEL_INDEX_SCHEMA.to_string(),
            scope_id: self.scope_id.clone(),
            member_count: self.member_count,
            members_hash: self.members_hash.clone(),
            members: self.members.iter().map(|member| member.id).collect(),
            source_identity: self.source_identity.clone(),
            index_kind: "membership_manifest".to_string(),
            note:
                "Vector HNSW is built downstream from universal S20 name-semantic embeddings; this \
                   manifest pins the exact member set and order that index must \
                   cover, content-addressed by members_hash."
                    .to_string(),
            fvs_validity: self.fvs_validity.clone(),
            graph_coverage: self.graph_coverage.clone(),
            compactness: self.compactness,
            freshness: self.freshness.clone(),
            trust: self.trust.clone(),
        };
        let mut bytes = serde_json::to_vec_pretty(&manifest).expect("index manifest serializes");
        bytes.push(b'\n');
        bytes
    }

    /// Builds the members-hash ledger entry for this artifact.
    pub fn ledger_entry(&self) -> KernelLedgerEntry {
        KernelLedgerEntry {
            schema: KERNEL_LEDGER_SCHEMA.to_string(),
            entry_kind: "kernel_build".to_string(),
            scope_id: self.scope_id.clone(),
            members_hash: self.members_hash.clone(),
            member_count: self.member_count,
            source_identity: self.source_identity.clone(),
            fvs_validity: self.fvs_validity.clone(),
            graph_coverage: self.graph_coverage.clone(),
            compactness: self.compactness,
        }
    }
}

/// The `index.json` membership manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelIndexManifest {
    /// Manifest schema tag.
    pub schema: String,
    /// Scope identity.
    pub scope_id: String,
    /// Member count.
    pub member_count: usize,
    /// Members-hash the manifest is content-addressed by.
    pub members_hash: String,
    /// Member identities, ascending.
    pub members: Vec<CxId>,
    /// Canonical full source graph and configuration identity.
    pub source_identity: KernelSourceIdentity,
    /// Index kind discriminator.
    pub index_kind: String,
    /// Honesty note describing the manifest boundary.
    pub note: String,
    /// Full-graph deterministic-FVS validity proof.
    pub fvs_validity: FvsValidityProof,
    /// Diagnostic graph coverage the members achieve.
    pub graph_coverage: GraphCoverageMeasurement,
    /// Strict compactness admission.
    pub compactness: KernelCompactness,
    /// Freshness label.
    pub freshness: String,
    /// Trust label.
    pub trust: String,
}

/// A kernel-build ledger entry pairing the artifact write with its members-hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelLedgerEntry {
    /// Ledger entry schema tag.
    pub schema: String,
    /// Ledger entry kind.
    pub entry_kind: String,
    /// Scope identity.
    pub scope_id: String,
    /// Members-hash of the persisted kernel.
    pub members_hash: String,
    /// Member count.
    pub member_count: usize,
    /// Canonical full source graph and configuration identity.
    pub source_identity: KernelSourceIdentity,
    /// Full-graph deterministic-FVS validity proof.
    pub fvs_validity: FvsValidityProof,
    /// Diagnostic graph coverage recorded with the build.
    pub graph_coverage: GraphCoverageMeasurement,
    /// Strict compactness admission.
    pub compactness: KernelCompactness,
}

/// Computes the hex members-hash over an ascending member identity set.
pub fn members_hash(member_ids: &[CxId]) -> String {
    let mut sorted: Vec<CxId> = member_ids.to_vec();
    sorted.sort_unstable();
    let mut hash = FramedContentAddress::new();
    hash.update(KERNEL_MEMBERS_HASH_TAG);
    for id in &sorted {
        hash.update(id.as_bytes());
    }
    hex_lower(&hash.finalize())
}

/// Recomputes the exact canonical source identity used by a kernel artifact.
///
/// Server readers must construct a [`KernelGraph`] from the current CSR/source
/// generation, call this function with the artifact's persisted config, and
/// require exact equality with [`KernelArtifact::source_identity`] before
/// serving the artifact.
pub fn kernel_source_identity(
    graph: &KernelGraph,
    config: &KernelBuildConfig,
) -> Result<KernelSourceIdentity> {
    config.validate()?;
    let (node_order, edge_order) = canonical_source_order(graph);
    let projection = kernel_projection_identity_in_order(graph, &node_order, &edge_order);
    let mut anchor_hash = FramedContentAddress::new();
    anchor_hash.update(b"astro.kernel.source.anchor_trust_roster.v1");
    anchor_hash.update(&(node_order.len() as u64).to_be_bytes());
    for &index in &node_order {
        let node = &graph.nodes()[index];
        anchor_hash.update(node.id.as_bytes());
        anchor_hash.update(
            node.anchor_trust
                .map(TrustTag::as_str)
                .unwrap_or("none")
                .as_bytes(),
        );
    }
    let anchor_trust_roster_hash = hex_lower(&anchor_hash.finalize());
    let config_hash = kernel_build_config_hash(config);
    let combined_hash =
        kernel_source_combined_hash(&projection, &anchor_trust_roster_hash, &config_hash);

    Ok(KernelSourceIdentity {
        schema: KERNEL_SOURCE_IDENTITY_SCHEMA.to_string(),
        algorithm_schema: KERNEL_BUILD_ALGORITHM_SCHEMA.to_string(),
        node_count: projection.node_count,
        edge_count: projection.edge_count,
        node_roster_hash: projection.node_roster_hash,
        anchor_trust_roster_hash,
        directed_topology_hash: projection.directed_topology_hash,
        weighted_edge_roster_hash: projection.weighted_edge_roster_hash,
        config_hash,
        combined_hash,
    })
}

/// Computes the exact identity observable from a current graph projection.
/// Node anchor trust is deliberately excluded because it is a separate source;
/// [`KernelSourceIdentity::anchor_trust_roster_hash`] binds it independently.
pub fn kernel_projection_identity(graph: &KernelGraph) -> KernelProjectionIdentity {
    let (node_order, edge_order) = canonical_source_order(graph);
    kernel_projection_identity_in_order(graph, &node_order, &edge_order)
}

fn canonical_source_order(graph: &KernelGraph) -> (Vec<usize>, Vec<usize>) {
    let mut node_order: Vec<usize> = (0..graph.nodes().len()).collect();
    node_order.sort_unstable_by_key(|&index| graph.nodes()[index].id);
    let mut edge_order: Vec<usize> = (0..graph.edges().len()).collect();
    edge_order.sort_unstable_by(|&left, &right| {
        let left = graph.edges()[left];
        let right = graph.edges()[right];
        left.src
            .cmp(&right.src)
            .then_with(|| left.dst.cmp(&right.dst))
            .then_with(|| left.weight.to_bits().cmp(&right.weight.to_bits()))
    });
    (node_order, edge_order)
}

fn kernel_projection_identity_in_order(
    graph: &KernelGraph,
    node_order: &[usize],
    edge_order: &[usize],
) -> KernelProjectionIdentity {
    let mut node_hash = FramedContentAddress::new();
    node_hash.update(b"astro.kernel.source.projection_node_roster.v1");
    node_hash.update(&(node_order.len() as u64).to_be_bytes());
    for &index in node_order {
        let node = &graph.nodes()[index];
        node_hash.update(node.id.as_bytes());
        node_hash.update(&node.frequency.to_be_bytes());
    }
    let mut topology_hash = FramedContentAddress::new();
    topology_hash.update(b"astro.kernel.source.directed_topology.v1");
    topology_hash.update(&(edge_order.len() as u64).to_be_bytes());
    let mut weighted_hash = FramedContentAddress::new();
    weighted_hash.update(b"astro.kernel.source.weighted_edge_roster.v1");
    weighted_hash.update(&(edge_order.len() as u64).to_be_bytes());
    for &index in edge_order {
        let edge = graph.edges()[index];
        topology_hash.update(edge.src.as_bytes());
        topology_hash.update(edge.dst.as_bytes());
        weighted_hash.update(edge.src.as_bytes());
        weighted_hash.update(edge.dst.as_bytes());
        weighted_hash.update(&edge.weight.to_bits().to_be_bytes());
    }

    KernelProjectionIdentity {
        node_count: node_order.len(),
        edge_count: edge_order.len(),
        node_roster_hash: hex_lower(&node_hash.finalize()),
        directed_topology_hash: hex_lower(&topology_hash.finalize()),
        weighted_edge_roster_hash: hex_lower(&weighted_hash.finalize()),
    }
}

/// Streaming equivalent of `calyx_core::content_address`. Each part is framed
/// exactly once, preserving the existing hash bytes without allocating one
/// heap buffer per graph field.
struct FramedContentAddress {
    hasher: blake3::Hasher,
}

impl FramedContentAddress {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, part: &[u8]) {
        self.hasher.update(&(part.len() as u64).to_be_bytes());
        self.hasher.update(part);
    }

    fn finalize(self) -> [u8; 16] {
        let digest = self.hasher.finalize();
        let mut output = [0_u8; 16];
        output.copy_from_slice(&digest.as_bytes()[..16]);
        output
    }
}

/// Recomputes the algorithm/config identity carried by a source identity.
pub fn kernel_build_config_identity(config: &KernelBuildConfig) -> Result<String> {
    config.validate()?;
    Ok(kernel_build_config_hash(config))
}

/// Verifies a persisted source identity against the current graph projection
/// and the artifact's config. Anchor trust has a separately stored hash; callers
/// that own the current anchor roster must additionally recompute the complete
/// [`kernel_source_identity`] and require exact equality.
pub fn verify_kernel_source_projection_identity(
    graph: &KernelGraph,
    config: &KernelBuildConfig,
    expected: &KernelSourceIdentity,
) -> Result<()> {
    let observed_projection = kernel_projection_identity(graph);
    let observed_config_hash = kernel_build_config_identity(config)?;
    let expected_projection = expected.projection_identity();
    let internally_recomputed_combined = kernel_source_combined_hash(
        &expected_projection,
        &expected.anchor_trust_roster_hash,
        &expected.config_hash,
    );
    let matches = expected.schema == KERNEL_SOURCE_IDENTITY_SCHEMA
        && expected.algorithm_schema == KERNEL_BUILD_ALGORITHM_SCHEMA
        && observed_projection == expected_projection
        && observed_config_hash == expected.config_hash
        && internally_recomputed_combined == expected.combined_hash;
    if !matches {
        return Err(DomainError::new(
            ASTRO_KERNEL_SOURCE_IDENTITY_MISMATCH,
            format!(
                "kernel source identity mismatch: schema expected={} actual={} algorithm expected={} actual={} projection expected={expected_projection:?} observed={observed_projection:?} config_hash expected={} observed={} combined_hash stored={} recomputed={}",
                KERNEL_SOURCE_IDENTITY_SCHEMA,
                expected.schema,
                KERNEL_BUILD_ALGORITHM_SCHEMA,
                expected.algorithm_schema,
                expected.config_hash,
                observed_config_hash,
                expected.combined_hash,
                internally_recomputed_combined,
            ),
            "rebuild the kernel from the current canonical graph projection and anchor roster; never serve or silently refresh a stale artifact on the read path",
        ));
    }
    Ok(())
}

fn kernel_source_combined_hash(
    projection: &KernelProjectionIdentity,
    anchor_trust_roster_hash: &str,
    config_hash: &str,
) -> String {
    hex_lower(&content_address([
        b"astro.kernel.source.combined.v1".as_slice(),
        KERNEL_SOURCE_IDENTITY_SCHEMA.as_bytes(),
        KERNEL_BUILD_ALGORITHM_SCHEMA.as_bytes(),
        &(projection.node_count as u64).to_be_bytes(),
        &(projection.edge_count as u64).to_be_bytes(),
        projection.node_roster_hash.as_bytes(),
        anchor_trust_roster_hash.as_bytes(),
        projection.directed_topology_hash.as_bytes(),
        projection.weighted_edge_roster_hash.as_bytes(),
        config_hash.as_bytes(),
    ]))
}

fn kernel_build_config_hash(config: &KernelBuildConfig) -> String {
    hex_lower(&content_address([
        b"astro.kernel.build.config.v3".as_slice(),
        KERNEL_BUILD_ALGORITHM_SCHEMA.as_bytes(),
        KERNEL_BUILD_KNOB_REGISTRY_VERSION.as_bytes(),
        &config.weight_degree_permille.to_be_bytes(),
        &config.weight_betweenness_permille.to_be_bytes(),
        &config.weight_groundedness_permille.to_be_bytes(),
        &config.groundedness_hop_limit.to_be_bytes(),
        &config.groundedness_freq_cap.to_be_bytes(),
        &config.groundedness_freq_bonus_permille.to_be_bytes(),
        &config.betweenness_exact_max_nodes.to_be_bytes(),
        &config.betweenness_sample_pivots.to_be_bytes(),
        &config.betweenness_sample_seed.to_be_bytes(),
        &config.graph_coverage_min_permille.to_be_bytes(),
        &config.graph_coverage_radius_hops.to_be_bytes(),
        &config.max_member_fraction_permille.to_be_bytes(),
        FVS_SELECTION_SCHEMA.as_bytes(),
        FVS_RESIDUAL_PROOF_SCHEMA.as_bytes(),
    ]))
}

/// Builds a full-graph-FVS-validated, compact, grounded kernel for a scope.
///
/// Refuses fail-closed on an empty graph ([`ASTRO_KERNEL_EMPTY_GRAPH`]) — a
/// kernel over zero symbols is meaningless. An anchor-ungrounded scope still
/// yields a kernel, tagged provisional with `ungrounded_reason` set (blueprint
/// 09 §7). The persisted kernel carries diagnostic graph coverage, never a
/// retrieval-recall claim.
pub fn build_kernel(
    graph: &KernelGraph,
    scope_id: &str,
    config: &KernelBuildConfig,
) -> Result<KernelArtifact> {
    build_kernel_inner(graph, scope_id, config, None)
}

/// Computes a betweenness cache bound to the canonical topology, ascending
/// `CxId` roster, and betweenness configuration.
pub fn kernel_betweenness_cache(
    graph: &KernelGraph,
    config: &KernelBuildConfig,
) -> Result<BetweennessCache> {
    config.validate()?;
    let indexed = graph.compile()?;
    let measured = betweenness_auto(
        &indexed,
        config.betweenness_exact_max_nodes,
        config.betweenness_sample_pivots,
        config.betweenness_sample_seed,
    );
    let node_roster_hash = betweenness_node_roster_hash(&indexed)?;
    let topology_hash = betweenness_topology_hash(&indexed)?;
    let config_hash = kernel_build_config_hash(config);
    let permille_hash = betweenness_permille_hash(&measured.permille)?;
    let cache_hash = betweenness_cache_hash(
        indexed.len(),
        &node_roster_hash,
        &topology_hash,
        &config_hash,
        measured.exact,
        measured.sources_used,
        &permille_hash,
    )?;
    Ok(BetweennessCache {
        schema: KERNEL_BETWEENNESS_CACHE_SCHEMA.to_string(),
        node_count: indexed.len(),
        node_roster_hash,
        topology_hash,
        config_hash,
        exact: measured.exact,
        sources_used: measured.sources_used,
        permille: measured.permille,
        permille_hash,
        cache_hash,
    })
}

/// Builds a kernel only when a cached betweenness receipt exactly matches the
/// canonical topology, ordinal roster, and betweenness configuration. Every
/// mismatch is a refusal; reuse mode never recomputes silently.
pub fn build_kernel_reusing_betweenness(
    graph: &KernelGraph,
    scope_id: &str,
    config: &KernelBuildConfig,
    cached_betweenness: &BetweennessCache,
) -> Result<KernelArtifact> {
    build_kernel_inner(graph, scope_id, config, Some(cached_betweenness))
}

fn validated_cached_betweenness(
    indexed: &crate::kernel_graph::IndexedGraph,
    config: &KernelBuildConfig,
    cache: &BetweennessCache,
) -> Result<crate::betweenness::BetweennessResult> {
    let expected_roster_hash = betweenness_node_roster_hash(indexed)?;
    let expected_topology_hash = betweenness_topology_hash(indexed)?;
    let expected_config_hash = kernel_build_config_hash(config);
    let indexed_len_u64 = u64::try_from(indexed.len()).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel node count is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    let expected_exact = indexed_len_u64 <= config.betweenness_exact_max_nodes;
    let expected_sources = if expected_exact {
        indexed.len()
    } else {
        usize::try_from(config.betweenness_sample_pivots)
            .map_err(|_| {
                DomainError::new(
                    ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
                    "kernel betweenness sample-pivot count is not representable as usize",
                    "repair the declared betweenness registry before building the kernel",
                )
            })?
            .min(indexed.len())
    };
    let expected_permille_hash = betweenness_permille_hash(&cache.permille)?;
    let expected_cache_hash = betweenness_cache_hash(
        cache.node_count,
        &cache.node_roster_hash,
        &cache.topology_hash,
        &cache.config_hash,
        cache.exact,
        cache.sources_used,
        &cache.permille_hash,
    )?;
    let invalid_value = cache.permille.iter().position(|value| *value > 1000);
    let matches = cache.schema == KERNEL_BETWEENNESS_CACHE_SCHEMA
        && cache.node_count == indexed.len()
        && cache.permille.len() == indexed.len()
        && cache.node_roster_hash == expected_roster_hash
        && cache.topology_hash == expected_topology_hash
        && cache.config_hash == expected_config_hash
        && cache.exact == expected_exact
        && cache.sources_used == expected_sources
        && cache.permille_hash == expected_permille_hash
        && cache.cache_hash == expected_cache_hash
        && invalid_value.is_none();
    if !matches {
        return Err(DomainError::new(
            ASTRO_KERNEL_BETWEENNESS_CACHE_MISMATCH,
            format!(
                "betweenness cache mismatch: schema expected={} actual={} node_count expected={} actual={} values={} roster_hash expected={} actual={} topology_hash expected={} actual={} config_hash expected={} actual={} exact expected={} actual={} sources_used expected={} actual={} permille_hash expected={} actual={} cache_hash expected={} actual={} first_invalid_permille={invalid_value:?}",
                KERNEL_BETWEENNESS_CACHE_SCHEMA,
                cache.schema,
                indexed.len(),
                cache.node_count,
                cache.permille.len(),
                expected_roster_hash,
                cache.node_roster_hash,
                expected_topology_hash,
                cache.topology_hash,
                expected_config_hash,
                cache.config_hash,
                expected_exact,
                cache.exact,
                expected_sources,
                cache.sources_used,
                expected_permille_hash,
                cache.permille_hash,
                expected_cache_hash,
                cache.cache_hash,
            ),
            "recompute the cache from this exact canonical topology and betweenness configuration; reuse mode never substitutes a fresh computation",
        ));
    }
    Ok(crate::betweenness::BetweennessResult {
        raw: Vec::new(),
        permille: cache.permille.clone(),
        exact: cache.exact,
        sources_used: cache.sources_used,
    })
}

fn betweenness_node_roster_hash(indexed: &crate::kernel_graph::IndexedGraph) -> Result<String> {
    let node_count = u64::try_from(indexed.len()).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel node roster length is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    let mut hash = FramedContentAddress::new();
    hash.update(b"astro.kernel.betweenness.node_roster.v1");
    hash.update(&node_count.to_be_bytes());
    for id in indexed.ids() {
        hash.update(id.as_bytes());
    }
    Ok(hex_lower(&hash.finalize()))
}

fn betweenness_topology_hash(indexed: &crate::kernel_graph::IndexedGraph) -> Result<String> {
    let edge_count = (0..indexed.len()).try_fold(0usize, |total, src| {
        total
            .checked_add(indexed.out_neighbors(src).len())
            .and_then(|total| total.checked_add(usize::from(indexed.has_self_loop(src))))
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
                    "kernel topology edge count overflowed usize",
                    "reduce the graph through an explicit, identity-preserving scope before building the kernel",
                )
            })
    })?;
    let node_count = u64::try_from(indexed.len()).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel topology node count is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    let edge_count_u64 = u64::try_from(edge_count).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel topology edge count is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    let mut hash = FramedContentAddress::new();
    hash.update(b"astro.kernel.betweenness.directed_topology.v1");
    hash.update(&node_count.to_be_bytes());
    hash.update(&edge_count_u64.to_be_bytes());
    for src in 0..indexed.len() {
        if indexed.has_self_loop(src) {
            hash.update(indexed.id(src).as_bytes());
            hash.update(indexed.id(src).as_bytes());
        }
        for &dst in indexed.out_neighbors(src) {
            hash.update(indexed.id(src).as_bytes());
            hash.update(indexed.id(dst).as_bytes());
        }
    }
    Ok(hex_lower(&hash.finalize()))
}

fn betweenness_permille_hash(values: &[u64]) -> Result<String> {
    let value_count = u64::try_from(values.len()).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel betweenness value count is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    let mut hash = FramedContentAddress::new();
    hash.update(b"astro.kernel.betweenness.permille.v1");
    hash.update(&value_count.to_be_bytes());
    for value in values {
        hash.update(&value.to_be_bytes());
    }
    Ok(hex_lower(&hash.finalize()))
}

fn betweenness_cache_hash(
    node_count: usize,
    node_roster_hash: &str,
    topology_hash: &str,
    config_hash: &str,
    exact: bool,
    sources_used: usize,
    permille_hash: &str,
) -> Result<String> {
    let node_count = u64::try_from(node_count).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel betweenness cache node count is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    let sources_used = u64::try_from(sources_used).map_err(|_| {
        DomainError::new(
            ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
            "kernel betweenness cache source count is not representable as u64",
            "reduce the graph through an explicit, identity-preserving scope before building the kernel",
        )
    })?;
    Ok(hex_lower(&content_address([
        b"astro.kernel.betweenness.cache.v1".as_slice(),
        KERNEL_BETWEENNESS_CACHE_SCHEMA.as_bytes(),
        &node_count.to_be_bytes(),
        node_roster_hash.as_bytes(),
        topology_hash.as_bytes(),
        config_hash.as_bytes(),
        &[u8::from(exact)],
        &sources_used.to_be_bytes(),
        permille_hash.as_bytes(),
    ])))
}

fn build_kernel_inner(
    graph: &KernelGraph,
    scope_id: &str,
    config: &KernelBuildConfig,
    cached_betweenness: Option<&BetweennessCache>,
) -> Result<KernelArtifact> {
    // #443 permanent sub-phase timing (env-gated `ASTRO_KERNEL_TIMING`): the
    // kernel_artifact cold-index phase's internal breakdown so the #443 3-scale
    // matrix can attribute its 83s@n=45,557 to a real sub-stage. Silent by
    // default; carries no behaviour.
    let mut timing = crate::KernelPhaseTiming::start("kernel_artifact");
    config.validate()?;
    if graph.node_count() == 0 {
        return Err(DomainError::new(
            ASTRO_KERNEL_EMPTY_GRAPH,
            "refusing to build a kernel over a graph with no symbol versions",
            "ingest at least one symbol version into scope before building a kernel",
        ));
    }
    let source_identity = kernel_source_identity(graph, config)?;
    let indexed = graph.compile()?;
    let n = indexed.len();
    timing.lap("compile");

    let betweenness = match cached_betweenness {
        Some(cache) => validated_cached_betweenness(&indexed, config, cache)?,
        None => betweenness_auto(
            &indexed,
            config.betweenness_exact_max_nodes,
            config.betweenness_sample_pivots,
            config.betweenness_sample_seed,
        ),
    };
    timing.lap("betweenness");
    let groundedness = score_groundedness(
        &indexed,
        config.groundedness_hop_limit,
        config.groundedness_freq_cap,
        config.groundedness_freq_bonus_permille,
    );
    timing.lap("groundedness");

    let max_degree = (0..n).map(|index| indexed.degree(index)).max().unwrap_or(0);
    let score_permille: Vec<u64> = (0..n)
        .map(|index| {
            let degree = indexed.degree(index);
            let degree_norm = if max_degree == 0 {
                0
            } else {
                degree.checked_mul(1000).ok_or_else(|| {
                    DomainError::new(
                        ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
                        "kernel normalized-degree numerator overflowed u64",
                        "reduce the graph through an explicit, identity-preserving scope before building the kernel",
                    )
                })? / max_degree
            };
            let degree_term = config
                .weight_degree_permille
                .checked_mul(degree_norm);
            let betweenness_term = config
                .weight_betweenness_permille
                .checked_mul(betweenness.permille[index]);
            let groundedness_term = config
                .weight_groundedness_permille
                .checked_mul(groundedness.permille[index]);
            degree_term
                .and_then(|score| score.checked_add(betweenness_term?))
                .and_then(|score| score.checked_add(groundedness_term?))
                .map(|score| score / 1000)
                .ok_or_else(|| {
                    DomainError::new(
                        ASTRO_KERNEL_REPRESENTATION_OVERFLOW,
                        "kernel importance fixed-point score overflowed u64",
                        "repair the declared score-weight registry before building the kernel",
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    timing.lap("importance_scores");

    let fvs = canonical_dfs_feedback_vertex_set(&indexed)?;
    if fvs.cyclic_scc_count == 0 {
        return Err(DomainError::new(
            ASTRO_KERNEL_NO_CYCLIC_CORE,
            format!(
                "scope {scope_id} has nodes={n} but no cyclic SCC; an empty structural FVS cannot be published as a successful answer kernel"
            ),
            "persist an explicitly structural empty-DAG observation or supply a graph generation with a cyclic association core; do not label topology coverage as answer recall",
        ));
    }
    let members: BTreeSet<usize> = fvs.members.iter().copied().collect();
    let fvs_count = members.len();
    timing.lap("fvs");

    // Undirected graph coverage is diagnostic only. It neither adds members nor
    // admits/refuses a generation: treating topology coverage as query recall was
    // the semantic defect tracked by #1148. Retrieval admission belongs to the
    // separately measured graph-routed report over persisted external queries.
    let mut graph_coverage =
        measure_graph_coverage(&indexed, &members, config.graph_coverage_radius_hops);
    graph_coverage.meets_coverage_floor =
        graph_coverage.permille >= config.graph_coverage_min_permille;
    timing.lap("graph_coverage");
    let compactness = kernel_compactness(n, members.len(), config);
    if !compactness.admitted {
        return Err(compactness_error(scope_id, &compactness));
    }

    let member_rows = members
        .iter()
        .map(|&index| KernelMember {
            id: indexed.id(index),
            score_permille: score_permille[index],
            degree: indexed.degree(index),
            betweenness_permille: betweenness.permille[index],
            groundedness_permille: groundedness.permille[index],
            frequency: indexed.frequency(index),
            grounded: groundedness.distance[index].is_some(),
            in_fvs: true,
        })
        .collect::<Vec<_>>();

    let member_ids: Vec<CxId> = member_rows.iter().map(|member| member.id).collect();
    let hash = members_hash(&member_ids);
    let trust = rollup_trust(member_rows.iter().map(|member| {
        if member.grounded {
            TrustTag::Trusted
        } else {
            TrustTag::Provisional
        }
    }));
    let ungrounded_reason = if groundedness.has_trusted_anchor {
        None
    } else {
        Some(
            "no Trusted anchor in scope; kernel is provisional and all members are gaps"
                .to_string(),
        )
    };

    // Member-row assembly + members-hash + trust rollup attribute here.
    timing.lap("assemble");

    Ok(KernelArtifact {
        schema: KERNEL_ARTIFACT_SCHEMA.to_string(),
        scope_id: scope_id.to_string(),
        knob_registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION.to_string(),
        config: *config,
        node_count: n,
        source_identity,
        fvs_count,
        fvs_validity: FvsValidityProof {
            method: FVS_VALIDITY_METHOD.to_string(),
            cyclic_scc_count: fvs.cyclic_scc_count,
            largest_cyclic_scc_node_count: fvs.largest_cyclic_scc_node_count,
            dfs_checked_edge_count: fvs.dfs_checked_edge_count,
            dfs_back_edge_count: fvs.dfs_back_edge_count,
            dfs_back_edge_roster_hash: fvs.dfs_back_edge_roster_hash,
            residual_node_count: fvs.residual_node_count,
            residual_topological_order_hash: fvs.residual_topological_order_hash,
        },
        member_count: member_rows.len(),
        betweenness_exact: betweenness.exact,
        anchor_grounded: groundedness.has_trusted_anchor,
        ungrounded_reason,
        graph_coverage,
        compactness,
        members: member_rows,
        members_hash: hash,
        freshness: "fresh".to_string(),
        trust: trust.as_str().to_string(),
    })
}

/// Measures the fraction of graph nodes within `radius` undirected hops of a
/// member. This is a topology diagnostic only; no query, vector, exact answer,
/// or routed answer is observed here.
pub fn measure_graph_coverage(
    indexed: &crate::kernel_graph::IndexedGraph,
    members: &BTreeSet<usize>,
    radius: u64,
) -> GraphCoverageMeasurement {
    let total = indexed.len() as u64;
    let covered = coverage(indexed, members, radius);
    let covered_count = covered.iter().filter(|&&flag| flag).count() as u64;
    let permille = if total == 0 {
        0
    } else {
        ((u128::from(covered_count) * 1000) / u128::from(total)) as u64
    };
    GraphCoverageMeasurement {
        metric: "undirected_graph_coverage_at_radius".to_string(),
        admission_role: "diagnostic_only_not_retrieval_recall".to_string(),
        radius_hops: radius,
        covered: covered_count,
        total,
        permille,
        meets_coverage_floor: false,
    }
}

fn maximum_member_count(node_count: usize, max_fraction_permille: u64) -> usize {
    ((node_count as u128) * (max_fraction_permille as u128) / 1000_u128) as usize
}

fn kernel_compactness(
    node_count: usize,
    member_count: usize,
    config: &KernelBuildConfig,
) -> KernelCompactness {
    let member_fraction_permille =
        ((member_count as u128) * 1000_u128 / (node_count.max(1) as u128)) as u64;
    let max_members = maximum_member_count(node_count, config.max_member_fraction_permille);
    KernelCompactness {
        member_count,
        source_node_count: node_count,
        member_fraction_permille,
        max_member_fraction_permille: config.max_member_fraction_permille,
        admitted: member_count < node_count && member_count <= max_members,
    }
}

fn compactness_error(scope: &str, compactness: &KernelCompactness) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_COMPACTNESS_UNREACHABLE,
        format!(
            "scope={scope} kernel compactness refused: members={} source_nodes={} fraction_permille={} maximum_permille={} admitted={}",
            compactness.member_count,
            compactness.source_node_count,
            compactness.member_fraction_permille,
            compactness.max_member_fraction_permille,
            compactness.admitted,
        ),
        "change the graph/declared kernel algorithm or select an explicit compactness ceiling that still keeps the member roster strictly smaller than the source; diagnostic graph-coverage knobs never change membership and a whole-corpus kernel is inadmissible",
    )
}

/// Marks every node within `radius` undirected hops of any member.
fn coverage(
    indexed: &crate::kernel_graph::IndexedGraph,
    members: &BTreeSet<usize>,
    radius: u64,
) -> Vec<bool> {
    let n = indexed.len();
    let mut covered = vec![false; n];
    let mut depth = vec![0_u64; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    for &member in members {
        if !covered[member] {
            covered[member] = true;
            depth[member] = 0;
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}
