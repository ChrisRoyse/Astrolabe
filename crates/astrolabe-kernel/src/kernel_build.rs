//! Kernel build pipeline: score, feedback-vertex-set core, recall gate, and the
//! atomically written `kernel.json` / `index.json` / ledger artifacts (#37).
//!
//! Pipeline (blueprint 09 §1): iterative Tarjan SCC → `betweenness_auto` →
//! candidate score `0.40·degree + 0.40·betweenness + 0.20·groundedness` → top
//! ~10% → approximate directed FVS (~1%) → recall gate ≥ 0.95 recall@10 with
//! `refine_kernel_with_recall_support` restoring the gate when it fails. Every
//! threshold and weight is a registry-declared knob (invariant 4); every score
//! that reaches the persisted artifact is an integer permille, so `kernel.json`
//! is byte-identical across runs and worker counts (invariant 5). Writing the
//! artifacts appends a members-hash ledger entry — the mutation is paired with
//! its ledger record (invariant 5).

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_domain::calyx::{CxId, content_address};
use astrolabe_domain::{DomainError, Result, TrustTag, rollup_trust};
use serde::{Deserialize, Serialize};

use crate::U64KnobDeclaration;
use crate::betweenness::betweenness_auto;
use crate::fvs::approximate_directed_fvs;
use crate::groundedness::score_groundedness;
use crate::kernel_graph::{ASTRO_KERNEL_EMPTY_GRAPH, KernelGraph};

/// Schema tag for a persisted kernel artifact.
pub const KERNEL_ARTIFACT_SCHEMA: &str = "astrolabe.kernel.v1";
/// Schema tag for a persisted kernel index manifest.
pub const KERNEL_INDEX_SCHEMA: &str = "astrolabe.kernel_index.v1";
/// Schema tag for a kernel-build ledger entry.
pub const KERNEL_LEDGER_SCHEMA: &str = "astrolabe.kernel_ledger.v1";
/// Knob registry version for the kernel build pipeline.
pub const KERNEL_BUILD_KNOB_REGISTRY_VERSION: &str = "astro.kernel.build_knobs.v1";
/// Framing tag for the members hash preimage.
pub const KERNEL_MEMBERS_HASH_TAG: &[u8] = b"astro.kernel.members.v1";

/// Refusal raised when the score weights do not sum to 1000 permille.
pub const ASTRO_KERNEL_WEIGHT_SUM: &str = "ASTRO_KERNEL_WEIGHT_SUM";
/// Refusal raised when a kernel build knob is outside its declared bounds.
pub const ASTRO_KERNEL_KNOB_RANGE: &str = "ASTRO_KERNEL_KNOB_RANGE";
/// Refusal raised when refinement cannot lift recall to the gate.
pub const ASTRO_KERNEL_RECALL_UNREACHABLE: &str = "ASTRO_KERNEL_RECALL_UNREACHABLE";
/// Refusal raised when an artifact read back after write does not match.
pub const ASTRO_KERNEL_ARTIFACT_READBACK: &str = "ASTRO_KERNEL_ARTIFACT_READBACK";
/// Refusal raised when an artifact directory cannot be written.
pub const ASTRO_KERNEL_ARTIFACT_IO: &str = "ASTRO_KERNEL_ARTIFACT_IO";

// Knob names.
pub const KNOB_WEIGHT_DEGREE: &str = "kernel.score.weight_degree_permille";
pub const KNOB_WEIGHT_BETWEENNESS: &str = "kernel.score.weight_betweenness_permille";
pub const KNOB_WEIGHT_GROUNDEDNESS: &str = "kernel.score.weight_groundedness_permille";
pub const KNOB_GROUNDEDNESS_HOP_LIMIT: &str = "kernel.groundedness.hop_limit";
pub const KNOB_GROUNDEDNESS_FREQ_CAP: &str = "kernel.groundedness.freq_cap";
pub const KNOB_GROUNDEDNESS_FREQ_BONUS: &str = "kernel.groundedness.freq_bonus_permille";
pub const KNOB_CANDIDATE_TOP_FRACTION: &str = "kernel.candidate.top_fraction_permille";
pub const KNOB_BETWEENNESS_EXACT_MAX_NODES: &str = "kernel.betweenness.exact_max_nodes";
pub const KNOB_BETWEENNESS_SAMPLE_PIVOTS: &str = "kernel.betweenness.sample_pivots";
pub const KNOB_BETWEENNESS_SAMPLE_SEED: &str = "kernel.betweenness.sample_seed";
pub const KNOB_RECALL_MIN_PERMILLE: &str = "kernel.recall.min_permille";
pub const KNOB_RECALL_ANSWER_RADIUS: &str = "kernel.recall.answer_radius_hops";

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
        rationale: "degree term of the candidate score; the three weights sum to 1000 (0.40·degree)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_WEIGHT_BETWEENNESS,
        default: 400,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "betweenness term of the candidate score (0.40·betweenness)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_WEIGHT_GROUNDEDNESS,
        default: 200,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "groundedness term of the candidate score (0.20·groundedness)",
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
        name: KNOB_CANDIDATE_TOP_FRACTION,
        default: 100,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "fraction of top-scored nodes kept as FVS candidates (~10%)",
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
        name: KNOB_RECALL_MIN_PERMILLE,
        default: 950,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "recall@10 gate the persisted kernel must reach (≥ 0.95)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION,
        name: KNOB_RECALL_ANSWER_RADIUS,
        default: 2,
        min: 0,
        max: 16,
        unit: "hops",
        source: SOURCE,
        rationale: "answer-path radius within which a kernel member covers a query symbol",
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
    /// Top candidate fraction in permille.
    pub candidate_top_fraction_permille: u64,
    /// Exact-betweenness node ceiling.
    pub betweenness_exact_max_nodes: u64,
    /// Sampled-betweenness pivot count.
    pub betweenness_sample_pivots: u64,
    /// Sampled-betweenness pinned seed.
    pub betweenness_sample_seed: u64,
    /// Recall gate in permille.
    pub recall_min_permille: u64,
    /// Answer-path coverage radius in hops.
    pub recall_answer_radius_hops: u64,
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
            candidate_top_fraction_permille: knob_default(KNOB_CANDIDATE_TOP_FRACTION),
            betweenness_exact_max_nodes: knob_default(KNOB_BETWEENNESS_EXACT_MAX_NODES),
            betweenness_sample_pivots: knob_default(KNOB_BETWEENNESS_SAMPLE_PIVOTS),
            betweenness_sample_seed: knob_default(KNOB_BETWEENNESS_SAMPLE_SEED),
            recall_min_permille: knob_default(KNOB_RECALL_MIN_PERMILLE),
            recall_answer_radius_hops: knob_default(KNOB_RECALL_ANSWER_RADIUS),
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
            KNOB_CANDIDATE_TOP_FRACTION,
            self.candidate_top_fraction_permille,
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
        check_range(KNOB_RECALL_MIN_PERMILLE, self.recall_min_permille)?;
        check_range(KNOB_RECALL_ANSWER_RADIUS, self.recall_answer_radius_hops)?;
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

/// Measured recall of a kernel index against the full index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallMeasurement {
    /// Synthetic-QN queries whose target symbol is covered by the kernel within
    /// the answer radius.
    pub recalled: u64,
    /// Total synthetic-QN queries (one per symbol version).
    pub total: u64,
    /// `recalled / total` in permille.
    pub permille: u64,
    /// Whether the measurement reaches the recall gate.
    pub gated: bool,
}

/// One kernel member row in a persisted artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelMember {
    /// Symbol version identity.
    pub id: CxId,
    /// Combined candidate score in permille.
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
    /// Whether the member was added by recall refinement.
    pub support_added: bool,
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
    /// Candidate nodes (top-scored fraction).
    pub candidate_count: usize,
    /// Feedback-vertex-set core size.
    pub fvs_count: usize,
    /// Members added by recall refinement.
    pub support_count: usize,
    /// Total kernel members.
    pub member_count: usize,
    /// Whether betweenness was computed exactly.
    pub betweenness_exact: bool,
    /// Whether any Trusted anchor exists in scope.
    pub anchor_grounded: bool,
    /// Set only when the kernel has no Trusted anchor in scope.
    pub ungrounded_reason: Option<String>,
    /// Measured recall carried by the persisted kernel.
    pub recall: RecallMeasurement,
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
            index_kind: "membership_manifest".to_string(),
            note: "Vector HNSW is built downstream from S18 embeddings; this \
                   manifest pins the exact member set and order that index must \
                   cover, content-addressed by members_hash."
                .to_string(),
            recall: self.recall,
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
            recall: self.recall,
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
    /// Index kind discriminator.
    pub index_kind: String,
    /// Honesty note describing the manifest boundary.
    pub note: String,
    /// Measured recall the covered members achieve.
    pub recall: RecallMeasurement,
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
    /// Measured recall recorded with the build.
    pub recall: RecallMeasurement,
}

/// Computes the hex members-hash over an ascending member identity set.
pub fn members_hash(member_ids: &[CxId]) -> String {
    let mut sorted: Vec<CxId> = member_ids.to_vec();
    sorted.sort_unstable();
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(sorted.len() + 1);
    parts.push(KERNEL_MEMBERS_HASH_TAG.to_vec());
    for id in &sorted {
        parts.push(id.as_bytes().to_vec());
    }
    hex_lower(&content_address(parts))
}

/// Builds a recall-gated, grounded kernel over the graph for a scope.
///
/// Refuses fail-closed on an empty graph ([`ASTRO_KERNEL_EMPTY_GRAPH`]) — a
/// kernel over zero symbols is meaningless. An anchor-ungrounded scope still
/// yields a kernel, tagged provisional with `ungrounded_reason` set (blueprint
/// 09 §7). The persisted kernel always carries its measured recall.
pub fn build_kernel(
    graph: &KernelGraph,
    scope_id: &str,
    config: &KernelBuildConfig,
) -> Result<KernelArtifact> {
    config.validate()?;
    if graph.node_count() == 0 {
        return Err(DomainError::new(
            ASTRO_KERNEL_EMPTY_GRAPH,
            "refusing to build a kernel over a graph with no symbol versions",
            "ingest at least one symbol version into scope before building a kernel",
        ));
    }
    let indexed = graph.compile()?;
    let n = indexed.len();

    let betweenness = betweenness_auto(
        &indexed,
        config.betweenness_exact_max_nodes,
        config.betweenness_sample_pivots,
        config.betweenness_sample_seed,
    );
    let groundedness = score_groundedness(
        &indexed,
        config.groundedness_hop_limit,
        config.groundedness_freq_cap,
        config.groundedness_freq_bonus_permille,
    );

    let max_degree = (0..n).map(|index| indexed.degree(index)).max().unwrap_or(0);
    let score_permille: Vec<u64> = (0..n)
        .map(|index| {
            let degree_norm = indexed
                .degree(index)
                .saturating_mul(1000)
                .checked_div(max_degree)
                .unwrap_or(0);
            (config.weight_degree_permille * degree_norm
                + config.weight_betweenness_permille * betweenness.permille[index]
                + config.weight_groundedness_permille * groundedness.permille[index])
                / 1000
        })
        .collect();
    let score_usize: Vec<usize> = score_permille.iter().map(|&value| value as usize).collect();

    // Top candidate fraction by (score desc, id asc).
    let candidate_count =
        (((n as u64) * config.candidate_top_fraction_permille) / 1000).max(1) as usize;
    let mut ranked: Vec<usize> = (0..n).collect();
    ranked.sort_by(|&left, &right| {
        score_permille[right]
            .cmp(&score_permille[left])
            .then_with(|| indexed.id(left).cmp(&indexed.id(right)))
    });
    let candidates: BTreeSet<usize> = ranked.into_iter().take(candidate_count).collect();

    let fvs = approximate_directed_fvs(&indexed, &candidates, &score_usize);
    let mut members: BTreeSet<usize> = fvs.members.iter().copied().collect();
    let fvs_count = members.len();

    // Recall gate over the full graph; refine when below the gate.
    let mut recall = measure_recall(&indexed, &members, config.recall_answer_radius_hops);
    let support = if recall.permille < config.recall_min_permille {
        let added = refine_kernel_with_recall_support(&indexed, &mut members, config)?;
        recall = measure_recall(&indexed, &members, config.recall_answer_radius_hops);
        recall.gated = recall.permille >= config.recall_min_permille;
        if !recall.gated {
            return Err(DomainError::new(
                ASTRO_KERNEL_RECALL_UNREACHABLE,
                format!(
                    "kernel recall {} permille still below gate {} after adding every symbol",
                    recall.permille, config.recall_min_permille
                ),
                "widen the recall answer radius or lower the recall gate knob within bounds",
            ));
        }
        added
    } else {
        recall.gated = true;
        BTreeSet::new()
    };

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
            in_fvs: fvs.members.contains(&index),
            support_added: support.contains(&index),
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

    Ok(KernelArtifact {
        schema: KERNEL_ARTIFACT_SCHEMA.to_string(),
        scope_id: scope_id.to_string(),
        knob_registry_version: KERNEL_BUILD_KNOB_REGISTRY_VERSION.to_string(),
        config: *config,
        node_count: n,
        candidate_count,
        fvs_count,
        support_count: support.len(),
        member_count: member_rows.len(),
        betweenness_exact: betweenness.exact,
        anchor_grounded: groundedness.has_trusted_anchor,
        ungrounded_reason,
        recall,
        members: member_rows,
        members_hash: hash,
        freshness: "fresh".to_string(),
        trust: trust.as_str().to_string(),
    })
}

/// Measures kernel recall as synthetic-QN coverage: the fraction of symbol
/// versions that lie within the answer radius (undirected) of some kernel
/// member. The full index trivially recalls every symbol, so the gold set is
/// every node; the kernel index recalls a query when a member covers it. This
/// is a genuine graph-coverage measurement, not a mock — an empty member set
/// recalls nothing, the whole graph recalls everything.
pub fn measure_recall(
    indexed: &crate::kernel_graph::IndexedGraph,
    members: &BTreeSet<usize>,
    radius: u64,
) -> RecallMeasurement {
    let total = indexed.len() as u64;
    let covered = coverage(indexed, members, radius);
    let recalled = covered.iter().filter(|&&flag| flag).count() as u64;
    let permille = recalled
        .saturating_mul(1000)
        .checked_div(total)
        .unwrap_or(0);
    RecallMeasurement {
        recalled,
        total,
        permille,
        gated: false,
    }
}

/// Greedy max-coverage refinement: while recall is below the gate, add the
/// uncovered symbol whose inclusion newly covers the most uncovered symbols
/// (ties broken by ascending `CxId`). Returns the added member indices. Adding
/// every symbol drives recall to 1000, so the loop always reaches the gate for
/// any gate ≤ 1000.
pub fn refine_kernel_with_recall_support(
    indexed: &crate::kernel_graph::IndexedGraph,
    members: &mut BTreeSet<usize>,
    config: &KernelBuildConfig,
) -> Result<BTreeSet<usize>> {
    let n = indexed.len();
    let radius = config.recall_answer_radius_hops;
    let mut added = BTreeSet::new();

    loop {
        let recall = measure_recall(indexed, members, radius);
        if recall.permille >= config.recall_min_permille {
            break;
        }
        let covered = coverage(indexed, members, radius);
        let uncovered: Vec<usize> = (0..n).filter(|&index| !covered[index]).collect();
        if uncovered.is_empty() {
            return Err(DomainError::new(
                ASTRO_KERNEL_RECALL_UNREACHABLE,
                "kernel recall is below the gate but every symbol is already covered",
                "recompute the recall answer radius; coverage and recall disagree",
            ));
        }
        // Choose the uncovered node whose radius reaches the most uncovered nodes.
        let chosen = uncovered
            .iter()
            .copied()
            .max_by(|&left, &right| {
                let left_gain = new_coverage_gain(indexed, left, radius, &covered);
                let right_gain = new_coverage_gain(indexed, right, radius, &covered);
                left_gain
                    .cmp(&right_gain)
                    .then_with(|| indexed.id(right).cmp(&indexed.id(left)))
            })
            .expect("uncovered set is non-empty");
        members.insert(chosen);
        added.insert(chosen);
    }
    Ok(added)
}

fn new_coverage_gain(
    indexed: &crate::kernel_graph::IndexedGraph,
    source: usize,
    radius: u64,
    covered: &[bool],
) -> usize {
    let mut single = BTreeSet::new();
    single.insert(source);
    let reach = coverage(indexed, &single, radius);
    (0..indexed.len())
        .filter(|&index| reach[index] && !covered[index])
        .count()
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

/// Filesystem paths of a persisted kernel artifact set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelArtifactPaths {
    /// Path to `kernel.json`.
    pub kernel_json: PathBuf,
    /// Path to `index.json`.
    pub index_json: PathBuf,
    /// Path to the append-only `kernel_ledger.jsonl`.
    pub ledger: PathBuf,
}

/// Atomically writes `kernel.json` and `index.json` and appends the members-hash
/// ledger entry, then reads every artifact back and verifies the bytes.
///
/// Each JSON artifact is written to a temp sibling and renamed over its final
/// path — a rename is atomic on a single volume, so a crash between the temp
/// write and the rename leaves the previous artifact intact and never a torn
/// file (invariant 5). The ledger append rewrites the full file through the same
/// temp+rename discipline.
pub fn write_kernel_artifacts(
    dir: &Path,
    artifact: &KernelArtifact,
) -> Result<KernelArtifactPaths> {
    fs::create_dir_all(dir).map_err(|error| io_error("create artifact directory", dir, &error))?;
    let kernel_path = dir.join("kernel.json");
    let index_path = dir.join("index.json");
    let ledger_path = dir.join("kernel_ledger.jsonl");

    let kernel_bytes = artifact.kernel_json_bytes();
    let index_bytes = artifact.index_json_bytes();
    atomic_write(&kernel_path, &kernel_bytes)?;
    atomic_write(&index_path, &index_bytes)?;

    let mut ledger_bytes = match fs::read(&ledger_path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(io_error("read ledger", &ledger_path, &error)),
    };
    let mut entry_line =
        serde_json::to_vec(&artifact.ledger_entry()).expect("ledger entry serializes");
    entry_line.push(b'\n');
    ledger_bytes.extend_from_slice(&entry_line);
    atomic_write(&ledger_path, &ledger_bytes)?;

    verify_readback(&kernel_path, &kernel_bytes)?;
    verify_readback(&index_path, &index_bytes)?;
    verify_readback(&ledger_path, &ledger_bytes)?;

    Ok(KernelArtifactPaths {
        kernel_json: kernel_path,
        index_json: index_path,
        ledger: ledger_path,
    })
}

/// Writes `bytes` to `path.tmp` without renaming, returning the staged temp
/// path. A crash here leaves `path` untouched — the staged bytes are never
/// observable at the final path. [`commit_staged`] completes the write.
pub fn stage_write(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let tmp = temp_path(path);
    fs::write(&tmp, bytes).map_err(|error| io_error("stage artifact", &tmp, &error))?;
    Ok(tmp)
}

/// Renames a staged temp file over its final path, atomically completing a
/// [`stage_write`].
pub fn commit_staged(tmp: &Path, path: &Path) -> Result<()> {
    fs::rename(tmp, path).map_err(|error| io_error("commit staged artifact", path, &error))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = stage_write(path, bytes)?;
    commit_staged(&tmp, path)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

fn verify_readback(path: &Path, expected: &[u8]) -> Result<()> {
    let actual = fs::read(path).map_err(|error| io_error("read back artifact", path, &error))?;
    if actual != expected {
        return Err(DomainError::new(
            ASTRO_KERNEL_ARTIFACT_READBACK,
            format!(
                "artifact {} read back {} bytes that differ from the {} bytes written",
                path.display(),
                actual.len(),
                expected.len()
            ),
            "retry the kernel artifact write; the persisted bytes did not match the staged bytes",
        ));
    }
    Ok(())
}

fn io_error(action: &str, path: &Path, error: &std::io::Error) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ARTIFACT_IO,
        format!("failed to {action} at {}: {error}", path.display()),
        "ensure the kernel artifact directory is writable and on a single volume",
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}
