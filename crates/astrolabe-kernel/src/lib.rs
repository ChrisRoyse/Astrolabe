#![forbid(unsafe_code)]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

/// Env-gated (`ASTRO_KERNEL_TIMING`) permanent sub-phase timing for the
/// kernel_artifact / label_propagation cold-index phases (#443).
pub mod phase_timing;
pub use phase_timing::KernelPhaseTiming;

/// Directory-role frame, `placement_truth` cross-term, and `layout_map` aspect
/// (#180b): the structure-convention reference frame built on the S23
/// `layer_role` lens.
pub mod layout;
pub use layout::*;

/// Kernel build graph substrate: the kernel-owned input the pipeline consumes
/// (#37). Decoupled from the ingest projection crate to avoid a dependency
/// cycle.
pub mod kernel_graph;
pub use kernel_graph::{
    ASTRO_KERNEL_EMPTY_GRAPH, ASTRO_KERNEL_GRAPH_INVALID, IndexedGraph, KernelGraph,
    KernelGraphEdge, KernelGraphNode,
};

/// Iterative Tarjan strongly-connected components (#37).
pub mod scc;
pub use scc::{all_strongly_connected_components, strongly_connected_components};

/// Betweenness centrality with exact/sampled auto-switch (#37).
pub mod betweenness;
pub use betweenness::{BetweennessResult, betweenness_auto, brandes, select_pivots};

/// Groundedness scoring against Trusted anchors (#37).
pub mod groundedness;
pub use groundedness::{GroundednessResult, score_groundedness};

/// Approximate directed feedback vertex set (#37).
pub mod fvs;
pub use fvs::{FeedbackVertexSet, approximate_directed_fvs};

/// Kernel build pipeline, recall gate, and persisted artifacts (#37).
pub mod kernel_build;
pub use kernel_build::{
    KERNEL_ARTIFACT_SCHEMA, KERNEL_BUILD_KNOB_REGISTRY_VERSION, KERNEL_BUILD_KNOBS,
    KERNEL_INDEX_SCHEMA, KERNEL_LEDGER_SCHEMA, KernelArtifact, KernelArtifactPaths,
    KernelBuildConfig, KernelIndexManifest, KernelLedgerEntry, KernelMember, RecallMeasurement,
    build_kernel, build_kernel_reusing_betweenness, kernel_betweenness_permille, measure_recall,
    members_hash, refine_kernel_with_recall_support, write_kernel_artifacts,
};

/// Grounding-gap report + coverage-vs-importance quadrant over a persisted
/// kernel (#39): the "here be dragons" QA map.
pub mod gaps;
pub use gaps::{
    COVERAGE_QUADRANT_SCHEMA, CoverageImportanceQuadrant, GAP_QUADRANT_KNOB_REGISTRY_VERSION,
    GAP_QUADRANT_KNOBS, GROUNDING_GAP_SCHEMA, GapQuadrant, GroundingGap, GroundingGapReport,
    QuadrantConfig, QuadrantPoint, classify_quadrant, coverage_importance_quadrant,
    coverage_importance_quadrant_artifact_bytes, grounding_gap_report,
    grounding_gap_report_artifact_bytes,
};

/// Scope algebra for scoped and hierarchical kernels (#38).
pub mod scope;
pub use scope::{NodeScope, Scope, ScopeAttributes, induced_subgraph};

/// Scoped builds, scope cache, standing-kernel triggers, freshness (#38).
pub mod scope_cache;
pub use scope_cache::{
    CacheKey, FreshnessDecision, KernelCache, RefreshReason, STANDING_KERNEL_KNOB_REGISTRY_VERSION,
    STANDING_KERNEL_KNOBS, StandingKernelPolicy, build_scoped_kernel, decide_freshness,
};

/// Incremental rebuild and hierarchical region kernels (#38).
pub mod incremental;
pub use incremental::{
    GraphDelta, RebuildReport, RegionGraph, build_region_graph, rebuild_dirty, region_id,
};

/// Grounded kernel answer paths: hop-attenuated, ledger-wired Q&A (#40).
pub mod answer;
pub use answer::{
    ASTRO_KERNEL_ANSWER_KNOB_RANGE, ASTRO_KERNEL_ANSWER_NO_ENTRY,
    ASTRO_KERNEL_ANSWER_TRACE_MISMATCH, ASTRO_KERNEL_ANSWER_UNGROUNDED, AnswerConfig,
    AnswerDeficit, AnswerEdge, AnswerHop, AnswerNode, AnswerRefusal, AnswerResolution,
    CALYX_KERNEL_ANSWER_LEDGER_REQUIRED, KERNEL_ANSWER_KNOB_REGISTRY_VERSION, KERNEL_ANSWER_KNOBS,
    KERNEL_ANSWER_REFUSAL_SCHEMA, KERNEL_ANSWER_SCHEMA, KERNEL_GAP_REPORT_SCHEMA,
    KNOB_ANSWER_INDEX_CACHE_ENTRIES, KernelAnswer, KernelGap, KernelGapReport,
    answer_artifact_bytes, answer_query, attenuation_at, kernel_gap_report, verify_answer_trace,
    weight_to_permille,
};

/// Change blast-radius reach through the kernel graph and its risk composition
/// (#366): the answer-path reach term folded into `detect_changes` grounded risk.
pub mod blast_radius;
pub use blast_radius::{
    ASTRO_CHANGE_REACH_KNOB_RANGE, ASTRO_CHANGE_REACH_UNKNOWN_SYMBOL,
    CHANGE_REACH_KNOB_REGISTRY_VERSION, CHANGE_REACH_KNOBS, CHANGE_REACH_SCHEMA, ChangeReach,
    ReachConfig, ReachRisk, ReachedNode, change_reach, change_reach_artifact_bytes,
    reach_risk_permille,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const SEARCH_SCALE_SCHEMA: &str = "astrolabe.search_scale_plan.v1";
pub const SEARCH_SCALE_KNOB_REGISTRY_VERSION: &str = "astro.kernel.search_scale_knobs.v1";
pub const SKILL_TREE_SCHEMA: &str = "astrolabe.skill_tree.v1";
pub const SKILL_DISCOVERY_KNOB_REGISTRY_VERSION: &str = "astro.kernel.skill_discovery_knobs.v1";
pub const BRIDGE_SCHEMA: &str = "astrolabe.bridge.v1";
pub const BRIDGE_CACHE_KEY_SCHEMA: &str = "astrolabe.bridge_cache_key.v1";
pub const LABEL_PROPAGATION_SCHEMA: &str = "astrolabe.label_propagation.v1";
pub const LABEL_PROPAGATION_KNOB_REGISTRY_VERSION: &str = "astro.kernel.label_propagation_knobs.v1";
pub const SCOPE_SUMMARY_SCHEMA: &str = "astrolabe.scope_summary.v1";
pub const FUNNEL_ACTIVATION_RECORDS_KNOB: &str = "search.funnel.activation_records";
pub const SKILL_MIN_CLUSTER_SIZE_KNOB: &str = "skills.min_cluster_size";
pub const SKILL_MIN_SHARED_TOKEN_PERMILLE_KNOB: &str = "skills.min_shared_token_permille";
pub const SKILL_MAX_SYMBOLS_KNOB: &str = "skills.discovery.max_symbols";
pub const LABEL_PROPAGATION_DECAY_MILLIPER_STEP_KNOB: &str =
    "labels.propagation.decay_milliper_step";
pub const ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED: &str = "ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED";
pub const ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT: &str = "ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT";
pub const ASTRO_LABEL_PROPAGATION_KNOB_RANGE: &str = "ASTRO_LABEL_PROPAGATION_KNOB_RANGE";
pub const ASTRO_LABEL_SEED_CONFIDENCE_RANGE: &str = "ASTRO_LABEL_SEED_CONFIDENCE_RANGE";
pub const ASTRO_LABEL_MATH_PARSE: &str = "ASTRO_LABEL_MATH_PARSE";
pub const ASTRO_PROPAGATED_LABEL_TRUST_WRITE: &str = "ASTRO_PROPAGATED_LABEL_TRUST_WRITE";
pub const ASTRO_SKILL_DISCOVERY_KNOB_RANGE: &str = "ASTRO_SKILL_DISCOVERY_KNOB_RANGE";
pub const ASTRO_SKILL_SEARCH_CAP_RANGE: &str = "ASTRO_SKILL_SEARCH_CAP_RANGE";
pub const ASTRO_SKILL_DISCOVERY_NODE_LIMIT: &str = "ASTRO_SKILL_DISCOVERY_NODE_LIMIT";
pub const ASTRO_SKILL_UNKNOWN_ID: &str = "ASTRO_SKILL_UNKNOWN_ID";
pub const DEFAULT_FUNNEL_ACTIVATION_RECORDS: u64 = 10_000_000;
pub const MIN_FUNNEL_ACTIVATION_RECORDS: u64 = 1_000;
pub const MAX_FUNNEL_ACTIVATION_RECORDS: u64 = 1_000_000_000;
pub const DEFAULT_SKILL_MIN_CLUSTER_SIZE: u64 = 2;
pub const MIN_SKILL_MIN_CLUSTER_SIZE: u64 = 2;
pub const MAX_SKILL_MIN_CLUSTER_SIZE: u64 = 10_000;
pub const DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE: u64 = 500;
pub const MIN_SKILL_MIN_SHARED_TOKEN_PERMILLE: u64 = 1;
pub const MAX_SKILL_MIN_SHARED_TOKEN_PERMILLE: u64 = 1_000;
/// Node-limit guard for the quadratic skill-discovery sweep. `build_skill_tree`
/// re-scans every symbol against every other symbol (BTreeSet token
/// intersection/union per pair), so its cost grows as O(n²); without a bound it
/// is unusable on the monorepos (10^5–10^6 symbols) the discovery targets. The
/// default mirrors the weave similarity planner's exact-pair node limit
/// (`astrolabe_weave::DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT` = 50_000): the
/// same 50_000-node bound on the same class of O(n²) exact-pair sweep. Raise the
/// registered knob (bounded opt-out) only for an intentionally larger run.
pub const DEFAULT_SKILL_MAX_SYMBOLS: u64 = 50_000;
pub const MIN_SKILL_MAX_SYMBOLS: u64 = 2;
pub const MAX_SKILL_MAX_SYMBOLS: u64 = 1_000_000;
pub const DEFAULT_LABEL_PROPAGATION_DECAY_MILLIPER_STEP: u64 = 500;
pub const MIN_LABEL_PROPAGATION_DECAY_MILLIPER_STEP: u64 = 1;
pub const MAX_LABEL_PROPAGATION_DECAY_MILLIPER_STEP: u64 = 999;

/// Millipoints scale: `1000` millipoints denote full confidence (`1.0`). It is
/// the fixed denominator of the per-hop decay floor `floor(c * decay / 1000)`
/// and the upper bound of a well-formed confidence.
pub const LABEL_CONFIDENCE_MILLIPOINTS_SCALE: u64 = 1_000;
/// Smallest confidence a label seed may carry. Zero is rejected because a
/// zero-confidence seed produces no reachable labels yet still asserts a claim;
/// the accepted seed-confidence domain is the closed interval
/// `[MIN_SEED_CONFIDENCE_MILLIPOINTS, MAX_SEED_CONFIDENCE_MILLIPOINTS]`.
pub const MIN_SEED_CONFIDENCE_MILLIPOINTS: u64 = 1;
/// Largest confidence a label seed may carry: full confidence on the millipoints
/// scale. Any seed above this is malformed (it would inflate downstream trust).
pub const MAX_SEED_CONFIDENCE_MILLIPOINTS: u64 = LABEL_CONFIDENCE_MILLIPOINTS_SCALE;

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct U64KnobDeclaration {
    pub registry_version: &'static str,
    pub name: &'static str,
    pub default: u64,
    pub min: u64,
    pub max: u64,
    pub unit: &'static str,
    pub source: &'static str,
    pub rationale: &'static str,
}

pub const SEARCH_SCALE_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: SEARCH_SCALE_KNOB_REGISTRY_VERSION,
    name: FUNNEL_ACTIVATION_RECORDS_KNOB,
    default: DEFAULT_FUNNEL_ACTIVATION_RECORDS,
    min: MIN_FUNNEL_ACTIVATION_RECORDS,
    max: MAX_FUNNEL_ACTIVATION_RECORDS,
    unit: "records",
    source: "docs/astrolabe-blueprint.md#12-search-unification",
    rationale: "activate kernel-first funnel above the documented giant-monorepo threshold; tune later from replay/bench evidence",
}];

pub const SKILL_DISCOVERY_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: SKILL_DISCOVERY_KNOB_REGISTRY_VERSION,
        name: SKILL_MIN_CLUSTER_SIZE_KNOB,
        default: DEFAULT_SKILL_MIN_CLUSTER_SIZE,
        min: MIN_SKILL_MIN_CLUSTER_SIZE,
        max: MAX_SKILL_MIN_CLUSTER_SIZE,
        unit: "symbols",
        source: "docs/astrolabe-blueprint.md#12-search-unification",
        rationale: "exclude singleton/noise symbols from generated skill clusters until measured HDBSCAN policy replaces the seed threshold",
    },
    U64KnobDeclaration {
        registry_version: SKILL_DISCOVERY_KNOB_REGISTRY_VERSION,
        name: SKILL_MIN_SHARED_TOKEN_PERMILLE_KNOB,
        default: DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE,
        min: MIN_SKILL_MIN_SHARED_TOKEN_PERMILLE,
        max: MAX_SKILL_MIN_SHARED_TOKEN_PERMILLE,
        unit: "permille",
        source: "docs/astrolabe-blueprint.md#12-search-unification",
        rationale: "seed deterministic skill discovery from exemplar token overlap before HDBSCAN/vector clustering is wired",
    },
    U64KnobDeclaration {
        registry_version: SKILL_DISCOVERY_KNOB_REGISTRY_VERSION,
        name: SKILL_MAX_SYMBOLS_KNOB,
        default: DEFAULT_SKILL_MAX_SYMBOLS,
        min: MIN_SKILL_MAX_SYMBOLS,
        max: MAX_SKILL_MAX_SYMBOLS,
        unit: "symbols",
        source: "docs/astrolabe-blueprint.md#12-search-unification",
        rationale: "bound the O(n^2) token-Jaccard component sweep; default matches the weave similarity planner exact-pair node limit (50_000) on the same class of quadratic sweep, fail closed above it until inverted-index blocking replaces the seed algorithm",
    },
];

pub const LABEL_PROPAGATION_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
    name: LABEL_PROPAGATION_DECAY_MILLIPER_STEP_KNOB,
    default: DEFAULT_LABEL_PROPAGATION_DECAY_MILLIPER_STEP,
    min: MIN_LABEL_PROPAGATION_DECAY_MILLIPER_STEP,
    max: MAX_LABEL_PROPAGATION_DECAY_MILLIPER_STEP,
    unit: "milliper_step",
    source: "docs/astrolabe-blueprint.md#tier-5--the-kernel-distillation--context",
    rationale: "seed deterministic provisional label propagation before live Lodestar harmonic propagation is wired to persisted graphs",
}];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SearchIndexBackend {
    InMemoryHnsw,
    DiskAnn,
    Spann,
}

impl SearchIndexBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InMemoryHnsw => "in_memory_hnsw",
            Self::DiskAnn => "diskann",
            Self::Spann => "spann",
        }
    }

    pub fn is_disk_backed(self) -> bool {
        matches!(self, Self::DiskAnn | Self::Spann)
    }
}

impl FromStr for SearchIndexBackend {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "in_memory_hnsw" => Ok(Self::InMemoryHnsw),
            "diskann" => Ok(Self::DiskAnn),
            "spann" => Ok(Self::Spann),
            _ => Err("unknown search index backend"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SearchFunnelMode {
    Direct,
    KernelFirst,
}

impl SearchFunnelMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::KernelFirst => "kernel_first",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchScaleConfig {
    pub total_records: u64,
    pub funnel_activation_records: u64,
    pub index_backend: SearchIndexBackend,
    pub estimated_index_rss_bytes: u64,
    pub master_budget_bytes: u64,
}

impl SearchScaleConfig {
    pub fn with_registry_defaults(
        total_records: u64,
        estimated_index_rss_bytes: u64,
        master_budget_bytes: u64,
    ) -> Self {
        Self {
            total_records,
            funnel_activation_records: DEFAULT_FUNNEL_ACTIVATION_RECORDS,
            index_backend: SearchIndexBackend::InMemoryHnsw,
            estimated_index_rss_bytes,
            master_budget_bytes,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchScalePlan {
    pub schema: &'static str,
    pub knob_registry_version: &'static str,
    pub total_records: u64,
    pub funnel_activation_records: u64,
    pub funnel_mode: SearchFunnelMode,
    pub activation_label: String,
    pub index_backend: SearchIndexBackend,
    pub index_backend_label: String,
    pub estimated_index_rss_bytes: u64,
    pub master_budget_bytes: u64,
    pub freshness: &'static str,
    pub trust: &'static str,
}

pub fn plan_search_scale(config: &SearchScaleConfig) -> astrolabe_domain::Result<SearchScalePlan> {
    validate_funnel_threshold(config.funnel_activation_records)?;
    validate_ram_budget(config)?;

    let funnel_mode = if config.total_records > config.funnel_activation_records {
        SearchFunnelMode::KernelFirst
    } else {
        SearchFunnelMode::Direct
    };
    Ok(SearchScalePlan {
        schema: SEARCH_SCALE_SCHEMA,
        knob_registry_version: SEARCH_SCALE_KNOB_REGISTRY_VERSION,
        total_records: config.total_records,
        funnel_activation_records: config.funnel_activation_records,
        funnel_mode,
        activation_label: format!(
            "funnel={} because total_records={} and {}={}",
            funnel_mode.as_str(),
            config.total_records,
            FUNNEL_ACTIVATION_RECORDS_KNOB,
            config.funnel_activation_records
        ),
        index_backend: config.index_backend,
        index_backend_label: format!(
            "index_backend={}{}",
            config.index_backend.as_str(),
            if config.index_backend.is_disk_backed() {
                " (operator opt-in)"
            } else {
                " (default)"
            }
        ),
        estimated_index_rss_bytes: config.estimated_index_rss_bytes,
        master_budget_bytes: config.master_budget_bytes,
        freshness: "fresh",
        trust: "verified",
    })
}

fn validate_funnel_threshold(value: u64) -> astrolabe_domain::Result<()> {
    let knob = SEARCH_SCALE_KNOBS
        .iter()
        .find(|knob| knob.name == FUNNEL_ACTIVATION_RECORDS_KNOB)
        .expect("funnel threshold knob is declared");
    if value < knob.min || value > knob.max {
        return Err(astrolabe_domain::DomainError::new(
            "ASTRO_SEARCH_SCALE_KNOB_RANGE",
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the search funnel activation threshold through the registered knob bounds",
        ));
    }
    Ok(())
}

fn validate_ram_budget(config: &SearchScaleConfig) -> astrolabe_domain::Result<()> {
    if config.estimated_index_rss_bytes <= config.master_budget_bytes {
        return Ok(());
    }
    Err(astrolabe_domain::DomainError::new(
        ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED,
        format!(
            "estimated per-slot index RSS {} bytes exceeds master budget {} bytes for backend {}",
            config.estimated_index_rss_bytes,
            config.master_budget_bytes,
            config.index_backend.as_str()
        ),
        "enable diskann/spann indexes, opt out high-cost slots, or increase the configured CBM master memory budget before loading the index",
    ))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeKernelSymbol {
    pub symbol_id: String,
    pub qualified_name: String,
    pub kernel_weight: u64,
    pub provenance_ref: String,
}

impl BridgeKernelSymbol {
    pub fn new(
        symbol_id: impl Into<String>,
        qualified_name: impl Into<String>,
        kernel_weight: u64,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            symbol_id: symbol_id.into(),
            qualified_name: qualified_name.into(),
            kernel_weight,
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeScopeKernel {
    pub scope_id: String,
    pub vault_id: String,
    pub dirty_region_hash: String,
    pub grounded: bool,
    pub symbols: Vec<BridgeKernelSymbol>,
}

impl BridgeScopeKernel {
    pub fn new(
        scope_id: impl Into<String>,
        vault_id: impl Into<String>,
        dirty_region_hash: impl Into<String>,
        grounded: bool,
        symbols: Vec<BridgeKernelSymbol>,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            vault_id: vault_id.into(),
            dirty_region_hash: dirty_region_hash.into(),
            grounded,
            symbols,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeReport {
    pub schema: &'static str,
    pub scope_a: String,
    pub scope_b: String,
    pub cache_key: String,
    pub bridges: Vec<BridgeResult>,
    /// Count of conflicting duplicate `symbol_id` rows dropped while canonicalizing
    /// the two scopes (a scope row that disagreed with the retained row on
    /// qualified name, kernel weight, or provenance). Exact-duplicate collapses are
    /// not counted. Non-zero means the source scopes carried contradictory rows for
    /// the same symbol; the retained rows are the deterministic sorted-first choice.
    pub conflicting_duplicate_symbols: usize,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeResult {
    pub symbol_id: String,
    pub qualified_name: String,
    pub combined_kernel_weight: u64,
    pub scope_a_kernel_weight: u64,
    pub scope_b_kernel_weight: u64,
    pub provenance: BridgeProvenancePair,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeProvenancePair {
    pub scope_a: String,
    pub scope_b: String,
}

pub fn bridge_symbols(scope_a: &BridgeScopeKernel, scope_b: &BridgeScopeKernel) -> BridgeReport {
    let (left_symbols, left_dropped) = canonical_symbol_map(scope_a);
    let (right_symbols, right_dropped) = canonical_symbol_map(scope_b);
    let trust = bridge_trust(scope_a, scope_b);
    let mut bridges = left_symbols
        .iter()
        .filter_map(|(symbol_id, left)| {
            let right = right_symbols.get(symbol_id)?;
            Some(BridgeResult {
                symbol_id: symbol_id.clone(),
                qualified_name: left.qualified_name.clone(),
                combined_kernel_weight: left.kernel_weight.saturating_add(right.kernel_weight),
                scope_a_kernel_weight: left.kernel_weight,
                scope_b_kernel_weight: right.kernel_weight,
                provenance: BridgeProvenancePair {
                    scope_a: left.provenance_ref.clone(),
                    scope_b: right.provenance_ref.clone(),
                },
                freshness: "fresh",
                trust,
            })
        })
        .collect::<Vec<_>>();
    bridges.sort_by(|left, right| {
        right
            .combined_kernel_weight
            .cmp(&left.combined_kernel_weight)
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
    });

    BridgeReport {
        schema: BRIDGE_SCHEMA,
        scope_a: scope_a.scope_id.clone(),
        scope_b: scope_b.scope_id.clone(),
        cache_key: bridge_cache_key(scope_a, scope_b),
        bridges,
        conflicting_duplicate_symbols: left_dropped + right_dropped,
        freshness: "fresh",
        trust,
    }
}

pub fn bridge_cache_key(scope_a: &BridgeScopeKernel, scope_b: &BridgeScopeKernel) -> String {
    let mut scope_hashes = [bridge_scope_hash(scope_a), bridge_scope_hash(scope_b)];
    scope_hashes.sort();
    hex_lower(&astrolabe_domain::calyx::content_address([
        BRIDGE_CACHE_KEY_SCHEMA.as_bytes(),
        scope_hashes[0].as_bytes(),
        scope_hashes[1].as_bytes(),
    ]))
}

pub fn bridge_report_artifact_bytes(report: &BridgeReport) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(report.schema);
    out.push('\n');
    out.push_str("scope_a=");
    out.push_str(&report.scope_a);
    out.push('\n');
    out.push_str("scope_b=");
    out.push_str(&report.scope_b);
    out.push('\n');
    out.push_str("cache_key=");
    out.push_str(&report.cache_key);
    out.push('\n');
    out.push_str("trust=");
    out.push_str(report.trust);
    out.push('\n');
    out.push_str("conflicting_duplicate_symbols=");
    out.push_str(&report.conflicting_duplicate_symbols.to_string());
    out.push('\n');
    for bridge in &report.bridges {
        out.push_str("bridge\t");
        out.push_str(&bridge.symbol_id);
        out.push('\t');
        out.push_str(&bridge.qualified_name);
        out.push('\t');
        out.push_str(&bridge.combined_kernel_weight.to_string());
        out.push('\t');
        out.push_str(&bridge.scope_a_kernel_weight.to_string());
        out.push('\t');
        out.push_str(&bridge.scope_b_kernel_weight.to_string());
        out.push('\t');
        out.push_str(&bridge.provenance.scope_a);
        out.push('\t');
        out.push_str(&bridge.provenance.scope_b);
        out.push('\n');
    }
    out.into_bytes()
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CrossVaultEdge {
    pub from_vault_id: String,
    pub from_symbol_id: String,
    pub to_vault_id: String,
    pub to_symbol_id: String,
    pub edge_kind: String,
    pub provenance_ref: String,
}

impl CrossVaultEdge {
    pub fn new(
        from_vault_id: impl Into<String>,
        from_symbol_id: impl Into<String>,
        to_vault_id: impl Into<String>,
        to_symbol_id: impl Into<String>,
        edge_kind: impl Into<String>,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            from_vault_id: from_vault_id.into(),
            from_symbol_id: from_symbol_id.into(),
            to_vault_id: to_vault_id.into(),
            to_symbol_id: to_symbol_id.into(),
            edge_kind: edge_kind.into(),
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CrossVaultBridgeChain {
    pub from_scope: String,
    pub to_scope: String,
    pub from_symbol_id: String,
    pub to_symbol_id: String,
    pub hops: Vec<CrossVaultBridgeHop>,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CrossVaultBridgeHop {
    pub from_vault_id: String,
    pub from_symbol_id: String,
    pub to_vault_id: String,
    pub to_symbol_id: String,
    pub edge_kind: String,
    pub provenance_ref: String,
}

pub fn resolve_cross_vault_bridge_chains(
    scope_a: &BridgeScopeKernel,
    scope_b: &BridgeScopeKernel,
    edges: &[CrossVaultEdge],
) -> astrolabe_domain::Result<Vec<CrossVaultBridgeChain>> {
    let scope_a_members = symbol_id_set(scope_a);
    let scope_b_members = symbol_id_set(scope_b);
    let trust = bridge_trust(scope_a, scope_b);
    let mut chains = Vec::new();

    for edge in edges
        .iter()
        .filter(|edge| edge.edge_kind.starts_with("CROSS_"))
    {
        let forward_source = edge.from_vault_id == scope_a.vault_id
            && scope_a_members.contains(&edge.from_symbol_id);
        let reverse_source = edge.from_vault_id == scope_b.vault_id
            && scope_b_members.contains(&edge.from_symbol_id);
        if !forward_source && !reverse_source {
            continue;
        }

        if forward_source {
            if edge.to_vault_id != scope_b.vault_id {
                return Err(missing_counterpart_vault_error(edge, scope_b));
            }
            if scope_b_members.contains(&edge.to_symbol_id) {
                chains.push(cross_vault_chain(scope_a, scope_b, edge, trust));
            }
        } else {
            if edge.to_vault_id != scope_a.vault_id {
                return Err(missing_counterpart_vault_error(edge, scope_a));
            }
            if scope_a_members.contains(&edge.to_symbol_id) {
                chains.push(cross_vault_chain(scope_b, scope_a, edge, trust));
            }
        }
    }

    chains.sort_by(|left, right| {
        left.from_symbol_id
            .cmp(&right.from_symbol_id)
            .then_with(|| left.to_symbol_id.cmp(&right.to_symbol_id))
            .then_with(|| {
                left.hops[0]
                    .provenance_ref
                    .cmp(&right.hops[0].provenance_ref)
            })
    });
    Ok(chains)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeclaredBridgeBoundary {
    pub scope_a: String,
    pub scope_b: String,
    pub allowed: bool,
    pub provenance_ref: String,
}

impl DeclaredBridgeBoundary {
    pub fn new(
        scope_a: impl Into<String>,
        scope_b: impl Into<String>,
        allowed: bool,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            scope_a: scope_a.into(),
            scope_b: scope_b.into(),
            allowed,
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeBoundaryDiff {
    pub schema: &'static str,
    pub scope_a: String,
    pub scope_b: String,
    pub violations: Vec<BridgeBoundaryViolation>,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeBoundaryViolation {
    pub symbol_id: String,
    pub qualified_name: String,
    pub declared_provenance_ref: String,
    pub measured_scope_a_provenance_ref: String,
    pub measured_scope_b_provenance_ref: String,
}

pub fn diff_declared_bridge_boundaries(
    report: &BridgeReport,
    declared: &[DeclaredBridgeBoundary],
) -> BridgeBoundaryDiff {
    let forbidden = declared.iter().find(|boundary| {
        !boundary.allowed
            && same_scope_pair(
                &report.scope_a,
                &report.scope_b,
                &boundary.scope_a,
                &boundary.scope_b,
            )
    });
    let violations = forbidden
        .map(|boundary| {
            report
                .bridges
                .iter()
                .map(|bridge| BridgeBoundaryViolation {
                    symbol_id: bridge.symbol_id.clone(),
                    qualified_name: bridge.qualified_name.clone(),
                    declared_provenance_ref: boundary.provenance_ref.clone(),
                    measured_scope_a_provenance_ref: bridge.provenance.scope_a.clone(),
                    measured_scope_b_provenance_ref: bridge.provenance.scope_b.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    BridgeBoundaryDiff {
        schema: BRIDGE_SCHEMA,
        scope_a: report.scope_a.clone(),
        scope_b: report.scope_b.clone(),
        violations,
        freshness: report.freshness,
        trust: report.trust,
    }
}

/// Collapses a scope's symbols to one canonical row per `symbol_id`, keeping the
/// deterministic sorted-first row (smallest `qualified_name`, then
/// `provenance_ref`), and returns how many *conflicting* duplicate rows were
/// dropped.
///
/// A second row for a `symbol_id` that is byte-identical to the retained row is a
/// harmless collapse. A second row that disagrees on `qualified_name`,
/// `kernel_weight`, or `provenance_ref` is a real loss of information — exactly the
/// silent drop the doctrine forbids — so it is counted and surfaced on the
/// [`BridgeReport`]. The retained row (and therefore the bridge output and cache
/// key) is unchanged; only the previously-unrecorded conflict count is new.
fn canonical_symbol_map(
    scope: &BridgeScopeKernel,
) -> (BTreeMap<String, BridgeKernelSymbol>, usize) {
    let mut symbols = scope.symbols.clone();
    symbols.sort_by(|left, right| {
        left.symbol_id
            .cmp(&right.symbol_id)
            .then_with(|| left.qualified_name.cmp(&right.qualified_name))
            .then_with(|| left.provenance_ref.cmp(&right.provenance_ref))
    });
    let mut map: BTreeMap<String, BridgeKernelSymbol> = BTreeMap::new();
    let mut conflicting_dropped = 0usize;
    for symbol in symbols {
        match map.entry(symbol.symbol_id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(symbol);
            }
            Entry::Occupied(retained) => {
                if retained.get() != &symbol {
                    conflicting_dropped += 1;
                }
            }
        }
    }
    (map, conflicting_dropped)
}

fn symbol_id_set(scope: &BridgeScopeKernel) -> BTreeSet<String> {
    scope
        .symbols
        .iter()
        .map(|symbol| symbol.symbol_id.clone())
        .collect()
}

fn bridge_trust(scope_a: &BridgeScopeKernel, scope_b: &BridgeScopeKernel) -> &'static str {
    if scope_a.grounded && scope_b.grounded {
        "verified"
    } else {
        "provisional"
    }
}

fn bridge_scope_hash(scope: &BridgeScopeKernel) -> String {
    let (symbols, _conflicting_dropped) = canonical_symbol_map(scope);
    let mut canonical = String::new();
    canonical.push_str(&scope.scope_id);
    canonical.push('\t');
    canonical.push_str(&scope.vault_id);
    canonical.push('\t');
    canonical.push_str(&scope.dirty_region_hash);
    canonical.push('\t');
    canonical.push_str(if scope.grounded {
        "grounded"
    } else {
        "ungrounded"
    });
    canonical.push('\n');
    for symbol in symbols.values() {
        canonical.push_str(&symbol.symbol_id);
        canonical.push('\t');
        canonical.push_str(&symbol.qualified_name);
        canonical.push('\t');
        canonical.push_str(&symbol.kernel_weight.to_string());
        canonical.push('\t');
        canonical.push_str(&symbol.provenance_ref);
        canonical.push('\n');
    }
    hex_lower(&astrolabe_domain::calyx::content_address([
        b"astrolabe-bridge-scope-v1".as_slice(),
        canonical.as_bytes(),
    ]))
}

fn cross_vault_chain(
    from_scope: &BridgeScopeKernel,
    to_scope: &BridgeScopeKernel,
    edge: &CrossVaultEdge,
    trust: &'static str,
) -> CrossVaultBridgeChain {
    CrossVaultBridgeChain {
        from_scope: from_scope.scope_id.clone(),
        to_scope: to_scope.scope_id.clone(),
        from_symbol_id: edge.from_symbol_id.clone(),
        to_symbol_id: edge.to_symbol_id.clone(),
        hops: vec![CrossVaultBridgeHop {
            from_vault_id: edge.from_vault_id.clone(),
            from_symbol_id: edge.from_symbol_id.clone(),
            to_vault_id: edge.to_vault_id.clone(),
            to_symbol_id: edge.to_symbol_id.clone(),
            edge_kind: edge.edge_kind.clone(),
            provenance_ref: edge.provenance_ref.clone(),
        }],
        freshness: "fresh",
        trust,
    }
}

fn missing_counterpart_vault_error(
    edge: &CrossVaultEdge,
    expected: &BridgeScopeKernel,
) -> astrolabe_domain::DomainError {
    astrolabe_domain::DomainError::new(
        ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT,
        format!(
            "{} edge {}:{} -> {}:{} does not target counterpart vault {} for scope {}",
            edge.edge_kind,
            edge.from_vault_id,
            edge.from_symbol_id,
            edge.to_vault_id,
            edge.to_symbol_id,
            expected.vault_id,
            expected.scope_id
        ),
        "load the counterpart vault named by the CROSS_* edge or exclude the unresolved cross-vault route from bridge resolution",
    )
}

fn same_scope_pair(left_a: &str, left_b: &str, right_a: &str, right_b: &str) -> bool {
    (left_a == right_a && left_b == right_b) || (left_a == right_b && left_b == right_a)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LabelPropagationConfig {
    pub decay_milliper_step: u64,
}

impl Default for LabelPropagationConfig {
    fn default() -> Self {
        Self {
            decay_milliper_step: DEFAULT_LABEL_PROPAGATION_DECAY_MILLIPER_STEP,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LabelTrust {
    Trusted,
    Provisional,
}

impl LabelTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Provisional => "provisional",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LabelSeed {
    pub symbol_id: String,
    pub label: String,
    /// Seed confidence on the millipoints scale. The accepted domain is the
    /// closed interval `[MIN_SEED_CONFIDENCE_MILLIPOINTS,
    /// MAX_SEED_CONFIDENCE_MILLIPOINTS]` = `[1, 1000]`; `propagate_labels`
    /// rejects any out-of-range seed fail-closed with
    /// [`ASTRO_LABEL_SEED_CONFIDENCE_RANGE`].
    pub confidence_millipoints: u64,
    pub provenance_ref: String,
}

impl LabelSeed {
    pub fn new(
        symbol_id: impl Into<String>,
        label: impl Into<String>,
        confidence_millipoints: u64,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            symbol_id: symbol_id.into(),
            label: label.into(),
            confidence_millipoints,
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LabelGraphEdge {
    pub left_symbol_id: String,
    pub right_symbol_id: String,
    pub provenance_ref: String,
}

impl LabelGraphEdge {
    pub fn new(
        left_symbol_id: impl Into<String>,
        right_symbol_id: impl Into<String>,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            left_symbol_id: left_symbol_id.into(),
            right_symbol_id: right_symbol_id.into(),
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LabelTombstone {
    pub symbol_id: String,
    pub provenance_ref: String,
}

impl LabelTombstone {
    pub fn new(symbol_id: impl Into<String>, provenance_ref: impl Into<String>) -> Self {
        Self {
            symbol_id: symbol_id.into(),
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LabelPropagationReport {
    pub schema: &'static str,
    pub knob_registry_version: &'static str,
    pub decay_milliper_step: u64,
    pub labels: Vec<PropagatedLabel>,
    pub empty_reason: Option<&'static str>,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PropagatedLabel {
    pub symbol_id: String,
    pub label: String,
    pub confidence_millipoints: u64,
    pub seed_symbol_id: String,
    pub seed_confidence_millipoints: u64,
    pub distance: u64,
    pub provenance: LabelPropagationProvenance,
    pub freshness: &'static str,
    pub trust: LabelTrust,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LabelPropagationProvenance {
    pub seed_provenance_ref: String,
    pub graph_provenance_refs: Vec<String>,
    pub math: String,
}

pub fn propagate_labels(
    seeds: &[LabelSeed],
    edges: &[LabelGraphEdge],
    tombstones: &[LabelTombstone],
    config: &LabelPropagationConfig,
) -> astrolabe_domain::Result<LabelPropagationReport> {
    // #443 permanent sub-phase timing (env-gated `ASTRO_KERNEL_TIMING`): the
    // label_propagation cold-index phase's internal breakdown (adjacency build /
    // per-seed flood / collect+sort) so the #443 matrix can attribute its
    // 44s@n=45,557 to a real sub-stage. Silent by default; carries no behaviour.
    let mut timing = KernelPhaseTiming::start("label_propagation");
    validate_label_propagation_knob(config.decay_milliper_step)?;
    for seed in seeds {
        validate_seed_confidence(seed)?;
    }

    let tombstoned = tombstones
        .iter()
        .map(|tombstone| tombstone.symbol_id.clone())
        .collect::<BTreeSet<_>>();
    let active_seeds = seeds
        .iter()
        .filter(|seed| !tombstoned.contains(&seed.symbol_id))
        .cloned()
        .collect::<Vec<_>>();
    if active_seeds.is_empty() {
        return Ok(LabelPropagationReport {
            schema: LABEL_PROPAGATION_SCHEMA,
            knob_registry_version: LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
            decay_milliper_step: config.decay_milliper_step,
            labels: Vec::new(),
            empty_reason: Some("zero_seed_scope"),
            freshness: "fresh",
            trust: "verified",
        });
    }

    let adjacency = label_adjacency(edges, &tombstoned);
    let seed_keys = active_seeds
        .iter()
        .map(|seed| (seed.symbol_id.clone(), seed.label.clone()))
        .collect::<BTreeSet<_>>();
    let mut best = BTreeMap::<(String, String), PropagatedLabel>::new();
    timing.lap("adjacency");

    for seed in active_seeds {
        let mut queue = vec![LabelPropagationFrontier {
            symbol_id: seed.symbol_id.clone(),
            confidence_millipoints: seed.confidence_millipoints,
            distance: 0,
            path_provenance_refs: Vec::new(),
        }];
        let mut best_seen_for_seed = BTreeMap::<String, u64>::new();
        best_seen_for_seed.insert(seed.symbol_id.clone(), seed.confidence_millipoints);

        while let Some(frontier) = queue.pop() {
            let Some(neighbors) = adjacency.get(&frontier.symbol_id) else {
                continue;
            };
            for (neighbor, edge_provenance_ref) in neighbors {
                if tombstoned.contains(neighbor) {
                    continue;
                }
                let next_confidence = decay_confidence_one_hop(
                    frontier.confidence_millipoints,
                    config.decay_milliper_step,
                );
                if next_confidence == 0 {
                    continue;
                }
                if best_seen_for_seed.get(neighbor).copied().unwrap_or(0) >= next_confidence {
                    continue;
                }
                best_seen_for_seed.insert(neighbor.clone(), next_confidence);
                let mut path_provenance_refs = frontier.path_provenance_refs.clone();
                path_provenance_refs.push(edge_provenance_ref.clone());
                let distance = frontier.distance + 1;
                queue.push(LabelPropagationFrontier {
                    symbol_id: neighbor.clone(),
                    confidence_millipoints: next_confidence,
                    distance,
                    path_provenance_refs: path_provenance_refs.clone(),
                });

                if seed_keys.contains(&(neighbor.clone(), seed.label.clone())) {
                    continue;
                }
                let candidate = PropagatedLabel {
                    symbol_id: neighbor.clone(),
                    label: seed.label.clone(),
                    confidence_millipoints: next_confidence,
                    seed_symbol_id: seed.symbol_id.clone(),
                    seed_confidence_millipoints: seed.confidence_millipoints,
                    distance,
                    provenance: LabelPropagationProvenance {
                        seed_provenance_ref: seed.provenance_ref.clone(),
                        graph_provenance_refs: path_provenance_refs,
                        math: label_propagation_math(
                            seed.confidence_millipoints,
                            config.decay_milliper_step,
                            distance,
                            next_confidence,
                        ),
                    },
                    freshness: "fresh",
                    trust: LabelTrust::Provisional,
                };
                let key = (candidate.symbol_id.clone(), candidate.label.clone());
                let replace = best
                    .get(&key)
                    .map(|current| propagated_label_rank(&candidate, current).is_lt())
                    .unwrap_or(true);
                if replace {
                    best.insert(key, candidate);
                }
            }
        }
    }

    timing.lap("flood");

    let mut labels = best.into_values().collect::<Vec<_>>();
    labels.sort_by(|left, right| {
        left.symbol_id
            .cmp(&right.symbol_id)
            .then_with(|| left.label.cmp(&right.label))
    });
    timing.lap("collect_sort");

    Ok(LabelPropagationReport {
        schema: LABEL_PROPAGATION_SCHEMA,
        knob_registry_version: LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
        decay_milliper_step: config.decay_milliper_step,
        empty_reason: if labels.is_empty() {
            Some("no_reachable_unseeded_symbols")
        } else {
            None
        },
        labels,
        freshness: "fresh",
        trust: "provisional",
    })
}

pub fn validate_propagated_label_write(
    label: &PropagatedLabel,
    requested_trust: LabelTrust,
) -> astrolabe_domain::Result<()> {
    if requested_trust == LabelTrust::Trusted {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_PROPAGATED_LABEL_TRUST_WRITE,
            format!(
                "propagated label {} on {} cannot be written as trusted",
                label.label, label.symbol_id
            ),
            "write propagated labels as provisional, or create a grounded label seed with trusted provenance",
        ));
    }
    Ok(())
}

pub fn filter_symbols_by_propagated_label(
    report: &LabelPropagationReport,
    label: &str,
    candidates: &[String],
) -> Vec<String> {
    let labeled_symbols = report
        .labels
        .iter()
        .filter(|propagated| propagated.label == label)
        .map(|propagated| propagated.symbol_id.as_str())
        .collect::<BTreeSet<_>>();
    candidates
        .iter()
        .filter(|candidate| labeled_symbols.contains(candidate.as_str()))
        .cloned()
        .collect()
}

pub fn label_propagation_artifact_bytes(report: &LabelPropagationReport) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(report.schema);
    out.push('\n');
    out.push_str("knobs=");
    out.push_str(report.knob_registry_version);
    out.push('\n');
    out.push_str("decay=");
    out.push_str(&report.decay_milliper_step.to_string());
    out.push('\n');
    if let Some(reason) = report.empty_reason {
        out.push_str("empty_reason=");
        out.push_str(reason);
        out.push('\n');
    }
    for label in &report.labels {
        out.push_str("label\t");
        out.push_str(&label.symbol_id);
        out.push('\t');
        out.push_str(&label.label);
        out.push('\t');
        out.push_str(&label.confidence_millipoints.to_string());
        out.push('\t');
        out.push_str(&label.seed_symbol_id);
        out.push('\t');
        out.push_str(&label.distance.to_string());
        out.push('\t');
        out.push_str(label.trust.as_str());
        out.push('\t');
        out.push_str(&label.provenance.seed_provenance_ref);
        out.push('\t');
        out.push_str(&label.provenance.graph_provenance_refs.join(","));
        out.push('\t');
        out.push_str(&label.provenance.math);
        out.push('\n');
    }
    out.into_bytes()
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScopeSummaryInput {
    pub scope_id: String,
    pub dirty_region_hash: String,
    pub grounded: bool,
    pub kernel_members: Vec<ScopeSummaryMember>,
    pub recall: Option<ScopeRecallMeasurement>,
}

impl ScopeSummaryInput {
    pub fn new(
        scope_id: impl Into<String>,
        dirty_region_hash: impl Into<String>,
        grounded: bool,
        kernel_members: Vec<ScopeSummaryMember>,
        recall: Option<ScopeRecallMeasurement>,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            dirty_region_hash: dirty_region_hash.into(),
            grounded,
            kernel_members,
            recall,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScopeSummaryMember {
    pub symbol_id: String,
    pub qualified_name: String,
    pub kernel_weight: u64,
    pub grounded: bool,
    pub provenance_ref: String,
}

impl ScopeSummaryMember {
    pub fn new(
        symbol_id: impl Into<String>,
        qualified_name: impl Into<String>,
        kernel_weight: u64,
        grounded: bool,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            symbol_id: symbol_id.into(),
            qualified_name: qualified_name.into(),
            kernel_weight,
            grounded,
            provenance_ref: provenance_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ScopeRecallMeasurement {
    pub recalled: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScopeSummary {
    pub schema: &'static str,
    pub scope_id: String,
    pub dirty_region_hash: String,
    pub members: Vec<ScopeSummaryMember>,
    pub recall: Option<ScopeRecallMeasurement>,
    pub recall_millipoints: Option<u64>,
    pub grounded_member_count: usize,
    pub total_member_count: usize,
    pub grounded_fraction_millipoints: u64,
    pub summary_hash: String,
    pub freshness: &'static str,
    pub trust: &'static str,
}

pub fn summarize_scope_kernel(input: &ScopeSummaryInput) -> ScopeSummary {
    let mut members = input.kernel_members.clone();
    members.sort_by(|left, right| {
        right
            .kernel_weight
            .cmp(&left.kernel_weight)
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
    });
    let grounded_member_count = members.iter().filter(|member| member.grounded).count();
    let total_member_count = members.len();
    let grounded_fraction_millipoints = (grounded_member_count as u64)
        .saturating_mul(1_000)
        .checked_div(total_member_count as u64)
        .unwrap_or(0);
    let recall_millipoints = input.recall.and_then(|recall| {
        recall
            .recalled
            .saturating_mul(1_000)
            .checked_div(recall.total)
    });
    let summary_hash = scope_summary_hash(&input.scope_id, &input.dirty_region_hash, &members);

    ScopeSummary {
        schema: SCOPE_SUMMARY_SCHEMA,
        scope_id: input.scope_id.clone(),
        dirty_region_hash: input.dirty_region_hash.clone(),
        members,
        recall: input.recall,
        recall_millipoints,
        grounded_member_count,
        total_member_count,
        grounded_fraction_millipoints,
        summary_hash,
        freshness: "fresh",
        trust: if input.grounded {
            "verified"
        } else {
            "provisional"
        },
    }
}

pub fn scope_summary_artifact_bytes(summary: &ScopeSummary) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(summary.schema);
    out.push('\n');
    out.push_str("scope=");
    out.push_str(&summary.scope_id);
    out.push('\n');
    out.push_str("summary_hash=");
    out.push_str(&summary.summary_hash);
    out.push('\n');
    out.push_str("grounded_fraction=");
    out.push_str(&summary.grounded_fraction_millipoints.to_string());
    out.push('\n');
    if let Some(recall) = summary.recall_millipoints {
        out.push_str("recall=");
        out.push_str(&recall.to_string());
        out.push('\n');
    }
    for member in &summary.members {
        out.push_str("member\t");
        out.push_str(&member.symbol_id);
        out.push('\t');
        out.push_str(&member.qualified_name);
        out.push('\t');
        out.push_str(&member.kernel_weight.to_string());
        out.push('\t');
        out.push_str(if member.grounded {
            "grounded"
        } else {
            "ungrounded"
        });
        out.push('\t');
        out.push_str(&member.provenance_ref);
        out.push('\n');
    }
    out.into_bytes()
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct LabelPropagationFrontier {
    symbol_id: String,
    confidence_millipoints: u64,
    distance: u64,
    path_provenance_refs: Vec<String>,
}

fn validate_label_propagation_knob(value: u64) -> astrolabe_domain::Result<()> {
    let knob = LABEL_PROPAGATION_KNOBS
        .iter()
        .find(|knob| knob.name == LABEL_PROPAGATION_DECAY_MILLIPER_STEP_KNOB)
        .expect("label propagation decay knob is declared");
    if value < knob.min || value > knob.max {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_LABEL_PROPAGATION_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set label propagation decay through the registered knob bounds",
        ));
    }
    Ok(())
}

fn validate_seed_confidence(seed: &LabelSeed) -> astrolabe_domain::Result<()> {
    let value = seed.confidence_millipoints;
    if !(MIN_SEED_CONFIDENCE_MILLIPOINTS..=MAX_SEED_CONFIDENCE_MILLIPOINTS).contains(&value) {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_LABEL_SEED_CONFIDENCE_RANGE,
            format!(
                "label seed {} for {} has confidence_millipoints={} outside accepted domain {}..={}",
                seed.symbol_id,
                seed.label,
                value,
                MIN_SEED_CONFIDENCE_MILLIPOINTS,
                MAX_SEED_CONFIDENCE_MILLIPOINTS
            ),
            "provide seed confidence_millipoints within [1,1000] (1000 millipoints = full confidence)",
        ));
    }
    Ok(())
}

/// Apply one propagation hop's decay floor: `floor(confidence * decay / 1000)`.
/// This is the single source of truth for the per-hop recurrence used both by
/// `propagate_labels` and by the emitted provenance math string, so a recompute
/// from that string reproduces the stored confidence exactly.
fn decay_confidence_one_hop(confidence: u64, decay: u64) -> u64 {
    confidence.saturating_mul(decay) / LABEL_CONFIDENCE_MILLIPOINTS_SCALE
}

/// Emit a self-contained, machine-parseable provenance math string that states
/// the actual computation inputs (`c0` = seed confidence, `factor` = decay,
/// `denominator` = millipoints scale, `hops` = distance) and the recurrence
/// (`iterated_per_hop_floor`). Recomputing from the stated values via
/// [`recompute_from_label_math`] reproduces `result` — the stored confidence —
/// exactly. `result` is the real propagated value, not a re-derivation, so a
/// test can prove the inputs recompute to the persisted output.
fn label_propagation_math(seed_confidence: u64, decay: u64, hops: u64, result: u64) -> String {
    format!(
        "recurrence=iterated_per_hop_floor; c0={}; factor={}; denominator={}; hops={}; result={}",
        seed_confidence, decay, LABEL_CONFIDENCE_MILLIPOINTS_SCALE, hops, result
    )
}

/// Recompute a propagated confidence from an emitted provenance math string by
/// replaying the exact iterated per-hop decay floor over the stated inputs.
/// Fail-closed on any missing/malformed field or a zero denominator so a
/// consumer can independently verify a stored label's confidence from its
/// provenance alone.
pub fn recompute_from_label_math(math: &str) -> astrolabe_domain::Result<u64> {
    fn field(math: &str, key: &str) -> astrolabe_domain::Result<u64> {
        let raw = math
            .split("; ")
            .find_map(|part| {
                part.strip_prefix(key)
                    .and_then(|rest| rest.strip_prefix('='))
            })
            .ok_or_else(|| {
                astrolabe_domain::DomainError::new(
                    ASTRO_LABEL_MATH_PARSE,
                    format!("label provenance math is missing field {key}: {math}"),
                    "recompute only from a provenance string emitted by label_propagation_math",
                )
            })?;
        raw.parse::<u64>().map_err(|err| {
            astrolabe_domain::DomainError::new(
                ASTRO_LABEL_MATH_PARSE,
                format!("label provenance math field {key} is not a u64 ({raw}): {err}"),
                "recompute only from a provenance string emitted by label_propagation_math",
            )
        })
    }

    let c0 = field(math, "c0")?;
    let factor = field(math, "factor")?;
    let denominator = field(math, "denominator")?;
    let hops = field(math, "hops")?;
    if denominator == 0 {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_LABEL_MATH_PARSE,
            format!("label provenance math has zero denominator: {math}"),
            "recompute only from a provenance string emitted by label_propagation_math",
        ));
    }
    let mut confidence = c0;
    for _ in 0..hops {
        confidence = confidence.saturating_mul(factor) / denominator;
    }
    Ok(confidence)
}

fn label_adjacency(
    edges: &[LabelGraphEdge],
    tombstoned: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<(String, String)>> {
    let mut adjacency = BTreeMap::<String, BTreeSet<(String, String)>>::new();
    for edge in edges {
        if tombstoned.contains(&edge.left_symbol_id) || tombstoned.contains(&edge.right_symbol_id) {
            continue;
        }
        adjacency
            .entry(edge.left_symbol_id.clone())
            .or_default()
            .insert((edge.right_symbol_id.clone(), edge.provenance_ref.clone()));
        adjacency
            .entry(edge.right_symbol_id.clone())
            .or_default()
            .insert((edge.left_symbol_id.clone(), edge.provenance_ref.clone()));
    }
    adjacency
}

fn propagated_label_rank(left: &PropagatedLabel, right: &PropagatedLabel) -> std::cmp::Ordering {
    right
        .confidence_millipoints
        .cmp(&left.confidence_millipoints)
        .then_with(|| left.distance.cmp(&right.distance))
        .then_with(|| left.seed_symbol_id.cmp(&right.seed_symbol_id))
}

fn scope_summary_hash(
    scope_id: &str,
    dirty_region_hash: &str,
    members: &[ScopeSummaryMember],
) -> String {
    let mut canonical = String::new();
    canonical.push_str(scope_id);
    canonical.push('\t');
    canonical.push_str(dirty_region_hash);
    canonical.push('\n');
    for member in members {
        canonical.push_str(&member.symbol_id);
        canonical.push('\t');
        canonical.push_str(&member.qualified_name);
        canonical.push('\t');
        canonical.push_str(&member.kernel_weight.to_string());
        canonical.push('\t');
        canonical.push_str(if member.grounded {
            "grounded"
        } else {
            "ungrounded"
        });
        canonical.push('\t');
        canonical.push_str(&member.provenance_ref);
        canonical.push('\n');
    }
    hex_lower(&astrolabe_domain::calyx::content_address([
        b"astrolabe-scope-summary-v1".as_slice(),
        canonical.as_bytes(),
    ]))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkillSymbolInput {
    pub symbol_id: String,
    pub qualified_name: String,
    pub path: String,
    pub tokens: BTreeSet<String>,
}

impl SkillSymbolInput {
    pub fn new(
        symbol_id: impl Into<String>,
        qualified_name: impl Into<String>,
        path: impl Into<String>,
        tokens: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            symbol_id: symbol_id.into(),
            qualified_name: qualified_name.into(),
            path: path.into(),
            tokens: tokens.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkillDiscoveryConfig {
    pub min_cluster_size: u64,
    pub min_shared_token_permille: u64,
    /// Registry-declared node-limit guard (`SKILL_MAX_SYMBOLS_KNOB`). The
    /// discovery sweep is O(n²); inputs above this bound are refused fail-closed
    /// with [`ASTRO_SKILL_DISCOVERY_NODE_LIMIT`] rather than silently running an
    /// unbounded scan. Raise it within the registered bounds to opt into a
    /// larger, intentionally slower run.
    pub max_symbols: u64,
}

impl Default for SkillDiscoveryConfig {
    fn default() -> Self {
        Self {
            min_cluster_size: DEFAULT_SKILL_MIN_CLUSTER_SIZE,
            min_shared_token_permille: DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE,
            max_symbols: DEFAULT_SKILL_MAX_SYMBOLS,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkillTree {
    pub schema: &'static str,
    pub knob_registry_version: &'static str,
    pub skills: Vec<SkillNode>,
    pub noise_symbols: Vec<String>,
    pub membership_hash: String,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkillNode {
    pub skill_id: String,
    pub name: String,
    pub members: Vec<String>,
    pub exemplar_tokens: Vec<String>,
    pub membership_hash: String,
}

pub fn build_skill_tree(
    inputs: &[SkillSymbolInput],
    config: &SkillDiscoveryConfig,
) -> astrolabe_domain::Result<SkillTree> {
    validate_skill_knob(
        SKILL_MIN_CLUSTER_SIZE_KNOB,
        config.min_cluster_size,
        SKILL_DISCOVERY_KNOBS,
    )?;
    validate_skill_knob(
        SKILL_MIN_SHARED_TOKEN_PERMILLE_KNOB,
        config.min_shared_token_permille,
        SKILL_DISCOVERY_KNOBS,
    )?;
    validate_skill_knob(
        SKILL_MAX_SYMBOLS_KNOB,
        config.max_symbols,
        SKILL_DISCOVERY_KNOBS,
    )?;

    if inputs.len() as u64 > config.max_symbols {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_SKILL_DISCOVERY_NODE_LIMIT,
            format!(
                "skill discovery input has {} symbols, exceeding the O(n^2) node limit {}={}",
                inputs.len(),
                SKILL_MAX_SYMBOLS_KNOB,
                config.max_symbols
            ),
            "raise the skills.discovery.max_symbols knob within its registered bounds to opt into a larger run, or narrow the discovery scope",
        ));
    }

    let mut symbols = inputs.to_vec();
    symbols.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
    let mut visited = vec![false; symbols.len()];
    let mut skills = Vec::new();
    let mut noise_symbols = Vec::new();

    for index in 0..symbols.len() {
        if visited[index] {
            continue;
        }
        let mut stack = vec![index];
        let mut component_indexes = Vec::new();
        visited[index] = true;
        while let Some(current) = stack.pop() {
            component_indexes.push(current);
            for next in 0..symbols.len() {
                if visited[next] {
                    continue;
                }
                if shared_token_permille(&symbols[current].tokens, &symbols[next].tokens)
                    >= config.min_shared_token_permille
                {
                    visited[next] = true;
                    stack.push(next);
                }
            }
        }

        let mut members = component_indexes
            .iter()
            .map(|component_index| symbols[*component_index].symbol_id.clone())
            .collect::<Vec<_>>();
        members.sort();
        if members.len() < config.min_cluster_size as usize {
            noise_symbols.extend(members);
            continue;
        }

        let exemplar_tokens = exemplar_tokens(&symbols, &component_indexes);
        let membership_hash = membership_hash_for_members(&members);
        let skill_id = hex_lower(&astrolabe_domain::calyx::content_address([
            b"astrolabe-skill-v1".as_slice(),
            membership_hash.as_bytes(),
        ]));
        let name = format!("skill:{}", exemplar_tokens.join("-"));
        skills.push(SkillNode {
            skill_id,
            name,
            members,
            exemplar_tokens,
            membership_hash,
        });
    }

    skills.sort_by(|left, right| left.name.cmp(&right.name));
    noise_symbols.sort();
    let membership_hash = membership_hash_for_tree(&skills, &noise_symbols);
    Ok(SkillTree {
        schema: SKILL_TREE_SCHEMA,
        knob_registry_version: SKILL_DISCOVERY_KNOB_REGISTRY_VERSION,
        skills,
        noise_symbols,
        membership_hash,
        freshness: "fresh",
        trust: "verified",
    })
}

pub fn skill_tree_artifact_bytes(tree: &SkillTree) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(tree.schema);
    out.push('\n');
    out.push_str("knobs=");
    out.push_str(tree.knob_registry_version);
    out.push('\n');
    out.push_str("membership_hash=");
    out.push_str(&tree.membership_hash);
    out.push('\n');
    for skill in &tree.skills {
        out.push_str("skill\t");
        out.push_str(&skill.skill_id);
        out.push('\t');
        out.push_str(&skill.name);
        out.push('\t');
        out.push_str(&skill.membership_hash);
        out.push('\t');
        out.push_str(&skill.exemplar_tokens.join(","));
        out.push('\t');
        out.push_str(&skill.members.join(","));
        out.push('\n');
    }
    out.push_str("noise\t");
    out.push_str(&tree.noise_symbols.join(","));
    out.push('\n');
    out.into_bytes()
}

/// Filter `candidates` down to the members of the skill named by `skill_id`,
/// capped at `max_results`.
///
/// Fails closed rather than returning an empty result for two operator errors,
/// so a genuinely empty match is never confused with a misconfigured request:
/// - `max_results == 0` → [`ASTRO_SKILL_SEARCH_CAP_RANGE`].
/// - `skill_id` not present in `tree` (typo'd or stale id) →
///   [`ASTRO_SKILL_UNKNOWN_ID`]. An unknown skill is indistinguishable from
///   "no candidates matched" if it returns `Ok(vec![])`, so it is refused.
pub fn filter_results_within_skill(
    tree: &SkillTree,
    skill_id: &str,
    candidates: &[String],
    max_results: usize,
) -> astrolabe_domain::Result<Vec<String>> {
    if max_results == 0 {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_SKILL_SEARCH_CAP_RANGE,
            "skill-scoped search max_results must be greater than zero",
            "set max_results to a positive planner cap before filtering skill results",
        ));
    }
    let Some(skill) = tree.skills.iter().find(|skill| skill.skill_id == skill_id) else {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_SKILL_UNKNOWN_ID,
            format!("skill_id {skill_id} is not present in the skill tree"),
            "pass a skill_id returned by build_skill_tree; a stale or typo'd id is refused rather than returning silently empty results",
        ));
    };
    let members = skill.members.iter().collect::<BTreeSet<_>>();
    Ok(candidates
        .iter()
        .filter(|candidate| members.contains(candidate))
        .take(max_results)
        .cloned()
        .collect())
}

fn validate_skill_knob(
    name: &'static str,
    value: u64,
    registry: &[U64KnobDeclaration],
) -> astrolabe_domain::Result<()> {
    let knob = registry
        .iter()
        .find(|knob| knob.name == name)
        .expect("skill knob is declared");
    if value < knob.min || value > knob.max {
        return Err(astrolabe_domain::DomainError::new(
            ASTRO_SKILL_DISCOVERY_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set skill discovery knobs through the registered bounds",
        ));
    }
    Ok(())
}

fn shared_token_permille(left: &BTreeSet<String>, right: &BTreeSet<String>) -> u64 {
    let intersection = left.intersection(right).count() as u64;
    let union = left.union(right).count() as u64;
    (intersection * 1_000).checked_div(union).unwrap_or(0)
}

fn exemplar_tokens(symbols: &[SkillSymbolInput], component_indexes: &[usize]) -> Vec<String> {
    let mut counts = BTreeMap::<String, usize>::new();
    for index in component_indexes {
        for token in &symbols[*index].tokens {
            *counts.entry(token.clone()).or_default() += 1;
        }
    }
    let mut ranked = counts.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked.into_iter().take(2).map(|(token, _)| token).collect()
}

fn membership_hash_for_members(members: &[String]) -> String {
    let joined = members.join("\n");
    hex_lower(&astrolabe_domain::calyx::content_address([
        b"astrolabe-skill-members-v1".as_slice(),
        joined.as_bytes(),
    ]))
}

fn membership_hash_for_tree(skills: &[SkillNode], noise_symbols: &[String]) -> String {
    let mut canonical = String::new();
    for skill in skills {
        canonical.push_str(&skill.skill_id);
        canonical.push('\t');
        canonical.push_str(&skill.membership_hash);
        canonical.push('\n');
    }
    canonical.push_str("noise\t");
    canonical.push_str(&noise_symbols.join(","));
    hex_lower(&astrolabe_domain::calyx::content_address([
        b"astrolabe-skill-tree-v1".as_slice(),
        canonical.as_bytes(),
    ]))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
