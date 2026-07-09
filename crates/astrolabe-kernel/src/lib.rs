#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const SEARCH_SCALE_SCHEMA: &str = "astrolabe.search_scale_plan.v1";
pub const SEARCH_SCALE_KNOB_REGISTRY_VERSION: &str = "astro.kernel.search_scale_knobs.v1";
pub const SKILL_TREE_SCHEMA: &str = "astrolabe.skill_tree.v1";
pub const SKILL_DISCOVERY_KNOB_REGISTRY_VERSION: &str = "astro.kernel.skill_discovery_knobs.v1";
pub const BRIDGE_SCHEMA: &str = "astrolabe.bridge.v1";
pub const BRIDGE_CACHE_KEY_SCHEMA: &str = "astrolabe.bridge_cache_key.v1";
pub const FUNNEL_ACTIVATION_RECORDS_KNOB: &str = "search.funnel.activation_records";
pub const SKILL_MIN_CLUSTER_SIZE_KNOB: &str = "skills.min_cluster_size";
pub const SKILL_MIN_SHARED_TOKEN_PERMILLE_KNOB: &str = "skills.min_shared_token_permille";
pub const ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED: &str = "ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED";
pub const ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT: &str = "ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT";
pub const ASTRO_SKILL_DISCOVERY_KNOB_RANGE: &str = "ASTRO_SKILL_DISCOVERY_KNOB_RANGE";
pub const ASTRO_SKILL_SEARCH_CAP_RANGE: &str = "ASTRO_SKILL_SEARCH_CAP_RANGE";
pub const DEFAULT_FUNNEL_ACTIVATION_RECORDS: u64 = 10_000_000;
pub const MIN_FUNNEL_ACTIVATION_RECORDS: u64 = 1_000;
pub const MAX_FUNNEL_ACTIVATION_RECORDS: u64 = 1_000_000_000;
pub const DEFAULT_SKILL_MIN_CLUSTER_SIZE: u64 = 2;
pub const MIN_SKILL_MIN_CLUSTER_SIZE: u64 = 2;
pub const MAX_SKILL_MIN_CLUSTER_SIZE: u64 = 10_000;
pub const DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE: u64 = 500;
pub const MIN_SKILL_MIN_SHARED_TOKEN_PERMILLE: u64 = 1;
pub const MAX_SKILL_MIN_SHARED_TOKEN_PERMILLE: u64 = 1_000;

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
];

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
    let left_symbols = canonical_symbol_map(scope_a);
    let right_symbols = canonical_symbol_map(scope_b);
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

fn canonical_symbol_map(scope: &BridgeScopeKernel) -> BTreeMap<String, BridgeKernelSymbol> {
    let mut symbols = scope.symbols.clone();
    symbols.sort_by(|left, right| {
        left.symbol_id
            .cmp(&right.symbol_id)
            .then_with(|| left.qualified_name.cmp(&right.qualified_name))
            .then_with(|| left.provenance_ref.cmp(&right.provenance_ref))
    });
    let mut map = BTreeMap::new();
    for symbol in symbols {
        map.entry(symbol.symbol_id.clone()).or_insert(symbol);
    }
    map
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
    let symbols = canonical_symbol_map(scope);
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
}

impl Default for SkillDiscoveryConfig {
    fn default() -> Self {
        Self {
            min_cluster_size: DEFAULT_SKILL_MIN_CLUSTER_SIZE,
            min_shared_token_permille: DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE,
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
        return Ok(Vec::new());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn funnel_threshold_is_registry_declared_with_bounds() {
        let knob = SEARCH_SCALE_KNOBS
            .iter()
            .find(|knob| knob.name == FUNNEL_ACTIVATION_RECORDS_KNOB)
            .expect("funnel threshold knob");
        assert_eq!(knob.registry_version, SEARCH_SCALE_KNOB_REGISTRY_VERSION);
        assert_eq!(knob.default, DEFAULT_FUNNEL_ACTIVATION_RECORDS);
        assert_eq!(knob.default, 10_000_000);
        assert!(knob.min < knob.default);
        assert!(knob.default < knob.max);
        assert_eq!(knob.unit, "records");
    }

    #[test]
    fn funnel_activation_is_labeled_and_uses_strict_threshold() {
        let direct = plan_search_scale(&SearchScaleConfig::with_registry_defaults(
            DEFAULT_FUNNEL_ACTIVATION_RECORDS,
            1024,
            2048,
        ))
        .expect("direct plan");
        assert_eq!(direct.funnel_mode, SearchFunnelMode::Direct);
        assert!(direct.activation_label.contains("funnel=direct"));
        assert!(
            direct
                .activation_label
                .contains(FUNNEL_ACTIVATION_RECORDS_KNOB)
        );
        assert_eq!(direct.trust, "verified");

        let funnel = plan_search_scale(&SearchScaleConfig::with_registry_defaults(
            DEFAULT_FUNNEL_ACTIVATION_RECORDS + 1,
            1024,
            2048,
        ))
        .expect("funnel plan");
        assert_eq!(funnel.funnel_mode, SearchFunnelMode::KernelFirst);
        assert!(funnel.activation_label.contains("funnel=kernel_first"));
        assert!(funnel.activation_label.contains("total_records=10000001"));
    }

    #[test]
    fn disk_backends_round_trip_through_config_strings() {
        for backend in [
            SearchIndexBackend::InMemoryHnsw,
            SearchIndexBackend::DiskAnn,
            SearchIndexBackend::Spann,
        ] {
            assert_eq!(backend.as_str().parse::<SearchIndexBackend>(), Ok(backend));
        }
        assert!("flat_scan".parse::<SearchIndexBackend>().is_err());

        let mut config = SearchScaleConfig::with_registry_defaults(20_000_000, 1024, 2048);
        config.index_backend = "diskann".parse().expect("parse diskann");
        let plan = plan_search_scale(&config).expect("diskann plan");
        assert_eq!(plan.index_backend, SearchIndexBackend::DiskAnn);
        assert!(plan.index_backend_label.contains("operator opt-in"));
    }

    #[test]
    fn over_budget_index_load_fails_closed_before_allocation() {
        let err = plan_search_scale(&SearchScaleConfig::with_registry_defaults(1, 4096, 1024))
            .expect_err("over budget index load refused");
        assert_eq!(err.code(), ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED);
        assert!(err.message().contains("exceeds master budget"));
        assert!(err.remediation().contains("enable diskann/spann"));
    }

    #[test]
    fn out_of_range_knob_is_refused_with_remediation() {
        let mut config = SearchScaleConfig::with_registry_defaults(1, 1024, 2048);
        config.funnel_activation_records = MIN_FUNNEL_ACTIVATION_RECORDS - 1;
        let err = plan_search_scale(&config).expect_err("invalid threshold refused");
        assert_eq!(err.code(), "ASTRO_SEARCH_SCALE_KNOB_RANGE");
        assert!(err.message().contains(FUNNEL_ACTIVATION_RECORDS_KNOB));
        assert!(err.remediation().contains("registered knob bounds"));
    }

    #[test]
    fn planted_bridge_golden_returns_exact_connectors_ranked() {
        let (frontend, backend) = bridge_fixture_scopes();
        let report = bridge_symbols(&frontend, &backend);

        assert_eq!(report.schema, BRIDGE_SCHEMA);
        assert_eq!(report.scope_a, "frontend");
        assert_eq!(report.scope_b, "backend");
        assert_eq!(report.trust, "verified");
        assert_eq!(
            report
                .bridges
                .iter()
                .map(|bridge| bridge.symbol_id.as_str())
                .collect::<Vec<_>>(),
            vec!["shared.audit", "shared.session"]
        );
        assert_eq!(report.bridges[0].combined_kernel_weight, 190);
        assert_eq!(report.bridges[1].combined_kernel_weight, 90);
        assert_eq!(report.bridges[0].provenance.scope_a, "ledger:frontend:2");
        assert_eq!(report.bridges[0].provenance.scope_b, "ledger:backend:5");
    }

    #[test]
    fn ungrounded_scope_marks_bridge_results_provisional() {
        let (frontend, mut backend) = bridge_fixture_scopes();
        backend.grounded = false;
        let report = bridge_symbols(&frontend, &backend);

        assert_eq!(report.trust, "provisional");
        assert!(
            report
                .bridges
                .iter()
                .all(|bridge| bridge.trust == "provisional")
        );
    }

    #[test]
    fn cross_repo_bridge_chain_resolves_with_hop_provenance() {
        let frontend = BridgeScopeKernel::new(
            "repo:frontend",
            "frontend-vault",
            "front-dirty",
            true,
            vec![BridgeKernelSymbol::new(
                "route.checkout",
                "frontend.routes.checkout",
                77,
                "ledger:front:3",
            )],
        );
        let checkout = BridgeScopeKernel::new(
            "repo:checkout",
            "checkout-vault",
            "checkout-dirty",
            true,
            vec![BridgeKernelSymbol::new(
                "handler.checkout",
                "checkout.handlers.checkout",
                81,
                "ledger:checkout:8",
            )],
        );
        let edges = vec![CrossVaultEdge::new(
            "frontend-vault",
            "route.checkout",
            "checkout-vault",
            "handler.checkout",
            "CROSS_HTTP_CALLS",
            "ledger:cross:13",
        )];

        let chains = resolve_cross_vault_bridge_chains(&frontend, &checkout, &edges)
            .expect("cross-vault bridge chains");

        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].from_scope, "repo:frontend");
        assert_eq!(chains[0].to_scope, "repo:checkout");
        assert_eq!(chains[0].from_symbol_id, "route.checkout");
        assert_eq!(chains[0].to_symbol_id, "handler.checkout");
        assert_eq!(chains[0].hops[0].edge_kind, "CROSS_HTTP_CALLS");
        assert_eq!(chains[0].hops[0].provenance_ref, "ledger:cross:13");
        assert_eq!(chains[0].trust, "verified");
    }

    #[test]
    fn cross_repo_missing_counterpart_vault_fails_closed() {
        let frontend = BridgeScopeKernel::new(
            "repo:frontend",
            "frontend-vault",
            "front-dirty",
            true,
            vec![BridgeKernelSymbol::new(
                "route.checkout",
                "frontend.routes.checkout",
                77,
                "ledger:front:3",
            )],
        );
        let checkout = BridgeScopeKernel::new(
            "repo:checkout",
            "checkout-vault",
            "checkout-dirty",
            true,
            vec![BridgeKernelSymbol::new(
                "handler.checkout",
                "checkout.handlers.checkout",
                81,
                "ledger:checkout:8",
            )],
        );
        let edges = vec![CrossVaultEdge::new(
            "frontend-vault",
            "route.checkout",
            "missing-vault",
            "handler.checkout",
            "CROSS_HTTP_CALLS",
            "ledger:cross:13",
        )];

        let err = resolve_cross_vault_bridge_chains(&frontend, &checkout, &edges)
            .expect_err("missing counterpart vault refused");

        assert_eq!(err.code(), ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT);
        assert!(err.message().contains("missing-vault"));
        assert!(err.remediation().contains("counterpart vault"));
    }

    #[test]
    fn boundary_diff_flags_forbidden_declared_bridge() {
        let (frontend, backend) = bridge_fixture_scopes();
        let report = bridge_symbols(&frontend, &backend);
        let diff = diff_declared_bridge_boundaries(
            &report,
            &[DeclaredBridgeBoundary::new(
                "frontend",
                "backend",
                false,
                "architecture:layering:1",
            )],
        );

        assert_eq!(diff.schema, BRIDGE_SCHEMA);
        assert_eq!(diff.violations.len(), 2);
        assert_eq!(diff.violations[0].symbol_id, "shared.audit");
        assert_eq!(
            diff.violations[0].declared_provenance_ref,
            "architecture:layering:1"
        );
        assert_eq!(
            diff.violations[0].measured_scope_a_provenance_ref,
            "ledger:frontend:2"
        );
        assert_eq!(
            diff.violations[0].measured_scope_b_provenance_ref,
            "ledger:backend:5"
        );
    }

    #[test]
    fn bridge_cache_key_is_symmetric_and_invalidates_on_dirty_region() {
        let (frontend, mut backend) = bridge_fixture_scopes();
        assert_eq!(
            bridge_cache_key(&frontend, &backend),
            bridge_cache_key(&backend, &frontend)
        );

        let original = bridge_cache_key(&frontend, &backend);
        backend.dirty_region_hash = "backend-dirty-v2".to_string();
        assert_ne!(original, bridge_cache_key(&frontend, &backend));
    }

    #[test]
    fn bridge_report_artifact_bytes_read_back_from_disk() {
        let (frontend, backend) = bridge_fixture_scopes();
        let report = bridge_symbols(&frontend, &backend);
        let bytes = bridge_report_artifact_bytes(&report);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-bridge-report-{}-{}.txt",
            std::process::id(),
            report.cache_key
        ));
        std::fs::write(&path, &bytes).expect("write bridge artifact");
        let readback = std::fs::read(&path).expect("read bridge artifact");
        std::fs::remove_file(&path).ok();

        assert_eq!(readback, bytes);
        assert!(
            String::from_utf8(readback)
                .expect("utf8 bridge artifact")
                .contains("bridge\tshared.audit")
        );
    }

    #[test]
    fn skill_discovery_knobs_are_registry_declared() {
        let min_size = SKILL_DISCOVERY_KNOBS
            .iter()
            .find(|knob| knob.name == SKILL_MIN_CLUSTER_SIZE_KNOB)
            .expect("min cluster size knob");
        assert_eq!(
            min_size.registry_version,
            SKILL_DISCOVERY_KNOB_REGISTRY_VERSION
        );
        assert_eq!(min_size.default, DEFAULT_SKILL_MIN_CLUSTER_SIZE);
        assert_eq!(min_size.unit, "symbols");

        let overlap = SKILL_DISCOVERY_KNOBS
            .iter()
            .find(|knob| knob.name == SKILL_MIN_SHARED_TOKEN_PERMILLE_KNOB)
            .expect("shared token knob");
        assert_eq!(
            overlap.registry_version,
            SKILL_DISCOVERY_KNOB_REGISTRY_VERSION
        );
        assert_eq!(overlap.default, DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE);
        assert_eq!(overlap.unit, "permille");
    }

    #[test]
    fn planted_skill_clusters_are_recovered_and_noise_stays_out() {
        let tree = build_skill_tree(&skill_fixture(), &SkillDiscoveryConfig::default())
            .expect("build skill tree");
        assert_eq!(tree.schema, SKILL_TREE_SCHEMA);
        assert_eq!(tree.skills.len(), 2);
        assert_eq!(tree.noise_symbols, vec!["health.ping"]);

        let auth = tree
            .skills
            .iter()
            .find(|skill| skill.name == "skill:auth-user")
            .expect("auth skill");
        assert_eq!(
            auth.members,
            vec!["auth.issue_token", "auth.login", "auth.logout"]
        );
        assert!(auth.membership_hash.len() == 32);

        let billing = tree
            .skills
            .iter()
            .find(|skill| skill.name == "skill:billing-payment")
            .expect("billing skill");
        assert_eq!(
            billing.members,
            vec!["billing.charge", "billing.invoice", "billing.refund"]
        );
    }

    #[test]
    fn skill_tree_artifact_is_deterministic_across_input_order() {
        let mut reversed = skill_fixture();
        reversed.reverse();
        let first = build_skill_tree(&skill_fixture(), &SkillDiscoveryConfig::default())
            .expect("first skill tree");
        let second = build_skill_tree(&reversed, &SkillDiscoveryConfig::default())
            .expect("second skill tree");
        assert_eq!(first, second);
        assert_eq!(
            skill_tree_artifact_bytes(&first),
            skill_tree_artifact_bytes(&second)
        );
    }

    #[test]
    fn skill_scoped_filter_returns_only_members_and_respects_cap() {
        let tree = build_skill_tree(&skill_fixture(), &SkillDiscoveryConfig::default())
            .expect("build skill tree");
        let auth = tree
            .skills
            .iter()
            .find(|skill| skill.name == "skill:auth-user")
            .expect("auth skill");
        let candidates = vec![
            "billing.charge".to_string(),
            "auth.logout".to_string(),
            "auth.login".to_string(),
        ];
        let scoped = filter_results_within_skill(&tree, &auth.skill_id, &candidates, 1)
            .expect("skill scoped filter");
        assert_eq!(scoped, vec!["auth.logout"]);

        let err = filter_results_within_skill(&tree, &auth.skill_id, &candidates, 0)
            .expect_err("zero cap refused");
        assert_eq!(err.code(), ASTRO_SKILL_SEARCH_CAP_RANGE);
    }

    #[test]
    fn skill_tree_artifact_bytes_read_back_from_disk() {
        let tree = build_skill_tree(&skill_fixture(), &SkillDiscoveryConfig::default())
            .expect("build skill tree");
        let bytes = skill_tree_artifact_bytes(&tree);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-skill-tree-{}-{}.txt",
            std::process::id(),
            tree.membership_hash
        ));
        std::fs::write(&path, &bytes).expect("write skill artifact");
        let readback = std::fs::read(&path).expect("read skill artifact");
        std::fs::remove_file(&path).ok();
        assert_eq!(readback, bytes);
        assert!(
            String::from_utf8(readback)
                .expect("utf8 artifact")
                .contains("skill:auth-user")
        );
    }

    #[test]
    fn skill_discovery_knob_range_is_fail_closed() {
        let config = SkillDiscoveryConfig {
            min_cluster_size: 1,
            min_shared_token_permille: DEFAULT_SKILL_MIN_SHARED_TOKEN_PERMILLE,
        };
        let err = build_skill_tree(&skill_fixture(), &config).expect_err("invalid knob refused");
        assert_eq!(err.code(), ASTRO_SKILL_DISCOVERY_KNOB_RANGE);
        assert!(err.message().contains(SKILL_MIN_CLUSTER_SIZE_KNOB));
        assert!(err.remediation().contains("registered bounds"));
    }

    fn bridge_fixture_scopes() -> (BridgeScopeKernel, BridgeScopeKernel) {
        let frontend = BridgeScopeKernel::new(
            "frontend",
            "app-vault",
            "frontend-dirty-v1",
            true,
            vec![
                BridgeKernelSymbol::new(
                    "frontend.form",
                    "demo.frontend.form",
                    70,
                    "ledger:frontend:1",
                ),
                BridgeKernelSymbol::new(
                    "shared.audit",
                    "demo.shared.audit",
                    90,
                    "ledger:frontend:2",
                ),
                BridgeKernelSymbol::new(
                    "shared.session",
                    "demo.shared.session",
                    70,
                    "ledger:frontend:3",
                ),
            ],
        );
        let backend = BridgeScopeKernel::new(
            "backend",
            "app-vault",
            "backend-dirty-v1",
            true,
            vec![
                BridgeKernelSymbol::new(
                    "backend.handler",
                    "demo.backend.handler",
                    95,
                    "ledger:backend:4",
                ),
                BridgeKernelSymbol::new(
                    "shared.audit",
                    "demo.shared.audit",
                    100,
                    "ledger:backend:5",
                ),
                BridgeKernelSymbol::new(
                    "shared.session",
                    "demo.shared.session",
                    20,
                    "ledger:backend:6",
                ),
            ],
        );
        (frontend, backend)
    }

    fn skill_fixture() -> Vec<SkillSymbolInput> {
        vec![
            SkillSymbolInput::new(
                "auth.login",
                "demo.auth.login",
                "src/auth/login.rs",
                ["auth", "user", "login"],
            ),
            SkillSymbolInput::new(
                "auth.logout",
                "demo.auth.logout",
                "src/auth/logout.rs",
                ["auth", "user", "session"],
            ),
            SkillSymbolInput::new(
                "auth.issue_token",
                "demo.auth.issue_token",
                "src/auth/token.rs",
                ["auth", "user", "token"],
            ),
            SkillSymbolInput::new(
                "billing.charge",
                "demo.billing.charge",
                "src/billing/charge.rs",
                ["billing", "payment", "card"],
            ),
            SkillSymbolInput::new(
                "billing.refund",
                "demo.billing.refund",
                "src/billing/refund.rs",
                ["billing", "payment", "refund"],
            ),
            SkillSymbolInput::new(
                "billing.invoice",
                "demo.billing.invoice",
                "src/billing/invoice.rs",
                ["billing", "payment", "invoice"],
            ),
            SkillSymbolInput::new(
                "health.ping",
                "demo.health.ping",
                "src/health.rs",
                ["health", "ping", "status"],
            ),
        ]
    }
}
