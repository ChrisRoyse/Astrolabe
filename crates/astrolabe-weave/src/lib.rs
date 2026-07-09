#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use astrolabe_domain::EdgeKind;
use calyx_core::{SlotId, SlotVector, SparseEntry};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

pub const SIM_STRUCT_SLOT: SlotId = SlotId::new(1);
pub const SIM_API_SLOT: SlotId = SlotId::new(4);
pub const SIM_SEMANTIC_SLOT: SlotId = SlotId::new(18);
pub const SIM_PROFILE_SLOT: SlotId = SlotId::new(21);

pub const DEFAULT_SIM_STRUCT_MIN_SCORE: f32 = 0.95;
pub const DEFAULT_SIM_SEMANTIC_MIN_SCORE: f32 = 0.80;
pub const DEFAULT_SIM_API_MIN_SCORE: f32 = 0.80;
pub const DEFAULT_SIM_PROFILE_MIN_SCORE: f32 = 0.80;
pub const DEFAULT_SIMILARITY_PER_NODE_CAP: usize = 10;
pub const DEFAULT_SIMILARITY_WORKERS: usize = 1;
pub const DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT: usize = 50_000;
pub const PANEL_SLOT_COUNT_FOR_ABUNDANCE: usize = 22;
pub const PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE: usize =
    PANEL_SLOT_COUNT_FOR_ABUNDANCE * (PANEL_SLOT_COUNT_FOR_ABUNDANCE - 1) / 2;

pub const SLOT_COMPLEXITY: SlotId = SlotId::new(2);
pub const SLOT_GRAPH_POSITION: SlotId = SlotId::new(8);
pub const SLOT_CHURN: SlotId = SlotId::new(10);
pub const SLOT_TEST_COVERAGE: SlotId = SlotId::new(14);
pub const SLOT_ROUTE_MATCH: SlotId = SlotId::new(17);
pub const SLOT_DOC_SEMANTIC: SlotId = SlotId::new(19);
pub const SLOT_NAME_SEMANTIC: SlotId = SlotId::new(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimilarityFamily {
    Struct,
    Semantic,
    Api,
    Profile,
}

impl SimilarityFamily {
    pub const ALL: [Self; 4] = [Self::Struct, Self::Semantic, Self::Api, Self::Profile];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Struct => "SIM_STRUCT",
            Self::Semantic => "SIM_SEMANTIC",
            Self::Api => "SIM_API",
            Self::Profile => "SIM_PROFILE",
        }
    }

    pub const fn slot(self) -> SlotId {
        match self {
            Self::Struct => SIM_STRUCT_SLOT,
            Self::Semantic => SIM_SEMANTIC_SLOT,
            Self::Api => SIM_API_SLOT,
            Self::Profile => SIM_PROFILE_SLOT,
        }
    }

    pub const fn graph_edge_kind(self) -> EdgeKind {
        match self {
            Self::Semantic => EdgeKind::SemanticallyRelated,
            Self::Struct | Self::Api | Self::Profile => EdgeKind::SimilarTo,
        }
    }

    pub const fn threshold_field(self) -> &'static str {
        match self {
            Self::Struct => "sim_struct_min_score",
            Self::Semantic => "sim_semantic_min_score",
            Self::Api => "sim_api_min_score",
            Self::Profile => "sim_profile_min_score",
        }
    }

    const fn sort_index(self) -> u8 {
        match self {
            Self::Struct => 0,
            Self::Semantic => 1,
            Self::Api => 2,
            Self::Profile => 3,
        }
    }
}

impl fmt::Display for SimilarityFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityThresholds {
    pub sim_struct_min_score: f32,
    pub sim_semantic_min_score: f32,
    pub sim_api_min_score: f32,
    pub sim_profile_min_score: f32,
}

impl SimilarityThresholds {
    pub fn threshold(&self, family: SimilarityFamily) -> f32 {
        match family {
            SimilarityFamily::Struct => self.sim_struct_min_score,
            SimilarityFamily::Semantic => self.sim_semantic_min_score,
            SimilarityFamily::Api => self.sim_api_min_score,
            SimilarityFamily::Profile => self.sim_profile_min_score,
        }
    }
}

impl Default for SimilarityThresholds {
    fn default() -> Self {
        Self {
            sim_struct_min_score: DEFAULT_SIM_STRUCT_MIN_SCORE,
            sim_semantic_min_score: DEFAULT_SIM_SEMANTIC_MIN_SCORE,
            sim_api_min_score: DEFAULT_SIM_API_MIN_SCORE,
            sim_profile_min_score: DEFAULT_SIM_PROFILE_MIN_SCORE,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityPlannerConfig {
    pub thresholds: SimilarityThresholds,
    pub per_node_cap: usize,
    pub worker_count: usize,
    pub disabled_families: BTreeSet<SimilarityFamily>,
    pub exact_pair_node_limit: Option<usize>,
}

impl SimilarityPlannerConfig {
    pub fn with_disabled_family(mut self, family: SimilarityFamily) -> Self {
        self.disabled_families.insert(family);
        self
    }

    pub fn with_exact_pair_node_limit(mut self, limit: Option<usize>) -> Self {
        self.exact_pair_node_limit = limit;
        self
    }
}

impl Default for SimilarityPlannerConfig {
    fn default() -> Self {
        Self {
            thresholds: SimilarityThresholds::default(),
            per_node_cap: DEFAULT_SIMILARITY_PER_NODE_CAP,
            worker_count: DEFAULT_SIMILARITY_WORKERS,
            disabled_families: BTreeSet::new(),
            exact_pair_node_limit: Some(DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityNode {
    pub qualified_name: String,
    pub slots: BTreeMap<SlotId, SlotVector>,
}

impl SimilarityNode {
    pub fn new(qualified_name: impl Into<String>) -> Self {
        Self {
            qualified_name: qualified_name.into(),
            slots: BTreeMap::new(),
        }
    }

    pub fn with_slot(mut self, slot: SlotId, vector: SlotVector) -> Self {
        self.slots.insert(slot, vector);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityMetric {
    Cosine,
}

impl SimilarityMetric {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cosine => "cosine",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityEdge {
    pub family: SimilarityFamily,
    pub source_qn: String,
    pub target_qn: String,
    pub slot: SlotId,
    pub graph_edge_kind: EdgeKind,
    pub metric: SimilarityMetric,
    pub weight: f32,
    pub threshold: f32,
}

impl SimilarityEdge {
    pub fn graph_properties(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("family".to_string(), self.family.wire_name().to_string()),
            ("metric".to_string(), self.metric.as_str().to_string()),
            ("slot_id".to_string(), self.slot.get().to_string()),
            ("score".to_string(), format_score(self.weight)),
            ("threshold".to_string(), format_score(self.threshold)),
        ])
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityPlan {
    pub edges: Vec<SimilarityEdge>,
    pub skips: SimilaritySkipReport,
    pub workers_requested: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimilaritySkipReport {
    pub vector_skips: Vec<SimilarityVectorSkip>,
    pub family_opt_outs: Vec<SimilarityFamilyOptOut>,
    pub pair_counts: BTreeMap<SimilarityFamily, SimilarityPairCounts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityVectorSkip {
    pub family: SimilarityFamily,
    pub qualified_name: String,
    pub reason: SimilarityVectorSkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimilarityVectorSkipReason {
    MissingSlot,
    AbsentSlot,
    UnsupportedSlotShape { shape: &'static str },
    ZeroNorm,
    InvalidSchema { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityFamilyOptOut {
    pub family: SimilarityFamily,
    pub slot: SlotId,
    pub reason: SimilarityFamilyOptOutReason,
    pub node_count: usize,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityFamilyOptOutReason {
    DisabledByConfig,
    ExactCandidateLimitExceeded,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimilarityPairCounts {
    pub candidate_pairs: usize,
    pub incompatible_shape_pairs: usize,
    pub below_threshold_pairs: usize,
    pub cap_dropped_pairs: usize,
    pub admitted_pairs: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SimilarityPlanError {
    EmptyQualifiedName { node_index: usize },
    DuplicateQualifiedName { qualified_name: String },
    InvalidPerNodeCap { value: usize },
    InvalidWorkerCount { value: usize },
    InvalidThreshold { field: &'static str, value: f32 },
}

impl fmt::Display for SimilarityPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQualifiedName { node_index } => {
                write!(
                    f,
                    "similarity node {node_index} has an empty qualified name"
                )
            }
            Self::DuplicateQualifiedName { qualified_name } => {
                write!(
                    f,
                    "duplicate similarity node qualified name {qualified_name:?}"
                )
            }
            Self::InvalidPerNodeCap { value } => {
                write!(
                    f,
                    "similarity per_node_cap must be greater than zero, got {value}"
                )
            }
            Self::InvalidWorkerCount { value } => {
                write!(
                    f,
                    "similarity worker_count must be greater than zero, got {value}"
                )
            }
            Self::InvalidThreshold { field, value } => {
                write!(
                    f,
                    "similarity threshold {field} must be finite and in [0, 1], got {value}"
                )
            }
        }
    }
}

impl Error for SimilarityPlanError {}

pub fn plan_similarity_edges(
    nodes: &[SimilarityNode],
    config: &SimilarityPlannerConfig,
) -> Result<SimilarityPlan, SimilarityPlanError> {
    validate_plan_request(nodes, config)?;
    let mut edges = Vec::new();
    let mut skips = SimilaritySkipReport::default();

    for family in SimilarityFamily::ALL {
        if config.disabled_families.contains(&family) {
            skips.family_opt_outs.push(SimilarityFamilyOptOut {
                family,
                slot: family.slot(),
                reason: SimilarityFamilyOptOutReason::DisabledByConfig,
                node_count: 0,
                limit: None,
            });
            continue;
        }

        let vectors = collect_family_vectors(nodes, family, &mut skips);
        if let Some(limit) = config.exact_pair_node_limit
            && vectors.len() > limit
        {
            skips.family_opt_outs.push(SimilarityFamilyOptOut {
                family,
                slot: family.slot(),
                reason: SimilarityFamilyOptOutReason::ExactCandidateLimitExceeded,
                node_count: vectors.len(),
                limit: Some(limit),
            });
            continue;
        }

        let threshold = config.thresholds.threshold(family);
        let (family_edges, pair_counts) =
            plan_family_edges(family, threshold, config.per_node_cap, &vectors);
        skips.pair_counts.insert(family, pair_counts);
        edges.extend(family_edges);
    }

    edges.sort_by(stable_edge_order);
    Ok(SimilarityPlan {
        edges,
        skips,
        workers_requested: config.worker_count,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EagerAgreementKind {
    DocDrift,
    NameTruth,
    CloneTaxonomy,
    ComplexityChurn,
    CentralityCoverage,
    RouteMatch,
}

impl EagerAgreementKind {
    pub const ALL: [Self; 6] = [
        Self::DocDrift,
        Self::NameTruth,
        Self::CloneTaxonomy,
        Self::ComplexityChurn,
        Self::CentralityCoverage,
        Self::RouteMatch,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DocDrift => "DOC_DRIFT",
            Self::NameTruth => "NAME_TRUTH",
            Self::CloneTaxonomy => "CLONE_TAXONOMY",
            Self::ComplexityChurn => "COMPLEXITY_CHURN",
            Self::CentralityCoverage => "CENTRALITY_COVERAGE",
            Self::RouteMatch => "ROUTE_MATCH",
        }
    }

    pub const fn slots(self) -> (SlotId, SlotId) {
        match self {
            Self::DocDrift => (SLOT_DOC_SEMANTIC, SIM_SEMANTIC_SLOT),
            Self::NameTruth => (SLOT_NAME_SEMANTIC, SIM_API_SLOT),
            Self::CloneTaxonomy => (SIM_SEMANTIC_SLOT, SIM_STRUCT_SLOT),
            Self::ComplexityChurn => (SLOT_COMPLEXITY, SLOT_CHURN),
            Self::CentralityCoverage => (SLOT_GRAPH_POSITION, SLOT_TEST_COVERAGE),
            Self::RouteMatch => (SIM_SEMANTIC_SLOT, SLOT_ROUTE_MATCH),
        }
    }
}

impl fmt::Display for EagerAgreementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EagerCrossTermPlan {
    pub rows: Vec<EagerCrossTermRow>,
    pub agreement_graph: Vec<AgreementGraphEdge>,
    pub abundance: CrossTermAbundance,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EagerCrossTermRow {
    pub qualified_name: String,
    pub kind: EagerAgreementKind,
    pub left_slot: SlotId,
    pub right_slot: SlotId,
    pub value: CrossTermValue,
    pub persisted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrossTermValue {
    Scalar(f32),
    Absent { reason: CrossTermAbsentReason },
}

impl CrossTermValue {
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossTermAbsentReason {
    MissingSlot { slot: SlotId },
    SlotAbsent { slot: SlotId },
    UnsupportedSlotShape { slot: SlotId, shape: &'static str },
    ZeroNorm { slot: SlotId },
    InvalidSchema { slot: SlotId, message: String },
    ShapeMismatch,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgreementGraphEdge {
    pub kind: EagerAgreementKind,
    pub left_slot: SlotId,
    pub right_slot: SlotId,
    pub mean_agreement: Option<f32>,
    pub scalar_count: usize,
    pub absent_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossTermAbundance {
    pub symbol_count: usize,
    pub panel_slot_count: usize,
    pub possible_pair_count_per_symbol: usize,
    pub raw_yield: usize,
    pub eager_pair_count_per_symbol: usize,
    pub materialized_count: usize,
    pub scalar_count: usize,
    pub absent_count: usize,
    pub lazy_pair_count: usize,
}

pub fn plan_eager_cross_terms(nodes: &[SimilarityNode]) -> EagerCrossTermPlan {
    let mut rows = Vec::with_capacity(nodes.len() * EagerAgreementKind::ALL.len());
    for node in nodes {
        for kind in EagerAgreementKind::ALL {
            let (left_slot, right_slot) = kind.slots();
            rows.push(EagerCrossTermRow {
                qualified_name: node.qualified_name.clone(),
                kind,
                left_slot,
                right_slot,
                value: cross_term_value(node, left_slot, right_slot),
                persisted: true,
            });
        }
    }
    rows.sort_by(cross_term_row_order);

    let agreement_graph = agreement_graph_from_cross_terms(&rows);
    let scalar_count = rows
        .iter()
        .filter(|row| matches!(row.value, CrossTermValue::Scalar(_)))
        .count();
    let absent_count = rows.len() - scalar_count;
    let symbol_count = nodes.len();
    EagerCrossTermPlan {
        rows,
        agreement_graph,
        abundance: CrossTermAbundance {
            symbol_count,
            panel_slot_count: PANEL_SLOT_COUNT_FOR_ABUNDANCE,
            possible_pair_count_per_symbol: PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE,
            raw_yield: symbol_count
                * (PANEL_SLOT_COUNT_FOR_ABUNDANCE + PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE + 1),
            eager_pair_count_per_symbol: EagerAgreementKind::ALL.len(),
            materialized_count: symbol_count * EagerAgreementKind::ALL.len(),
            scalar_count,
            absent_count,
            lazy_pair_count: symbol_count
                * (PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE - EagerAgreementKind::ALL.len()),
        },
    }
}

fn cross_term_value(
    node: &SimilarityNode,
    left_slot: SlotId,
    right_slot: SlotId,
) -> CrossTermValue {
    let left = match cross_term_operand(node, left_slot) {
        Ok(value) => value,
        Err(reason) => return CrossTermValue::Absent { reason },
    };
    let right = match cross_term_operand(node, right_slot) {
        Ok(value) => value,
        Err(reason) => return CrossTermValue::Absent { reason },
    };
    match cosine(&left, &right) {
        Some(value) => CrossTermValue::Scalar(value),
        None => CrossTermValue::Absent {
            reason: CrossTermAbsentReason::ShapeMismatch,
        },
    }
}

fn cross_term_operand(
    node: &SimilarityNode,
    slot: SlotId,
) -> Result<NormalizedVector, CrossTermAbsentReason> {
    let Some(vector) = node.slots.get(&slot) else {
        return Err(CrossTermAbsentReason::MissingSlot { slot });
    };
    match normalized_vector(vector) {
        Ok(Some(vector)) => Ok(vector),
        Ok(None) => Err(CrossTermAbsentReason::UnsupportedSlotShape {
            slot,
            shape: "empty",
        }),
        Err(reason) => Err(cross_term_absent_reason(slot, reason)),
    }
}

fn cross_term_absent_reason(
    slot: SlotId,
    reason: SimilarityVectorSkipReason,
) -> CrossTermAbsentReason {
    match reason {
        SimilarityVectorSkipReason::MissingSlot => CrossTermAbsentReason::MissingSlot { slot },
        SimilarityVectorSkipReason::AbsentSlot => CrossTermAbsentReason::SlotAbsent { slot },
        SimilarityVectorSkipReason::UnsupportedSlotShape { shape } => {
            CrossTermAbsentReason::UnsupportedSlotShape { slot, shape }
        }
        SimilarityVectorSkipReason::ZeroNorm => CrossTermAbsentReason::ZeroNorm { slot },
        SimilarityVectorSkipReason::InvalidSchema { message } => {
            CrossTermAbsentReason::InvalidSchema { slot, message }
        }
    }
}

fn cross_term_row_order(left: &EagerCrossTermRow, right: &EagerCrossTermRow) -> Ordering {
    left.qualified_name
        .cmp(&right.qualified_name)
        .then_with(|| left.kind.cmp(&right.kind))
}

fn agreement_graph_from_cross_terms(rows: &[EagerCrossTermRow]) -> Vec<AgreementGraphEdge> {
    let mut sums = BTreeMap::<EagerAgreementKind, (f32, usize, usize)>::new();
    for row in rows {
        let entry = sums.entry(row.kind).or_default();
        match row.value {
            CrossTermValue::Scalar(value) => {
                entry.0 += value;
                entry.1 += 1;
            }
            CrossTermValue::Absent { .. } => entry.2 += 1,
        }
    }

    EagerAgreementKind::ALL
        .into_iter()
        .map(|kind| {
            let (sum, scalar_count, absent_count) = sums.get(&kind).copied().unwrap_or_default();
            let (left_slot, right_slot) = kind.slots();
            AgreementGraphEdge {
                kind,
                left_slot,
                right_slot,
                mean_agreement: (scalar_count > 0).then_some(sum / scalar_count as f32),
                scalar_count,
                absent_count,
            }
        })
        .collect()
}

fn validate_plan_request(
    nodes: &[SimilarityNode],
    config: &SimilarityPlannerConfig,
) -> Result<(), SimilarityPlanError> {
    if config.per_node_cap == 0 {
        return Err(SimilarityPlanError::InvalidPerNodeCap {
            value: config.per_node_cap,
        });
    }
    if config.worker_count == 0 {
        return Err(SimilarityPlanError::InvalidWorkerCount {
            value: config.worker_count,
        });
    }
    for family in SimilarityFamily::ALL {
        let value = config.thresholds.threshold(family);
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(SimilarityPlanError::InvalidThreshold {
                field: family.threshold_field(),
                value,
            });
        }
    }

    let mut seen = BTreeSet::new();
    for (node_index, node) in nodes.iter().enumerate() {
        if node.qualified_name.trim().is_empty() {
            return Err(SimilarityPlanError::EmptyQualifiedName { node_index });
        }
        if !seen.insert(node.qualified_name.clone()) {
            return Err(SimilarityPlanError::DuplicateQualifiedName {
                qualified_name: node.qualified_name.clone(),
            });
        }
    }
    Ok(())
}

fn collect_family_vectors(
    nodes: &[SimilarityNode],
    family: SimilarityFamily,
    skips: &mut SimilaritySkipReport,
) -> Vec<IndexedVector> {
    let mut out = Vec::new();
    let slot = family.slot();
    for node in nodes {
        let Some(vector) = node.slots.get(&slot) else {
            skips.vector_skips.push(SimilarityVectorSkip {
                family,
                qualified_name: node.qualified_name.clone(),
                reason: SimilarityVectorSkipReason::MissingSlot,
            });
            continue;
        };
        match normalized_vector(vector) {
            Ok(Some(vector)) => out.push(IndexedVector {
                qualified_name: node.qualified_name.clone(),
                vector,
            }),
            Ok(None) => {}
            Err(reason) => skips.vector_skips.push(SimilarityVectorSkip {
                family,
                qualified_name: node.qualified_name.clone(),
                reason,
            }),
        }
    }
    out.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    out
}

fn normalized_vector(
    vector: &SlotVector,
) -> Result<Option<NormalizedVector>, SimilarityVectorSkipReason> {
    if let Err(error) = vector.validate_schema() {
        return Err(SimilarityVectorSkipReason::InvalidSchema {
            message: error.to_string(),
        });
    }

    match vector {
        SlotVector::Dense { dim, data } => {
            let norm = dense_norm(data);
            if zero_norm(norm) {
                return Err(SimilarityVectorSkipReason::ZeroNorm);
            }
            Ok(Some(NormalizedVector::Dense {
                dim: *dim,
                data: data.clone(),
                norm,
            }))
        }
        SlotVector::Sparse { dim, entries } => {
            let norm = sparse_norm(entries);
            if zero_norm(norm) {
                return Err(SimilarityVectorSkipReason::ZeroNorm);
            }
            let mut entries = entries.clone();
            entries.sort_by_key(|entry| entry.idx);
            Ok(Some(NormalizedVector::Sparse {
                dim: *dim,
                entries,
                norm,
            }))
        }
        SlotVector::Multi { .. } => {
            Err(SimilarityVectorSkipReason::UnsupportedSlotShape { shape: "multi" })
        }
        SlotVector::Absent { .. } => Err(SimilarityVectorSkipReason::AbsentSlot),
    }
}

fn plan_family_edges(
    family: SimilarityFamily,
    threshold: f32,
    per_node_cap: usize,
    vectors: &[IndexedVector],
) -> (Vec<SimilarityEdge>, SimilarityPairCounts) {
    let mut counts = SimilarityPairCounts::default();
    let mut candidates = Vec::new();

    for i in 0..vectors.len() {
        for j in (i + 1)..vectors.len() {
            counts.candidate_pairs += 1;
            let left = &vectors[i];
            let right = &vectors[j];
            let Some(score) = cosine(&left.vector, &right.vector) else {
                counts.incompatible_shape_pairs += 1;
                continue;
            };
            if score < threshold {
                counts.below_threshold_pairs += 1;
                continue;
            }
            candidates.push(SimilarityEdge {
                family,
                source_qn: left.qualified_name.clone(),
                target_qn: right.qualified_name.clone(),
                slot: family.slot(),
                graph_edge_kind: family.graph_edge_kind(),
                metric: SimilarityMetric::Cosine,
                weight: score,
                threshold,
            });
        }
    }

    candidates.sort_by(admission_order);
    let mut admitted = Vec::new();
    let mut source_counts = BTreeMap::<String, usize>::new();
    for edge in candidates {
        let count = source_counts.entry(edge.source_qn.clone()).or_default();
        if *count < per_node_cap {
            *count += 1;
            admitted.push(edge);
        } else {
            counts.cap_dropped_pairs += 1;
        }
    }
    counts.admitted_pairs = admitted.len();
    (admitted, counts)
}

fn admission_order(left: &SimilarityEdge, right: &SimilarityEdge) -> Ordering {
    left.source_qn
        .cmp(&right.source_qn)
        .then_with(|| right.weight.total_cmp(&left.weight))
        .then_with(|| left.target_qn.cmp(&right.target_qn))
}

fn stable_edge_order(left: &SimilarityEdge, right: &SimilarityEdge) -> Ordering {
    left.family
        .sort_index()
        .cmp(&right.family.sort_index())
        .then_with(|| left.source_qn.cmp(&right.source_qn))
        .then_with(|| left.target_qn.cmp(&right.target_qn))
}

#[derive(Debug, Clone)]
struct IndexedVector {
    qualified_name: String,
    vector: NormalizedVector,
}

#[derive(Debug, Clone)]
enum NormalizedVector {
    Dense {
        dim: u32,
        data: Vec<f32>,
        norm: f32,
    },
    Sparse {
        dim: u32,
        entries: Vec<SparseEntry>,
        norm: f32,
    },
}

fn cosine(left: &NormalizedVector, right: &NormalizedVector) -> Option<f32> {
    let score = match (left, right) {
        (
            NormalizedVector::Dense {
                dim: left_dim,
                data: left_data,
                norm: left_norm,
            },
            NormalizedVector::Dense {
                dim: right_dim,
                data: right_data,
                norm: right_norm,
            },
        ) if left_dim == right_dim => {
            dense_dot(left_data, right_data) / (left_norm.sqrt() * right_norm.sqrt())
        }
        (
            NormalizedVector::Sparse {
                dim: left_dim,
                entries: left_entries,
                norm: left_norm,
            },
            NormalizedVector::Sparse {
                dim: right_dim,
                entries: right_entries,
                norm: right_norm,
            },
        ) if left_dim == right_dim => {
            sparse_dot(left_entries, right_entries) / (left_norm.sqrt() * right_norm.sqrt())
        }
        _ => return None,
    };
    Some(score.clamp(-1.0, 1.0))
}

fn dense_dot(left: &[f32], right: &[f32]) -> f32 {
    left.iter()
        .zip(right.iter())
        .map(|(left, right)| left * right)
        .sum()
}

fn dense_norm(values: &[f32]) -> f32 {
    values.iter().map(|value| value * value).sum()
}

fn sparse_dot(left: &[SparseEntry], right: &[SparseEntry]) -> f32 {
    let mut i = 0usize;
    let mut j = 0usize;
    let mut dot = 0.0f32;
    while i < left.len() && j < right.len() {
        match left[i].idx.cmp(&right[j].idx) {
            Ordering::Less => i += 1,
            Ordering::Equal => {
                dot += left[i].val * right[j].val;
                i += 1;
                j += 1;
            }
            Ordering::Greater => j += 1,
        }
    }
    dot
}

fn sparse_norm(entries: &[SparseEntry]) -> f32 {
    entries.iter().map(|entry| entry.val * entry.val).sum()
}

fn zero_norm(norm: f32) -> bool {
    norm <= f32::EPSILON
}

fn format_score(value: f32) -> String {
    format!("{value:.9}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use calyx_core::SparseEntry;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn family_metadata_uses_calyx_panel_slots_and_named_thresholds() {
        assert_eq!(SimilarityFamily::Struct.wire_name(), "SIM_STRUCT");
        assert_eq!(SimilarityFamily::Semantic.wire_name(), "SIM_SEMANTIC");
        assert_eq!(SimilarityFamily::Api.wire_name(), "SIM_API");
        assert_eq!(SimilarityFamily::Profile.wire_name(), "SIM_PROFILE");

        assert_eq!(SimilarityFamily::Struct.slot(), SlotId::new(1));
        assert_eq!(SimilarityFamily::Api.slot(), SlotId::new(4));
        assert_eq!(SimilarityFamily::Semantic.slot(), SlotId::new(18));
        assert_eq!(SimilarityFamily::Profile.slot(), SlotId::new(21));

        let thresholds = SimilarityThresholds::default();
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Struct),
            DEFAULT_SIM_STRUCT_MIN_SCORE
        );
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Semantic),
            DEFAULT_SIM_SEMANTIC_MIN_SCORE
        );
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Api),
            DEFAULT_SIM_API_MIN_SCORE
        );
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Profile),
            DEFAULT_SIM_PROFILE_MIN_SCORE
        );
    }

    #[test]
    fn golden_knn_admission_uses_lower_qn_owner_and_cap() {
        let mut config = struct_only_config();
        config.per_node_cap = 1;
        config.thresholds.sim_struct_min_score = 0.40;
        let nodes = vec![
            sparse_node("alpha", SimilarityFamily::Struct, 8, &[(0, 1.0), (1, 1.0)]),
            sparse_node("beta", SimilarityFamily::Struct, 8, &[(0, 1.0), (1, 1.0)]),
            sparse_node("gamma", SimilarityFamily::Struct, 8, &[(0, 1.0), (2, 1.0)]),
            sparse_node("omega", SimilarityFamily::Struct, 8, &[(7, 1.0)]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert_eq!(
            edge_qns(&plan.edges),
            vec![("alpha", "beta"), ("beta", "gamma")]
        );
        assert_eq!(plan.edges[0].family, SimilarityFamily::Struct);
        assert_eq!(plan.edges[0].graph_edge_kind, EdgeKind::SimilarTo);
        assert_eq!(plan.edges[0].weight, 1.0);
        assert_eq!(plan.edges[0].threshold, 0.40);

        let counts = plan
            .skips
            .pair_counts
            .get(&SimilarityFamily::Struct)
            .expect("struct pair counts");
        assert_eq!(counts.candidate_pairs, 6);
        assert_eq!(counts.below_threshold_pairs, 3);
        assert_eq!(counts.cap_dropped_pairs, 1);
        assert_eq!(counts.admitted_pairs, 2);
    }

    #[test]
    fn dense_semantic_cosine_is_exact_for_golden_pair() {
        let mut config = family_only_config(SimilarityFamily::Semantic);
        config.thresholds.sim_semantic_min_score = 0.50;
        let nodes = vec![
            dense_node("left", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("right", SimilarityFamily::Semantic, &[0.6, 0.8]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert_eq!(plan.edges.len(), 1);
        assert_eq!(plan.edges[0].source_qn, "left");
        assert_eq!(plan.edges[0].target_qn, "right");
        assert_eq!(plan.edges[0].graph_edge_kind, EdgeKind::SemanticallyRelated);
        assert!((plan.edges[0].weight - 0.6).abs() <= f32::EPSILON);
        assert_eq!(
            plan.edges[0].graph_properties().get("family"),
            Some(&"SIM_SEMANTIC".to_string())
        );
    }

    #[test]
    fn worker_count_does_not_change_deterministic_admission() {
        let mut one_worker = struct_only_config();
        one_worker.worker_count = 1;
        one_worker.per_node_cap = 2;
        one_worker.thresholds.sim_struct_min_score = 0.30;

        let mut eight_workers = one_worker.clone();
        eight_workers.worker_count = 8;

        let nodes = vec![
            sparse_node("zeta", SimilarityFamily::Struct, 8, &[(0, 1.0), (1, 1.0)]),
            sparse_node("alpha", SimilarityFamily::Struct, 8, &[(0, 1.0), (1, 1.0)]),
            sparse_node("delta", SimilarityFamily::Struct, 8, &[(0, 1.0), (2, 1.0)]),
            sparse_node("beta", SimilarityFamily::Struct, 8, &[(1, 1.0), (2, 1.0)]),
        ];

        let left = plan_similarity_edges(&nodes, &one_worker).expect("one-worker plan");
        let right = plan_similarity_edges(&nodes, &eight_workers).expect("eight-worker plan");

        assert_eq!(left.edges, right.edges);
        assert_eq!(left.skips, right.skips);
        assert_eq!(left.workers_requested, 1);
        assert_eq!(right.workers_requested, 8);
    }

    #[test]
    fn disabled_family_and_scale_opt_out_are_reported_explicitly() {
        let mut config = family_only_config(SimilarityFamily::Semantic)
            .with_disabled_family(SimilarityFamily::Struct)
            .with_exact_pair_node_limit(Some(2));
        config.thresholds.sim_semantic_min_score = 0.10;

        let nodes = vec![
            dense_node("a", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("b", SimilarityFamily::Semantic, &[0.9, 0.1]),
            dense_node("c", SimilarityFamily::Semantic, &[0.8, 0.2]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert!(plan.edges.is_empty());
        assert!(plan.skips.family_opt_outs.iter().any(|skip| {
            skip.family == SimilarityFamily::Struct
                && skip.reason == SimilarityFamilyOptOutReason::DisabledByConfig
        }));
        assert!(plan.skips.family_opt_outs.iter().any(|skip| {
            skip.family == SimilarityFamily::Semantic
                && skip.reason == SimilarityFamilyOptOutReason::ExactCandidateLimitExceeded
                && skip.node_count == 3
                && skip.limit == Some(2)
        }));
    }

    #[test]
    fn absent_zero_norm_missing_and_bad_shapes_are_not_silent_fallbacks() {
        let config = family_only_config(SimilarityFamily::Semantic);
        let nodes = vec![
            SimilarityNode::new("absent").with_slot(
                SimilarityFamily::Semantic.slot(),
                SlotVector::Absent {
                    reason: calyx_core::AbsentReason::Deferred,
                },
            ),
            SimilarityNode::new("missing"),
            dense_node("zero", SimilarityFamily::Semantic, &[0.0, 0.0]),
            SimilarityNode::new("multi").with_slot(
                SimilarityFamily::Semantic.slot(),
                SlotVector::Multi {
                    token_dim: 2,
                    tokens: vec![vec![1.0, 0.0]],
                },
            ),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert_eq!(plan.edges, Vec::new());
        assert!(has_vector_skip(
            &plan,
            "absent",
            SimilarityVectorSkipReason::AbsentSlot
        ));
        assert!(has_vector_skip(
            &plan,
            "missing",
            SimilarityVectorSkipReason::MissingSlot
        ));
        assert!(has_vector_skip(
            &plan,
            "zero",
            SimilarityVectorSkipReason::ZeroNorm
        ));
        assert!(has_vector_skip(
            &plan,
            "multi",
            SimilarityVectorSkipReason::UnsupportedSlotShape { shape: "multi" }
        ));
    }

    #[test]
    fn invalid_config_and_inputs_are_rejected() {
        let nodes = vec![dense_node("n", SimilarityFamily::Semantic, &[1.0, 0.0])];

        let mut config = SimilarityPlannerConfig {
            per_node_cap: 0,
            ..SimilarityPlannerConfig::default()
        };
        assert!(matches!(
            plan_similarity_edges(&nodes, &config),
            Err(SimilarityPlanError::InvalidPerNodeCap { value: 0 })
        ));

        config.per_node_cap = 1;
        config.worker_count = 0;
        assert!(matches!(
            plan_similarity_edges(&nodes, &config),
            Err(SimilarityPlanError::InvalidWorkerCount { value: 0 })
        ));

        config.worker_count = 1;
        config.thresholds.sim_api_min_score = f32::NAN;
        assert!(matches!(
            plan_similarity_edges(&nodes, &config),
            Err(SimilarityPlanError::InvalidThreshold {
                field: "sim_api_min_score",
                ..
            })
        ));

        assert!(matches!(
            plan_similarity_edges(
                &[SimilarityNode::new(" ")],
                &SimilarityPlannerConfig::default()
            ),
            Err(SimilarityPlanError::EmptyQualifiedName { node_index: 0 })
        ));
    }

    #[test]
    fn eager_cross_terms_materialize_exactly_six_designed_pairs_per_symbol() {
        let node = all_dense_cross_term_node("symbol");

        let plan = plan_eager_cross_terms(&[node]);

        assert_eq!(plan.rows.len(), EagerAgreementKind::ALL.len());
        assert_eq!(
            plan.rows.iter().map(|row| row.kind).collect::<Vec<_>>(),
            EagerAgreementKind::ALL
        );
        assert!(plan.rows.iter().all(|row| row.persisted));
        assert_eq!(plan.abundance.symbol_count, 1);
        assert_eq!(plan.abundance.panel_slot_count, 22);
        assert_eq!(plan.abundance.possible_pair_count_per_symbol, 231);
        assert_eq!(plan.abundance.raw_yield, 254);
        assert_eq!(plan.abundance.materialized_count, 6);
        assert_eq!(plan.abundance.lazy_pair_count, 225);
    }

    #[test]
    fn golden_cross_terms_compute_dense_and_sparse_cosine() {
        let node = SimilarityNode::new("symbol")
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[0.6, 0.8]))
            .with_slot(SLOT_NAME_SEMANTIC, sparse(8, &[(1, 1.0), (3, 1.0)]))
            .with_slot(SIM_API_SLOT, sparse(8, &[(1, 1.0), (3, 1.0)]))
            .with_slot(SIM_STRUCT_SLOT, dense(&[0.6, 0.8]))
            .with_slot(SLOT_COMPLEXITY, dense(&[1.0, 1.0]))
            .with_slot(SLOT_CHURN, dense(&[1.0, 1.0]))
            .with_slot(SLOT_GRAPH_POSITION, dense(&[1.0, 1.0]))
            .with_slot(SLOT_TEST_COVERAGE, dense(&[1.0, 1.0]))
            .with_slot(SLOT_ROUTE_MATCH, dense(&[0.6, 0.8]));

        let plan = plan_eager_cross_terms(&[node]);
        let doc = row_value(&plan, EagerAgreementKind::DocDrift);
        let name = row_value(&plan, EagerAgreementKind::NameTruth);

        assert!((doc - 0.6).abs() <= f32::EPSILON);
        assert_eq!(name, 1.0);
        assert_eq!(plan.abundance.scalar_count, 6);
        assert_eq!(plan.abundance.absent_count, 0);
    }

    #[test]
    fn absent_operand_propagates_instead_of_zero_fallback() {
        let node = SimilarityNode::new("symbol")
            .with_slot(
                SLOT_DOC_SEMANTIC,
                SlotVector::Absent {
                    reason: calyx_core::AbsentReason::LensUnavailable,
                },
            )
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0]));

        let plan = plan_eager_cross_terms(&[node]);
        let doc = plan
            .rows
            .iter()
            .find(|row| row.kind == EagerAgreementKind::DocDrift)
            .expect("doc drift row");

        assert_eq!(
            doc.value,
            CrossTermValue::Absent {
                reason: CrossTermAbsentReason::SlotAbsent {
                    slot: SLOT_DOC_SEMANTIC
                }
            }
        );
        assert!(plan.rows.iter().all(|row| row.value.is_absent()));
        assert_eq!(plan.abundance.scalar_count, 0);
        assert_eq!(plan.abundance.absent_count, 6);
    }

    #[test]
    fn agreement_graph_means_scalars_and_counts_absent_rows() {
        let present = all_dense_cross_term_node("present");
        let absent = SimilarityNode::new("absent")
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(
                SIM_SEMANTIC_SLOT,
                SlotVector::Absent {
                    reason: calyx_core::AbsentReason::Deferred,
                },
            );

        let plan = plan_eager_cross_terms(&[present, absent]);
        let graph = plan
            .agreement_graph
            .iter()
            .find(|edge| edge.kind == EagerAgreementKind::DocDrift)
            .expect("doc drift graph edge");

        assert_eq!(graph.mean_agreement, Some(1.0));
        assert_eq!(graph.scalar_count, 1);
        assert_eq!(graph.absent_count, 1);
        assert_eq!(plan.abundance.materialized_count, 12);
        assert_eq!(plan.abundance.raw_yield, 508);
        assert_eq!(plan.abundance.lazy_pair_count, 450);
    }

    fn struct_only_config() -> SimilarityPlannerConfig {
        family_only_config(SimilarityFamily::Struct)
    }

    fn family_only_config(family: SimilarityFamily) -> SimilarityPlannerConfig {
        let disabled_families = SimilarityFamily::ALL
            .into_iter()
            .filter(|candidate| *candidate != family)
            .collect();
        SimilarityPlannerConfig {
            disabled_families,
            exact_pair_node_limit: None,
            ..SimilarityPlannerConfig::default()
        }
    }

    fn dense_node(qn: &str, family: SimilarityFamily, data: &[f32]) -> SimilarityNode {
        SimilarityNode::new(qn).with_slot(
            family.slot(),
            SlotVector::Dense {
                dim: data.len() as u32,
                data: data.to_vec(),
            },
        )
    }

    fn all_dense_cross_term_node(qn: &str) -> SimilarityNode {
        SimilarityNode::new(qn)
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0]))
            .with_slot(SLOT_NAME_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(SIM_API_SLOT, dense(&[1.0, 0.0]))
            .with_slot(SIM_STRUCT_SLOT, dense(&[1.0, 0.0]))
            .with_slot(SLOT_COMPLEXITY, dense(&[1.0, 0.0]))
            .with_slot(SLOT_CHURN, dense(&[1.0, 0.0]))
            .with_slot(SLOT_GRAPH_POSITION, dense(&[1.0, 0.0]))
            .with_slot(SLOT_TEST_COVERAGE, dense(&[1.0, 0.0]))
            .with_slot(SLOT_ROUTE_MATCH, dense(&[1.0, 0.0]))
    }

    fn dense(data: &[f32]) -> SlotVector {
        SlotVector::Dense {
            dim: data.len() as u32,
            data: data.to_vec(),
        }
    }

    fn sparse(dim: u32, entries: &[(u32, f32)]) -> SlotVector {
        SlotVector::Sparse {
            dim,
            entries: entries
                .iter()
                .map(|(idx, val)| SparseEntry {
                    idx: *idx,
                    val: *val,
                })
                .collect(),
        }
    }

    fn sparse_node(
        qn: &str,
        family: SimilarityFamily,
        dim: u32,
        entries: &[(u32, f32)],
    ) -> SimilarityNode {
        SimilarityNode::new(qn).with_slot(
            family.slot(),
            SlotVector::Sparse {
                dim,
                entries: entries
                    .iter()
                    .map(|(idx, val)| SparseEntry {
                        idx: *idx,
                        val: *val,
                    })
                    .collect(),
            },
        )
    }

    fn edge_qns(edges: &[SimilarityEdge]) -> Vec<(&str, &str)> {
        edges
            .iter()
            .map(|edge| (edge.source_qn.as_str(), edge.target_qn.as_str()))
            .collect()
    }

    fn row_value(plan: &EagerCrossTermPlan, kind: EagerAgreementKind) -> f32 {
        match plan
            .rows
            .iter()
            .find(|row| row.kind == kind)
            .expect("cross term row")
            .value
        {
            CrossTermValue::Scalar(value) => value,
            CrossTermValue::Absent { ref reason } => panic!("expected scalar, got {reason:?}"),
        }
    }

    fn has_vector_skip(
        plan: &SimilarityPlan,
        qn: &str,
        reason: SimilarityVectorSkipReason,
    ) -> bool {
        plan.skips.vector_skips.iter().any(|skip| {
            skip.qualified_name == qn
                && skip.family == SimilarityFamily::Semantic
                && skip.reason == reason
        })
    }
}
