//! Atomic fleet-kernel generations (#1151).
//!
//! A fleet kernel is one indivisible, content-addressed serving object: the
//! exact repository-generation roster, fleet graph, complete graph-vector
//! roster, kernel artifact, member provenance, complete member HNSW/bindings,
//! genuine external query corpus, graph-routed recall report, manifest, current
//! pointer, and one physical Ledger entry. Visibility moves only in the
//! ledger-bound pointer commit. Retention keeps current plus previous and
//! tombstones the superseded generation in that same transaction. A generation
//! address hashes both immutable row content and its predecessor generation;
//! recurring content (A -> B -> A) therefore never reuses or overwrites A's
//! manifest key with a different Ledger/retention lineage.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::TrustTag;
use astrolabe_kernel::{
    GraphRoutedRecallParams, GraphRoutedRecallReport, KernelArtifact, KernelBuildConfig,
    KernelGraph, KernelGraphEdge, KernelGraphNode, KernelSourceIdentity,
    evaluate_graph_routed_recall, kernel_source_identity, members_hash,
    validate_graph_routed_recall_report,
};
use astrolabe_weave::kernel_index::KernelMemberBinding;
use astrolabe_weave::search::SLOT_NAME_SEMANTIC;
use astrolabe_weave::search_index::{BM25_B_MILLIS, BM25_K1_MILLIS, HNSW_M, IndexKnobs};
use astrolabe_weave::{
    KernelRecallQueryCorpus, KernelRecallQueryInput, WeaveSlotBinding,
    build_kernel_recall_query_corpus, validate_kernel_recall_query_corpus_encoder,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, CxId, LedgerRef, SlotVector};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use calyx_sextant::{HnswArtifactExpectation, HnswIndex, IndexSearchHit, QuantKind, SextantIndex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::compose::ComposeConfig;

pub const FLEET_KERNEL_GENERATION_MANIFEST_SCHEMA: &str =
    "astrolabe.fleet_kernel_generation_manifest.v1";
pub const FLEET_KERNEL_GENERATION_POINTER_SCHEMA: &str =
    "astrolabe.fleet_kernel_generation_pointer.v1";
pub const FLEET_KERNEL_GENERATION_LEDGER_SCHEMA: &str =
    "astrolabe.fleet_kernel_generation_ledger.v1";
pub const FLEET_KERNEL_SOURCE_ROSTER_SCHEMA: &str = "astrolabe.fleet_kernel_source_roster.v2";
pub const FLEET_KERNEL_GRAPH_SCHEMA: &str = "astrolabe.fleet_kernel_graph.v1";
pub const FLEET_KERNEL_VECTOR_ROSTER_SCHEMA: &str = "astrolabe.fleet_kernel_vectors.v1";
pub const FLEET_KERNEL_PROVENANCE_SCHEMA: &str = "astrolabe.fleet_kernel_provenance.v1";
pub const FLEET_KERNEL_INDEX_SCHEMA: &str = "astrolabe.fleet_kernel_member_index.v1";
pub const FLEET_KERNEL_ADMISSION_SCHEMA: &str = "astrolabe.fleet_kernel_admission.v1";
pub const FLEET_KERNEL_ADMISSION_SOURCE_KIND: &str = "external_operator_query_log";
pub const FLEET_KERNEL_GENERATION_ACTOR: &str = "astrolabe-fleet-kernel-generation";
pub const FLEET_KERNEL_GENERATION_PREFIX: &[u8] = b"astrolabe:fleet-kernel-generation:v1:";
pub const FLEET_KERNEL_CURRENT_PREFIX: &[u8] = b"astrolabe:fleet-kernel-current:v1:";

pub const ASTRO_FLEET_GENERATION_CORRUPT: &str = "ASTRO_FLEET_GENERATION_CORRUPT";
pub const ASTRO_FLEET_GENERATION_PERSIST: &str = "ASTRO_FLEET_GENERATION_PERSIST";
pub const ASTRO_FLEET_GENERATION_INCOMPLETE: &str = "ASTRO_FLEET_GENERATION_INCOMPLETE";
pub const ASTRO_FLEET_ADMISSION_REQUIRED: &str = "ASTRO_FLEET_ADMISSION_REQUIRED";
pub const ASTRO_FLEET_GENERATION_SOURCE_DRIFT: &str = "ASTRO_FLEET_GENERATION_SOURCE_DRIFT";

const CURRENT_LEAF: &[u8] = b"current.json";
const MANIFEST_LEAF: &[u8] = b"manifest.json";
const LOGICAL_SOURCE_ROSTER: &str = "source-roster.json";
const LOGICAL_GRAPH: &str = "fleet-graph.json";
const LOGICAL_VECTORS: &str = "complete-s20-vectors.json";
const LOGICAL_KERNEL: &str = "kernel.json";
const LOGICAL_PROVENANCE: &str = "member-provenance.json";
const LOGICAL_INDEX: &str = "member-index.json";
const LOGICAL_BINDINGS: &str = "member-bindings.json";
const LOGICAL_HNSW: &str = "s20.hnsw";
const LOGICAL_ADMISSION: &str = "admission.json";
const LOGICAL_QUERY_CORPUS: &str = "real-query-corpus.json";
const LOGICAL_RECALL_REPORT: &str = "graph-routed-recall.json";

const LOGICAL_NAMES: [&str; 11] = [
    LOGICAL_SOURCE_ROSTER,
    LOGICAL_GRAPH,
    LOGICAL_VECTORS,
    LOGICAL_KERNEL,
    LOGICAL_PROVENANCE,
    LOGICAL_INDEX,
    LOGICAL_BINDINGS,
    LOGICAL_HNSW,
    LOGICAL_ADMISSION,
    LOGICAL_QUERY_CORPUS,
    LOGICAL_RECALL_REPORT,
];

/// Explicit, externally authored fleet recall admission input.
///
/// There is no default and no graph-derived query constructor. The exact file
/// supplied by the operator must declare itself as an external query log and
/// carry every routing, exact-work, recall, compactness, and index control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetKernelAdmissionInput {
    pub schema: String,
    pub source_kind: String,
    pub capture_id: String,
    pub queries: Vec<KernelRecallQueryInput>,
    pub params: GraphRoutedRecallParams,
    pub index_knobs: IndexKnobs,
    /// Hard pre-computation ceiling for unordered fleet similarity pairs.
    pub max_fleet_similarity_pair_evaluations: u64,
}

impl FleetKernelAdmissionInput {
    pub fn validate(&self) -> Result<(), CalyxError> {
        if self.schema != FLEET_KERNEL_ADMISSION_SCHEMA
            || self.source_kind != FLEET_KERNEL_ADMISSION_SOURCE_KIND
            || self.capture_id.trim().is_empty()
            || self.queries.is_empty()
            || self.max_fleet_similarity_pair_evaluations == 0
        {
            return Err(admission_error(format!(
                "fleet admission requires schema={FLEET_KERNEL_ADMISSION_SCHEMA:?}, source_kind={FLEET_KERNEL_ADMISSION_SOURCE_KIND:?}, nonempty capture_id, nonempty external rows, and a positive similarity-pair ceiling; observed schema={:?} source_kind={:?} capture_id={:?} rows={} max_pairs={}",
                self.schema,
                self.source_kind,
                self.capture_id,
                self.queries.len(),
                self.max_fleet_similarity_pair_evaluations,
            )));
        }
        if self.index_knobs.bm25_k1_millis != BM25_K1_MILLIS
            || self.index_knobs.bm25_b_millis != BM25_B_MILLIS
            || self.index_knobs.hnsw_m != HNSW_M
            || self.index_knobs.hnsw_ef_search == 0
            || self.index_knobs.hnsw_ef_search < self.params.top_k as u64
        {
            return Err(admission_error(format!(
                "fleet HNSW controls are unsupported or insufficient: bm25_k1={} bm25_b={} hnsw_m={} hnsw_ef_search={} recall_top_k={}",
                self.index_knobs.bm25_k1_millis,
                self.index_knobs.bm25_b_millis,
                self.index_knobs.hnsw_m,
                self.index_knobs.hnsw_ef_search,
                self.params.top_k,
            )));
        }
        let mut stable_ids = BTreeSet::new();
        let mut contents = BTreeSet::new();
        for row in &self.queries {
            if row.stable_id.trim().is_empty()
                || row.source.trim().is_empty()
                || row.content.trim().is_empty()
                || !stable_ids.insert(row.stable_id.as_str())
                || !contents.insert(row.content.as_str())
            {
                return Err(admission_error(format!(
                    "external query rows require nonempty stable_id/source/content plus unique stable ids and exact query content; offending stable_id={:?} source={:?}",
                    row.stable_id, row.source,
                )));
            }
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CalyxError> {
        self.validate()?;
        canonical_json(self, "fleet admission input")
    }

    pub fn identity_blake3(&self) -> Result<String, CalyxError> {
        Ok(blake3_hex(&self.canonical_json_bytes()?))
    }
}

/// Exact per-repository source bound into a fleet generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetRepoSourceBinding {
    pub catalog_project: String,
    pub store_key: String,
    pub index_project: String,
    pub kernel_scope: String,
    pub generation_id: String,
    pub source_generation_identity: String,
    /// Domain-separated hash of the exact current repository pointer and
    /// immutable manifest selected during the cold source read.
    pub kernel_header_blake3: String,
    /// Durable logical-content generations for the Cx-addressed Base rows and
    /// canonical Blob inputs consumed by fleet composition. These let warm
    /// serving reject source drift with bounded metadata reads.
    pub base_content_generation: u64,
    pub blob_content_generation: u64,
    pub compose_source_hash: String,
    pub artifact_source_identity_hash: String,
    pub members_hash: String,
    pub member_count: usize,
    pub panel_version: u32,
    pub semantic_dim: u32,
    pub s20_source_binding_seq: u64,
    pub s20_source_final_verification_seq: u64,
    pub s20_source_binding: WeaveSlotBinding,
}

/// Canonical complete source roster and every graph/build policy input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetKernelSourceRoster {
    pub schema: String,
    pub scope_id: String,
    pub compose_input_hash: String,
    pub candidacy_policy_version: String,
    pub panel_version: u32,
    pub semantic_dim: u32,
    pub compose_config: ComposeConfig,
    pub kernel_config: KernelBuildConfig,
    pub repositories: Vec<FleetRepoSourceBinding>,
    pub source_roster_hash: String,
}

impl FleetKernelSourceRoster {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CalyxError> {
        validate_source_roster(self)?;
        canonical_json(self, "fleet source roster")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetGraphNodeRecord {
    pub cx_id: CxId,
    pub frequency: u64,
    pub anchor_trust: Option<TrustTag>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetGraphEdgeRecord {
    pub src: CxId,
    pub dst: CxId,
    pub weight_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetKernelGraphRecord {
    pub schema: String,
    pub nodes: Vec<FleetGraphNodeRecord>,
    pub edges: Vec<FleetGraphEdgeRecord>,
    pub graph_hash: String,
}

impl FleetKernelGraphRecord {
    pub fn from_graph(graph: &KernelGraph) -> Result<Self, CalyxError> {
        let mut nodes = graph
            .nodes()
            .iter()
            .map(|node| FleetGraphNodeRecord {
                cx_id: node.id,
                frequency: node.frequency,
                anchor_trust: node.anchor_trust,
            })
            .collect::<Vec<_>>();
        nodes.sort_by_key(|node| node.cx_id);
        let mut edges = graph
            .edges()
            .iter()
            .map(|edge| FleetGraphEdgeRecord {
                src: edge.src,
                dst: edge.dst,
                weight_bits: edge.weight.to_bits(),
            })
            .collect::<Vec<_>>();
        edges.sort_by_key(|edge| (edge.src, edge.dst, edge.weight_bits));
        let mut row = Self {
            schema: FLEET_KERNEL_GRAPH_SCHEMA.to_string(),
            nodes,
            edges,
            graph_hash: String::new(),
        };
        row.graph_hash = compute_graph_hash(&row)?;
        row.to_graph()?;
        Ok(row)
    }

    pub fn to_graph(&self) -> Result<KernelGraph, CalyxError> {
        if self.schema != FLEET_KERNEL_GRAPH_SCHEMA
            || self.graph_hash != compute_graph_hash(self)?
            || self.nodes.is_empty()
            || !strict_by_key(&self.nodes, |node| node.cx_id)
            || !strict_by_key(&self.edges, |edge| (edge.src, edge.dst, edge.weight_bits))
        {
            return Err(corrupt_error(format!(
                "fleet graph schema/order/hash is invalid: schema={:?} nodes={} edges={} hash={}",
                self.schema,
                self.nodes.len(),
                self.edges.len(),
                self.graph_hash,
            )));
        }
        let nodes = self
            .nodes
            .iter()
            .map(|node| KernelGraphNode::new(node.cx_id, node.frequency, node.anchor_trust))
            .collect();
        let edges = self
            .edges
            .iter()
            .map(|edge| KernelGraphEdge::new(edge.src, edge.dst, f32::from_bits(edge.weight_bits)))
            .collect();
        KernelGraph::new(nodes, edges)
            .map_err(|error| corrupt_error(format!("decode fleet graph: {error}")))
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CalyxError> {
        self.to_graph()?;
        canonical_json(self, "fleet graph")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetVectorRecord {
    pub cx_id: CxId,
    pub component_bits: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetVectorRoster {
    pub schema: String,
    pub panel_version: u32,
    pub slot: u16,
    pub dimension: u32,
    pub vectors: Vec<FleetVectorRecord>,
    pub vector_roster_hash: String,
}

impl FleetVectorRoster {
    pub fn from_vectors(
        panel_version: u32,
        dimension: u32,
        vectors: &BTreeMap<CxId, Vec<f32>>,
    ) -> Result<Self, CalyxError> {
        let mut row = Self {
            schema: FLEET_KERNEL_VECTOR_ROSTER_SCHEMA.to_string(),
            panel_version,
            slot: SLOT_NAME_SEMANTIC.get(),
            dimension,
            vectors: vectors
                .iter()
                .map(|(&cx_id, vector)| FleetVectorRecord {
                    cx_id,
                    component_bits: vector.iter().map(|value| value.to_bits()).collect(),
                })
                .collect(),
            vector_roster_hash: String::new(),
        };
        row.vector_roster_hash = compute_vector_roster_hash(&row)?;
        row.to_vectors()?;
        Ok(row)
    }

    pub fn to_vectors(&self) -> Result<BTreeMap<CxId, Vec<f32>>, CalyxError> {
        if self.schema != FLEET_KERNEL_VECTOR_ROSTER_SCHEMA
            || self.panel_version == 0
            || self.slot != SLOT_NAME_SEMANTIC.get()
            || self.dimension == 0
            || self.vectors.is_empty()
            || !strict_by_key(&self.vectors, |row| row.cx_id)
            || self.vector_roster_hash != compute_vector_roster_hash(self)?
        {
            return Err(corrupt_error(format!(
                "fleet vector roster schema/order/hash is invalid: schema={:?} panel={} slot={} dim={} rows={} hash={}",
                self.schema,
                self.panel_version,
                self.slot,
                self.dimension,
                self.vectors.len(),
                self.vector_roster_hash,
            )));
        }
        let mut vectors = BTreeMap::new();
        for row in &self.vectors {
            let vector = row
                .component_bits
                .iter()
                .map(|bits| f32::from_bits(*bits))
                .collect::<Vec<_>>();
            if vector.len() != self.dimension as usize
                || vector.iter().any(|value| !value.is_finite())
                || !vector.iter().any(|value| *value != 0.0)
                || vectors.insert(row.cx_id, vector).is_some()
            {
                return Err(corrupt_error(format!(
                    "fleet vector {} has invalid/duplicate dimension or numeric state",
                    row.cx_id,
                )));
            }
        }
        Ok(vectors)
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CalyxError> {
        self.to_vectors()?;
        canonical_json(self, "fleet vector roster")
    }
}

/// One exact home-repository occurrence retained for a fleet kernel member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetMemberOccurrenceProvenance {
    pub project: String,
    pub cx_id: CxId,
    pub qualified_name: String,
    pub rel_file_path: String,
    pub label: String,
    pub language: String,
    pub content_key_hex: String,
    pub grounded: bool,
    pub score_permille: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetMemberProvenance {
    pub fleet_cx: CxId,
    pub content_key_hex: Option<String>,
    pub grounded: bool,
    pub occurrences: Vec<FleetMemberOccurrenceProvenance>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetMemberProvenanceRoster {
    pub schema: String,
    pub members_hash: String,
    pub members: Vec<FleetMemberProvenance>,
    pub provenance_hash: String,
}

impl FleetMemberProvenanceRoster {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CalyxError> {
        validate_provenance(self)?;
        canonical_json(self, "fleet member provenance")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetKernelMemberIndexDescriptor {
    pub schema: String,
    pub scope_id: String,
    pub members_hash: String,
    pub vector_roster_hash: String,
    pub panel_version: u32,
    pub slot: u16,
    pub semantic_dim: u32,
    pub base_seq: u64,
    pub knobs: IndexKnobs,
    pub member_count: usize,
    pub binding_count: usize,
    pub indexed_member_count: usize,
    pub bindings_blake3: String,
    pub hnsw_artifact_bytes: usize,
    pub hnsw_artifact_blake3: String,
}

/// Checksum-validated fleet member index ready for serving.
#[derive(Clone, Debug)]
pub struct LoadedFleetKernelMemberIndex {
    pub descriptor: FleetKernelMemberIndexDescriptor,
    pub bindings: Vec<KernelMemberBinding>,
    hnsw: HnswIndex,
}

impl LoadedFleetKernelMemberIndex {
    pub fn query(
        &self,
        vector: &[f32],
        k: usize,
        ef: usize,
    ) -> Result<Vec<IndexSearchHit>, CalyxError> {
        if vector.len() != self.descriptor.semantic_dim as usize
            || vector.iter().any(|value| !value.is_finite())
            || !vector.iter().any(|value| *value != 0.0)
            || k == 0
            || ef < k
        {
            return Err(corrupt_error(format!(
                "fleet query vector/controls are invalid: len={} expected_dim={} finite={} nonzero={} k={k} ef={ef}",
                vector.len(),
                self.descriptor.semantic_dim,
                vector.iter().all(|value| value.is_finite()),
                vector.iter().any(|value| *value != 0.0),
            )));
        }
        self.hnsw
            .search(
                &SlotVector::Dense {
                    dim: self.descriptor.semantic_dim,
                    data: vector.to_vec(),
                },
                k.min(self.descriptor.member_count),
                Some(ef),
            )
            .map_err(|error| corrupt_error(format!("fleet member HNSW query failed: {error}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetGenerationRowBinding {
    pub logical_name: String,
    pub key_hex: String,
    pub bytes: u64,
    pub blake3: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetGenerationPointerTarget {
    pub generation_id: String,
    pub manifest_key_hex: String,
    pub manifest_blake3: String,
    pub commit_seq: u64,
    pub ledger_ref: LedgerRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetKernelGenerationManifest {
    pub schema: String,
    pub scope_id: String,
    pub generation_id: String,
    pub source_generation_identity: String,
    /// Catalog sequence retained before the sole atomic pointer commit.
    pub base_seq: u64,
    pub compose_input_hash: String,
    pub admission_input_blake3: String,
    pub source_roster_hash: String,
    pub graph_hash: String,
    pub vector_roster_hash: String,
    pub artifact_source_identity: KernelSourceIdentity,
    pub members_hash: String,
    pub member_count: usize,
    pub graph_node_count: usize,
    pub graph_edge_count: usize,
    pub panel_version: u32,
    pub semantic_dim: u32,
    pub provenance_hash: String,
    pub index_bindings_blake3: String,
    pub index_hnsw_blake3: String,
    pub query_encoder_identity_hash: String,
    pub query_corpus_hash: String,
    pub graph_routed_report_hash: String,
    pub rows: Vec<FleetGenerationRowBinding>,
    pub ledger_ref: LedgerRef,
    pub ledger_payload_blake3: String,
    pub previous_generation_id: Option<String>,
    pub retired_generation_id: Option<String>,
    pub retention: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetKernelGenerationPointer {
    pub schema: String,
    pub scope_id: String,
    pub current: FleetGenerationPointerTarget,
    pub previous: Option<FleetGenerationPointerTarget>,
    pub retained_generation_count: usize,
}

#[derive(Clone, Debug)]
pub struct CurrentFleetKernelGeneration {
    pub source_roster: FleetKernelSourceRoster,
    pub graph_record: FleetKernelGraphRecord,
    pub graph: KernelGraph,
    pub vectors: BTreeMap<CxId, Vec<f32>>,
    pub artifact: KernelArtifact,
    pub provenance: FleetMemberProvenanceRoster,
    pub index: LoadedFleetKernelMemberIndex,
    pub admission: FleetKernelAdmissionInput,
    pub query_corpus: KernelRecallQueryCorpus,
    pub graph_routed_report: GraphRoutedRecallReport,
    pub manifest: FleetKernelGenerationManifest,
    pub pointer: FleetKernelGenerationPointer,
    pub rows_verified: usize,
    pub ledger_physical_tiers: Vec<String>,
}

/// Narrow immutable-header read used to validate a warm serving-cache key.
#[derive(Clone, Debug)]
pub struct FleetKernelGenerationHeader {
    pub manifest: FleetKernelGenerationManifest,
    pub pointer: FleetKernelGenerationPointer,
    pub ledger_physical_tiers: Vec<String>,
}

pub struct FleetKernelGenerationPublishRequest<'a> {
    pub scope_id: &'a str,
    pub source_roster: &'a FleetKernelSourceRoster,
    pub graph: &'a KernelGraph,
    pub complete_vectors: &'a BTreeMap<CxId, Vec<f32>>,
    pub artifact: &'a KernelArtifact,
    pub provenance: &'a FleetMemberProvenanceRoster,
    pub admission: &'a FleetKernelAdmissionInput,
    pub base_seq: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FleetKernelGenerationPersistReport {
    pub published: bool,
    pub commit_seq: u64,
    pub generation_id: String,
    pub source_generation_identity: String,
    pub manifest: FleetKernelGenerationManifest,
    pub pointer: FleetKernelGenerationPointer,
    pub ledger_ref: LedgerRef,
    pub ledger_physical_tiers: Vec<String>,
    pub rows_readback_verified: usize,
    pub member_count: usize,
    pub graph_node_count: usize,
    pub query_count: usize,
    pub recall_permille: u64,
    pub graph_routed_report_hash: String,
    pub vector_roster_hash: String,
    pub retired_generation_id: Option<String>,
    pub flush_sst_files: usize,
    pub flush_sst_entries: usize,
    pub flush_sst_bytes: u64,
}

#[derive(Clone)]
struct PreparedRow {
    logical_name: &'static str,
    key: Vec<u8>,
    value: Vec<u8>,
}

fn validate_source_roster(roster: &FleetKernelSourceRoster) -> Result<(), CalyxError> {
    let strict = strict_by_key(&roster.repositories, |row| {
        (
            row.catalog_project.as_str(),
            row.store_key.as_str(),
            row.index_project.as_str(),
        )
    });
    if roster.schema != FLEET_KERNEL_SOURCE_ROSTER_SCHEMA
        || roster.scope_id.trim().is_empty()
        || !is_hash(&roster.compose_input_hash)
        || roster.candidacy_policy_version.trim().is_empty()
        || roster.panel_version == 0
        || roster.semantic_dim == 0
        || roster.repositories.is_empty()
        || !strict
    {
        return Err(corrupt_error(format!(
            "fleet source roster shape is invalid: schema={:?} scope={:?} compose_hash={} policy={:?} panel={} dim={} repos={} strict={strict}",
            roster.schema,
            roster.scope_id,
            roster.compose_input_hash,
            roster.candidacy_policy_version,
            roster.panel_version,
            roster.semantic_dim,
            roster.repositories.len(),
        )));
    }
    roster
        .compose_config
        .validate()
        .map_err(|error| corrupt_error(format!("fleet compose config is invalid: {error}")))?;
    roster
        .kernel_config
        .validate()
        .map_err(|error| corrupt_error(format!("fleet kernel config is invalid: {error}")))?;
    for repo in &roster.repositories {
        if repo.catalog_project.trim().is_empty()
            || repo.store_key.trim().is_empty()
            || repo.index_project.trim().is_empty()
            || repo.kernel_scope.trim().is_empty()
            || !is_hash(&repo.generation_id)
            || !is_hash(&repo.source_generation_identity)
            || !is_hash(&repo.kernel_header_blake3)
            || !is_hash(&repo.compose_source_hash)
            || !is_hash(&repo.artifact_source_identity_hash)
            || !is_hash(&repo.members_hash)
            || repo.member_count == 0
            || repo.panel_version != roster.panel_version
            || repo.semantic_dim != roster.semantic_dim
            || repo.s20_source_final_verification_seq < repo.s20_source_binding_seq
            || repo.s20_source_binding.slot != SLOT_NAME_SEMANTIC
            || repo.s20_source_binding.slot_cf_generation > repo.s20_source_binding_seq
            || repo.s20_source_binding.compression_cf_generation > repo.s20_source_binding_seq
            || repo
                .s20_source_binding
                .compressed_generation_identity
                .as_ref()
                .is_some_and(|identity| {
                    identity.slot_id != SLOT_NAME_SEMANTIC.get()
                        || identity.raw_dim != repo.semantic_dim
                        || identity.stored_dim == 0
                        || u128::from(identity.row_count) < repo.member_count as u128
                        || !is_hash(&identity.codec_context_sha256)
                        || !is_hash(&identity.generation_sha256)
                        || !is_hash(&identity.raw_generation_sha256)
                        || !is_hash(&identity.membership_sha256)
                        || identity
                            .assay_attestation_sha256
                            .as_ref()
                            .is_some_and(|hash| !is_hash(hash))
                })
        {
            return Err(corrupt_error(format!(
                "repository source binding is incomplete or inconsistent: catalog_project={:?} store_key={:?} generation={} members={} panel={} dim={}",
                repo.catalog_project,
                repo.store_key,
                repo.generation_id,
                repo.member_count,
                repo.panel_version,
                repo.semantic_dim,
            )));
        }
    }
    let input_sources = roster
        .repositories
        .iter()
        .map(|repo| (repo.store_key.clone(), repo.compose_source_hash.clone()))
        .collect::<Vec<_>>();
    let expected_compose = crate::compose::compose_input_hash(
        &input_sources,
        &roster.candidacy_policy_version,
        &roster.compose_config,
        &roster.kernel_config,
    );
    let expected_roster_hash = compute_source_roster_hash(roster)?;
    if expected_compose != roster.compose_input_hash
        || expected_roster_hash != roster.source_roster_hash
    {
        return Err(corrupt_error(format!(
            "fleet source roster identities drift: compose expected={expected_compose} observed={} roster expected={expected_roster_hash} observed={}",
            roster.compose_input_hash, roster.source_roster_hash,
        )));
    }
    Ok(())
}

pub fn finalize_fleet_source_roster(
    mut roster: FleetKernelSourceRoster,
) -> Result<FleetKernelSourceRoster, CalyxError> {
    roster.repositories.sort_by(|left, right| {
        left.catalog_project
            .cmp(&right.catalog_project)
            .then_with(|| left.store_key.cmp(&right.store_key))
            .then_with(|| left.index_project.cmp(&right.index_project))
    });
    let input_sources = roster
        .repositories
        .iter()
        .map(|repo| (repo.store_key.clone(), repo.compose_source_hash.clone()))
        .collect::<Vec<_>>();
    roster.compose_input_hash = crate::compose::compose_input_hash(
        &input_sources,
        &roster.candidacy_policy_version,
        &roster.compose_config,
        &roster.kernel_config,
    );
    roster.source_roster_hash = compute_source_roster_hash(&roster)?;
    validate_source_roster(&roster)?;
    Ok(roster)
}

pub fn finalize_fleet_member_provenance(
    mut roster: FleetMemberProvenanceRoster,
) -> Result<FleetMemberProvenanceRoster, CalyxError> {
    roster.members.sort_by_key(|member| member.fleet_cx);
    for member in &mut roster.members {
        member.occurrences.sort_by(|left, right| {
            left.project
                .cmp(&right.project)
                .then_with(|| left.cx_id.cmp(&right.cx_id))
        });
    }
    roster.provenance_hash = compute_provenance_hash(&roster)?;
    validate_provenance(&roster)?;
    Ok(roster)
}

fn validate_provenance(roster: &FleetMemberProvenanceRoster) -> Result<(), CalyxError> {
    let ids = roster
        .members
        .iter()
        .map(|member| member.fleet_cx)
        .collect::<Vec<_>>();
    if roster.schema != FLEET_KERNEL_PROVENANCE_SCHEMA
        || ids.is_empty()
        || !ids.windows(2).all(|pair| pair[0] < pair[1])
        || members_hash(&ids) != roster.members_hash
        || roster.provenance_hash != compute_provenance_hash(roster)?
    {
        return Err(corrupt_error(format!(
            "fleet provenance schema/member/hash contract is invalid: schema={:?} members={} members_hash={} provenance_hash={}",
            roster.schema,
            roster.members.len(),
            roster.members_hash,
            roster.provenance_hash,
        )));
    }
    for member in &roster.members {
        let member_content = member.content_key_hex.as_deref();
        if member.occurrences.is_empty()
            || member_content.is_none_or(|value| !is_hash(value))
            || member.grounded != member.occurrences.iter().any(|row| row.grounded)
            || !strict_by_key(&member.occurrences, |row| (row.project.as_str(), row.cx_id))
            || member.occurrences.iter().any(|row| {
                row.project.trim().is_empty()
                    || row.qualified_name.trim().is_empty()
                    || row.rel_file_path.trim().is_empty()
                    || row.label.trim().is_empty()
                    || row.language.trim().is_empty()
                    || !is_hash(&row.content_key_hex)
                    || Some(row.content_key_hex.as_str()) != member_content
            })
        {
            return Err(corrupt_error(format!(
                "fleet member {} has an empty, unordered, duplicate, or incomplete provenance roster",
                member.fleet_cx,
            )));
        }
    }
    Ok(())
}

fn compute_source_roster_hash(roster: &FleetKernelSourceRoster) -> Result<String, CalyxError> {
    let mut value = roster.clone();
    value.source_roster_hash.clear();
    Ok(blake3_hex(&serde_json::to_vec(&value).map_err(
        |error| corrupt_error(format!("encode fleet source roster identity: {error}")),
    )?))
}

fn compute_graph_hash(graph: &FleetKernelGraphRecord) -> Result<String, CalyxError> {
    let mut value = graph.clone();
    value.graph_hash.clear();
    Ok(blake3_hex(&serde_json::to_vec(&value).map_err(
        |error| corrupt_error(format!("encode fleet graph identity: {error}")),
    )?))
}

fn compute_vector_roster_hash(roster: &FleetVectorRoster) -> Result<String, CalyxError> {
    let mut value = roster.clone();
    value.vector_roster_hash.clear();
    Ok(blake3_hex(&serde_json::to_vec(&value).map_err(
        |error| corrupt_error(format!("encode fleet vector identity: {error}")),
    )?))
}

fn compute_provenance_hash(roster: &FleetMemberProvenanceRoster) -> Result<String, CalyxError> {
    let mut value = roster.clone();
    value.provenance_hash.clear();
    Ok(blake3_hex(&serde_json::to_vec(&value).map_err(
        |error| corrupt_error(format!("encode fleet provenance identity: {error}")),
    )?))
}

fn build_member_index(
    scope_id: &str,
    artifact: &KernelArtifact,
    vectors: &BTreeMap<CxId, Vec<f32>>,
    vector_roster_hash: &str,
    panel_version: u32,
    semantic_dim: u32,
    knobs: IndexKnobs,
) -> Result<
    (
        FleetKernelMemberIndexDescriptor,
        Vec<KernelMemberBinding>,
        Vec<u8>,
    ),
    CalyxError,
> {
    if knobs.bm25_k1_millis != BM25_K1_MILLIS
        || knobs.bm25_b_millis != BM25_B_MILLIS
        || knobs.hnsw_m != HNSW_M
        || knobs.hnsw_ef_search == 0
    {
        return Err(admission_error(format!(
            "unsupported fleet index knobs: {knobs:?}"
        )));
    }
    let member_ids = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    if member_ids.is_empty()
        || !member_ids.windows(2).all(|pair| pair[0] < pair[1])
        || members_hash(&member_ids) != artifact.members_hash
        || member_ids.len() != artifact.member_count
    {
        return Err(incomplete_error(
            "fleet artifact does not carry one nonempty canonical member roster",
        ));
    }
    let bindings = member_ids
        .iter()
        .map(|&cx_id| KernelMemberBinding {
            cx_id,
            symbol_id: format!("fleet:{cx_id}"),
        })
        .collect::<Vec<_>>();
    let bindings_bytes = canonical_json(&bindings, "fleet member bindings")?;
    let mut hnsw = HnswIndex::new(SLOT_NAME_SEMANTIC, semantic_dim, knobs.seed);
    for cx_id in member_ids {
        let vector = vectors.get(&cx_id).ok_or_else(|| {
            incomplete_error(format!(
                "fleet kernel member {cx_id} is absent from the complete graph-vector roster"
            ))
        })?;
        hnsw.insert(
            cx_id,
            SlotVector::Dense {
                dim: semantic_dim,
                data: vector.clone(),
            },
            0,
        )
        .map_err(|error| {
            incomplete_error(format!(
                "Calyx HNSW rejected fleet member {cx_id}: code={} message={:?}",
                error.code, error.message,
            ))
        })?;
    }
    if hnsw.total_nodes() != artifact.member_count || hnsw.live_len() != artifact.member_count {
        return Err(incomplete_error(format!(
            "fleet HNSW population is incomplete: expected={} total={} live={}",
            artifact.member_count,
            hnsw.total_nodes(),
            hnsw.live_len(),
        )));
    }
    let hnsw_bytes = hnsw.to_artifact_bytes().map_err(|error| {
        incomplete_error(format!(
            "serialize fleet member HNSW: code={} message={:?}",
            error.code, error.message,
        ))
    })?;
    let descriptor = FleetKernelMemberIndexDescriptor {
        schema: FLEET_KERNEL_INDEX_SCHEMA.to_string(),
        scope_id: scope_id.to_string(),
        members_hash: artifact.members_hash.clone(),
        vector_roster_hash: vector_roster_hash.to_string(),
        panel_version,
        slot: SLOT_NAME_SEMANTIC.get(),
        semantic_dim,
        base_seq: 0,
        knobs,
        member_count: artifact.member_count,
        binding_count: bindings.len(),
        indexed_member_count: hnsw.live_len(),
        bindings_blake3: blake3_hex(&bindings_bytes),
        hnsw_artifact_bytes: hnsw_bytes.len(),
        hnsw_artifact_blake3: blake3_hex(&hnsw_bytes),
    };
    let loaded = load_member_index(
        descriptor.clone(),
        bindings.clone(),
        &bindings_bytes,
        hnsw_bytes.clone(),
    )?;
    verify_member_index_vectors(&loaded, vectors)?;
    Ok((descriptor, bindings, hnsw_bytes))
}

fn load_member_index(
    descriptor: FleetKernelMemberIndexDescriptor,
    bindings: Vec<KernelMemberBinding>,
    bindings_bytes: &[u8],
    hnsw_bytes: Vec<u8>,
) -> Result<LoadedFleetKernelMemberIndex, CalyxError> {
    let binding_ids = bindings.iter().map(|row| row.cx_id).collect::<Vec<_>>();
    let unique_symbols = bindings
        .iter()
        .map(|row| row.symbol_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        == bindings.len();
    let canonical_symbols = bindings
        .iter()
        .all(|row| row.symbol_id == format!("fleet:{}", row.cx_id));
    if descriptor.schema != FLEET_KERNEL_INDEX_SCHEMA
        || descriptor.scope_id.trim().is_empty()
        || !is_hash(&descriptor.members_hash)
        || !is_hash(&descriptor.vector_roster_hash)
        || descriptor.panel_version == 0
        || descriptor.slot != SLOT_NAME_SEMANTIC.get()
        || descriptor.semantic_dim == 0
        || descriptor.base_seq != 0
        || descriptor.member_count == 0
        || descriptor.member_count != bindings.len()
        || descriptor.binding_count != bindings.len()
        || descriptor.indexed_member_count != bindings.len()
        || !binding_ids.windows(2).all(|pair| pair[0] < pair[1])
        || !unique_symbols
        || !canonical_symbols
        || members_hash(&binding_ids) != descriptor.members_hash
        || blake3_hex(bindings_bytes) != descriptor.bindings_blake3
        || hnsw_bytes.len() != descriptor.hnsw_artifact_bytes
        || blake3_hex(&hnsw_bytes) != descriptor.hnsw_artifact_blake3
    {
        return Err(corrupt_error(format!(
            "fleet member-index descriptor/binding/HNSW identity is invalid: scope={:?} members={} bindings={} indexed={} dim={} hnsw_bytes={}",
            descriptor.scope_id,
            descriptor.member_count,
            bindings.len(),
            descriptor.indexed_member_count,
            descriptor.semantic_dim,
            hnsw_bytes.len(),
        )));
    }
    let (hnsw, metadata) = HnswIndex::from_artifact_bytes(
        &hnsw_bytes,
        HnswArtifactExpectation {
            slot: SLOT_NAME_SEMANTIC,
            dim: descriptor.semantic_dim,
            quant_kind: QuantKind::None,
            quant_geometry_id: [0; 32],
            base_seq: 0,
        },
    )
    .map_err(|error| {
        corrupt_error(format!(
            "decode fleet HNSW: code={} message={:?}",
            error.code, error.message,
        ))
    })?;
    if metadata.live_rows as usize != descriptor.member_count
        || hnsw.total_nodes() != descriptor.member_count
        || hnsw.live_len() != descriptor.member_count
        || hnsw.tombstone_count() != 0
    {
        return Err(corrupt_error(format!(
            "fleet HNSW population differs from descriptor: descriptor={} metadata_live={} total={} live={} tombstones={}",
            descriptor.member_count,
            metadata.live_rows,
            hnsw.total_nodes(),
            hnsw.live_len(),
            hnsw.tombstone_count(),
        )));
    }
    Ok(LoadedFleetKernelMemberIndex {
        descriptor,
        bindings,
        hnsw,
    })
}

fn verify_member_index_vectors(
    index: &LoadedFleetKernelMemberIndex,
    expected_vectors: &BTreeMap<CxId, Vec<f32>>,
) -> Result<(), CalyxError> {
    for binding in &index.bindings {
        let Some(SlotVector::Dense { dim, data }) = index.hnsw.vector(binding.cx_id) else {
            return Err(corrupt_error(format!(
                "fleet HNSW has no dense vector for bound member {}",
                binding.cx_id,
            )));
        };
        let expected = expected_vectors.get(&binding.cx_id).ok_or_else(|| {
            corrupt_error(format!(
                "fleet vector roster has no row for indexed member {}",
                binding.cx_id,
            ))
        })?;
        if dim != index.descriptor.semantic_dim
            || data.len() != expected.len()
            || data
                .iter()
                .zip(expected)
                .any(|(observed, expected)| observed.to_bits() != expected.to_bits())
        {
            return Err(corrupt_error(format!(
                "fleet HNSW vector differs from immutable complete S20 roster for member {}",
                binding.cx_id,
            )));
        }
    }
    Ok(())
}

/// Publishes a complete fleet generation or proves the exact generation is
/// already current without writing.
///
/// The content address includes the exact predecessor id. This makes every
/// manifest key immutable across recurring content while a same-current source
/// identity takes the verified no-write path.
///
/// # Cost contract (#1064)
///
/// Repository admission is caller-owned and measured at production
/// `N=192,873/E=328,899` (2026-08-20). Here fleet graph nodes `V_f`, edges
/// `E_f`, kernel members `M_f`, dimension `D`, and queries `Q` are persisted
/// outputs (fleet production totals remain unknown): preparation is
/// `O(V_f*D + E_f + M_f*D)`, exact recall admission is `O(Q*V_f*D)` plus the
/// declared bounded route work, and durable readback is `O(B_generation)`. One
/// conditional group commit and one flush own publication. The repository
/// roster, fleet graph, vector roster, query corpus, and all controls are
/// invariant across the operation (PC-03/04/07/14/15/28/35/37/38/41/43).
pub fn persist_fleet_kernel_generation<C>(
    vault: &AsterVault<C>,
    request: FleetKernelGenerationPublishRequest<'_>,
) -> Result<FleetKernelGenerationPersistReport, CalyxError>
where
    C: Clock,
{
    let FleetKernelGenerationPublishRequest {
        scope_id,
        source_roster,
        graph,
        complete_vectors,
        artifact,
        provenance,
        admission,
        base_seq,
    } = request;
    if vault.latest_seq() != base_seq {
        return Err(incomplete_error(format!(
            "fleet publication expected catalog seq {base_seq}, observed {}; no rows were prepared or written",
            vault.latest_seq(),
        )));
    }
    admission.validate()?;
    validate_source_roster(source_roster)?;
    validate_provenance(provenance)?;
    if source_roster.scope_id != scope_id
        || artifact.scope_id != scope_id
        || provenance.members_hash != artifact.members_hash
        || admission.params.expected_vector_dimension != source_roster.semantic_dim as usize
        || admission.params.max_kernel_member_fraction_permille
            != artifact.config.max_member_fraction_permille
    {
        return Err(incomplete_error(format!(
            "fleet publication joins incompatible scope/member/vector/compactness inputs: requested_scope={scope_id:?} roster_scope={:?} artifact_scope={:?} provenance_members={} artifact_members={} query_dim={} fleet_dim={} recall_compactness={} kernel_compactness={}",
            source_roster.scope_id,
            artifact.scope_id,
            provenance.members_hash,
            artifact.members_hash,
            admission.params.expected_vector_dimension,
            source_roster.semantic_dim,
            admission.params.max_kernel_member_fraction_permille,
            artifact.config.max_member_fraction_permille,
        )));
    }
    let graph_record = FleetKernelGraphRecord::from_graph(graph)?;
    let observed_source_identity = kernel_source_identity(graph, &artifact.config)
        .map_err(|error| incomplete_error(format!("recompute fleet source identity: {error}")))?;
    if observed_source_identity != artifact.source_identity
        || graph_record.nodes.len() != artifact.node_count
    {
        return Err(incomplete_error(format!(
            "fleet graph/artifact source identity differs: expected={} observed={} graph_nodes={} artifact_nodes={}",
            artifact.source_identity.combined_hash,
            observed_source_identity.combined_hash,
            graph_record.nodes.len(),
            artifact.node_count,
        )));
    }
    let vector_roster = FleetVectorRoster::from_vectors(
        source_roster.panel_version,
        source_roster.semantic_dim,
        complete_vectors,
    )?;
    let graph_ids = graph_record
        .nodes
        .iter()
        .map(|node| node.cx_id)
        .collect::<Vec<_>>();
    let vector_ids = complete_vectors.keys().copied().collect::<Vec<_>>();
    if graph_ids != vector_ids {
        return Err(incomplete_error(format!(
            "complete fleet graph/vector roster differs: graph_nodes={} vector_rows={}",
            graph_ids.len(),
            vector_ids.len(),
        )));
    }
    let artifact_ids = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let provenance_ids = provenance
        .members
        .iter()
        .map(|member| member.fleet_cx)
        .collect::<Vec<_>>();
    if artifact_ids != provenance_ids
        || artifact_ids.len() != artifact.member_count
        || members_hash(&artifact_ids) != artifact.members_hash
    {
        return Err(incomplete_error(format!(
            "fleet artifact/provenance roster differs: artifact={} provenance={} declared={}",
            artifact_ids.len(),
            provenance_ids.len(),
            artifact.member_count,
        )));
    }

    let query_corpus = build_kernel_recall_query_corpus(
        "fleet",
        scope_id,
        source_roster.panel_version,
        &admission.queries,
        admission.params.clone(),
    )
    .map_err(|error| {
        admission_error(format!(
            "encode genuine fleet query corpus: code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation(),
        ))
    })?;
    let report = evaluate_graph_routed_recall(
        graph,
        artifact,
        complete_vectors,
        &query_corpus.graph_routed_queries(),
        &query_corpus.params,
    )
    .map_err(|error| {
        admission_error(format!(
            "fleet graph-routed admission refused: code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation(),
        ))
    })?;
    let (index_descriptor, index_bindings, hnsw_bytes) = build_member_index(
        scope_id,
        artifact,
        complete_vectors,
        &vector_roster.vector_roster_hash,
        source_roster.panel_version,
        source_roster.semantic_dim,
        admission.index_knobs,
    )?;
    let admission_input_blake3 = admission.identity_blake3()?;

    let source_roster_bytes = source_roster.canonical_json_bytes()?;
    let graph_bytes = graph_record.canonical_json_bytes()?;
    let vector_bytes = vector_roster.canonical_json_bytes()?;
    let artifact_bytes = artifact.kernel_json_bytes();
    let provenance_bytes = provenance.canonical_json_bytes()?;
    let index_bytes = canonical_json(&index_descriptor, "fleet member-index descriptor")?;
    let binding_bytes = canonical_json(&index_bindings, "fleet member bindings")?;
    let admission_bytes = admission.canonical_json_bytes()?;
    let query_bytes = query_corpus
        .canonical_json_bytes()
        .map_err(|error| admission_error(format!("serialize fleet query corpus: {error}")))?;
    let report_bytes = report.canonical_json_bytes().map_err(|error| {
        admission_error(format!("serialize fleet routed-recall report: {error}"))
    })?;

    let source_generation_identity = stable_source_identity(
        scope_id,
        source_roster,
        &graph_record,
        &vector_roster,
        artifact,
        provenance,
        &index_descriptor,
        &query_corpus,
        &report,
        &admission_input_blake3,
    )?;
    let provisional_rows = prepare_rows(
        scope_id,
        "pending",
        source_roster_bytes,
        graph_bytes,
        vector_bytes,
        artifact_bytes,
        provenance_bytes,
        index_bytes,
        binding_bytes,
        hnsw_bytes,
        admission_bytes,
        query_bytes,
        report_bytes,
    );
    let existing = read_header_at(vault, base_seq, scope_id)?;
    if let Some(existing) = &existing
        && existing.1.source_generation_identity == source_generation_identity
    {
        let current = read_current_fleet_kernel_generation_at(vault, base_seq, scope_id)?
            .ok_or_else(|| corrupt_error("fleet current pointer disappeared during no-op"))?;
        if current.source_roster != *source_roster
            || current.graph_record != graph_record
            || current.vectors != *complete_vectors
            || current.artifact != *artifact
            || current.provenance != *provenance
            || current.index.descriptor != index_descriptor
            || current.index.bindings != index_bindings
            || current.admission != *admission
            || current.query_corpus != query_corpus
            || current.graph_routed_report != report
        {
            return Err(corrupt_error(format!(
                "fleet stable source identity matched but immutable current bytes differ: current_generation={}",
                current.manifest.generation_id,
            )));
        }
        verify_retained_previous_at(vault, base_seq, scope_id, &current.pointer)?;
        let generation_id = current.manifest.generation_id.clone();
        return Ok(FleetKernelGenerationPersistReport {
            published: false,
            commit_seq: current.pointer.current.commit_seq,
            generation_id,
            source_generation_identity,
            manifest: current.manifest.clone(),
            pointer: current.pointer.clone(),
            ledger_ref: current.manifest.ledger_ref.clone(),
            ledger_physical_tiers: current.ledger_physical_tiers,
            rows_readback_verified: current.rows_verified,
            member_count: current.artifact.member_count,
            graph_node_count: current.artifact.node_count,
            query_count: current.query_corpus.queries.len(),
            recall_permille: current.graph_routed_report.recall_permille,
            graph_routed_report_hash: current.graph_routed_report.report_hash.clone(),
            vector_roster_hash: current.manifest.vector_roster_hash.clone(),
            retired_generation_id: None,
            flush_sst_files: 0,
            flush_sst_entries: 0,
            flush_sst_bytes: 0,
        });
    }
    if let Some((pointer, manifest)) = &existing {
        verify_manifest_rows_at(vault, base_seq, scope_id, manifest)?;
        let (_, physical_ref) = verify_physical_ledger(vault, scope_id, manifest)?;
        if physical_ref != manifest.ledger_ref || manifest.ledger_ref != pointer.current.ledger_ref
        {
            return Err(corrupt_error(
                "fleet predecessor pointer/manifest/physical-Ledger identities differ before publication",
            ));
        }
        verify_retained_previous_at(vault, base_seq, scope_id, pointer)?;
    }

    let previous_target = existing
        .as_ref()
        .map(|(pointer, _)| pointer.current.clone());
    let retired_target = existing
        .as_ref()
        .and_then(|(pointer, _)| pointer.previous.clone());
    if let Some(retired) = &retired_target {
        read_manifest_target(vault, base_seq, scope_id, retired)?;
    }
    let generation_id = content_generation_id(
        scope_id,
        &source_generation_identity,
        previous_target
            .as_ref()
            .map(|target| target.generation_id.as_str()),
        &provisional_rows,
    );
    let rows = provisional_rows
        .into_iter()
        .map(|mut row| {
            row.key = generation_row_key(scope_id, &generation_id, row.logical_name.as_bytes());
            row
        })
        .collect::<Vec<_>>();

    let row_bindings = rows
        .iter()
        .map(|row| {
            Ok(FleetGenerationRowBinding {
                logical_name: row.logical_name.to_string(),
                key_hex: hex_lower(&row.key),
                bytes: u64::try_from(row.value.len()).map_err(|_| {
                    incomplete_error(format!(
                        "fleet row {:?} length {} exceeds u64",
                        row.logical_name,
                        row.value.len(),
                    ))
                })?,
                blake3: blake3_hex(&row.value),
            })
        })
        .collect::<Result<Vec<_>, CalyxError>>()?;
    let retired_generation_id = retired_target
        .as_ref()
        .map(|target| target.generation_id.clone());
    let predicted_commit_seq = base_seq
        .checked_add(1)
        .ok_or_else(|| persist_error("fleet commit sequence overflow"))?;
    let ledger_payload = serde_json::to_vec(&serde_json::json!({
        "schema": FLEET_KERNEL_GENERATION_LEDGER_SCHEMA,
        "scope_id": scope_id,
        "generation_id": generation_id,
        "source_generation_identity": source_generation_identity,
        "base_seq": base_seq,
        "compose_input_hash": source_roster.compose_input_hash,
        "admission_input_blake3": admission_input_blake3,
        "source_roster_hash": source_roster.source_roster_hash,
        "graph_hash": graph_record.graph_hash,
        "vector_roster_hash": vector_roster.vector_roster_hash,
        "artifact_source_identity": artifact.source_identity,
        "members_hash": artifact.members_hash,
        "member_count": artifact.member_count,
        "graph_node_count": graph_record.nodes.len(),
        "graph_edge_count": graph_record.edges.len(),
        "panel_version": source_roster.panel_version,
        "semantic_dim": source_roster.semantic_dim,
        "provenance_hash": provenance.provenance_hash,
        "index_bindings_blake3": index_descriptor.bindings_blake3,
        "index_hnsw_blake3": index_descriptor.hnsw_artifact_blake3,
        "query_encoder_identity_hash": query_corpus.encoder.identity_hash,
        "query_corpus_hash": query_corpus.corpus_hash,
        "graph_routed_report_hash": report.report_hash,
        "rows": row_bindings,
        "previous_generation_id": previous_target.as_ref().map(|target| target.generation_id.as_str()),
        "retired_generation_id": retired_generation_id,
    }))
    .map_err(|error| persist_error(format!("encode fleet ledger payload: {error}")))?;
    let ledger_payload_blake3 = blake3_hex(&ledger_payload);
    let initial_rows = rows
        .iter()
        .map(|row| (ColumnFamily::Kernel, row.key.clone(), row.value.clone()))
        .collect::<Vec<_>>();
    let callback_scope = scope_id.to_string();
    let callback_generation = generation_id.clone();
    let callback_source_identity = source_generation_identity.clone();
    let callback_compose_input = source_roster.compose_input_hash.clone();
    let callback_admission = admission_input_blake3.clone();
    let callback_source_roster = source_roster.source_roster_hash.clone();
    let callback_graph_hash = graph_record.graph_hash.clone();
    let callback_vector_hash = vector_roster.vector_roster_hash.clone();
    let callback_artifact_source = artifact.source_identity.clone();
    let callback_members_hash = artifact.members_hash.clone();
    let callback_provenance_hash = provenance.provenance_hash.clone();
    let callback_bindings_hash = index_descriptor.bindings_blake3.clone();
    let callback_hnsw_hash = index_descriptor.hnsw_artifact_blake3.clone();
    let callback_query_encoder = query_corpus.encoder.identity_hash.clone();
    let callback_query_hash = query_corpus.corpus_hash.clone();
    let callback_report_hash = report.report_hash.clone();
    let callback_payload_hash = ledger_payload_blake3.clone();
    let callback_previous = previous_target.clone();
    let callback_retired = retired_target.clone();
    let (commit, (manifest, pointer, retired_keys)) = vault
        .write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
            base_seq,
            initial_rows,
            EntryKind::Kernel,
            generation_subject(scope_id, &generation_id),
            ledger_payload.clone(),
            ActorId::Service(FLEET_KERNEL_GENERATION_ACTOR.to_string()),
            move |ledger_ref, _| {
                let manifest = FleetKernelGenerationManifest {
                    schema: FLEET_KERNEL_GENERATION_MANIFEST_SCHEMA.to_string(),
                    scope_id: callback_scope.clone(),
                    generation_id: callback_generation.clone(),
                    source_generation_identity: callback_source_identity.clone(),
                    base_seq,
                    compose_input_hash: callback_compose_input.clone(),
                    admission_input_blake3: callback_admission.clone(),
                    source_roster_hash: callback_source_roster.clone(),
                    graph_hash: callback_graph_hash.clone(),
                    vector_roster_hash: callback_vector_hash.clone(),
                    artifact_source_identity: callback_artifact_source.clone(),
                    members_hash: callback_members_hash.clone(),
                    member_count: artifact.member_count,
                    graph_node_count: graph_record.nodes.len(),
                    graph_edge_count: graph_record.edges.len(),
                    panel_version: source_roster.panel_version,
                    semantic_dim: source_roster.semantic_dim,
                    provenance_hash: callback_provenance_hash.clone(),
                    index_bindings_blake3: callback_bindings_hash.clone(),
                    index_hnsw_blake3: callback_hnsw_hash.clone(),
                    query_encoder_identity_hash: callback_query_encoder.clone(),
                    query_corpus_hash: callback_query_hash.clone(),
                    graph_routed_report_hash: callback_report_hash.clone(),
                    rows: row_bindings.clone(),
                    ledger_ref: ledger_ref.clone(),
                    ledger_payload_blake3: callback_payload_hash.clone(),
                    previous_generation_id: callback_previous
                        .as_ref()
                        .map(|target| target.generation_id.clone()),
                    retired_generation_id: callback_retired
                        .as_ref()
                        .map(|target| target.generation_id.clone()),
                    retention: "bounded_current_plus_previous; superseded immutable generation rows are tombstoned in the pointer commit".to_string(),
                };
                let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
                    CalyxError::ledger_group_commit_failed(format!(
                        "encode fleet generation manifest: {error}"
                    ))
                })?;
                let manifest_key = generation_manifest_key(
                    &callback_scope,
                    &callback_generation,
                );
                let pointer = FleetKernelGenerationPointer {
                    schema: FLEET_KERNEL_GENERATION_POINTER_SCHEMA.to_string(),
                    scope_id: callback_scope.clone(),
                    current: FleetGenerationPointerTarget {
                        generation_id: callback_generation.clone(),
                        manifest_key_hex: hex_lower(&manifest_key),
                        manifest_blake3: blake3_hex(&manifest_bytes),
                        commit_seq: predicted_commit_seq,
                        ledger_ref: ledger_ref.clone(),
                    },
                    previous: callback_previous.clone(),
                    retained_generation_count: usize::from(callback_previous.is_some()) + 1,
                };
                let pointer_bytes = serde_json::to_vec(&pointer).map_err(|error| {
                    CalyxError::ledger_group_commit_failed(format!(
                        "encode fleet current pointer: {error}"
                    ))
                })?;
                let mut derived = vec![
                    (ColumnFamily::Kernel, manifest_key, manifest_bytes),
                    (
                        ColumnFamily::Kernel,
                        generation_current_key(&callback_scope),
                        pointer_bytes,
                    ),
                ];
                let mut retired_keys = Vec::new();
                if let Some(retired) = &callback_retired
                    && retired.generation_id != callback_generation
                    && callback_previous
                        .as_ref()
                        .is_none_or(|previous| previous.generation_id != retired.generation_id)
                {
                    retired_keys = complete_generation_keys(
                        &callback_scope,
                        &retired.generation_id,
                    );
                    for key in &retired_keys {
                        derived.push((ColumnFamily::Kernel, key.clone(), tombstone_value()));
                    }
                }
                Ok((derived, (manifest, pointer, retired_keys)))
            },
        )
        .map_err(|error| {
            persist_error(format!(
                "fleet atomic commit refused: underlying_code={} message={:?} remediation={:?}",
                error.code, error.message, error.remediation,
            ))
        })?;
    if commit.seq != predicted_commit_seq
        || commit.ledger_ref != manifest.ledger_ref
        || commit.ledger_ref != pointer.current.ledger_ref
    {
        return Err(persist_error(format!(
            "fleet commit receipt differs: predicted_seq={predicted_commit_seq} observed_seq={} commit_ledger={:?} manifest_ledger={:?} pointer_ledger={:?}",
            commit.seq, commit.ledger_ref, manifest.ledger_ref, pointer.current.ledger_ref,
        )));
    }
    let flush = vault.flush_with_report().map_err(|error| {
        persist_error(format!(
            "flush fleet generation: underlying_code={} message={:?} remediation={:?}",
            error.code, error.message, error.remediation,
        ))
    })?;
    let _commit_rows_readback_verified =
        verify_commit_rows(vault, commit.seq, &commit.data_row_digests)?;
    verify_retired_rows(vault, commit.seq, &retired_keys)?;
    let current = read_current_fleet_kernel_generation_at(vault, commit.seq, scope_id)?
        .ok_or_else(|| persist_error("fleet current pointer absent after atomic commit"))?;
    if current.manifest != manifest
        || current.pointer != pointer
        || current.source_roster != *source_roster
        || current.graph_record != graph_record
        || current.vectors != *complete_vectors
        || current.artifact != *artifact
        || current.provenance != *provenance
        || current.index.descriptor != index_descriptor
        || current.index.bindings != index_bindings
        || current.admission != *admission
        || current.query_corpus != query_corpus
        || current.graph_routed_report != report
    {
        return Err(persist_error(format!(
            "decoded fleet generation readback differs after commit: generation={generation_id}"
        )));
    }
    verify_retained_previous_at(vault, commit.seq, scope_id, &pointer)?;
    let (ledger_physical_tiers, physical_ref) = verify_physical_ledger(vault, scope_id, &manifest)?;
    if physical_ref != commit.ledger_ref {
        return Err(persist_error(
            "fleet physical Ledger row differs from the group-commit receipt",
        ));
    }
    Ok(FleetKernelGenerationPersistReport {
        published: true,
        commit_seq: commit.seq,
        generation_id,
        source_generation_identity,
        manifest,
        pointer,
        ledger_ref: commit.ledger_ref,
        ledger_physical_tiers,
        rows_readback_verified: current.rows_verified,
        member_count: artifact.member_count,
        graph_node_count: graph_record.nodes.len(),
        query_count: query_corpus.queries.len(),
        recall_permille: report.recall_permille,
        graph_routed_report_hash: report.report_hash.clone(),
        vector_roster_hash: vector_roster.vector_roster_hash.clone(),
        retired_generation_id,
        flush_sst_files: flush.sst_files(),
        flush_sst_entries: flush.sst_entries(),
        flush_sst_bytes: flush.sst_bytes(),
    })
}

/// Reads and independently verifies the complete current fleet generation.
/// The read opens no repository vault and scans no Ledger history; callers that
/// claim current external-source freshness must additionally recompute and
/// compare [`FleetKernelSourceRoster`] through
/// [`verify_fleet_source_roster_exact`].
pub fn read_current_fleet_kernel_generation<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
) -> Result<Option<CurrentFleetKernelGeneration>, CalyxError>
where
    C: Clock,
{
    let lease = vault.retain_latest_snapshot();
    let snapshot = lease.seq();
    let current = read_current_fleet_kernel_generation_at(vault, snapshot, scope_id)?;
    lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(corrupt_error(format!(
            "fleet catalog moved during current-generation read: retained_seq={snapshot} observed_seq={}",
            vault.latest_seq(),
        )));
    }
    Ok(current)
}

/// Reads only the current pointer, its content-addressed manifest, and the
/// exact physical Ledger row. It never scans generation rows or Ledger history.
/// A caller may use this solely to prove that an already fully verified,
/// immutable cached generation remains the selected generation.
pub fn read_current_fleet_kernel_generation_header<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
) -> Result<Option<FleetKernelGenerationHeader>, CalyxError>
where
    C: Clock,
{
    let lease = vault.retain_latest_snapshot();
    let snapshot = lease.seq();
    let header = read_header_at(vault, snapshot, scope_id)?;
    lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(corrupt_error(format!(
            "fleet catalog moved during narrow header read: retained_seq={snapshot} observed_seq={}",
            vault.latest_seq(),
        )));
    }
    let Some((pointer, manifest)) = header else {
        return Ok(None);
    };
    let (ledger_physical_tiers, physical_ref) = verify_physical_ledger(vault, scope_id, &manifest)?;
    if physical_ref != manifest.ledger_ref || manifest.ledger_ref != pointer.current.ledger_ref {
        return Err(corrupt_error(
            "fleet warm-header pointer/manifest/physical-Ledger identities differ",
        ));
    }
    if vault.latest_seq() != snapshot {
        return Err(corrupt_error(format!(
            "fleet catalog moved during narrow header read: retained_seq={snapshot} observed_seq={}",
            vault.latest_seq(),
        )));
    }
    Ok(Some(FleetKernelGenerationHeader {
        manifest,
        pointer,
        ledger_physical_tiers,
    }))
}

/// Explicitly deep-verifies the current generation's bounded retention chain.
/// Ordinary current serving deliberately does not pay this predecessor-row
/// cost; publication/no-op readback and manual FSV/history inspection call this
/// boundary when predecessor integrity is the question being answered.
pub fn verify_fleet_kernel_generation_retention<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
) -> Result<Option<FleetKernelGenerationPointer>, CalyxError>
where
    C: Clock,
{
    let lease = vault.retain_latest_snapshot();
    let snapshot = lease.seq();
    let Some((pointer, manifest)) = read_header_at(vault, snapshot, scope_id)? else {
        return Ok(None);
    };
    let (_, physical_ref) = verify_physical_ledger(vault, scope_id, &manifest)?;
    if physical_ref != manifest.ledger_ref || manifest.ledger_ref != pointer.current.ledger_ref {
        return Err(corrupt_error(
            "fleet retention verification found different current pointer/manifest/physical-Ledger identities",
        ));
    }
    verify_retained_previous_at(vault, snapshot, scope_id, &pointer)?;
    if let Some(retired_generation_id) = &manifest.retired_generation_id {
        let retired_keys = complete_generation_keys(scope_id, retired_generation_id);
        verify_retired_rows(vault, pointer.current.commit_seq, &retired_keys)?;
    }
    lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(corrupt_error(format!(
            "fleet catalog moved during explicit retention verification: retained_seq={snapshot} observed_seq={}",
            vault.latest_seq(),
        )));
    }
    Ok(Some(pointer))
}

/// Compares a freshly recomputed source roster with the immutable generation
/// roster. This is the independent multi-vault freshness boundary used by
/// compose no-op, CLI readback, retirement, and the cold serving load.
pub fn verify_fleet_source_roster_exact(
    expected: &FleetKernelSourceRoster,
    observed: &FleetKernelSourceRoster,
) -> Result<(), CalyxError> {
    validate_source_roster(expected)?;
    validate_source_roster(observed)?;
    if expected != observed {
        return Err(CalyxError {
            code: ASTRO_FLEET_GENERATION_SOURCE_DRIFT,
            message: format!(
                "fleet source roster changed: expected_hash={} observed_hash={} expected_compose={} observed_compose={} expected_repos={} observed_repos={}",
                expected.source_roster_hash,
                observed.source_roster_hash,
                expected.compose_input_hash,
                observed.compose_input_hash,
                expected.repositories.len(),
                observed.repositories.len(),
            ),
            remediation: "discard the stale read, recompose from the exact current repository generations and genuine query admission, then retry",
        });
    }
    Ok(())
}

fn read_current_fleet_kernel_generation_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    scope_id: &str,
) -> Result<Option<CurrentFleetKernelGeneration>, CalyxError>
where
    C: Clock,
{
    let Some((pointer, manifest)) = read_header_at(vault, snapshot, scope_id)? else {
        return Ok(None);
    };
    let row_bytes = read_manifest_rows_at(vault, snapshot, scope_id, &manifest)?;
    let source_roster_bytes = row(&row_bytes, LOGICAL_SOURCE_ROSTER)?;
    let graph_bytes = row(&row_bytes, LOGICAL_GRAPH)?;
    let vector_bytes = row(&row_bytes, LOGICAL_VECTORS)?;
    let artifact_bytes = row(&row_bytes, LOGICAL_KERNEL)?;
    let provenance_bytes = row(&row_bytes, LOGICAL_PROVENANCE)?;
    let index_bytes = row(&row_bytes, LOGICAL_INDEX)?;
    let binding_bytes = row(&row_bytes, LOGICAL_BINDINGS)?;
    let hnsw_bytes = row(&row_bytes, LOGICAL_HNSW)?;
    let admission_bytes = row(&row_bytes, LOGICAL_ADMISSION)?;
    let query_bytes = row(&row_bytes, LOGICAL_QUERY_CORPUS)?;
    let report_bytes = row(&row_bytes, LOGICAL_RECALL_REPORT)?;

    let source_roster: FleetKernelSourceRoster = decode_json(source_roster_bytes, "source roster")?;
    validate_source_roster(&source_roster)?;
    let graph_record: FleetKernelGraphRecord = decode_json(graph_bytes, "fleet graph")?;
    let graph = graph_record.to_graph()?;
    let vector_roster: FleetVectorRoster = decode_json(vector_bytes, "vector roster")?;
    let vectors = vector_roster.to_vectors()?;
    if source_roster.canonical_json_bytes()?.as_slice() != source_roster_bytes.as_slice()
        || graph_record.canonical_json_bytes()?.as_slice() != graph_bytes.as_slice()
        || vector_roster.canonical_json_bytes()?.as_slice() != vector_bytes.as_slice()
    {
        return Err(corrupt_error(
            "fleet source-roster, graph, or complete-vector row is not canonical JSON",
        ));
    }
    let artifact: KernelArtifact = decode_json(artifact_bytes, "kernel artifact")?;
    if artifact.kernel_json_bytes().as_slice() != artifact_bytes.as_slice() {
        return Err(corrupt_error(
            "fleet kernel.json is not canonical under the sole artifact serializer",
        ));
    }
    let provenance: FleetMemberProvenanceRoster =
        decode_json(provenance_bytes, "member provenance")?;
    validate_provenance(&provenance)?;
    if provenance.canonical_json_bytes()?.as_slice() != provenance_bytes.as_slice() {
        return Err(corrupt_error(
            "fleet member-provenance row is not canonical JSON",
        ));
    }
    let index_descriptor: FleetKernelMemberIndexDescriptor =
        decode_json(index_bytes, "member-index descriptor")?;
    let bindings: Vec<KernelMemberBinding> = decode_json(binding_bytes, "member bindings")?;
    if canonical_json(&index_descriptor, "fleet member-index descriptor")?.as_slice()
        != index_bytes.as_slice()
        || canonical_json(&bindings, "fleet member bindings")?.as_slice()
            != binding_bytes.as_slice()
    {
        return Err(corrupt_error(
            "fleet index descriptor or bindings are not canonical JSON bytes",
        ));
    }
    let index = load_member_index(
        index_descriptor,
        bindings,
        binding_bytes,
        hnsw_bytes.clone(),
    )?;
    verify_member_index_vectors(&index, &vectors)?;
    let admission: FleetKernelAdmissionInput = decode_json(admission_bytes, "admission input")?;
    admission.validate()?;
    if admission.canonical_json_bytes()?.as_slice() != admission_bytes.as_slice()
        || admission.identity_blake3()? != manifest.admission_input_blake3
        || admission.index_knobs != index.descriptor.knobs
    {
        return Err(corrupt_error(
            "fleet admission row is noncanonical or differs from manifest/index controls",
        ));
    }
    let query_corpus: KernelRecallQueryCorpus = decode_json(query_bytes, "query corpus")?;
    if query_corpus
        .canonical_json_bytes()
        .map_err(|error| corrupt_error(format!("validate fleet query corpus: {error}")))?
        .as_slice()
        != query_bytes.as_slice()
    {
        return Err(corrupt_error(
            "fleet real-query corpus is not canonical under its sole serializer",
        ));
    }
    validate_kernel_recall_query_corpus_encoder(&query_corpus).map_err(|error| {
        corrupt_error(format!(
            "fleet query encoder readback failed: code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation(),
        ))
    })?;
    let rebuilt_query_corpus = build_kernel_recall_query_corpus(
        "fleet",
        scope_id,
        source_roster.panel_version,
        &admission.queries,
        admission.params.clone(),
    )
    .map_err(|error| {
        corrupt_error(format!(
            "re-encode fleet admission rows: code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation(),
        ))
    })?;
    if rebuilt_query_corpus != query_corpus {
        return Err(corrupt_error(
            "fleet real-query corpus differs from the exact persisted external admission rows",
        ));
    }
    let report: GraphRoutedRecallReport = decode_json(report_bytes, "routed-recall report")?;
    if report
        .canonical_json_bytes()
        .map_err(|error| corrupt_error(format!("validate fleet routed-recall report: {error}")))?
        .as_slice()
        != report_bytes.as_slice()
    {
        return Err(corrupt_error(
            "fleet routed-recall report is not canonical under its sole serializer",
        ));
    }

    let graph_ids = graph.nodes().iter().map(|node| node.id).collect::<Vec<_>>();
    let vector_ids = vectors.keys().copied().collect::<Vec<_>>();
    let artifact_ids = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let provenance_ids = provenance
        .members
        .iter()
        .map(|member| member.fleet_cx)
        .collect::<Vec<_>>();
    let index_ids = index
        .bindings
        .iter()
        .map(|binding| binding.cx_id)
        .collect::<Vec<_>>();
    let observed_source_identity = kernel_source_identity(&graph, &artifact.config)
        .map_err(|error| corrupt_error(format!("recompute fleet kernel identity: {error}")))?;
    if source_roster.scope_id != scope_id
        || artifact.scope_id != scope_id
        || query_corpus.scope_id != scope_id
        || admission.params != query_corpus.params
        || admission.queries.len() != query_corpus.queries.len()
        || graph_ids != vector_ids
        || artifact_ids != provenance_ids
        || artifact_ids != index_ids
        || members_hash(&artifact_ids) != artifact.members_hash
        || observed_source_identity != artifact.source_identity
    {
        return Err(corrupt_error(format!(
            "fleet decoded generation joins disagree: scope={scope_id:?} roster_scope={:?} artifact_scope={:?} query_scope={:?} graph_nodes={} vectors={} artifact_members={} provenance={} index={} source_expected={} source_observed={}",
            source_roster.scope_id,
            artifact.scope_id,
            query_corpus.scope_id,
            graph_ids.len(),
            vector_ids.len(),
            artifact_ids.len(),
            provenance_ids.len(),
            index_ids.len(),
            artifact.source_identity.combined_hash,
            observed_source_identity.combined_hash,
        )));
    }
    validate_graph_routed_recall_report(
        &report,
        &graph,
        &artifact,
        &vectors,
        &query_corpus.graph_routed_queries(),
        &query_corpus.params,
    )
    .map_err(|error| {
        corrupt_error(format!(
            "rebuild fleet routed-recall report: code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation(),
        ))
    })?;

    validate_manifest_decoded(
        scope_id,
        &manifest,
        &source_roster,
        &graph_record,
        &vector_roster,
        &artifact,
        &provenance,
        &index.descriptor,
        &admission,
        &query_corpus,
        &report,
    )?;
    let (ledger_physical_tiers, _) = verify_physical_ledger(vault, scope_id, &manifest)?;
    Ok(Some(CurrentFleetKernelGeneration {
        source_roster,
        graph_record,
        graph,
        vectors,
        artifact,
        provenance,
        index,
        admission,
        query_corpus,
        graph_routed_report: report,
        manifest,
        pointer,
        rows_verified: row_bytes.len(),
        ledger_physical_tiers,
    }))
}

// This verifier intentionally names every independently decoded immutable row;
// bundling them would make an unverified aggregate look like one trusted input.
#[allow(clippy::too_many_arguments)]
fn validate_manifest_decoded(
    scope_id: &str,
    manifest: &FleetKernelGenerationManifest,
    source_roster: &FleetKernelSourceRoster,
    graph: &FleetKernelGraphRecord,
    vectors: &FleetVectorRoster,
    artifact: &KernelArtifact,
    provenance: &FleetMemberProvenanceRoster,
    index: &FleetKernelMemberIndexDescriptor,
    admission: &FleetKernelAdmissionInput,
    query: &KernelRecallQueryCorpus,
    report: &GraphRoutedRecallReport,
) -> Result<(), CalyxError> {
    if manifest.schema != FLEET_KERNEL_GENERATION_MANIFEST_SCHEMA
        || manifest.scope_id != scope_id
        || manifest.compose_input_hash != source_roster.compose_input_hash
        || manifest.source_roster_hash != source_roster.source_roster_hash
        || manifest.graph_hash != graph.graph_hash
        || manifest.vector_roster_hash != vectors.vector_roster_hash
        || manifest.artifact_source_identity != artifact.source_identity
        || manifest.members_hash != artifact.members_hash
        || manifest.member_count != artifact.member_count
        || manifest.graph_node_count != graph.nodes.len()
        || manifest.graph_edge_count != graph.edges.len()
        || manifest.panel_version != source_roster.panel_version
        || manifest.semantic_dim != source_roster.semantic_dim
        || manifest.provenance_hash != provenance.provenance_hash
        || index.scope_id != scope_id
        || index.members_hash != artifact.members_hash
        || index.panel_version != source_roster.panel_version
        || index.semantic_dim != source_roster.semantic_dim
        || index.member_count != artifact.member_count
        || manifest.index_bindings_blake3 != index.bindings_blake3
        || manifest.index_hnsw_blake3 != index.hnsw_artifact_blake3
        || index.vector_roster_hash != vectors.vector_roster_hash
        || manifest.admission_input_blake3 != admission.identity_blake3()?
        || admission.index_knobs != index.knobs
        || admission.params != query.params
        || admission.queries.len() != query.queries.len()
        || manifest.query_encoder_identity_hash != query.encoder.identity_hash
        || manifest.query_corpus_hash != query.corpus_hash
        || manifest.graph_routed_report_hash != report.report_hash
        || !is_hash(&manifest.admission_input_blake3)
        || manifest.retention
            != "bounded_current_plus_previous; superseded immutable generation rows are tombstoned in the pointer commit"
    {
        return Err(corrupt_error(format!(
            "fleet manifest differs from decoded immutable rows: generation={} scope={:?}",
            manifest.generation_id, manifest.scope_id,
        )));
    }
    let observed_source = stable_source_identity(
        scope_id,
        source_roster,
        graph,
        vectors,
        artifact,
        provenance,
        index,
        query,
        report,
        &manifest.admission_input_blake3,
    )?;
    if observed_source != manifest.source_generation_identity {
        return Err(corrupt_error(format!(
            "fleet stable source identity differs: expected={} observed={observed_source}",
            manifest.source_generation_identity,
        )));
    }
    Ok(())
}

fn read_header_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    scope_id: &str,
) -> Result<Option<(FleetKernelGenerationPointer, FleetKernelGenerationManifest)>, CalyxError>
where
    C: Clock,
{
    let Some(bytes) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Kernel,
        &generation_current_key(scope_id),
    )?
    else {
        return Ok(None);
    };
    let pointer: FleetKernelGenerationPointer = decode_json(&bytes, "current pointer")?;
    if serde_json::to_vec(&pointer)
        .map_err(|error| corrupt_error(format!("re-encode fleet current pointer: {error}")))?
        != bytes
    {
        return Err(corrupt_error(
            "fleet current pointer is not canonical compact JSON",
        ));
    }
    validate_pointer(&pointer, scope_id, snapshot)?;
    let manifest = read_manifest_target(vault, snapshot, scope_id, &pointer.current)?;
    if manifest.previous_generation_id
        != pointer
            .previous
            .as_ref()
            .map(|target| target.generation_id.clone())
    {
        return Err(corrupt_error(
            "fleet manifest previous-generation id differs from the current pointer",
        ));
    }
    Ok(Some((pointer, manifest)))
}

fn validate_pointer(
    pointer: &FleetKernelGenerationPointer,
    scope_id: &str,
    snapshot: u64,
) -> Result<(), CalyxError> {
    if pointer.schema != FLEET_KERNEL_GENERATION_POINTER_SCHEMA
        || pointer.scope_id != scope_id
        || !is_hash(&pointer.current.generation_id)
        || !is_hash(&pointer.current.manifest_blake3)
        || pointer.retained_generation_count != usize::from(pointer.previous.is_some()) + 1
        || pointer.retained_generation_count == 0
        || pointer.retained_generation_count > 2
        || pointer.current.commit_seq == 0
        || pointer.current.commit_seq > snapshot
        || pointer.previous.as_ref().is_some_and(|previous| {
            previous.generation_id == pointer.current.generation_id
                || !is_hash(&previous.generation_id)
                || !is_hash(&previous.manifest_blake3)
                || previous.commit_seq == 0
                || previous.commit_seq >= pointer.current.commit_seq
        })
    {
        return Err(corrupt_error(format!(
            "fleet current pointer is invalid: schema={:?} scope={:?} current={} previous={:?} retained={} snapshot={snapshot} current_commit_seq={}",
            pointer.schema,
            pointer.scope_id,
            pointer.current.generation_id,
            pointer
                .previous
                .as_ref()
                .map(|target| target.generation_id.as_str()),
            pointer.retained_generation_count,
            pointer.current.commit_seq,
        )));
    }
    Ok(())
}

fn read_manifest_target<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    scope_id: &str,
    target: &FleetGenerationPointerTarget,
) -> Result<FleetKernelGenerationManifest, CalyxError>
where
    C: Clock,
{
    let key = generation_manifest_key(scope_id, &target.generation_id);
    if target.manifest_key_hex != hex_lower(&key) || target.commit_seq > snapshot {
        return Err(corrupt_error(format!(
            "fleet manifest target key/sequence is invalid: generation={} commit_seq={} snapshot={snapshot}",
            target.generation_id, target.commit_seq,
        )));
    }
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &key)?
        .ok_or_else(|| {
            corrupt_error(format!("fleet manifest {} is absent", target.generation_id,))
        })?;
    if blake3_hex(&bytes) != target.manifest_blake3 {
        return Err(corrupt_error(format!(
            "fleet manifest {} hash differs from pointer",
            target.generation_id,
        )));
    }
    let manifest: FleetKernelGenerationManifest = decode_json(&bytes, "generation manifest")?;
    if serde_json::to_vec(&manifest)
        .map_err(|error| corrupt_error(format!("re-encode fleet manifest: {error}")))?
        != bytes
    {
        return Err(corrupt_error(
            "fleet generation manifest is not canonical compact JSON",
        ));
    }
    validate_manifest_shape(scope_id, &manifest)?;
    let expected_commit_seq = manifest
        .base_seq
        .checked_add(1)
        .ok_or_else(|| corrupt_error("fleet manifest base sequence cannot advance"))?;
    if manifest.generation_id != target.generation_id
        || manifest.ledger_ref != target.ledger_ref
        || target.commit_seq != expected_commit_seq
    {
        return Err(corrupt_error(format!(
            "fleet manifest target identity differs: target={} manifest={}",
            target.generation_id, manifest.generation_id,
        )));
    }
    Ok(manifest)
}

fn validate_manifest_shape(
    scope_id: &str,
    manifest: &FleetKernelGenerationManifest,
) -> Result<(), CalyxError> {
    let logical = manifest
        .rows
        .iter()
        .map(|row| row.logical_name.as_str())
        .collect::<Vec<_>>();
    if manifest.schema != FLEET_KERNEL_GENERATION_MANIFEST_SCHEMA
        || manifest.scope_id != scope_id
        || !is_hash(&manifest.generation_id)
        || !is_hash(&manifest.source_generation_identity)
        || !is_hash(&manifest.compose_input_hash)
        || !is_hash(&manifest.admission_input_blake3)
        || !is_hash(&manifest.source_roster_hash)
        || !is_hash(&manifest.graph_hash)
        || !is_hash(&manifest.vector_roster_hash)
        || !is_hash(&manifest.members_hash)
        || !is_hash(&manifest.provenance_hash)
        || !is_hash(&manifest.index_bindings_blake3)
        || !is_hash(&manifest.index_hnsw_blake3)
        || !is_hash(&manifest.query_encoder_identity_hash)
        || !is_hash(&manifest.query_corpus_hash)
        || !is_hash(&manifest.graph_routed_report_hash)
        || !is_hash(&manifest.ledger_payload_blake3)
        || manifest
            .previous_generation_id
            .as_deref()
            .is_some_and(|generation| !is_hash(generation) || generation == manifest.generation_id)
        || manifest
            .retired_generation_id
            .as_deref()
            .is_some_and(|generation| {
                !is_hash(generation)
                    || generation == manifest.generation_id
                    || manifest.previous_generation_id.as_deref() == Some(generation)
            })
        || manifest.member_count == 0
        || manifest.graph_node_count == 0
        || manifest.panel_version == 0
        || manifest.semantic_dim == 0
        || logical != LOGICAL_NAMES
    {
        return Err(corrupt_error(format!(
            "fleet manifest shape is invalid: generation={} rows={logical:?}",
            manifest.generation_id,
        )));
    }
    let observed_generation = content_generation_id_from_bindings(
        scope_id,
        &manifest.source_generation_identity,
        manifest.previous_generation_id.as_deref(),
        &manifest.rows,
    );
    if observed_generation != manifest.generation_id {
        return Err(corrupt_error(format!(
            "fleet generation content address differs: expected={} observed={observed_generation}",
            manifest.generation_id,
        )));
    }
    Ok(())
}

fn read_manifest_rows_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    scope_id: &str,
    manifest: &FleetKernelGenerationManifest,
) -> Result<BTreeMap<String, Vec<u8>>, CalyxError>
where
    C: Clock,
{
    validate_manifest_shape(scope_id, manifest)?;
    let mut rows = BTreeMap::new();
    for binding in &manifest.rows {
        let key = generation_row_key(
            scope_id,
            &manifest.generation_id,
            binding.logical_name.as_bytes(),
        );
        if binding.key_hex != hex_lower(&key) {
            return Err(corrupt_error(format!(
                "fleet generation row {:?} key differs from schema",
                binding.logical_name,
            )));
        }
        let bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Kernel, &key)?
            .ok_or_else(|| {
                corrupt_error(format!(
                    "fleet generation row {:?} is absent",
                    binding.logical_name,
                ))
            })?;
        if bytes.len() as u128 != u128::from(binding.bytes)
            || blake3_hex(&bytes) != binding.blake3
            || rows.insert(binding.logical_name.clone(), bytes).is_some()
        {
            return Err(corrupt_error(format!(
                "fleet generation row {:?} length/hash/name differs",
                binding.logical_name,
            )));
        }
    }
    Ok(rows)
}

fn verify_manifest_rows_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    scope_id: &str,
    manifest: &FleetKernelGenerationManifest,
) -> Result<(), CalyxError>
where
    C: Clock,
{
    let _ = read_manifest_rows_at(vault, snapshot, scope_id, manifest)?;
    Ok(())
}

fn verify_retained_previous_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    scope_id: &str,
    pointer: &FleetKernelGenerationPointer,
) -> Result<(), CalyxError>
where
    C: Clock,
{
    if let Some(previous) = &pointer.previous {
        let manifest = read_manifest_target(vault, snapshot, scope_id, previous)?;
        verify_manifest_rows_at(vault, snapshot, scope_id, &manifest)?;
        let _ = verify_physical_ledger(vault, scope_id, &manifest)?;
    }
    Ok(())
}

// The content identity preimage is kept as an explicit field roster so adding
// a persisted source cannot silently omit it behind a loosely typed aggregate.
#[allow(clippy::too_many_arguments)]
fn stable_source_identity(
    scope_id: &str,
    source_roster: &FleetKernelSourceRoster,
    graph: &FleetKernelGraphRecord,
    vectors: &FleetVectorRoster,
    artifact: &KernelArtifact,
    provenance: &FleetMemberProvenanceRoster,
    index: &FleetKernelMemberIndexDescriptor,
    query: &KernelRecallQueryCorpus,
    report: &GraphRoutedRecallReport,
    admission_input_blake3: &str,
) -> Result<String, CalyxError> {
    let value = serde_json::json!({
        "schema": "astrolabe.fleet_kernel_stable_source.v1",
        "scope_id": scope_id,
        "compose_input_hash": source_roster.compose_input_hash,
        "source_roster_hash": source_roster.source_roster_hash,
        "graph_hash": graph.graph_hash,
        "vector_roster_hash": vectors.vector_roster_hash,
        "artifact_source_identity": artifact.source_identity,
        "artifact_blake3": blake3_hex(&artifact.kernel_json_bytes()),
        "members_hash": artifact.members_hash,
        "member_count": artifact.member_count,
        "provenance_hash": provenance.provenance_hash,
        "index_bindings_blake3": index.bindings_blake3,
        "index_hnsw_blake3": index.hnsw_artifact_blake3,
        "index_knobs": index.knobs,
        "panel_version": source_roster.panel_version,
        "semantic_dim": source_roster.semantic_dim,
        "admission_input_blake3": admission_input_blake3,
        "query_encoder_identity_hash": query.encoder.identity_hash,
        "query_corpus_hash": query.corpus_hash,
        "graph_routed_report_hash": report.report_hash,
    });
    Ok(blake3_hex(&serde_json::to_vec(&value).map_err(
        |error| incomplete_error(format!("encode fleet stable source identity: {error}")),
    )?))
}

// Each argument is one separately serialized logical generation row; keeping
// the roster explicit makes row-order/content-address coverage reviewable.
#[allow(clippy::too_many_arguments)]
fn prepare_rows(
    scope_id: &str,
    generation_id: &str,
    source_roster: Vec<u8>,
    graph: Vec<u8>,
    vectors: Vec<u8>,
    artifact: Vec<u8>,
    provenance: Vec<u8>,
    index: Vec<u8>,
    bindings: Vec<u8>,
    hnsw: Vec<u8>,
    admission: Vec<u8>,
    query: Vec<u8>,
    report: Vec<u8>,
) -> Vec<PreparedRow> {
    [
        (LOGICAL_SOURCE_ROSTER, source_roster),
        (LOGICAL_GRAPH, graph),
        (LOGICAL_VECTORS, vectors),
        (LOGICAL_KERNEL, artifact),
        (LOGICAL_PROVENANCE, provenance),
        (LOGICAL_INDEX, index),
        (LOGICAL_BINDINGS, bindings),
        (LOGICAL_HNSW, hnsw),
        (LOGICAL_ADMISSION, admission),
        (LOGICAL_QUERY_CORPUS, query),
        (LOGICAL_RECALL_REPORT, report),
    ]
    .into_iter()
    .map(|(logical_name, value)| PreparedRow {
        logical_name,
        key: generation_row_key(scope_id, generation_id, logical_name.as_bytes()),
        value,
    })
    .collect()
}

fn content_generation_id(
    scope_id: &str,
    source_generation_identity: &str,
    previous_generation_id: Option<&str>,
    rows: &[PreparedRow],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_frame(&mut hasher, b"astrolabe.fleet_kernel_generation_content.v2");
    hash_frame(&mut hasher, scope_id.as_bytes());
    hash_frame(&mut hasher, source_generation_identity.as_bytes());
    hash_frame(&mut hasher, previous_generation_id.unwrap_or("").as_bytes());
    for row in rows {
        hash_frame(&mut hasher, row.logical_name.as_bytes());
        hash_frame(&mut hasher, &(row.value.len() as u64).to_be_bytes());
        hash_frame(&mut hasher, blake3_hex(&row.value).as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn content_generation_id_from_bindings(
    scope_id: &str,
    source_generation_identity: &str,
    previous_generation_id: Option<&str>,
    rows: &[FleetGenerationRowBinding],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_frame(&mut hasher, b"astrolabe.fleet_kernel_generation_content.v2");
    hash_frame(&mut hasher, scope_id.as_bytes());
    hash_frame(&mut hasher, source_generation_identity.as_bytes());
    hash_frame(&mut hasher, previous_generation_id.unwrap_or("").as_bytes());
    for row in rows {
        hash_frame(&mut hasher, row.logical_name.as_bytes());
        hash_frame(&mut hasher, &row.bytes.to_be_bytes());
        hash_frame(&mut hasher, row.blake3.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn generation_subject(scope_id: &str, generation_id: &str) -> SubjectId {
    SubjectId::Query(format!("fleet-kernel-generation:{scope_id}:{generation_id}").into_bytes())
}

fn generation_row_key(scope_id: &str, generation_id: &str, leaf: &[u8]) -> Vec<u8> {
    let mut key = FLEET_KERNEL_GENERATION_PREFIX.to_vec();
    append_part(&mut key, scope_id.as_bytes());
    append_part(&mut key, generation_id.as_bytes());
    append_part(&mut key, leaf);
    key
}

fn generation_manifest_key(scope_id: &str, generation_id: &str) -> Vec<u8> {
    generation_row_key(scope_id, generation_id, MANIFEST_LEAF)
}

fn generation_current_key(scope_id: &str) -> Vec<u8> {
    let mut key = FLEET_KERNEL_CURRENT_PREFIX.to_vec();
    append_part(&mut key, scope_id.as_bytes());
    append_part(&mut key, CURRENT_LEAF);
    key
}

fn complete_generation_keys(scope_id: &str, generation_id: &str) -> Vec<Vec<u8>> {
    LOGICAL_NAMES
        .iter()
        .map(|leaf| generation_row_key(scope_id, generation_id, leaf.as_bytes()))
        .chain(std::iter::once(generation_manifest_key(
            scope_id,
            generation_id,
        )))
        .collect()
}

fn verify_commit_rows<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    digests: &[calyx_aster::vault::LedgerBoundRowDigest],
) -> Result<usize, CalyxError>
where
    C: Clock,
{
    for digest in digests {
        if digest.cf != ColumnFamily::Kernel {
            return Err(persist_error(format!(
                "fleet commit receipt includes unexpected CF {}",
                digest.cf.name(),
            )));
        }
        let logical = vault.read_cf_at(snapshot, digest.cf, &digest.key)?;
        if digest.tombstoned {
            if logical.is_some() {
                return Err(persist_error(format!(
                    "tombstoned fleet row {} remains logically visible",
                    hex_lower(&digest.key),
                )));
            }
        } else {
            let value = logical.ok_or_else(|| {
                persist_error(format!(
                    "fleet commit row {} is absent after flush",
                    hex_lower(&digest.key),
                ))
            })?;
            if *blake3::hash(&value).as_bytes() != digest.value_blake3 {
                return Err(persist_error(format!(
                    "fleet commit row {} BLAKE3 differs from receipt",
                    hex_lower(&digest.key),
                )));
            }
        }
    }
    Ok(digests.len())
}

fn verify_retired_rows<C>(
    vault: &AsterVault<C>,
    commit_seq: u64,
    retired_keys: &[Vec<u8>],
) -> Result<(), CalyxError>
where
    C: Clock,
{
    if retired_keys.is_empty() {
        return Ok(());
    }
    let inventory = vault.physical_commit_inventory(
        commit_seq,
        &[
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    let tombstone = tombstone_value();
    let tombstone_hash = Sha256::digest(&tombstone);
    for key in retired_keys {
        if vault
            .read_cf_at(commit_seq, ColumnFamily::Kernel, key)?
            .is_some()
        {
            return Err(persist_error(format!(
                "retired fleet row {} remains logically visible",
                hex_lower(key),
            )));
        }
        let matches = inventory
            .rows
            .iter()
            .filter(|row| row.cf == ColumnFamily::Kernel && row.key == *key)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(persist_error(format!(
                "retired fleet row {} occurs {} times in the exact physical commit inventory",
                hex_lower(key),
                matches.len(),
            )));
        }
        let row = matches[0];
        if !row.tombstoned
            || row.value_length != tombstone.len() as u64
            || row.value_sha256.as_slice() != tombstone_hash.as_slice()
        {
            return Err(persist_error(format!(
                "retired fleet row {} physical digest is not the exact tombstone: ordinal={} tombstoned={} bytes={} sha256={}",
                hex_lower(key),
                row.ordinal,
                row.tombstoned,
                row.value_length,
                row.value_sha256_hex(),
            )));
        }
    }
    Ok(())
}

fn verify_physical_ledger<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
    manifest: &FleetKernelGenerationManifest,
) -> Result<(Vec<String>, LedgerRef), CalyxError>
where
    C: Clock,
{
    let wanted = BTreeSet::from([manifest.ledger_ref.seq]);
    let (rows, trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let row = rows.get(&manifest.ledger_ref.seq).ok_or_else(|| {
        corrupt_error(format!(
            "fleet physical Ledger row {} is absent",
            manifest.ledger_ref.seq,
        ))
    })?;
    let entry = calyx_ledger::decode(&row.bytes)?;
    let expected_payload = serde_json::to_vec(&serde_json::json!({
        "schema": FLEET_KERNEL_GENERATION_LEDGER_SCHEMA,
        "scope_id": manifest.scope_id,
        "generation_id": manifest.generation_id,
        "source_generation_identity": manifest.source_generation_identity,
        "base_seq": manifest.base_seq,
        "compose_input_hash": manifest.compose_input_hash,
        "admission_input_blake3": manifest.admission_input_blake3,
        "source_roster_hash": manifest.source_roster_hash,
        "graph_hash": manifest.graph_hash,
        "vector_roster_hash": manifest.vector_roster_hash,
        "artifact_source_identity": manifest.artifact_source_identity,
        "members_hash": manifest.members_hash,
        "member_count": manifest.member_count,
        "graph_node_count": manifest.graph_node_count,
        "graph_edge_count": manifest.graph_edge_count,
        "panel_version": manifest.panel_version,
        "semantic_dim": manifest.semantic_dim,
        "provenance_hash": manifest.provenance_hash,
        "index_bindings_blake3": manifest.index_bindings_blake3,
        "index_hnsw_blake3": manifest.index_hnsw_blake3,
        "query_encoder_identity_hash": manifest.query_encoder_identity_hash,
        "query_corpus_hash": manifest.query_corpus_hash,
        "graph_routed_report_hash": manifest.graph_routed_report_hash,
        "rows": manifest.rows,
        "previous_generation_id": manifest.previous_generation_id,
        "retired_generation_id": manifest.retired_generation_id,
    }))
    .map_err(|error| corrupt_error(format!("rebuild fleet Ledger payload: {error}")))?;
    if row.seq != manifest.ledger_ref.seq
        || entry.seq != manifest.ledger_ref.seq
        || entry.entry_hash != manifest.ledger_ref.hash
        || !entry.verify()
        || entry.kind != EntryKind::Kernel
        || entry.actor != ActorId::Service(FLEET_KERNEL_GENERATION_ACTOR.to_string())
        || entry.subject != generation_subject(scope_id, &manifest.generation_id)
        || entry.payload != expected_payload
        || blake3_hex(&entry.payload) != manifest.ledger_payload_blake3
    {
        return Err(corrupt_error(format!(
            "fleet physical Ledger identity differs: generation={} expected_seq={} observed_seq={} expected_hash={} observed_hash={} expected_payload={} observed_payload={}",
            manifest.generation_id,
            manifest.ledger_ref.seq,
            entry.seq,
            hex_lower(&manifest.ledger_ref.hash),
            hex_lower(&entry.entry_hash),
            manifest.ledger_payload_blake3,
            blake3_hex(&entry.payload),
        )));
    }
    Ok((
        trace
            .tiers
            .into_iter()
            .map(|tier| tier.tier.to_string())
            .collect(),
        LedgerRef {
            seq: entry.seq,
            hash: entry.entry_hash,
        },
    ))
}

fn row<'a>(
    rows: &'a BTreeMap<String, Vec<u8>>,
    logical_name: &str,
) -> Result<&'a Vec<u8>, CalyxError> {
    rows.get(logical_name).ok_or_else(|| {
        corrupt_error(format!(
            "fleet manifest omitted required row {logical_name:?}"
        ))
    })
}

fn canonical_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, CalyxError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| incomplete_error(format!("serialize {label}: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, CalyxError> {
    serde_json::from_slice(bytes)
        .map_err(|error| corrupt_error(format!("decode fleet {label}: {error}")))
}

fn append_part(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn hash_frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn strict_by_key<T, K: Ord>(rows: &[T], key: impl Fn(&T) -> K) -> bool {
    rows.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn corrupt_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_GENERATION_CORRUPT,
        message: message.into(),
        remediation: "preserve the fleet catalog and source vaults; reconcile the exact corrupt generation/pointer bytes under a tracked recovery before recomposing",
    }
}

fn persist_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_GENERATION_PERSIST,
        message: message.into(),
        remediation: "preserve the fleet catalog and inspect the exact conditional commit, physical rows, pointer, manifest, and Ledger record before retrying",
    }
}

fn incomplete_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_GENERATION_INCOMPLETE,
        message: message.into(),
        remediation: "supply one complete exact source roster, fleet graph/vector roster, artifact/provenance roster, and explicit genuine-query admission before publication",
    }
}

fn admission_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_ADMISSION_REQUIRED,
        message: message.into(),
        remediation: "provide an explicit astrolabe.fleet_kernel_admission.v1 file from a genuine external operator query log with all route, exact-work, recall, compactness, and HNSW controls; no synthetic or graph-derived query is accepted",
    }
}
