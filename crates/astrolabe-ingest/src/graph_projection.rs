use std::collections::{BTreeMap, BTreeSet};
use std::thread;

use astrolabe_domain::EdgeKind;
use calyx_aster::cf::{ColumnFamily, ledger_key, prefix_range};
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_aster::vault::{AsterVault, encode::WriteRow};
use calyx_core::{Clock, CxId, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};
use calyx_paths::AssocGraph;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::sqlite_import::{
    ASTRO_INGEST_READBACK_MISMATCH, EDGE_ROW_PREFIX, EdgeGraphRow, NODE_MAP_PREFIX,
    SCHEMA_EDGE_ROW, supported_node_map_schema,
};
use crate::{IngestError, IngestResult};

/// Stable failure code for corrupt or stale persisted graph projections.
pub const ASTRO_GRAPH_PROJECTION_CORRUPT: &str = "ASTRO_GRAPH_PROJECTION_CORRUPT";
/// Kernel CF prefix for Astrolabe graph projection CSR manifests and segments.
pub const GRAPH_PROJECTION_CSR_PREFIX: &[u8] = b"astrolabe:projection-csr:v1:";

const PROJECTION_REMEDIATION: &str =
    "Rebuild graph projections from Graph CF typed edge rows, then rerun astrolabe verify --deep.";

// --- Persisted SIM_* similarity edge family (#522) ---
//
// Version-agnostic base prefix for persisted SIM_* similarity edge rows. The
// authoritative writer is `astrolabe_weave::sim_rows` (`SimEdgeGraphRow`, wire
// schema `astrolabe-sim-edge-v2`). `astrolabe-weave` depends on this crate, so
// the composite kernel projection reads the rows by their stable persisted
// schema rather than importing weave, which would be a dependency cycle. The
// scan is version-agnostic and fails closed on any version segment other than
// `v2`: a future SIM row version must be taught here explicitly, never silently
// dropped, or the kernel graph would omit a whole similarity source family.
const SIM_EDGE_ROW_BASE_PREFIX: &[u8] = b"astrolabe:sim-edge:";
const SIM_EDGE_ROW_V2_PREFIX: &[u8] = b"astrolabe:sim-edge:v2:";
const SCHEMA_SIM_EDGE_ROW: &str = "astrolabe-sim-edge-v2";
const SIM_SOURCE_ATTESTATION_SCHEMA: &str = "astrolabe.sim_source_attestation.v1";
const SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA: &str = "astrolabe.sim_source_attestation_ledger.v1";
const SIM_SOURCE_ATTESTATION_PREFIX: &[u8] = b"astrolabe:sim-source-attestation:v1:";
const SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX: &str = "astrolabe-sim-source-attestation:v1";
const SIM_FAMILY_DUMP_SCHEMA: &[u8] = b"astrolabe.sim_family_persisted_dump.v1";
const PROJECTION_SCHEMA: &str = "astrolabe-graph-projection-csr-v2";
const SOURCE_FINGERPRINT_SCHEMA: &[u8] = b"astrolabe.graph_projection_source_fingerprint.v2";
const MANIFEST_VERSION: u32 = 1;
const SEGMENT_MAGIC: &[u8; 8] = b"ASTROCSR";
// v2 (#393): each CSR edge additionally carries its source edge row's ledger
// attestation (`ledger_seq` u64 LE + `ledger_hash` 32 bytes) after the weight.
const SEGMENT_VERSION: u32 = 2;
const CXID_BYTES: usize = 16;
const ASTROLABE_PROJECTION_ACTOR: &str = "astrolabe-graph-projection";

/// Projection names materialized from typed Codebase Memory MCP edge rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum GraphProjectionKind {
    /// Direct call graph: `CALLS` and `RESOLVED_CALLS`.
    CallGraph,
    /// Dependency graph: imports, dependencies, type uses, and instantiations.
    DependencyGraph,
    /// Dataflow graph: reads, writes, usage, throws, and explicit dataflow.
    DataflowGraph,
    /// Service graph: RPC, route/channel, handler, infra, and cross-service edges.
    ServiceGraph,
    /// Evolution graph: temporal co-change edges.
    EvolutionGraph,
    /// Composite Lodestar kernel graph.
    KernelGraph,
}

impl GraphProjectionKind {
    /// All v1 projections in stable manifest order.
    pub const ALL: [Self; 6] = [
        Self::CallGraph,
        Self::DependencyGraph,
        Self::DataflowGraph,
        Self::ServiceGraph,
        Self::EvolutionGraph,
        Self::KernelGraph,
    ];

    /// Stable projection name used in Kernel CF keys.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CallGraph => "call_graph",
            Self::DependencyGraph => "dependency_graph",
            Self::DataflowGraph => "dataflow_graph",
            Self::ServiceGraph => "service_graph",
            Self::EvolutionGraph => "evolution_graph",
            Self::KernelGraph => "kernel_graph",
        }
    }

    const fn wire_code(self) -> u8 {
        match self {
            Self::CallGraph => 1,
            Self::DependencyGraph => 2,
            Self::DataflowGraph => 3,
            Self::ServiceGraph => 4,
            Self::EvolutionGraph => 5,
            Self::KernelGraph => 6,
        }
    }

    fn from_wire_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_code() == code)
    }

    fn projected_weight(self, edge: EdgeKind, source_weight: f32) -> Option<f32> {
        match self {
            Self::CallGraph => is_call_edge(edge).then_some(source_weight),
            Self::DependencyGraph => is_dependency_edge(edge).then_some(source_weight),
            Self::DataflowGraph => is_dataflow_edge(edge).then_some(source_weight),
            Self::ServiceGraph => is_service_edge(edge).then_some(source_weight),
            Self::EvolutionGraph => (edge == EdgeKind::FileChangesWith).then_some(source_weight),
            Self::KernelGraph => {
                kernel_multiplier(edge).map(|multiplier| source_weight * multiplier)
            }
        }
    }
}

/// Options for graph projection materialization.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphProjectionBuildOptions {
    /// Deterministic worker count requested by the caller.
    pub workers: usize,
    /// Optional source-node regions the caller believes are dirty.
    pub dirty_regions: Option<BTreeSet<u8>>,
}

impl GraphProjectionBuildOptions {
    /// Creates default projection build options.
    pub fn new() -> Self {
        Self {
            workers: 1,
            dirty_regions: None,
        }
    }

    /// Sets the caller-visible deterministic worker count.
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Limits an incremental rebuild to a caller-supplied dirty region set.
    pub fn with_dirty_regions<I>(mut self, regions: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        self.dirty_regions = Some(regions.into_iter().collect());
        self
    }
}

/// One node in a persisted projection CSR.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphProjectionNode {
    /// Calyx content id.
    pub id: CxId,
    /// Node frequency weight used by `AssocGraph`.
    pub weight: f32,
}

/// One typed edge in a persisted projection CSR.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphProjectionCsrEdge {
    /// Destination node id.
    pub dst: CxId,
    /// Stable Astrolabe/CBM edge vocabulary code.
    pub etype: u16,
    /// Projection edge weight in `[0, 1]`.
    pub weight: f32,
    /// Ledger sequence of the source Graph CF edge row that attests this edge
    /// (#393). `0` with an all-zero [`Self::ledger_hash`] denotes an edge carrying
    /// no ledger attestation, which a multi-hop kernel answer refuses to traverse.
    #[serde(default)]
    pub ledger_seq: u64,
    /// Hash-chain entry hash of the attesting ledger entry (#393). All-zero with a
    /// `0` [`Self::ledger_seq`] denotes an unattested edge.
    #[serde(default)]
    pub ledger_hash: [u8; 32],
}

impl GraphProjectionCsrEdge {
    /// Renders this edge's persisted ledger attestation as a `seq:hex(hash)`
    /// reference, or `None` when the edge carries no attestation (a zero ledger
    /// pointer) — the shape the kernel answer engine's per-hop ledger-required gate
    /// consumes (#393). The reference points at a real, persisted Ledger CF entry:
    /// the `provenance` [`calyx_core::LedgerRef`] of the source edge row this
    /// projection edge was materialized from.
    pub fn ledger_ref(&self) -> Option<String> {
        if self.ledger_seq == 0 && self.ledger_hash == [0_u8; 32] {
            return None;
        }
        Some(format!(
            "{}:{}",
            self.ledger_seq,
            hex_lower(&self.ledger_hash)
        ))
    }
}

/// Decoded graph projection CSR.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphProjectionCsr {
    /// Projection kind.
    pub kind: GraphProjectionKind,
    /// Fingerprint of the typed source edge rows used to build this CSR.
    pub source_fingerprint_blake3: [u8; 32],
    /// Nodes sorted by `CxId`.
    pub nodes: Vec<GraphProjectionNode>,
    /// CSR offsets, length `nodes.len() + 1`.
    pub offsets: Vec<usize>,
    /// CSR edges sorted within each source node by `(etype, dst)`.
    pub edges: Vec<GraphProjectionCsrEdge>,
    /// Edge count visible after decoding this typed CSR into untyped `AssocGraph`.
    pub association_edge_count: usize,
}

impl GraphProjectionCsr {
    /// Decodes this CSR into the Calyx weighted association graph used by paths.
    pub fn assoc_graph(&self) -> IngestResult<AssocGraph> {
        validate_csr(self)?;
        let mut builder = AssocGraph::builder();
        for node in &self.nodes {
            builder.add_node(node.id, node.weight).map_err(|error| {
                projection_corrupt(format!("projection node rejected: {error}"))
            })?;
        }
        let node_ids = self
            .nodes
            .iter()
            .map(|node| node.id)
            .collect::<BTreeSet<_>>();
        for (src_index, window) in self.offsets.windows(2).enumerate() {
            let src = self.nodes[src_index].id;
            for edge in &self.edges[window[0]..window[1]] {
                if !node_ids.contains(&edge.dst) {
                    return Err(projection_corrupt(format!(
                        "projection edge destination {} has no node row",
                        edge.dst
                    )));
                }
                builder
                    .add_edge(src, edge.dst, edge.weight)
                    .map_err(|error| {
                        projection_corrupt(format!("projection edge rejected: {error}"))
                    })?;
            }
        }
        let graph = builder.build();
        if graph.edge_count() != self.association_edge_count {
            return Err(projection_corrupt(format!(
                "projection association_edge_count={} but decoded graph has {}",
                self.association_edge_count,
                graph.edge_count()
            )));
        }
        Ok(graph)
    }
}

/// Per-projection materialization result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphProjectionMaterializeEntry {
    /// Projection kind.
    pub kind: GraphProjectionKind,
    /// Number of source regions in the desired projection.
    pub source_regions: Vec<u8>,
    /// Regions whose persisted segment was missing or stale.
    pub stale_regions: Vec<u8>,
    /// Persisted segment count.
    pub segment_count: usize,
    /// Segment rows written during this materialization.
    pub segments_written: usize,
    /// Segment rows tombstoned because their region disappeared.
    pub segments_tombstoned: usize,
    /// Whether the projection manifest row was written.
    pub manifest_written: bool,
    /// Number of nodes in the decoded CSR.
    pub node_count: usize,
    /// Number of typed CSR edges.
    pub edge_count: usize,
    /// Number of untyped association edges after decoding.
    pub association_edge_count: usize,
    /// Kernel CF rows (segments, tombstones, manifest) re-read and
    /// byte-verified at the commit snapshot after the write (#178). Zero when
    /// the materialization wrote nothing.
    pub rows_readback_verified: usize,
    /// Whether the commit's paired ledger entry was read back and verified
    /// (#178). `false` only when the materialization wrote nothing, so no
    /// ledger entry was due.
    pub ledger_paired: bool,
}

/// Materialization result for one or more projections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphProjectionMaterializeReport {
    /// Number of source edge rows scanned from Graph CF across both families
    /// (typed structural + persisted SIM_* similarity).
    pub source_edge_rows: usize,
    /// Typed CBM structural edge rows scanned from Graph CF.
    pub source_typed_edge_rows: usize,
    /// Persisted SIM_* similarity edge rows folded into the composite graph (#522).
    pub source_sim_edge_rows: usize,
    /// Fingerprint of all source edge rows (both families) scanned from Graph CF.
    pub source_fingerprint_blake3: [u8; 32],
    /// Deterministic worker count requested by the caller.
    pub workers: usize,
    /// Per-projection reports.
    pub projections: Vec<GraphProjectionMaterializeEntry>,
}

/// Composite Kernel projection planned as part of a live direct-ingest commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtomicKernelProjectionReport {
    /// Typed CBM structural edge rows in the final ledger-bound Graph state.
    pub source_typed_edge_rows: usize,
    /// Persisted SIM similarity rows in that same final Graph state.
    pub source_sim_edge_rows: usize,
    /// Fingerprint framing every final typed and SIM source key/value byte.
    pub source_fingerprint_blake3: [u8; 32],
    /// Deterministic worker count used to encode independent CSR regions.
    pub workers: usize,
    /// Exact composite projection mutation/readback accounting.
    pub projection: GraphProjectionMaterializeEntry,
}

pub(crate) struct AtomicKernelProjectionPlan {
    pub(crate) rows: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    pub(crate) report: AtomicKernelProjectionReport,
}

/// Raw persisted-row evidence for one composite-kernel CSR region.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompositeKernelSegmentEvidence {
    /// Kernel CF key as lowercase hexadecimal.
    pub key_hex: String,
    /// Region byte encoded into the segment key/header.
    pub region: u8,
    /// Exact persisted segment byte length.
    pub value_len: usize,
    /// SHA-256 of the exact persisted segment bytes.
    pub value_sha256: String,
    /// BLAKE3 of the exact persisted segment bytes, matched to the manifest.
    pub value_blake3: String,
}

/// One persisted SIM edge whose endpoints have no typed structural edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimOnlyKernelEdgeEvidence {
    /// Raw Graph CF SIM-row key as lowercase hexadecimal.
    pub sim_row_key_hex: String,
    /// SHA-256 of the exact persisted SIM-row value bytes.
    pub sim_row_value_sha256: String,
    /// Exact persisted SIM-row value length.
    pub sim_row_value_len: usize,
    /// Stable source-atom identity from the SIM row.
    pub source_id: String,
    /// Stable target-atom identity from the SIM row.
    pub target_id: String,
    /// Source CxId resolved through the persisted node map.
    pub source_cx_id: CxId,
    /// Target CxId resolved through the persisted node map.
    pub target_cx_id: CxId,
    /// Persisted similarity edge type.
    pub etype: u16,
    /// Exact source SIM weight bits.
    pub source_weight_bits: u32,
    /// Exact projected kernel-graph weight bits.
    pub projected_weight_bits: u32,
    /// Ledger reference physically carried by the persisted CSR edge.
    pub projection_ledger_ref: String,
}

/// Independent deep-verification report for the complete typed+SIM kernel graph.
///
/// The verifier reconstructs the expected CSR from the current raw Graph rows and
/// requires exact equality with the decoded persisted CSR. It therefore proves
/// more than a source-fingerprint match: every projected node, offset, edge,
/// weight, type, and ledger pointer must be the value the raw source rows imply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompositeKernelProjectionVerifyReport {
    /// MVCC sequence independently read during verification.
    pub snapshot_seq: Seq,
    /// Typed structural source rows included in the reconstruction.
    pub source_typed_edge_rows: usize,
    /// SIM source rows included in the reconstruction.
    pub source_sim_edge_rows: usize,
    /// Raw source-family fingerprint framing every typed and SIM key/value byte.
    pub source_fingerprint_blake3: String,
    /// Whether a persisted kernel CSR exists. False is valid only for no sources.
    pub csr_present: bool,
    /// Persisted CSR node count.
    pub node_count: usize,
    /// Persisted typed CSR edge count.
    pub edge_count: usize,
    /// Persisted association edge count after edge-type collapse.
    pub association_edge_count: usize,
    /// CSR edges carrying a similarity edge type.
    pub projected_similarity_edge_count: usize,
    /// SIM rows whose ordered endpoints have no typed structural edge.
    pub sim_only_source_edge_count: usize,
    /// Raw kernel-CSR manifest key, when a CSR exists.
    pub manifest_key_hex: Option<String>,
    /// Exact persisted manifest byte length.
    pub manifest_value_len: Option<usize>,
    /// SHA-256 of the exact persisted manifest bytes.
    pub manifest_value_sha256: Option<String>,
    /// Independently read and hash-checked persisted segment rows.
    pub segments: Vec<CompositeKernelSegmentEvidence>,
    /// Deterministic first SIM-only relationship, proven in the persisted CSR.
    pub representative_sim_only_edge: Option<SimOnlyKernelEdgeEvidence>,
}

/// Point-readable identity for one persisted projection manifest. This binds
/// the exact manifest bytes (including every segment length/hash) without
/// materializing the CSR or scanning the raw Graph source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphProjectionManifestIdentity {
    pub schema: String,
    pub projection_schema: String,
    pub csr_manifest_version: u32,
    pub projection: String,
    pub source_fingerprint_blake3: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub association_edge_count: usize,
    pub segment_count: usize,
    pub manifest_key_hex: String,
    pub manifest_bytes: u64,
    pub manifest_blake3: String,
    pub manifest_sha256: String,
}

/// Exact point-readable source binding used by bounded ordinary CSR reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphProjectionReadBinding {
    pub graph_content_generation: Seq,
    pub manifest: GraphProjectionManifestIdentity,
}

#[derive(Clone, Debug)]
struct SourceEdges {
    rows: Vec<SourceEdgeRow>,
    fingerprint: [u8; 32],
    /// Exact MVCC snapshot whose Graph rows were scanned.
    source_snapshot: Seq,
    /// Durable Graph content generation before and after the source scan.
    graph_content_generation: Seq,
    /// Typed CBM structural edge rows scanned from Graph CF.
    typed_edge_rows: usize,
    /// Persisted SIM_* similarity edge rows folded into the composite graph.
    sim_edge_rows: usize,
}

/// Which persisted Graph CF family a normalized source edge came from (#522).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceFamily {
    /// `astrolabe:edge:v1:` typed CBM structural edge.
    Typed,
    /// `astrolabe:sim-edge:v2:` persisted learned/semantic similarity edge.
    Similarity,
}

/// A source edge normalized across both persisted families (#522).
///
/// Typed structural rows carry a `CxId` src/dst directly; SIM_* rows carry
/// stable source-atom ids resolved to `CxId`s through the persisted node map. Both
/// contribute their source ledger attestation so the composite CSR edge stays
/// attributable to a real persisted Ledger CF entry.
#[derive(Clone, Debug)]
struct SourceEdgeRow {
    src: CxId,
    dst: CxId,
    etype: u16,
    weight: f32,
    kind: EdgeKind,
    ledger_seq: u64,
    ledger_hash: [u8; 32],
    props: serde_json::Value,
    #[allow(dead_code)]
    family: SourceFamily,
}

/// Deserialize view of the persisted `astrolabe-sim-edge-v2` wire row.
///
/// Mirrors the complete authoritative
/// `astrolabe_weave::sim_rows::SimEdgeGraphRow` wire schema. Strict decoding is
/// required because the terminal family digest binds the exact raw bytes while
/// the projection separately validates their decoded meaning.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimEdgeSourceRow {
    schema: String,
    family: String,
    source_id: String,
    target_id: String,
    #[serde(rename = "source_qn")]
    _source_qn: String,
    #[serde(rename = "target_qn")]
    _target_qn: String,
    slot: u16,
    etype: u16,
    metric: String,
    weight_bits: u32,
    threshold_bits: u32,
    props: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum SimSourceFamily {
    Struct,
    Semantic,
    Api,
    Profile,
}

impl SimSourceFamily {
    const ALL: [Self; 4] = [Self::Struct, Self::Semantic, Self::Api, Self::Profile];

    const fn wire_name(self) -> &'static str {
        match self {
            Self::Struct => "SIM_STRUCT",
            Self::Semantic => "SIM_SEMANTIC",
            Self::Api => "SIM_API",
            Self::Profile => "SIM_PROFILE",
        }
    }

    fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|family| family.wire_name() == name)
    }

    const fn sort_index(self) -> u8 {
        match self {
            Self::Struct => 0,
            Self::Semantic => 1,
            Self::Api => 2,
            Self::Profile => 3,
        }
    }

    const fn slot(self) -> u16 {
        match self {
            Self::Struct => 1,
            Self::Semantic => 18,
            Self::Api => 4,
            Self::Profile => 21,
        }
    }

    const fn edge_kind(self) -> EdgeKind {
        match self {
            Self::Semantic => EdgeKind::SemanticallyRelated,
            Self::Struct | Self::Api | Self::Profile => EdgeKind::SimilarTo,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimSourceAttestation {
    schema: String,
    family: String,
    row_count: u64,
    total_bytes: u64,
    content_blake3: String,
    ledger_seq: u64,
    ledger_hash: String,
    actor: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimSourceAttestationLedgerPayload {
    schema: String,
    family: String,
    row_count: u64,
    total_bytes: u64,
    content_blake3: String,
}

#[derive(Debug)]
struct SimFamilySourceRows {
    rows: Vec<(Vec<u8>, Vec<u8>, SimEdgeSourceRow)>,
    row_count: u64,
    total_bytes: u64,
    content_hasher: blake3::Hasher,
}

impl SimFamilySourceRows {
    fn new() -> Self {
        let mut content_hasher = blake3::Hasher::new();
        frame_hash(&mut content_hasher, SIM_FAMILY_DUMP_SCHEMA);
        Self {
            rows: Vec::new(),
            row_count: 0,
            total_bytes: 0,
            content_hasher,
        }
    }
}

#[derive(Debug, Deserialize)]
struct NodeMapProjectionRow {
    schema: String,
    node_id: i64,
    atom_id: String,
    qualified_name: String,
    cx_id: CxId,
}

#[derive(Clone, Debug)]
struct ProjectionBytes {
    csr: GraphProjectionCsr,
    manifest_bytes: Vec<u8>,
    manifest_key: Vec<u8>,
    segments: Vec<ProjectionSegmentBytes>,
}

#[derive(Clone, Debug)]
struct ProjectionSegmentBytes {
    region: u8,
    key: Vec<u8>,
    bytes: Vec<u8>,
    manifest: ProjectionManifestRegion,
}

struct ProjectionUpdatePlan {
    desired: ProjectionBytes,
    segment_is_stale: Vec<bool>,
    tombstoned_keys: Vec<Vec<u8>>,
    rows: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    entry: GraphProjectionMaterializeEntry,
}

struct ProjectionCommitReadbackExpectation<'a> {
    kind: GraphProjectionKind,
    commit_seq: Seq,
    ledger_ref: &'a calyx_core::LedgerRef,
    subject: &'a SubjectId,
    payload: &'a [u8],
    actor: &'a ActorId,
    desired: &'a ProjectionBytes,
    segment_is_stale: &'a [bool],
    manifest_written: bool,
    tombstoned_keys: &'a [Vec<u8>],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProjectionManifest {
    schema: String,
    csr_manifest_version: u32,
    projection: String,
    source_fingerprint_blake3: String,
    node_count: usize,
    edge_count: usize,
    association_edge_count: usize,
    segment_count: usize,
    regions: Vec<ProjectionManifestRegion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProjectionManifestRegion {
    region: u8,
    node_count: usize,
    edge_count: usize,
    total_bytes: usize,
    stream_blake3: String,
}

#[derive(Clone, Debug)]
struct DecodedSegment {
    kind: GraphProjectionKind,
    region: u8,
    nodes: Vec<GraphProjectionNode>,
    offsets: Vec<usize>,
    edges: Vec<GraphProjectionCsrEdge>,
}

#[derive(Clone, Debug, PartialEq)]
enum PersistedProjectionState {
    Missing,
    Incomplete,
    Complete(GraphProjectionCsr),
}

/// Materializes all v1 graph projections into Kernel CF binary CSR segments.
pub fn materialize_graph_projections<C>(
    vault: &AsterVault<C>,
    options: &GraphProjectionBuildOptions,
) -> IngestResult<GraphProjectionMaterializeReport>
where
    C: Clock,
{
    let source = read_source_edges(vault)?;
    let mut projections = Vec::with_capacity(GraphProjectionKind::ALL.len());
    for kind in GraphProjectionKind::ALL {
        projections.push(materialize_graph_projection_from_source(
            vault, kind, options, &source,
        )?);
    }
    Ok(GraphProjectionMaterializeReport {
        source_edge_rows: source.rows.len(),
        source_typed_edge_rows: source.typed_edge_rows,
        source_sim_edge_rows: source.sim_edge_rows,
        source_fingerprint_blake3: source.fingerprint,
        workers: options.workers.max(1),
        projections,
    })
}

/// Materializes one v1 graph projection into Kernel CF binary CSR segments.
pub fn materialize_graph_projection<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    options: &GraphProjectionBuildOptions,
) -> IngestResult<GraphProjectionMaterializeEntry>
where
    C: Clock,
{
    let source = read_source_edges(vault)?;
    materialize_graph_projection_from_source(vault, kind, options, &source)
}

/// Reads and verifies a persisted projection CSR without rebuilding stale or
/// missing rows. Both the manifest/segment hashes and the current Graph CF
/// source fingerprint must match before the artifact is returned.
pub fn read_graph_projection_csr<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
) -> IngestResult<Option<GraphProjectionCsr>>
where
    C: Clock,
{
    read_graph_projection_csr_at(vault, kind, vault.latest_seq())
}

/// Reads and verifies a projection and its complete typed+similarity source at
/// the caller-retained current MVCC sequence. This is the discovery-safe
/// variant: no helper is permitted to acquire a newer snapshot mid-read, and a
/// source generation that advances during the read is refused.
pub fn read_graph_projection_csr_at<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    snapshot: Seq,
) -> IngestResult<Option<GraphProjectionCsr>>
where
    C: Clock,
{
    match load_persisted_projection_at(vault, kind, false, snapshot)? {
        PersistedProjectionState::Missing => Ok(None),
        PersistedProjectionState::Incomplete => Err(projection_corrupt(format!(
            "{} CSR segment set is incomplete; call ensure_graph_projection_csr to rebuild",
            kind.name()
        ))),
        PersistedProjectionState::Complete(csr) => {
            let source = read_source_edges_at(vault, snapshot)?;
            if csr.source_fingerprint_blake3 != source.fingerprint {
                return Err(projection_corrupt(format!(
                    "{} CSR source fingerprint {} is stale against current Graph CF fingerprint {}; call ensure_graph_projection_csr to rebuild",
                    kind.name(),
                    hex_lower(&csr.source_fingerprint_blake3),
                    hex_lower(&source.fingerprint),
                )));
            }
            Ok(Some(csr))
        }
    }
}

/// Reads and validates only the immutable projection-manifest point row.
///
/// # Cost contract (#1064)
///
/// This performs one Kernel CF point read and `O(S)` validation over the
/// manifest's region roster, where `S <= 256` by the one-byte region scheme. It
/// performs no Graph scan and no CSR segment read. The retained snapshot, exact
/// manifest bytes, projection kind, and canonical region order are invariant.
pub fn read_graph_projection_manifest_identity_at<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    snapshot: Seq,
) -> IngestResult<Option<GraphProjectionManifestIdentity>>
where
    C: Clock,
{
    let key = manifest_key(kind);
    let Some(bytes) = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &key)? else {
        return Ok(None);
    };
    let manifest: ProjectionManifest = serde_json::from_slice(&bytes).map_err(|error| {
        projection_corrupt(format!(
            "decode {} CSR manifest identity point row: {error}",
            kind.name()
        ))
    })?;
    validate_manifest(kind, &manifest)?;
    let manifest_bytes = u64::try_from(bytes.len())
        .map_err(|_| projection_corrupt("projection manifest byte length exceeds u64"))?;
    Ok(Some(GraphProjectionManifestIdentity {
        schema: "astrolabe.graph_projection_manifest_identity.v1".to_string(),
        projection_schema: manifest.schema,
        csr_manifest_version: manifest.csr_manifest_version,
        projection: manifest.projection,
        source_fingerprint_blake3: manifest.source_fingerprint_blake3,
        node_count: manifest.node_count,
        edge_count: manifest.edge_count,
        association_edge_count: manifest.association_edge_count,
        segment_count: manifest.segment_count,
        manifest_key_hex: hex_key(&key),
        manifest_bytes,
        manifest_blake3: blake3::hash(&bytes).to_hex().to_string(),
        manifest_sha256: sha256_hex(&bytes),
    }))
}

/// Reads only the manifest-bound CSR segments after proving the exact durable
/// Graph generation has not changed. Unlike the deep verification reader, this
/// performs no raw Graph or Ledger scan.
///
/// # Cost contract (#1064)
///
/// Two Graph-generation probes and two manifest point reads are `O(1)`; segment
/// decode/hash work is `O(N+E)` because the caller requested the actual CSR.
/// The retained snapshot, durable Graph generation, exact manifest bytes, and
/// canonical segment roster are invariant across the read (PC-02/03/38/40/43).
pub fn read_graph_projection_csr_bound_at<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    snapshot: Seq,
    expected: &GraphProjectionReadBinding,
) -> IngestResult<GraphProjectionCsr>
where
    C: Clock,
{
    if vault.latest_seq() != snapshot {
        return Err(projection_corrupt(format!(
            "{} bounded CSR read requires the current retained snapshot; expected {snapshot}, observed {}",
            kind.name(),
            vault.latest_seq()
        )));
    }
    let graph_generation_before = vault.cf_content_generation(ColumnFamily::Graph)?;
    let manifest_before = read_graph_projection_manifest_identity_at(vault, kind, snapshot)?
        .ok_or_else(|| {
            projection_corrupt(format!(
                "{} bounded CSR read found no projection manifest",
                kind.name()
            ))
        })?;
    if graph_generation_before != expected.graph_content_generation
        || manifest_before != expected.manifest
    {
        return Err(projection_corrupt(format!(
            "{} bounded CSR source differs before segment read: expected_graph_generation={}, observed_graph_generation={graph_generation_before}, expected_manifest={:?}, observed_manifest={manifest_before:?}",
            kind.name(),
            expected.graph_content_generation,
            expected.manifest,
        )));
    }
    let csr = match load_persisted_projection_at(vault, kind, false, snapshot)? {
        PersistedProjectionState::Complete(csr) => csr,
        PersistedProjectionState::Missing => {
            return Err(projection_corrupt(format!(
                "{} bounded CSR manifest exists but segment set is absent",
                kind.name()
            )));
        }
        PersistedProjectionState::Incomplete => {
            return Err(projection_corrupt(format!(
                "{} bounded CSR segment set is incomplete",
                kind.name()
            )));
        }
    };
    let graph_generation_after = vault.cf_content_generation(ColumnFamily::Graph)?;
    let manifest_after = read_graph_projection_manifest_identity_at(vault, kind, snapshot)?
        .ok_or_else(|| {
            projection_corrupt(format!(
                "{} bounded CSR manifest disappeared during segment read",
                kind.name()
            ))
        })?;
    let latest_after = vault.latest_seq();
    if graph_generation_after != expected.graph_content_generation
        || manifest_after != expected.manifest
        || latest_after != snapshot
    {
        return Err(projection_corrupt(format!(
            "{} bounded CSR source changed during segment read: expected_snapshot={snapshot}, observed_latest={latest_after}, expected_graph_generation={}, observed_graph_generation={graph_generation_after}, expected_manifest={:?}, observed_manifest={manifest_after:?}",
            kind.name(),
            expected.graph_content_generation,
            expected.manifest,
        )));
    }
    Ok(csr)
}

/// Independently verifies the persisted composite kernel projection against all
/// current typed and SIM Graph CF source rows and returns hash-bound physical
/// evidence suitable for operational inspection.
///
/// A missing CSR is accepted only when both source families are empty. Any
/// non-empty source with no CSR is stale derived state and fails closed. When a
/// CSR exists, this function rebuilds the entire expected CSR from the raw rows
/// and requires exact structural equality with the persisted decode; source
/// fingerprint equality alone is not treated as proof.
pub fn verify_composite_kernel_projection<C>(
    vault: &AsterVault<C>,
) -> IngestResult<CompositeKernelProjectionVerifyReport>
where
    C: Clock,
{
    let snapshot_seq = vault.latest_seq();
    let source = read_source_edges(vault)?;
    let persisted = read_graph_projection_csr(vault, GraphProjectionKind::KernelGraph)?;
    let Some(csr) = persisted else {
        if !source.rows.is_empty() {
            return Err(projection_corrupt(format!(
                "{} source rows exist (typed={}, SIM={}) but the composite kernel CSR is absent",
                source.rows.len(),
                source.typed_edge_rows,
                source.sim_edge_rows,
            )));
        }
        return Ok(CompositeKernelProjectionVerifyReport {
            snapshot_seq,
            source_typed_edge_rows: 0,
            source_sim_edge_rows: 0,
            source_fingerprint_blake3: hex_lower(&source.fingerprint),
            csr_present: false,
            node_count: 0,
            edge_count: 0,
            association_edge_count: 0,
            projected_similarity_edge_count: 0,
            sim_only_source_edge_count: 0,
            manifest_key_hex: None,
            manifest_value_len: None,
            manifest_value_sha256: None,
            segments: Vec::new(),
            representative_sim_only_edge: None,
        });
    };

    let expected = build_projection_csr(GraphProjectionKind::KernelGraph, &source)?;
    if csr != expected {
        return Err(projection_corrupt(
            "persisted kernel_graph CSR does not exactly equal the CSR independently rebuilt from current typed and SIM Graph CF rows",
        ));
    }

    let manifest_key = manifest_key(GraphProjectionKind::KernelGraph);
    let manifest_bytes = vault
        .read_cf_at(snapshot_seq, ColumnFamily::Kernel, &manifest_key)?
        .ok_or_else(|| {
            projection_corrupt("kernel_graph CSR manifest disappeared during deep verification")
        })?;
    let manifest =
        serde_json::from_slice::<ProjectionManifest>(&manifest_bytes).map_err(|error| {
            projection_corrupt(format!(
                "decode kernel_graph CSR manifest during deep verification: {error}"
            ))
        })?;
    validate_manifest(GraphProjectionKind::KernelGraph, &manifest)?;

    let mut segments = Vec::with_capacity(manifest.regions.len());
    for region in &manifest.regions {
        let key = segment_key(GraphProjectionKind::KernelGraph, region.region);
        let bytes = vault
            .read_cf_at(snapshot_seq, ColumnFamily::Kernel, &key)?
            .ok_or_else(|| {
                projection_corrupt(format!(
                    "kernel_graph CSR segment {} disappeared during deep verification",
                    region.region
                ))
            })?;
        let value_blake3 = blake3::hash(&bytes).to_hex().to_string();
        if bytes.len() != region.total_bytes || value_blake3 != region.stream_blake3 {
            return Err(projection_corrupt(format!(
                "kernel_graph CSR segment {} physical bytes disagree with manifest: bytes={} expected={} blake3={} expected={}",
                region.region,
                bytes.len(),
                region.total_bytes,
                value_blake3,
                region.stream_blake3,
            )));
        }
        segments.push(CompositeKernelSegmentEvidence {
            key_hex: hex_key(&key),
            region: region.region,
            value_len: bytes.len(),
            value_sha256: sha256_hex(&bytes),
            value_blake3,
        });
    }

    let typed_endpoint_pairs = source
        .rows
        .iter()
        .filter(|row| row.family == SourceFamily::Typed)
        .map(|row| undirected_endpoint_pair(row.src, row.dst))
        .collect::<BTreeSet<_>>();
    let sim_only_source_edge_count = source
        .rows
        .iter()
        .filter(|row| {
            row.family == SourceFamily::Similarity
                && !typed_endpoint_pairs.contains(&undirected_endpoint_pair(row.src, row.dst))
        })
        .count();
    let projected_similarity_edge_count = csr
        .edges
        .iter()
        .filter(|edge| {
            matches!(
                edge_kind_from_code(edge.etype),
                Some(EdgeKind::SimilarTo | EdgeKind::SemanticallyRelated)
            )
        })
        .count();
    let representative_sim_only_edge = representative_sim_only_edge(
        vault,
        snapshot_seq,
        &csr,
        &typed_endpoint_pairs,
        sim_only_source_edge_count,
    )?;

    Ok(CompositeKernelProjectionVerifyReport {
        snapshot_seq,
        source_typed_edge_rows: source.typed_edge_rows,
        source_sim_edge_rows: source.sim_edge_rows,
        source_fingerprint_blake3: hex_lower(&source.fingerprint),
        csr_present: true,
        node_count: csr.nodes.len(),
        edge_count: csr.edges.len(),
        association_edge_count: csr.association_edge_count,
        projected_similarity_edge_count,
        sim_only_source_edge_count,
        manifest_key_hex: Some(hex_key(&manifest_key)),
        manifest_value_len: Some(manifest_bytes.len()),
        manifest_value_sha256: Some(sha256_hex(&manifest_bytes)),
        segments,
        representative_sim_only_edge,
    })
}

fn representative_sim_only_edge<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    csr: &GraphProjectionCsr,
    typed_endpoint_pairs: &BTreeSet<(CxId, CxId)>,
    sim_only_source_edge_count: usize,
) -> IngestResult<Option<SimOnlyKernelEdgeEvidence>>
where
    C: Clock,
{
    if sim_only_source_edge_count == 0 {
        return Ok(None);
    }
    let resolved = crate::sqlite_import::read_global_atom_cx_ids(vault)?;
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_EDGE_ROW_V2_PREFIX),
    )? {
        let row = serde_json::from_slice::<SimEdgeSourceRow>(&value).map_err(|error| {
            projection_corrupt(format!(
                "decode SIM edge row {} while selecting deep-verification witness: {error}",
                hex_key(&key)
            ))
        })?;
        let src = resolve_sim_endpoint(&resolved, &row.source_id, &key, "source")?;
        let dst = resolve_sim_endpoint(&resolved, &row.target_id, &key, "target")?;
        if typed_endpoint_pairs.contains(&undirected_endpoint_pair(src, dst)) {
            continue;
        }
        let kind = edge_kind_from_code(row.etype).ok_or_else(|| {
            projection_corrupt(format!(
                "SIM edge row {} has unknown etype {} while selecting deep-verification witness",
                hex_key(&key),
                row.etype
            ))
        })?;
        let source_weight = f32::from_bits(row.weight_bits);
        let projected_weight = GraphProjectionKind::KernelGraph
            .projected_weight(kind, source_weight)
            .ok_or_else(|| {
                projection_corrupt(format!(
                    "SIM edge row {} did not project into the composite kernel graph",
                    hex_key(&key)
                ))
            })?;
        let source_index = csr
            .nodes
            .binary_search_by_key(&src, |node| node.id)
            .map_err(|_| {
                projection_corrupt(format!(
                    "SIM-only witness source {src} has no persisted CSR node"
                ))
            })?;
        let edge = csr.edges[csr.offsets[source_index]..csr.offsets[source_index + 1]]
            .iter()
            .find(|edge| edge.dst == dst && edge.etype == row.etype)
            .ok_or_else(|| {
                projection_corrupt(format!(
                    "SIM-only witness {} -> {} etype={} is absent from the persisted CSR",
                    src, dst, row.etype
                ))
            })?;
        // Multiple learned families may collapse onto the same
        // (source,target,etype) edge. The projection keeps their maximum
        // weight, so only the raw row that actually determines that maximum
        // is a valid byte-level witness for the persisted CSR edge.
        if edge.weight.to_bits() != projected_weight.to_bits() {
            continue;
        }
        let projection_ledger_ref = edge.ledger_ref().ok_or_else(|| {
            projection_corrupt(format!(
                "SIM-only witness {} -> {} etype={} has no persisted CSR ledger attestation",
                src, dst, row.etype
            ))
        })?;
        return Ok(Some(SimOnlyKernelEdgeEvidence {
            sim_row_key_hex: hex_key(&key),
            sim_row_value_sha256: sha256_hex(&value),
            sim_row_value_len: value.len(),
            source_id: row.source_id,
            target_id: row.target_id,
            source_cx_id: src,
            target_cx_id: dst,
            etype: row.etype,
            source_weight_bits: row.weight_bits,
            projected_weight_bits: projected_weight.to_bits(),
            projection_ledger_ref,
        }));
    }
    Err(projection_corrupt(format!(
        "counted {sim_only_source_edge_count} SIM-only source edges but could not select a persisted witness"
    )))
}

fn undirected_endpoint_pair(left: CxId, right: CxId) -> (CxId, CxId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

/// Returns a projection CSR, rebuilding it when the regenerable rows are stale or absent.
pub fn ensure_graph_projection_csr<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    options: &GraphProjectionBuildOptions,
) -> IngestResult<GraphProjectionCsr>
where
    C: Clock,
{
    let source = read_source_edges(vault)?;
    let projection_snapshot = vault.latest_seq();
    if vault.cf_content_generation(ColumnFamily::Graph)? != source.graph_content_generation {
        return Err(projection_corrupt(format!(
            "{} Graph source changed before persisted projection inspection",
            kind.name()
        )));
    }
    let persisted = load_persisted_projection_at(vault, kind, true, projection_snapshot)?;
    if vault.latest_seq() != projection_snapshot
        || vault.cf_content_generation(ColumnFamily::Graph)? != source.graph_content_generation
    {
        return Err(projection_corrupt(format!(
            "{} source or persisted projection state changed during ensure inspection",
            kind.name()
        )));
    }
    match persisted {
        PersistedProjectionState::Complete(csr)
            if csr.source_fingerprint_blake3 == source.fingerprint =>
        {
            Ok(csr)
        }
        PersistedProjectionState::Missing
        | PersistedProjectionState::Incomplete
        | PersistedProjectionState::Complete(_) => {
            materialize_graph_projection_from_source(vault, kind, options, &source)?;
            read_graph_projection_csr(vault, kind)?.ok_or_else(|| {
                projection_corrupt(format!("{} CSR missing after rebuild", kind.name()))
            })
        }
    }
}

fn materialize_graph_projection_from_source<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    options: &GraphProjectionBuildOptions,
    source: &SourceEdges,
) -> IngestResult<GraphProjectionMaterializeEntry>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    if source.source_snapshot > snapshot {
        return Err(projection_corrupt(format!(
            "{} source snapshot {} is newer than current snapshot {snapshot}",
            kind.name(),
            source.source_snapshot
        )));
    }
    let graph_generation_before = vault.cf_content_generation(ColumnFamily::Graph)?;
    if graph_generation_before != source.graph_content_generation {
        return Err(projection_corrupt(format!(
            "{} source Graph generation {} is stale against current generation {graph_generation_before}",
            kind.name(),
            source.graph_content_generation
        )));
    }
    let mut plan = plan_projection_update(vault, snapshot, kind, options, source)?;
    let graph_generation_after_plan = vault.cf_content_generation(ColumnFamily::Graph)?;
    if graph_generation_after_plan != source.graph_content_generation {
        return Err(projection_corrupt(format!(
            "{} Graph generation changed while planning projection publication: expected {}, observed {graph_generation_after_plan}",
            kind.name(),
            source.graph_content_generation
        )));
    }
    let wrote_rows = !plan.rows.is_empty();
    if wrote_rows {
        let payload = serde_json::to_vec(&json!({
            "schema": "agp_v1",
            "projection": kind.name(),
            "source_fingerprint_blake3_prefix": hex_prefix(&source.fingerprint, 8),
            "node_count": plan.desired.csr.nodes.len(),
            "edge_count": plan.desired.csr.edges.len(),
            "association_edge_count": plan.desired.csr.association_edge_count,
            "segments_written": plan.entry.segments_written,
            "segments_tombstoned": plan.entry.segments_tombstoned,
            "manifest_written": plan.entry.manifest_written,
        }))?;
        let subject = SubjectId::Query(kind.name().as_bytes().to_vec());
        let actor = ActorId::Service(ASTROLABE_PROJECTION_ACTOR.to_string());
        let (commit, ()) = vault
            .write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
                snapshot,
                std::mem::take(&mut plan.rows),
                EntryKind::Kernel,
                subject.clone(),
                payload.clone(),
                actor.clone(),
                |_ledger_ref, _| Ok((Vec::new(), ())),
            )?;
        plan.entry.rows_readback_verified = verify_projection_commit_readback(
            vault,
            &ProjectionCommitReadbackExpectation {
                kind,
                commit_seq: commit.seq,
                ledger_ref: &commit.ledger_ref,
                subject: &subject,
                payload: &payload,
                actor: &actor,
                desired: &plan.desired,
                segment_is_stale: &plan.segment_is_stale,
                manifest_written: plan.entry.manifest_written,
                tombstoned_keys: &plan.tombstoned_keys,
            },
        )?;
        let graph_generation_after_commit = vault.cf_content_generation(ColumnFamily::Graph)?;
        if graph_generation_after_commit != source.graph_content_generation {
            return Err(projection_corrupt(format!(
                "{} Graph generation changed across projection commit: expected {}, observed {graph_generation_after_commit}",
                kind.name(),
                source.graph_content_generation
            )));
        }
        plan.entry.ledger_paired = true;
    } else if vault.latest_seq() != snapshot
        || vault.cf_content_generation(ColumnFamily::Graph)? != source.graph_content_generation
    {
        return Err(projection_corrupt(format!(
            "{} source or persisted projection state changed during no-op publication decision",
            kind.name()
        )));
    }

    Ok(plan.entry)
}

fn plan_projection_update<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    kind: GraphProjectionKind,
    options: &GraphProjectionBuildOptions,
    source: &SourceEdges,
) -> IngestResult<ProjectionUpdatePlan>
where
    C: Clock,
{
    let desired = build_projection_bytes(kind, source, options.workers)?;
    // Enumerate persisted segment keys WITHOUT loading their (potentially large) CSR byte values.
    // The prior path scanned every persisted segment's full bytes into a map that coexisted with
    // the freshly built `desired` segment bytes — old+new whole-projection copies held at once
    // (#101). A key-only scan is enough to detect regions that must be tombstoned, and each desired
    // segment is compared against persisted bytes via an on-demand point read that holds a single
    // segment at a time.
    let existing_by_region = existing_segment_regions(vault, snapshot, kind)?;
    let desired_by_region = desired
        .segments
        .iter()
        .map(|segment| (segment.region, segment))
        .collect::<BTreeMap<_, _>>();
    // Compare each desired segment against its persisted bytes once (single point read per
    // segment), recording staleness so the write loop below reuses the decision without a second
    // read and without retaining any persisted bytes.
    let mut segment_is_stale = Vec::with_capacity(desired.segments.len());
    let mut stale_regions = BTreeSet::new();
    for segment in &desired.segments {
        let persisted = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &segment.key)?;
        let stale = persisted.as_deref() != Some(segment.bytes.as_slice());
        if stale {
            stale_regions.insert(segment.region);
        }
        segment_is_stale.push(stale);
    }
    for region in existing_by_region.keys() {
        if !desired_by_region.contains_key(region) {
            stale_regions.insert(*region);
        }
    }
    if let Some(dirty_regions) = &options.dirty_regions {
        let missing = stale_regions
            .difference(dirty_regions)
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(projection_corrupt(format!(
                "{} stale regions {:?} were not included in dirty_regions",
                kind.name(),
                missing
            )));
        }
    }

    let mut rows = Vec::new();
    let mut segments_written = 0;
    for (segment, stale) in desired.segments.iter().zip(&segment_is_stale) {
        if *stale {
            rows.push((
                ColumnFamily::Kernel,
                segment.key.clone(),
                segment.bytes.clone(),
            ));
            segments_written += 1;
        }
    }
    let mut segments_tombstoned = 0;
    let mut tombstoned_keys = Vec::new();
    for (region, key) in existing_by_region {
        if !desired_by_region.contains_key(&region) {
            tombstoned_keys.push(key.clone());
            rows.push((ColumnFamily::Kernel, key, tombstone_value()));
            segments_tombstoned += 1;
        }
    }
    let manifest_persisted =
        vault.read_cf_at(snapshot, ColumnFamily::Kernel, &desired.manifest_key)?;
    let manifest_written = manifest_persisted.as_deref() != Some(desired.manifest_bytes.as_slice());
    if manifest_written {
        rows.push((
            ColumnFamily::Kernel,
            desired.manifest_key.clone(),
            desired.manifest_bytes.clone(),
        ));
    }

    let entry = GraphProjectionMaterializeEntry {
        kind,
        source_regions: desired
            .segments
            .iter()
            .map(|segment| segment.region)
            .collect(),
        stale_regions: stale_regions.into_iter().collect(),
        segment_count: desired.segments.len(),
        segments_written,
        segments_tombstoned,
        manifest_written,
        node_count: desired.csr.nodes.len(),
        edge_count: desired.csr.edges.len(),
        association_edge_count: desired.csr.association_edge_count,
        rows_readback_verified: 0,
        ledger_paired: false,
    };
    Ok(ProjectionUpdatePlan {
        desired,
        segment_is_stale,
        tombstoned_keys,
        rows,
        entry,
    })
}

/// Post-commit FSV for one projection materialization (#178 scope item 1).
///
/// Re-reads every Kernel CF row the commit wrote at the commit snapshot and
/// compares persisted bytes against the bytes that were staged: written
/// segments and the manifest must read back byte-identical, tombstoned keys
/// must no longer read back as live values, and the commit's paired ledger
/// entry (Kernel kind, projection actor, projection-name subject) must exist.
/// Any divergence is a fail-closed readback refusal — the mutation is never
/// acked as verified on trust.
fn verify_projection_commit_readback<C>(
    vault: &AsterVault<C>,
    expected: &ProjectionCommitReadbackExpectation<'_>,
) -> IngestResult<usize>
where
    C: Clock,
{
    let kind = expected.kind;
    let commit_seq = expected.commit_seq;
    let ledger_ref = expected.ledger_ref;
    let expected_subject = expected.subject;
    let expected_payload = expected.payload;
    let expected_actor = expected.actor;
    let desired = expected.desired;
    let segment_is_stale = expected.segment_is_stale;
    let manifest_written = expected.manifest_written;
    let tombstoned_keys = expected.tombstoned_keys;
    let mut rows_verified = 0;
    for (segment, stale) in desired.segments.iter().zip(segment_is_stale) {
        if !*stale {
            continue;
        }
        let persisted = vault
            .read_cf_at(commit_seq, ColumnFamily::Kernel, &segment.key)?
            .ok_or_else(|| projection_readback(kind, "segment row missing at commit snapshot"))?;
        if persisted != segment.bytes {
            return Err(projection_readback(
                kind,
                "segment row bytes changed between commit and readback",
            ));
        }
        rows_verified += 1;
    }
    if manifest_written {
        let persisted = vault
            .read_cf_at(commit_seq, ColumnFamily::Kernel, &desired.manifest_key)?
            .ok_or_else(|| projection_readback(kind, "manifest row missing at commit snapshot"))?;
        if persisted != desired.manifest_bytes {
            return Err(projection_readback(
                kind,
                "manifest row bytes changed between commit and readback",
            ));
        }
        rows_verified += 1;
    }
    for key in tombstoned_keys {
        if let Some(persisted) = vault.read_cf_at(commit_seq, ColumnFamily::Kernel, key)?
            && persisted != tombstone_value()
        {
            return Err(projection_readback(
                kind,
                "tombstoned segment still reads back as a live value",
            ));
        }
        rows_verified += 1;
    }

    let ledger_bytes = vault
        .read_cf_at(
            commit_seq,
            ColumnFamily::Ledger,
            &ledger_key(ledger_ref.seq),
        )?
        .ok_or_else(|| {
            projection_readback(
                kind,
                "paired Ledger row absent at projection commit snapshot",
            )
        })?;
    let entry = decode(&ledger_bytes)?;
    if entry.seq != ledger_ref.seq || entry.entry_hash != ledger_ref.hash {
        return Err(projection_readback(
            kind,
            "paired ledger entry differs from the exact commit receipt",
        ));
    }
    if entry.kind != EntryKind::Kernel {
        return Err(projection_readback(
            kind,
            "paired ledger entry has the wrong entry kind",
        ));
    }
    if &entry.actor != expected_actor {
        return Err(projection_readback(
            kind,
            "paired ledger entry names the wrong actor",
        ));
    }
    if &entry.subject != expected_subject {
        return Err(projection_readback(
            kind,
            "paired ledger entry names the wrong subject",
        ));
    }
    if entry.payload.as_slice() != expected_payload {
        return Err(projection_readback(
            kind,
            "paired ledger entry carries the wrong projection payload",
        ));
    }

    Ok(rows_verified)
}

/// Reads the composite source-edge set the graph projections are built from:
/// typed CBM structural edge rows **and** persisted SIM_* similarity edge rows
/// (#522). The returned fingerprint frames the raw persisted bytes of **both**
/// families, so a mutation to either invalidates every persisted CSR — a
/// similarity edge can never be silently dropped and the structural-only graph
/// is never a fallback.
fn read_source_edges<C>(vault: &AsterVault<C>) -> IngestResult<SourceEdges>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    read_source_edges_at(vault, snapshot)
}

fn read_source_edges_at<C>(vault: &AsterVault<C>, snapshot: Seq) -> IngestResult<SourceEdges>
where
    C: Clock,
{
    let latest_before = vault.latest_seq();
    if latest_before != snapshot {
        return Err(projection_corrupt(format!(
            "projection source scan requires the current retained snapshot; requested {snapshot}, current snapshot is {latest_before}"
        )));
    }
    let graph_content_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let mut hasher = blake3::Hasher::new();
    frame_hash(&mut hasher, SOURCE_FINGERPRINT_SCHEMA);

    // Family 1 — typed CBM structural edge rows (`astrolabe:edge:v1:`).
    let typed = vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(EDGE_ROW_PREFIX),
    )?;
    let mut out = Vec::with_capacity(typed.len());
    for (key, value) in typed {
        frame_hash(&mut hasher, &key);
        frame_hash(&mut hasher, &value);
        let row = serde_json::from_slice::<EdgeGraphRow>(&value).map_err(|error| {
            projection_corrupt(format!("decode typed edge row {}: {error}", hex_key(&key)))
        })?;
        validate_source_edge_row(&key, &row)?;
        let kind = edge_kind_from_code(row.etype).ok_or_else(|| {
            projection_corrupt(format!(
                "typed edge row {} has unknown etype {}",
                hex_key(&key),
                row.etype
            ))
        })?;
        out.push(SourceEdgeRow {
            src: row.src,
            dst: row.dst,
            etype: row.etype,
            weight: row.weight,
            kind,
            ledger_seq: row.provenance.seq,
            ledger_hash: row.provenance.hash,
            props: row.props,
            family: SourceFamily::Typed,
        });
    }
    let typed_edge_rows = out.len();

    // Family 2 — persisted SIM_* similarity edge rows (`astrolabe:sim-edge:*`).
    let sim_edge_rows = read_similarity_source_edges(vault, snapshot, &mut hasher, &mut out)?;
    let observed_graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let latest_after = vault.latest_seq();
    if observed_graph_generation != graph_content_generation || latest_after != snapshot {
        return Err(projection_corrupt(format!(
            "source changed during projection scan: expected_snapshot={snapshot}, observed_snapshot={latest_after}, expected_graph_generation={graph_content_generation}, observed_graph_generation={observed_graph_generation}"
        )));
    }

    Ok(SourceEdges {
        rows: out,
        fingerprint: *hasher.finalize().as_bytes(),
        source_snapshot: snapshot,
        graph_content_generation,
        typed_edge_rows,
        sim_edge_rows,
    })
}

/// Plans the composite Kernel CSR from the exact final Graph state of a direct
/// ingest without publishing either side independently.
///
/// `existing_graph` is the importer's one full Graph-CF materialization.
/// `ledger_bound_rows` contains the current commit delta, already stamped with
/// the exact ingest [`calyx_core::LedgerRef`]. The ordered merge below operates
/// on the caller's existing Graph snapshot and that bound delta.
pub(crate) fn plan_atomic_kernel_projection<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    ledger_bound_rows: &[WriteRow],
    workers: usize,
) -> IngestResult<AtomicKernelProjectionPlan>
where
    C: Clock,
{
    let source = source_edges_from_final_graph(vault, snapshot, existing_graph, ledger_bound_rows)?;
    let options = GraphProjectionBuildOptions::new().with_workers(workers);
    let update = plan_projection_update(
        vault,
        snapshot,
        GraphProjectionKind::KernelGraph,
        &options,
        &source,
    )?;
    Ok(AtomicKernelProjectionPlan {
        rows: update.rows,
        report: AtomicKernelProjectionReport {
            source_typed_edge_rows: source.typed_edge_rows,
            source_sim_edge_rows: source.sim_edge_rows,
            source_fingerprint_blake3: source.fingerprint,
            workers: options.workers,
            projection: update.entry,
        },
    })
}

fn source_edges_from_final_graph<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    ledger_bound_rows: &[WriteRow],
) -> IngestResult<SourceEdges>
where
    C: Clock,
{
    if vault.latest_seq() != snapshot {
        return Err(projection_corrupt(format!(
            "direct-ingest final-state projection requires current snapshot {snapshot}, observed {}",
            vault.latest_seq()
        )));
    }
    let graph_content_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let mut overlay = BTreeMap::<&[u8], Option<&[u8]>>::new();
    for row in ledger_bound_rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Graph)
    {
        let value = (!is_tombstone_value(&row.value)).then_some(row.value.as_slice());
        if overlay.insert(row.key.as_slice(), value).is_some() {
            return Err(projection_corrupt(format!(
                "direct-ingest Graph delta contains duplicate key {}",
                hex_key(&row.key)
            )));
        }
    }

    let mut hasher = blake3::Hasher::new();
    frame_hash(&mut hasher, SOURCE_FINGERPRINT_SCHEMA);
    let mut typed = Vec::new();
    let mut resolved = BTreeMap::<String, CxId>::new();
    let mut sim_groups = empty_sim_family_groups();
    let mut final_sim_markers = BTreeMap::<SimSourceFamily, Vec<u8>>::new();
    {
        let mut observe = |key: &[u8], value: &[u8]| -> IngestResult<()> {
            if key.starts_with(EDGE_ROW_PREFIX) {
                frame_hash(&mut hasher, key);
                frame_hash(&mut hasher, value);
                let row = serde_json::from_slice::<EdgeGraphRow>(value).map_err(|error| {
                    projection_corrupt(format!(
                        "decode final typed edge row {}: {error}",
                        hex_key(key)
                    ))
                })?;
                validate_source_edge_row(key, &row)?;
                let kind = edge_kind_from_code(row.etype).ok_or_else(|| {
                    projection_corrupt(format!(
                        "final typed edge row {} has unknown etype {}",
                        hex_key(key),
                        row.etype
                    ))
                })?;
                typed.push(SourceEdgeRow {
                    src: row.src,
                    dst: row.dst,
                    etype: row.etype,
                    weight: row.weight,
                    kind,
                    ledger_seq: row.provenance.seq,
                    ledger_hash: row.provenance.hash,
                    props: row.props,
                    family: SourceFamily::Typed,
                });
            } else if key.starts_with(NODE_MAP_PREFIX) {
                let row =
                    serde_json::from_slice::<NodeMapProjectionRow>(value).map_err(|error| {
                        projection_corrupt(format!(
                            "decode final node-map row {}: {error}",
                            hex_key(key)
                        ))
                    })?;
                if !supported_node_map_schema(&row.schema) {
                    return Err(projection_corrupt(format!(
                        "final node-map row {} has wrong schema {}",
                        row.node_id, row.schema
                    )));
                }
                if row.atom_id.trim().is_empty() {
                    return Err(projection_corrupt(format!(
                        "final node-map row {} ({:?}) has an empty stable atom id",
                        row.node_id, row.qualified_name
                    )));
                }
                if let Some(existing) = resolved.insert(row.atom_id.clone(), row.cx_id) {
                    return Err(projection_corrupt(format!(
                        "stable atom id {:?} maps to multiple final node-map CxIds: {} and {}",
                        row.atom_id, existing, row.cx_id
                    )));
                }
            } else if key.starts_with(SIM_EDGE_ROW_BASE_PREFIX) {
                collect_sim_family_row(&mut sim_groups, key.to_vec(), value.to_vec())?;
            } else if key.starts_with(SIM_SOURCE_ATTESTATION_PREFIX) {
                let family = sim_source_attestation_family_from_key(key)?;
                if final_sim_markers.insert(family, value.to_vec()).is_some() {
                    return Err(projection_corrupt(format!(
                        "direct-ingest final Graph state contains duplicate {} SIM source markers",
                        family.wire_name()
                    )));
                }
            }
            Ok(())
        };

        let mut existing = existing_graph.iter().peekable();
        let mut changed = overlay.iter().peekable();
        loop {
            match (existing.peek(), changed.peek()) {
                (Some((existing_key, existing_value)), Some((changed_key, changed_value))) => {
                    match existing_key.as_slice().cmp(changed_key) {
                        std::cmp::Ordering::Less => {
                            observe(existing_key, existing_value)?;
                            existing.next();
                        }
                        std::cmp::Ordering::Equal => {
                            if let Some(value) = changed_value {
                                observe(changed_key, value)?;
                            }
                            existing.next();
                            changed.next();
                        }
                        std::cmp::Ordering::Greater => {
                            if let Some(value) = changed_value {
                                observe(changed_key, value)?;
                            }
                            changed.next();
                        }
                    }
                }
                (Some((key, value)), None) => {
                    observe(key, value)?;
                    existing.next();
                }
                (None, Some((key, value))) => {
                    if let Some(value) = value {
                        observe(key, value)?;
                    }
                    changed.next();
                }
                (None, None) => break,
            }
        }
    }

    let typed_edge_rows = typed.len();
    let sim_edge_rows = sim_groups.values().try_fold(0usize, |total, group| {
        total
            .checked_add(group.rows.len())
            .ok_or_else(|| projection_corrupt("direct-ingest SIM source row count overflow"))
    })?;
    append_verified_sim_groups(
        vault,
        snapshot,
        &resolved,
        &mut sim_groups,
        Some(&final_sim_markers),
        &mut hasher,
        &mut typed,
    )?;
    let observed_graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let latest_after = vault.latest_seq();
    if observed_graph_generation != graph_content_generation || latest_after != snapshot {
        return Err(projection_corrupt(format!(
            "source changed during direct-ingest final-state projection planning: expected_snapshot={snapshot}, observed_snapshot={latest_after}, expected_graph_generation={graph_content_generation}, observed_graph_generation={observed_graph_generation}"
        )));
    }

    Ok(SourceEdges {
        rows: typed,
        fingerprint: *hasher.finalize().as_bytes(),
        source_snapshot: snapshot,
        graph_content_generation,
        typed_edge_rows,
        sim_edge_rows,
    })
}

/// Scans and normalizes the persisted SIM_* similarity edge family, appending
/// the resolved edges to `out` and framing every raw persisted row's bytes into
/// `hasher` (so the shared source fingerprint covers this family). Returns the
/// number of SIM rows folded in.
///
/// Fails closed — never silently drops a similarity source family — on: an
/// unknown `astrolabe:sim-edge:` version segment, a wrong row schema, a family
/// whose edge kind is not a similarity edge, a non-finite or out-of-range
/// weight, a source/target stable atom id that is unmapped in the
/// persisted node map, or SIM rows whose exact family dump lacks a matching
/// terminal marker and point-readable Ledger attestation.
fn read_similarity_source_edges<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    hasher: &mut blake3::Hasher,
    out: &mut Vec<SourceEdgeRow>,
) -> IngestResult<usize>
where
    C: Clock,
{
    let raw = vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_EDGE_ROW_BASE_PREFIX),
    )?;
    let mut groups = empty_sim_family_groups();
    for (key, value) in raw {
        collect_sim_family_row(&mut groups, key, value)?;
    }
    let row_count = groups.values().try_fold(0usize, |total, group| {
        total
            .checked_add(group.rows.len())
            .ok_or_else(|| projection_corrupt("SIM source row count overflow"))
    })?;
    let resolved = if row_count == 0 {
        BTreeMap::new()
    } else {
        crate::sqlite_import::read_global_atom_cx_ids_at(vault, snapshot)?
    };
    append_verified_sim_groups(vault, snapshot, &resolved, &mut groups, None, hasher, out)?;
    Ok(row_count)
}

#[derive(Clone, Copy, Debug)]
struct VerifiedSimFamilyAttestation {
    ledger_seq: u64,
    ledger_hash: [u8; 32],
}

fn empty_sim_family_groups() -> BTreeMap<SimSourceFamily, SimFamilySourceRows> {
    SimSourceFamily::ALL
        .into_iter()
        .map(|family| (family, SimFamilySourceRows::new()))
        .collect()
}

fn collect_sim_family_row(
    groups: &mut BTreeMap<SimSourceFamily, SimFamilySourceRows>,
    key: Vec<u8>,
    value: Vec<u8>,
) -> IngestResult<()> {
    if !key.starts_with(SIM_EDGE_ROW_V2_PREFIX) {
        return Err(projection_corrupt(format!(
            "SIM edge row {} carries an unknown astrolabe:sim-edge version; refusing to build a projection that would silently omit a similarity source family",
            hex_key(&key)
        )));
    }
    let row = serde_json::from_slice::<SimEdgeSourceRow>(&value).map_err(|error| {
        projection_corrupt(format!("decode SIM edge row {}: {error}", hex_key(&key)))
    })?;
    let family = validate_sim_source_row(&key, &row)?;
    let group = groups
        .get_mut(&family)
        .expect("complete fixed SIM family roster");
    if group
        .rows
        .last()
        .is_some_and(|(previous, _, _)| previous >= &key)
    {
        return Err(projection_corrupt(format!(
            "{} SIM family rows are not strictly key-sorted at {}",
            family.wire_name(),
            hex_key(&key)
        )));
    }
    frame_hash(&mut group.content_hasher, &key);
    frame_hash(&mut group.content_hasher, &value);
    group.row_count = group
        .row_count
        .checked_add(1)
        .ok_or_else(|| projection_corrupt("SIM family row count overflow"))?;
    group.total_bytes = group
        .total_bytes
        .checked_add(key.len() as u64)
        .and_then(|total| total.checked_add(value.len() as u64))
        .ok_or_else(|| projection_corrupt("SIM family byte count overflow"))?;
    group.rows.push((key, value, row));
    Ok(())
}

fn validate_sim_source_row(key: &[u8], row: &SimEdgeSourceRow) -> IngestResult<SimSourceFamily> {
    if row.schema != SCHEMA_SIM_EDGE_ROW {
        return Err(projection_corrupt(format!(
            "SIM edge row {} carries schema {:?}, expected {SCHEMA_SIM_EDGE_ROW}",
            hex_key(key),
            row.schema
        )));
    }
    let family = SimSourceFamily::from_wire_name(&row.family).ok_or_else(|| {
        projection_corrupt(format!(
            "SIM edge row {} names unknown family {:?}",
            hex_key(key),
            row.family
        ))
    })?;
    if row.source_id.trim().is_empty() || row.target_id.trim().is_empty() {
        return Err(projection_corrupt(format!(
            "SIM edge row {} carries an empty stable endpoint identity",
            hex_key(key)
        )));
    }
    if row.slot != family.slot() || row.etype != family.edge_kind().code() || row.metric != "cosine"
    {
        return Err(projection_corrupt(format!(
            "SIM edge row {} disagrees with {} family metadata",
            hex_key(key),
            family.wire_name()
        )));
    }
    let expected_key = sim_source_row_key(family, &row.source_id, &row.target_id);
    if key != expected_key.as_slice() {
        return Err(projection_corrupt(format!(
            "SIM edge row key {} does not match its decoded family/endpoints",
            hex_key(key)
        )));
    }
    let weight = f32::from_bits(row.weight_bits);
    let threshold = f32::from_bits(row.threshold_bits);
    validate_edge_weight(weight, "SIM edge weight")?;
    validate_edge_weight(threshold, "SIM edge threshold")?;
    let expected_props = BTreeMap::from([
        ("family".to_string(), row.family.clone()),
        ("metric".to_string(), row.metric.clone()),
        ("source_atom_id".to_string(), row.source_id.clone()),
        ("target_atom_id".to_string(), row.target_id.clone()),
        ("slot_id".to_string(), row.slot.to_string()),
        ("score".to_string(), format!("{weight:.9}")),
        ("threshold".to_string(), format!("{threshold:.9}")),
    ]);
    if row.props != expected_props {
        return Err(projection_corrupt(format!(
            "SIM edge row {} carries properties inconsistent with its typed fields",
            hex_key(key)
        )));
    }
    Ok(family)
}

fn sim_source_row_key(family: SimSourceFamily, source_id: &str, target_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        SIM_EDGE_ROW_V2_PREFIX.len() + 1 + 4 + source_id.len() + 4 + target_id.len(),
    );
    key.extend_from_slice(SIM_EDGE_ROW_V2_PREFIX);
    key.push(family.sort_index());
    key.extend_from_slice(&(source_id.len() as u32).to_be_bytes());
    key.extend_from_slice(source_id.as_bytes());
    key.extend_from_slice(&(target_id.len() as u32).to_be_bytes());
    key.extend_from_slice(target_id.as_bytes());
    key
}

fn append_verified_sim_groups<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    resolved: &BTreeMap<String, CxId>,
    groups: &mut BTreeMap<SimSourceFamily, SimFamilySourceRows>,
    final_markers: Option<&BTreeMap<SimSourceFamily, Vec<u8>>>,
    hasher: &mut blake3::Hasher,
    out: &mut Vec<SourceEdgeRow>,
) -> IngestResult<()>
where
    C: Clock,
{
    for family in SimSourceFamily::ALL {
        let group = groups
            .get_mut(&family)
            .expect("complete fixed SIM family roster");
        let marker_key = sim_source_attestation_key(family);
        let marker_bytes = match final_markers {
            Some(markers) => markers.get(&family).cloned(),
            None => vault.read_cf_at(snapshot, ColumnFamily::Graph, &marker_key)?,
        };
        let Some(marker_bytes) = marker_bytes else {
            if group.row_count != 0 {
                return Err(projection_corrupt(format!(
                    "{} has {} persisted SIM rows but no terminal source attestation marker",
                    family.wire_name(),
                    group.row_count
                )));
            }
            continue;
        };
        let attestation =
            verify_sim_family_attestation(vault, snapshot, family, group, &marker_bytes)?;
        frame_hash(
            hasher,
            b"astrolabe.graph_projection.sim_family_attestation.v1",
        );
        frame_hash(hasher, &marker_key);
        frame_hash(hasher, &marker_bytes);
        for (key, value, row) in std::mem::take(&mut group.rows) {
            frame_hash(hasher, &key);
            frame_hash(hasher, &value);
            let src = resolve_sim_endpoint(resolved, &row.source_id, &key, "source")?;
            let dst = resolve_sim_endpoint(resolved, &row.target_id, &key, "target")?;
            frame_resolved_sim_source(
                hasher,
                src,
                dst,
                attestation.ledger_seq,
                &attestation.ledger_hash,
            );
            out.push(SourceEdgeRow {
                src,
                dst,
                etype: row.etype,
                weight: f32::from_bits(row.weight_bits),
                kind: family.edge_kind(),
                ledger_seq: attestation.ledger_seq,
                ledger_hash: attestation.ledger_hash,
                props: serde_json::Value::Null,
                family: SourceFamily::Similarity,
            });
        }
    }
    Ok(())
}

fn verify_sim_family_attestation<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    family: SimSourceFamily,
    group: &SimFamilySourceRows,
    marker_bytes: &[u8],
) -> IngestResult<VerifiedSimFamilyAttestation>
where
    C: Clock,
{
    let marker: SimSourceAttestation = serde_json::from_slice(marker_bytes).map_err(|error| {
        projection_corrupt(format!(
            "decode {} terminal SIM source marker: {error}",
            family.wire_name()
        ))
    })?;
    let canonical_marker_bytes = serde_json::to_vec(&marker).map_err(|error| {
        projection_corrupt(format!(
            "encode canonical {} terminal SIM source marker: {error}",
            family.wire_name()
        ))
    })?;
    if canonical_marker_bytes.as_slice() != marker_bytes {
        return Err(projection_corrupt(format!(
            "{} terminal SIM source marker bytes are not canonical",
            family.wire_name()
        )));
    }
    let observed_content = hex_lower(group.content_hasher.finalize().as_bytes());
    let marker_content = parse_hash_32(&marker.content_blake3)?;
    let marker_ledger_hash = parse_hash_32(&marker.ledger_hash)?;
    if marker.schema != SIM_SOURCE_ATTESTATION_SCHEMA
        || marker.family != family.wire_name()
        || marker.row_count != group.row_count
        || marker.total_bytes != group.total_bytes
        || marker.content_blake3 != observed_content
        || hex_lower(&marker_content) != marker.content_blake3
        || hex_lower(&marker_ledger_hash) != marker.ledger_hash
    {
        return Err(projection_corrupt(format!(
            "{} terminal SIM source marker does not match the exact sorted family readback: marker_rows={}, observed_rows={}, marker_bytes={}, observed_bytes={}, marker_hash={}, observed_hash={observed_content}",
            family.wire_name(),
            marker.row_count,
            group.row_count,
            marker.total_bytes,
            group.total_bytes,
            marker.content_blake3,
        )));
    }
    let ledger_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(marker.ledger_seq),
        )?
        .ok_or_else(|| {
            projection_corrupt(format!(
                "{} terminal SIM marker names absent Ledger row {}",
                family.wire_name(),
                marker.ledger_seq
            ))
        })?;
    let entry = decode(&ledger_bytes)?;
    let expected_payload = SimSourceAttestationLedgerPayload {
        schema: SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA.to_string(),
        family: family.wire_name().to_string(),
        row_count: group.row_count,
        total_bytes: group.total_bytes,
        content_blake3: observed_content,
    };
    let observed_payload: SimSourceAttestationLedgerPayload =
        serde_json::from_slice(&entry.payload).map_err(|error| {
            projection_corrupt(format!(
                "decode {} terminal SIM Ledger payload: {error}",
                family.wire_name()
            ))
        })?;
    let expected_payload_bytes = serde_json::to_vec(&expected_payload).map_err(|error| {
        projection_corrupt(format!(
            "encode expected {} terminal SIM Ledger payload: {error}",
            family.wire_name()
        ))
    })?;
    let expected_subject = sim_source_attestation_subject(family, group);
    if entry.seq != marker.ledger_seq
        || entry.entry_hash != marker_ledger_hash
        || entry.kind != EntryKind::Ingest
        || entry.subject != expected_subject
        || entry.actor != ActorId::Service(marker.actor.clone())
        || observed_payload != expected_payload
        || entry.payload != expected_payload_bytes
    {
        return Err(projection_corrupt(format!(
            "{} terminal SIM Ledger row {} disagrees with marker kind/subject/payload/actor/ref",
            family.wire_name(),
            marker.ledger_seq
        )));
    }
    Ok(VerifiedSimFamilyAttestation {
        ledger_seq: marker.ledger_seq,
        ledger_hash: marker_ledger_hash,
    })
}

fn sim_source_attestation_key(family: SimSourceFamily) -> Vec<u8> {
    let mut key = SIM_SOURCE_ATTESTATION_PREFIX.to_vec();
    key.extend_from_slice(family.wire_name().as_bytes());
    key
}

fn sim_source_attestation_family_from_key(key: &[u8]) -> IngestResult<SimSourceFamily> {
    SimSourceFamily::ALL
        .into_iter()
        .find(|family| key == sim_source_attestation_key(*family))
        .ok_or_else(|| {
            projection_corrupt(format!(
                "unknown SIM source attestation marker key {}",
                hex_key(key)
            ))
        })
}

fn sim_source_attestation_subject(
    family: SimSourceFamily,
    group: &SimFamilySourceRows,
) -> SubjectId {
    SubjectId::Query(
        format!(
            "{SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX}:{}:{}:{}:{}",
            family.wire_name(),
            group.row_count,
            group.total_bytes,
            hex_lower(group.content_hasher.finalize().as_bytes())
        )
        .into_bytes(),
    )
}

fn frame_resolved_sim_source(
    hasher: &mut blake3::Hasher,
    src: CxId,
    dst: CxId,
    ledger_seq: u64,
    ledger_hash: &[u8; 32],
) {
    frame_hash(hasher, b"astrolabe.graph_projection.resolved_sim_source.v1");
    frame_hash(hasher, src.as_bytes());
    frame_hash(hasher, dst.as_bytes());
    frame_hash(hasher, &ledger_seq.to_be_bytes());
    frame_hash(hasher, ledger_hash);
}

/// Resolves one SIM edge stable source-atom id to its `CxId` fail-closed.
fn resolve_sim_endpoint(
    resolved: &BTreeMap<String, CxId>,
    symbol_id: &str,
    key: &[u8],
    role: &str,
) -> IngestResult<CxId> {
    resolved.get(symbol_id).copied().ok_or_else(|| {
        projection_corrupt(format!(
            "SIM edge row {} {role} stable atom id {:?} has no persisted node-map CxId mapping",
            hex_key(key),
            symbol_id
        ))
    })
}

fn validate_source_edge_row(key: &[u8], row: &EdgeGraphRow) -> IngestResult<()> {
    if row.schema != SCHEMA_EDGE_ROW {
        return Err(projection_corrupt(format!(
            "typed edge row {} has wrong schema {}",
            hex_key(key),
            row.schema
        )));
    }
    let Some(kind) = EdgeKind::from_cbm_type(&row.edge_type) else {
        return Err(projection_corrupt(format!(
            "typed edge row {} has unknown edge_type {}",
            hex_key(key),
            row.edge_type
        )));
    };
    if kind.code() != row.etype {
        return Err(projection_corrupt(format!(
            "typed edge row {} etype {} does not match {}",
            hex_key(key),
            row.etype,
            row.edge_type
        )));
    }
    validate_edge_weight(row.weight, "source edge weight")?;
    if !row.props.is_object() {
        return Err(projection_corrupt(format!(
            "typed edge row {} props are not an object",
            hex_key(key)
        )));
    }
    Ok(())
}

fn build_projection_bytes(
    kind: GraphProjectionKind,
    source: &SourceEdges,
    workers: usize,
) -> IngestResult<ProjectionBytes> {
    let csr = build_projection_csr(kind, source)?;
    let mut segments = encode_region_segments(kind, segment_projection(&csr)?, workers)?;
    segments.sort_by_key(|segment| segment.region);
    let manifest = ProjectionManifest {
        schema: PROJECTION_SCHEMA.to_string(),
        csr_manifest_version: MANIFEST_VERSION,
        projection: kind.name().to_string(),
        source_fingerprint_blake3: hex_lower(&source.fingerprint),
        node_count: csr.nodes.len(),
        edge_count: csr.edges.len(),
        association_edge_count: csr.association_edge_count,
        segment_count: segments.len(),
        regions: segments
            .iter()
            .map(|segment| segment.manifest.clone())
            .collect(),
    };
    Ok(ProjectionBytes {
        csr,
        manifest_bytes: serde_json::to_vec(&manifest)?,
        manifest_key: manifest_key(kind),
        segments,
    })
}

/// Encodes each region CSR segment into its persisted bytes, sharding the
/// independent per-region encode + BLAKE3 hash across `workers`.
///
/// Region segments are disjoint (each owns a distinct region id and node/edge
/// slice) and encoding is pure, so partitioning the regions across worker threads
/// and merging their outputs is a merge-order-invariant reduction: every region is
/// encoded exactly once and [`build_projection_bytes`] sorts the merged segments
/// by region. The persisted bytes are therefore byte-identical for any `workers`,
/// which is the property `projection_bytes_are_deterministic_across_workers_and_repeated_builds`
/// asserts. This is the caller-visible `workers` knob's real effect; it no longer
/// only round-trips into the materialize report.
fn encode_region_segments(
    kind: GraphProjectionKind,
    regions: Vec<(u8, DecodedSegment)>,
    workers: usize,
) -> IngestResult<Vec<ProjectionSegmentBytes>> {
    let worker_count = workers.min(regions.len()).max(1);
    if worker_count == 1 {
        return regions
            .into_iter()
            .map(|(region, segment)| encode_region_segment(kind, region, &segment))
            .collect();
    }

    let chunk_size = regions.len().div_ceil(worker_count);
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in regions.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            handles.push(scope.spawn(move || {
                chunk
                    .into_iter()
                    .map(|(region, segment)| encode_region_segment(kind, region, &segment))
                    .collect::<IngestResult<Vec<_>>>()
            }));
        }
        let mut out = Vec::new();
        for handle in handles {
            out.extend(handle.join().map_err(|_| {
                projection_corrupt("graph projection region-encode worker panicked")
            })??);
        }
        Ok(out)
    })
}

fn encode_region_segment(
    kind: GraphProjectionKind,
    region: u8,
    segment: &DecodedSegment,
) -> IngestResult<ProjectionSegmentBytes> {
    let bytes = encode_segment(segment)?;
    let stream_blake3 = blake3::hash(&bytes).to_hex().to_string();
    Ok(ProjectionSegmentBytes {
        region,
        key: segment_key(kind, region),
        manifest: ProjectionManifestRegion {
            region,
            node_count: segment.nodes.len(),
            edge_count: segment.edges.len(),
            total_bytes: bytes.len(),
            stream_blake3,
        },
        bytes,
    })
}

fn build_projection_csr(
    kind: GraphProjectionKind,
    source: &SourceEdges,
) -> IngestResult<GraphProjectionCsr> {
    let mut node_weights = BTreeMap::<CxId, f32>::new();
    // Per deduped (src, dst, etype): the max projected weight, plus the strongest
    // ledger attestation (greatest (seq, hash)) among the source rows that produced
    // it (#393). Every source edge row carries a real `provenance` LedgerRef pointing
    // at a persisted Ledger CF entry; picking the greatest deterministically pairs a
    // real attestation with the projection edge without fabricating a reference.
    let mut edges = BTreeMap::<(CxId, CxId, u16), (f32, u64, [u8; 32])>::new();
    for source_edge in &source.rows {
        let Some(weight) = kind.projected_weight(source_edge.kind, source_edge.weight) else {
            continue;
        };
        validate_edge_weight(weight, "projection edge weight")?;
        node_weights.entry(source_edge.src).or_insert(1.0);
        node_weights.entry(source_edge.dst).or_insert(1.0);
        if kind == GraphProjectionKind::KernelGraph {
            apply_kernel_node_weight(&mut node_weights, source_edge)?;
        }
        let seq = source_edge.ledger_seq;
        let hash = source_edge.ledger_hash;
        edges
            .entry((source_edge.src, source_edge.dst, source_edge.etype))
            .and_modify(|current| {
                current.0 = current.0.max(weight);
                if (seq, hash) > (current.1, current.2) {
                    current.1 = seq;
                    current.2 = hash;
                }
            })
            .or_insert((weight, seq, hash));
    }

    let nodes = node_weights
        .into_iter()
        .map(|(id, weight)| GraphProjectionNode { id, weight })
        .collect::<Vec<_>>();
    let mut node_index = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        validate_node_weight(node.weight)?;
        node_index.insert(node.id, index);
    }
    let mut by_src = vec![Vec::<GraphProjectionCsrEdge>::new(); nodes.len()];
    let mut association_edges = BTreeSet::<(CxId, CxId)>::new();
    for ((src, dst, etype), (weight, ledger_seq, ledger_hash)) in edges {
        let src_index = *node_index
            .get(&src)
            .ok_or_else(|| projection_corrupt("projection edge source has no node row"))?;
        by_src[src_index].push(GraphProjectionCsrEdge {
            dst,
            etype,
            weight,
            ledger_seq,
            ledger_hash,
        });
        association_edges.insert((src, dst));
    }
    let mut offsets = Vec::with_capacity(nodes.len() + 1);
    let mut flat_edges = Vec::new();
    offsets.push(0);
    for src_edges in &mut by_src {
        src_edges.sort_by(|left, right| {
            left.etype
                .cmp(&right.etype)
                .then_with(|| left.dst.cmp(&right.dst))
        });
        flat_edges.append(src_edges);
        offsets.push(flat_edges.len());
    }
    let csr = GraphProjectionCsr {
        kind,
        source_fingerprint_blake3: source.fingerprint,
        nodes,
        offsets,
        edges: flat_edges,
        association_edge_count: association_edges.len(),
    };
    validate_csr(&csr)?;
    Ok(csr)
}

fn apply_kernel_node_weight(
    node_weights: &mut BTreeMap<CxId, f32>,
    row: &SourceEdgeRow,
) -> IngestResult<()> {
    if let Some(count) = numeric_prop_any(&row.props, &["src_change_count", "source_change_count"])?
    {
        node_weights.insert(row.src, count + 1.0);
    }
    if let Some(count) = numeric_prop_any(&row.props, &["dst_change_count", "target_change_count"])?
    {
        node_weights.insert(row.dst, count + 1.0);
    }
    if row.etype == EdgeKind::FileChangesWith.code()
        && let Some(count) = numeric_prop_any(&row.props, &["change_count"])?
    {
        node_weights
            .entry(row.src)
            .and_modify(|weight| *weight = (*weight).max(count + 1.0))
            .or_insert(count + 1.0);
        node_weights
            .entry(row.dst)
            .and_modify(|weight| *weight = (*weight).max(count + 1.0))
            .or_insert(count + 1.0);
    }
    Ok(())
}

fn segment_projection(csr: &GraphProjectionCsr) -> IngestResult<Vec<(u8, DecodedSegment)>> {
    let mut nodes_by_region = BTreeMap::<u8, Vec<(usize, GraphProjectionNode)>>::new();
    for (index, node) in csr.nodes.iter().copied().enumerate() {
        nodes_by_region
            .entry(region_for(node.id))
            .or_default()
            .push((index, node));
    }
    let mut segments = Vec::with_capacity(nodes_by_region.len());
    for (region, indexed_nodes) in nodes_by_region {
        let mut nodes = Vec::with_capacity(indexed_nodes.len());
        let mut offsets = Vec::with_capacity(indexed_nodes.len() + 1);
        let mut edges = Vec::new();
        offsets.push(0);
        for (source_index, node) in indexed_nodes {
            nodes.push(node);
            let start = csr.offsets[source_index];
            let end = csr.offsets[source_index + 1];
            edges.extend_from_slice(&csr.edges[start..end]);
            offsets.push(edges.len());
        }
        segments.push((
            region,
            DecodedSegment {
                kind: csr.kind,
                region,
                nodes,
                offsets,
                edges,
            },
        ));
    }
    Ok(segments)
}

fn load_persisted_projection_at<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    incomplete_ok: bool,
    snapshot: Seq,
) -> IngestResult<PersistedProjectionState>
where
    C: Clock,
{
    let Some(manifest_bytes) =
        vault.read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key(kind))?
    else {
        return Ok(PersistedProjectionState::Missing);
    };
    let manifest = match serde_json::from_slice::<ProjectionManifest>(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) if incomplete_ok => {
            let _ = error;
            return Ok(PersistedProjectionState::Incomplete);
        }
        Err(error) => {
            return Err(projection_corrupt(format!(
                "decode {} CSR manifest: {error}",
                kind.name()
            )));
        }
    };
    if let Err(error) = validate_manifest(kind, &manifest) {
        if incomplete_ok {
            return Ok(PersistedProjectionState::Incomplete);
        }
        return Err(error);
    }
    let mut segments = Vec::with_capacity(manifest.regions.len());
    for region in &manifest.regions {
        let Some(bytes) = vault.read_cf_at(
            snapshot,
            ColumnFamily::Kernel,
            &segment_key(kind, region.region),
        )?
        else {
            return Ok(PersistedProjectionState::Incomplete);
        };
        if bytes.len() != region.total_bytes {
            if incomplete_ok {
                return Ok(PersistedProjectionState::Incomplete);
            }
            return Err(projection_corrupt(format!(
                "{} segment {} byte length {} does not match manifest {}",
                kind.name(),
                region.region,
                bytes.len(),
                region.total_bytes
            )));
        }
        let stream_blake3 = blake3::hash(&bytes).to_hex().to_string();
        if stream_blake3 != region.stream_blake3 {
            if incomplete_ok {
                return Ok(PersistedProjectionState::Incomplete);
            }
            return Err(projection_corrupt(format!(
                "{} segment {} hash {} does not match manifest {}",
                kind.name(),
                region.region,
                stream_blake3,
                region.stream_blake3
            )));
        }
        match decode_segment(&bytes) {
            Ok(segment) => segments.push(segment),
            Err(error) if incomplete_ok => {
                let _ = error;
                return Ok(PersistedProjectionState::Incomplete);
            }
            Err(error) => return Err(error),
        }
    }
    let csr = assemble_segments(kind, &manifest, segments)?;
    Ok(PersistedProjectionState::Complete(csr))
}

fn assemble_segments(
    kind: GraphProjectionKind,
    manifest: &ProjectionManifest,
    mut segments: Vec<DecodedSegment>,
) -> IngestResult<GraphProjectionCsr> {
    let source_fingerprint = parse_hash_32(&manifest.source_fingerprint_blake3)?;
    segments.sort_by_key(|segment| segment.region);
    let mut nodes = Vec::new();
    let mut offsets = Vec::new();
    let mut edges = Vec::new();
    offsets.push(0);
    for segment in segments {
        if segment.kind != kind {
            return Err(projection_corrupt(format!(
                "projection segment kind {:?} does not match manifest {:?}",
                segment.kind, kind
            )));
        }
        for (index, node) in segment.nodes.into_iter().enumerate() {
            nodes.push(node);
            let start = segment.offsets[index];
            let end = segment.offsets[index + 1];
            edges.extend_from_slice(&segment.edges[start..end]);
            offsets.push(edges.len());
        }
    }
    let csr = GraphProjectionCsr {
        kind,
        source_fingerprint_blake3: source_fingerprint,
        nodes,
        offsets,
        edges,
        association_edge_count: manifest.association_edge_count,
    };
    validate_csr(&csr)?;
    if csr.nodes.len() != manifest.node_count || csr.edges.len() != manifest.edge_count {
        return Err(projection_corrupt(format!(
            "{} decoded CSR counts differ from manifest",
            kind.name()
        )));
    }
    Ok(csr)
}

fn validate_manifest(kind: GraphProjectionKind, manifest: &ProjectionManifest) -> IngestResult<()> {
    if manifest.schema != PROJECTION_SCHEMA {
        return Err(projection_corrupt(format!(
            "{} manifest has wrong schema {}",
            kind.name(),
            manifest.schema
        )));
    }
    if manifest.csr_manifest_version != MANIFEST_VERSION {
        return Err(projection_corrupt(format!(
            "{} manifest version {} is not supported",
            kind.name(),
            manifest.csr_manifest_version
        )));
    }
    if manifest.projection != kind.name() {
        return Err(projection_corrupt(format!(
            "{} manifest projection name is {}",
            kind.name(),
            manifest.projection
        )));
    }
    if manifest.segment_count != manifest.regions.len() {
        return Err(projection_corrupt(format!(
            "{} manifest segment_count {} differs from region count {}",
            kind.name(),
            manifest.segment_count,
            manifest.regions.len()
        )));
    }
    let source_fingerprint = parse_hash_32(&manifest.source_fingerprint_blake3)?;
    if hex_lower(&source_fingerprint) != manifest.source_fingerprint_blake3 {
        return Err(projection_corrupt(format!(
            "{} manifest source fingerprint is not canonical lowercase hexadecimal",
            kind.name()
        )));
    }
    if manifest.association_edge_count > manifest.edge_count {
        return Err(projection_corrupt(format!(
            "{} manifest association edge count {} exceeds total edge count {}",
            kind.name(),
            manifest.association_edge_count,
            manifest.edge_count
        )));
    }
    if manifest.node_count == 0
        && (manifest.edge_count != 0
            || manifest.association_edge_count != 0
            || manifest.segment_count != 0)
    {
        return Err(projection_corrupt(format!(
            "{} empty manifest has nonempty edges/associations/segments",
            kind.name()
        )));
    }
    if manifest.node_count != 0 && manifest.segment_count == 0 {
        return Err(projection_corrupt(format!(
            "{} nonempty manifest has no regions",
            kind.name()
        )));
    }
    let mut region_nodes = 0_usize;
    let mut region_edges = 0_usize;
    for pair in manifest.regions.windows(2) {
        if pair[0].region >= pair[1].region {
            return Err(projection_corrupt(format!(
                "{} manifest regions are not strictly ordered",
                kind.name()
            )));
        }
    }
    for region in &manifest.regions {
        if region.node_count == 0 || region.total_bytes == 0 {
            return Err(projection_corrupt(format!(
                "{} manifest region {} has zero nodes or bytes",
                kind.name(),
                region.region
            )));
        }
        let stream_hash = parse_hash_32(&region.stream_blake3)?;
        if hex_lower(&stream_hash) != region.stream_blake3 {
            return Err(projection_corrupt(format!(
                "{} manifest region {} stream hash is not canonical lowercase hexadecimal",
                kind.name(),
                region.region
            )));
        }
        region_nodes = region_nodes.checked_add(region.node_count).ok_or_else(|| {
            projection_corrupt(format!(
                "{} manifest region node count overflow",
                kind.name()
            ))
        })?;
        region_edges = region_edges.checked_add(region.edge_count).ok_or_else(|| {
            projection_corrupt(format!(
                "{} manifest region edge count overflow",
                kind.name()
            ))
        })?;
    }
    if region_nodes != manifest.node_count || region_edges != manifest.edge_count {
        return Err(projection_corrupt(format!(
            "{} manifest region totals nodes={region_nodes}/{} edges={region_edges}/{} disagree with top-level counts",
            kind.name(),
            manifest.node_count,
            manifest.edge_count
        )));
    }
    Ok(())
}

fn validate_csr(csr: &GraphProjectionCsr) -> IngestResult<()> {
    if csr.offsets.len() != csr.nodes.len() + 1 {
        return Err(projection_corrupt(format!(
            "{} CSR offsets length {} does not match nodes {}",
            csr.kind.name(),
            csr.offsets.len(),
            csr.nodes.len()
        )));
    }
    if csr.offsets.first().copied() != Some(0) {
        return Err(projection_corrupt(format!(
            "{} CSR offsets must start at 0",
            csr.kind.name()
        )));
    }
    if csr.offsets.last().copied() != Some(csr.edges.len()) {
        return Err(projection_corrupt(format!(
            "{} CSR final offset {:?} does not match edge count {}",
            csr.kind.name(),
            csr.offsets.last(),
            csr.edges.len()
        )));
    }
    for pair in csr.offsets.windows(2) {
        if pair[0] > pair[1] {
            return Err(projection_corrupt(format!(
                "{} CSR offsets are not monotonic",
                csr.kind.name()
            )));
        }
    }
    let mut previous = None;
    for node in &csr.nodes {
        validate_node_weight(node.weight)?;
        if let Some(previous) = previous
            && previous >= node.id
        {
            return Err(projection_corrupt(format!(
                "{} CSR nodes are not strictly sorted",
                csr.kind.name()
            )));
        }
        previous = Some(node.id);
    }
    let node_set = csr
        .nodes
        .iter()
        .map(|node| node.id)
        .collect::<BTreeSet<_>>();
    for edge in &csr.edges {
        if !node_set.contains(&edge.dst) {
            return Err(projection_corrupt(format!(
                "{} CSR edge destination {} has no node",
                csr.kind.name(),
                edge.dst
            )));
        }
        validate_edge_weight(edge.weight, "CSR edge weight")?;
        if edge_kind_from_code(edge.etype).is_none() {
            return Err(projection_corrupt(format!(
                "{} CSR edge etype {} is unknown",
                csr.kind.name(),
                edge.etype
            )));
        }
    }
    Ok(())
}

fn encode_segment(segment: &DecodedSegment) -> IngestResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(SEGMENT_MAGIC);
    put_u32(&mut out, SEGMENT_VERSION);
    out.push(segment.kind.wire_code());
    out.push(segment.region);
    put_len(&mut out, segment.nodes.len(), "segment node count")?;
    put_len(&mut out, segment.offsets.len(), "segment offset count")?;
    put_len(&mut out, segment.edges.len(), "segment edge count")?;
    for node in &segment.nodes {
        out.extend_from_slice(node.id.as_bytes());
        out.extend_from_slice(&node.weight.to_le_bytes());
    }
    for offset in &segment.offsets {
        put_len(&mut out, *offset, "segment CSR offset")?;
    }
    for edge in &segment.edges {
        out.extend_from_slice(edge.dst.as_bytes());
        out.extend_from_slice(&edge.etype.to_le_bytes());
        out.extend_from_slice(&edge.weight.to_le_bytes());
        out.extend_from_slice(&edge.ledger_seq.to_le_bytes());
        out.extend_from_slice(&edge.ledger_hash);
    }
    Ok(out)
}

fn decode_segment(bytes: &[u8]) -> IngestResult<DecodedSegment> {
    let mut reader = SegmentReader::new(bytes);
    reader.expect_bytes(SEGMENT_MAGIC, "CSR segment magic")?;
    let version = reader.read_u32("CSR segment version")?;
    if version != SEGMENT_VERSION {
        return Err(projection_corrupt(format!(
            "CSR segment version {version} is not supported"
        )));
    }
    let kind_code = reader.read_u8("CSR projection kind")?;
    let kind = GraphProjectionKind::from_wire_code(kind_code).ok_or_else(|| {
        projection_corrupt(format!(
            "CSR segment projection kind {kind_code} is unknown"
        ))
    })?;
    let region = reader.read_u8("CSR source region")?;
    let node_count = reader.read_len("CSR segment node count")?;
    let offset_count = reader.read_len("CSR segment offset count")?;
    let edge_count = reader.read_len("CSR segment edge count")?;
    if offset_count != node_count + 1 {
        return Err(projection_corrupt(format!(
            "CSR segment offset count {offset_count} does not match node count {node_count}"
        )));
    }
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let id = reader.read_cxid("CSR node id")?;
        let weight = reader.read_f32("CSR node weight")?;
        validate_node_weight(weight)?;
        nodes.push(GraphProjectionNode { id, weight });
    }
    let mut offsets = Vec::with_capacity(offset_count);
    for _ in 0..offset_count {
        offsets.push(reader.read_len("CSR offset")?);
    }
    let mut edges = Vec::with_capacity(edge_count);
    for _ in 0..edge_count {
        let dst = reader.read_cxid("CSR edge dst")?;
        let etype = reader.read_u16("CSR edge etype")?;
        let weight = reader.read_f32("CSR edge weight")?;
        validate_edge_weight(weight, "CSR edge weight")?;
        let ledger_seq = reader.read_u64("CSR edge ledger seq")?;
        let ledger_hash = reader.read_hash32("CSR edge ledger hash")?;
        edges.push(GraphProjectionCsrEdge {
            dst,
            etype,
            weight,
            ledger_seq,
            ledger_hash,
        });
    }
    reader.finish()?;
    Ok(DecodedSegment {
        kind,
        region,
        nodes,
        offsets,
        edges,
    })
}

struct SegmentReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SegmentReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_bytes(&mut self, expected: &[u8], field: &str) -> IngestResult<()> {
        let actual = self.take(expected.len(), field)?;
        if actual == expected {
            Ok(())
        } else {
            Err(projection_corrupt(format!("{field} mismatch")))
        }
    }

    fn read_u8(&mut self, field: &str) -> IngestResult<u8> {
        let bytes = self.take(1, field)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self, field: &str) -> IngestResult<u16> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &str) -> IngestResult<u32> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, field: &str) -> IngestResult<u64> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_len(&mut self, field: &str) -> IngestResult<usize> {
        usize::try_from(self.read_u64(field)?)
            .map_err(|_| projection_corrupt(format!("{field} overflows usize")))
    }

    fn read_f32(&mut self, field: &str) -> IngestResult<f32> {
        let bytes = self.take(4, field)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_cxid(&mut self, field: &str) -> IngestResult<CxId> {
        let bytes = self.take(CXID_BYTES, field)?;
        let mut out = [0_u8; CXID_BYTES];
        out.copy_from_slice(bytes);
        Ok(CxId::from_bytes(out))
    }

    fn read_hash32(&mut self, field: &str) -> IngestResult<[u8; 32]> {
        let bytes = self.take(32, field)?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn take(&mut self, len: usize, field: &str) -> IngestResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| projection_corrupt(format!("{field} offset overflow")))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| projection_corrupt(format!("{field} is truncated")))?;
        self.offset = end;
        Ok(slice)
    }

    fn finish(&self) -> IngestResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(projection_corrupt(format!(
                "CSR segment has {} trailing bytes",
                self.bytes.len() - self.offset
            )))
        }
    }
}

/// Maps each persisted segment region to its key using a key-only scan.
///
/// This never loads the segment CSR byte values, keeping projection re-materialization from
/// holding the entire persisted projection in memory alongside the freshly built one (#101).
fn existing_segment_regions<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    kind: GraphProjectionKind,
) -> IngestResult<BTreeMap<u8, Vec<u8>>>
where
    C: Clock,
{
    Ok(vault
        .scan_cf_range_keys_at(
            snapshot,
            ColumnFamily::Kernel,
            &prefix_range(&projection_prefix(kind)),
        )?
        .into_iter()
        .filter_map(|key| segment_region_from_key(kind, &key).map(|region| (region, key)))
        .collect())
}

fn manifest_key(kind: GraphProjectionKind) -> Vec<u8> {
    let mut key = projection_prefix(kind);
    key.extend_from_slice(b"manifest");
    key
}

fn segment_key(kind: GraphProjectionKind, region: u8) -> Vec<u8> {
    let mut key = projection_prefix(kind);
    key.extend_from_slice(b"segment:");
    key.push(region);
    key
}

fn segment_region_from_key(kind: GraphProjectionKind, key: &[u8]) -> Option<u8> {
    let mut prefix = projection_prefix(kind);
    prefix.extend_from_slice(b"segment:");
    if key.len() == prefix.len() + 1 && key.starts_with(&prefix) {
        key.last().copied()
    } else {
        None
    }
}

fn projection_prefix(kind: GraphProjectionKind) -> Vec<u8> {
    let mut key = Vec::with_capacity(GRAPH_PROJECTION_CSR_PREFIX.len() + kind.name().len() + 1);
    key.extend_from_slice(GRAPH_PROJECTION_CSR_PREFIX);
    key.extend_from_slice(kind.name().as_bytes());
    key.push(b':');
    key
}

pub(crate) fn is_kernel_projection_key(key: &[u8]) -> bool {
    key.strip_prefix(GRAPH_PROJECTION_CSR_PREFIX)
        .is_some_and(|suffix| suffix.starts_with(b"kernel_graph:"))
}

fn region_for(id: CxId) -> u8 {
    id.as_bytes()[0]
}

fn is_call_edge(kind: EdgeKind) -> bool {
    matches!(kind, EdgeKind::Calls | EdgeKind::ResolvedCalls)
}

fn is_dependency_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Imports | EdgeKind::DependsOn | EdgeKind::UsesType | EdgeKind::Instantiates
    )
}

fn is_dataflow_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Reads
            | EdgeKind::Writes
            | EdgeKind::Usage
            | EdgeKind::Throws
            | EdgeKind::Raises
            | EdgeKind::DataFlows
    )
}

fn is_service_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::HttpCalls
            | EdgeKind::AsyncCalls
            | EdgeKind::GrpcCalls
            | EdgeKind::GraphqlCalls
            | EdgeKind::TrpcCalls
            | EdgeKind::Emits
            | EdgeKind::ListensOn
            | EdgeKind::Handles
            | EdgeKind::InfraMaps
            | EdgeKind::CrossHttpCalls
            | EdgeKind::CrossAsyncCalls
            | EdgeKind::CrossChannel
            | EdgeKind::CrossGrpcCalls
            | EdgeKind::CrossGraphqlCalls
            | EdgeKind::CrossTrpcCalls
    )
}

fn is_structure_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Defines
            | EdgeKind::DefinesMethod
            | EdgeKind::Contains
            | EdgeKind::HasBranch
            | EdgeKind::Inherits
            | EdgeKind::Implements
            | EdgeKind::Override
            | EdgeKind::Decorates
            | EdgeKind::Tests
            | EdgeKind::TestsFile
            | EdgeKind::Configures
            | EdgeKind::SimilarTo
            | EdgeKind::SemanticallyRelated
    )
}

fn kernel_multiplier(kind: EdgeKind) -> Option<f32> {
    if is_call_edge(kind) {
        Some(1.0)
    } else if is_dataflow_edge(kind) {
        Some(0.7)
    } else if is_dependency_edge(kind) {
        Some(0.6)
    } else if is_service_edge(kind) {
        Some(0.9)
    } else if is_structure_edge(kind) {
        Some(0.3)
    } else if kind == EdgeKind::FileChangesWith {
        Some(0.5)
    } else {
        None
    }
}

fn edge_kind_from_code(code: u16) -> Option<EdgeKind> {
    EdgeKind::ALL.into_iter().find(|kind| kind.code() == code)
}

fn numeric_prop_any(value: &serde_json::Value, keys: &[&str]) -> IngestResult<Option<f32>> {
    for key in keys {
        let Some(raw) = value.get(*key) else {
            continue;
        };
        let number = match raw {
            serde_json::Value::Number(number) => number.as_f64().map(|value| value as f32),
            serde_json::Value::String(text) => Some(text.parse::<f32>().map_err(|error| {
                projection_corrupt(format!(
                    "change_count property {key} is not numeric: {error}"
                ))
            })?),
            _ => {
                return Err(projection_corrupt(format!(
                    "change_count property {key} must be numeric"
                )));
            }
        };
        if let Some(number) = number {
            if number.is_finite() && number >= 0.0 {
                return Ok(Some(number));
            }
            return Err(projection_corrupt(format!(
                "change_count property {key} must be finite and >= 0"
            )));
        }
    }
    Ok(None)
}

fn validate_node_weight(weight: f32) -> IngestResult<()> {
    if weight.is_finite() && weight > 0.0 {
        Ok(())
    } else {
        Err(projection_corrupt(format!(
            "projection node weight must be finite and > 0; got {weight}"
        )))
    }
}

fn validate_edge_weight(weight: f32, field: &str) -> IngestResult<()> {
    if weight.is_finite() && (0.0..=1.0).contains(&weight) {
        Ok(())
    } else {
        Err(projection_corrupt(format!(
            "{field} must be finite and in [0, 1]; got {weight}"
        )))
    }
}

fn put_len(out: &mut Vec<u8>, value: usize, field: &str) -> IngestResult<()> {
    let value =
        u64::try_from(value).map_err(|_| projection_corrupt(format!("{field} overflows u64")))?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn frame_hash(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn parse_hash_32(value: &str) -> IngestResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(projection_corrupt(format!(
            "hash has length {}, expected 64",
            value.len()
        )));
    }
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(pair[0]).ok_or_else(|| projection_corrupt("hash has invalid hex"))?;
        let lo = hex_value(pair[1]).ok_or_else(|| projection_corrupt("hash has invalid hex"))?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_prefix(bytes: &[u8; 32], len: usize) -> String {
    let full = hex_lower(bytes);
    full[..len.min(full.len())].to_string()
}

fn hex_key(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn projection_corrupt(message: impl Into<String>) -> IngestError {
    IngestError::refused(
        ASTRO_GRAPH_PROJECTION_CORRUPT,
        message,
        PROJECTION_REMEDIATION,
    )
}

fn projection_readback(kind: GraphProjectionKind, message: &str) -> IngestError {
    IngestError::refused(
        ASTRO_INGEST_READBACK_MISMATCH,
        format!("{} projection commit readback: {message}", kind.name()),
        PROJECTION_REMEDIATION,
    )
}
