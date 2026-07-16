use std::collections::{BTreeMap, BTreeSet};
use std::thread;

use astrolabe_domain::EdgeKind;
use calyx_aster::cf::{ColumnFamily, prefix_range};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, CxId, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};
use calyx_paths::AssocGraph;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::sqlite_import::{
    ASTRO_INGEST_READBACK_MISMATCH, EDGE_ROW_PREFIX, EdgeGraphRow, SCHEMA_EDGE_ROW,
};
use crate::{IngestError, IngestResult};

/// Stable failure code for corrupt or stale persisted graph projections.
pub const ASTRO_GRAPH_PROJECTION_CORRUPT: &str = "ASTRO_GRAPH_PROJECTION_CORRUPT";
/// Kernel CF prefix for Astrolabe graph projection CSR manifests and segments.
pub const GRAPH_PROJECTION_CSR_PREFIX: &[u8] = b"astrolabe:projection-csr:v1:";

const PROJECTION_REMEDIATION: &str =
    "Rebuild graph projections from Graph CF typed edge rows, then rerun astrolabe verify --deep.";
const PROJECTION_SCHEMA: &str = "astrolabe-graph-projection-csr-v1";
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
    /// Number of typed source edge rows scanned from Graph CF.
    pub source_edge_rows: usize,
    /// Fingerprint of all source edge rows scanned from Graph CF.
    pub source_fingerprint_blake3: [u8; 32],
    /// Deterministic worker count requested by the caller.
    pub workers: usize,
    /// Per-projection reports.
    pub projections: Vec<GraphProjectionMaterializeEntry>,
}

#[derive(Clone, Debug)]
struct SourceEdges {
    rows: Vec<SourceEdgeRow>,
    fingerprint: [u8; 32],
}

#[derive(Clone, Debug)]
struct SourceEdgeRow {
    row: EdgeGraphRow,
    kind: EdgeKind,
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
    match load_persisted_projection(vault, kind, false)? {
        PersistedProjectionState::Missing => Ok(None),
        PersistedProjectionState::Incomplete => Err(projection_corrupt(format!(
            "{} CSR segment set is incomplete; call ensure_graph_projection_csr to rebuild",
            kind.name()
        ))),
        PersistedProjectionState::Complete(csr) => {
            let source = read_source_edges(vault)?;
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
    match load_persisted_projection(vault, kind, true)? {
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
    let desired = build_projection_bytes(kind, source, options.workers)?;
    let snapshot = vault.latest_seq();
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

    let wrote_rows = !rows.is_empty();
    if wrote_rows {
        let payload = serde_json::to_vec(&json!({
            "schema": "agp_v1",
            "projection": kind.name(),
            "source_fingerprint_blake3_prefix": hex_prefix(&source.fingerprint, 8),
            "node_count": desired.csr.nodes.len(),
            "edge_count": desired.csr.edges.len(),
            "association_edge_count": desired.csr.association_edge_count,
            "segments_written": segments_written,
            "segments_tombstoned": segments_tombstoned,
            "manifest_written": manifest_written,
        }))?;
        vault.write_cf_batch_with_ledger_entry(
            rows,
            EntryKind::Kernel,
            SubjectId::Query(kind.name().as_bytes().to_vec()),
            payload,
            ActorId::Service(ASTROLABE_PROJECTION_ACTOR.to_string()),
        )?;
    }
    let (rows_readback_verified, ledger_paired) = if wrote_rows {
        let verified = verify_projection_commit_readback(
            vault,
            kind,
            &desired,
            &segment_is_stale,
            manifest_written,
            &tombstoned_keys,
        )?;
        (verified, true)
    } else {
        (0, false)
    };

    Ok(GraphProjectionMaterializeEntry {
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
        rows_readback_verified,
        ledger_paired,
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
    kind: GraphProjectionKind,
    desired: &ProjectionBytes,
    segment_is_stale: &[bool],
    manifest_written: bool,
    tombstoned_keys: &[Vec<u8>],
) -> IngestResult<usize>
where
    C: Clock,
{
    let commit_seq = vault.latest_seq();
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

    let (_key, ledger_bytes) = calyx_aster::ledger_view::newest_pairable_ledger(
        vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?,
    )?
    .ok_or_else(|| projection_readback(kind, "Ledger CF empty at projection commit snapshot"))?;
    let entry = decode(&ledger_bytes)?;
    if entry.kind != EntryKind::Kernel {
        return Err(projection_readback(
            kind,
            "paired ledger entry has the wrong entry kind",
        ));
    }
    if !matches!(&entry.actor, ActorId::Service(actor) if actor == ASTROLABE_PROJECTION_ACTOR) {
        return Err(projection_readback(
            kind,
            "paired ledger entry names the wrong actor",
        ));
    }
    if !matches!(&entry.subject, SubjectId::Query(subject) if subject.as_slice() == kind.name().as_bytes())
    {
        return Err(projection_readback(
            kind,
            "paired ledger entry names the wrong subject",
        ));
    }

    Ok(rows_verified)
}

fn read_source_edges<C>(vault: &AsterVault<C>) -> IngestResult<SourceEdges>
where
    C: Clock,
{
    let rows = vault.scan_cf_range_at(
        vault.latest_seq(),
        ColumnFamily::Graph,
        &prefix_range(EDGE_ROW_PREFIX),
    )?;
    let mut hasher = blake3::Hasher::new();
    let mut out = Vec::with_capacity(rows.len());
    for (key, value) in rows {
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
        out.push(SourceEdgeRow { row, kind });
    }
    Ok(SourceEdges {
        rows: out,
        fingerprint: *hasher.finalize().as_bytes(),
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
        let Some(weight) = kind.projected_weight(source_edge.kind, source_edge.row.weight) else {
            continue;
        };
        validate_edge_weight(weight, "projection edge weight")?;
        node_weights.entry(source_edge.row.src).or_insert(1.0);
        node_weights.entry(source_edge.row.dst).or_insert(1.0);
        if kind == GraphProjectionKind::KernelGraph {
            apply_kernel_node_weight(&mut node_weights, &source_edge.row)?;
        }
        let seq = source_edge.row.provenance.seq;
        let hash = source_edge.row.provenance.hash;
        edges
            .entry((
                source_edge.row.src,
                source_edge.row.dst,
                source_edge.row.etype,
            ))
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
    row: &EdgeGraphRow,
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

fn load_persisted_projection<C>(
    vault: &AsterVault<C>,
    kind: GraphProjectionKind,
    incomplete_ok: bool,
) -> IngestResult<PersistedProjectionState>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
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
    for pair in manifest.regions.windows(2) {
        if pair[0].region >= pair[1].region {
            return Err(projection_corrupt(format!(
                "{} manifest regions are not strictly ordered",
                kind.name()
            )));
        }
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
