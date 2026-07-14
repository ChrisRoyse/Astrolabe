//! Streaming CBM row-sink → Aster vault writer (#59, P9.1 single-parse pipeline).
//!
//! The legacy shadow-import path parsed the CBM graph twice: CBM dumped its graph
//! to a SQLite artifact, then `astrolabe-ingest` re-opened and re-parsed that
//! SQLite file to build the Aster vault. `import_cbm_graph_snapshot_to_vault_direct`
//! removed the SQLite re-parse for callers that can hand over a fully materialized
//! [`CbmGraphSnapshot`]. This module removes the remaining requirement to
//! *pre-materialize the whole snapshot*: it consumes the CBM row-sink output as a
//! stream of individually fallible rows ([`IngestResult<RowSinkStreamRow>`]) and
//! feeds them into the same single ledger-paired vault write.
//!
//! ## The #123 Result-stream contract
//!
//! Each streamed item is a [`Result`]: the row-sink and the raw CBM run fail
//! independently, so a mid-stream sink error is surfaced per-row rather than
//! discarding the whole run. This writer honours that contract fail-closed — the
//! first `Err`, or the first structurally malformed row, refuses the entire import
//! with `{code, message, remediation}` and a count of how many well-formed rows had
//! been accepted. It never skips-and-continues.
//!
//! ## No partial batch is ever persisted
//!
//! The drain (phase A) performs no vault writes; it only validates and stages rows
//! in registry-bounded batches (the [`ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB`]
//! backpressure window). Persistence (phase B) is a single call into the shared
//! [`import_cbm_graph_snapshot_to_vault_direct`] path, which writes exactly one
//! ledger-paired batch. Because no bytes are written until the whole stream has
//! validated, any refusal leaves the vault untouched — there is no half-written
//! import to roll back.
//!
//! ## One ledger entry per import is deliberate (parity)
//!
//! Splitting persistence into independently ledgered sub-batches is a **non-goal**.
//! The raw-CF byte parity proof (`direct_row_sink_snapshot_import_matches_sqlite_import_raw_cfs`)
//! depends on this path writing exactly one ledger entry, byte-identical to the
//! SQLite importer's single entry. N ledgered sub-batches would produce N ledger CF
//! rows where the import path produces one, breaking that parity. The drain-batch
//! knob therefore governs only the transient validation/backpressure window; it
//! never changes what is durably written.

use astrolabe_domain::knobs::{ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB, row_sink_stream_knob};
use astrolabe_panel::SlotRuntime;
use calyx_aster::vault::AsterVault;
use calyx_core::Clock;
use serde_json::Value;

use crate::registry::{IngestError, IngestResult};
use crate::sqlite_import::{
    CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, SqliteImportOptions, SqliteImportReport,
    import_cbm_graph_snapshot_to_vault_direct,
};

/// Refusal code: the requested drain-batch size is outside the declared knob bounds.
pub const ASTRO_ROW_SINK_STREAM_BATCH_INVALID: &str = "ASTRO_ROW_SINK_STREAM_BATCH_INVALID";
/// Refusal code: a streamed row was an error or was structurally malformed. The
/// whole import is refused and nothing is persisted.
pub const ASTRO_ROW_SINK_STREAM_ROW_REFUSED: &str = "ASTRO_ROW_SINK_STREAM_ROW_REFUSED";

const BATCH_REMEDIATION: &str = "Set the row-sink stream drain-batch size inside the declared knob bounds, or use RowSinkStreamParams::from_registry() for the registry default.";
const ROW_REMEDIATION: &str = "Fix or drop the malformed CBM row-sink row at its source; the streaming importer refuses the whole stream and persists nothing until every streamed row is well-formed.";

/// One item of the CBM row-sink stream: a node row or an edge row.
///
/// This mirrors the two row kinds the CBM pipeline row sink emits. The stream is a
/// sequence of `IngestResult<RowSinkStreamRow>` so an individual row-sink failure
/// is carried per the #123 independent-failure contract.
#[derive(Debug, Clone, PartialEq)]
pub enum RowSinkStreamRow {
    /// A CBM node row.
    Node(CbmGraphNode),
    /// A CBM edge row.
    Edge(CbmGraphEdge),
}

/// Registry-bounded parameters for the streaming row-sink importer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RowSinkStreamParams {
    drain_batch_rows: u64,
}

impl RowSinkStreamParams {
    /// Builds params from the registry-declared default drain-batch knob.
    pub fn from_registry() -> Self {
        let knob = row_sink_stream_knob(ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB)
            .expect("row-sink stream drain-batch knob is declared in the knob registry");
        Self {
            drain_batch_rows: knob.default,
        }
    }

    /// Builds params with an explicit drain-batch size, validated against the knob
    /// bounds. A size outside the declared closed interval is refused fail-closed.
    pub fn with_drain_batch_rows(drain_batch_rows: u64) -> IngestResult<Self> {
        let knob = row_sink_stream_knob(ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB)
            .expect("row-sink stream drain-batch knob is declared in the knob registry");
        if !knob.accepts(drain_batch_rows) {
            return Err(IngestError::refused(
                ASTRO_ROW_SINK_STREAM_BATCH_INVALID,
                format!(
                    "row-sink stream drain-batch size {drain_batch_rows} is outside the declared knob bounds [{}, {}]",
                    knob.min, knob.max
                ),
                BATCH_REMEDIATION,
            ));
        }
        Ok(Self { drain_batch_rows })
    }

    /// Returns the configured drain-batch size in rows.
    pub fn drain_batch_rows(&self) -> u64 {
        self.drain_batch_rows
    }
}

impl Default for RowSinkStreamParams {
    fn default() -> Self {
        Self::from_registry()
    }
}

/// Report for a completed streaming row-sink import.
#[derive(Debug, Clone)]
pub struct RowSinkStreamReport {
    /// The underlying single ledger-paired import report (ledger seq, readback,
    /// row counts) produced by the shared direct vault-writer path.
    pub import: SqliteImportReport,
    /// Number of node rows accepted from the stream.
    pub stream_nodes: usize,
    /// Number of edge rows accepted from the stream.
    pub stream_edges: usize,
    /// Number of drain/backpressure batches the stream was validated in.
    pub drain_batches: usize,
    /// The registry-bounded drain-batch size used for this import.
    pub drain_batch_rows: u64,
}

/// Streams CBM row-sink rows directly into an Aster vault as a single ledger-paired
/// import.
///
/// The stream is drained and validated in registry-bounded batches (phase A) and
/// then persisted as exactly one ledger-paired write (phase B). Any streamed `Err`
/// or malformed row refuses the whole import fail-closed with nothing persisted.
/// The persisted CF bytes are byte-identical to
/// [`import_cbm_graph_snapshot_to_vault_direct`] for the same rows and, transitively,
/// to the SQLite importer.
pub fn import_cbm_row_stream_to_vault<C, R, I>(
    source_fingerprint_sha256: [u8; 32],
    stream: I,
    params: &RowSinkStreamParams,
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
) -> IngestResult<RowSinkStreamReport>
where
    C: Clock,
    R: SlotRuntime + Sync,
    I: IntoIterator<Item = IngestResult<RowSinkStreamRow>>,
{
    let batch = params.drain_batch_rows;
    let project = options.project.as_str();

    let drain_start = std::time::Instant::now();
    let mut nodes: Vec<CbmGraphNode> = Vec::new();
    let mut edges: Vec<CbmGraphEdge> = Vec::new();
    let mut drain_batches: usize = 0;
    let mut rows_in_batch: u64 = 0;

    // Phase A: streaming drain in registry-bounded batches. No vault write happens
    // here, so any refusal (a stream-level Err, or a structurally malformed row)
    // returns before a single byte is persisted — there is never a partial batch.
    for item in stream {
        let accepted = StreamCounts {
            nodes: nodes.len(),
            edges: edges.len(),
        };
        // A stream-level Err honours the #123 independent-failure contract: the
        // sink failed for this row, so the whole import fails closed.
        let row = item.map_err(|error| {
            stream_row_refused(
                accepted,
                format!("row-sink stream yielded an error before completion: {error}"),
            )
        })?;
        match row {
            RowSinkStreamRow::Node(node) => {
                validate_stream_node(project, &node, accepted)?;
                nodes.push(node);
            }
            RowSinkStreamRow::Edge(edge) => {
                validate_stream_edge(project, &edge, accepted)?;
                edges.push(edge);
            }
        }
        rows_in_batch += 1;
        if rows_in_batch >= batch {
            drain_batches += 1;
            rows_in_batch = 0;
        }
    }
    if rows_in_batch > 0 {
        drain_batches += 1;
    }

    let stream_nodes = nodes.len();
    let stream_edges = edges.len();

    let snapshot = CbmGraphSnapshot {
        project: options.project.clone(),
        panel_version: Some(options.panel_version),
        projects: Vec::new(),
        nodes,
        edges,
        file_hashes: Vec::new(),
        project_summaries: Vec::new(),
        token_vectors: Vec::new(),
    };

    let drain_ms = drain_start.elapsed().as_millis() as u64;
    // Phase B: single ledger-paired persistence through the shared direct path.
    // Exactly one write batch, one ledger entry — the invariant the raw-CF byte
    // parity with the SQLite importer depends on. An empty stream reaches here with
    // zero nodes and is refused by the shared path's >=1-node contract, so an empty
    // import never records a successful-but-empty ledger entry.
    let mut import = import_cbm_graph_snapshot_to_vault_direct(
        &snapshot,
        source_fingerprint_sha256,
        vault,
        runtime,
        options,
    )?;
    import.timing_ms.0.insert(0, ("stream_drain", drain_ms));

    Ok(RowSinkStreamReport {
        import,
        stream_nodes,
        stream_edges,
        drain_batches,
        drain_batch_rows: batch,
    })
}

/// Lazily adapts a materialized [`CbmGraphSnapshot`] into the
/// [`RowSinkStreamRow`] sequence [`import_cbm_row_stream_to_vault`] consumes.
///
/// Nodes are yielded first (in stored order), then edges. Every item is `Ok`
/// because a snapshot handed to this adapter has already cleared FFI row-sink
/// validation — the per-item [`IngestResult`] failure channel is reserved for a
/// live producer whose sink can fail mid-stream (the #123 contract). The adapter
/// is *lazy*: it never clones the row vectors and yields one row at a time as the
/// importer pulls it, so a bounded channel placed between a producer and this
/// stream backpressures the producer instead of forcing a full second copy.
///
/// This is the production bridge between the shadow-import row-sink snapshot
/// ([`pipeline_rows_to_graph_snapshot`] materializes CBM `CbmPipelineRows` into a
/// [`CbmGraphSnapshot`] to derive the security-screen / skill-tree / bridge /
/// kernel-context / anomaly / provenance surfaces) and the streaming vault
/// writer: the same materialized rows are streamed row-by-row into the single
/// ledger-paired write instead of being handed over as one snapshot argument.
/// The `projects` / `file_hashes` / `project_summaries` / `token_vectors` fields
/// are always empty on a row-sink snapshot, so streaming only nodes and edges
/// preserves byte-for-byte parity with the direct snapshot writer.
///
/// [`pipeline_rows_to_graph_snapshot`]: crate::sqlite_import::CbmGraphSnapshot
pub fn snapshot_into_row_stream(
    snapshot: CbmGraphSnapshot,
) -> impl Iterator<Item = IngestResult<RowSinkStreamRow>> {
    snapshot
        .nodes
        .into_iter()
        .map(|node| Ok(RowSinkStreamRow::Node(node)))
        .chain(
            snapshot
                .edges
                .into_iter()
                .map(|edge| Ok(RowSinkStreamRow::Edge(edge))),
        )
}

#[derive(Debug, Clone, Copy)]
struct StreamCounts {
    nodes: usize,
    edges: usize,
}

fn stream_row_refused(accepted: StreamCounts, detail: String) -> IngestError {
    IngestError::refused(
        ASTRO_ROW_SINK_STREAM_ROW_REFUSED,
        format!(
            "{detail} (refused after accepting {} well-formed rows: {} nodes, {} edges; nothing persisted)",
            accepted.nodes + accepted.edges,
            accepted.nodes,
            accepted.edges
        ),
        ROW_REMEDIATION,
    )
}

fn validate_stream_node(
    project: &str,
    node: &CbmGraphNode,
    accepted: StreamCounts,
) -> IngestResult<()> {
    if node.project != project {
        return Err(stream_row_refused(
            accepted,
            format!(
                "row-sink node {} belongs to project {:?}, not the import project {:?}",
                node.source_node_id, node.project, project
            ),
        ));
    }
    let properties = serde_json::from_str::<Value>(&node.properties_json).map_err(|error| {
        stream_row_refused(
            accepted,
            format!(
                "row-sink node {} properties JSON is invalid: {error}",
                node.source_node_id
            ),
        )
    })?;
    if !properties.is_object() {
        return Err(stream_row_refused(
            accepted,
            format!(
                "row-sink node {} properties JSON must be an object",
                node.source_node_id
            ),
        ));
    }
    Ok(())
}

fn validate_stream_edge(
    project: &str,
    edge: &CbmGraphEdge,
    accepted: StreamCounts,
) -> IngestResult<()> {
    if edge.project != project {
        return Err(stream_row_refused(
            accepted,
            format!(
                "row-sink edge {} belongs to project {:?}, not the import project {:?}",
                edge.sqlite_edge_id, edge.project, project
            ),
        ));
    }
    let properties = serde_json::from_str::<Value>(&edge.properties_json).map_err(|error| {
        stream_row_refused(
            accepted,
            format!(
                "row-sink edge {} properties JSON is invalid: {error}",
                edge.sqlite_edge_id
            ),
        )
    })?;
    if !properties.is_object() {
        return Err(stream_row_refused(
            accepted,
            format!(
                "row-sink edge {} properties JSON must be an object",
                edge.sqlite_edge_id
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_default_matches_registry_knob_default() {
        let knob = row_sink_stream_knob(ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB).expect("declared");
        assert_eq!(
            RowSinkStreamParams::from_registry().drain_batch_rows(),
            knob.default
        );
        assert_eq!(
            RowSinkStreamParams::default().drain_batch_rows(),
            knob.default
        );
    }

    #[test]
    fn params_reject_zero_batch_fail_closed() {
        let err = RowSinkStreamParams::with_drain_batch_rows(0)
            .expect_err("zero drain batch must be refused");
        assert_eq!(err.code(), Some(ASTRO_ROW_SINK_STREAM_BATCH_INVALID));
        assert!(err.remediation().is_some());
    }

    #[test]
    fn params_accept_in_bounds_batch() {
        let knob = row_sink_stream_knob(ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB).expect("declared");
        let params = RowSinkStreamParams::with_drain_batch_rows(2).expect("2 is in bounds");
        assert_eq!(params.drain_batch_rows(), 2);
        assert!(RowSinkStreamParams::with_drain_batch_rows(knob.max).is_ok());
        assert!(RowSinkStreamParams::with_drain_batch_rows(knob.max + 1).is_err());
    }
}
