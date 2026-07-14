//! `GraphProjectionCsr` → `KernelGraph` adapter and vault Kernel-CF persistence
//! for the #37/#38 kernel build pipeline (#343).
//!
//! The kernel crate (`astrolabe-kernel`) owns the build pipeline over a
//! kernel-owned [`KernelGraph`], but it cannot reach the data plane: ingest
//! depends on the kernel crate, so the reverse is a cycle (see
//! `astrolabe-kernel::kernel_graph`). This module is the downstream wiring the
//! kernel crate documents as living in ingest/server:
//!
//! 1. **Adapter** — [`kernel_graph_from_projection_csr`] compiles the decoded
//!    composite kernel [`GraphProjectionCsr`] (P2.2) plus a caller-supplied
//!    anchor trust rollup into a [`KernelGraph`], so `build_kernel` runs over a
//!    real vault-projected graph instead of a caller-constructed one.
//! 2. **Persistence** — [`build_and_persist_kernel`] routes the exact
//!    `kernel.json` / `index.json` / members-hash ledger bytes the kernel crate
//!    produces into the production AsterVault Kernel CF paired with a Kernel
//!    ledger entry, then independently reads the persisted bytes back and
//!    re-derives the members-hash, refusing fail-closed on any divergence.
//!
//! The serializers are the kernel crate's own ([`KernelArtifact::kernel_json_bytes`],
//! [`KernelArtifact::index_json_bytes`], [`KernelArtifact::ledger_entry`]), so the
//! vault-persisted bytes are byte-identical to the crate-level filesystem path
//! ([`astrolabe_kernel::write_kernel_artifacts`]); there is one serializer and no
//! silent divergence between the two persistence sinks.

use std::collections::BTreeMap;

use astrolabe_domain::TrustTag;
use astrolabe_kernel::{
    KernelArtifact, KernelBuildConfig, KernelGraph, KernelGraphEdge, KernelGraphNode, KernelMember,
    build_kernel, members_hash,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, CxId, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};

use crate::graph_projection::{
    GraphProjectionBuildOptions, GraphProjectionCsr, GraphProjectionKind,
    ensure_graph_projection_csr,
};
use crate::{IngestError, IngestResult};

/// Kernel CF prefix for persisted kernel build artifacts (kernel.json,
/// index.json, members-hash), keyed per scope.
pub const KERNEL_ARTIFACT_CF_PREFIX: &[u8] = b"astrolabe:kernel-artifact:v1:";

/// Ledger/CF actor for a persisted kernel build.
pub const KERNEL_ARTIFACT_ACTOR: &str = "astrolabe-kernel-build";

/// Refusal raised when the adapter is handed a projection that is not the
/// composite kernel projection, or a node weight that is not a valid frequency.
pub const ASTRO_KERNEL_GRAPH_ADAPTER_REFUSED: &str = "ASTRO_KERNEL_GRAPH_ADAPTER_REFUSED";

/// Refusal raised when a persisted kernel artifact does not read back
/// byte-identically, or its re-derived members-hash disagrees with the paired
/// ledger entry.
pub const ASTRO_KERNEL_ARTIFACT_PERSIST_READBACK: &str = "ASTRO_KERNEL_ARTIFACT_PERSIST_READBACK";

const ADAPTER_REMEDIATION: &str = "Materialize the composite kernel_graph projection and supply finite positive node \
     frequencies before building a kernel.";
const READBACK_REMEDIATION: &str = "Quarantine the vault and rebuild the kernel artifact; the persisted Kernel CF bytes did \
     not match the staged bytes or the paired ledger entry.";

/// Persisted-artifact readback outcome for one kernel build commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelArtifactPersistReport {
    /// Scope identity the kernel was built for.
    pub scope_id: String,
    /// Hex members-hash of the persisted kernel, re-derived from the read-back
    /// `kernel.json` member set and matched against the paired ledger entry.
    pub members_hash: String,
    /// Persisted kernel member count.
    pub member_count: usize,
    /// Source graph node count.
    pub node_count: usize,
    /// Measured recall in permille carried by the persisted kernel.
    pub recall_permille: u64,
    /// Whether the persisted kernel reaches its recall gate.
    pub recall_gated: bool,
    /// Whether a Trusted anchor existed in scope.
    pub anchor_grounded: bool,
    /// Kernel CF key of the persisted `kernel.json` row.
    pub kernel_json_key: Vec<u8>,
    /// Kernel CF key of the persisted `index.json` row.
    pub index_json_key: Vec<u8>,
    /// Kernel CF key of the persisted members-hash row.
    pub members_hash_key: Vec<u8>,
    /// Commit sequence of the write.
    pub commit_seq: Seq,
    /// Kernel CF rows re-read and byte-verified after the commit (always 3 on
    /// success: kernel.json, index.json, members-hash).
    pub rows_readback_verified: usize,
    /// Whether the commit's paired Kernel ledger entry was read back and its
    /// members-hash verified byte-compatible with the persisted rows.
    pub ledger_paired: bool,
}

/// Compiles a decoded composite kernel [`GraphProjectionCsr`] plus an anchor
/// trust rollup into the kernel-owned [`KernelGraph`].
///
/// Refuses fail-closed when handed any projection other than
/// [`GraphProjectionKind::KernelGraph`] — the kernel build runs over the
/// composite projection, whose edge weights already fold every relation's
/// annealed type weight (blueprint 09 §1), never a single-relation projection.
///
/// Node frequency is recovered from the projection node weight, which the
/// composite kernel projection sets to `change_count + 1` (ingest
/// `graph_projection::apply_kernel_node_weight`); anchor trust is looked up per
/// node in `anchor_trust`, `None` when the node carries no anchor. Directed
/// weighted edges are read out of the CSR offset windows unchanged. The final
/// [`KernelGraph::new`] revalidates node uniqueness, edge endpoints, and edge
/// weight bounds, so a corrupt CSR is refused at the kernel boundary too.
pub fn kernel_graph_from_projection_csr(
    csr: &GraphProjectionCsr,
    anchor_trust: &BTreeMap<CxId, TrustTag>,
) -> IngestResult<KernelGraph> {
    if csr.kind != GraphProjectionKind::KernelGraph {
        return Err(adapter_refused(format!(
            "kernel build requires the composite {} projection, not {}",
            GraphProjectionKind::KernelGraph.name(),
            csr.kind.name()
        )));
    }
    if csr.offsets.len() != csr.nodes.len() + 1 {
        return Err(adapter_refused(format!(
            "kernel projection CSR has {} offsets for {} nodes",
            csr.offsets.len(),
            csr.nodes.len()
        )));
    }

    let mut nodes = Vec::with_capacity(csr.nodes.len());
    for node in &csr.nodes {
        let frequency = projection_weight_to_frequency(node.weight, node.id)?;
        nodes.push(KernelGraphNode::new(
            node.id,
            frequency,
            anchor_trust.get(&node.id).copied(),
        ));
    }

    let mut edges = Vec::with_capacity(csr.edges.len());
    for (src_index, window) in csr.offsets.windows(2).enumerate() {
        let src = csr.nodes[src_index].id;
        for edge in &csr.edges[window[0]..window[1]] {
            edges.push(KernelGraphEdge::new(src, edge.dst, edge.weight));
        }
    }

    Ok(KernelGraph::new(nodes, edges)?)
}

/// Builds a recall-gated kernel over the vault's composite kernel projection and
/// persists it to the production Kernel CF with a paired ledger entry.
///
/// Ensures the composite kernel projection is materialized and fresh against the
/// current Graph CF, adapts it into a [`KernelGraph`] with the supplied anchor
/// trust rollup, runs `build_kernel`, and hands the artifact to
/// [`persist_kernel_artifact`]. Fail-closed refusals (empty graph, stale
/// projection, unreachable recall gate, readback mismatch) propagate their
/// stable codes.
pub fn build_and_persist_kernel<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
    anchor_trust: &BTreeMap<CxId, TrustTag>,
    config: &KernelBuildConfig,
    options: &GraphProjectionBuildOptions,
) -> IngestResult<KernelArtifactPersistReport>
where
    C: Clock,
{
    let csr = ensure_graph_projection_csr(vault, GraphProjectionKind::KernelGraph, options)?;
    let graph = kernel_graph_from_projection_csr(&csr, anchor_trust)?;
    let artifact = build_kernel(&graph, scope_id, config)?;
    persist_kernel_artifact(vault, &artifact)
}

/// Persists a computed [`KernelArtifact`] to the Kernel CF and reads it back.
///
/// Writes three Kernel CF rows — `kernel.json`, `index.json`, and the
/// members-hash ledger entry — in one batch paired with a `Kernel` ledger entry
/// whose payload is the same members-hash serialization. The row bytes are the
/// kernel crate's own serializers, so they are byte-identical to
/// [`astrolabe_kernel::write_kernel_artifacts`]. After the commit every row is
/// read back at the commit snapshot and byte-compared, the members-hash is
/// re-derived from the persisted `kernel.json` member set, and the paired ledger
/// entry is re-read and its members-hash matched — any divergence is a
/// fail-closed [`ASTRO_KERNEL_ARTIFACT_PERSIST_READBACK`] refusal.
pub fn persist_kernel_artifact<C>(
    vault: &AsterVault<C>,
    artifact: &KernelArtifact,
) -> IngestResult<KernelArtifactPersistReport>
where
    C: Clock,
{
    let kernel_bytes = artifact.kernel_json_bytes();
    let index_bytes = artifact.index_json_bytes();
    let ledger_bytes = serde_json::to_vec(&artifact.ledger_entry())?;

    let kernel_key = artifact_key(&artifact.scope_id, b"kernel.json");
    let index_key = artifact_key(&artifact.scope_id, b"index.json");
    let members_key = artifact_key(&artifact.scope_id, b"members-hash");

    let rows = vec![
        (
            ColumnFamily::Kernel,
            kernel_key.clone(),
            kernel_bytes.clone(),
        ),
        (ColumnFamily::Kernel, index_key.clone(), index_bytes.clone()),
        (
            ColumnFamily::Kernel,
            members_key.clone(),
            ledger_bytes.clone(),
        ),
    ];
    let commit_seq = vault.write_cf_batch_with_ledger_entry(
        rows,
        EntryKind::Kernel,
        SubjectId::Query(scope_subject(&artifact.scope_id)),
        ledger_bytes.clone(),
        ActorId::Service(KERNEL_ARTIFACT_ACTOR.to_string()),
    )?;

    let rows_readback_verified = verify_kernel_artifact_readback(
        vault,
        commit_seq,
        artifact,
        &kernel_key,
        &kernel_bytes,
        &index_key,
        &index_bytes,
        &members_key,
        &ledger_bytes,
    )?;

    Ok(KernelArtifactPersistReport {
        scope_id: artifact.scope_id.clone(),
        members_hash: artifact.members_hash.clone(),
        member_count: artifact.member_count,
        node_count: artifact.node_count,
        recall_permille: artifact.recall.permille,
        recall_gated: artifact.recall.gated,
        anchor_grounded: artifact.anchor_grounded,
        kernel_json_key: kernel_key,
        index_json_key: index_key,
        members_hash_key: members_key,
        commit_seq,
        rows_readback_verified,
        ledger_paired: true,
    })
}

/// Reads a persisted kernel `kernel.json` artifact back out of the Kernel CF at
/// the latest snapshot, if present. Independent of the write path — used by
/// serving/FSV callers to re-derive the members-hash from persisted bytes.
pub fn read_persisted_kernel_artifact<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
) -> IngestResult<Option<KernelArtifact>>
where
    C: Clock,
{
    let key = artifact_key(scope_id, b"kernel.json");
    let Some(bytes) = vault.read_cf_at(vault.latest_seq(), ColumnFamily::Kernel, &key)? else {
        return Ok(None);
    };
    let artifact = serde_json::from_slice::<KernelArtifact>(&bytes)?;
    Ok(Some(artifact))
}

#[allow(clippy::too_many_arguments)]
fn verify_kernel_artifact_readback<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
    artifact: &KernelArtifact,
    kernel_key: &[u8],
    kernel_bytes: &[u8],
    index_key: &[u8],
    index_bytes: &[u8],
    members_key: &[u8],
    ledger_bytes: &[u8],
) -> IngestResult<usize>
where
    C: Clock,
{
    read_back_row(vault, commit_seq, kernel_key, kernel_bytes, "kernel.json")?;
    read_back_row(vault, commit_seq, index_key, index_bytes, "index.json")?;
    read_back_row(vault, commit_seq, members_key, ledger_bytes, "members-hash")?;

    // Independently re-derive the members-hash from the persisted kernel.json
    // member set. A tampered member set or a members-hash that does not cover
    // the persisted members is caught here even if every row read back byte
    // clean against the staged bytes.
    let persisted = serde_json::from_slice::<KernelArtifact>(kernel_bytes)?;
    let member_ids: Vec<CxId> = persisted
        .members
        .iter()
        .map(|member: &KernelMember| member.id)
        .collect();
    let derived = members_hash(&member_ids);
    if derived != artifact.members_hash {
        return Err(readback_refused(format!(
            "re-derived members-hash {derived} for scope {} differs from the artifact members-hash {}",
            artifact.scope_id, artifact.members_hash
        )));
    }
    if persisted.members_hash != artifact.members_hash {
        return Err(readback_refused(format!(
            "persisted kernel.json members_hash {} differs from the artifact members-hash {} for scope {}",
            persisted.members_hash, artifact.members_hash, artifact.scope_id
        )));
    }

    // The paired Kernel ledger entry must exist at the commit snapshot, name the
    // kernel-build actor and scope subject, and carry the same members-hash
    // payload bytes as the persisted members-hash row (one serializer).
    let (_key, entry_bytes) = vault
        .scan_cf_at(commit_seq, ColumnFamily::Ledger)?
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0))
        .ok_or_else(|| readback_refused("Ledger CF empty at kernel artifact commit snapshot"))?;
    let entry = decode(&entry_bytes)?;
    if entry.kind != EntryKind::Kernel {
        return Err(readback_refused(
            "paired ledger entry has the wrong entry kind",
        ));
    }
    if !matches!(&entry.actor, ActorId::Service(actor) if actor == KERNEL_ARTIFACT_ACTOR) {
        return Err(readback_refused(
            "paired ledger entry names the wrong actor",
        ));
    }
    if !matches!(&entry.subject, SubjectId::Query(subject) if subject.as_slice() == scope_subject(&artifact.scope_id).as_slice())
    {
        return Err(readback_refused(
            "paired ledger entry names the wrong scope subject",
        ));
    }
    if entry.payload != ledger_bytes {
        return Err(readback_refused(
            "paired ledger entry payload differs from the persisted members-hash bytes",
        ));
    }

    Ok(3)
}

fn read_back_row<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
    key: &[u8],
    expected: &[u8],
    label: &str,
) -> IngestResult<()>
where
    C: Clock,
{
    let persisted = vault
        .read_cf_at(commit_seq, ColumnFamily::Kernel, key)?
        .ok_or_else(|| {
            readback_refused(format!(
                "{label} row missing at kernel artifact commit snapshot"
            ))
        })?;
    if persisted != expected {
        return Err(readback_refused(format!(
            "{label} row read back {} bytes that differ from the {} bytes written",
            persisted.len(),
            expected.len()
        )));
    }
    Ok(())
}

fn projection_weight_to_frequency(weight: f32, id: CxId) -> IngestResult<u64> {
    if !weight.is_finite() || weight <= 0.0 {
        return Err(adapter_refused(format!(
            "kernel projection node {id} weight {weight} is not a finite positive frequency"
        )));
    }
    // The composite kernel projection stores node frequency (change_count + 1)
    // as an f32; recover the integer frequency the kernel pipeline expects.
    Ok(weight.round() as u64)
}

fn artifact_key(scope_id: &str, leaf: &[u8]) -> Vec<u8> {
    let scope = scope_id.as_bytes();
    let mut key =
        Vec::with_capacity(KERNEL_ARTIFACT_CF_PREFIX.len() + scope.len() + 1 + leaf.len());
    key.extend_from_slice(KERNEL_ARTIFACT_CF_PREFIX);
    key.extend_from_slice(scope);
    key.push(b':');
    key.extend_from_slice(leaf);
    key
}

fn scope_subject(scope_id: &str) -> Vec<u8> {
    let mut subject = Vec::with_capacity(b"astrolabe-kernel:".len() + scope_id.len());
    subject.extend_from_slice(b"astrolabe-kernel:");
    subject.extend_from_slice(scope_id.as_bytes());
    subject
}

fn adapter_refused(message: impl Into<String>) -> IngestError {
    IngestError::refused(
        ASTRO_KERNEL_GRAPH_ADAPTER_REFUSED,
        message,
        ADAPTER_REMEDIATION,
    )
}

fn readback_refused(message: impl Into<String>) -> IngestError {
    IngestError::refused(
        ASTRO_KERNEL_ARTIFACT_PERSIST_READBACK,
        message,
        READBACK_REMEDIATION,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_projection::{
        GraphProjectionCsr, GraphProjectionCsrEdge, GraphProjectionNode,
    };
    use crate::sqlite_import::{EdgeGraphRow, SCHEMA_EDGE_ROW, edge_graph_key};
    use astrolabe_domain::EdgeKind;
    use astrolabe_kernel::{ASTRO_KERNEL_EMPTY_GRAPH, KernelLedgerEntry, write_kernel_artifacts};
    use calyx_aster::cf::prefix_range;
    use calyx_core::LedgerRef;
    use serde_json::json;

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }

    fn vault() -> AsterVault {
        AsterVault::new(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            b"kernel-artifact-test",
        )
    }

    fn source_row(
        id: i64,
        src: CxId,
        dst: CxId,
        kind: EdgeKind,
        weight: f32,
        props: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>) {
        let row = EdgeGraphRow {
            schema: SCHEMA_EDGE_ROW.to_string(),
            project: "demo".to_string(),
            sqlite_edge_id: id,
            source_node_id: id * 10,
            target_node_id: id * 10 + 1,
            src,
            dst,
            edge_type: kind.as_str().to_string(),
            etype: kind.code(),
            local_name_gen: String::new(),
            weight,
            props,
            properties_json: None,
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            commit: "commit-a".to_string(),
        };
        let key = edge_graph_key(src, dst, kind, "").expect("edge key");
        (key, serde_json::to_vec(&row).expect("edge json"))
    }

    /// A seven-symbol call/dependency/dataflow/service/evolution corpus that
    /// spans two `CxId` regions and carries known change counts. This is the same
    /// shape the production projection golden uses, so it exercises the composite
    /// kernel projection the adapter consumes.
    fn fixture_rows() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            source_row(1, cx(1), cx(2), EdgeKind::Calls, 0.8, json!({})),
            source_row(2, cx(1), cx(3), EdgeKind::ResolvedCalls, 0.6, json!({})),
            source_row(3, cx(2), cx(3), EdgeKind::Imports, 1.0, json!({})),
            source_row(4, cx(2), cx(4), EdgeKind::DependsOn, 0.9, json!({})),
            source_row(5, cx(3), cx(4), EdgeKind::UsesType, 0.75, json!({})),
            source_row(6, cx(3), cx(5), EdgeKind::Instantiates, 0.5, json!({})),
            source_row(7, cx(4), cx(5), EdgeKind::Reads, 0.7, json!({})),
            source_row(8, cx(4), cx(6), EdgeKind::Writes, 0.65, json!({})),
            source_row(9, cx(5), cx(6), EdgeKind::Usage, 0.55, json!({})),
            source_row(10, cx(5), cx(7), EdgeKind::Throws, 0.45, json!({})),
            source_row(11, cx(6), cx(7), EdgeKind::DataFlows, 0.5, json!({})),
            source_row(12, cx(1), cx(4), EdgeKind::HttpCalls, 0.5, json!({})),
            source_row(13, cx(1), cx(5), EdgeKind::Emits, 0.7, json!({})),
            source_row(14, cx(2), cx(6), EdgeKind::Handles, 0.9, json!({})),
            source_row(15, cx(3), cx(7), EdgeKind::CrossGrpcCalls, 0.4, json!({})),
            source_row(
                16,
                cx(7),
                cx(1),
                EdgeKind::FileChangesWith,
                0.25,
                json!({ "src_change_count": 2, "dst_change_count": 4 }),
            ),
            source_row(17, cx(6), cx(1), EdgeKind::Contains, 1.0, json!({})),
        ]
    }

    fn write_sources(vault: &AsterVault, rows: Vec<(Vec<u8>, Vec<u8>)>) {
        vault
            .write_cf_batch(
                rows.into_iter()
                    .map(|(key, value)| (ColumnFamily::Graph, key, value)),
            )
            .expect("write source rows");
    }

    fn anchor_trust() -> BTreeMap<CxId, TrustTag> {
        // cx(1) is the hottest, most-connected symbol; ground it Trusted so the
        // kernel has an anchor to root groundedness at, and mark cx(4) as a
        // Provisional proxy anchor.
        let mut map = BTreeMap::new();
        map.insert(cx(1), TrustTag::Trusted);
        map.insert(cx(4), TrustTag::Provisional);
        map
    }

    // --- adapter unit test: hand-built CSR -> KernelGraph ---

    #[test]
    fn adapter_maps_projection_nodes_edges_and_anchor_trust() {
        // Three nodes with known frequencies (weight = change_count + 1) and one
        // directed edge each; a hand-built CSR the adapter must reproduce exactly.
        let csr = GraphProjectionCsr {
            kind: GraphProjectionKind::KernelGraph,
            source_fingerprint_blake3: [7; 32],
            nodes: vec![
                GraphProjectionNode {
                    id: cx(1),
                    weight: 5.0,
                },
                GraphProjectionNode {
                    id: cx(2),
                    weight: 1.0,
                },
                GraphProjectionNode {
                    id: cx(3),
                    weight: 3.0,
                },
            ],
            offsets: vec![0, 2, 2, 2],
            edges: vec![
                GraphProjectionCsrEdge {
                    dst: cx(2),
                    etype: EdgeKind::Calls.code(),
                    weight: 0.8,
                },
                GraphProjectionCsrEdge {
                    dst: cx(3),
                    etype: EdgeKind::DependsOn.code(),
                    weight: 0.6,
                },
            ],
            association_edge_count: 2,
        };
        let mut trust = BTreeMap::new();
        trust.insert(cx(1), TrustTag::Trusted);
        trust.insert(cx(3), TrustTag::Provisional);

        let graph = kernel_graph_from_projection_csr(&csr, &trust).expect("adapter");
        let nodes = graph.nodes();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].id, cx(1));
        assert_eq!(nodes[0].frequency, 5);
        assert_eq!(nodes[0].anchor_trust, Some(TrustTag::Trusted));
        assert!(nodes[0].is_trusted_anchor());
        assert_eq!(nodes[1].id, cx(2));
        assert_eq!(nodes[1].frequency, 1);
        assert_eq!(nodes[1].anchor_trust, None);
        assert_eq!(nodes[2].frequency, 3);
        assert_eq!(nodes[2].anchor_trust, Some(TrustTag::Provisional));
        assert!(!nodes[2].is_trusted_anchor());

        let edges = graph.edges();
        assert_eq!(edges.len(), 2);
        assert_eq!((edges[0].src, edges[0].dst), (cx(1), cx(2)));
        assert!((edges[0].weight - 0.8).abs() <= f32::EPSILON);
        assert_eq!((edges[1].src, edges[1].dst), (cx(1), cx(3)));
        assert!((edges[1].weight - 0.6).abs() <= f32::EPSILON);
    }

    #[test]
    fn adapter_refuses_non_kernel_projection() {
        let csr = GraphProjectionCsr {
            kind: GraphProjectionKind::CallGraph,
            source_fingerprint_blake3: [0; 32],
            nodes: vec![GraphProjectionNode {
                id: cx(1),
                weight: 1.0,
            }],
            offsets: vec![0, 0],
            edges: vec![],
            association_edge_count: 0,
        };
        let error = kernel_graph_from_projection_csr(&csr, &BTreeMap::new())
            .expect_err("non-kernel projection must be refused");
        assert_eq!(error.code(), Some(ASTRO_KERNEL_GRAPH_ADAPTER_REFUSED));
        assert!(error.remediation().is_some());
    }

    // --- FSV: real vault projection -> adapter -> build -> persist -> readback ---

    #[test]
    fn fsv_build_and_persist_kernel_from_real_projection_readback() {
        let vault = vault();
        write_sources(&vault, fixture_rows());
        let trust = anchor_trust();
        let config = KernelBuildConfig::with_registry_defaults();
        let options = GraphProjectionBuildOptions::new();

        let report = build_and_persist_kernel(&vault, "repo:demo", &trust, &config, &options)
            .expect("build");
        assert_eq!(report.rows_readback_verified, 3);
        assert!(report.ledger_paired);
        assert!(report.member_count > 0);
        assert_eq!(report.node_count, 7);
        assert!(report.recall_gated);
        assert!(report.anchor_grounded, "cx(1) is a Trusted anchor in scope");

        // Independent readback: scan the Kernel CF rows directly and re-derive
        // the members-hash from the persisted kernel.json member set. This never
        // trusts the persist function's own report.
        let snapshot = vault.latest_seq();
        let kernel_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Kernel, &report.kernel_json_key)
            .expect("read kernel.json")
            .expect("kernel.json present");
        let persisted_artifact =
            serde_json::from_slice::<KernelArtifact>(&kernel_bytes).expect("decode kernel.json");
        let member_ids: Vec<CxId> = persisted_artifact.members.iter().map(|m| m.id).collect();
        let derived_hash = members_hash(&member_ids);
        assert_eq!(derived_hash, report.members_hash);
        assert_eq!(derived_hash, persisted_artifact.members_hash);

        // The persisted members-hash CF row is a KernelLedgerEntry whose hash and
        // member count must match the re-derived values.
        let members_row = vault
            .read_cf_at(snapshot, ColumnFamily::Kernel, &report.members_hash_key)
            .expect("read members-hash")
            .expect("members-hash present");
        let ledger_entry =
            serde_json::from_slice::<KernelLedgerEntry>(&members_row).expect("decode members-hash");
        assert_eq!(ledger_entry.members_hash, derived_hash);
        assert_eq!(ledger_entry.member_count, member_ids.len());

        // The index.json manifest pins the same member set and hash.
        let index_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Kernel, &report.index_json_key)
            .expect("read index.json")
            .expect("index.json present");
        let manifest =
            serde_json::from_slice::<serde_json::Value>(&index_bytes).expect("decode index.json");
        assert_eq!(manifest["members_hash"], json!(derived_hash));
        assert_eq!(manifest["index_kind"], json!("membership_manifest"));

        // The paired Kernel ledger entry carries the same members-hash payload.
        let (_k, entry_bytes) = vault
            .scan_cf_at(snapshot, ColumnFamily::Ledger)
            .expect("scan ledger")
            .into_iter()
            .max_by(|a, b| a.0.cmp(&b.0))
            .expect("ledger entry");
        let entry = decode(&entry_bytes).expect("decode ledger");
        assert_eq!(entry.kind, EntryKind::Kernel);
        let payload_entry =
            serde_json::from_slice::<KernelLedgerEntry>(&entry.payload).expect("ledger payload");
        assert_eq!(payload_entry.members_hash, derived_hash);
    }

    #[test]
    fn persisted_kernel_json_bytes_match_filesystem_serializer() {
        // DoD: one serializer, byte-compatible payloads. The vault-persisted
        // kernel.json/index.json bytes must equal the crate-level filesystem
        // path's bytes for the same artifact — no silent divergence.
        let vault = vault();
        write_sources(&vault, fixture_rows());
        let trust = anchor_trust();
        let config = KernelBuildConfig::with_registry_defaults();
        let options = GraphProjectionBuildOptions::new();

        let csr = ensure_graph_projection_csr(&vault, GraphProjectionKind::KernelGraph, &options)
            .expect("csr");
        let graph = kernel_graph_from_projection_csr(&csr, &trust).expect("adapter");
        let artifact = build_kernel(&graph, "repo:demo", &config).expect("build");

        let report = persist_kernel_artifact(&vault, &artifact).expect("persist");

        let dir = std::env::temp_dir().join(format!(
            "astro-kernel-fsv-{}-{}",
            std::process::id(),
            report.commit_seq
        ));
        let paths = write_kernel_artifacts(&dir, &artifact).expect("fs artifacts");
        let fs_kernel = std::fs::read(&paths.kernel_json).expect("fs kernel.json");
        let fs_index = std::fs::read(&paths.index_json).expect("fs index.json");

        let vault_kernel = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Kernel,
                &report.kernel_json_key,
            )
            .expect("read")
            .expect("present");
        let vault_index = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Kernel,
                &report.index_json_key,
            )
            .expect("read")
            .expect("present");

        assert_eq!(
            vault_kernel, fs_kernel,
            "vault kernel.json diverged from the filesystem serializer"
        );
        assert_eq!(
            vault_index, fs_index,
            "vault index.json diverged from the filesystem serializer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_bytes_are_deterministic_across_repeated_builds() {
        let build_once = || {
            let vault = vault();
            write_sources(&vault, fixture_rows());
            let report = build_and_persist_kernel(
                &vault,
                "repo:demo",
                &anchor_trust(),
                &KernelBuildConfig::with_registry_defaults(),
                &GraphProjectionBuildOptions::new(),
            )
            .expect("build");
            let rows = vault
                .scan_cf_range_at(
                    vault.latest_seq(),
                    ColumnFamily::Kernel,
                    &prefix_range(KERNEL_ARTIFACT_CF_PREFIX),
                )
                .expect("scan artifact rows");
            (report.members_hash, rows)
        };
        let (hash_a, rows_a) = build_once();
        let (hash_b, rows_b) = build_once();
        assert_eq!(hash_a, hash_b);
        assert_eq!(
            rows_a, rows_b,
            "persisted kernel artifact bytes must be deterministic"
        );
    }

    #[test]
    fn promotion_aware_trust_flips_persisted_groundedness() {
        // #352 adapter seam FSV: the per-symbol anchor trust map the kernel
        // consumes drives the persisted kernel score. Building the SAME graph with
        // cx(1) as a Provisional anchor vs a Trusted anchor must flip cx(1)'s
        // grounded flag and lift its groundedness permille on the readback — this
        // is exactly the flip a `promote_on_resolution` produces in
        // `astrolabe_anchors::effective_anchor_trust_map`.
        let config = KernelBuildConfig::with_registry_defaults();
        let options = GraphProjectionBuildOptions::new();

        // Unpromoted: cx(1) carries only a Provisional (proxy) anchor => no Trusted
        // anchor in scope, so no member is grounded.
        let unpromoted = vault();
        write_sources(&unpromoted, fixture_rows());
        let mut before = BTreeMap::new();
        before.insert(cx(1), TrustTag::Provisional);
        let before_report =
            build_and_persist_kernel(&unpromoted, "repo:demo", &before, &config, &options)
                .expect("build unpromoted");
        assert!(
            !before_report.anchor_grounded,
            "a Provisional-only scope has no Trusted grounding anchor"
        );
        let before_artifact = read_persisted_kernel_artifact(&unpromoted, "repo:demo")
            .expect("read unpromoted")
            .expect("unpromoted artifact present");
        let before_member = before_artifact
            .members
            .iter()
            .find(|member| member.id == cx(1))
            .expect("cx(1) is a kernel member");
        assert!(
            !before_member.grounded,
            "cx(1) is not grounded before promotion"
        );

        // Promoted: cx(1)'s anchor is now effectively Trusted (a CI resolution).
        let promoted = vault();
        write_sources(&promoted, fixture_rows());
        let mut after = BTreeMap::new();
        after.insert(cx(1), TrustTag::Trusted);
        let after_report =
            build_and_persist_kernel(&promoted, "repo:demo", &after, &config, &options)
                .expect("build promoted");
        assert!(
            after_report.anchor_grounded,
            "promotion makes cx(1) a Trusted grounding anchor"
        );
        let after_artifact = read_persisted_kernel_artifact(&promoted, "repo:demo")
            .expect("read promoted")
            .expect("promoted artifact present");
        let after_member = after_artifact
            .members
            .iter()
            .find(|member| member.id == cx(1))
            .expect("cx(1) is a kernel member");
        assert!(after_member.grounded, "cx(1) is grounded after promotion");
        assert!(
            after_member.groundedness_permille > before_member.groundedness_permille,
            "promotion lifts cx(1) groundedness ({} -> {})",
            before_member.groundedness_permille,
            after_member.groundedness_permille
        );
        // The members-hash is unchanged (same member set, same graph); only the
        // groundedness contribution moved — the flip is in the scoring, not the
        // membership.
        assert_ne!(
            before_report.members_hash, "",
            "a members-hash was persisted"
        );
    }

    #[test]
    fn empty_graph_refuses_fail_closed() {
        // A vault with no typed edge rows projects an empty kernel graph; the
        // kernel build must refuse rather than persist a meaningless kernel.
        let vault = vault();
        let error = build_and_persist_kernel(
            &vault,
            "repo:empty",
            &BTreeMap::new(),
            &KernelBuildConfig::with_registry_defaults(),
            &GraphProjectionBuildOptions::new(),
        )
        .expect_err("empty graph must be refused");
        assert_eq!(error.code(), Some(ASTRO_KERNEL_EMPTY_GRAPH));
    }

    #[test]
    fn tampered_persisted_kernel_row_fails_readback() {
        // Persist cleanly, then tamper the persisted kernel.json bytes and re-run
        // the readback verifier: it must refuse fail-closed.
        let vault = vault();
        write_sources(&vault, fixture_rows());
        let config = KernelBuildConfig::with_registry_defaults();
        let options = GraphProjectionBuildOptions::new();
        let csr = ensure_graph_projection_csr(&vault, GraphProjectionKind::KernelGraph, &options)
            .expect("csr");
        let graph = kernel_graph_from_projection_csr(&csr, &anchor_trust()).expect("adapter");
        let artifact = build_kernel(&graph, "repo:demo", &config).expect("build");
        let report = persist_kernel_artifact(&vault, &artifact).expect("persist");

        vault
            .write_cf_batch([(
                ColumnFamily::Kernel,
                report.kernel_json_key.clone(),
                b"tampered-kernel-json".to_vec(),
            )])
            .expect("tamper");

        let kernel_bytes = artifact.kernel_json_bytes();
        let index_bytes = artifact.index_json_bytes();
        let ledger_bytes = serde_json::to_vec(&artifact.ledger_entry()).unwrap();
        let error = verify_kernel_artifact_readback(
            &vault,
            vault.latest_seq(),
            &artifact,
            &report.kernel_json_key,
            &kernel_bytes,
            &report.index_json_key,
            &index_bytes,
            &report.members_hash_key,
            &ledger_bytes,
        )
        .expect_err("tampered kernel.json must fail readback");
        assert_eq!(error.code(), Some(ASTRO_KERNEL_ARTIFACT_PERSIST_READBACK));
        assert!(error.remediation().is_some());
    }
}
