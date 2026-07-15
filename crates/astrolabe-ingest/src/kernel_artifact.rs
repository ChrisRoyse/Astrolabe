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
