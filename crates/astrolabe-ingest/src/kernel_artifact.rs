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
//! [`KernelArtifact::index_json_bytes`], [`KernelArtifact::ledger_entry`]); there
//! is one canonical byte representation and durable publication is owned by the
//! Aster generation transaction.

use std::collections::BTreeMap;

use astrolabe_domain::TrustTag;
use astrolabe_kernel::{
    FVS_VALIDITY_METHOD, KERNEL_ARTIFACT_SCHEMA, KERNEL_BUILD_ALGORITHM_SCHEMA,
    KERNEL_BUILD_KNOB_REGISTRY_VERSION, KERNEL_INDEX_SCHEMA, KERNEL_LEDGER_SCHEMA,
    KERNEL_SOURCE_IDENTITY_SCHEMA, KernelArtifact, KernelBuildConfig, KernelGraph, KernelGraphEdge,
    KernelGraphNode, KernelIndexManifest, KernelLedgerEntry, KernelMember, build_kernel,
    kernel_build_config_identity, members_hash,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, CxId, LedgerRef, Seq};
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
    /// Diagnostic graph coverage in permille carried by the persisted kernel.
    pub graph_coverage_permille: u64,
    /// Whether the diagnostic reaches its declared graph-coverage floor.
    pub graph_coverage_meets_floor: bool,
    /// Complete canonical source graph/config identity bound into the artifact.
    pub source_identity_hash: String,
    /// Full residual-DAG topological-order identity carried by the FVS proof.
    pub residual_topological_order_hash: String,
    /// Whether the strict whole-corpus compactness ceiling admitted the artifact.
    pub compactness_admitted: bool,
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
    /// Exact append-only Ledger identity verified at `commit_seq`.
    ///
    /// This is deliberately separate from [`Self::commit_seq`]: the Aster MVCC
    /// commit sequence and the Ledger entry sequence are independent counters
    /// and must never be treated as interchangeable provenance identities.
    pub ledger_ref: LedgerRef,
    /// Kernel CF rows re-read and byte-verified after the commit (always 3 on
    /// success: kernel.json, index.json, members-hash).
    pub rows_readback_verified: usize,
    /// Whether the commit's paired Kernel ledger entry was read back and its
    /// members-hash verified byte-compatible with the persisted rows.
    pub ledger_paired: bool,
}

/// Canonical fixed-row serialization of one fully validated kernel artifact.
///
/// This is a mutation-free preparation object. The composite generation owner
/// can place the three values under content-addressed keys and/or their legacy
/// fixed aliases in the same outer transaction as the member HNSW, manifest,
/// current pointer, and Ledger row. No serializer is duplicated outside this
/// module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedKernelArtifactRows {
    /// Decoded artifact proven equal to all three canonical row encodings.
    pub artifact: KernelArtifact,
    /// Canonical `kernel.json` bytes.
    pub kernel_json: Vec<u8>,
    /// Canonical `index.json` bytes.
    pub index_json: Vec<u8>,
    /// Canonical members-hash / Kernel-ledger payload bytes.
    pub members_hash: Vec<u8>,
    /// Existing fixed alias key for `kernel.json`.
    pub fixed_kernel_json_key: Vec<u8>,
    /// Existing fixed alias key for `index.json`.
    pub fixed_index_json_key: Vec<u8>,
    /// Existing fixed alias key for the members-hash payload.
    pub fixed_members_hash_key: Vec<u8>,
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

/// Builds one kernel artifact from an already-read composite projection.
///
/// Unlike [`build_and_persist_kernel`], this function never materializes a
/// projection and never writes the vault. Its caller owns the retained snapshot
/// and must obtain `csr` and `anchor_trust` at that same sequence. This is the
/// required preparation boundary for atomic complete-kernel publication: source
/// discovery, FVS/compactness validation, S20 index construction, and all byte
/// preparation finish before the first mutation.
pub fn build_kernel_artifact_from_projection_csr(
    csr: &GraphProjectionCsr,
    scope_id: &str,
    anchor_trust: &BTreeMap<CxId, TrustTag>,
    config: &KernelBuildConfig,
) -> IngestResult<KernelArtifact> {
    let graph = kernel_graph_from_projection_csr(csr, anchor_trust)?;
    Ok(build_kernel(&graph, scope_id, config)?)
}

/// Produces the canonical three-row artifact serialization without mutating a
/// vault. The returned bytes have already passed a full independent decode and
/// invariant check.
pub fn prepare_kernel_artifact_rows(
    artifact: &KernelArtifact,
) -> IngestResult<PreparedKernelArtifactRows> {
    let kernel_json = artifact.kernel_json_bytes();
    let index_json = artifact.index_json_bytes();
    let members_hash = serde_json::to_vec(&artifact.ledger_entry())?;
    let validated = validate_kernel_artifact_rows(
        &artifact.scope_id,
        &kernel_json,
        &index_json,
        &members_hash,
    )?;
    if validated != *artifact {
        return Err(readback_refused(format!(
            "prepared kernel artifact for scope {:?} changed across its canonical serializers",
            artifact.scope_id
        )));
    }
    Ok(PreparedKernelArtifactRows {
        artifact: validated,
        kernel_json,
        index_json,
        members_hash,
        fixed_kernel_json_key: artifact_key(&artifact.scope_id, b"kernel.json"),
        fixed_index_json_key: artifact_key(&artifact.scope_id, b"index.json"),
        fixed_members_hash_key: artifact_key(&artifact.scope_id, b"members-hash"),
    })
}

/// Decodes and validates three canonical artifact rows read from an independently
/// selected generation. Used by the composite pointer reader so generation rows
/// and fixed aliases share exactly the same invariant implementation.
pub fn decode_kernel_artifact_rows(
    scope_id: &str,
    kernel_json: &[u8],
    index_json: &[u8],
    members_hash: &[u8],
) -> IngestResult<KernelArtifact> {
    validate_kernel_artifact_rows(scope_id, kernel_json, index_json, members_hash)
}

/// Builds a full-graph-FVS-validated compact kernel over the vault's composite projection and
/// persists it to the production Kernel CF with a paired ledger entry.
///
/// Ensures the composite kernel projection is materialized and fresh against the
/// current Graph CF, adapts it into a [`KernelGraph`] with the supplied anchor
/// trust rollup, runs `build_kernel`, and hands the artifact to
/// [`persist_kernel_artifact`]. Fail-closed refusals (empty graph, stale
/// projection, invalid full-graph FVS, compactness refusal, and readback mismatch) propagate their
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
    // #443 permanent sub-phase timing (env-gated `ASTRO_KERNEL_TIMING`): split
    // the kernel_artifact phase into projection materialization vs graph adapter
    // vs the kernel algorithm (`build_kernel`, itself sub-timed) vs persist, so
    // the #443 matrix separates data-plane cost from algorithm cost. build_kernel
    // emits its own finer `phase=kernel_artifact` sub-stages.
    let mut timing = astrolabe_kernel::KernelPhaseTiming::start("kernel_artifact_wrap");
    let csr = ensure_graph_projection_csr(vault, GraphProjectionKind::KernelGraph, options)?;
    timing.lap("projection");
    let graph = kernel_graph_from_projection_csr(&csr, anchor_trust)?;
    timing.lap("adapter");
    let artifact = build_kernel(&graph, scope_id, config)?;
    timing.lap("build_kernel");
    let report = persist_kernel_artifact(vault, &artifact)?;
    timing.lap("persist");
    Ok(report)
}

/// Persists a computed [`KernelArtifact`] to the Kernel CF and reads it back.
///
/// Writes three Kernel CF rows — `kernel.json`, `index.json`, and the
/// members-hash ledger entry — in one batch paired with a `Kernel` ledger entry
/// whose payload is the same members-hash serialization. The row bytes are the
/// kernel crate's own canonical serializers. After the commit every row is read
/// back at the commit snapshot and byte-compared, the members-hash is
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
    let prepared = prepare_kernel_artifact_rows(artifact)?;
    let kernel_bytes = prepared.kernel_json;
    let index_bytes = prepared.index_json;
    let ledger_bytes = prepared.members_hash;
    let kernel_key = prepared.fixed_kernel_json_key;
    let index_key = prepared.fixed_index_json_key;
    let members_key = prepared.fixed_members_hash_key;

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

    let (rows_readback_verified, ledger_ref) = verify_kernel_artifact_readback(
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
        graph_coverage_permille: artifact.graph_coverage.permille,
        graph_coverage_meets_floor: artifact.graph_coverage.meets_coverage_floor,
        source_identity_hash: artifact.source_identity.combined_hash.clone(),
        residual_topological_order_hash: artifact
            .fvs_validity
            .residual_topological_order_hash
            .clone(),
        compactness_admitted: artifact.compactness.admitted,
        anchor_grounded: artifact.anchor_grounded,
        kernel_json_key: kernel_key,
        index_json_key: index_key,
        members_hash_key: members_key,
        commit_seq,
        ledger_ref,
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
    let snapshot = vault.latest_seq();
    read_persisted_kernel_artifact_at(vault, scope_id, snapshot)
}

/// Reads and validates the exact three-row kernel artifact generation at one
/// caller-retained snapshot. This avoids combining rows from different MVCC
/// generations when a reader also inspects the raw bytes or paired Ledger row.
pub fn read_persisted_kernel_artifact_at<C>(
    vault: &AsterVault<C>,
    scope_id: &str,
    snapshot: Seq,
) -> IngestResult<Option<KernelArtifact>>
where
    C: Clock,
{
    let kernel_key = artifact_key(scope_id, b"kernel.json");
    let index_key = artifact_key(scope_id, b"index.json");
    let members_key = artifact_key(scope_id, b"members-hash");
    let kernel_bytes = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &kernel_key)?;
    let index_bytes = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &index_key)?;
    let members_bytes = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &members_key)?;
    let Some(kernel_bytes) = kernel_bytes else {
        if index_bytes.is_some() || members_bytes.is_some() {
            return Err(readback_refused(format!(
                "scope {scope_id:?} has auxiliary index/members rows but no kernel.json at snapshot {snapshot}"
            )));
        }
        return Ok(None);
    };
    let index_bytes = index_bytes.ok_or_else(|| {
        readback_refused(format!(
            "scope {scope_id:?} has kernel.json but no index.json at snapshot {snapshot}"
        ))
    })?;
    let members_bytes = members_bytes.ok_or_else(|| {
        readback_refused(format!(
            "scope {scope_id:?} has kernel.json but no members-hash row at snapshot {snapshot}"
        ))
    })?;
    validate_kernel_artifact_rows(scope_id, &kernel_bytes, &index_bytes, &members_bytes).map(Some)
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
) -> IngestResult<(usize, LedgerRef)>
where
    C: Clock,
{
    let persisted_kernel =
        read_back_row(vault, commit_seq, kernel_key, kernel_bytes, "kernel.json")?;
    let persisted_index = read_back_row(vault, commit_seq, index_key, index_bytes, "index.json")?;
    let persisted_members =
        read_back_row(vault, commit_seq, members_key, ledger_bytes, "members-hash")?;

    // Independently re-derive the members-hash from the persisted kernel.json
    // member set. A tampered member set or a members-hash that does not cover
    // the persisted members is caught here even if every row read back byte
    // clean against the staged bytes.
    let persisted = validate_kernel_artifact_rows(
        &artifact.scope_id,
        &persisted_kernel,
        &persisted_index,
        &persisted_members,
    )?;
    if persisted != *artifact {
        return Err(readback_refused(format!(
            "decoded persisted kernel artifact differs from the staged artifact for scope {}",
            artifact.scope_id
        )));
    }

    // The paired Kernel ledger entry must exist at the commit snapshot, name the
    // kernel-build actor and scope subject, and carry the same members-hash
    // payload bytes as the persisted members-hash row (one serializer).
    let (key, entry_bytes) = calyx_aster::ledger_view::newest_pairable_ledger(
        vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?,
    )?
    .ok_or_else(|| readback_refused("Ledger CF empty at kernel artifact commit snapshot"))?;
    let entry = decode(&entry_bytes)?;
    if !entry.verify() {
        return Err(readback_refused(
            "paired ledger entry failed its hash-chain self-verification",
        ));
    }
    if key.as_slice() != entry.seq.to_be_bytes().as_slice() {
        return Err(readback_refused(format!(
            "paired ledger key {} does not encode entry sequence {}",
            hex_lower(&key),
            entry.seq
        )));
    }
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
    if entry.payload != persisted_members {
        return Err(readback_refused(
            "paired ledger entry payload differs from the persisted members-hash bytes",
        ));
    }

    Ok((
        3,
        LedgerRef {
            seq: entry.seq,
            hash: entry.entry_hash,
        },
    ))
}

fn read_back_row<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
    key: &[u8],
    expected: &[u8],
    label: &str,
) -> IngestResult<Vec<u8>>
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
    Ok(persisted)
}

fn validate_kernel_artifact_rows(
    scope_id: &str,
    kernel_bytes: &[u8],
    index_bytes: &[u8],
    members_bytes: &[u8],
) -> IngestResult<KernelArtifact> {
    let artifact = serde_json::from_slice::<KernelArtifact>(kernel_bytes)?;
    let index = serde_json::from_slice::<KernelIndexManifest>(index_bytes)?;
    let ledger = serde_json::from_slice::<KernelLedgerEntry>(members_bytes)?;

    if artifact.schema != KERNEL_ARTIFACT_SCHEMA
        || artifact.knob_registry_version != KERNEL_BUILD_KNOB_REGISTRY_VERSION
        || artifact.scope_id != scope_id
        || artifact.source_identity.schema != KERNEL_SOURCE_IDENTITY_SCHEMA
        || artifact.source_identity.algorithm_schema != KERNEL_BUILD_ALGORITHM_SCHEMA
    {
        return Err(readback_refused(format!(
            "kernel.json schema/scope/source identity mismatch: expected_schema={KERNEL_ARTIFACT_SCHEMA:?} observed_schema={:?} expected_knobs={KERNEL_BUILD_KNOB_REGISTRY_VERSION:?} observed_knobs={:?} expected_scope={scope_id:?} observed_scope={:?} expected_source_schema={KERNEL_SOURCE_IDENTITY_SCHEMA:?} observed_source_schema={:?} expected_algorithm_schema={KERNEL_BUILD_ALGORITHM_SCHEMA:?} observed_algorithm_schema={:?}",
            artifact.schema,
            artifact.knob_registry_version,
            artifact.scope_id,
            artifact.source_identity.schema,
            artifact.source_identity.algorithm_schema,
        )));
    }
    if artifact.kernel_json_bytes() != kernel_bytes {
        return Err(readback_refused(format!(
            "kernel.json for scope {scope_id:?} is not the canonical artifact serialization"
        )));
    }
    let member_ids = artifact
        .members
        .iter()
        .map(|member: &KernelMember| member.id)
        .collect::<Vec<_>>();
    if member_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(readback_refused(format!(
            "kernel.json for scope {scope_id:?} does not carry a strictly ascending unique member roster"
        )));
    }
    let derived = members_hash(&member_ids);
    let expected_fraction =
        ((artifact.member_count as u128) * 1000_u128 / (artifact.node_count.max(1) as u128)) as u64;
    let expected_coverage_permille = artifact
        .graph_coverage
        .covered
        .saturating_mul(1000)
        .checked_div(artifact.graph_coverage.total)
        .unwrap_or(0);
    let expected_config_hash = kernel_build_config_identity(&artifact.config)?;
    validate_persisted_fvs_proof(scope_id, &artifact)?;
    if artifact.member_count != artifact.members.len()
        || derived != artifact.members_hash
        || artifact.node_count == 0
        || artifact.member_count == 0
        || artifact.source_identity.node_count != artifact.node_count
        || artifact.source_identity.config_hash != expected_config_hash
        || artifact.graph_coverage.total != artifact.node_count as u64
        || artifact.graph_coverage.metric != "undirected_graph_coverage_at_radius"
        || artifact.graph_coverage.admission_role != "diagnostic_only_not_retrieval_recall"
        || artifact.graph_coverage.radius_hops != artifact.config.graph_coverage_radius_hops
        || artifact.graph_coverage.covered > artifact.graph_coverage.total
        || artifact.graph_coverage.permille != expected_coverage_permille
        || artifact.graph_coverage.meets_coverage_floor
            != (artifact.graph_coverage.permille >= artifact.config.graph_coverage_min_permille)
        || artifact.compactness.member_count != artifact.member_count
        || artifact.compactness.source_node_count != artifact.node_count
        || artifact.compactness.member_fraction_permille != expected_fraction
        || artifact.compactness.max_member_fraction_permille
            != artifact.config.max_member_fraction_permille
        || !artifact.compactness.admitted
        || artifact.member_count >= artifact.node_count
    {
        return Err(readback_refused(format!(
            "kernel.json for scope {scope_id:?} fails member/source/FVS/graph-coverage/compactness invariants: derived_members_hash={derived} stored_members_hash={} members={} declared_members={} source_nodes={} source_identity_nodes={} source_edges={} source_config_hash={} expected_config_hash={expected_config_hash} fvs_members={} fvs_method={:?} residual_nodes={} residual_order_sha256={:?} cyclic_sccs={} largest_cyclic_scc_nodes={} dfs_checked_edges={} dfs_back_edges={} dfs_back_edge_roster_sha256={:?} coverage={}/{} coverage_permille={} expected_coverage_permille={expected_coverage_permille} compactness={:?}",
            artifact.members_hash,
            artifact.members.len(),
            artifact.member_count,
            artifact.node_count,
            artifact.source_identity.node_count,
            artifact.source_identity.edge_count,
            artifact.source_identity.config_hash,
            artifact.fvs_count,
            artifact.fvs_validity.method,
            artifact.fvs_validity.residual_node_count,
            artifact.fvs_validity.residual_topological_order_hash,
            artifact.fvs_validity.cyclic_scc_count,
            artifact.fvs_validity.largest_cyclic_scc_node_count,
            artifact.fvs_validity.dfs_checked_edge_count,
            artifact.fvs_validity.dfs_back_edge_count,
            artifact.fvs_validity.dfs_back_edge_roster_hash,
            artifact.graph_coverage.covered,
            artifact.graph_coverage.total,
            artifact.graph_coverage.permille,
            artifact.compactness,
        )));
    }
    if index.schema != KERNEL_INDEX_SCHEMA
        || ledger.schema != KERNEL_LEDGER_SCHEMA
        || artifact.index_json_bytes() != index_bytes
        || serde_json::to_vec(&artifact.ledger_entry())? != members_bytes
        || index.scope_id != artifact.scope_id
        || index.members != member_ids
        || index.members_hash != artifact.members_hash
        || index.member_count != artifact.member_count
        || index.source_identity != artifact.source_identity
        || index.fvs_validity != artifact.fvs_validity
        || index.graph_coverage != artifact.graph_coverage
        || index.compactness != artifact.compactness
        || ledger.scope_id != artifact.scope_id
        || ledger.members_hash != artifact.members_hash
        || ledger.member_count != artifact.member_count
        || ledger.source_identity != artifact.source_identity
        || ledger.fvs_validity != artifact.fvs_validity
        || ledger.graph_coverage != artifact.graph_coverage
        || ledger.compactness != artifact.compactness
    {
        return Err(readback_refused(format!(
            "scope {scope_id:?} kernel.json, index.json, and members-hash ledger payload do not carry one exact schema-v3 member/source/FVS/graph-coverage/compactness identity"
        )));
    }
    Ok(artifact)
}

fn validate_persisted_fvs_proof(scope_id: &str, artifact: &KernelArtifact) -> IngestResult<()> {
    let proof = &artifact.fvs_validity;
    let mismatch = if artifact.fvs_count != artifact.member_count {
        Some(format!(
            "FVS member count {} differs from persisted kernel member count {}",
            artifact.fvs_count, artifact.member_count
        ))
    } else if let Some(member) = artifact.members.iter().find(|member| !member.in_fvs) {
        Some(format!(
            "persisted kernel member {} is not marked as a DFS-selected FVS member",
            member.id
        ))
    } else if proof.method != FVS_VALIDITY_METHOD {
        Some(format!(
            "FVS method drift: expected={FVS_VALIDITY_METHOD:?} observed={:?}",
            proof.method
        ))
    } else if proof.cyclic_scc_count == 0 || proof.cyclic_scc_count > artifact.node_count {
        Some(format!(
            "cyclic SCC count {} is outside 1..={}",
            proof.cyclic_scc_count, artifact.node_count
        ))
    } else if proof.largest_cyclic_scc_node_count == 0
        || proof.largest_cyclic_scc_node_count > artifact.node_count
    {
        Some(format!(
            "largest cyclic SCC node count {} is outside 1..={}",
            proof.largest_cyclic_scc_node_count, artifact.node_count
        ))
    } else if proof.dfs_checked_edge_count == 0
        || proof.dfs_checked_edge_count > artifact.source_identity.edge_count
    {
        Some(format!(
            "canonical DFS checked-edge count {} is outside 1..={} source edges",
            proof.dfs_checked_edge_count, artifact.source_identity.edge_count
        ))
    } else if proof.dfs_back_edge_count == 0
        || proof.dfs_back_edge_count > proof.dfs_checked_edge_count
    {
        Some(format!(
            "canonical DFS back-edge count {} is outside 1..={} checked edges",
            proof.dfs_back_edge_count, proof.dfs_checked_edge_count
        ))
    } else if artifact.fvs_count > proof.dfs_back_edge_count {
        Some(format!(
            "FVS member count {} exceeds the {} recorded gray/back-edges that can select members",
            artifact.fvs_count, proof.dfs_back_edge_count
        ))
    } else if !is_lower_hex_sha256(&proof.dfs_back_edge_roster_hash) {
        Some(format!(
            "DFS back-edge roster hash is not a 64-character lowercase SHA-256: {:?}",
            proof.dfs_back_edge_roster_hash
        ))
    } else {
        let expected_residual = artifact.node_count.saturating_sub(artifact.fvs_count);
        if proof.residual_node_count != expected_residual {
            Some(format!(
                "residual node count {} differs from source_nodes({}) - fvs_members({}) = {expected_residual}",
                proof.residual_node_count, artifact.node_count, artifact.fvs_count
            ))
        } else if !is_lower_hex_sha256(&proof.residual_topological_order_hash) {
            Some(format!(
                "residual topological-order hash is not a 64-character lowercase SHA-256: {:?}",
                proof.residual_topological_order_hash
            ))
        } else {
            None
        }
    };
    if let Some(mismatch) = mismatch {
        return Err(readback_refused(format!(
            "kernel.json for scope {scope_id:?} fails the schema-v3 canonical DFS/full-residual-DAG proof contract: {mismatch}"
        )));
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
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

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
