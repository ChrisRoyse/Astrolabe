//! Embedding-backed kernel-member search index (#344).
//!
//! The #37/#38 kernel pipeline emits `index.json` as an
//! `astrolabe.kernel_index.v1` *membership manifest*: it pins the exact kernel
//! member set and its `members_hash`, honestly labeled `membership_manifest`,
//! because embeddings are not available inside `astrolabe-kernel`. The
//! blueprint's kernel index is an embedding-backed ANN over the S18
//! code-semantic vectors restricted to the kernel members, so kernel-scoped
//! semantic search serves from a small index instead of the full corpus.
//!
//! This module builds that index where the panel vectors live (weave), keyed by
//! the kernel manifest's member set:
//!
//! - [`build_kernel_member_index`] resolves the member `CxId`s to their live
//!   symbols, reads the persisted S18 vectors for exactly those members (reusing
//!   the #42 production search-index machinery: [`read_search_corpus_from_vault`]
//!   then [`build_manifest_from_corpus`]), and freezes an HNSW manifest over the
//!   member subcorpus. The result is content-addressed by the same `members_hash`
//!   the kernel manifest carries.
//! - [`kernel_scoped_semantic_query`] serves a symbol-anchored semantic query
//!   from the small index, **refusing fail-closed** when the caller's current
//!   `members_hash` no longer matches the index's ([`ASTRO_KERNEL_INDEX_STALE`])
//!   or when no embedding-backed index is present ([`ASTRO_KERNEL_INDEX_ABSENT`]).
//!   Absence is always labeled, never silently degraded into an empty result.
//! - [`measure_kernel_index_recall`] measures recall@k of the kernel-scoped
//!   index against the full index (restricted to kernel members) — the #37
//!   recall gate ([`KERNEL_INDEX_RECALL_GATE_PERMILLE`], the same >= 0.95 gate
//!   the kernel build persists under).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use astrolabe_ingest::read_cbm_graph_snapshot_at;
use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver};
use calyx_core::{Clock, CxId, LedgerRef, SlotId, SlotVector};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use calyx_registry::{VaultPanelState, load_vault_panel_state};
use calyx_sextant::{HnswArtifactExpectation, HnswIndex, QuantKind, SextantIndex};
use serde::{Deserialize, Serialize};

use crate::search::{SLOT_CODE_SEMANTIC, SearchCaps, SearchError};
use crate::search_index::{IndexKnobs, SlotIndexManifest, SlotIndexSet};
use crate::search_production::{
    CorpusReadReport, CorpusSymbol, SemanticQueryResult, build_manifest_from_corpus,
    semantic_more_like_this,
};

/// Schema tag for a kernel-member embedding index descriptor.
pub const KERNEL_MEMBER_INDEX_SCHEMA: &str = "astrolabe.kernel_member_index.v2";
/// Kernel-CF rows holding the exact project/scope member-index generation.
pub const KERNEL_MEMBER_INDEX_CF_PREFIX: &[u8] = b"astrolabe:kernel-member-index:v2:";
/// Actor sealing descriptor/map/HNSW publication into the Ledger CF.
pub const KERNEL_MEMBER_INDEX_ACTOR: &str = "astrolabe-kernel-member-index";

/// The kernel-scoped recall gate in permille — the same ≥ 0.95 recall@10 gate the
/// #37 kernel build persists under (`astrolabe_kernel::kernel_build`'s
/// `kernel.recall.min_permille` knob, default 950). A kernel-scoped index that
/// recalls the full index's member results below this gate is not fit to serve.
pub const KERNEL_INDEX_RECALL_GATE_PERMILLE: u64 = 950;

/// Fail-closed: a kernel-member index build was requested with no members.
pub const ASTRO_KERNEL_INDEX_NO_MEMBERS: &str = "ASTRO_KERNEL_INDEX_NO_MEMBERS";
/// Fail-closed: a kernel-scoped text query carried no usable query vector, so
/// there is nothing to rank the members against. Never degraded into "rank
/// everything by global weight" — that would answer a question nobody asked.
pub const ASTRO_KERNEL_QUERY_UNRESOLVED: &str = "ASTRO_KERNEL_QUERY_UNRESOLVED";
/// Fail-closed: a kernel member `CxId` has no live symbol in the graph snapshot,
/// so the member set is inconsistent with the corpus the index serves.
pub const ASTRO_KERNEL_INDEX_MEMBER_ABSENT: &str = "ASTRO_KERNEL_INDEX_MEMBER_ABSENT";
/// Fail-closed: reading the graph snapshot for member resolution failed.
pub const ASTRO_KERNEL_INDEX_VAULT: &str = "ASTRO_KERNEL_INDEX_VAULT";
/// Fail-closed: the served index's `members_hash` no longer matches the caller's
/// current kernel manifest `members_hash` — the member set moved, so the index
/// is stale and must be rebuilt (never served against a changed kernel).
pub const ASTRO_KERNEL_INDEX_STALE: &str = "ASTRO_KERNEL_INDEX_STALE";
/// Fail-closed: no embedding-backed index is present (the kernel members carry
/// no persisted S18 vectors); the index is a labeled membership manifest and a
/// semantic query must refuse rather than silently return nothing.
pub const ASTRO_KERNEL_INDEX_ABSENT: &str = "ASTRO_KERNEL_INDEX_ABSENT";
/// Fail-closed: persisted descriptor/map/HNSW rows are missing or disagree.
pub const ASTRO_KERNEL_INDEX_CORRUPT: &str = "ASTRO_KERNEL_INDEX_CORRUPT";
/// Fail-closed: a kernel-member index could not be persisted and read back.
pub const ASTRO_KERNEL_INDEX_PERSIST: &str = "ASTRO_KERNEL_INDEX_PERSIST";

/// What a kernel-member index actually is: a real embedding-backed ANN, or a
/// labeled membership manifest when no member carries an S18 vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelIndexKind {
    /// An HNSW index over the members' persisted S18 code-semantic vectors.
    EmbeddingBackedHnsw,
    /// No member carried a persisted S18 vector; the index is the kernel's
    /// membership manifest only. Semantic queries refuse fail-closed.
    MembershipManifestOnly,
}

/// Compact exact identity carried beside the HNSW bytes. The ANN stores the real
/// member `CxId`, while this table supplies its stable source atom for evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelMemberBinding {
    pub cx_id: CxId,
    pub symbol_id: String,
}

/// The small self-describing row read before a query touches the binary HNSW.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelMemberIndexDescriptor {
    pub schema: String,
    pub project: String,
    pub scope_id: String,
    pub members_hash: String,
    pub index_kind: KernelIndexKind,
    pub slot: SlotId,
    pub semantic_dim: Option<u32>,
    pub base_seq: u64,
    pub knobs: IndexKnobs,
    pub indexed_member_count: usize,
    pub missing_vector_members: Vec<String>,
    pub binding_count: usize,
    pub bindings_blake3: String,
    pub hnsw_artifact_bytes: usize,
    pub hnsw_artifact_blake3: Option<String>,
}

/// A checksum-validated persisted member index ready to serve without graph or
/// vector-manifest reconstruction.
#[derive(Clone, Debug)]
pub struct LoadedKernelMemberIndex {
    pub descriptor: KernelMemberIndexDescriptor,
    pub bindings: Vec<KernelMemberBinding>,
    hnsw: Option<HnswIndex>,
}

/// Independent byte readback from one member-index publication transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMemberIndexPersistReport {
    pub descriptor_key: Vec<u8>,
    pub bindings_key: Vec<u8>,
    pub hnsw_key: Vec<u8>,
    pub commit_seq: u64,
    pub descriptor_blake3: String,
    pub bindings_blake3: String,
    pub hnsw_artifact_blake3: Option<String>,
    pub ledger_ref: LedgerRef,
    pub ledger_physical_tiers: Vec<String>,
    pub rows_readback_verified: usize,
}

impl KernelIndexKind {
    /// Stable discriminator string, matching the kernel `index.json` `index_kind`
    /// vocabulary (`membership_manifest` for the un-upgraded manifest).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmbeddingBackedHnsw => "embedding_backed_hnsw",
            Self::MembershipManifestOnly => "membership_manifest",
        }
    }
}

/// A kernel-scoped search index bound to a kernel manifest's member set.
#[derive(Debug, Clone, PartialEq)]
pub struct KernelMemberIndex {
    /// Descriptor schema tag.
    pub schema: String,
    /// The kernel manifest `members_hash` this index is content-addressed by.
    pub members_hash: String,
    /// Whether a real embedding-backed index is present, or only the labeled
    /// membership manifest.
    pub index_kind: KernelIndexKind,
    /// The frozen HNSW manifest over the member subcorpus — `Some` iff
    /// `index_kind == EmbeddingBackedHnsw`.
    pub manifest: Option<SlotIndexManifest>,
    /// Canonical Calyx HNSW bytes over the members' real `CxId`s. Persisted once
    /// at kernel publication and loaded/cached by exact generation on queries.
    pub hnsw_artifact: Option<Vec<u8>>,
    /// Exact CxId↔source-atom map for the indexed generation.
    pub member_bindings: Vec<KernelMemberBinding>,
    /// Knobs whose exact seed/geometry produced the artifact.
    pub knobs: IndexKnobs,
    /// Resolved stable source-atom ids, ascending.
    pub member_symbol_ids: Vec<String>,
    /// Members that carried a persisted S18 vector and are in the index.
    pub indexed_member_count: usize,
    /// Members resolved to a live symbol but carrying no persisted S18 vector — a
    /// labeled skip, never silently indexed as a zero vector.
    pub missing_vector_members: Vec<String>,
    /// S18 vector dimension of the index, when embedding-backed.
    pub semantic_dim: Option<u32>,
    /// Vault sequence the member corpus was read at (freshness base).
    pub base_seq: u64,
}

/// A kernel-scoped recall measurement of the small index against the full index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelRecallMeasurement {
    /// Member results the kernel index recalled from the full index's ranking.
    pub recalled: u64,
    /// Total member results in the full index's ranking (the gold set).
    pub total: u64,
    /// `recalled / total` in permille.
    pub permille: u64,
    /// Whether the measurement reaches [`KERNEL_INDEX_RECALL_GATE_PERMILLE`].
    pub gated: bool,
}

/// Builds an embedding-backed kernel-member index over S18 for the kernel
/// manifest's member set, content-addressed by `members_hash`.
///
/// Resolves each member `CxId` to its stable source-atom id via the graph snapshot
/// (fail-closed [`ASTRO_KERNEL_INDEX_MEMBER_ABSENT`] if a member is not a live
/// symbol), reads the persisted S18 vectors for exactly those members, and
/// freezes an HNSW manifest over the member subcorpus. When no member carries a
/// persisted S18 vector the index is a labeled [`KernelIndexKind::MembershipManifestOnly`]
/// (never a silently-empty ANN).
pub fn build_kernel_member_index<C>(
    vault: &AsterVault<C>,
    vault_dir: &Path,
    project: &str,
    member_cx_ids: &[CxId],
    members_hash: &str,
    knobs: IndexKnobs,
) -> Result<KernelMemberIndex, SearchError>
where
    C: Clock,
{
    if member_cx_ids.is_empty() {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_NO_MEMBERS,
            "cannot build a kernel-member index for an empty member set".to_string(),
            "Build a kernel with at least one member before building its search index.",
        ));
    }

    // One explicit MVCC generation for both identity and member vectors. Graph
    // reconstruction is a publication-time cost only; the persisted binding map
    // removes it entirely from the serving path (#996).
    let base_seq = vault.latest_seq();
    let compressed_manifest = vault
        .read_cf_at(
            base_seq,
            ColumnFamily::Compression,
            &compression_manifest_key(SLOT_CODE_SEMANTIC),
        )
        .map_err(|error| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!("read S18 compression discriminator at seq {base_seq}: {error}"),
                "Repair the exact Compression/S18 generation before rebuilding the kernel-member index.",
            )
        })?;
    let panel_state: Option<VaultPanelState> = if compressed_manifest.is_some() {
        Some(load_vault_panel_state(vault_dir).map_err(|error| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "load manifest-backed panel/registry context for compressed S18: {error}"
                ),
                "Restore the exact MANIFEST panel_ref/registry_ref assets that own S18, then rebuild the kernel-member index.",
            )
        })?)
    } else {
        None
    };
    let raw_resolver = StrictRawSlotResolver;
    let slot_resolver: &dyn SlotVectorResolver<C> = match &panel_state {
        Some(state) => state,
        None => &raw_resolver,
    };
    let snapshot = read_cbm_graph_snapshot_at(vault, project, base_seq).map_err(|error| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!("read graph snapshot for project {project:?}: {error}"),
            "Re-run index_repository with calyx=\"shadow\" so the vault holds a current graph \
             snapshot before building the kernel-member index.",
        )
    })?;
    let mut node_by_cx = BTreeMap::new();
    let mut atom_to_cx = BTreeMap::new();
    for node in snapshot.nodes.into_iter().filter(|node| !node.structural) {
        let Some(cx_id) = node.cx_id else {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "live non-structural node {:?} in project {project:?} has no CxId",
                    node.qualified_name
                ),
                "Re-index the project so every live source atom has one exact CxId.",
            ));
        };
        if let Some(prior) = atom_to_cx.insert(node.atom_id.clone(), cx_id)
            && prior != cx_id
        {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "source atom {} maps to both {prior} and {cx_id} in project {project:?}",
                    node.atom_id
                ),
                "Re-index the project and repair duplicate source-atom identity before publishing a kernel index.",
            ));
        }
        if node_by_cx.insert(cx_id, node).is_some() {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!("CxId {cx_id} maps to multiple live nodes in project {project:?}"),
                "Re-index the project and repair duplicate CxId identity before publishing a kernel index.",
            ));
        }
    }

    let mut members = member_cx_ids.to_vec();
    members.sort();
    if members.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            "kernel member set contains a duplicate CxId".to_string(),
            "Rebuild the kernel from a unique member set before publishing its index.",
        ));
    }

    let resolved_vectors = slot_resolver
        .resolve_slot_vectors_at(vault, base_seq, SLOT_CODE_SEMANTIC, &members)
        .map_err(|error| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "resolve persisted S18 member batch at seq {base_seq}: {error}"
                ),
                "Repair the exact S18 primary/manifest/proof context; raw sidecars are never substituted.",
            )
        })?;
    if resolved_vectors.len() != members.len() {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!(
                "S18 resolver returned {} rows for {} kernel members",
                resolved_vectors.len(),
                members.len()
            ),
            "Repair the slot resolver generation before rebuilding the kernel-member index.",
        ));
    }

    let mut member_bindings = Vec::with_capacity(members.len());
    let mut member_symbols = Vec::new();
    let mut missing_vector_members = Vec::new();
    let mut semantic_dim = None;
    for (expected_cx, (cx, vector)) in members.into_iter().zip(resolved_vectors) {
        if expected_cx != cx {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "S18 resolver changed requested order: expected {expected_cx}, returned {cx}"
                ),
                "Repair the slot resolver ordering contract before rebuilding the kernel-member index.",
            ));
        }
        let Some(node) = node_by_cx.get(&cx) else {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_MEMBER_ABSENT,
                format!(
                    "kernel member {cx} has no live symbol in project {project:?}; the member set \
                     is inconsistent with the corpus"
                ),
                "Rebuild the kernel from the current graph so every member is a live symbol, then \
                 rebuild the kernel-member index.",
            ));
        };
        member_bindings.push(KernelMemberBinding {
            cx_id: cx,
            symbol_id: node.atom_id.clone(),
        });
        let Some(vector) = vector else {
            missing_vector_members.push(node.atom_id.clone());
            continue;
        };
        let SlotVector::Dense { dim, data } = vector else {
            if matches!(vector, SlotVector::Absent { .. }) {
                missing_vector_members.push(node.atom_id.clone());
                continue;
            }
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "kernel member {} ({cx}) carries a non-dense, non-Absent S18 row",
                    node.atom_id
                ),
                "Re-index the project with the frozen S18 dense contract; never substitute another slot shape.",
            ));
        };
        match semantic_dim {
            None => semantic_dim = Some(dim),
            Some(expected) if expected != dim => {
                return Err(SearchError::new(
                    ASTRO_KERNEL_INDEX_VAULT,
                    format!(
                        "kernel member {} S18 dimension {dim} differs from generation dimension {expected}",
                        node.atom_id
                    ),
                    "Re-index the project so every S18 vector shares the frozen slot dimension.",
                ));
            }
            Some(_) => {}
        }
        member_symbols.push(CorpusSymbol {
            symbol_id: node.atom_id.clone(),
            qualified_name: node.qualified_name.clone(),
            name: node.name.clone(),
            label: node.label.clone(),
            vectors: BTreeMap::from([(SLOT_CODE_SEMANTIC, data)]),
            sparse_vectors: BTreeMap::new(),
        });
    }
    missing_vector_members.sort();
    let member_symbol_ids = member_bindings
        .iter()
        .map(|binding| binding.symbol_id.clone())
        .collect();

    if member_symbols.is_empty() {
        return Ok(KernelMemberIndex {
            schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
            members_hash: members_hash.to_string(),
            index_kind: KernelIndexKind::MembershipManifestOnly,
            manifest: None,
            hnsw_artifact: None,
            member_bindings,
            knobs,
            member_symbol_ids,
            indexed_member_count: 0,
            missing_vector_members,
            semantic_dim: None,
            base_seq,
        });
    }

    let semantic_dim = semantic_dim.expect("member_symbols is non-empty");
    let declared_vector_slots = BTreeMap::from([(SLOT_CODE_SEMANTIC, semantic_dim)]);
    let vector_rows_read = member_symbols
        .iter()
        .filter(|s| s.vectors.contains_key(&SLOT_CODE_SEMANTIC))
        .count();
    let indexed_member_count = member_symbols.len();

    let filtered = CorpusReadReport {
        symbols: member_symbols,
        symbols_total: indexed_member_count,
        vector_rows_read,
        structural_rows_read: 0,
        absent_slot_rows: 0,
        missing_slot_rows: missing_vector_members.len(),
        non_dense_slot_rows: 0,
        zero_norm_structural_rows: 0,
        declared_vector_slots,
        declared_structural_slots: BTreeMap::new(),
        base_seq,
    };
    let manifest = build_manifest_from_corpus(&filtered, knobs)?;
    let binding_by_symbol: BTreeMap<&str, CxId> = member_bindings
        .iter()
        .map(|binding| (binding.symbol_id.as_str(), binding.cx_id))
        .collect();
    let mut hnsw = HnswIndex::new(SLOT_CODE_SEMANTIC, semantic_dim, knobs.seed);
    for symbol in &filtered.symbols {
        let cx_id = binding_by_symbol
            .get(symbol.symbol_id.as_str())
            .copied()
            .ok_or_else(|| {
                SearchError::new(
                    ASTRO_KERNEL_INDEX_CORRUPT,
                    format!("indexed symbol {} has no CxId binding", symbol.symbol_id),
                    "Rebuild the kernel-member index from the exact kernel generation.",
                )
            })?;
        let vector = symbol.vectors.get(&SLOT_CODE_SEMANTIC).ok_or_else(|| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_CORRUPT,
                format!("indexed symbol {} has no S18 vector", symbol.symbol_id),
                "Rebuild the kernel-member index from complete persisted S18 rows.",
            )
        })?;
        hnsw
            .insert(
                cx_id,
                SlotVector::Dense {
                    dim: semantic_dim,
                    data: vector.clone(),
                },
                base_seq,
            )
            .map_err(|error| {
                SearchError::new(
                    ASTRO_KERNEL_INDEX_CORRUPT,
                    format!(
                        "Calyx HNSW rejected kernel member {} ({cx_id}): {} ({})",
                        symbol.symbol_id, error.message, error.code
                    ),
                    "Repair the persisted S18 vector or kernel identity and rebuild the exact generation.",
                )
            })?;
    }
    let hnsw_artifact = hnsw.to_artifact_bytes().map_err(|error| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_CORRUPT,
            format!(
                "Calyx HNSW artifact serialization failed: {} ({})",
                error.message, error.code
            ),
            "Rebuild the kernel-member index after repairing the HNSW generation.",
        )
    })?;

    Ok(KernelMemberIndex {
        schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
        members_hash: members_hash.to_string(),
        index_kind: KernelIndexKind::EmbeddingBackedHnsw,
        manifest: Some(manifest),
        hnsw_artifact: Some(hnsw_artifact),
        member_bindings,
        knobs,
        member_symbol_ids,
        indexed_member_count,
        missing_vector_members,
        semantic_dim: Some(semantic_dim),
        base_seq,
    })
}

/// Atomically publishes the descriptor, compact identity map, and canonical
/// Calyx HNSW bytes, then re-reads every logical row at the commit snapshot.
pub fn persist_kernel_member_index<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    index: &KernelMemberIndex,
) -> Result<KernelMemberIndexPersistReport, SearchError>
where
    C: Clock,
{
    let bindings_bytes = serde_json::to_vec(&index.member_bindings)
        .map_err(|error| index_corrupt(format!("encode member bindings: {error}")))?;
    let bindings_blake3 = blake3_hex(&bindings_bytes);
    let artifact_blake3 = index.hnsw_artifact.as_deref().map(blake3_hex);
    let descriptor = KernelMemberIndexDescriptor {
        schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
        project: project.to_string(),
        scope_id: scope_id.to_string(),
        members_hash: index.members_hash.clone(),
        index_kind: index.index_kind,
        slot: SLOT_CODE_SEMANTIC,
        semantic_dim: index.semantic_dim,
        base_seq: index.base_seq,
        knobs: index.knobs,
        indexed_member_count: index.indexed_member_count,
        missing_vector_members: index.missing_vector_members.clone(),
        binding_count: index.member_bindings.len(),
        bindings_blake3: bindings_blake3.clone(),
        hnsw_artifact_bytes: index.hnsw_artifact.as_ref().map_or(0, Vec::len),
        hnsw_artifact_blake3: artifact_blake3.clone(),
    };
    // Validate exactly the rows about to be committed, including the Calyx
    // artifact checksum/shape, before mutating the source of truth.
    let _ = loaded_from_parts(
        descriptor.clone(),
        bindings_bytes.clone(),
        index.hnsw_artifact.clone(),
    )?;
    let descriptor_bytes = serde_json::to_vec(&descriptor)
        .map_err(|error| index_corrupt(format!("encode member-index descriptor: {error}")))?;
    let descriptor_blake3 = blake3_hex(&descriptor_bytes);

    let descriptor_key = kernel_member_index_key(project, scope_id, b"descriptor.json");
    let bindings_key = kernel_member_index_key(project, scope_id, b"bindings.json");
    let hnsw_key = kernel_member_index_key(project, scope_id, b"s18.hnsw");
    let hnsw_value = index
        .hnsw_artifact
        .clone()
        .unwrap_or_else(calyx_aster::mvcc::tombstone_value);
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": KERNEL_MEMBER_INDEX_SCHEMA,
        "project": project,
        "scope_id": scope_id,
        "members_hash": index.members_hash,
        "base_seq": index.base_seq,
        "descriptor_blake3": descriptor_blake3,
        "bindings_blake3": bindings_blake3,
        "hnsw_artifact_blake3": artifact_blake3,
    }))
    .map_err(|error| index_corrupt(format!("encode member-index ledger payload: {error}")))?;
    let ledger_subject = SubjectId::Query(
        format!(
            "kernel-member-index:{project}:{scope_id}:{}",
            index.members_hash
        )
        .into_bytes(),
    );
    let ledger_actor = ActorId::Service(KERNEL_MEMBER_INDEX_ACTOR.to_string());
    let commit = vault
        .write_cf_batch_with_ledger_entry_with_row_digests(
            vec![
                (
                    ColumnFamily::Kernel,
                    descriptor_key.clone(),
                    descriptor_bytes.clone(),
                ),
                (
                    ColumnFamily::Kernel,
                    bindings_key.clone(),
                    bindings_bytes.clone(),
                ),
                (ColumnFamily::Kernel, hnsw_key.clone(), hnsw_value),
            ],
            EntryKind::Kernel,
            ledger_subject.clone(),
            payload.clone(),
            ledger_actor.clone(),
        )
        .map_err(|error| {
            index_persist(format!(
                "commit project {project:?} scope {scope_id:?} member index: {error}"
            ))
        })?;
    let commit_seq = commit.seq;
    vault.flush().map_err(|error| {
        index_persist(format!(
            "flush project {project:?} scope {scope_id:?} member index: {error}"
        ))
    })?;

    readback_exact(
        vault,
        commit_seq,
        &descriptor_key,
        &descriptor_bytes,
        "descriptor",
    )?;
    readback_exact(
        vault,
        commit_seq,
        &bindings_key,
        &bindings_bytes,
        "bindings",
    )?;
    let persisted_hnsw = vault
        .read_cf_at(commit_seq, ColumnFamily::Kernel, &hnsw_key)
        .map_err(|error| index_persist(format!("read back HNSW row: {error}")))?;
    match (&index.hnsw_artifact, persisted_hnsw) {
        (Some(expected), Some(actual)) if expected == &actual => {}
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(index_persist(
                "persisted HNSW row differs from the committed artifact bytes",
            ));
        }
        (Some(_), None) => return Err(index_persist("persisted HNSW row is missing")),
        (None, Some(_)) => {
            return Err(index_persist(
                "membership-only generation retained a visible HNSW row",
            ));
        }
    }
    // Decode through the independent read path after the byte comparisons.
    let loaded = read_persisted_kernel_member_index(vault, project, scope_id, &index.members_hash)?
        .ok_or_else(|| index_persist("member index disappeared after committed readback"))?;
    if loaded.descriptor != descriptor || loaded.bindings != index.member_bindings {
        return Err(index_persist(
            "decoded persisted member index differs from the staged generation",
        ));
    }

    // The return value is only a claim: independently point-read and decode the
    // physical Ledger row after flush, then bind its hash and complete payload
    // back to the exact publication transaction.
    let wanted_ledger = BTreeSet::from([commit.ledger_ref.seq]);
    let (physical_ledger, ledger_trace) =
        vault
            .read_physical_ledger_seqs(&wanted_ledger)
            .map_err(|error| {
                index_persist(format!("read physical member-index ledger row: {error}"))
            })?;
    let physical_row = physical_ledger
        .get(&commit.ledger_ref.seq)
        .ok_or_else(|| index_persist("physical member-index ledger row is missing"))?;
    let physical_entry = calyx_ledger::decode(&physical_row.bytes).map_err(|error| {
        index_persist(format!("decode physical member-index ledger row: {error}"))
    })?;
    if physical_row.seq != commit.ledger_ref.seq
        || physical_entry.seq != commit.ledger_ref.seq
        || physical_entry.entry_hash != commit.ledger_ref.hash
        || !physical_entry.verify()
        || physical_entry.kind != EntryKind::Kernel
        || physical_entry.subject != ledger_subject
        || physical_entry.payload != payload
        || physical_entry.actor != ledger_actor
    {
        return Err(index_persist(
            "physical member-index Ledger row does not match its committed ref/kind/subject/payload/actor",
        ));
    }

    Ok(KernelMemberIndexPersistReport {
        descriptor_key,
        bindings_key,
        hnsw_key,
        commit_seq,
        descriptor_blake3,
        bindings_blake3,
        hnsw_artifact_blake3: artifact_blake3,
        ledger_ref: commit.ledger_ref,
        ledger_physical_tiers: ledger_trace
            .tiers
            .into_iter()
            .map(|tier| tier.tier.to_string())
            .collect(),
        rows_readback_verified: 4,
    })
}

/// Reads only the small exact-generation descriptor. A cache hit can prove its
/// generation without rereading or reconstructing the binary HNSW.
pub fn read_persisted_kernel_member_index_descriptor<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    expected_members_hash: &str,
) -> Result<Option<KernelMemberIndexDescriptor>, SearchError>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    read_persisted_kernel_member_index_descriptor_at(
        vault,
        snapshot,
        project,
        scope_id,
        expected_members_hash,
    )
}

fn read_persisted_kernel_member_index_descriptor_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
    expected_members_hash: &str,
) -> Result<Option<KernelMemberIndexDescriptor>, SearchError>
where
    C: Clock,
{
    let descriptor_key = kernel_member_index_key(project, scope_id, b"descriptor.json");
    let Some(bytes) = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &descriptor_key)
        .map_err(|error| index_corrupt(format!("read member-index descriptor: {error}")))?
    else {
        // A subordinate row without its descriptor is an interrupted/corrupt
        // publication, not an absent capability.
        for suffix in [b"bindings.json".as_slice(), b"s18.hnsw".as_slice()] {
            let key = kernel_member_index_key(project, scope_id, suffix);
            if vault
                .read_cf_at(snapshot, ColumnFamily::Kernel, &key)
                .map_err(|error| index_corrupt(format!("probe subordinate index row: {error}")))?
                .is_some()
            {
                return Err(index_corrupt(format!(
                    "project {project:?} scope {scope_id:?} has subordinate member-index state but no descriptor"
                )));
            }
        }
        return Ok(None);
    };
    let descriptor: KernelMemberIndexDescriptor = serde_json::from_slice(&bytes)
        .map_err(|error| index_corrupt(format!("decode member-index descriptor: {error}")))?;
    validate_descriptor(&descriptor, project, scope_id, expected_members_hash)?;
    Ok(Some(descriptor))
}

/// Reads and checksum-validates the complete persisted generation. Call this on
/// a cache miss; cache hits need only the descriptor function above.
pub fn read_persisted_kernel_member_index<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    expected_members_hash: &str,
) -> Result<Option<LoadedKernelMemberIndex>, SearchError>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let Some(descriptor) = read_persisted_kernel_member_index_descriptor_at(
        vault,
        snapshot,
        project,
        scope_id,
        expected_members_hash,
    )?
    else {
        return Ok(None);
    };
    let bindings_key = kernel_member_index_key(project, scope_id, b"bindings.json");
    let bindings = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &bindings_key)
        .map_err(|error| index_corrupt(format!("read member-index bindings: {error}")))?
        .ok_or_else(|| {
            index_corrupt("member-index descriptor exists but bindings row is missing")
        })?;
    let hnsw_key = kernel_member_index_key(project, scope_id, b"s18.hnsw");
    let hnsw = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &hnsw_key)
        .map_err(|error| index_corrupt(format!("read member-index HNSW: {error}")))?;
    loaded_from_parts(descriptor, bindings, hnsw).map(Some)
}

fn loaded_from_parts(
    descriptor: KernelMemberIndexDescriptor,
    bindings_bytes: Vec<u8>,
    hnsw_bytes: Option<Vec<u8>>,
) -> Result<LoadedKernelMemberIndex, SearchError> {
    if blake3_hex(&bindings_bytes) != descriptor.bindings_blake3 {
        return Err(index_corrupt(
            "member-index bindings hash differs from the descriptor",
        ));
    }
    let bindings: Vec<KernelMemberBinding> = serde_json::from_slice(&bindings_bytes)
        .map_err(|error| index_corrupt(format!("decode member-index bindings: {error}")))?;
    if bindings.len() != descriptor.binding_count {
        return Err(index_corrupt(format!(
            "member-index descriptor declares {} bindings but {} decoded",
            descriptor.binding_count,
            bindings.len()
        )));
    }
    let mut seen_cx = BTreeSet::new();
    let mut seen_atoms = BTreeSet::new();
    for binding in &bindings {
        if !seen_cx.insert(binding.cx_id) || !seen_atoms.insert(binding.symbol_id.as_str()) {
            return Err(index_corrupt(
                "member-index bindings contain a duplicate CxId or source atom",
            ));
        }
    }
    let hnsw = match descriptor.index_kind {
        KernelIndexKind::MembershipManifestOnly => {
            if hnsw_bytes.is_some()
                || descriptor.hnsw_artifact_bytes != 0
                || descriptor.hnsw_artifact_blake3.is_some()
                || descriptor.semantic_dim.is_some()
                || descriptor.indexed_member_count != 0
            {
                return Err(index_corrupt(
                    "membership-only descriptor carries HNSW state or indexed members",
                ));
            }
            None
        }
        KernelIndexKind::EmbeddingBackedHnsw => {
            let bytes = hnsw_bytes
                .ok_or_else(|| index_corrupt("embedding-backed descriptor has no HNSW row"))?;
            let expected_hash = descriptor
                .hnsw_artifact_blake3
                .as_deref()
                .ok_or_else(|| index_corrupt("embedding-backed descriptor has no HNSW hash"))?;
            if bytes.len() != descriptor.hnsw_artifact_bytes || blake3_hex(&bytes) != expected_hash
            {
                return Err(index_corrupt(
                    "HNSW artifact length or BLAKE3 differs from the descriptor",
                ));
            }
            let dim = descriptor
                .semantic_dim
                .ok_or_else(|| index_corrupt("embedding-backed descriptor has no dimension"))?;
            let (index, metadata) = HnswIndex::from_artifact_bytes(
                &bytes,
                HnswArtifactExpectation {
                    slot: SLOT_CODE_SEMANTIC,
                    dim,
                    quant_kind: QuantKind::None,
                    quant_geometry_id: [0; 32],
                    base_seq: descriptor.base_seq,
                },
            )
            .map_err(|error| {
                index_corrupt(format!(
                    "Calyx HNSW artifact validation failed: {} ({})",
                    error.message, error.code
                ))
            })?;
            if metadata.live_rows as usize != descriptor.indexed_member_count {
                return Err(index_corrupt(format!(
                    "HNSW has {} live rows but descriptor declares {}",
                    metadata.live_rows, descriptor.indexed_member_count
                )));
            }
            Some(index)
        }
    };
    Ok(LoadedKernelMemberIndex {
        descriptor,
        bindings,
        hnsw,
    })
}

fn validate_descriptor(
    descriptor: &KernelMemberIndexDescriptor,
    project: &str,
    scope_id: &str,
    expected_members_hash: &str,
) -> Result<(), SearchError> {
    if descriptor.schema != KERNEL_MEMBER_INDEX_SCHEMA {
        return Err(index_corrupt(format!(
            "member-index schema {:?} != {:?}",
            descriptor.schema, KERNEL_MEMBER_INDEX_SCHEMA
        )));
    }
    if descriptor.project != project || descriptor.scope_id != scope_id {
        return Err(index_corrupt(format!(
            "member index belongs to project {:?}/scope {:?}, not {project:?}/{scope_id:?}",
            descriptor.project, descriptor.scope_id
        )));
    }
    if descriptor.members_hash != expected_members_hash {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_STALE,
            format!(
                "persisted member-index hash {} differs from current kernel hash {expected_members_hash}",
                descriptor.members_hash
            ),
            "Rebuild the kernel so its exact member index is published before serving a query.",
        ));
    }
    if descriptor.slot != SLOT_CODE_SEMANTIC {
        return Err(index_corrupt(format!(
            "member-index slot {} is not S{}",
            descriptor.slot.get(),
            SLOT_CODE_SEMANTIC.get()
        )));
    }
    Ok(())
}

fn kernel_member_index_key(project: &str, scope_id: &str, suffix: &[u8]) -> Vec<u8> {
    let mut key = KERNEL_MEMBER_INDEX_CF_PREFIX.to_vec();
    append_part(&mut key, project.as_bytes());
    append_part(&mut key, scope_id.as_bytes());
    append_part(&mut key, suffix);
    key
}

fn append_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_be_bytes());
    out.extend_from_slice(part);
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn index_corrupt(message: impl Into<String>) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_INDEX_CORRUPT,
        message.into(),
        "Preserve the vault, inspect the named descriptor/map/HNSW row, and rebuild the exact kernel generation.",
    )
}

fn index_persist(message: impl Into<String>) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_INDEX_PERSIST,
        message.into(),
        "Preserve the vault and rebuild the kernel; publication must commit and read back every member-index row.",
    )
}

fn readback_exact<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    key: &[u8],
    expected: &[u8],
    label: &str,
) -> Result<(), SearchError>
where
    C: Clock,
{
    let actual = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, key)
        .map_err(|error| index_persist(format!("read back {label} row: {error}")))?
        .ok_or_else(|| index_persist(format!("{label} row is missing after commit")))?;
    if actual != expected {
        return Err(index_persist(format!(
            "{label} row differs from the bytes staged for commit"
        )));
    }
    Ok(())
}

/// Serves a symbol-anchored semantic query from a kernel-scoped index.
///
/// Refuses fail-closed when `expected_members_hash` (the caller's current kernel
/// manifest hash) differs from the index's ([`ASTRO_KERNEL_INDEX_STALE`]), or
/// when the index carries no embedding-backed manifest
/// ([`ASTRO_KERNEL_INDEX_ABSENT`]). Otherwise ranks the member subcorpus by S18
/// cosine via [`semantic_more_like_this`] — the anchor excluded — so every
/// neighbor is a kernel member.
pub fn kernel_scoped_semantic_query(
    index: &KernelMemberIndex,
    expected_members_hash: &str,
    anchor_symbol_id: &str,
    k: u64,
    ef: u64,
    caps: &SearchCaps,
) -> Result<SemanticQueryResult, SearchError> {
    if index.members_hash != expected_members_hash {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_STALE,
            format!(
                "kernel-member index members_hash {} does not match the current kernel manifest \
                 members_hash {expected_members_hash}",
                index.members_hash
            ),
            "Rebuild the kernel-member index for the current kernel manifest; its member set \
             changed since this index was built.",
        ));
    }
    let Some(manifest) = &index.manifest else {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_ABSENT,
            format!(
                "kernel-member index for members_hash {} is a labeled {} with no embedding-backed \
                 index",
                index.members_hash,
                index.index_kind.as_str()
            ),
            "Ensure the kernel members carry persisted S18 vectors (re-run index_repository with \
             calyx=\"shadow\"), then rebuild the kernel-member index.",
        ));
    };
    let index_set = SlotIndexSet::from_manifest(manifest)?;
    semantic_more_like_this(
        &index_set,
        anchor_symbol_id,
        &[SLOT_CODE_SEMANTIC],
        k,
        ef,
        caps,
    )
}

/// One kernel member reached by a query, with the rank that selected it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelQueryMatch {
    /// The member's stable source-atom id.
    pub symbol_id: String,
    /// The exact persisted constellation identity ranked by the HNSW row.
    pub cx_id: CxId,
    /// 0-based position in the ranking; 0 is the best match.
    pub rank: u64,
}

/// The result of ranking a kernel's members against a query vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelQueryResult {
    /// The member set this ranking is bound to.
    pub members_hash: String,
    /// The vault sequence the member index was built at.
    pub base_seq: u64,
    /// Members carrying a persisted S18 vector (the rankable population).
    pub indexed_member_count: usize,
    /// The slot the ranking was produced from.
    pub slot: SlotId,
    /// Members reached by the query, best first.
    pub matches: Vec<KernelQueryMatch>,
}

/// Ranks a kernel's members against a **query vector** on the kernel-scoped index.
///
/// This is the text-query counterpart of [`kernel_scoped_semantic_query`], which
/// can only anchor on an already-indexed symbol. It exists so a caller holding a
/// free-text question can resolve it into kernel members through the same frozen
/// S18 space the corpus was measured in, instead of falling back to a
/// query-independent ordering (#880).
///
/// Fail-closed contract, no silent degradation:
/// - [`ASTRO_KERNEL_INDEX_STALE`] when `expected_members_hash` differs from the
///   index's — a ranking against another generation's members is not an answer.
/// - [`ASTRO_KERNEL_INDEX_ABSENT`] when the index carries no embedding-backed
///   manifest.
/// - [`ASTRO_KERNEL_QUERY_UNRESOLVED`] when `query_vector` is empty (the query
///   resolved to no in-vocabulary dimension).
/// - A query/index dimension mismatch is refused by the slot index itself.
///
/// `k` is supplied by the caller and is normally the full indexed member count:
/// the kernel is already the small pre-selected set, so ranking it exhaustively
/// avoids a truncation cap that would silently hide grounded candidates.
pub fn kernel_query_members(
    index: &KernelMemberIndex,
    expected_members_hash: &str,
    query_vector: &[f32],
    k: u64,
    ef: u64,
) -> Result<KernelQueryResult, SearchError> {
    if index.members_hash != expected_members_hash {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_STALE,
            format!(
                "kernel-member index members_hash {} does not match the current kernel manifest \
                 members_hash {expected_members_hash}",
                index.members_hash
            ),
            "Rebuild the kernel-member index for the current kernel manifest; its member set \
             changed since this index was built.",
        ));
    }
    let Some(hnsw_artifact) = &index.hnsw_artifact else {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_ABSENT,
            format!(
                "kernel-member index for members_hash {} is a labeled {} with no embedding-backed \
                 index, so a query cannot reach any member",
                index.members_hash,
                index.index_kind.as_str()
            ),
            "Ensure the kernel members carry persisted S18 vectors (re-run index_repository with \
             calyx=\"shadow\"), then rebuild the kernel-member index.",
        ));
    };
    if query_vector.is_empty() {
        return Err(SearchError::new(
            ASTRO_KERNEL_QUERY_UNRESOLVED,
            "the query resolved to no S18 query vector, so no kernel member can be reached by it"
                .to_string(),
            "Rephrase the query using vocabulary the indexed corpus actually contains; an \
             out-of-vocabulary query is refused rather than answered from an unrelated member.",
        ));
    }

    let bindings_bytes = serde_json::to_vec(&index.member_bindings)
        .map_err(|error| index_corrupt(format!("encode in-memory member bindings: {error}")))?;
    let loaded = loaded_from_parts(
        KernelMemberIndexDescriptor {
            schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
            project: String::new(),
            scope_id: String::new(),
            members_hash: index.members_hash.clone(),
            index_kind: index.index_kind,
            slot: SLOT_CODE_SEMANTIC,
            semantic_dim: index.semantic_dim,
            base_seq: index.base_seq,
            knobs: index.knobs,
            indexed_member_count: index.indexed_member_count,
            missing_vector_members: index.missing_vector_members.clone(),
            binding_count: index.member_bindings.len(),
            bindings_blake3: blake3_hex(&bindings_bytes),
            hnsw_artifact_bytes: hnsw_artifact.len(),
            hnsw_artifact_blake3: Some(blake3_hex(hnsw_artifact)),
        },
        bindings_bytes,
        Some(hnsw_artifact.clone()),
    )?;
    kernel_query_loaded_members(&loaded, expected_members_hash, query_vector, k, ef)
}

/// Ranks a query on a checksum-validated, already-loaded HNSW generation. This is
/// the production hot path: no graph read, slot read, manifest build, or HNSW
/// reconstruction occurs here.
pub fn kernel_query_loaded_members(
    index: &LoadedKernelMemberIndex,
    expected_members_hash: &str,
    query_vector: &[f32],
    k: u64,
    ef: u64,
) -> Result<KernelQueryResult, SearchError> {
    if index.descriptor.members_hash != expected_members_hash {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_STALE,
            format!(
                "loaded member-index hash {} differs from current kernel hash {expected_members_hash}",
                index.descriptor.members_hash
            ),
            "Load the persisted member index for the current kernel generation.",
        ));
    }
    if query_vector.is_empty() {
        return Err(SearchError::new(
            ASTRO_KERNEL_QUERY_UNRESOLVED,
            "the query resolved to no S18 query vector, so no kernel member can be reached by it"
                .to_string(),
            "Rephrase the query using vocabulary the indexed corpus contains.",
        ));
    }
    let hnsw = index.hnsw.as_ref().ok_or_else(|| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_ABSENT,
            format!(
                "member index for hash {} is {} and has no HNSW",
                index.descriptor.members_hash,
                index.descriptor.index_kind.as_str()
            ),
            "Re-index so kernel members carry persisted S18 vectors, then rebuild the kernel.",
        )
    })?;
    let dim = index
        .descriptor
        .semantic_dim
        .ok_or_else(|| index_corrupt("loaded embedding-backed index has no dimension"))?;
    if query_vector.len() != dim as usize {
        return Err(index_corrupt(format!(
            "query S18 dimension {} differs from persisted HNSW dimension {dim}",
            query_vector.len()
        )));
    }
    let hits = hnsw
        .search(
            &SlotVector::Dense {
                dim,
                data: query_vector.to_vec(),
            },
            usize::try_from(k).map_err(|_| index_corrupt("query k does not fit usize"))?,
            Some(usize::try_from(ef).map_err(|_| index_corrupt("query ef does not fit usize"))?),
        )
        .map_err(|error| {
            index_corrupt(format!(
                "Calyx HNSW query failed: {} ({})",
                error.message, error.code
            ))
        })?;
    let atom_by_cx: BTreeMap<CxId, &str> = index
        .bindings
        .iter()
        .map(|binding| (binding.cx_id, binding.symbol_id.as_str()))
        .collect();
    let mut matches = Vec::with_capacity(hits.len());
    for (rank, hit) in hits.into_iter().enumerate() {
        let symbol_id = atom_by_cx.get(&hit.cx_id).ok_or_else(|| {
            index_corrupt(format!(
                "HNSW returned CxId {} absent from its persisted binding map",
                hit.cx_id
            ))
        })?;
        matches.push(KernelQueryMatch {
            symbol_id: (*symbol_id).to_string(),
            cx_id: hit.cx_id,
            rank: rank as u64,
        });
    }
    Ok(KernelQueryResult {
        members_hash: index.descriptor.members_hash.clone(),
        base_seq: index.descriptor.base_seq,
        indexed_member_count: index.descriptor.indexed_member_count,
        slot: SLOT_CODE_SEMANTIC,
        matches,
    })
}

/// Measures recall@`k` of a kernel-scoped index against the full index.
///
/// For each anchor, the gold set is the full index's semantic ranking of the
/// same anchor *restricted to kernel members*, truncated to `k`; the candidate
/// set is the kernel index's own top-`k`. Recall is `|gold ∩ candidate| / |gold|`
/// summed over anchors. Both rank the identical persisted S18 vectors for the
/// members, so an index that covers the members completely recalls at 1000‰; the
/// gate tolerates HNSW approximation down to [`KERNEL_INDEX_RECALL_GATE_PERMILLE`].
pub fn measure_kernel_index_recall(
    full_index: &SlotIndexSet,
    kernel_index: &KernelMemberIndex,
    anchors: &[String],
    k: u64,
    ef: u64,
    caps: &SearchCaps,
) -> Result<KernelRecallMeasurement, SearchError> {
    let members: BTreeSet<&String> = kernel_index.member_symbol_ids.iter().collect();
    let mut recalled = 0u64;
    let mut total = 0u64;
    for anchor in anchors {
        // Full-index ranking of this anchor, restricted to kernel members, top-k.
        let full = semantic_more_like_this(
            full_index,
            anchor,
            &[SLOT_CODE_SEMANTIC],
            caps.max_k,
            ef,
            caps,
        )?;
        let gold: Vec<String> = full
            .neighbors
            .into_iter()
            .map(|result| result.symbol_id)
            .filter(|id| members.contains(id))
            .take(k as usize)
            .collect();
        if gold.is_empty() {
            continue;
        }
        let candidate = kernel_scoped_semantic_query(
            kernel_index,
            &kernel_index.members_hash,
            anchor,
            k,
            ef,
            caps,
        )?;
        let candidate_ids: BTreeSet<String> = candidate
            .neighbors
            .into_iter()
            .map(|result| result.symbol_id)
            .collect();
        total += gold.len() as u64;
        recalled += gold.iter().filter(|id| candidate_ids.contains(*id)).count() as u64;
    }
    let permille = recalled
        .saturating_mul(1000)
        .checked_div(total)
        .unwrap_or(0);
    Ok(KernelRecallMeasurement {
        recalled,
        total,
        permille,
        gated: total > 0 && permille >= KERNEL_INDEX_RECALL_GATE_PERMILLE,
    })
}
