//! Embedding-backed kernel-member search index (#344).
//!
//! The current pipeline publishes `astrolabe.kernel_member_index.v4`: an
//! embedding-backed ANN over the universal S20 name-semantic vectors for the
//! complete kernel-member roster. The descriptor binds the exact member set,
//! S20/Compression source generation, panel identity, and HNSW bytes; a
//! membership-only or partial-vector generation is not a valid index.
//!
//! This module builds that index where the panel vectors live (weave), keyed by
//! the kernel manifest's member set:
//!
//! - [`build_kernel_member_index`] resolves the member `CxId`s to their live
//!   symbols, captures one exact S20 Slot/Compression representation, reads the
//!   complete member roster through that binding, and freezes an HNSW manifest
//!   over every member. One absent or invalid vector refuses the generation;
//!   partial and automatic membership-only indexes are not publishable.
//! - [`kernel_scoped_semantic_query`] serves a symbol-anchored semantic query
//!   from the small index, **refusing fail-closed** when the caller's current
//!   `members_hash` no longer matches the index's ([`ASTRO_KERNEL_INDEX_STALE`])
//!   or when no embedding-backed index is present ([`ASTRO_KERNEL_INDEX_ABSENT`]).
//!   Absence is always labeled, never silently degraded into an empty result.
//! - [`measure_kernel_index_parity`] measures diagnostic top-k agreement between
//!   the kernel-scoped HNSW and the full HNSW restricted to kernel members. Both
//!   sides are approximate indexes, so this is never retrieval-recall or
//!   generation-admission evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use astrolabe_ingest::read_cbm_graph_snapshot_at;
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, CxId, LedgerRef, SlotId, SlotVector};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use calyx_sextant::{HnswArtifactExpectation, HnswIndex, QuantKind, SextantIndex};
use serde::{Deserialize, Serialize};

use crate::search::{SLOT_NAME_SEMANTIC, SearchCaps, SearchError};
use crate::search_index::{IndexKnobs, SlotIndexManifest, SlotIndexSet};
use crate::search_production::{
    CorpusReadReport, CorpusSymbol, SemanticQueryResult, build_manifest_from_corpus,
    semantic_more_like_this,
};
use crate::slot_source::{WeaveSlotBinding, WeaveSlotSource};

/// Schema tag for a kernel-member embedding index descriptor.
pub const KERNEL_MEMBER_INDEX_SCHEMA: &str = "astrolabe.kernel_member_index.v4";
/// Kernel-CF rows holding the exact project/scope member-index generation. The
/// durable row namespace stays at v2 so a validated v4 publication atomically
/// replaces obsolete rows instead of orphaning an unowned legacy generation;
/// the descriptor's schema tag owns decoding semantics.
pub const KERNEL_MEMBER_INDEX_CF_PREFIX: &[u8] = b"astrolabe:kernel-member-index:v2:";
/// Actor sealing descriptor/map/HNSW publication into the Ledger CF.
pub const KERNEL_MEMBER_INDEX_ACTOR: &str = "astrolabe-kernel-member-index";

/// Diagnostic kernel-index parity threshold in permille. This measures whether
/// the member HNSW reproduces the full HNSW's member ranking; it is not an exact
/// full-corpus oracle and cannot admit a kernel generation.
pub const KERNEL_INDEX_PARITY_GATE_PERMILLE: u64 = 950;

/// Fail-closed: a kernel-member index build was requested with no members.
pub const ASTRO_KERNEL_INDEX_NO_MEMBERS: &str = "ASTRO_KERNEL_INDEX_NO_MEMBERS";
/// Fail-closed: a kernel-scoped text query carried no usable query vector, so
/// there is nothing to rank the members against. Never degraded into "rank
/// everything by global weight" — that would answer a question nobody asked.
pub const ASTRO_KERNEL_QUERY_UNRESOLVED: &str = "ASTRO_KERNEL_QUERY_UNRESOLVED";
/// Fail-closed: a kernel member `CxId` has no live symbol in the graph snapshot,
/// so the member set is inconsistent with the corpus the index serves.
pub const ASTRO_KERNEL_INDEX_MEMBER_ABSENT: &str = "ASTRO_KERNEL_INDEX_MEMBER_ABSENT";
/// Fail-closed: at least one live kernel member has no valid dense S20 row.
pub const ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE: &str = "ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE";
/// Fail-closed: the Slot or Compression representation moved after the build
/// captured its exact S20 source binding.
pub const ASTRO_KERNEL_INDEX_SOURCE_CHANGED: &str = "ASTRO_KERNEL_INDEX_SOURCE_CHANGED";
/// Fail-closed: reading the graph snapshot for member resolution failed.
pub const ASTRO_KERNEL_INDEX_VAULT: &str = "ASTRO_KERNEL_INDEX_VAULT";
/// Fail-closed: the served index's `members_hash` no longer matches the caller's
/// current kernel manifest `members_hash` — the member set moved, so the index
/// is stale and must be rebuilt (never served against a changed kernel).
pub const ASTRO_KERNEL_INDEX_STALE: &str = "ASTRO_KERNEL_INDEX_STALE";
/// Fail-closed: no embedding-backed index is present (the kernel members carry
/// no persisted S20 vectors); the index is a labeled membership manifest and a
/// semantic query must refuse rather than silently return nothing.
pub const ASTRO_KERNEL_INDEX_ABSENT: &str = "ASTRO_KERNEL_INDEX_ABSENT";
/// Fail-closed: persisted descriptor/map/HNSW rows are missing or disagree.
pub const ASTRO_KERNEL_INDEX_CORRUPT: &str = "ASTRO_KERNEL_INDEX_CORRUPT";
/// Fail-closed: a kernel-member index could not be persisted and read back.
pub const ASTRO_KERNEL_INDEX_PERSIST: &str = "ASTRO_KERNEL_INDEX_PERSIST";
/// Fail-closed: a diagnostic parity counter or fixed-point ratio is not
/// representable, so the measurement cannot be published honestly.
pub const ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW: &str = "ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW";

/// Kernel-member index representation. `MembershipManifestOnly` remains only
/// to decode and explicitly refuse obsolete pre-v4 state; new generations are
/// always complete embedding-backed indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelIndexKind {
    /// An HNSW index over the members' persisted S20 name-semantic vectors.
    EmbeddingBackedHnsw,
    /// Obsolete pre-v4 membership manifest. Never constructed or published by
    /// the current builder and always refused by the v4 reader.
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
    /// Exact source graph/panel version whose universal S20 contract produced
    /// the member and external-query vector space.
    pub panel_version: u32,
    pub base_seq: u64,
    /// Current-latest sequence at which `source_binding` was captured.
    pub source_binding_seq: u64,
    /// Current-latest sequence of the final pre-publication source check.
    pub source_final_verification_seq: u64,
    /// Exact Slot/Compression representation used for every member vector.
    pub source_binding: WeaveSlotBinding,
    pub knobs: IndexKnobs,
    /// Complete live member population represented by this generation.
    pub member_count: usize,
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
    pub member_count: usize,
    pub source_binding_seq: u64,
    pub source_final_verification_seq: u64,
    pub source_binding: WeaveSlotBinding,
    pub ledger_ref: LedgerRef,
    pub ledger_physical_tiers: Vec<String>,
    pub rows_readback_verified: usize,
}

/// Mutation-free canonical row preparation for one complete member index.
///
/// The composite generation publisher owns persistence. This object contains
/// the exact descriptor/map/HNSW values plus the existing fixed alias keys so
/// all eight composite kernel-generation values can enter one ledger-bound commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedKernelMemberIndexRows {
    pub descriptor: KernelMemberIndexDescriptor,
    pub descriptor_bytes: Vec<u8>,
    pub bindings_bytes: Vec<u8>,
    pub hnsw_bytes: Vec<u8>,
    pub fixed_descriptor_key: Vec<u8>,
    pub fixed_bindings_key: Vec<u8>,
    pub fixed_hnsw_key: Vec<u8>,
}

/// Exact read-only verification of one persisted descriptor's S20 source.
///
/// A serving cache records this once for each newly loaded descriptor. Warm
/// requests still read the descriptor and compare the cheap Slot/Compression
/// content generations; a changed generation produces a different/refused
/// descriptor before the cached HNSW can be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelMemberIndexSourceVerification {
    pub read_snapshot_seq: u64,
    pub source_binding_seq: u64,
    pub source_final_verification_seq: u64,
    pub source_binding: WeaveSlotBinding,
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
    /// Complete live member population required in both bindings and HNSW.
    pub member_count: usize,
    /// Members that carried a persisted S20 vector and are in the index.
    pub indexed_member_count: usize,
    /// Must be empty. Retained in the descriptor so corrupt/obsolete partial
    /// generations carry their exact rejected roster in diagnostics.
    pub missing_vector_members: Vec<String>,
    /// S20 vector dimension of the index, when embedding-backed.
    pub semantic_dim: Option<u32>,
    /// Exact source graph/panel version that owns the S20 encoder contract.
    pub panel_version: u32,
    /// Vault sequence the member corpus was read at (freshness base).
    pub base_seq: u64,
    /// Current-latest sequence at which `source_binding` was captured.
    pub source_binding_seq: u64,
    /// Current-latest sequence of the final completed-build source check.
    pub source_final_verification_seq: u64,
    /// Exact S20 Slot/Compression representation bracketed around the build.
    pub source_binding: WeaveSlotBinding,
}

/// Diagnostic top-k agreement between the small HNSW and the full HNSW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelIndexParityMeasurement {
    /// Member results shared by the two approximate rankings.
    pub matching: u64,
    /// Total member results in the full HNSW's reference ranking.
    pub total: u64,
    /// `matching / total` in permille.
    pub permille: u64,
    /// Whether the diagnostic reaches [`KERNEL_INDEX_PARITY_GATE_PERMILLE`].
    /// This flag is not a generation-admission decision.
    pub gated: bool,
}

/// Builds an embedding-backed kernel-member index over S20 for the kernel
/// manifest's member set, content-addressed by `members_hash`.
///
/// Resolves each member `CxId` to its stable source-atom id via the graph snapshot
/// (fail-closed [`ASTRO_KERNEL_INDEX_MEMBER_ABSENT`] if a member is not a live
/// symbol), captures one exact S20 Slot/Compression binding, resolves the whole
/// roster through that binding, and freezes an HNSW manifest over every member.
/// Any absent, malformed, wrong-shape, zero, or dimension-inconsistent member
/// vector refuses before an index generation can be returned.
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
    let snapshot = vault.latest_seq();
    build_kernel_member_index_at(
        vault,
        vault_dir,
        project,
        member_cx_ids,
        members_hash,
        knobs,
        snapshot,
    )
}

/// Builds a complete member index from one explicitly captured current
/// snapshot. The function performs no mutation and refuses if the vault moves
/// before or during graph/S20 resolution or HNSW construction.
pub fn build_kernel_member_index_at<C>(
    vault: &AsterVault<C>,
    vault_dir: &Path,
    project: &str,
    member_cx_ids: &[CxId],
    members_hash: &str,
    knobs: IndexKnobs,
    base_seq: u64,
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

    // One explicit latest generation for both identity and member vectors.
    // Graph reconstruction is a publication-time cost only; the persisted
    // binding map removes it entirely from the serving path (#996).
    if vault.latest_seq() != base_seq {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_SOURCE_CHANGED,
            format!(
                "member-index build expected captured seq {base_seq}, observed latest seq {}; no index bytes were prepared",
                vault.latest_seq()
            ),
            "Re-read the graph, anchors, and S20 representation from one new exact snapshot before rebuilding the complete generation.",
        ));
    }
    let snapshot = read_cbm_graph_snapshot_at(vault, project, base_seq).map_err(|error| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!("read graph snapshot for project {project:?}: {error}"),
            "Re-run index_repository with calyx=\"shadow\" so the vault holds a current graph \
             snapshot before building the kernel-member index.",
        )
    })?;
    let panel_version = snapshot.panel_version.ok_or_else(|| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!("graph snapshot for project {project:?} has no persisted panel_version"),
            "Re-index the project with one explicit panel version before publishing a complete kernel generation.",
        )
    })?;
    let slot_source = WeaveSlotSource::open(base_seq, Some(vault_dir), Some(panel_version))
        .map_err(|error| source_binding_error("open S20 interpretation source", &error))?;
    let source_binding = slot_source
        .bind_latest_at(vault, base_seq, SLOT_NAME_SEMANTIC)
        .map_err(|error| source_binding_error("capture S20 source binding", &error))?;
    let mut node_by_cx = BTreeMap::new();
    let mut atom_to_cx = BTreeMap::new();
    for node in snapshot.nodes {
        let Some(cx_id) = node.cx_id else {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "live graph node {:?} in project {project:?} has no CxId",
                    node.qualified_name
                ),
                "Re-index the project so every live symbol and structural graph node has one exact CxId.",
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

    let resolved_vectors = slot_source
        .resolve_many_bound_at(vault, base_seq, &source_binding, &members)
        .map_err(|error| {
            source_binding_error(
                &format!("resolve complete persisted S20 member batch at seq {base_seq}"),
                &error,
            )
        })?;
    if resolved_vectors.len() != members.len() {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!(
                "S20 resolver returned {} rows for {} kernel members",
                resolved_vectors.len(),
                members.len()
            ),
            "Repair the slot resolver generation before rebuilding the kernel-member index.",
        ));
    }

    let mut member_bindings = Vec::with_capacity(members.len());
    let mut member_symbols = Vec::with_capacity(members.len());
    let mut missing_vector_members = Vec::new();
    let mut invalid_vector_roster = Vec::new();
    let mut semantic_dim = None;
    for (expected_cx, (cx, vector)) in members.into_iter().zip(resolved_vectors) {
        if expected_cx != cx {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VAULT,
                format!(
                    "S20 resolver changed requested order: expected {expected_cx}, returned {cx}"
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
            invalid_vector_roster.push(format!(
                "cx_id={cx}, symbol_id={:?}, reason=missing_s20_row",
                node.atom_id
            ));
            continue;
        };
        if let Err(error) = vector.validate_schema() {
            missing_vector_members.push(node.atom_id.clone());
            invalid_vector_roster.push(format!(
                "cx_id={cx}, symbol_id={:?}, reason=invalid_schema, calyx_code={}, detail={:?}",
                node.atom_id, error.code, error.message
            ));
            continue;
        }
        let SlotVector::Dense { dim, data } = vector else {
            missing_vector_members.push(node.atom_id.clone());
            let reason = match vector {
                SlotVector::Absent { reason } => format!("absent:{reason:?}"),
                SlotVector::Sparse { .. } => "wrong_shape:sparse".to_string(),
                SlotVector::Multi { .. } => "wrong_shape:multi".to_string(),
                SlotVector::Dense { .. } => "internal_dense_pattern_mismatch".to_string(),
            };
            invalid_vector_roster.push(format!(
                "cx_id={cx}, symbol_id={:?}, reason={reason}",
                node.atom_id
            ));
            continue;
        };
        if data.iter().all(|value| *value == 0.0) {
            missing_vector_members.push(node.atom_id.clone());
            invalid_vector_roster.push(format!(
                "cx_id={cx}, symbol_id={:?}, reason=zero_s20_vector",
                node.atom_id
            ));
            continue;
        }
        match semantic_dim {
            None => semantic_dim = Some(dim),
            Some(expected) if expected != dim => {
                missing_vector_members.push(node.atom_id.clone());
                invalid_vector_roster.push(format!(
                    "cx_id={cx}, symbol_id={:?}, reason=dimension_mismatch:{dim}!={expected}",
                    node.atom_id
                ));
                continue;
            }
            Some(_) => {}
        }
        member_symbols.push(CorpusSymbol {
            symbol_id: node.atom_id.clone(),
            qualified_name: node.qualified_name.clone(),
            name: node.name.clone(),
            label: node.label.clone(),
            vectors: BTreeMap::from([(SLOT_NAME_SEMANTIC, data)]),
            sparse_vectors: BTreeMap::new(),
        });
    }
    missing_vector_members.sort();
    invalid_vector_roster.sort();
    if !invalid_vector_roster.is_empty() {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
            format!(
                "kernel-member S20 coverage is incomplete: member_count={}, invalid_or_missing_count={}, exact_roster={invalid_vector_roster:?}; no descriptor, binding map, HNSW row, or current generation was published",
                member_bindings.len(),
                invalid_vector_roster.len(),
            ),
            "Re-run index_repository with calyx=\"shadow\", verify one valid dense S20 row for every named CxId/source atom, then rebuild the same kernel generation; never substitute another slot or publish a partial member roster.",
        ));
    }
    let mut member_symbol_ids = member_bindings
        .iter()
        .map(|binding| binding.symbol_id.clone())
        .collect::<Vec<_>>();
    member_symbol_ids.sort();

    let semantic_dim = semantic_dim.ok_or_else(|| {
        index_corrupt("complete non-empty S20 roster did not establish a semantic dimension")
    })?;
    let member_count = member_bindings.len();
    let declared_vector_slots = BTreeMap::from([(SLOT_NAME_SEMANTIC, semantic_dim)]);
    let vector_rows_read = member_symbols
        .iter()
        .filter(|s| s.vectors.contains_key(&SLOT_NAME_SEMANTIC))
        .count();
    let indexed_member_count = member_symbols.len();
    if member_count != indexed_member_count || member_count != vector_rows_read {
        return Err(index_corrupt(format!(
            "complete S20 roster changed before HNSW construction: member_count={member_count}, indexed_member_count={indexed_member_count}, vector_rows_read={vector_rows_read}"
        )));
    }

    let filtered = CorpusReadReport {
        symbols: member_symbols,
        symbols_total: indexed_member_count,
        vector_rows_read,
        structural_rows_read: 0,
        absent_slot_rows: 0,
        missing_slot_rows: 0,
        non_dense_slot_rows: 0,
        zero_norm_structural_rows: 0,
        declared_vector_slots,
        declared_structural_slots: BTreeMap::new(),
        base_seq,
    };
    let manifest = build_manifest_from_corpus(&filtered, knobs)?;
    let manifest_symbol_ids = manifest
        .documents
        .iter()
        .map(|document| document.symbol_id.clone())
        .collect::<Vec<_>>();
    if manifest_symbol_ids != member_symbol_ids {
        return Err(index_corrupt(format!(
            "S20 manifest roster differs from the complete bound member roster: member_count={member_count}, manifest_count={}, expected_symbol_ids={member_symbol_ids:?}, observed_symbol_ids={manifest_symbol_ids:?}",
            manifest_symbol_ids.len(),
        )));
    }
    let binding_by_symbol: BTreeMap<&str, CxId> = member_bindings
        .iter()
        .map(|binding| (binding.symbol_id.as_str(), binding.cx_id))
        .collect();
    let mut hnsw = HnswIndex::new(SLOT_NAME_SEMANTIC, semantic_dim, knobs.seed);
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
        let vector = symbol.vectors.get(&SLOT_NAME_SEMANTIC).ok_or_else(|| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_CORRUPT,
                format!("indexed symbol {} has no S20 vector", symbol.symbol_id),
                "Rebuild the kernel-member index from complete persisted S20 rows.",
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
                    "Repair the persisted S20 vector or kernel identity and rebuild the exact generation.",
                )
            })?;
    }
    if hnsw.total_nodes() != member_count || hnsw.live_len() != member_count {
        return Err(index_corrupt(format!(
            "Calyx HNSW construction is incomplete: member_count={member_count}, total_rows={}, live_rows={}",
            hnsw.total_nodes(),
            hnsw.live_len(),
        )));
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
    slot_source
        .verify_latest_binding_at(vault, base_seq, &source_binding)
        .map_err(|error| {
            source_binding_error(
                "final S20 source verification after HNSW construction",
                &error,
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
        member_count,
        indexed_member_count,
        missing_vector_members,
        semantic_dim: Some(semantic_dim),
        panel_version,
        base_seq,
        source_binding_seq: base_seq,
        source_final_verification_seq: base_seq,
        source_binding,
    })
}

/// Reads the complete graph-node S20 roster through the exact representation
/// already captured by the member-index build. This is the authoritative vector
/// input for graph-routed admission's exhaustive comparator; it performs no
/// mutation and refuses one missing, extra, malformed, zero, or drifted row.
///
/// # Cost contract (#1064)
///
/// For caller-supplied complete graph size `N` and semantic dimension `D`, this
/// performs one bound batch resolution and validation in `O(N*D)` time and
/// `O(N*D)` returned space. The ascending graph identity roster, captured MVCC
/// sequence, S20 Slot/Compression binding, panel version, and dimension are
/// invariant across the pass (PC-03/04/07/14/15/28/35/37/41/43).
pub fn read_complete_kernel_s20_vectors_at<C>(
    vault: &AsterVault<C>,
    vault_dir: &Path,
    panel_version: u32,
    graph_node_ids: &[CxId],
    expected_binding: &WeaveSlotBinding,
    expected_dimension: u32,
    base_seq: u64,
) -> Result<BTreeMap<CxId, Vec<f32>>, SearchError>
where
    C: Clock,
{
    if graph_node_ids.is_empty()
        || !graph_node_ids.windows(2).all(|pair| pair[0] < pair[1])
        || expected_binding.slot != SLOT_NAME_SEMANTIC
        || panel_version == 0
        || expected_dimension == 0
    {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
            format!(
                "complete S20 read requires a nonempty strictly ascending graph roster, S20 binding, panel version, and positive dimension: node_count={} strict_order={} binding_slot={} panel_version={panel_version} expected_dimension={expected_dimension}",
                graph_node_ids.len(),
                graph_node_ids.windows(2).all(|pair| pair[0] < pair[1]),
                expected_binding.slot.get()
            ),
            "Re-read the exact KernelGraph projection roster and rebuild the complete member index at one new captured sequence before graph-routed admission.",
        ));
    }
    if vault.latest_seq() != base_seq {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_SOURCE_CHANGED,
            format!(
                "complete S20 read expected captured seq {base_seq}, observed latest seq {}",
                vault.latest_seq()
            ),
            "Discard the staged artifact/index/report and restart from one fresh current snapshot.",
        ));
    }
    let source = WeaveSlotSource::open(base_seq, Some(vault_dir), Some(panel_version))
        .map_err(|error| source_binding_error("open complete S20 interpretation source", &error))?;
    let resolved = source
        .resolve_many_bound_at(vault, base_seq, expected_binding, graph_node_ids)
        .map_err(|error| {
            source_binding_error(
                &format!(
                    "resolve complete graph S20 batch at seq {base_seq} through captured binding"
                ),
                &error,
            )
        })?;
    if resolved.len() != graph_node_ids.len() {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
            format!(
                "complete S20 resolver returned {} rows for {} graph nodes",
                resolved.len(),
                graph_node_ids.len()
            ),
            "Repair the exact S20 source generation; every graph node must resolve once before recall admission.",
        ));
    }
    let mut vectors = BTreeMap::new();
    for (&expected_cx, (observed_cx, vector)) in graph_node_ids.iter().zip(resolved) {
        if expected_cx != observed_cx {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
                format!(
                    "complete S20 resolver changed roster order: expected {expected_cx}, observed {observed_cx}"
                ),
                "Repair the slot resolver ordering contract before graph-routed admission.",
            ));
        }
        let vector = vector.ok_or_else(|| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
                format!("complete graph node {expected_cx} has no persisted S20 row"),
                "Re-index the exact source so every graph node has one persisted production S20 vector.",
            )
        })?;
        vector.validate_schema().map_err(|error| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
                format!(
                    "complete graph node {expected_cx} has invalid S20 schema: code={} message={:?}",
                    error.code, error.message
                ),
                "Repair the named persisted S20 row; malformed vectors cannot enter the exact comparator.",
            )
        })?;
        let SlotVector::Dense { dim, data } = vector else {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
                format!(
                    "complete graph node {expected_cx} expected dense S20, observed absent/sparse/multi"
                ),
                "Re-index the named graph node with the production dense S20 lens.",
            ));
        };
        if dim != expected_dimension
            || data.len() != expected_dimension as usize
            || data.iter().any(|value| !value.is_finite())
            || !data.iter().any(|value| *value != 0.0)
        {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
                format!(
                    "complete graph node {expected_cx} S20 invalid: expected_dim={expected_dimension} observed_dim={dim} observed_len={} finite={} nonzero={}",
                    data.len(),
                    data.iter().all(|value| value.is_finite()),
                    data.iter().any(|value| *value != 0.0)
                ),
                "Repair the named persisted production S20 row and restart admission from one new snapshot.",
            ));
        }
        if vectors.insert(expected_cx, data).is_some() {
            return Err(SearchError::new(
                ASTRO_KERNEL_INDEX_VECTOR_INCOMPLETE,
                format!("complete S20 roster duplicated graph node {expected_cx}"),
                "Repair the graph identity roster before graph-routed admission.",
            ));
        }
    }
    source
        .verify_latest_binding_at(vault, base_seq, expected_binding)
        .map_err(|error| source_binding_error("final complete S20 source verification", &error))?;
    if vectors.len() != graph_node_ids.len() || vault.latest_seq() != base_seq {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_SOURCE_CHANGED,
            format!(
                "complete S20 readback mismatch: expected_nodes={} observed_vectors={} expected_seq={base_seq} observed_seq={}",
                graph_node_ids.len(),
                vectors.len(),
                vault.latest_seq()
            ),
            "Discard every staged byte and restart from one fresh graph/S20 snapshot.",
        ));
    }
    Ok(vectors)
}

fn validate_built_index(index: &KernelMemberIndex) -> Result<(), SearchError> {
    if index.schema != KERNEL_MEMBER_INDEX_SCHEMA {
        return Err(index_corrupt(format!(
            "in-memory member-index schema {:?} != {:?}",
            index.schema, KERNEL_MEMBER_INDEX_SCHEMA
        )));
    }
    if index.index_kind != KernelIndexKind::EmbeddingBackedHnsw {
        return Err(index_corrupt(format!(
            "kernel-member publication requires embedding_backed_hnsw, observed {}",
            index.index_kind.as_str()
        )));
    }
    validate_source_binding_shape(&index.source_binding)?;
    if index.source_binding_seq != index.base_seq
        || index.source_final_verification_seq != index.base_seq
        || index.source_binding.slot_cf_generation > index.source_binding_seq
        || index.source_binding.compression_cf_generation > index.source_binding_seq
    {
        return Err(index_corrupt(format!(
            "completed in-memory build has inconsistent source epochs: base_seq={}, source_binding_seq={}, source_final_verification_seq={}, slot_generation={}, compression_generation={}",
            index.base_seq,
            index.source_binding_seq,
            index.source_final_verification_seq,
            index.source_binding.slot_cf_generation,
            index.source_binding.compression_cf_generation,
        )));
    }
    if index.member_count == 0 {
        return Err(index_corrupt(
            "kernel-member publication has a zero member_count",
        ));
    }
    if index.panel_version == 0 {
        return Err(index_corrupt(
            "kernel-member publication has no source panel version",
        ));
    }
    if !index.missing_vector_members.is_empty() {
        return Err(index_corrupt(format!(
            "kernel-member publication carries {} missing S20 members: {:?}",
            index.missing_vector_members.len(),
            index.missing_vector_members
        )));
    }
    if index.member_count != index.member_bindings.len()
        || index.member_count != index.indexed_member_count
    {
        return Err(index_corrupt(format!(
            "kernel-member population is incomplete: member_count={}, binding_count={}, indexed_member_count={}",
            index.member_count,
            index.member_bindings.len(),
            index.indexed_member_count
        )));
    }
    let mut prior_cx = None;
    let mut binding_symbols = BTreeSet::new();
    for binding in &index.member_bindings {
        if prior_cx.is_some_and(|prior| prior >= binding.cx_id) {
            return Err(index_corrupt(
                "kernel-member bindings are not in strict ascending CxId order",
            ));
        }
        prior_cx = Some(binding.cx_id);
        if !binding_symbols.insert(binding.symbol_id.clone()) {
            return Err(index_corrupt(format!(
                "kernel-member bindings repeat source atom {:?}",
                binding.symbol_id
            )));
        }
    }
    let sorted_binding_symbols = binding_symbols.into_iter().collect::<Vec<_>>();
    if index.member_symbol_ids != sorted_binding_symbols {
        return Err(index_corrupt(format!(
            "member_symbol_ids do not equal the sorted complete binding roster: expected={sorted_binding_symbols:?}, observed={:?}",
            index.member_symbol_ids
        )));
    }
    let manifest = index
        .manifest
        .as_ref()
        .ok_or_else(|| index_corrupt("embedding-backed member index has no manifest"))?;
    if manifest.base_seq != index.base_seq || manifest.knobs != index.knobs {
        return Err(index_corrupt(format!(
            "member-index manifest generation/knobs differ from its build: manifest_base_seq={}, index_base_seq={}, manifest_knobs={:?}, index_knobs={:?}",
            manifest.base_seq, index.base_seq, manifest.knobs, index.knobs
        )));
    }
    let manifest_symbols = manifest
        .documents
        .iter()
        .map(|document| document.symbol_id.clone())
        .collect::<Vec<_>>();
    if manifest_symbols != index.member_symbol_ids {
        return Err(index_corrupt(format!(
            "member-index manifest does not equal the complete binding roster: expected={:?}, observed={manifest_symbols:?}",
            index.member_symbol_ids
        )));
    }
    if manifest.documents.iter().any(|document| {
        document.slots.len() != 1 || !document.slots.contains_key(&SLOT_NAME_SEMANTIC)
    }) {
        return Err(index_corrupt(
            "member-index manifest has a document without exactly one S20 vector",
        ));
    }
    if index.semantic_dim.is_none() || index.hnsw_artifact.is_none() {
        return Err(index_corrupt(
            "embedding-backed member index lacks its semantic dimension or HNSW artifact",
        ));
    }
    if let Some(identity) = &index.source_binding.compressed_generation_identity
        && (index.semantic_dim != Some(identity.raw_dim)
            || (identity.row_count as usize) < index.member_count)
    {
        return Err(index_corrupt(format!(
            "member-index semantic dimension/population differs from compressed S20 identity: semantic_dim={:?}, compressed_raw_dim={}, member_count={}, compressed_row_count={}",
            index.semantic_dim, identity.raw_dim, index.member_count, identity.row_count
        )));
    }
    Ok(())
}

fn validate_source_binding_shape(binding: &WeaveSlotBinding) -> Result<(), SearchError> {
    if binding.slot != SLOT_NAME_SEMANTIC {
        return Err(index_corrupt(format!(
            "member-index source binding names S{}, expected S{}",
            binding.slot.get(),
            SLOT_NAME_SEMANTIC.get()
        )));
    }
    if let Some(identity) = &binding.compressed_generation_identity {
        if identity.slot_id != SLOT_NAME_SEMANTIC.get()
            || identity.raw_dim == 0
            || identity.stored_dim == 0
            || identity.row_count == 0
        {
            return Err(index_corrupt(format!(
                "compressed generation identity has invalid slot/dimensions/population: slot={}, raw_dim={}, stored_dim={}, row_count={}",
                identity.slot_id, identity.raw_dim, identity.stored_dim, identity.row_count
            )));
        }
        for (label, hash) in [
            (
                "codec_context_sha256",
                identity.codec_context_sha256.as_str(),
            ),
            ("generation_sha256", identity.generation_sha256.as_str()),
            (
                "raw_generation_sha256",
                identity.raw_generation_sha256.as_str(),
            ),
            ("membership_sha256", identity.membership_sha256.as_str()),
        ] {
            require_lower_sha256(label, hash)?;
        }
        if let Some(hash) = identity.assay_attestation_sha256.as_deref() {
            require_lower_sha256("assay_attestation_sha256", hash)?;
        }
    }
    Ok(())
}

fn require_lower_sha256(label: &str, value: &str) -> Result<(), SearchError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(index_corrupt(format!(
            "compressed generation {label} is not 64 lowercase hexadecimal characters: {value:?}"
        )));
    }
    Ok(())
}

fn source_binding_error(context: &str, error: &CalyxError) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_INDEX_SOURCE_CHANGED,
        format!(
            "{context}: underlying_code={}, underlying_message={:?}, underlying_remediation={:?}",
            error.code, error.message, error.remediation
        ),
        "Preserve the prior kernel generation, identify the exact S20 Slot/Compression writer or persisted Registry-context fault, and rebuild only after one complete stable source representation can be captured and re-read.",
    )
}

pub(crate) fn verify_source_binding_generations_at<C>(
    vault: &AsterVault<C>,
    expected_seq: u64,
    binding: &WeaveSlotBinding,
    phase: &str,
) -> Result<(), SearchError>
where
    C: Clock,
{
    validate_source_binding_shape(binding)?;
    let latest_before = vault.latest_seq();
    let slot_generation = vault
        .cf_content_generation(ColumnFamily::slot(binding.slot))
        .map_err(|error| source_binding_error(phase, &error))?;
    let compression_generation = vault
        .cf_content_generation(ColumnFamily::Compression)
        .map_err(|error| source_binding_error(phase, &error))?;
    let latest_after = vault.latest_seq();
    if latest_before != expected_seq
        || latest_after != expected_seq
        || slot_generation != binding.slot_cf_generation
        || compression_generation != binding.compression_cf_generation
    {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_SOURCE_CHANGED,
            format!(
                "{phase}: expected_seq={expected_seq}, observed_seq_before={latest_before}, observed_seq_after={latest_after}, expected_slot_generation={}, observed_slot_generation={slot_generation}, expected_compression_generation={}, observed_compression_generation={compression_generation}, expected_compressed_identity={:?}",
                binding.slot_cf_generation,
                binding.compression_cf_generation,
                binding.compressed_generation_identity,
            ),
            "Preserve the prior kernel generation and rebuild from one newly captured complete S20 Slot/Compression representation; never reuse the staged HNSW across this identity change.",
        ));
    }
    Ok(())
}

/// Atomically publishes the descriptor, compact identity map, and canonical
/// Calyx HNSW bytes, then re-reads every logical row at the commit snapshot.
///
/// New production kernel generations use the composite publisher in
/// `kernel_generation`; this standalone primitive remains for explicit
/// compatibility migrations and cannot publish a composite current pointer.
pub fn prepare_kernel_member_index_rows<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    index: &KernelMemberIndex,
    publication_seq: u64,
) -> Result<PreparedKernelMemberIndexRows, SearchError>
where
    C: Clock,
{
    validate_built_index(index)?;
    if index.base_seq > publication_seq {
        return Err(SearchError::new(
            ASTRO_KERNEL_INDEX_SOURCE_CHANGED,
            format!(
                "member-index preparation at publication seq {publication_seq} cannot consume a future completed index built at seq {}; no rows were prepared",
                index.base_seq
            ),
            "Discard the staged index and rebuild the artifact and complete S20 index from one current snapshot.",
        ));
    }
    // `base_seq` truthfully remains the HNSW build epoch embedded in its
    // canonical artifact. A later publication is admitted only after the exact
    // Slot/Compression generations are re-read below; unrelated Graph/Kv
    // transactions therefore do not force a second K*D build, while any vector
    // source change still refuses.
    verify_source_binding_generations_at(
        vault,
        publication_seq,
        &index.source_binding,
        "before member-index row preparation",
    )?;
    let bindings_bytes = serde_json::to_vec(&index.member_bindings)
        .map_err(|error| index_corrupt(format!("encode member bindings: {error}")))?;
    let bindings_blake3 = blake3_hex(&bindings_bytes);
    let hnsw_bytes = index
        .hnsw_artifact
        .clone()
        .ok_or_else(|| index_corrupt("complete member index has no HNSW artifact"))?;
    let artifact_blake3 = blake3_hex(&hnsw_bytes);
    let descriptor = KernelMemberIndexDescriptor {
        schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
        project: project.to_string(),
        scope_id: scope_id.to_string(),
        members_hash: index.members_hash.clone(),
        index_kind: index.index_kind,
        slot: SLOT_NAME_SEMANTIC,
        semantic_dim: index.semantic_dim,
        panel_version: index.panel_version,
        base_seq: index.base_seq,
        source_binding_seq: index.source_binding_seq,
        source_final_verification_seq: publication_seq,
        source_binding: index.source_binding.clone(),
        knobs: index.knobs,
        member_count: index.member_count,
        indexed_member_count: index.indexed_member_count,
        missing_vector_members: index.missing_vector_members.clone(),
        binding_count: index.member_bindings.len(),
        bindings_blake3,
        hnsw_artifact_bytes: hnsw_bytes.len(),
        hnsw_artifact_blake3: Some(artifact_blake3),
    };
    validate_descriptor(
        &descriptor,
        publication_seq,
        project,
        scope_id,
        &index.members_hash,
    )?;
    let _ = loaded_from_parts(
        descriptor.clone(),
        bindings_bytes.clone(),
        Some(hnsw_bytes.clone()),
    )?;
    let descriptor_bytes = serde_json::to_vec(&descriptor)
        .map_err(|error| index_corrupt(format!("encode member-index descriptor: {error}")))?;
    Ok(PreparedKernelMemberIndexRows {
        descriptor,
        descriptor_bytes,
        bindings_bytes,
        hnsw_bytes,
        fixed_descriptor_key: kernel_member_index_key(project, scope_id, b"descriptor.json"),
        fixed_bindings_key: kernel_member_index_key(project, scope_id, b"bindings.json"),
        fixed_hnsw_key: kernel_member_index_key(project, scope_id, b"s20.hnsw"),
    })
}

pub fn persist_kernel_member_index<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    index: &KernelMemberIndex,
) -> Result<KernelMemberIndexPersistReport, SearchError>
where
    C: Clock,
{
    let publication_seq = vault.latest_seq();
    let prepared =
        prepare_kernel_member_index_rows(vault, project, scope_id, index, publication_seq)?;
    let descriptor = prepared.descriptor;
    let descriptor_bytes = prepared.descriptor_bytes;
    let bindings_bytes = prepared.bindings_bytes;
    let hnsw_value = prepared.hnsw_bytes;
    let descriptor_key = prepared.fixed_descriptor_key;
    let bindings_key = prepared.fixed_bindings_key;
    let hnsw_key = prepared.fixed_hnsw_key;
    let bindings_blake3 = descriptor.bindings_blake3.clone();
    let artifact_blake3 = descriptor.hnsw_artifact_blake3.clone();
    let descriptor_blake3 = blake3_hex(&descriptor_bytes);
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": KERNEL_MEMBER_INDEX_SCHEMA,
        "project": project,
        "scope_id": scope_id,
        "members_hash": index.members_hash,
        "base_seq": index.base_seq,
        "source_binding_seq": index.source_binding_seq,
        "source_final_verification_seq": publication_seq,
        "source_binding": index.source_binding,
        "member_count": index.member_count,
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
    let (commit_seq, ledger_ref) = vault
        .write_cf_batch_with_ledger_entry_if_seq(
            publication_seq,
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
                (ColumnFamily::Kernel, hnsw_key.clone(), hnsw_value.clone()),
            ],
            EntryKind::Kernel,
            ledger_subject.clone(),
            payload.clone(),
            ledger_actor.clone(),
        )
        .map_err(|error| {
            index_persist(format!(
                "conditionally commit project {project:?} scope {scope_id:?} member index from exact seq {publication_seq}: {error}"
            ))
        })?;
    vault.flush().map_err(|error| {
        index_persist(format!(
            "flush project {project:?} scope {scope_id:?} member index: {error}"
        ))
    })?;
    verify_source_binding_generations_at(
        vault,
        commit_seq,
        &index.source_binding,
        "after member-index commit and flush",
    )?;

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
        .map_err(|error| index_persist(format!("read back HNSW row: {error}")))?
        .ok_or_else(|| index_persist("persisted HNSW row is missing"))?;
    if persisted_hnsw != hnsw_value {
        return Err(index_persist(
            "persisted HNSW row differs from the committed artifact bytes",
        ));
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
    let wanted_ledger = BTreeSet::from([ledger_ref.seq]);
    let (physical_ledger, ledger_trace) =
        vault
            .read_physical_ledger_seqs(&wanted_ledger)
            .map_err(|error| {
                index_persist(format!("read physical member-index ledger row: {error}"))
            })?;
    let physical_row = physical_ledger
        .get(&ledger_ref.seq)
        .ok_or_else(|| index_persist("physical member-index ledger row is missing"))?;
    let physical_entry = calyx_ledger::decode(&physical_row.bytes).map_err(|error| {
        index_persist(format!("decode physical member-index ledger row: {error}"))
    })?;
    if physical_row.seq != ledger_ref.seq
        || physical_entry.seq != ledger_ref.seq
        || physical_entry.entry_hash != ledger_ref.hash
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
        member_count: index.member_count,
        source_binding_seq: index.source_binding_seq,
        source_final_verification_seq: commit_seq,
        source_binding: index.source_binding.clone(),
        ledger_ref,
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

/// Recomputes and compares a persisted descriptor's exact S20 representation
/// identity at the current latest read-only snapshot.
///
/// The selected Aster handle must include only `Kernel` (for the caller's
/// descriptor read), `Slot(S20)`, and `Compression`; this verifier itself reads
/// only S20 and Compression. A manifested representation additionally reads the
/// exact panel/Registry assets below `vault_panel_root`. It needs neither Graph
/// nor Base, and it does not reconstruct a graph snapshot or infer a panel
/// version. Call this before admitting a newly loaded descriptor/HNSW generation
/// into the resident cache. [`read_persisted_kernel_member_index_descriptor`]
/// remains the warm-request generation guard.
pub fn verify_kernel_member_index_source_at_latest<C>(
    vault: &AsterVault<C>,
    vault_panel_root: &Path,
    descriptor: &KernelMemberIndexDescriptor,
) -> Result<KernelMemberIndexSourceVerification, SearchError>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let persisted = read_persisted_kernel_member_index_descriptor_at(
        vault,
        snapshot,
        &descriptor.project,
        &descriptor.scope_id,
        &descriptor.members_hash,
    )?
    .ok_or_else(|| {
        index_corrupt("member-index descriptor disappeared before exact source verification")
    })?;
    if &persisted != descriptor {
        return Err(index_corrupt(
            "current persisted member-index descriptor differs from the generation submitted for exact source verification",
        ));
    }
    let source = WeaveSlotSource::open(snapshot, Some(vault_panel_root), None)
        .map_err(|error| source_binding_error("open persisted S20 read verifier", &error))?;
    source
        .verify_latest_binding_at(vault, snapshot, &descriptor.source_binding)
        .map_err(|error| {
            source_binding_error(
                "verify persisted S20 Slot/Compression representation before serving",
                &error,
            )
        })?;
    Ok(KernelMemberIndexSourceVerification {
        read_snapshot_seq: snapshot,
        source_binding_seq: descriptor.source_binding_seq,
        source_final_verification_seq: descriptor.source_final_verification_seq,
        source_binding: descriptor.source_binding.clone(),
    })
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
        for suffix in [b"bindings.json".as_slice(), b"s20.hnsw".as_slice()] {
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
    validate_descriptor(
        &descriptor,
        snapshot,
        project,
        scope_id,
        expected_members_hash,
    )?;
    verify_source_binding_generations_at(
        vault,
        snapshot,
        &descriptor.source_binding,
        "read persisted member-index descriptor",
    )?;
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
    let hnsw_key = kernel_member_index_key(project, scope_id, b"s20.hnsw");
    let hnsw = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &hnsw_key)
        .map_err(|error| index_corrupt(format!("read member-index HNSW: {error}")))?;
    let source_binding = descriptor.source_binding.clone();
    let loaded = loaded_from_parts(descriptor, bindings, hnsw)?;
    verify_source_binding_generations_at(
        vault,
        snapshot,
        &source_binding,
        "final persisted member-index generation readback",
    )?;
    Ok(Some(loaded))
}

pub(crate) fn loaded_from_parts(
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
    if descriptor.member_count != descriptor.binding_count
        || descriptor.member_count != descriptor.indexed_member_count
        || bindings.len() != descriptor.member_count
    {
        return Err(index_corrupt(format!(
            "member-index population is incomplete: member_count={}, binding_count={}, indexed_member_count={}, decoded_bindings={}",
            descriptor.member_count,
            descriptor.binding_count,
            descriptor.indexed_member_count,
            bindings.len()
        )));
    }
    let mut seen_cx = BTreeSet::new();
    let mut seen_atoms = BTreeSet::new();
    let mut prior_cx = None;
    for binding in &bindings {
        if prior_cx.is_some_and(|prior| prior >= binding.cx_id) {
            return Err(index_corrupt(
                "member-index bindings are not in strict ascending CxId order",
            ));
        }
        prior_cx = Some(binding.cx_id);
        if !seen_cx.insert(binding.cx_id) || !seen_atoms.insert(binding.symbol_id.as_str()) {
            return Err(index_corrupt(
                "member-index bindings contain a duplicate CxId or source atom",
            ));
        }
    }
    let hnsw = match descriptor.index_kind {
        KernelIndexKind::MembershipManifestOnly => {
            return Err(index_corrupt(
                "v4 member-index descriptor is membership-only; production serving requires one valid S20 vector and one live HNSW row for every member",
            ));
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
                    slot: SLOT_NAME_SEMANTIC,
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
            if index.total_nodes() != descriptor.member_count
                || index.live_len() != descriptor.member_count
            {
                return Err(index_corrupt(format!(
                    "HNSW population differs from the complete member roster: member_count={}, total_rows={}, live_rows={}",
                    descriptor.member_count,
                    index.total_nodes(),
                    index.live_len()
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

pub(crate) fn validate_descriptor(
    descriptor: &KernelMemberIndexDescriptor,
    snapshot: u64,
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
    if descriptor.slot != SLOT_NAME_SEMANTIC {
        return Err(index_corrupt(format!(
            "member-index slot {} is not S{}",
            descriptor.slot.get(),
            SLOT_NAME_SEMANTIC.get()
        )));
    }
    validate_source_binding_shape(&descriptor.source_binding)?;
    if descriptor.source_binding_seq != descriptor.base_seq
        || descriptor.panel_version == 0
        || descriptor.source_final_verification_seq < descriptor.source_binding_seq
        || descriptor.source_final_verification_seq > snapshot
        || descriptor.source_binding.slot_cf_generation > descriptor.source_binding_seq
        || descriptor.source_binding.compression_cf_generation > descriptor.source_binding_seq
    {
        return Err(index_corrupt(format!(
            "v4 descriptor has inconsistent source epochs: read_snapshot={snapshot}, panel_version={}, base_seq={}, source_binding_seq={}, source_final_verification_seq={}, slot_generation={}, compression_generation={}",
            descriptor.panel_version,
            descriptor.base_seq,
            descriptor.source_binding_seq,
            descriptor.source_final_verification_seq,
            descriptor.source_binding.slot_cf_generation,
            descriptor.source_binding.compression_cf_generation,
        )));
    }
    if descriptor.index_kind != KernelIndexKind::EmbeddingBackedHnsw {
        return Err(index_corrupt(format!(
            "v4 descriptor index_kind {} is not embedding_backed_hnsw",
            descriptor.index_kind.as_str()
        )));
    }
    if descriptor.member_count == 0
        || descriptor.member_count != descriptor.binding_count
        || descriptor.member_count != descriptor.indexed_member_count
        || !descriptor.missing_vector_members.is_empty()
    {
        return Err(index_corrupt(format!(
            "v4 descriptor is not a complete member generation: member_count={}, binding_count={}, indexed_member_count={}, missing_vector_count={}, missing_vector_members={:?}",
            descriptor.member_count,
            descriptor.binding_count,
            descriptor.indexed_member_count,
            descriptor.missing_vector_members.len(),
            descriptor.missing_vector_members
        )));
    }
    if descriptor.semantic_dim.is_none()
        || descriptor.hnsw_artifact_bytes == 0
        || descriptor.hnsw_artifact_blake3.is_none()
    {
        return Err(index_corrupt(
            "v4 embedding-backed descriptor lacks semantic dimension or HNSW artifact identity",
        ));
    }
    if let Some(identity) = &descriptor.source_binding.compressed_generation_identity
        && (descriptor.semantic_dim != Some(identity.raw_dim)
            || (identity.row_count as usize) < descriptor.member_count)
    {
        return Err(index_corrupt(format!(
            "v4 descriptor semantic dimension/population differs from compressed S20 identity: semantic_dim={:?}, compressed_raw_dim={}, member_count={}, compressed_row_count={}",
            descriptor.semantic_dim, identity.raw_dim, descriptor.member_count, identity.row_count
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
/// ([`ASTRO_KERNEL_INDEX_ABSENT`]). Otherwise ranks the member subcorpus by S20
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
    validate_built_index(index)?;
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
            "Ensure the kernel members carry persisted S20 vectors (re-run index_repository with \
             calyx=\"shadow\"), then rebuild the kernel-member index.",
        ));
    };
    let index_set = SlotIndexSet::from_manifest(manifest)?;
    semantic_more_like_this(
        &index_set,
        anchor_symbol_id,
        &[SLOT_NAME_SEMANTIC],
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
    /// Members carrying a persisted S20 vector (the rankable population).
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
/// S20 space the corpus was measured in, instead of falling back to a
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
    validate_built_index(index)?;
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
            "Ensure the kernel members carry persisted S20 vectors (re-run index_repository with \
             calyx=\"shadow\"), then rebuild the kernel-member index.",
        ));
    };
    if query_vector.is_empty() {
        return Err(SearchError::new(
            ASTRO_KERNEL_QUERY_UNRESOLVED,
            "the query resolved to no S20 query vector, so no kernel member can be reached by it"
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
            slot: SLOT_NAME_SEMANTIC,
            semantic_dim: index.semantic_dim,
            panel_version: index.panel_version,
            base_seq: index.base_seq,
            source_binding_seq: index.source_binding_seq,
            source_final_verification_seq: index.source_final_verification_seq,
            source_binding: index.source_binding.clone(),
            knobs: index.knobs,
            member_count: index.member_count,
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
            "the query resolved to no S20 query vector, so no kernel member can be reached by it"
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
            "Re-index so kernel members carry persisted S20 vectors, then rebuild the kernel.",
        )
    })?;
    let dim = index
        .descriptor
        .semantic_dim
        .ok_or_else(|| index_corrupt("loaded embedding-backed index has no dimension"))?;
    if query_vector.len() != dim as usize {
        return Err(index_corrupt(format!(
            "query S20 dimension {} differs from persisted HNSW dimension {dim}",
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
        slot: SLOT_NAME_SEMANTIC,
        matches,
    })
}

/// Measures top-`k` parity between a kernel-scoped HNSW and the full HNSW.
///
/// For each anchor, the reference set is the full index's semantic ranking of the
/// same anchor *restricted to kernel members*, truncated to `k`; the candidate
/// set is the kernel index's own top-`k`. Parity is
/// `|reference ∩ candidate| / |reference|` summed over anchors. Because both
/// rankings are approximate, this diagnostic cannot replace the exact
/// full-corpus graph-routed recall validator used by complete generation
/// admission.
pub fn measure_kernel_index_parity(
    full_index: &SlotIndexSet,
    kernel_index: &KernelMemberIndex,
    anchors: &[String],
    k: u64,
    ef: u64,
    caps: &SearchCaps,
) -> Result<KernelIndexParityMeasurement, SearchError> {
    let k_usize = usize::try_from(k).map_err(|_| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW,
            "kernel-index parity k is not representable as usize",
            "use a k value within the declared search caps for this target",
        )
    })?;
    let members: BTreeSet<&String> = kernel_index.member_symbol_ids.iter().collect();
    let mut matching = 0u64;
    let mut total = 0u64;
    for anchor in anchors {
        // Full-index ranking of this anchor, restricted to kernel members, top-k.
        let full = semantic_more_like_this(
            full_index,
            anchor,
            &[SLOT_NAME_SEMANTIC],
            caps.max_k,
            ef,
            caps,
        )?;
        let reference: Vec<String> = full
            .neighbors
            .into_iter()
            .map(|result| result.symbol_id)
            .filter(|id| members.contains(id))
            .take(k_usize)
            .collect();
        if reference.is_empty() {
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
        let reference_count = u64::try_from(reference.len()).map_err(|_| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW,
                "kernel-index reference count is not representable as u64",
                "reduce the declared parity workload before measuring again",
            )
        })?;
        let matching_count = u64::try_from(
            reference
                .iter()
                .filter(|id| candidate_ids.contains(*id))
                .count(),
        )
        .map_err(|_| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW,
                "kernel-index matching count is not representable as u64",
                "reduce the declared parity workload before measuring again",
            )
        })?;
        total = total.checked_add(reference_count).ok_or_else(|| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW,
                "kernel-index parity reference total overflowed u64",
                "reduce the declared anchor/query workload before measuring again",
            )
        })?;
        matching = matching.checked_add(matching_count).ok_or_else(|| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW,
                "kernel-index parity matching total overflowed u64",
                "reduce the declared anchor/query workload before measuring again",
            )
        })?;
    }
    let permille = if total == 0 {
        0
    } else {
        matching.checked_mul(1000).ok_or_else(|| {
            SearchError::new(
                ASTRO_KERNEL_INDEX_MEASUREMENT_OVERFLOW,
                "kernel-index parity fixed-point numerator overflowed u64",
                "reduce the declared anchor/query workload before measuring again",
            )
        })? / total
    };
    Ok(KernelIndexParityMeasurement {
        matching,
        total,
        permille,
        gated: total > 0 && permille >= KERNEL_INDEX_PARITY_GATE_PERMILLE,
    })
}
