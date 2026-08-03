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

use astrolabe_ingest::read_cbm_graph_snapshot;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, CxId, SlotId};

use crate::search::{SLOT_CODE_SEMANTIC, SearchCaps, SearchError};
use crate::search_index::{IndexKnobs, SlotIndexManifest, SlotIndexSet};
use crate::search_production::{
    CorpusReadReport, SemanticQueryResult, build_manifest_from_corpus,
    read_search_corpus_from_vault, semantic_more_like_this,
};

/// Schema tag for a kernel-member embedding index descriptor.
pub const KERNEL_MEMBER_INDEX_SCHEMA: &str = "astrolabe.kernel_member_index.v1";

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

/// What a kernel-member index actually is: a real embedding-backed ANN, or a
/// labeled membership manifest when no member carries an S18 vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelIndexKind {
    /// An HNSW index over the members' persisted S18 code-semantic vectors.
    EmbeddingBackedHnsw,
    /// No member carried a persisted S18 vector; the index is the kernel's
    /// membership manifest only. Semantic queries refuse fail-closed.
    MembershipManifestOnly,
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

    // Resolve member CxIds -> stable source-atom ids via the graph snapshot.
    let snapshot = read_cbm_graph_snapshot(vault, project).map_err(|error| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!("read graph snapshot for project {project:?}: {error}"),
            "Re-run index_repository with calyx=\"shadow\" so the vault holds a current graph \
             snapshot before building the kernel-member index.",
        )
    })?;
    let cx_to_atom: BTreeMap<CxId, String> = snapshot
        .nodes
        .iter()
        .filter_map(|node| node.cx_id.map(|cx| (cx, node.atom_id.clone())))
        .collect();

    let mut member_ids = BTreeSet::new();
    for cx in member_cx_ids {
        let Some(symbol_id) = cx_to_atom.get(cx) else {
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
        member_ids.insert(symbol_id.clone());
    }

    // Read the persisted S18 corpus and restrict it to the members.
    let report = read_search_corpus_from_vault(vault, project, &[SLOT_CODE_SEMANTIC])?;
    let base_seq = report.base_seq;

    let mut member_symbols = Vec::new();
    let mut present_names = BTreeSet::new();
    for symbol in report.symbols {
        if !member_ids.contains(&symbol.symbol_id) {
            continue;
        }
        present_names.insert(symbol.symbol_id.clone());
        if symbol.vectors.contains_key(&SLOT_CODE_SEMANTIC) {
            member_symbols.push(symbol);
        }
    }
    let indexed_names: BTreeSet<&String> = member_symbols.iter().map(|s| &s.symbol_id).collect();
    let mut missing_vector_members: Vec<String> = member_ids
        .iter()
        .filter(|name| !indexed_names.contains(name))
        .cloned()
        .collect();
    // A resolved member absent from the non-structural corpus entirely is also a
    // labeled skip (already covered by the filter above, but make it explicit).
    let _ = &present_names;
    missing_vector_members.sort();
    missing_vector_members.dedup();

    let member_symbol_ids: Vec<String> = member_ids.iter().cloned().collect();

    if member_symbols.is_empty() {
        return Ok(KernelMemberIndex {
            schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
            members_hash: members_hash.to_string(),
            index_kind: KernelIndexKind::MembershipManifestOnly,
            manifest: None,
            member_symbol_ids,
            indexed_member_count: 0,
            missing_vector_members,
            semantic_dim: None,
            base_seq,
        });
    }

    let semantic_dim = member_symbols
        .iter()
        .find_map(|s| s.vectors.get(&SLOT_CODE_SEMANTIC).map(|v| v.len() as u32));
    let mut declared_vector_slots = BTreeMap::new();
    for symbol in &member_symbols {
        for (slot, vector) in &symbol.vectors {
            declared_vector_slots
                .entry(*slot)
                .or_insert(vector.len() as u32);
        }
    }
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

    Ok(KernelMemberIndex {
        schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
        members_hash: members_hash.to_string(),
        index_kind: KernelIndexKind::EmbeddingBackedHnsw,
        manifest: Some(manifest),
        member_symbol_ids,
        indexed_member_count,
        missing_vector_members,
        semantic_dim,
        base_seq,
    })
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
    let Some(manifest) = &index.manifest else {
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

    let index_set = SlotIndexSet::from_manifest(manifest)?;
    let query = crate::search_index::SlotQuery::text("")
        .with_vector(SLOT_CODE_SEMANTIC, query_vector.to_vec());
    let ranking = index_set.rank_slot(SLOT_CODE_SEMANTIC, &query, k, ef)?;
    let matches = ranking
        .ranked_symbol_ids
        .into_iter()
        .enumerate()
        .map(|(rank, symbol_id)| KernelQueryMatch {
            symbol_id,
            rank: rank as u64,
        })
        .collect();
    Ok(KernelQueryResult {
        members_hash: index.members_hash.clone(),
        base_seq: index.base_seq,
        indexed_member_count: index.indexed_member_count,
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
