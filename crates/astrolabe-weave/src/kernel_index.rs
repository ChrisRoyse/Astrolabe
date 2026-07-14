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
use calyx_core::{Clock, CxId};

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
    /// Resolved member symbol ids (qualified names), ascending.
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
/// Resolves each member `CxId` to its live qualified name via the graph snapshot
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

    // Resolve member CxIds -> live qualified names via the graph snapshot.
    let snapshot = read_cbm_graph_snapshot(vault, project).map_err(|error| {
        SearchError::new(
            ASTRO_KERNEL_INDEX_VAULT,
            format!("read graph snapshot for project {project:?}: {error}"),
            "Re-run index_repository with calyx=\"shadow\" so the vault holds a current graph \
             snapshot before building the kernel-member index.",
        )
    })?;
    let cx_to_name: BTreeMap<CxId, String> = snapshot
        .nodes
        .iter()
        .filter_map(|node| node.cx_id.map(|cx| (cx, node.qualified_name.clone())))
        .collect();

    let mut member_names = BTreeSet::new();
    for cx in member_cx_ids {
        let Some(name) = cx_to_name.get(cx) else {
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
        member_names.insert(name.clone());
    }

    // Read the persisted S18 corpus and restrict it to the members.
    let report = read_search_corpus_from_vault(vault, project, &[SLOT_CODE_SEMANTIC])?;
    let base_seq = report.base_seq;

    let mut member_symbols = Vec::new();
    let mut present_names = BTreeSet::new();
    for symbol in report.symbols {
        if !member_names.contains(&symbol.symbol_id) {
            continue;
        }
        present_names.insert(symbol.symbol_id.clone());
        if symbol.vectors.contains_key(&SLOT_CODE_SEMANTIC) {
            member_symbols.push(symbol);
        }
    }
    let indexed_names: BTreeSet<&String> = member_symbols.iter().map(|s| &s.symbol_id).collect();
    let mut missing_vector_members: Vec<String> = member_names
        .iter()
        .filter(|name| !indexed_names.contains(name))
        .cloned()
        .collect();
    // A resolved member absent from the non-structural corpus entirely is also a
    // labeled skip (already covered by the filter above, but make it explicit).
    let _ = &present_names;
    missing_vector_members.sort();
    missing_vector_members.dedup();

    let member_symbol_ids: Vec<String> = member_names.iter().cloned().collect();

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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use astrolabe_ingest::{
        CbmGraphNode, CbmGraphSnapshot, SqliteImportOptions,
        import_cbm_graph_snapshot_to_vault_direct,
    };
    use astrolabe_kernel::members_hash;
    use astrolabe_panel::FixtureSlotRuntime;
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{SystemClock, VaultId};

    use crate::search::SearchCaps;
    use crate::search_index::SlotIndexSet;
    use crate::search_production::build_search_index_manifest_from_vault;

    const PROJECT: &str = "kdemo";

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    fn test_vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().expect("vault id")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-weave-kernelidx-{name}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn open_vault(dir: &Path) -> AsterVault<SystemClock> {
        AsterVault::new_durable(
            dir,
            test_vault_id(),
            b"astrolabe-kernelidx-test-salt".to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable vault")
    }

    /// A distinct function node; the unique `body` gives it a distinct S18
    /// code-semantic vector under the fixture panel runtime.
    fn node(id: i64, name: &str, qn: &str, body: &str) -> CbmGraphNode {
        CbmGraphNode {
            source_node_id: id,
            project: PROJECT.to_string(),
            label: "Function".to_string(),
            name: name.to_string(),
            qualified_name: qn.to_string(),
            file_path: "src/lib.rs".to_string(),
            start_line: id * 10,
            end_line: id * 10 + 5,
            properties_json: format!(
                r#"{{"language":"rust","source_snippet":{body:?},"signature":"fn {name}()"}}"#
            ),
            node_vector: None,
            cx_id: None,
            structural: false,
        }
    }

    /// Fourteen distinct symbols spanning a few token themes so cosine separates
    /// them; every symbol carries a persisted S18 vector after import.
    fn corpus_snapshot() -> CbmGraphSnapshot {
        let bodies = [
            (
                "parse_config",
                "kdemo.cfg.parse_config",
                "let config = read_file(path); parse toml config settings",
            ),
            (
                "parse_args",
                "kdemo.cli.parse_args",
                "let args = read_argv(); parse command line flags and options",
            ),
            (
                "load_config",
                "kdemo.cfg.load_config",
                "read_file(path); load and parse toml config settings values",
            ),
            (
                "http_server",
                "kdemo.net.http_server",
                "bind tcp socket; accept http connections; route requests",
            ),
            (
                "tcp_listener",
                "kdemo.net.tcp_listener",
                "bind tcp socket; accept connections; read request bytes",
            ),
            (
                "route_request",
                "kdemo.net.route_request",
                "match http path; dispatch handler; write http response",
            ),
            (
                "hash_password",
                "kdemo.sec.hash_password",
                "compute salted blake3 hash of password bytes securely",
            ),
            (
                "verify_token",
                "kdemo.sec.verify_token",
                "verify signed auth token; check blake3 hash and expiry",
            ),
            (
                "encrypt_blob",
                "kdemo.sec.encrypt_blob",
                "encrypt blob bytes with aes gcm; derive key from secret",
            ),
            (
                "sum_metrics",
                "kdemo.math.sum_metrics",
                "sum numeric metric samples; compute mean and variance",
            ),
            (
                "mean_variance",
                "kdemo.math.mean_variance",
                "compute mean and variance of numeric metric samples",
            ),
            (
                "sort_records",
                "kdemo.data.sort_records",
                "sort record rows by key; stable order; return sorted vec",
            ),
            (
                "filter_rows",
                "kdemo.data.filter_rows",
                "filter record rows by predicate; retain matching rows",
            ),
            (
                "merge_rows",
                "kdemo.data.merge_rows",
                "merge two sorted record row streams into one sorted vec",
            ),
        ];
        let nodes = bodies
            .iter()
            .enumerate()
            .map(|(index, (name, qn, body))| node(index as i64 + 1, name, qn, body))
            .collect();
        CbmGraphSnapshot {
            project: PROJECT.to_string(),
            panel_version: Some(1),
            projects: Vec::new(),
            nodes,
            edges: Vec::new(),
            file_hashes: Vec::new(),
            project_summaries: Vec::new(),
            token_vectors: Vec::new(),
        }
    }

    fn import(vault: &AsterVault<SystemClock>) {
        import_cbm_graph_snapshot_to_vault_direct(
            &corpus_snapshot(),
            [9u8; 32],
            vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new(PROJECT, "commit-1", 1),
        )
        .expect("import corpus snapshot");
    }

    /// Reads the live (cx_id, qualified_name) pairs back from the vault snapshot,
    /// sorted by qualified name for determinism.
    fn live_symbols(vault: &AsterVault<SystemClock>) -> Vec<(CxId, String)> {
        let snapshot = read_cbm_graph_snapshot(vault, PROJECT).expect("snapshot");
        let mut pairs: Vec<(CxId, String)> = snapshot
            .nodes
            .into_iter()
            .filter(|node| !node.structural)
            .filter_map(|node| node.cx_id.map(|cx| (cx, node.qualified_name)))
            .collect();
        pairs.sort_by(|a, b| a.1.cmp(&b.1));
        pairs
    }

    #[test]
    fn build_serves_and_recalls_kernel_member_index_fsv() {
        let dir = temp_dir("recall");
        let vault = open_vault(&dir.join("vault"));
        import(&vault);

        let live = live_symbols(&vault);
        assert_eq!(
            live.len(),
            14,
            "every non-structural symbol resolves a CxId"
        );
        // Kernel member subset: 8 of the 14 symbols (a proper subset, so the
        // kernel index really is smaller than the full corpus).
        let member_cx_ids: Vec<CxId> = live.iter().take(8).map(|(cx, _)| *cx).collect();
        let member_names: BTreeSet<String> =
            live.iter().take(8).map(|(_, name)| name.clone()).collect();
        let hash = members_hash(&member_cx_ids);

        let knobs = IndexKnobs::defaults(0x1234);
        let index = build_kernel_member_index(&vault, PROJECT, &member_cx_ids, &hash, knobs)
            .expect("build kernel member index");
        assert_eq!(index.index_kind, KernelIndexKind::EmbeddingBackedHnsw);
        assert_eq!(index.members_hash, hash);
        assert_eq!(index.indexed_member_count, 8);
        assert!(index.missing_vector_members.is_empty());
        assert_eq!(index.semantic_dim, Some(768), "S18 is a dim-768 embedding");
        assert_eq!(
            index.member_symbol_ids,
            member_names.iter().cloned().collect::<Vec<_>>()
        );

        // Every neighbor served from the small index is a kernel member.
        let caps = SearchCaps::default_caps();
        let anchor = index.member_symbol_ids[0].clone();
        let served = kernel_scoped_semantic_query(&index, &hash, &anchor, 10, 32, &caps)
            .expect("serve kernel scoped query");
        assert!(!served.neighbors.is_empty());
        for neighbor in &served.neighbors {
            assert!(
                member_names.contains(&neighbor.symbol_id),
                "kernel-scoped neighbor {} escaped the member set",
                neighbor.symbol_id
            );
        }

        // Recall@10 of the kernel index vs the full index, restricted to members.
        let (full_manifest, _) =
            build_search_index_manifest_from_vault(&vault, PROJECT, &[SLOT_CODE_SEMANTIC], knobs)
                .expect("full manifest");
        let full_index = SlotIndexSet::from_manifest(&full_manifest).expect("full index set");
        let anchors = index.member_symbol_ids.clone();
        let recall = measure_kernel_index_recall(&full_index, &index, &anchors, 10, 32, &caps)
            .expect("measure recall");
        assert!(
            recall.total > 0,
            "recall must measure at least one member query"
        );
        assert!(
            recall.permille >= KERNEL_INDEX_RECALL_GATE_PERMILLE,
            "kernel index recall {}‰ below the #37 gate {}‰ (recalled {}/{})",
            recall.permille,
            KERNEL_INDEX_RECALL_GATE_PERMILLE,
            recall.recalled,
            recall.total
        );
        assert!(recall.gated);

        // FSV readback: persist the kernel manifest bytes, read them back
        // independently, rebuild, and re-serve — identical ranking + content hash.
        let manifest = index.manifest.as_ref().expect("embedding-backed manifest");
        let bytes = manifest.to_canonical_bytes().expect("canonical bytes");
        let reloaded = SlotIndexManifest::from_bytes(&bytes).expect("reload manifest");
        assert_eq!(
            &reloaded, manifest,
            "kernel manifest round-trips byte-identically"
        );
        assert_eq!(
            reloaded.content_hash().unwrap(),
            manifest.content_hash().unwrap()
        );
        let reindex = KernelMemberIndex {
            manifest: Some(reloaded),
            ..index.clone()
        };
        let reserved = kernel_scoped_semantic_query(&reindex, &hash, &anchor, 10, 32, &caps)
            .expect("re-serve from reloaded manifest");
        assert_eq!(
            served.neighbors, reserved.neighbors,
            "served ranking must survive a persist/readback round-trip"
        );
    }

    #[test]
    fn stale_members_hash_refuses_fail_closed() {
        let dir = temp_dir("stale");
        let vault = open_vault(&dir.join("vault"));
        import(&vault);
        let live = live_symbols(&vault);
        let member_cx_ids: Vec<CxId> = live.iter().take(6).map(|(cx, _)| *cx).collect();
        let hash = members_hash(&member_cx_ids);
        let index = build_kernel_member_index(
            &vault,
            PROJECT,
            &member_cx_ids,
            &hash,
            IndexKnobs::defaults(1),
        )
        .expect("build");
        let caps = SearchCaps::default_caps();
        let anchor = index.member_symbol_ids[0].clone();

        // A different current members_hash (kernel members moved) must refuse.
        let moved = members_hash(&live.iter().take(7).map(|(cx, _)| *cx).collect::<Vec<_>>());
        let error = kernel_scoped_semantic_query(&index, &moved, &anchor, 5, 32, &caps)
            .expect_err("stale members_hash must refuse");
        assert_eq!(error.code(), ASTRO_KERNEL_INDEX_STALE);
        assert!(!error.remediation().is_empty());
    }

    #[test]
    fn absent_embedding_index_refuses_labeled() {
        // A membership-manifest-only index (no member carried an S18 vector) must
        // refuse a semantic query rather than silently returning nothing.
        let index = KernelMemberIndex {
            schema: KERNEL_MEMBER_INDEX_SCHEMA.to_string(),
            members_hash: "abcd".to_string(),
            index_kind: KernelIndexKind::MembershipManifestOnly,
            manifest: None,
            member_symbol_ids: vec!["kdemo.a".to_string()],
            indexed_member_count: 0,
            missing_vector_members: vec!["kdemo.a".to_string()],
            semantic_dim: None,
            base_seq: 1,
        };
        assert_eq!(index.index_kind.as_str(), "membership_manifest");
        let caps = SearchCaps::default_caps();
        let error = kernel_scoped_semantic_query(&index, "abcd", "kdemo.a", 5, 32, &caps)
            .expect_err("absent embedding index must refuse");
        assert_eq!(error.code(), ASTRO_KERNEL_INDEX_ABSENT);
    }

    #[test]
    fn member_absent_from_snapshot_refuses() {
        let dir = temp_dir("absent-member");
        let vault = open_vault(&dir.join("vault"));
        import(&vault);
        let bogus = CxId::from_bytes([0xEE; 16]);
        let error =
            build_kernel_member_index(&vault, PROJECT, &[bogus], "cafe", IndexKnobs::defaults(2))
                .expect_err("member absent from snapshot must refuse");
        assert_eq!(error.code(), ASTRO_KERNEL_INDEX_MEMBER_ABSENT);
    }

    #[test]
    fn empty_member_set_refuses() {
        let dir = temp_dir("empty");
        let vault = open_vault(&dir.join("vault"));
        import(&vault);
        let error =
            build_kernel_member_index(&vault, PROJECT, &[], "cafe", IndexKnobs::defaults(3))
                .expect_err("empty member set must refuse");
        assert_eq!(error.code(), ASTRO_KERNEL_INDEX_NO_MEMBERS);
    }

    #[test]
    fn kernel_index_bytes_are_deterministic() {
        let dir = temp_dir("determinism");
        let vault = open_vault(&dir.join("vault"));
        import(&vault);
        let live = live_symbols(&vault);
        let member_cx_ids: Vec<CxId> = live.iter().take(8).map(|(cx, _)| *cx).collect();
        let hash = members_hash(&member_cx_ids);
        let knobs = IndexKnobs::defaults(0x9999);
        let a = build_kernel_member_index(&vault, PROJECT, &member_cx_ids, &hash, knobs)
            .expect("build a");
        let b = build_kernel_member_index(&vault, PROJECT, &member_cx_ids, &hash, knobs)
            .expect("build b");
        let ha = a.manifest.unwrap().content_hash().unwrap();
        let hb = b.manifest.unwrap().content_hash().unwrap();
        assert_eq!(ha, hb, "kernel-member index bytes must be deterministic");
    }
}
