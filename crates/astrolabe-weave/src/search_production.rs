//! Production owner for the Sextant-fused search index (P6.6, #42).
//!
//! [`search_index`](crate::search_index) builds a [`SlotIndexManifest`] from an
//! abstract corpus and [`search`](crate::search) plans/fuses over it. This
//! module is the missing production lifecycle both of them depend on: it reads a
//! **real, persisted shadow vault** — the graph node identities the CBM import
//! wrote plus the per-slot dense vectors the panel runtime measured — assembles
//! the corpus, and freezes it into a persisted, byte-stable manifest with an
//! explicit freshness contract.
//!
//! Every prior wave on #42 named "no `SlotIndexManifest` production owner" as
//! THE blocker for wiring `search_graph` through the fused planner: without a
//! lifecycle that turns real vault state into a manifest,
//! [`run_indexed_search`](crate::search_index::run_indexed_search) always
//! fail-closes `ASTRO_SEARCH_INDEX_ABSENT`. This module is that owner.
//!
//! What it reads from the vault (all real persisted state, never synthesized):
//! - **S7 lexical text** — the symbol identifier (`CbmGraphNode::name`), split
//!   into BM25 tokens at build time by
//!   [`split_identifier_tokens`](crate::search_index::split_identifier_tokens).
//! - **Vector slots** — the dense [`SlotVector`]s the panel runtime persisted at
//!   `ColumnFamily::slot(slot)` under [`slot_key`], read back and decoded with
//!   [`decode_slot_vector`]. Structural nodes (no constellation, no slots) are
//!   excluded exactly as the shadow weave planner excludes them.
//!
//! Fail-closed contract (no silent fallback, standing invariant #3):
//! - a corrupt/undecodable slot row or graph read is a coded refusal, never a
//!   dropped symbol;
//! - a persisted `SlotVector::Absent`, a missing slot row, or a non-dense
//!   (sparse/multi) slot is a **labeled skip** counted in [`CorpusReadReport`],
//!   never silently folded into the index;
//! - loading a manifest whose `base_seq` no longer matches the live vault
//!   sequence fail-closes [`ASTRO_SEARCH_PRODUCTION_STALE`] rather than serving
//!   a stale index (the fused planner must never rank against a stale corpus).

use std::collections::BTreeMap;
use std::path::Path;

use astrolabe_ingest::read_cbm_graph_snapshot;
use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode::decode_slot_vector;
use calyx_core::{Clock, SlotId, SlotVector, SparseEntry};

use crate::search::{
    FusedResult, SLOT_API_CALLEES, SLOT_CODE_SEMANTIC, SLOT_LEXICAL_BM25, SLOT_NAME_SEMANTIC,
    SLOT_STRUCT_TRIGRAMS, SearchCaps, SearchError, SearchRequest, WEIGHT_SCALE_MILLIS, plan_search,
};
use crate::search_index::{
    ASTRO_SEARCH_INDEX_CORPUS, IndexKnobs, SlotIndexManifest, SlotIndexSet, SlotIndexSetBuilder,
    SlotQuery, StoredContent, run_indexed_search,
};

/// The dense semantic slots the symbol-anchored "more like this" query ranks: S18
/// (code-semantic) and S20 (name-semantic), persisted per symbol as **dense**
/// embedding vectors. Pass these (or a narrower subset) to
/// [`semantic_more_like_this`] to rank against an anchor symbol's own persisted
/// semantic vectors. Identical membership to [`PRODUCTION_VECTOR_SLOTS`] (both are
/// the two query-embeddable semantic slots), named separately for the symbol-
/// anchored query surface so a reader sees the intent at the call site.
pub const SEMANTIC_QUERY_SLOTS: [SlotId; 2] = [SLOT_CODE_SEMANTIC, SLOT_NAME_SEMANTIC];

/// Fail-closed: reading the persisted shadow vault (graph snapshot or a slot
/// column-family row) failed. Wraps the underlying Calyx/ingest error.
pub const ASTRO_SEARCH_PRODUCTION_VAULT: &str = "ASTRO_SEARCH_PRODUCTION_VAULT";
/// Fail-closed: a persisted manifest's `base_seq` no longer matches the live
/// vault sequence, so the index is stale and must be rebuilt before use.
pub const ASTRO_SEARCH_PRODUCTION_STALE: &str = "ASTRO_SEARCH_PRODUCTION_STALE";
/// Fail-closed: manifest persistence/load I/O failed.
pub const ASTRO_SEARCH_PRODUCTION_IO: &str = "ASTRO_SEARCH_PRODUCTION_IO";

/// The vector slots a **free-text query** can actually rank against: the two
/// semantic embedding slots (S18 code-semantic, S20 name-semantic) that the
/// shadow import populates with `encode_static_embedding_slot` and that a query
/// string can be embedded into the same way. S7 lexical is always built from the
/// identifier text (not a persisted vector), so it is not listed here. Callers
/// may pass a narrower set; a slot absent from every symbol is simply not
/// declared (a labeled zero in [`CorpusReadReport::declared_vector_slots`]).
///
/// Deliberately excluded: S1 (struct trigrams) and S4 (API callees) are
/// persisted per symbol but have **no free-text query representation** — you
/// cannot embed a natural-language query into a struct-trigram or callee vector
/// space — so ranking them for a text query still fails closed
/// `ASTRO_SEARCH_INDEX_QUERY_MISSING`. Those slots are served instead by the
/// distinct, **declared** symbol-anchored structural query mode
/// ([`structural_more_like_this`], via [`STRUCTURAL_QUERY_SLOTS`]): it reads an
/// already-indexed symbol's own persisted sparse S1/S4 vector and ranks the
/// corpus by exact sparse cosine — never a silently degraded text profile.
pub const PRODUCTION_VECTOR_SLOTS: [SlotId; 2] = [SLOT_CODE_SEMANTIC, SLOT_NAME_SEMANTIC];

/// The structural slots the symbol-anchored "more like this" query ranks: S1
/// (struct-trigrams) and S4 (API-callees), persisted per symbol as **sparse**
/// vectors with no free-text representation. Pass these (or a narrower subset)
/// to [`build_search_index_manifest_from_vault`] to declare them, and to
/// [`structural_more_like_this`] to rank against them.
pub const STRUCTURAL_QUERY_SLOTS: [SlotId; 2] = [SLOT_STRUCT_TRIGRAMS, SLOT_API_CALLEES];

/// Fail-closed: a symbol-anchored structural query named an anchor symbol that
/// is not present in the manifest at all (never a silent empty result).
pub const ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT: &str = "ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT";
/// Fail-closed: the anchor symbol is present but carries no persisted structural
/// vector for a requested slot (S1/S4), or the requested slot is not a declared
/// structural index in this manifest. The query refuses rather than
/// partial-scoring on a subset of the requested structural slots.
pub const ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT: &str = "ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT";
/// Fail-closed: no structural slots were requested for the anchored query.
pub const ASTRO_SEARCH_STRUCTURAL_NO_SLOTS: &str = "ASTRO_SEARCH_STRUCTURAL_NO_SLOTS";

/// One corpus symbol read from the vault: its unique id (qualified name), the
/// identifier text for the S7 lexical slot, the legacy CBM label (kept for the
/// parity harness's label-boost accounting), and every dense per-slot vector the
/// panel runtime persisted for it.
#[derive(Debug, Clone, PartialEq)]
pub struct CorpusSymbol {
    /// Unique symbol id — the CBM qualified name.
    pub symbol_id: String,
    /// Identifier text fed to the S7 BM25 tokenizer.
    pub name: String,
    /// Legacy CBM label (Function/Method/Class/Route/…), for parity accounting.
    pub label: String,
    /// Dense per-slot query-space vectors keyed by slot id (sorted).
    pub vectors: BTreeMap<SlotId, Vec<f32>>,
    /// Sparse per-slot structural vectors (S1 struct-trigrams / S4 API-callees)
    /// keyed by slot id (sorted). These have no free-text query representation
    /// and are served only by the symbol-anchored structural query mode.
    pub sparse_vectors: BTreeMap<SlotId, SlotVector>,
}

/// The corpus read from a vault, with a full accounting of every skip so no
/// degradation is silent (standing invariant #3).
#[derive(Debug, Clone, PartialEq)]
pub struct CorpusReadReport {
    /// Symbols admitted into the corpus (non-structural, with a resolved id).
    pub symbols: Vec<CorpusSymbol>,
    /// Total non-structural live graph nodes considered.
    pub symbols_total: usize,
    /// Dense slot vectors admitted across all symbols.
    pub vector_rows_read: usize,
    /// Sparse **structural** slot vectors (S1/S4) admitted across all symbols.
    pub structural_rows_read: usize,
    /// Slot rows that decoded to `SlotVector::Absent` (labeled skip).
    pub absent_slot_rows: usize,
    /// Requested slot rows that were not present for a symbol (labeled skip).
    pub missing_slot_rows: usize,
    /// Slot rows that were present but neither dense nor sparse (multi; labeled skip).
    pub non_dense_slot_rows: usize,
    /// Sparse structural rows skipped because their norm is degenerate/zero and
    /// they cannot be ranked by cosine (labeled skip, invariant #3).
    pub zero_norm_structural_rows: usize,
    /// Vector slots that ended up declared (present as dense on ≥1 symbol),
    /// each mapped to its dimension.
    pub declared_vector_slots: BTreeMap<SlotId, u32>,
    /// Structural slots that ended up declared (present as a rankable sparse
    /// vector on ≥1 symbol), each mapped to its ambient dimension.
    pub declared_structural_slots: BTreeMap<SlotId, u32>,
    /// Vault sequence this corpus was read at — the manifest freshness base.
    pub base_seq: u64,
}

impl CorpusReadReport {
    /// Total labeled skips across every skip bucket.
    pub fn skip_count(&self) -> usize {
        self.absent_slot_rows
            + self.missing_slot_rows
            + self.non_dense_slot_rows
            + self.zero_norm_structural_rows
    }
}

fn vault_error(context: &str, detail: impl std::fmt::Display) -> SearchError {
    SearchError::new(
        ASTRO_SEARCH_PRODUCTION_VAULT,
        format!("{context}: {detail}"),
        "Re-run index_repository with calyx=\"shadow\" so the vault holds a complete, current \
         graph snapshot and per-slot vectors before building the search index.",
    )
}

/// Reads the production search corpus from a persisted shadow vault.
///
/// Reads the live graph snapshot (`read_cbm_graph_snapshot`) for identity + S7
/// text, then, at the same vault sequence, reads back and decodes the dense
/// per-slot vectors for each requested `vector_slots` entry. Fail-closed on any
/// undecodable row; every absent/missing/non-dense slot is a labeled skip.
pub fn read_search_corpus_from_vault<C>(
    vault: &AsterVault<C>,
    project: &str,
    vector_slots: &[SlotId],
) -> Result<CorpusReadReport, SearchError>
where
    C: Clock,
{
    let snapshot = read_cbm_graph_snapshot(vault, project)
        .map_err(|error| vault_error("graph snapshot", error))?;
    let at_seq = vault.latest_seq();

    let mut symbols = Vec::new();
    let mut symbols_total = 0usize;
    let mut vector_rows_read = 0usize;
    let mut structural_rows_read = 0usize;
    let mut absent_slot_rows = 0usize;
    let mut missing_slot_rows = 0usize;
    let mut non_dense_slot_rows = 0usize;
    let mut zero_norm_structural_rows = 0usize;
    let mut declared_vector_slots: BTreeMap<SlotId, u32> = BTreeMap::new();
    let mut declared_structural_slots: BTreeMap<SlotId, u32> = BTreeMap::new();

    for node in snapshot.nodes.into_iter().filter(|node| !node.structural) {
        let Some(cx_id) = node.cx_id else {
            // A live non-structural node without a CxId is a corrupt snapshot, not
            // a skippable symbol: refuse rather than silently drop it.
            return Err(vault_error(
                "graph node identity",
                format!(
                    "live non-structural node {:?} has no CxId",
                    node.qualified_name
                ),
            ));
        };
        symbols_total += 1;
        let mut vectors: BTreeMap<SlotId, Vec<f32>> = BTreeMap::new();
        let mut sparse_vectors: BTreeMap<SlotId, SlotVector> = BTreeMap::new();
        for slot in vector_slots {
            let Some(bytes) = vault
                .read_cf_at(at_seq, ColumnFamily::slot(*slot), &slot_key(cx_id))
                .map_err(|error| {
                    vault_error(
                        &format!("slot {} row for {:?}", slot.get(), node.qualified_name),
                        error,
                    )
                })?
            else {
                missing_slot_rows += 1;
                continue;
            };
            let vector = decode_slot_vector(&bytes).map_err(|error| {
                vault_error(
                    &format!(
                        "decode slot {} vector for {:?}",
                        slot.get(),
                        node.qualified_name
                    ),
                    error,
                )
            })?;
            match vector {
                SlotVector::Dense { dim, data } => {
                    match declared_vector_slots.entry(*slot) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(dim);
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => {
                            if *entry.get() != dim {
                                return Err(SearchError::new(
                                    ASTRO_SEARCH_INDEX_CORPUS,
                                    format!(
                                        "slot {} vector dim {} for {:?} disagrees with declared dim {}",
                                        slot.get(),
                                        dim,
                                        node.qualified_name,
                                        entry.get()
                                    ),
                                    "Every symbol's vector for a slot must share one dimension; \
                                     rebuild the vault so the panel measured a consistent shape.",
                                ));
                            }
                        }
                    }
                    vector_rows_read += 1;
                    vectors.insert(*slot, data);
                }
                SlotVector::Sparse { dim, entries } => {
                    // S1/S4 persist as sparse vectors. A degenerate/zero-norm
                    // sparse vector cannot be cosine-ranked, so it is a labeled
                    // skip (invariant #3), never silently admitted.
                    let squared_norm = crate::sparse_norm(&entries);
                    if crate::zero_norm(squared_norm) {
                        zero_norm_structural_rows += 1;
                    } else {
                        match declared_structural_slots.entry(*slot) {
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert(dim);
                            }
                            std::collections::btree_map::Entry::Occupied(entry) => {
                                if *entry.get() != dim {
                                    return Err(SearchError::new(
                                        ASTRO_SEARCH_INDEX_CORPUS,
                                        format!(
                                            "structural slot {} ambient dim {} for {:?} disagrees with declared dim {}",
                                            slot.get(),
                                            dim,
                                            node.qualified_name,
                                            entry.get()
                                        ),
                                        "Every symbol's structural vector for a slot must share one \
                                         ambient dimension; rebuild the vault so the panel measured a \
                                         consistent shape.",
                                    ));
                                }
                            }
                        }
                        structural_rows_read += 1;
                        sparse_vectors.insert(*slot, SlotVector::Sparse { dim, entries });
                    }
                }
                SlotVector::Absent { .. } => absent_slot_rows += 1,
                _ => non_dense_slot_rows += 1,
            }
        }
        symbols.push(CorpusSymbol {
            symbol_id: node.qualified_name,
            name: node.name,
            label: node.label,
            vectors,
            sparse_vectors,
        });
    }

    Ok(CorpusReadReport {
        symbols,
        symbols_total,
        vector_rows_read,
        structural_rows_read,
        absent_slot_rows,
        missing_slot_rows,
        non_dense_slot_rows,
        zero_norm_structural_rows,
        declared_vector_slots,
        declared_structural_slots,
        base_seq: at_seq,
    })
}

/// Freezes a read corpus into a validated, byte-stable [`SlotIndexManifest`].
///
/// Declares the S7 lexical index (always) plus every vector slot that appeared as
/// a dense vector on at least one symbol (from [`CorpusReadReport::declared_vector_slots`]),
/// then adds every symbol's identifier text and dense vectors. Fail-closed via
/// [`SlotIndexSetBuilder::build_manifest`] on any dim/kind mismatch.
pub fn build_manifest_from_corpus(
    report: &CorpusReadReport,
    knobs: IndexKnobs,
) -> Result<SlotIndexManifest, SearchError> {
    let mut builder = SlotIndexSetBuilder::new(knobs);
    builder.declare_lexical(SLOT_LEXICAL_BM25);
    for (slot, dim) in &report.declared_vector_slots {
        builder.declare_vector(*slot, *dim);
    }
    for (slot, dim) in &report.declared_structural_slots {
        builder.declare_structural(*slot, *dim);
    }
    for symbol in &report.symbols {
        builder.add_lexical(
            symbol.symbol_id.clone(),
            SLOT_LEXICAL_BM25,
            symbol.name.clone(),
        );
        for (slot, vector) in &symbol.vectors {
            builder.add_vector(symbol.symbol_id.clone(), *slot, vector);
        }
        for (slot, vector) in &symbol.sparse_vectors {
            if let SlotVector::Sparse { dim, entries } = vector {
                builder.add_structural(symbol.symbol_id.clone(), *slot, *dim, entries);
            }
        }
    }
    builder.build_manifest(report.base_seq)
}

/// End-to-end production owner: reads the vault corpus and freezes the manifest.
/// Returns the manifest and the read report (skip accounting) together so the
/// caller can persist both the artifact and its provenance.
pub fn build_search_index_manifest_from_vault<C>(
    vault: &AsterVault<C>,
    project: &str,
    vector_slots: &[SlotId],
    knobs: IndexKnobs,
) -> Result<(SlotIndexManifest, CorpusReadReport), SearchError>
where
    C: Clock,
{
    let report = read_search_corpus_from_vault(vault, project, vector_slots)?;
    let manifest = build_manifest_from_corpus(&report, knobs)?;
    Ok((manifest, report))
}

/// The freshness of a persisted manifest relative to the live vault sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestFreshness {
    /// The manifest was built against exactly the current vault sequence.
    Fresh,
    /// The vault advanced past the manifest's build sequence: rebuild required.
    Stale {
        /// The sequence the manifest was built against.
        manifest_base_seq: u64,
        /// The current live vault sequence.
        current_seq: u64,
    },
}

/// Compares a manifest's build sequence to the current vault sequence.
/// Fresh iff they are equal — any advance (new import, incremental delta) means
/// the corpus changed and the index must be rebuilt (never served stale).
pub fn manifest_freshness(manifest: &SlotIndexManifest, current_seq: u64) -> ManifestFreshness {
    if manifest.base_seq == current_seq {
        ManifestFreshness::Fresh
    } else {
        ManifestFreshness::Stale {
            manifest_base_seq: manifest.base_seq,
            current_seq,
        }
    }
}

/// Persists a manifest to `path` as its canonical bytes, returning the byte
/// length written. Fail-closed on serialization or I/O error.
pub fn persist_manifest(path: &Path, manifest: &SlotIndexManifest) -> Result<u64, SearchError> {
    let bytes = manifest.to_canonical_bytes()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            SearchError::new(
                ASTRO_SEARCH_PRODUCTION_IO,
                format!("create manifest directory {}: {error}", parent.display()),
                "Ensure the search-index cache directory is writable.",
            )
        })?;
    }
    std::fs::write(path, &bytes).map_err(|error| {
        SearchError::new(
            ASTRO_SEARCH_PRODUCTION_IO,
            format!("write manifest {}: {error}", path.display()),
            "Ensure the search-index cache path is writable.",
        )
    })?;
    Ok(bytes.len() as u64)
}

/// Loads a manifest from `path`, fail-closed on I/O and on parse
/// ([`SlotIndexManifest::from_bytes`] validates the schema).
pub fn load_manifest(path: &Path) -> Result<SlotIndexManifest, SearchError> {
    let bytes = std::fs::read(path).map_err(|error| {
        SearchError::new(
            ASTRO_SEARCH_PRODUCTION_IO,
            format!("read manifest {}: {error}", path.display()),
            "Rebuild the search index for this project; its persisted manifest is unreadable.",
        )
    })?;
    SlotIndexManifest::from_bytes(&bytes)
}

/// Loads a manifest and fail-closes if it is stale against `current_seq`.
/// This is the load path the fused planner must use: it can never rank against a
/// corpus older than the live vault.
pub fn load_manifest_if_fresh(
    path: &Path,
    current_seq: u64,
) -> Result<SlotIndexManifest, SearchError> {
    let manifest = load_manifest(path)?;
    match manifest_freshness(&manifest, current_seq) {
        ManifestFreshness::Fresh => Ok(manifest),
        ManifestFreshness::Stale {
            manifest_base_seq,
            current_seq,
        } => Err(SearchError::new(
            ASTRO_SEARCH_PRODUCTION_STALE,
            format!(
                "persisted search index was built at vault seq {manifest_base_seq} but the live \
                 vault is at seq {current_seq}"
            ),
            "Rebuild the search index (build_search_index_manifest_from_vault) before searching; \
             the fused planner must not rank against a stale corpus.",
        )),
    }
}

/// A symbol-anchored structural query result: the ranked structural neighbors of
/// an anchor symbol, with the anchor itself excluded.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralQueryResult {
    /// The anchor symbol whose persisted S1/S4 vectors drove the query.
    pub anchor_symbol_id: String,
    /// The structural slots actually anchored (each had a persisted vector on the
    /// anchor and a declared structural index in the manifest), in request order.
    pub anchored_slots: Vec<SlotId>,
    /// Ranked neighbors (anchor excluded), best first, at most `k`.
    pub neighbors: Vec<FusedResult>,
}

/// Symbol-anchored structural "more like this" query — a DECLARED mode, never a
/// silently degraded text profile.
///
/// Given an ALREADY-INDEXED `anchor_symbol_id`, this reads that symbol's own
/// persisted sparse structural vectors (S1 struct-trigrams / S4 API-callees) out
/// of the index set's manifest and uses them as the query against the production
/// search index, ranking the corpus by exact sparse cosine and fusing the
/// requested structural slots with RRF. The anchor — its own nearest neighbor at
/// cosine 1.0 — is excluded from the returned neighbor list.
///
/// This is the intended entry point for a future MCP `find_similar` structural
/// mode (#43): it takes a built [`SlotIndexSet`], the anchor symbol id, the
/// structural slots to anchor on ([`STRUCTURAL_QUERY_SLOTS`] or a subset), and
/// the standard `k`/`ef`/`caps`, and returns the fused neighbors.
///
/// Fail-closed contract (no silent fallback, no partial scoring):
/// - empty `structural_slots` => [`ASTRO_SEARCH_STRUCTURAL_NO_SLOTS`];
/// - anchor absent from the manifest => [`ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT`];
/// - a requested slot that is not a declared structural index, **or** for which
///   the anchor holds no persisted vector => [`ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT`]
///   (the whole query refuses — it never partial-scores a subset of the requested
///   structural slots);
/// - `k`/`ef`/slot-count over the declared caps => the planner's `PLAN_COST_EXCEEDED`.
pub fn structural_more_like_this(
    index_set: &SlotIndexSet,
    anchor_symbol_id: &str,
    structural_slots: &[SlotId],
    k: u64,
    ef: u64,
    caps: &SearchCaps,
) -> Result<StructuralQueryResult, SearchError> {
    if structural_slots.is_empty() {
        return Err(SearchError::new(
            ASTRO_SEARCH_STRUCTURAL_NO_SLOTS,
            "structural query requested no structural slots".to_string(),
            "Request at least one structural slot (S1 struct-trigrams and/or S4 API-callees).",
        ));
    }

    let manifest = index_set.manifest();
    let Some(doc) = manifest
        .documents
        .iter()
        .find(|doc| doc.symbol_id == anchor_symbol_id)
    else {
        return Err(SearchError::new(
            ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT,
            format!(
                "anchor symbol {anchor_symbol_id:?} is not present in the search index manifest"
            ),
            "Anchor a structural query on a symbol that was indexed; rebuild the corpus if it \
             should be present.",
        ));
    };

    // Read the anchor's own persisted structural vectors for every requested
    // slot. A single missing slot fails the whole query closed — never a partial.
    let mut query = SlotQuery::default();
    let mut weights: BTreeMap<SlotId, u64> = BTreeMap::new();
    let mut anchored_slots = Vec::with_capacity(structural_slots.len());
    for slot in structural_slots {
        if !index_set.has_slot(*slot) {
            return Err(SearchError::new(
                ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT,
                format!(
                    "slot {} is not a declared structural index in this manifest",
                    slot.get()
                ),
                "Build the manifest with the structural slots declared \
                 (STRUCTURAL_QUERY_SLOTS) before anchoring a structural query on them.",
            ));
        }
        let Some(StoredContent::SparseBits { dim, entries }) = doc.slots.get(slot) else {
            return Err(SearchError::new(
                ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT,
                format!(
                    "anchor symbol {anchor_symbol_id:?} has no persisted structural vector for slot {}",
                    slot.get()
                ),
                "The anchor carries no S1/S4 vector for this slot; choose an anchor whose \
                 structural vectors were persisted, or drop the slot from the request.",
            ));
        };
        let sparse = SlotVector::Sparse {
            dim: *dim,
            entries: entries
                .iter()
                .map(|word| SparseEntry {
                    idx: word.idx,
                    val: f32::from_bits(word.val_bits),
                })
                .collect(),
        };
        query = query.with_sparse_vector(*slot, sparse);
        weights.insert(*slot, WEIGHT_SCALE_MILLIS);
        anchored_slots.push(*slot);
    }

    // Request one extra result so the anchor (its own nearest neighbor at cosine
    // 1.0) can be dropped without shrinking the neighbor list below `k`; clamp to
    // the declared cap so the extra never turns a legal `k` into a cost refusal.
    let internal_k = k.saturating_add(1).min(caps.max_k);
    let request = SearchRequest {
        query: String::new(),
        k: internal_k,
        ef,
        timeout_ms: caps.max_timeout_ms,
        fusion_override_millis: Some(weights),
        temporal_alpha_millis: 0,
    };
    let plan = plan_search(&request, caps)?;
    let empty_filters: BTreeMap<String, String> = BTreeMap::new();
    let empty_attrs: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let empty_recency: BTreeMap<String, u64> = BTreeMap::new();
    let mut results = run_indexed_search(
        &plan,
        index_set,
        &query,
        &empty_filters,
        &empty_attrs,
        &empty_recency,
    )?;
    results.retain(|result| result.symbol_id != anchor_symbol_id);
    results.truncate(k as usize);

    Ok(StructuralQueryResult {
        anchor_symbol_id: anchor_symbol_id.to_string(),
        anchored_slots,
        neighbors: results,
    })
}

/// A symbol-anchored semantic query result: the ranked semantic neighbors of an
/// anchor symbol (its own dense S18/S20 vectors used as the query), anchor
/// excluded. The dense analogue of [`StructuralQueryResult`].
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticQueryResult {
    /// The anchor symbol whose persisted S18/S20 vectors drove the query.
    pub anchor_symbol_id: String,
    /// The semantic slots actually anchored (each had a persisted dense vector on
    /// the anchor and a declared vector index in the manifest), in request order.
    pub anchored_slots: Vec<SlotId>,
    /// Ranked neighbors (anchor excluded), best first, at most `k`.
    pub neighbors: Vec<FusedResult>,
}

/// Symbol-anchored semantic "more like this" query — the dense analogue of
/// [`structural_more_like_this`]. It is the DECLARED semantic mode of a future
/// MCP `find_similar` (#43): given an ALREADY-INDEXED `anchor_symbol_id`, it reads
/// that symbol's own persisted dense semantic vectors (S18 code-semantic / S20
/// name-semantic) out of the manifest and uses them as the query against the
/// production index, ranking the corpus by dense cosine (HNSW) and fusing the
/// requested semantic slots with RRF. The anchor — its own nearest neighbor — is
/// excluded from the returned neighbor list.
///
/// Fail-closed contract (identical shape to [`structural_more_like_this`], no
/// silent fallback, no partial scoring):
/// - empty `semantic_slots` => [`ASTRO_SEARCH_STRUCTURAL_NO_SLOTS`];
/// - anchor absent from the manifest => [`ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT`];
/// - a requested slot that is not a declared vector index, **or** for which the
///   anchor holds no persisted dense vector => [`ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT`]
///   (the whole query refuses — it never partial-scores a subset);
/// - `k`/`ef`/slot-count over the declared caps => the planner's `PLAN_COST_EXCEEDED`.
pub fn semantic_more_like_this(
    index_set: &SlotIndexSet,
    anchor_symbol_id: &str,
    semantic_slots: &[SlotId],
    k: u64,
    ef: u64,
    caps: &SearchCaps,
) -> Result<SemanticQueryResult, SearchError> {
    if semantic_slots.is_empty() {
        return Err(SearchError::new(
            ASTRO_SEARCH_STRUCTURAL_NO_SLOTS,
            "semantic query requested no semantic slots".to_string(),
            "Request at least one semantic slot (S18 code-semantic and/or S20 name-semantic).",
        ));
    }

    let manifest = index_set.manifest();
    let Some(doc) = manifest
        .documents
        .iter()
        .find(|doc| doc.symbol_id == anchor_symbol_id)
    else {
        return Err(SearchError::new(
            ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT,
            format!(
                "anchor symbol {anchor_symbol_id:?} is not present in the search index manifest"
            ),
            "Anchor a semantic query on a symbol that was indexed; rebuild the corpus if it \
             should be present.",
        ));
    };

    let mut query = SlotQuery::default();
    let mut weights: BTreeMap<SlotId, u64> = BTreeMap::new();
    let mut anchored_slots = Vec::with_capacity(semantic_slots.len());
    for slot in semantic_slots {
        if !index_set.has_slot(*slot) {
            return Err(SearchError::new(
                ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT,
                format!(
                    "slot {} is not a declared vector index in this manifest",
                    slot.get()
                ),
                "Build the manifest with the semantic slots declared (SEMANTIC_QUERY_SLOTS) \
                 before anchoring a semantic query on them.",
            ));
        }
        let Some(StoredContent::VectorBits(words)) = doc.slots.get(slot) else {
            return Err(SearchError::new(
                ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT,
                format!(
                    "anchor symbol {anchor_symbol_id:?} has no persisted dense vector for slot {}",
                    slot.get()
                ),
                "The anchor carries no S18/S20 vector for this slot; choose an anchor whose \
                 semantic vectors were persisted, or drop the slot from the request.",
            ));
        };
        let data: Vec<f32> = words.iter().map(|bits| f32::from_bits(*bits)).collect();
        query = query.with_vector(*slot, data);
        weights.insert(*slot, WEIGHT_SCALE_MILLIS);
        anchored_slots.push(*slot);
    }

    // One extra result so the anchor (its own nearest neighbor) can be dropped
    // without shrinking the list below `k`; clamp to the declared cap so the extra
    // never turns a legal `k` into a cost refusal.
    let internal_k = k.saturating_add(1).min(caps.max_k);
    let request = SearchRequest {
        query: String::new(),
        k: internal_k,
        ef,
        timeout_ms: caps.max_timeout_ms,
        fusion_override_millis: Some(weights),
        temporal_alpha_millis: 0,
    };
    let plan = plan_search(&request, caps)?;
    let empty_filters: BTreeMap<String, String> = BTreeMap::new();
    let empty_attrs: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let empty_recency: BTreeMap<String, u64> = BTreeMap::new();
    let mut results = run_indexed_search(
        &plan,
        index_set,
        &query,
        &empty_filters,
        &empty_attrs,
        &empty_recency,
    )?;
    results.retain(|result| result.symbol_id != anchor_symbol_id);
    results.truncate(k as usize);

    Ok(SemanticQueryResult {
        anchor_symbol_id: anchor_symbol_id.to_string(),
        anchored_slots,
        neighbors: results,
    })
}

/// The clone-taxonomy class of a candidate neighbor, decided by which anchored
/// signal(s) surfaced it (#43). Copy-paste shares structure but not (necessarily)
/// semantics; a reimplementation shares semantics but not structure; a true clone
/// shares both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneClass {
    /// Surfaced only by the structural (S1/S4) signal — copy-paste / near-textual.
    CopyPaste,
    /// Surfaced only by the semantic (S18/S20) signal — reimplementation.
    Reimplementation,
    /// Surfaced by BOTH signals — a true clone (structure and semantics agree).
    TrueClone,
}

impl CloneClass {
    /// Stable string label for the response envelope.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CopyPaste => "copy_paste",
            Self::Reimplementation => "reimplementation",
            Self::TrueClone => "true_clone",
        }
    }
}

/// One classified clone candidate: the neighbor symbol, its taxonomy class, and
/// the best (lowest, i.e. nearest) rank it achieved under each signal (`None` when
/// that signal did not surface it). Ranks are 0-based positions in each signal's
/// neighbor list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneCandidate {
    /// The neighbor symbol id.
    pub symbol_id: String,
    /// The clone-taxonomy class.
    pub class: CloneClass,
    /// 0-based rank under the structural signal, if it surfaced this symbol.
    pub structural_rank: Option<usize>,
    /// 0-based rank under the semantic signal, if it surfaced this symbol.
    pub semantic_rank: Option<usize>,
}

/// Classifies clone candidates by fusing a structural neighbor list and a semantic
/// neighbor list into the clone taxonomy (#43): present in both => true clone;
/// structural only => copy-paste; semantic only => reimplementation.
///
/// Pure and deterministic: the two inputs are ordered neighbor id lists (as
/// returned by [`structural_more_like_this`] / [`semantic_more_like_this`], anchor
/// already excluded). The output is ordered true-clone first, then copy-paste,
/// then reimplementation; within a class by ascending combined rank
/// (structural_rank + semantic_rank, missing side counted as its list length) so
/// the ordering is stable and never depends on iteration nondeterminism.
pub fn classify_clone_taxonomy(
    structural_neighbors: &[String],
    semantic_neighbors: &[String],
) -> Vec<CloneCandidate> {
    let structural_rank: BTreeMap<&str, usize> = structural_neighbors
        .iter()
        .enumerate()
        .map(|(rank, id)| (id.as_str(), rank))
        .collect();
    let semantic_rank: BTreeMap<&str, usize> = semantic_neighbors
        .iter()
        .enumerate()
        .map(|(rank, id)| (id.as_str(), rank))
        .collect();

    // Union of both neighbor sets, deduplicated, deterministic order.
    let mut ids: Vec<&str> = Vec::new();
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for id in structural_neighbors.iter().chain(semantic_neighbors.iter()) {
        if seen.insert(id.as_str()) {
            ids.push(id.as_str());
        }
    }

    let mut candidates: Vec<CloneCandidate> = ids
        .into_iter()
        .map(|id| {
            let s_rank = structural_rank.get(id).copied();
            let m_rank = semantic_rank.get(id).copied();
            let class = match (s_rank.is_some(), m_rank.is_some()) {
                (true, true) => CloneClass::TrueClone,
                (true, false) => CloneClass::CopyPaste,
                (false, true) => CloneClass::Reimplementation,
                // Unreachable: every id came from at least one list.
                (false, false) => CloneClass::Reimplementation,
            };
            CloneCandidate {
                symbol_id: id.to_string(),
                class,
                structural_rank: s_rank,
                semantic_rank: m_rank,
            }
        })
        .collect();

    let class_order = |class: CloneClass| match class {
        CloneClass::TrueClone => 0u8,
        CloneClass::CopyPaste => 1,
        CloneClass::Reimplementation => 2,
    };
    let s_len = structural_neighbors.len();
    let m_len = semantic_neighbors.len();
    candidates.sort_by(|a, b| {
        class_order(a.class)
            .cmp(&class_order(b.class))
            .then_with(|| {
                let a_combined =
                    a.structural_rank.unwrap_or(s_len) + a.semantic_rank.unwrap_or(m_len);
                let b_combined =
                    b.structural_rank.unwrap_or(s_len) + b.semantic_rank.unwrap_or(m_len);
                a_combined.cmp(&b_combined)
            })
            .then_with(|| a.symbol_id.cmp(&b.symbol_id))
    });
    candidates
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use astrolabe_ingest::{
        CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, SqliteImportOptions,
        import_cbm_graph_snapshot_to_vault_direct,
    };
    use astrolabe_panel::FixtureSlotRuntime;
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{SystemClock, VaultId};

    fn test_vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV"
            .parse()
            .expect("parse test vault id")
    }

    use super::*;
    use crate::search::{SearchCaps, SearchRequest, plan_search};
    use crate::search_index::{SlotIndexSet, SlotQuery, run_indexed_search};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-weave-searchprod-{name}-{}-{}",
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
            b"astrolabe-searchprod-test-salt".to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable vault")
    }

    fn node(id: i64, label: &str, name: &str, qn: &str, snippet: &str) -> CbmGraphNode {
        CbmGraphNode {
            source_node_id: id,
            project: "demo".to_string(),
            label: label.to_string(),
            name: name.to_string(),
            qualified_name: qn.to_string(),
            file_path: "src/lib.rs".to_string(),
            start_line: id * 10,
            end_line: id * 10 + 5,
            properties_json: format!(
                r#"{{"language":"rust","source_snippet":{snippet:?},"signature":"fn {name}()"}}"#
            ),
            node_vector: None,
            cx_id: None,
            structural: false,
        }
    }

    fn demo_snapshot() -> CbmGraphSnapshot {
        CbmGraphSnapshot {
            project: "demo".to_string(),
            panel_version: Some(1),
            projects: Vec::new(),
            nodes: vec![
                node(
                    1,
                    "Function",
                    "parse_config",
                    "demo.cfg.parse_config",
                    "fn parse_config() {}",
                ),
                node(
                    2,
                    "Function",
                    "parse_args",
                    "demo.cli.parse_args",
                    "fn parse_args() {}",
                ),
                node(
                    3,
                    "Method",
                    "http_server",
                    "demo.net.http_server",
                    "fn http_server() {}",
                ),
            ],
            edges: Vec::<CbmGraphEdge>::new(),
            file_hashes: Vec::new(),
            project_summaries: Vec::new(),
            token_vectors: Vec::new(),
        }
    }

    fn import_demo(vault: &AsterVault<SystemClock>) {
        import_cbm_graph_snapshot_to_vault_direct(
            &demo_snapshot(),
            [5u8; 32],
            vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-1", 1),
        )
        .expect("import demo snapshot to vault");
    }

    // FSV: build a real vault, read the corpus, freeze the manifest, persist it,
    // read the persisted bytes back independently, rebuild the live index set,
    // and run a real fused search — proving the whole production lifecycle end to
    // end against persisted state, never a mock.
    #[test]
    fn production_owner_builds_persists_and_searches_a_real_vault_fsv() {
        let dir = temp_dir("fsv");
        let vault = open_vault(&dir.join("vault"));
        import_demo(&vault);

        let (manifest, report) = build_search_index_manifest_from_vault(
            &vault,
            "demo",
            &PRODUCTION_VECTOR_SLOTS,
            IndexKnobs::defaults(0x51A3),
        )
        .expect("build manifest from vault");

        // Corpus accounting: 3 non-structural symbols, every skip labeled.
        assert_eq!(report.symbols_total, 3);
        assert_eq!(report.symbols.len(), 3);
        assert_eq!(report.base_seq, vault.latest_seq());
        // The S7 lexical slot is always declared; the manifest documents all 3.
        assert_eq!(manifest.documents.len(), 3);
        assert!(manifest.slots.iter().any(|s| s.slot == SLOT_LEXICAL_BM25));

        // Persist, then independently read the bytes back.
        let path = dir.join("search_index.v1.json");
        let written = persist_manifest(&path, &manifest).expect("persist manifest");
        let read_back = std::fs::read(&path).expect("read manifest bytes");
        assert_eq!(written as usize, read_back.len());
        let reloaded = SlotIndexManifest::from_bytes(&read_back).expect("parse persisted manifest");
        assert_eq!(
            reloaded, manifest,
            "persisted manifest round-trips byte-identically"
        );
        assert_eq!(
            reloaded.content_hash().expect("hash a"),
            manifest.content_hash().expect("hash b"),
        );

        // Rebuild the live index set from the persisted manifest and run a real
        // fused search over the S7 lexical slot (text-only query, no query
        // vectors) using an explicit S7-only fusion override.
        let index_set = SlotIndexSet::from_manifest(&reloaded).expect("rebuild index set");
        assert_eq!(index_set.built_at_seq(), report.base_seq);

        let request = SearchRequest {
            query: "parse config".to_string(),
            k: 10,
            ef: 64,
            timeout_ms: 1_000,
            fusion_override_millis: Some([(SLOT_LEXICAL_BM25, 1_000)].into_iter().collect()),
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&request, &SearchCaps::default_caps()).expect("plan");
        let results = run_indexed_search(
            &plan,
            &index_set,
            &SlotQuery::text("parse config"),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect("indexed search");
        // parse_config / parse_args both share the "parse" token; the query must
        // surface parse_config first (it matches both tokens).
        assert_eq!(
            results.first().map(|r| r.symbol_id.as_str()),
            Some("demo.cfg.parse_config")
        );
        assert!(
            results.iter().any(|r| r.symbol_id == "demo.cli.parse_args"),
            "the shared 'parse' token must also surface parse_args"
        );
    }

    // Edge 1: two independent reads of the same vault produce byte-identical
    // manifests (worker-count invariant / deterministic corpus read).
    #[test]
    fn two_reads_of_one_vault_produce_identical_manifests_fsv() {
        let dir = temp_dir("determinism");
        let vault = open_vault(&dir.join("vault"));
        import_demo(&vault);

        let knobs = IndexKnobs::defaults(0x99);
        let (a, _) =
            build_search_index_manifest_from_vault(&vault, "demo", &PRODUCTION_VECTOR_SLOTS, knobs)
                .expect("build a");
        let (b, _) =
            build_search_index_manifest_from_vault(&vault, "demo", &PRODUCTION_VECTOR_SLOTS, knobs)
                .expect("build b");
        assert_eq!(
            a.to_canonical_bytes().unwrap(),
            b.to_canonical_bytes().unwrap()
        );
        assert_eq!(a.content_hash().unwrap(), b.content_hash().unwrap());
    }

    // Edge 2: freshness fail-closes. A manifest built at the current seq is Fresh;
    // once the vault advances (a second import), load_manifest_if_fresh refuses
    // with ASTRO_SEARCH_PRODUCTION_STALE rather than serving the stale index.
    #[test]
    fn stale_manifest_is_refused_fail_closed_fsv() {
        let dir = temp_dir("stale");
        let vault = open_vault(&dir.join("vault"));
        import_demo(&vault);

        let (manifest, _) = build_search_index_manifest_from_vault(
            &vault,
            "demo",
            &PRODUCTION_VECTOR_SLOTS,
            IndexKnobs::defaults(1),
        )
        .expect("build manifest");
        let path = dir.join("index.json");
        persist_manifest(&path, &manifest).expect("persist");

        // Fresh at the build sequence.
        assert_eq!(
            manifest_freshness(&manifest, vault.latest_seq()),
            ManifestFreshness::Fresh
        );
        load_manifest_if_fresh(&path, vault.latest_seq()).expect("fresh load ok");

        // Advance the vault: re-import a changed snapshot so the sequence moves.
        let mut changed = demo_snapshot();
        changed.nodes.push(node(
            4,
            "Function",
            "auth_check",
            "demo.sec.auth_check",
            "fn auth_check() {}",
        ));
        import_cbm_graph_snapshot_to_vault_direct(
            &changed,
            [6u8; 32],
            &vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-2", 1),
        )
        .expect("second import");
        let now = vault.latest_seq();
        assert!(now > manifest.base_seq, "vault sequence must advance");
        assert!(matches!(
            manifest_freshness(&manifest, now),
            ManifestFreshness::Stale { .. }
        ));
        let err = load_manifest_if_fresh(&path, now).expect_err("stale load must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_PRODUCTION_STALE);
    }

    // Edge 3a: reading a project that was never imported fail-closes (the
    // snapshot reader refuses an unknown project), never returns a silent empty.
    #[test]
    fn unknown_project_read_is_refused_fail_closed_fsv() {
        let dir = temp_dir("unknown");
        let vault = open_vault(&dir.join("vault"));
        import_demo(&vault);

        let err = read_search_corpus_from_vault(&vault, "not-a-project", &PRODUCTION_VECTOR_SLOTS)
            .expect_err("unknown project must be refused, not served empty");
        assert_eq!(err.code(), ASTRO_SEARCH_PRODUCTION_VAULT);
        assert!(
            err.message().contains("MISSING_CBM_PROJECT_ROW"),
            "{}",
            err.message()
        );
    }

    // Edge 3b: the empty-corpus assembly path yields a well-formed S7-only,
    // zero-document manifest — a labeled empty, not a crash and not a guess.
    #[test]
    fn empty_corpus_yields_s7_only_manifest() {
        let report = CorpusReadReport {
            symbols: Vec::new(),
            symbols_total: 0,
            vector_rows_read: 0,
            structural_rows_read: 0,
            absent_slot_rows: 0,
            missing_slot_rows: 0,
            non_dense_slot_rows: 0,
            zero_norm_structural_rows: 0,
            declared_vector_slots: BTreeMap::new(),
            declared_structural_slots: BTreeMap::new(),
            base_seq: 0,
        };
        let manifest =
            build_manifest_from_corpus(&report, IndexKnobs::defaults(0)).expect("empty manifest");
        assert!(manifest.documents.is_empty());
        // S7 lexical is still declared (the schema is always well-formed).
        assert_eq!(manifest.slots.len(), 1);
        assert_eq!(manifest.slots[0].slot, SLOT_LEXICAL_BM25);
    }

    // --- Symbol-anchored structural query mode (#332) --------------------------

    fn sparse_entries(entries: &[(u32, f32)]) -> Vec<SparseEntry> {
        entries
            .iter()
            .map(|(idx, val)| SparseEntry {
                idx: *idx,
                val: *val,
            })
            .collect()
    }

    /// Hand-built structural manifest: S1 declared sparse with multi-coordinate
    /// vectors, so cosine truly separates neighbors (the panel fixture's
    /// single-coordinate S1 vectors all tie at cosine 1.0).
    fn structural_manifest(base_seq: u64) -> SlotIndexManifest {
        const DIM: u32 = 16;
        let mut builder = SlotIndexSetBuilder::new(IndexKnobs::defaults(0x5732));
        builder.declare_structural(SLOT_STRUCT_TRIGRAMS, DIM);
        builder.add_structural(
            "demo.anchor",
            SLOT_STRUCT_TRIGRAMS,
            DIM,
            &sparse_entries(&[(0, 1.0), (1, 1.0), (2, 1.0)]),
        );
        builder.add_structural(
            "demo.near",
            SLOT_STRUCT_TRIGRAMS,
            DIM,
            &sparse_entries(&[(0, 1.0), (1, 1.0), (4, 0.3)]),
        );
        builder.add_structural(
            "demo.far",
            SLOT_STRUCT_TRIGRAMS,
            DIM,
            &sparse_entries(&[(10, 1.0), (11, 1.0)]),
        );
        builder
            .build_manifest(base_seq)
            .expect("structural manifest")
    }

    // FSV: persist a structural manifest, read the bytes back independently,
    // rebuild, and run the symbol-anchored query TWICE — proving a real persisted
    // structural corpus ranks deterministically, excludes the anchor, and orders
    // neighbors by true sparse cosine (near before far).
    #[test]
    fn structural_more_like_this_ranks_persisted_vectors_fsv() {
        let dir = temp_dir("struct-fsv");
        let path = dir.join("structural_index.v1.json");
        let manifest = structural_manifest(9);
        let written = persist_manifest(&path, &manifest).expect("persist");
        println!(
            "FSV before: wrote {written} structural manifest bytes to {}",
            path.display()
        );

        let run = || {
            let bytes = std::fs::read(&path).expect("read bytes");
            let reloaded = SlotIndexManifest::from_bytes(&bytes).expect("parse");
            let set = SlotIndexSet::from_manifest(&reloaded).expect("build");
            structural_more_like_this(
                &set,
                "demo.anchor",
                &[SLOT_STRUCT_TRIGRAMS],
                5,
                32,
                &SearchCaps::default_caps(),
            )
            .expect("structural query")
        };
        let a = run();
        let b = run();
        let ids: Vec<&str> = a.neighbors.iter().map(|n| n.symbol_id.as_str()).collect();
        println!(
            "FSV after: anchor={} anchored_slots={:?} neighbors={ids:?}",
            a.anchor_symbol_id, a.anchored_slots
        );
        assert_eq!(a, b, "two persisted-bytes readbacks must rank identically");
        assert_eq!(a.anchored_slots, vec![SLOT_STRUCT_TRIGRAMS]);
        assert!(
            !ids.contains(&"demo.anchor"),
            "anchor is excluded from its own neighbor list"
        );
        assert_eq!(
            ids,
            vec!["demo.near", "demo.far"],
            "near neighbor must outrank the disjoint far one"
        );
    }

    // FSV: real vault path. Import a real snapshot, build the structural manifest
    // from the persisted (sparse) S1/S4 slot rows, read it back from disk, and
    // query a real symbol — proving the whole vault -> structural-manifest ->
    // ranked-neighbor lifecycle over genuinely persisted state.
    #[test]
    fn structural_mode_serves_real_persisted_s1_s4_vectors_fsv() {
        let dir = temp_dir("struct-vault");
        let vault = open_vault(&dir.join("vault"));
        import_demo(&vault);

        let (manifest, report) = build_search_index_manifest_from_vault(
            &vault,
            "demo",
            &STRUCTURAL_QUERY_SLOTS,
            IndexKnobs::defaults(0xA1),
        )
        .expect("build structural manifest from vault");
        println!(
            "FSV before: structural_rows_read={} declared_structural_slots={:?} skips={}",
            report.structural_rows_read,
            report.declared_structural_slots,
            report.skip_count()
        );
        assert!(
            report.structural_rows_read > 0,
            "real persisted S1/S4 sparse vectors must be admitted, not skipped"
        );
        assert!(
            report
                .declared_structural_slots
                .contains_key(&SLOT_STRUCT_TRIGRAMS),
            "S1 must be a declared structural slot"
        );
        assert!(
            report
                .declared_structural_slots
                .contains_key(&SLOT_API_CALLEES),
            "S4 must be a declared structural slot"
        );

        let path = dir.join("struct.json");
        persist_manifest(&path, &manifest).expect("persist");
        let reloaded =
            SlotIndexManifest::from_bytes(&std::fs::read(&path).expect("read")).expect("parse");
        let set = SlotIndexSet::from_manifest(&reloaded).expect("rebuild index set");
        let result = structural_more_like_this(
            &set,
            "demo.cfg.parse_config",
            &STRUCTURAL_QUERY_SLOTS,
            5,
            32,
            &SearchCaps::default_caps(),
        )
        .expect("structural query on a real symbol");
        let ids: Vec<&str> = result
            .neighbors
            .iter()
            .map(|n| n.symbol_id.as_str())
            .collect();
        println!("FSV after: structural neighbors of parse_config = {ids:?}");
        assert!(
            !ids.contains(&"demo.cfg.parse_config"),
            "anchor excluded from its own neighbors"
        );
        assert!(
            !ids.is_empty(),
            "a real symbol's structural query returns neighbors"
        );
    }

    // Edge triad (+): anchor absent, requested slot absent (declared-but-missing
    // AND undeclared), empty manifest, and no-slots — every one a labeled refusal,
    // never a partial score or a silent empty.
    #[test]
    fn structural_query_edges_are_all_fail_closed() {
        let caps = SearchCaps::default_caps();
        let set = SlotIndexSet::from_manifest(&structural_manifest(1)).expect("build");

        // Edge 1: anchor symbol not in the manifest.
        println!("edge anchor-absent before: manifest holds anchor/near/far only");
        let err =
            structural_more_like_this(&set, "demo.ghost", &[SLOT_STRUCT_TRIGRAMS], 5, 32, &caps)
                .expect_err("absent anchor must refuse");
        println!("edge anchor-absent after: code={}", err.code());
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT);

        // Edge 2: requested slot (S4) is not a declared structural index here.
        let err = structural_more_like_this(&set, "demo.anchor", &[SLOT_API_CALLEES], 5, 32, &caps)
            .expect_err("undeclared structural slot must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT);

        // Edge 2b: slot IS declared, but this anchor holds no vector for it —
        // fail-closed, never partial-scored on the slots it does have.
        let mut builder = SlotIndexSetBuilder::new(IndexKnobs::defaults(7));
        builder.declare_structural(SLOT_STRUCT_TRIGRAMS, 16);
        builder.declare_structural(SLOT_API_CALLEES, 16);
        builder.add_structural(
            "demo.only_s1",
            SLOT_STRUCT_TRIGRAMS,
            16,
            &sparse_entries(&[(0, 1.0), (1, 1.0)]),
        );
        let partial_set =
            SlotIndexSet::from_manifest(&builder.build_manifest(2).expect("m")).expect("s");
        println!("edge slot-absent before: demo.only_s1 has S1 but no S4 vector");
        let err = structural_more_like_this(
            &partial_set,
            "demo.only_s1",
            &[SLOT_API_CALLEES],
            5,
            32,
            &caps,
        )
        .expect_err("declared-but-missing anchor vector must refuse");
        println!("edge slot-absent after: code={}", err.code());
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT);

        // Edge 3: empty manifest — no documents, so any anchor is absent.
        let empty = SlotIndexSetBuilder::new(IndexKnobs::defaults(0))
            .build_manifest(0)
            .expect("empty manifest");
        let empty_set = SlotIndexSet::from_manifest(&empty).expect("build empty");
        println!("edge empty before: manifest has 0 documents");
        let err = structural_more_like_this(
            &empty_set,
            "demo.anchor",
            &[SLOT_STRUCT_TRIGRAMS],
            5,
            32,
            &caps,
        )
        .expect_err("empty manifest must refuse");
        println!("edge empty after: code={}", err.code());
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT);

        // Edge 4: no structural slots requested at all.
        let err = structural_more_like_this(&set, "demo.anchor", &[], 5, 32, &caps)
            .expect_err("no slots must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_NO_SLOTS);
    }

    // --- Symbol-anchored semantic query mode + clone taxonomy (#43) ------------

    /// Hand-built dense semantic manifest: S18 declared as a dim-4 vector index
    /// with vectors chosen so cosine separates near from far.
    fn semantic_manifest(base_seq: u64) -> SlotIndexManifest {
        const DIM: u32 = 4;
        let mut builder = SlotIndexSetBuilder::new(IndexKnobs::defaults(0x5EED));
        builder.declare_vector(SLOT_CODE_SEMANTIC, DIM);
        builder.add_vector("demo.anchor", SLOT_CODE_SEMANTIC, &[1.0, 0.0, 0.0, 0.0]);
        builder.add_vector("demo.near", SLOT_CODE_SEMANTIC, &[0.9, 0.1, 0.0, 0.0]);
        builder.add_vector("demo.far", SLOT_CODE_SEMANTIC, &[0.0, 0.0, 1.0, 0.0]);
        builder.build_manifest(base_seq).expect("semantic manifest")
    }

    // FSV: persist a dense semantic manifest, read the bytes back independently,
    // rebuild, and run the symbol-anchored semantic query TWICE — proving a real
    // persisted dense corpus ranks deterministically, excludes the anchor, and
    // orders neighbors by dense cosine (near before far).
    #[test]
    fn semantic_more_like_this_ranks_persisted_dense_vectors_fsv() {
        let dir = temp_dir("semantic-fsv");
        let path = dir.join("semantic_index.v1.json");
        let manifest = semantic_manifest(11);
        let written = persist_manifest(&path, &manifest).expect("persist");
        println!(
            "FSV before: wrote {written} semantic manifest bytes to {}",
            path.display()
        );

        let run = || {
            let bytes = std::fs::read(&path).expect("read bytes");
            let reloaded = SlotIndexManifest::from_bytes(&bytes).expect("parse");
            let set = SlotIndexSet::from_manifest(&reloaded).expect("build");
            semantic_more_like_this(
                &set,
                "demo.anchor",
                &[SLOT_CODE_SEMANTIC],
                5,
                32,
                &SearchCaps::default_caps(),
            )
            .expect("semantic query")
        };
        let a = run();
        let b = run();
        let ids: Vec<&str> = a.neighbors.iter().map(|n| n.symbol_id.as_str()).collect();
        println!(
            "FSV after: anchor={} anchored_slots={:?} neighbors={ids:?}",
            a.anchor_symbol_id, a.anchored_slots
        );
        assert_eq!(a, b, "two persisted-bytes readbacks must rank identically");
        assert_eq!(a.anchored_slots, vec![SLOT_CODE_SEMANTIC]);
        assert!(
            !ids.contains(&"demo.anchor"),
            "anchor excluded from its own neighbor list"
        );
        assert_eq!(
            ids,
            vec!["demo.near", "demo.far"],
            "near neighbor must outrank the disjoint far one"
        );
    }

    // Edge triad: semantic anchor absent / undeclared slot / declared-but-missing
    // anchor vector / no slots — every one a labeled refusal, mirroring the
    // structural mode's fail-closed contract.
    #[test]
    fn semantic_query_edges_are_all_fail_closed() {
        let caps = SearchCaps::default_caps();
        let set = SlotIndexSet::from_manifest(&semantic_manifest(1)).expect("build");

        let err = semantic_more_like_this(&set, "demo.ghost", &[SLOT_CODE_SEMANTIC], 5, 32, &caps)
            .expect_err("absent anchor must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_ANCHOR_ABSENT);

        // S20 is not declared in this manifest.
        let err = semantic_more_like_this(&set, "demo.anchor", &[SLOT_NAME_SEMANTIC], 5, 32, &caps)
            .expect_err("undeclared vector slot must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_SLOT_ABSENT);

        let err = semantic_more_like_this(&set, "demo.anchor", &[], 5, 32, &caps)
            .expect_err("no slots must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_STRUCTURAL_NO_SLOTS);
    }

    // Pure FSV of the clone taxonomy: a candidate in BOTH neighbor lists is a true
    // clone, structural-only is copy-paste, semantic-only is reimplementation, and
    // the ordering is deterministic (true_clone first, then by combined rank).
    #[test]
    fn classify_clone_taxonomy_partitions_by_signal() {
        let structural = vec!["sym.true".to_string(), "sym.copy".to_string()];
        let semantic = vec!["sym.true".to_string(), "sym.reimpl".to_string()];
        let classified = classify_clone_taxonomy(&structural, &semantic);
        println!(
            "clone taxonomy: {:?}",
            classified
                .iter()
                .map(|c| (c.symbol_id.as_str(), c.class.as_str()))
                .collect::<Vec<_>>()
        );

        assert_eq!(
            classified.len(),
            3,
            "union of {{true,copy}} and {{true,reimpl}}"
        );
        // True clone ranks first.
        assert_eq!(classified[0].symbol_id, "sym.true");
        assert_eq!(classified[0].class, CloneClass::TrueClone);
        assert_eq!(classified[0].structural_rank, Some(0));
        assert_eq!(classified[0].semantic_rank, Some(0));
        // Copy-paste (structural only) next.
        assert_eq!(classified[1].symbol_id, "sym.copy");
        assert_eq!(classified[1].class, CloneClass::CopyPaste);
        assert_eq!(classified[1].semantic_rank, None);
        // Reimplementation (semantic only) last.
        assert_eq!(classified[2].symbol_id, "sym.reimpl");
        assert_eq!(classified[2].class, CloneClass::Reimplementation);
        assert_eq!(classified[2].structural_rank, None);

        // Deterministic: reclassifying the same inputs yields identical output.
        assert_eq!(classify_clone_taxonomy(&structural, &semantic), classified);

        // Disjoint lists => no true clones.
        let disjoint = classify_clone_taxonomy(&["a".to_string()], &["b".to_string()]);
        assert!(!disjoint.iter().any(|c| c.class == CloneClass::TrueClone));
    }
}
