//! Per-slot index construction for the Sextant-fused engine (P6.6, #42).
//!
//! [`search`](crate::search) is the deterministic fusion/planner spine; this
//! module is the missing half it consumes: **real per-slot indexes** built over
//! a real corpus, persisted to a byte-stable manifest, and driven by the
//! existing planner via [`run_indexed_search`].
//!
//! Two index kinds are wired, both reusing the vendored `calyx-sextant`
//! primitives (no new search engine — the Calyx universality claim, blueprint
//! anti-pattern list):
//!
//! - **Lexical BM25** ([`calyx_sextant::InvertedIndex`]) for the S7
//!   `identifier_lexical` slot, fed camelCase/snake-split tokens (tokenizer
//!   parity, blueprint §12 table). Calyx pins Okapi BM25 at `k1=1.2, b=0.75`
//!   (Robertson et al., *Okapi at TREC-3*, 1994; the Lucene/Elasticsearch
//!   default).
//! - **Dense HNSW** ([`calyx_sextant::HnswIndex`]) for the semantic/structural
//!   vector slots (S18/S19/S20, S1, S4, S21/S2), with deterministic levels
//!   (`level_for(cx_id, ordinal)`) and `M = 32` neighbours (Malkov & Yashunin
//!   HNSW; the high-recall profile the blueprint fixes for code search).
//!
//! Out of scope, tracked elsewhere (labeled skips, never silent):
//! - **SPANN/DiskANN** posture is #72 — not built here.
//! - **Kernel-member index** is blocked by #37 — not built here.
//!
//! Determinism: construction inserts documents in canonical (sorted
//! symbol-id) order, `calyx-sextant` breaks every score tie by id
//! (`util::top_k`), and the whole build/search path is single-threaded, so
//! results are worker-count invariant and identical across independent builds
//! from the same manifest bytes (FSV: proven in the tests).

use std::collections::BTreeMap;

use calyx_core::{CxId, SlotId, SlotVector};
use calyx_sextant::{HnswIndex, IndexStats, InvertedIndex, SextantIndex};
use serde::{Deserialize, Serialize};

use crate::search::{
    FusedResult, SearchError, SearchPlan, SlotRanking, apply_exact_filters, apply_temporal_boost,
    fuse_rrf,
};

/// Manifest schema id carried by every persisted index set.
pub const SEARCH_INDEX_SCHEMA: &str = "astrolabe.search_index.v1";
/// Registry version for the per-slot index knobs below.
pub const SEARCH_INDEX_KNOB_REGISTRY_VERSION: &str = "astro.weave.search_index_knobs.v1";

/// Fail-closed: a planned slot has no constructed index (never a scan fallback).
pub const ASTRO_SEARCH_INDEX_ABSENT: &str = "ASTRO_SEARCH_INDEX_ABSENT";
/// Fail-closed: a planned vector slot received no query vector.
pub const ASTRO_SEARCH_INDEX_QUERY_MISSING: &str = "ASTRO_SEARCH_INDEX_QUERY_MISSING";
/// Fail-closed: a knob was set to a value the vendored index cannot honor.
pub const ASTRO_SEARCH_INDEX_KNOB_UNSUPPORTED: &str = "ASTRO_SEARCH_INDEX_KNOB_UNSUPPORTED";
/// Fail-closed: corpus/document shape is invalid (dim mismatch, undeclared slot…).
pub const ASTRO_SEARCH_INDEX_CORPUS: &str = "ASTRO_SEARCH_INDEX_CORPUS";
/// Fail-closed: a vendored index operation failed (wrapped Calyx error).
pub const ASTRO_SEARCH_INDEX_BUILD: &str = "ASTRO_SEARCH_INDEX_BUILD";
/// Fail-closed: persisted manifest bytes did not parse.
pub const ASTRO_SEARCH_INDEX_MANIFEST: &str = "ASTRO_SEARCH_INDEX_MANIFEST";

/// BM25 term-frequency saturation `k1`, in millis (1200 == 1.2). Declared knob;
/// cited default from Robertson et al. / Lucene / Elasticsearch. The vendored
/// [`calyx_sextant::InvertedIndex`] pins BM25 at this value, so any other
/// setting is refused fail-closed rather than silently ignored.
pub const BM25_K1_MILLIS: u64 = 1_200;
/// BM25 length-normalization `b`, in millis (750 == 0.75). Declared knob; same
/// cited default and same pinned-parity contract as [`BM25_K1_MILLIS`].
pub const BM25_B_MILLIS: u64 = 750;
/// HNSW max neighbours `M`. Declared knob; the vendored [`calyx_sextant::HnswIndex`]
/// pins `M = 32` (Malkov & Yashunin; the blueprint's high-recall code-search
/// profile). Any other value is refused fail-closed.
pub const HNSW_M: u32 = 32;
/// HNSW default query effort `ef_search` (Malkov & Yashunin balanced default 64).
/// This is only a default; a plan's per-slot `ef` (planner-capped) overrides it.
pub const HNSW_EF_SEARCH_DEFAULT: u64 = 64;

/// Declared per-slot index knobs (registry
/// [`SEARCH_INDEX_KNOB_REGISTRY_VERSION`]). Every field is a declared knob with
/// a cited default; none is a bare inline constant.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexKnobs {
    /// BM25 `k1` in millis (see [`BM25_K1_MILLIS`]).
    pub bm25_k1_millis: u64,
    /// BM25 `b` in millis (see [`BM25_B_MILLIS`]).
    pub bm25_b_millis: u64,
    /// HNSW neighbour count `M` (see [`HNSW_M`]).
    pub hnsw_m: u32,
    /// HNSW default `ef_search` (see [`HNSW_EF_SEARCH_DEFAULT`]).
    pub hnsw_ef_search: u64,
    /// Deterministic construction seed (feeds HNSW `level_for`).
    pub seed: u64,
}

impl IndexKnobs {
    /// Blueprint-default knobs at the given deterministic seed.
    pub const fn defaults(seed: u64) -> Self {
        Self {
            bm25_k1_millis: BM25_K1_MILLIS,
            bm25_b_millis: BM25_B_MILLIS,
            hnsw_m: HNSW_M,
            hnsw_ef_search: HNSW_EF_SEARCH_DEFAULT,
            seed,
        }
    }

    /// Refuses any knob the vendored index cannot honor. BM25 `k1`/`b` and HNSW
    /// `M` are pinned inside `calyx-sextant`; we declare them but cannot inject a
    /// different value, so honoring a custom setting would be a silent lie.
    fn validate(&self) -> Result<(), SearchError> {
        if self.bm25_k1_millis != BM25_K1_MILLIS || self.bm25_b_millis != BM25_B_MILLIS {
            return Err(SearchError::new(
                ASTRO_SEARCH_INDEX_KNOB_UNSUPPORTED,
                format!(
                    "BM25 k1={}/b={} millis requested, but the lexical index is pinned at k1={}/b={}",
                    self.bm25_k1_millis, self.bm25_b_millis, BM25_K1_MILLIS, BM25_B_MILLIS
                ),
                "Use the pinned BM25 defaults (k1=1.2, b=0.75); custom BM25 parameters require a \
                 tracked calyx-sextant change, not a silently-ignored knob.",
            ));
        }
        if self.hnsw_m != HNSW_M {
            return Err(SearchError::new(
                ASTRO_SEARCH_INDEX_KNOB_UNSUPPORTED,
                format!(
                    "HNSW M={} requested, but the vendored index is pinned at M={}",
                    self.hnsw_m, HNSW_M
                ),
                "Use the pinned HNSW M=32; a different neighbour count requires a tracked \
                 calyx-sextant change.",
            ));
        }
        Ok(())
    }
}

/// The kind of index a slot carries.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotIndexKind {
    /// BM25 inverted index over camelCase/snake-split identifier tokens.
    Lexical,
    /// Dense HNSW index over `dim`-dimensional vectors.
    Vector { dim: u32 },
}

/// One slot's declared index kind (manifest entry).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlotSpec {
    pub slot: SlotId,
    pub kind: SlotIndexKind,
}

/// One document's content for one slot, in a byte-stable form. Dense vectors are
/// stored as IEEE-754 bit patterns (`f32::to_bits`) so the manifest serializes
/// identically on every platform (no float-formatting drift in the content hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredContent {
    /// Raw identifier text; split into tokens deterministically at build time.
    Text(String),
    /// Dense vector as `f32::to_bits` words.
    VectorBits(Vec<u32>),
}

/// One document (a symbol) with per-slot content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocEntry {
    pub symbol_id: String,
    /// Per-slot content, sorted by slot id (a `BTreeMap` guarantees the order).
    pub slots: BTreeMap<SlotId, StoredContent>,
}

/// The persistable per-slot index definition: the byte source of truth. Rebuilt
/// into live indexes by [`SlotIndexSet::from_manifest`]. Field ordering plus the
/// sorted `slots`/`documents` vectors make [`Self::to_canonical_bytes`]
/// byte-stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotIndexManifest {
    pub schema: String,
    pub knob_registry_version: String,
    pub knobs: IndexKnobs,
    /// Declared slot indexes, sorted by slot id.
    pub slots: Vec<SlotSpec>,
    /// Corpus documents, sorted by symbol id.
    pub documents: Vec<DocEntry>,
    /// Vault sequence this index set was built against (freshness base).
    pub base_seq: u64,
}

impl SlotIndexManifest {
    /// Canonical, byte-stable serialization (the persisted bytes). Deterministic
    /// because every collection is pre-sorted and floats are stored as bits.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SearchError> {
        serde_json::to_vec(self).map_err(|error| {
            SearchError::new(
                ASTRO_SEARCH_INDEX_MANIFEST,
                format!("manifest serialization failed: {error}"),
                "Report this: a well-formed manifest must always serialize.",
            )
        })
    }

    /// Parses persisted bytes back into a manifest, fail-closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SearchError> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| {
            SearchError::new(
                ASTRO_SEARCH_INDEX_MANIFEST,
                format!("manifest bytes did not parse: {error}"),
                "Rebuild the manifest from the corpus; the persisted bytes are corrupt.",
            )
        })?;
        if manifest.schema != SEARCH_INDEX_SCHEMA {
            return Err(SearchError::new(
                ASTRO_SEARCH_INDEX_MANIFEST,
                format!(
                    "manifest schema {:?} != expected {:?}",
                    manifest.schema, SEARCH_INDEX_SCHEMA
                ),
                "Rebuild against the current index schema.",
            ));
        }
        Ok(manifest)
    }

    /// Content hash over the canonical bytes (the blueprint's members-hash), for
    /// ledger entries and cross-build equality checks.
    pub fn content_hash(&self) -> Result<[u8; 32], SearchError> {
        let bytes = self.to_canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

/// Accumulates a corpus and produces a validated [`SlotIndexManifest`].
#[derive(Debug, Clone)]
pub struct SlotIndexSetBuilder {
    knobs: IndexKnobs,
    kinds: BTreeMap<SlotId, SlotIndexKind>,
    documents: BTreeMap<String, BTreeMap<SlotId, StoredContent>>,
}

impl SlotIndexSetBuilder {
    /// Starts a builder with the given declared knobs.
    pub fn new(knobs: IndexKnobs) -> Self {
        Self {
            knobs,
            kinds: BTreeMap::new(),
            documents: BTreeMap::new(),
        }
    }

    /// Declares slot `slot` as a BM25 lexical index.
    pub fn declare_lexical(&mut self, slot: SlotId) -> &mut Self {
        self.kinds.insert(slot, SlotIndexKind::Lexical);
        self
    }

    /// Declares slot `slot` as a dense HNSW index of dimension `dim`.
    pub fn declare_vector(&mut self, slot: SlotId, dim: u32) -> &mut Self {
        self.kinds.insert(slot, SlotIndexKind::Vector { dim });
        self
    }

    /// Adds identifier text for `symbol_id` at a lexical slot.
    pub fn add_lexical(
        &mut self,
        symbol_id: impl Into<String>,
        slot: SlotId,
        text: impl Into<String>,
    ) -> &mut Self {
        self.documents
            .entry(symbol_id.into())
            .or_default()
            .insert(slot, StoredContent::Text(text.into()));
        self
    }

    /// Adds a dense vector for `symbol_id` at a vector slot.
    pub fn add_vector(
        &mut self,
        symbol_id: impl Into<String>,
        slot: SlotId,
        vector: &[f32],
    ) -> &mut Self {
        let bits = vector.iter().map(|value| value.to_bits()).collect();
        self.documents
            .entry(symbol_id.into())
            .or_default()
            .insert(slot, StoredContent::VectorBits(bits));
        self
    }

    /// Validates the corpus and freezes it into a manifest at `base_seq`.
    /// Fail-closed on undeclared slots, kind mismatches, and dim mismatches.
    pub fn build_manifest(&self, base_seq: u64) -> Result<SlotIndexManifest, SearchError> {
        self.knobs.validate()?;
        let corpus = |message: String| {
            SearchError::new(
                ASTRO_SEARCH_INDEX_CORPUS,
                message,
                "Fix the corpus: every document slot must match a declared index kind and dimension.",
            )
        };
        for (symbol_id, slots) in &self.documents {
            for (slot, content) in slots {
                let Some(kind) = self.kinds.get(slot) else {
                    return Err(corpus(format!(
                        "symbol {symbol_id} has content for undeclared slot {}",
                        slot.get()
                    )));
                };
                match (kind, content) {
                    (SlotIndexKind::Lexical, StoredContent::Text(_)) => {}
                    (SlotIndexKind::Vector { dim }, StoredContent::VectorBits(bits)) => {
                        if bits.len() as u32 != *dim {
                            return Err(corpus(format!(
                                "symbol {symbol_id} slot {} vector has dim {} != declared {}",
                                slot.get(),
                                bits.len(),
                                dim
                            )));
                        }
                    }
                    (SlotIndexKind::Lexical, StoredContent::VectorBits(_)) => {
                        return Err(corpus(format!(
                            "symbol {symbol_id} slot {} is lexical but got a vector",
                            slot.get()
                        )));
                    }
                    (SlotIndexKind::Vector { .. }, StoredContent::Text(_)) => {
                        return Err(corpus(format!(
                            "symbol {symbol_id} slot {} is a vector index but got text",
                            slot.get()
                        )));
                    }
                }
            }
        }

        let slots = self
            .kinds
            .iter()
            .map(|(slot, kind)| SlotSpec {
                slot: *slot,
                kind: *kind,
            })
            .collect();
        let documents = self
            .documents
            .iter()
            .map(|(symbol_id, slots)| DocEntry {
                symbol_id: symbol_id.clone(),
                slots: slots.clone(),
            })
            .collect();
        Ok(SlotIndexManifest {
            schema: SEARCH_INDEX_SCHEMA.to_string(),
            knob_registry_version: SEARCH_INDEX_KNOB_REGISTRY_VERSION.to_string(),
            knobs: self.knobs,
            slots,
            documents,
            base_seq,
        })
    }
}

/// A query, in the two forms the per-slot indexes consume.
#[derive(Debug, Clone, Default)]
pub struct SlotQuery {
    /// Free text for lexical slots (split with [`split_identifier_tokens`]).
    pub text: String,
    /// Per-slot dense query vectors for vector slots.
    pub vectors: BTreeMap<SlotId, Vec<f32>>,
}

impl SlotQuery {
    /// A text-only query (vector slots must be supplied separately).
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            vectors: BTreeMap::new(),
        }
    }

    /// Attaches a dense query vector for `slot`.
    pub fn with_vector(mut self, slot: SlotId, vector: Vec<f32>) -> Self {
        self.vectors.insert(slot, vector);
        self
    }
}

enum LiveIndex {
    Lexical(InvertedIndex),
    Vector { dim: u32, index: HnswIndex },
}

/// A live per-slot index set, rebuilt from a [`SlotIndexManifest`]. Holds one
/// vendored Calyx index per declared slot plus the reverse `CxId -> symbol_id`
/// map needed to translate hits back into the fusion core's string ids.
pub struct SlotIndexSet {
    manifest: SlotIndexManifest,
    indexes: BTreeMap<SlotId, LiveIndex>,
    symbol_by_cx: BTreeMap<CxId, String>,
    built_at_seq: u64,
}

/// Deterministic, collision-checked `symbol_id -> CxId` mapping. Content-addressed
/// so a symbol keeps its id regardless of corpus ordering or incremental adds.
fn symbol_cx_id(symbol_id: &str) -> CxId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrolabe-weave-search-index-symbol-v1");
    hasher.update(symbol_id.as_bytes());
    let digest = hasher.finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    CxId::from_bytes(id)
}

impl SlotIndexSet {
    /// Rebuilds live indexes from a persisted manifest, deterministically:
    /// documents are inserted in canonical (sorted symbol-id) order so HNSW
    /// ordinals — and therefore levels — are reproducible.
    pub fn from_manifest(manifest: &SlotIndexManifest) -> Result<Self, SearchError> {
        manifest.knobs.validate()?;
        let build = |message: String| {
            SearchError::new(
                ASTRO_SEARCH_INDEX_BUILD,
                message,
                "The vendored index rejected a document; check the corpus shape.",
            )
        };

        let mut indexes: BTreeMap<SlotId, LiveIndex> = BTreeMap::new();
        for spec in &manifest.slots {
            let live = match spec.kind {
                SlotIndexKind::Lexical => LiveIndex::Lexical(InvertedIndex::new(spec.slot)),
                SlotIndexKind::Vector { dim } => LiveIndex::Vector {
                    dim,
                    index: HnswIndex::new(spec.slot, dim, manifest.knobs.seed),
                },
            };
            indexes.insert(spec.slot, live);
        }

        let mut symbol_by_cx: BTreeMap<CxId, String> = BTreeMap::new();
        // `manifest.documents` is already sorted by symbol id (canonical order).
        for doc in &manifest.documents {
            let cx_id = symbol_cx_id(&doc.symbol_id);
            if let Some(existing) = symbol_by_cx.insert(cx_id, doc.symbol_id.clone())
                && existing != doc.symbol_id
            {
                return Err(SearchError::new(
                    ASTRO_SEARCH_INDEX_CORPUS,
                    format!(
                        "symbol id hash collision between {existing:?} and {:?}",
                        doc.symbol_id
                    ),
                    "Rename one of the colliding symbols; ids must map to distinct CxIds.",
                ));
            }
            for (slot, content) in &doc.slots {
                let Some(live) = indexes.get_mut(slot) else {
                    return Err(SearchError::new(
                        ASTRO_SEARCH_INDEX_CORPUS,
                        format!(
                            "document {} references undeclared slot {}",
                            doc.symbol_id,
                            slot.get()
                        ),
                        "Declare every slot the corpus uses before building.",
                    ));
                };
                match (live, content) {
                    (LiveIndex::Lexical(index), StoredContent::Text(text)) => {
                        let joined = split_identifier_tokens(text).join(" ");
                        index
                            .insert_text(cx_id, &joined, manifest.base_seq)
                            .map_err(|error| {
                                build(format!(
                                    "lexical insert failed for {}: {} ({})",
                                    doc.symbol_id, error.message, error.code
                                ))
                            })?;
                    }
                    (LiveIndex::Vector { dim, index }, StoredContent::VectorBits(bits)) => {
                        if bits.len() as u32 != *dim {
                            return Err(SearchError::new(
                                ASTRO_SEARCH_INDEX_CORPUS,
                                format!(
                                    "document {} slot {} vector dim {} != declared {}",
                                    doc.symbol_id,
                                    slot.get(),
                                    bits.len(),
                                    dim
                                ),
                                "Vector dimensions must match the declared slot dimension.",
                            ));
                        }
                        let data = bits.iter().map(|word| f32::from_bits(*word)).collect();
                        index
                            .insert(
                                cx_id,
                                SlotVector::Dense { dim: *dim, data },
                                manifest.base_seq,
                            )
                            .map_err(|error| {
                                build(format!(
                                    "vector insert failed for {}: {} ({})",
                                    doc.symbol_id, error.message, error.code
                                ))
                            })?;
                    }
                    _ => {
                        return Err(SearchError::new(
                            ASTRO_SEARCH_INDEX_CORPUS,
                            format!(
                                "document {} slot {} content does not match the declared index kind",
                                doc.symbol_id,
                                slot.get()
                            ),
                            "Content kind and slot index kind must agree.",
                        ));
                    }
                }
            }
        }

        Ok(Self {
            manifest: manifest.clone(),
            indexes,
            symbol_by_cx,
            built_at_seq: manifest.base_seq,
        })
    }

    /// The manifest this set was built from (the persisted source of truth).
    pub fn manifest(&self) -> &SlotIndexManifest {
        &self.manifest
    }

    /// Per-slot freshness/stats from the vendored indexes (built_at_seq/base_seq,
    /// kind, live length). Makes the index layer auditable, never a black box.
    pub fn freshness(&self) -> Vec<IndexStats> {
        self.indexes
            .values()
            .map(|live| match live {
                LiveIndex::Lexical(index) => index.stats(),
                LiveIndex::Vector { index, .. } => index.stats(),
            })
            .collect()
    }

    /// The highest sequence any index in the set was built at.
    pub fn built_at_seq(&self) -> u64 {
        self.built_at_seq
    }

    /// Whether a slot has a constructed index.
    pub fn has_slot(&self, slot: SlotId) -> bool {
        self.indexes.contains_key(&slot)
    }

    /// Ranks one slot for a query, returning the fusion core's [`SlotRanking`].
    ///
    /// Fail-closed contract:
    /// - a slot with no constructed index => [`ASTRO_SEARCH_INDEX_ABSENT`]
    ///   (never a silent scan fallback);
    /// - a vector slot with no query vector => [`ASTRO_SEARCH_INDEX_QUERY_MISSING`].
    ///
    /// An index that exists but holds no matching candidates (empty corpus,
    /// query term absent from every document) returns an *empty* ranking — a
    /// labeled "no candidates", not a refusal and not a guess.
    pub fn rank_slot(
        &self,
        slot: SlotId,
        query: &SlotQuery,
        k: u64,
        ef: u64,
    ) -> Result<SlotRanking, SearchError> {
        let Some(live) = self.indexes.get(&slot) else {
            return Err(SearchError::new(
                ASTRO_SEARCH_INDEX_ABSENT,
                format!("no index constructed for planned slot {}", slot.get()),
                "Build an index for this slot before planning against it; the planner must not \
                 fall back to an unbounded scan.",
            ));
        };
        let hits = match live {
            LiveIndex::Lexical(index) => {
                let joined = split_identifier_tokens(&query.text).join(" ");
                if joined.is_empty() {
                    Vec::new()
                } else {
                    index.search_text(&joined, k as usize)
                }
            }
            LiveIndex::Vector { dim, index } => {
                let Some(vector) = query.vectors.get(&slot) else {
                    return Err(SearchError::new(
                        ASTRO_SEARCH_INDEX_QUERY_MISSING,
                        format!(
                            "planned vector slot {} received no query vector",
                            slot.get()
                        ),
                        "Supply a dense query vector for every planned vector slot.",
                    ));
                };
                if vector.len() as u32 != *dim {
                    return Err(SearchError::new(
                        ASTRO_SEARCH_INDEX_CORPUS,
                        format!(
                            "query vector for slot {} has dim {} != index dim {}",
                            slot.get(),
                            vector.len(),
                            dim
                        ),
                        "Query and index vector dimensions must match.",
                    ));
                }
                // An empty index has nothing to rank: labeled no-candidates, not
                // a refusal (the slot IS indexed; the corpus is simply empty).
                if index.live_len() == 0 {
                    Vec::new()
                } else {
                    let query_vector = SlotVector::Dense {
                        dim: *dim,
                        data: vector.clone(),
                    };
                    index
                        .search(&query_vector, k as usize, Some(ef.max(k) as usize))
                        .map_err(|error| {
                            SearchError::new(
                                ASTRO_SEARCH_INDEX_BUILD,
                                format!(
                                    "vector search failed on slot {}: {} ({})",
                                    slot.get(),
                                    error.message,
                                    error.code
                                ),
                                "The vendored HNSW rejected the query; check k/ef bounds.",
                            )
                        })?
                }
            }
        };

        let mut ranked_symbol_ids = Vec::with_capacity(hits.len());
        for hit in hits {
            let Some(symbol_id) = self.symbol_by_cx.get(&hit.cx_id) else {
                return Err(SearchError::new(
                    ASTRO_SEARCH_INDEX_BUILD,
                    format!(
                        "slot {} returned a hit outside the symbol table",
                        slot.get()
                    ),
                    "Report this: every indexed CxId must resolve to a symbol id.",
                ));
            };
            ranked_symbol_ids.push(symbol_id.clone());
        }
        Ok(SlotRanking {
            slot,
            ranked_symbol_ids,
        })
    }
}

/// Runs a validated plan against real per-slot indexes and fuses the results.
///
/// This is the index-backed counterpart of [`crate::search::run_search`]: it
/// ranks every planned slot through its constructed index (fail-closed if an
/// index is absent — never a scan fallback), fuses with RRF, applies exact
/// filters, then the bounded temporal boost. Because the plan is the only way in
/// and [`SlotIndexSet::rank_slot`] refuses missing indexes, a query can neither
/// exceed the planner caps nor silently degrade to a full scan.
pub fn run_indexed_search(
    plan: &SearchPlan,
    index_set: &SlotIndexSet,
    query: &SlotQuery,
    filters: &BTreeMap<String, String>,
    attributes_by_symbol: &BTreeMap<String, BTreeMap<String, String>>,
    recency_millis_by_symbol: &BTreeMap<String, u64>,
) -> Result<Vec<FusedResult>, SearchError> {
    let mut rankings = Vec::with_capacity(plan.weights_millis.len());
    for slot in plan.weights_millis.keys() {
        rankings.push(index_set.rank_slot(*slot, query, plan.k, plan.ef)?);
    }
    let mut results = fuse_rrf(plan, &rankings)?;
    apply_exact_filters(&mut results, filters, attributes_by_symbol);
    apply_temporal_boost(plan, &mut results, recency_millis_by_symbol)?;
    Ok(results)
}

/// Deterministic camelCase/snake-split identifier tokenizer (blueprint §12: S7
/// tokens are camelCase/snake-split, lowercased). Splits on:
/// - any non-alphanumeric separator (`_`, `-`, `.`, whitespace, …);
/// - a lowercase/digit → uppercase transition (`parseConfig` → `parse config`);
/// - an uppercase-run → uppercase+lowercase transition (`HTTPServer` →
///   `http server`).
///
/// Digits stay attached to an adjacent letter run (`sha256`, `v2` stay whole).
/// Pure, allocation-ordered, and identical on every platform.
pub fn split_identifier_tokens(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for (position, &ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        if !current.is_empty() {
            let previous = chars[position - 1];
            let camel_boundary =
                ch.is_uppercase() && (previous.is_lowercase() || previous.is_numeric());
            let acronym_boundary = ch.is_uppercase()
                && previous.is_uppercase()
                && chars
                    .get(position + 1)
                    .is_some_and(|next| next.is_lowercase());
            if camel_boundary || acronym_boundary {
                tokens.push(std::mem::take(&mut current));
            }
        }
        current.extend(ch.to_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::{
        SLOT_CODE_SEMANTIC, SLOT_LEXICAL_BM25, SLOT_NAME_SEMANTIC, SearchCaps, SearchRequest,
        plan_search,
    };
    use std::path::PathBuf;

    const SEED: u64 = 0x0A57_0BAD_E5EE_D001; // deterministic build seed

    /// A small but real fixture corpus: five code symbols, each with an
    /// identifier-text lexical slot and a 4-d dense semantic vector.
    fn fixture_builder() -> SlotIndexSetBuilder {
        let mut builder = SlotIndexSetBuilder::new(IndexKnobs::defaults(SEED));
        builder
            .declare_lexical(SLOT_LEXICAL_BM25)
            .declare_vector(SLOT_CODE_SEMANTIC, 4);
        // (symbol_id, identifier text, semantic vector)
        let corpus: &[(&str, &str, [f32; 4])] = &[
            (
                "sym:parse_config",
                "parseConfig loadConfig",
                [0.9, 0.1, 0.0, 0.0],
            ),
            (
                "sym:parse_args",
                "parseArgs parseConfig",
                [0.8, 0.2, 0.1, 0.0],
            ),
            (
                "sym:auth_middleware",
                "authMiddleware checkToken",
                [0.0, 0.1, 0.9, 0.2],
            ),
            (
                "sym:token_store",
                "TokenStore saveToken",
                [0.0, 0.0, 0.8, 0.6],
            ),
            (
                "sym:http_server",
                "HTTPServer listenAndServe",
                [0.1, 0.9, 0.0, 0.1],
            ),
        ];
        for (id, text, vector) in corpus {
            builder
                .add_lexical(*id, SLOT_LEXICAL_BM25, *text)
                .add_vector(*id, SLOT_CODE_SEMANTIC, vector);
        }
        builder
    }

    fn scratch_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "astrolabe-search-index-{tag}-{}-{nanos}.json",
            std::process::id()
        ));
        path
    }

    #[test]
    fn identifier_tokenizer_splits_camel_snake_and_acronyms() {
        assert_eq!(
            split_identifier_tokens("parseConfig_v2 HTTPServer"),
            vec!["parse", "config", "v2", "http", "server"]
        );
        assert_eq!(split_identifier_tokens("saveToken"), vec!["save", "token"]);
        // Deterministic across repeats.
        for _ in 0..8 {
            assert_eq!(
                split_identifier_tokens("loadConfigFromDisk"),
                vec!["load", "config", "from", "disk"]
            );
        }
        // Empty / separator-only input yields no tokens (never a phantom token).
        assert!(split_identifier_tokens("   __  ").is_empty());
    }

    #[test]
    fn manifest_persists_and_reads_back_byte_identically_fsv() {
        let manifest = fixture_builder().build_manifest(42).expect("manifest");
        let path = scratch_path("roundtrip");

        // Persist the source-of-truth bytes to a real sidecar file.
        let bytes = manifest.to_canonical_bytes().expect("canonical bytes");
        std::fs::write(&path, &bytes).expect("write sidecar");
        println!(
            "FSV before: wrote {} manifest bytes, content_hash={}",
            bytes.len(),
            hex(&manifest.content_hash().expect("hash"))
        );

        // Independently read the persisted bytes back (no in-memory reuse).
        let read_back = std::fs::read(&path).expect("read sidecar");
        let parsed = SlotIndexManifest::from_bytes(&read_back).expect("parse");
        println!(
            "FSV after: read {} bytes, parsed schema={:?}, docs={}",
            read_back.len(),
            parsed.schema,
            parsed.documents.len()
        );

        // Byte-for-byte stable and structurally equal.
        assert_eq!(read_back, bytes, "persisted bytes must round-trip");
        assert_eq!(parsed, manifest, "parsed manifest must equal the original");
        // Re-serializing the parsed manifest reproduces the exact same bytes.
        assert_eq!(
            parsed.to_canonical_bytes().expect("reserialize"),
            bytes,
            "canonical serialization must be byte-stable"
        );
        assert_eq!(
            parsed.content_hash().expect("hash2"),
            manifest.content_hash().expect("hash1"),
            "content hash must be stable across a persist/read cycle"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn two_independent_builds_from_persisted_bytes_rank_identically_fsv() {
        let manifest = fixture_builder().build_manifest(7).expect("manifest");
        let path = scratch_path("determinism");
        std::fs::write(&path, manifest.to_canonical_bytes().expect("bytes")).expect("write");

        // Two fully independent readbacks + rebuilds (worker-count invariant:
        // the whole path is single-threaded and tie-broken by id).
        let manifest_a =
            SlotIndexManifest::from_bytes(&std::fs::read(&path).expect("read a")).expect("parse a");
        let manifest_b =
            SlotIndexManifest::from_bytes(&std::fs::read(&path).expect("read b")).expect("parse b");
        let set_a = SlotIndexSet::from_manifest(&manifest_a).expect("build a");
        let set_b = SlotIndexSet::from_manifest(&manifest_b).expect("build b");

        // Scope fusion to the two slots this fixture indexes (S7 lexical, S18
        // semantic); the classifier's Mixed profile also names un-indexed slots,
        // and planning against those is (correctly) refused fail-closed.
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_LEXICAL_BM25, 1_000_u64);
        weights.insert(SLOT_CODE_SEMANTIC, 800_u64);
        let req = SearchRequest {
            query: "parseConfig".to_string(),
            k: 5,
            ef: 32,
            timeout_ms: 1_000,
            fusion_override_millis: Some(weights),
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let query = SlotQuery::text("parseConfig")
            .with_vector(SLOT_CODE_SEMANTIC, vec![0.85, 0.15, 0.05, 0.0]);
        let empty = BTreeMap::new();

        let results_a = run_indexed_search(
            &plan,
            &set_a,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("search a");
        let results_b = run_indexed_search(
            &plan,
            &set_b,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("search b");

        let ids_a: Vec<&str> = results_a.iter().map(|r| r.symbol_id.as_str()).collect();
        println!("FSV determinism: build A ranked {ids_a:?}");
        assert_eq!(
            results_a, results_b,
            "independent builds must rank identically"
        );
        assert!(
            !results_a.is_empty(),
            "the parse query must retrieve symbols"
        );
        // The two parse_* symbols must surface (lexical + semantic agreement).
        assert!(ids_a.contains(&"sym:parse_config"));
        assert!(ids_a.contains(&"sym:parse_args"));

        std::fs::remove_file(&path).ok();
    }

    fn empty_attrs() -> BTreeMap<String, BTreeMap<String, String>> {
        BTreeMap::new()
    }

    fn empty_recency() -> BTreeMap<String, u64> {
        BTreeMap::new()
    }

    #[test]
    fn planner_and_indexes_wire_together_with_rrf() {
        let manifest = fixture_builder().build_manifest(1).expect("manifest");
        let set = SlotIndexSet::from_manifest(&manifest).expect("build");
        // Intent classifier picks a profile; the profile references slots we
        // only partially indexed, so override to the two indexed slots.
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_LEXICAL_BM25, 1_000_u64);
        weights.insert(SLOT_CODE_SEMANTIC, 800_u64);
        let req = SearchRequest {
            query: "authMiddleware".to_string(),
            k: 3,
            ef: 32,
            timeout_ms: 1_000,
            fusion_override_millis: Some(weights),
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let query = SlotQuery::text("authMiddleware")
            .with_vector(SLOT_CODE_SEMANTIC, vec![0.0, 0.1, 0.9, 0.2]);
        let empty = BTreeMap::new();
        let results = run_indexed_search(
            &plan,
            &set,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("search");
        assert_eq!(results[0].symbol_id, "sym:auth_middleware");
        // Explain: the top hit has contributions from both fused slots.
        let slots: BTreeSet<u16> = results[0]
            .contributions
            .iter()
            .map(|c| c.slot.get())
            .collect();
        assert_eq!(
            slots,
            BTreeSet::from([SLOT_LEXICAL_BM25.get(), SLOT_CODE_SEMANTIC.get()])
        );
    }

    use std::collections::BTreeSet;

    #[test]
    fn absent_index_refuses_fail_closed_never_scans() {
        let manifest = fixture_builder().build_manifest(1).expect("manifest");
        let set = SlotIndexSet::from_manifest(&manifest).expect("build");
        // Plan a slot (S20 name-semantic) that was never indexed.
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_NAME_SEMANTIC, 1_000_u64);
        let req = SearchRequest {
            query: "x".to_string(),
            k: 3,
            ef: 32,
            timeout_ms: 1_000,
            fusion_override_millis: Some(weights),
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let query = SlotQuery::text("x");
        let empty = BTreeMap::new();
        let err = run_indexed_search(
            &plan,
            &set,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect_err("absent index must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_INDEX_ABSENT);
        assert!(!err.remediation().is_empty());
    }

    #[test]
    fn vector_slot_without_query_vector_refuses_fail_closed() {
        let manifest = fixture_builder().build_manifest(1).expect("manifest");
        let set = SlotIndexSet::from_manifest(&manifest).expect("build");
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_CODE_SEMANTIC, 1_000_u64);
        let req = SearchRequest {
            query: "x".to_string(),
            k: 3,
            ef: 32,
            timeout_ms: 1_000,
            fusion_override_millis: Some(weights),
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        // No vector supplied for the planned vector slot.
        let query = SlotQuery::text("x");
        let empty = BTreeMap::new();
        let err = run_indexed_search(
            &plan,
            &set,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect_err("missing query vector must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_INDEX_QUERY_MISSING);
    }

    #[test]
    fn unsupported_knob_is_refused_not_silently_ignored() {
        let mut knobs = IndexKnobs::defaults(SEED);
        knobs.bm25_k1_millis = 2_000; // != pinned 1200
        let err = SlotIndexSetBuilder::new(knobs)
            .build_manifest(0)
            .expect_err("custom BM25 must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_INDEX_KNOB_UNSUPPORTED);

        let mut knobs = IndexKnobs::defaults(SEED);
        knobs.hnsw_m = 16; // != pinned 32
        let err = SlotIndexSetBuilder::new(knobs)
            .build_manifest(0)
            .expect_err("custom M must refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_INDEX_KNOB_UNSUPPORTED);
    }

    #[test]
    fn edge_triad_empty_single_and_absent_term() {
        let empty = BTreeMap::new();
        let query = SlotQuery::text("parseConfig")
            .with_vector(SLOT_CODE_SEMANTIC, vec![0.9, 0.1, 0.0, 0.0]);
        let req = SearchRequest {
            query: "parseConfig".to_string(),
            k: 5,
            ef: 32,
            timeout_ms: 1_000,
            fusion_override_millis: {
                let mut w = BTreeMap::new();
                w.insert(SLOT_LEXICAL_BM25, 1_000_u64);
                w.insert(SLOT_CODE_SEMANTIC, 1_000_u64);
                Some(w)
            },
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");

        // (1) EMPTY corpus: declared slots, zero documents.
        let mut empty_builder = SlotIndexSetBuilder::new(IndexKnobs::defaults(SEED));
        empty_builder
            .declare_lexical(SLOT_LEXICAL_BM25)
            .declare_vector(SLOT_CODE_SEMANTIC, 4);
        let empty_set =
            SlotIndexSet::from_manifest(&empty_builder.build_manifest(0).expect("m")).expect("s");
        println!("edge empty before: docs=0");
        let empty_results = run_indexed_search(
            &plan,
            &empty_set,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("empty search returns, not errors");
        println!("edge empty after: results={}", empty_results.len());
        assert!(empty_results.is_empty(), "empty corpus yields no results");

        // (2) SINGLE-document corpus.
        let mut one_builder = SlotIndexSetBuilder::new(IndexKnobs::defaults(SEED));
        one_builder
            .declare_lexical(SLOT_LEXICAL_BM25)
            .declare_vector(SLOT_CODE_SEMANTIC, 4)
            .add_lexical("sym:only", SLOT_LEXICAL_BM25, "parseConfig")
            .add_vector("sym:only", SLOT_CODE_SEMANTIC, &[0.9, 0.1, 0.0, 0.0]);
        let one_set =
            SlotIndexSet::from_manifest(&one_builder.build_manifest(0).expect("m")).expect("s");
        println!("edge single before: docs=1");
        let one_results = run_indexed_search(
            &plan,
            &one_set,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("single search");
        println!(
            "edge single after: results={:?}",
            one_results
                .iter()
                .map(|r| r.symbol_id.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(one_results.len(), 1);
        assert_eq!(one_results[0].symbol_id, "sym:only");

        // (3) Query TERM ABSENT from every document (lexical) but vector present.
        let full_set =
            SlotIndexSet::from_manifest(&fixture_builder().build_manifest(0).expect("m"))
                .expect("s");
        let absent_query = SlotQuery::text("zzznonexistentterm")
            .with_vector(SLOT_CODE_SEMANTIC, vec![0.9, 0.1, 0.0, 0.0]);
        println!("edge absent-term before: lexical term matches nothing");
        // Lexical-only plan: the absent term retrieves nothing.
        let mut lex_only = BTreeMap::new();
        lex_only.insert(SLOT_LEXICAL_BM25, 1_000_u64);
        let lex_req = SearchRequest {
            fusion_override_millis: Some(lex_only),
            ..req.clone()
        };
        let lex_plan = plan_search(&lex_req, &SearchCaps::default_caps()).expect("plan");
        let absent_results = run_indexed_search(
            &lex_plan,
            &full_set,
            &absent_query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("absent-term search");
        println!("edge absent-term after: results={}", absent_results.len());
        assert!(
            absent_results.is_empty(),
            "a term absent from every document retrieves nothing"
        );
    }

    #[test]
    fn incremental_rebuild_bumps_freshness_and_indexes_new_symbol() {
        // Build, then add a symbol at a higher seq, rebuild, and confirm the new
        // symbol is retrievable and built_at_seq advanced (freshness contract).
        let mut builder = fixture_builder();
        let base = SlotIndexSet::from_manifest(&builder.build_manifest(10).expect("m")).expect("s");
        let base_seq_before: Vec<u64> = base.freshness().iter().map(|s| s.built_at_seq).collect();
        println!("incremental before: built_at_seq={base_seq_before:?}");
        assert!(base_seq_before.iter().all(|&s| s == 10));

        builder
            .add_lexical("sym:new_symbol", SLOT_LEXICAL_BM25, "brandNewSymbol")
            .add_vector("sym:new_symbol", SLOT_CODE_SEMANTIC, &[0.5, 0.5, 0.5, 0.5]);
        let rebuilt =
            SlotIndexSet::from_manifest(&builder.build_manifest(20).expect("m")).expect("s");
        let seq_after: Vec<u64> = rebuilt.freshness().iter().map(|s| s.built_at_seq).collect();
        println!("incremental after: built_at_seq={seq_after:?}");
        assert!(
            seq_after.iter().all(|&s| s == 20),
            "rebuild bumps freshness"
        );

        let mut weights = BTreeMap::new();
        weights.insert(SLOT_LEXICAL_BM25, 1_000_u64);
        let req = SearchRequest {
            query: "brandNewSymbol".to_string(),
            k: 3,
            ef: 32,
            timeout_ms: 1_000,
            fusion_override_millis: Some(weights),
            temporal_alpha_millis: 0,
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let query = SlotQuery::text("brandNewSymbol");
        let empty = BTreeMap::new();
        let results = run_indexed_search(
            &plan,
            &rebuilt,
            &query,
            &empty,
            &empty_attrs(),
            &empty_recency(),
        )
        .expect("search");
        assert_eq!(results[0].symbol_id, "sym:new_symbol");
    }

    fn hex(bytes: &[u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}
