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
use calyx_core::{Clock, SlotId, SlotVector};

use crate::search::{SLOT_CODE_SEMANTIC, SLOT_LEXICAL_BM25, SLOT_NAME_SEMANTIC, SearchError};
use crate::search_index::{
    ASTRO_SEARCH_INDEX_CORPUS, IndexKnobs, SlotIndexManifest, SlotIndexSetBuilder,
};

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
/// space — so ranking them for a text query would fail-closed
/// `ASTRO_SEARCH_INDEX_QUERY_MISSING`. Fusing those corpus vectors requires a
/// structural query surface (a symbol-anchored "more like this" query), a
/// distinct path tracked separately; they are not part of the text-search owner.
pub const PRODUCTION_VECTOR_SLOTS: [SlotId; 2] = [SLOT_CODE_SEMANTIC, SLOT_NAME_SEMANTIC];

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
    /// Slot rows that decoded to `SlotVector::Absent` (labeled skip).
    pub absent_slot_rows: usize,
    /// Requested slot rows that were not present for a symbol (labeled skip).
    pub missing_slot_rows: usize,
    /// Slot rows that were present but not dense (sparse/multi; labeled skip).
    pub non_dense_slot_rows: usize,
    /// Vector slots that ended up declared (present as dense on ≥1 symbol),
    /// each mapped to its dimension.
    pub declared_vector_slots: BTreeMap<SlotId, u32>,
    /// Vault sequence this corpus was read at — the manifest freshness base.
    pub base_seq: u64,
}

impl CorpusReadReport {
    /// Total labeled skips across every skip bucket.
    pub fn skip_count(&self) -> usize {
        self.absent_slot_rows + self.missing_slot_rows + self.non_dense_slot_rows
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
    let mut absent_slot_rows = 0usize;
    let mut missing_slot_rows = 0usize;
    let mut non_dense_slot_rows = 0usize;
    let mut declared_vector_slots: BTreeMap<SlotId, u32> = BTreeMap::new();

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
                SlotVector::Absent { .. } => absent_slot_rows += 1,
                _ => non_dense_slot_rows += 1,
            }
        }
        symbols.push(CorpusSymbol {
            symbol_id: node.qualified_name,
            name: node.name,
            label: node.label,
            vectors,
        });
    }

    Ok(CorpusReadReport {
        symbols,
        symbols_total,
        vector_rows_read,
        absent_slot_rows,
        missing_slot_rows,
        non_dense_slot_rows,
        declared_vector_slots,
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
    for symbol in &report.symbols {
        builder.add_lexical(
            symbol.symbol_id.clone(),
            SLOT_LEXICAL_BM25,
            symbol.name.clone(),
        );
        for (slot, vector) in &symbol.vectors {
            builder.add_vector(symbol.symbol_id.clone(), *slot, vector);
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
            absent_slot_rows: 0,
            missing_slot_rows: 0,
            non_dense_slot_rows: 0,
            declared_vector_slots: BTreeMap::new(),
            base_seq: 0,
        };
        let manifest =
            build_manifest_from_corpus(&report, IndexKnobs::defaults(0)).expect("empty manifest");
        assert!(manifest.documents.is_empty());
        // S7 lexical is still declared (the schema is always well-formed).
        assert_eq!(manifest.slots.len(), 1);
        assert_eq!(manifest.slots[0].slot, SLOT_LEXICAL_BM25);
    }
}
