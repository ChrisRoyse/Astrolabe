use super::*;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};

use astrolabe_anchors::archaeology::{
    GitArchaeologyConfig, GitLineRange, GitMineMode, mine_git_archaeology,
};
use astrolabe_anchors::{
    OutcomeAnchorBatchItem, OutcomeAnchorRequest, OutcomeKind, OutcomeSubject,
    PreparedOutcomeAnchorBatch, prepare_outcome_anchor_batch,
};
use astrolabe_bridge::{
    CbmIndexMode, CbmPipeline, CbmPipelineEdgeRow, CbmPipelineFileHashRow, CbmPipelineNodeRow,
    CbmPipelineRowManifest, CbmPipelineRows, ExtractedFile, Import, ImportResolution, Language,
    discover_pipeline_files,
};
// #502: share the clone farm's #480 Windows-invalid-path classifier so the historical
// checkout and the farm never disagree on what NTFS can hold.
use astrolabe_fleet::clone_farm::windows_invalid_path;
use astrolabe_ingest::{
    HistoricalSymbolAdmissionBatch, HistoricalSymbolAdmissionSession, HistoricalSymbolLocation,
    PreparedHistoricalSymbolAdmission,
};
use calyx_aster::vault::{LedgerBoundGroupReceipt, LedgerBoundWriteGroup, VaultPhaseUsage};
use calyx_core::{AnchorKind, AnchorValue, CxId};

const ARCHAEOLOGY_ACTOR: &str = "astrolabe-git-archaeology";
const ARCHAEOLOGY_ANCHOR_BATCH_ENV: &str = "ASTRO_ARCHAEOLOGY_ANCHOR_BATCH_ENTRIES";
const ARCHAEOLOGY_HISTORICAL_BATCH_ENV: &str = "ASTRO_ARCHAEOLOGY_HISTORICAL_BATCH_GROUPS";
const ARCHAEOLOGY_DIFF_TREE_BATCH_ENV: &str = "ASTRO_ARCHAEOLOGY_DIFF_TREE_BATCH_COMMITS";
const HISTORICAL_CAT_FILE_BATCH_PATHS: usize = 4096;
/// Hard correctness bound for one commit's exact source-dependency closure.
/// A closure at this size is no longer a file-scoped historical slice and must
/// be diagnosed explicitly instead of exhausting memory or silently switching
/// to a whole-tree fallback.
const HISTORICAL_DEPENDENCY_CLOSURE_MAX_FILES: usize = 65_536;
/// Match libcbm's authoritative per-file extraction budget.
const HISTORICAL_DEPENDENCY_EXTRACT_TIMEOUT_MICROS: i64 = 5_000_000;

/// Write-side prefix for the transient git-archaeology scratch STORE this module
/// drops into the CBM store dir: the historical-index scratch database
/// `".astrolabe-archaeology-<pid>-<nanos>.db"` (plus its `-wal`/`-shm`/`-journal`
/// sidecars). The scratch store ends in `.db` but is NOT a project store — it is
/// live during an archaeology pass and can survive a crash — so the C enumerator
/// (`is_project_db_file` in `cbm/src/mcp/mcp.c`) skips the family by this reserved
/// prefix (#414). The scratch WORKTREE no longer lives beside it: a Windows process
/// CWD is hard-capped at MAX_PATH and `core.longpaths` covers git's file I/O but
/// NOT the `chdir` git performs into a `-C <worktree>` root, so on a deep store dir
/// `git checkout` died with `cannot change to '<deep>/…-worktree-…'`. The worktree
/// is relocated to a compact explicit scratch namespace
/// ([`archaeology_scratch_scope`], #427/#809); only the `\\?\`-safe scratch `.db`
/// (SQLite, #412) stays under the store.
///
/// DRIFT CONTRACT: MUST byte-match the C-side `CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX`
/// (declared in `cbm/src/mcp/mcp.h`); the compile-time assertion below binds
/// the two.
const ARCHAEOLOGY_DB_PREFIX: &str = ".astrolabe-archaeology-";

/// #414 drift guard — see `LOWERED_SQLITE_SUFFIX`'s twin assertion in
/// `migration/mod.rs`. `astrolabe_bridge::CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX` is
/// the bindgen-surfaced C macro (NUL-terminated byte array).
const _: () = {
    let rust = ARCHAEOLOGY_DB_PREFIX.as_bytes();
    let c = astrolabe_bridge::CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX;
    assert!(
        c.len() == rust.len() + 1,
        "C CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX and Rust ARCHAEOLOGY_DB_PREFIX have drifted (length)"
    );
    let mut i = 0;
    while i < rust.len() {
        assert!(
            c[i] == rust[i],
            "C CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX and Rust ARCHAEOLOGY_DB_PREFIX have drifted (bytes)"
        );
        i += 1;
    }
    assert!(
        c[rust.len()] == 0,
        "C reserved prefix is not NUL-terminated"
    );
};

/// Required process configuration for the one product-owned archaeology scratch
/// namespace (#809). There is deliberately no ambient-TEMP or store-directory
/// fallback: callers must name one absolute local root whose path satisfies Git's
/// Windows current-directory budget.
const ARCHAEOLOGY_ROOT_ENV: &str = "ASTRO_ARCHAEOLOGY_ROOT";
const ARCHAEOLOGY_SCOPE_SCHEMA: &str = "astrolabe.archaeology-scratch-scope.v1";

/// Directory-name prefix for the transient git-archaeology scratch WORKTREE,
/// rooted under the repo+project-bound compact namespace returned by
/// [`archaeology_scratch_scope`]. The embedded owner PID is the sweep's
/// concurrency discriminator: [`sweep_orphan_worktrees`] removes a leftover
/// worktree only when its PID is dead, so a concurrent live archaeology pass is
/// never swept out from under itself. Unlike the scratch `.db`, this name carries
/// no C-side enumeration contract — it never lands in a CBM store dir.
const ARCHAEOLOGY_WORKTREE_PREFIX: &str = "w-";

/// Byte budget for the scratch-worktree root path. [`add_historical_worktree`]
/// runs `git -C <worktree> checkout …`, which makes git `chdir` into the worktree
/// root; a Windows process CWD is hard-capped at MAX_PATH (260) and no `\\?\` form
/// or git config lifts that `chdir` limit (confirmed against git-for-windows
/// #3372 / #5464 — `core.longpaths` only reaches git's file I/O, never `chdir`).
/// 240 keeps the root ~20 bytes clear of the 260 cap; a worktree path over budget
/// fails closed (`ASTRO_ARCHAEOLOGY_WORKTREE_BASE_TOO_DEEP`) instead of letting
/// `git checkout` die mid-pass. This is a platform limit, not a tunable knob.
const ARCHAEOLOGY_WORKTREE_CWD_BUDGET: usize = 240;

/// #439 registry-declared decision: index ONLY the implicated files per evidence
/// commit (file-scoped historical index) instead of checking out and Fast-indexing
/// the WHOLE member subtree per commit.
///
/// MEASURED lever (#439): after the #434 mass-change diff fix (39.9s → 0.6s), the
/// per-evidence-commit historical-reindex loop became the largest git_archaeology
/// sub-phase — ~8.3s for 4 distinct commits on the `cbm/` corpus (ASTRO_ARCH_TIMING).
/// Each commit checked out and Fast-indexed the entire ~5,500-file member subtree even
/// though `select_implicated_rows` afterwards keeps only the handful of nodes that
/// overlap the evidence ranges. File-scoped indexing materializes and parses only the
/// implicated files, so both the historical checkout and the CBM parse shrink from the
/// whole subtree to a few files per commit.
///
/// BYTE-PARITY ARGUMENT (proven by the #439 probe, not assumed): CBM derives each
/// node's CxId from `rel_file_path` + content (`astrolabe_domain::canonical_input_bytes`).
/// The file-scoped checkout materializes each implicated file at the SAME
/// subtree-relative path (same `scoped_root` base, only fewer files under it) with the
/// SAME content, so every implicated node's CxId is identical to the whole-subtree
/// index. `select_implicated_rows` already discards every non-implicated node, so the
/// files skipped here are exactly the files whose rows would have been thrown away —
/// the retained rows, and thus the persisted anchors/constellations, are unchanged.
/// The known differences are all NON-outcomes and stay byte-parity:
///   * an implicated file DELETED at the evidence commit is not materialized (probed
///     with `git cat-file -e`), so CBM finds no node → `evidence_without_symbol` —
///     identical to whole-subtree, which indexes the subtree without that file;
///   * an implicated file CBM skips as oversized yields no node in either mode;
///   * multiple ranges hitting one file are de-duplicated to one checkout of that file.
///
/// `true` = file-scoped (default, the measured lever). `false` = pre-#439 whole-subtree
/// behavior. The env override `ASTRO_ARCH_FILE_SCOPED_INDEX` (`0`/`false` → whole
/// subtree, `1`/`true` → file-scoped) flips the mode on one binary so a measurement can
/// compare both against the same store, mirroring the ASTRO_ARCH_TIMING env gate
/// (invariant 4: a registry-declared decision with an explicit measurement override, not
/// a silent constant).
pub(crate) const HISTORICAL_INDEX_FILE_SCOPED_DEFAULT: bool = true;

/// Reads the effective #439 file-scoped-historical-index decision: the
/// [`HISTORICAL_INDEX_FILE_SCOPED_DEFAULT`] registry default, overridable per run via
/// `ASTRO_ARCH_FILE_SCOPED_INDEX` so the parity/timing probe can exercise both modes on
/// one binary. An unrecognized value falls back to the default (never a silent flip).
fn historical_index_file_scoped() -> bool {
    match std::env::var("ASTRO_ARCH_FILE_SCOPED_INDEX") {
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => false,
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => true,
        _ => HISTORICAL_INDEX_FILE_SCOPED_DEFAULT,
    }
}

#[derive(Debug, Clone)]
struct Evidence {
    commit: String,
    range: GitLineRange,
    source: String,
    observed_at: u64,
    confidence: f32,
    label: &'static str,
}

#[derive(Debug)]
struct PendingAnchorAdmission {
    request: OutcomeAnchorRequest,
    cx_ids: BTreeMap<String, CxId>,
}

struct PendingArchaeologyPersistenceGroup {
    historical: Option<PreparedHistoricalSymbolAdmission>,
    anchors: Vec<PendingAnchorAdmission>,
}

struct ArchaeologyPersistenceWindow {
    historical_batch: HistoricalSymbolAdmissionBatch,
    groups: Vec<PendingArchaeologyPersistenceGroup>,
    anchor_entries: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GitArchaeologyImportReport {
    pub(crate) head: String,
    pub(crate) mode: &'static str,
    pub(crate) evidence: usize,
    pub(crate) historical_constellations_written: usize,
    pub(crate) historical_constellations_reused: usize,
    pub(crate) anchors_written: usize,
    pub(crate) anchors_deduplicated: usize,
    pub(crate) evidence_without_symbol: usize,
    pub(crate) skipped_merge_fixes: usize,
    /// Fix/revert commits excluded from SZZ mining as mass-changes (#434) — the
    /// measured perf lever that removes the dominant M-scale diff cost. Counted
    /// and surfaced in the summary, never a silent skip (invariant 3).
    pub(crate) skipped_large_commits: usize,
    /// Revert commits whose message-mined target hash does not resolve in this
    /// clone (#467) — squash-merge reverts routinely cite PR-only commits. Each
    /// is a counted, labeled mining skip (invariant 3), never an import failure.
    pub(crate) skipped_unresolvable_reverts: usize,
    /// Diffed files excluded from range mining because the mined side is a
    /// gitlink (mode 160000) — submodule pointer bumps are tree entries, not
    /// blamable blobs, and are never line evidence (#514). A counted, labeled
    /// mining skip (invariant 3), never an import failure.
    pub(crate) skipped_gitlink_paths: usize,
    /// Blame targets git refused with `no such path` at the blamed parent —
    /// paths the diff names that the parent commit does not contain (#514).
    /// Each is a counted, labeled mining skip (invariant 3); every other blame
    /// failure stays repo-fatal.
    pub(crate) skipped_unblamable_paths: usize,
    /// Fix-like single-parent commits submitted to Git diff-tree raw count batching.
    pub(crate) diff_tree_count_requested_commits: usize,
    /// Raw count `git diff-tree --stdin` processes spawned.
    pub(crate) diff_tree_count_processes: usize,
    /// Per-commit raw count processes avoided by batching.
    pub(crate) diff_tree_count_processes_avoided: usize,
    /// Exact stdout bytes emitted by raw count batches.
    pub(crate) diff_tree_count_stdout_bytes: u64,
    /// Under-cap fix-like commits submitted to Git diff-tree unified range batching.
    pub(crate) diff_tree_ranges_requested_commits: usize,
    /// Unified range `git diff-tree --stdin` processes spawned.
    pub(crate) diff_tree_ranges_processes: usize,
    /// Per-commit unified range processes avoided by batching.
    pub(crate) diff_tree_ranges_processes_avoided: usize,
    /// Exact stdout bytes emitted by unified range batches.
    pub(crate) diff_tree_ranges_stdout_bytes: u64,
    /// Observed wall time for raw count batches.
    pub(crate) diff_tree_count_wall_ms: u64,
    /// Observed wall time for unified range batches.
    pub(crate) diff_tree_ranges_wall_ms: u64,
    /// Effective registry-declared diff-tree batch bound.
    pub(crate) diff_tree_batch_limit_commits: usize,
    /// Original SZZ line ranges submitted to Git blame.
    pub(crate) blame_requested_ranges: usize,
    /// Exact union ranges after overlap/adjacency coalescing.
    pub(crate) blame_effective_ranges: usize,
    /// Distinct parent/path groups submitted to Git blame.
    pub(crate) blame_groups: usize,
    /// Commit-local blame requests served by an already-mined parent/path group.
    pub(crate) blame_group_cache_hits: usize,
    /// Native incremental-blame processes spawned.
    pub(crate) blame_processes: usize,
    /// Per-request blame processes avoided by parent/path grouping.
    pub(crate) blame_processes_avoided: usize,
    /// Cat-file batch-command preflight processes spawned before blame.
    pub(crate) blame_cat_file_processes: usize,
    /// Exact cat-file preflight stdout volume.
    pub(crate) blame_cat_file_stdout_bytes: u64,
    /// Parent/path groups proved absent by cat-file preflight.
    pub(crate) blame_path_absent_groups: usize,
    /// Strictly parsed incremental protocol spans.
    pub(crate) blame_returned_spans: usize,
    /// Distinct attributed result lines retained.
    pub(crate) blame_returned_lines: usize,
    /// Exact incremental-blame stdout volume.
    pub(crate) blame_stdout_bytes: u64,
    /// Wall time spent in grouped incremental blame.
    pub(crate) blame_wall_ms: u64,
    /// Wall time spent in cat-file preflight.
    pub(crate) blame_cat_file_wall_ms: u64,
    /// Scratch worktrees / SQLite files that survived the bounded cleanup retry
    /// budget and were left on disk. Surfaced as a labeled count (invariant 3):
    /// a cleanup that cannot complete degrades to a counted remnant, never a
    /// silently swallowed `let _`.
    pub(crate) cleanup_remnants: usize,
    /// Implicated files excluded from the file-scoped historical checkout because the
    /// committed filename is not representable on NTFS (#502) — control bytes, reserved
    /// characters/device names, trailing dot/space (the
    /// [`astrolabe_fleet::clone_farm::windows_invalid_path`] class). A labeled, counted
    /// degradation (invariant 3): the excluded file's evidence lands as
    /// `evidence_without_symbol`, and the pass never aborts repo-fatally the way an
    /// unfiltered `git checkout` of such a path did before the fix.
    pub(crate) historical_paths_windows_invalid: usize,
    /// #515 crash-isolation counter: historical evidence commits whose CBM
    /// extraction ran on the pooled out-of-process worker ([`HistoricalExtractionPool`])
    /// that died/hung/erred without producing rows — a C-level pipeline fault (abort/access
    /// violation/heap-corruption class) on that commit's checkout. BEFORE #515 this
    /// same fault ran IN-PROCESS and took the whole host `index_repository` down with
    /// it: an empty-stdout `rc=127` silent hard-exit with no structured error (the
    /// exact fail-closed violation this issue tracks). Now the fault is contained in
    /// the child, the host survives, this commit's evidence lands as
    /// `evidence_without_symbol`, and the count is surfaced here (invariant 3: every
    /// degradation counted, never a silent skip). A nonzero value means the kernel
    /// still completed but that many historical commits contributed no anchors.
    pub(crate) historical_commits_crashed: usize,
    /// Successful historical extractions whose worker published a complete
    /// post-success response but could not be reused because native teardown
    /// then exited, faulted, or exceeded the existing extraction timeout. These
    /// are not lost commits: the parent accepted the manifest-validated rows
    /// and spawned a fresh worker for the next request, while surfacing the
    /// cleanup lifecycle as explicit telemetry.
    pub(crate) historical_post_success_worker_recycles: usize,
    /// Subset of post-success worker recycles caused by cleanup not reaching the
    /// next-request loop before the existing extraction timeout expired.
    pub(crate) historical_post_success_cleanup_timeouts: usize,
    /// Git processes used to resolve historical commit/path inventory. The default
    /// file-scoped path uses bounded cat-file object-info batches; the non-default
    /// whole-subtree measurement path still uses a temporary index inventory.
    pub(crate) historical_git_inventory_processes: usize,
    /// Git checkout-index processes used to materialize non-empty commit views.
    pub(crate) historical_git_checkout_processes: usize,
    /// Git cat-file processes used to stream filtered historical file bytes.
    pub(crate) historical_git_cat_file_processes: usize,
    /// Exact stdout bytes emitted by historical materialization cat-file batches.
    pub(crate) historical_git_cat_file_stdout_bytes: u64,
    /// Exact files materialized from commit-bound temporary indexes.
    pub(crate) historical_git_files_materialized: usize,
    /// Exact repository-local source dependencies added beyond the evidence
    /// seed set so each file-scoped CBM view is dependency-complete.
    pub(crate) historical_dependency_files_materialized: usize,
    /// Alternative immutable-tree candidates probed and proven absent while a
    /// typed Rust/ES dependency still resolved to exactly one live source.
    pub(crate) historical_dependency_candidate_paths_absent: usize,
    /// Exact source-dependency edges traversed while closing historical views.
    pub(crate) historical_dependency_edges: usize,
    /// Repeated dependency targets suppressed by the visited set (including
    /// finite cycles); every unique blob is materialized at most once.
    pub(crate) historical_dependency_revisits: usize,
    /// Deepest transitive exact-source expansion round observed in this pass.
    pub(crate) historical_dependency_max_depth: usize,
    /// Requested implicated paths absent at their historical commit. This is a
    /// labeled expected state for deleted/renamed evidence paths, never a silent
    /// materialization miss.
    pub(crate) historical_git_paths_absent: usize,
    /// Materialized files recognized by the exact libcbm language resolver.
    pub(crate) historical_git_source_files_materialized: usize,
    /// Commit views with no recognized source file, routed directly to an explicit
    /// empty historical result without invoking the extraction worker.
    pub(crate) historical_commits_without_materialized_source: usize,
    /// Per-path `git cat-file -e` process launches removed by one index inventory.
    pub(crate) historical_git_object_probe_processes_avoided: usize,
    /// Shared-repository worktree registration mutations removed (add + remove).
    pub(crate) historical_git_worktree_mutations_avoided: usize,
    /// Provenance label for the git history this pass mined (#434, invariant 1/3:
    /// no unlabeled claim, no silent fallback). `own_repo` when the corpus IS its
    /// own git toplevel (`.git` at the corpus root); `parent_repo` when the corpus
    /// is a subtree of an enclosing repository whose `.git` it mined (e.g. `cbm/`
    /// inside the Astrolabe repo) — so a consumer never mistakes parent-repo-derived
    /// anchors for the corpus's own history.
    pub(crate) archaeology_source: &'static str,
    /// Absolute path of the git toplevel whose history was mined (the discovered
    /// git root). For a `parent_repo` corpus this is the ENCLOSING repository, not
    /// the corpus dir — persisted so the parent-derived provenance is auditable.
    pub(crate) git_root: String,
    /// The toplevel-relative subtree pathspec every history walk was limited to
    /// (#381). `Some("cbm")` for a `parent_repo` corpus; `None` when the corpus is
    /// the whole repository (`own_repo`, unscoped walk).
    pub(crate) pathspec: Option<String>,
    /// Registry version that declared the ordered anchor batch bound.
    pub(crate) anchor_batch_registry_version: &'static str,
    /// Effective maximum logical anchor entries in one atomic commit.
    pub(crate) anchor_batch_limit: usize,
    /// Effective maximum historical commit groups in one atomic window.
    pub(crate) historical_batch_group_limit: usize,
    /// Historical commit groups prepared for persistence.
    pub(crate) historical_admission_groups: usize,
    /// Historical `Ingest` entries that wrote at least one physical row.
    pub(crate) historical_admission_logical_entries: usize,
    /// Physical commits containing one or more historical `Ingest` entries.
    pub(crate) historical_admission_atomic_commits: usize,
    /// Explicit flushes containing one or more historical `Ingest` entries.
    pub(crate) historical_admission_flushes: usize,
    /// Largest historical group window committed in this pass.
    pub(crate) historical_admission_max_window_groups: usize,
    /// Historical Base/slot/input rows written across committed windows.
    pub(crate) historical_admission_rows_written: usize,
    /// Exact historical `Ingest` Ledger refs independently read from disk.
    pub(crate) historical_admission_ledger_refs_verified: usize,
    /// Physical Ledger SST readers opened across shared window readbacks.
    pub(crate) persistence_ledger_files_opened: usize,
    /// Requested Ledger rows that required the complete-scan tier.
    pub(crate) persistence_ledger_complete_scan_wanted: usize,
    /// Physical persistence commits across combined historical/anchor windows.
    pub(crate) persistence_atomic_commits: usize,
    /// Physical flushes across combined historical/anchor windows.
    pub(crate) persistence_flushes: usize,
    /// Manifest-covered SST files published across persistence windows.
    pub(crate) persistence_durable_sst_files: usize,
    /// Manifest-covered SST rows published across persistence windows.
    pub(crate) persistence_durable_sst_entries: usize,
    /// Manifest-covered SST bytes published across persistence windows.
    pub(crate) persistence_durable_sst_bytes: u64,
    /// Logical Grounding entries admitted across all anchor batches.
    pub(crate) anchor_logical_entries: usize,
    /// Physical atomic commits used for those logical entries.
    pub(crate) anchor_atomic_commits: usize,
    /// Explicit vault flushes used for those atomic commits.
    pub(crate) anchor_flushes: usize,
    /// Largest logical batch observed during this pass.
    pub(crate) anchor_max_batch_entries: usize,
    /// Distinct final Anchors rows physically written across batches.
    pub(crate) anchor_rows_written: usize,
    /// Exact hash/sequence-bound Ledger refs independently point-read.
    pub(crate) anchor_ledger_refs_verified: usize,
    /// Manifest-covered durable SST files published by anchor flushes.
    pub(crate) anchor_durable_sst_files: usize,
    /// Rows encoded in manifest-covered durable SSTs.
    pub(crate) anchor_durable_sst_entries: usize,
    /// Bytes encoded in manifest-covered durable SSTs.
    pub(crate) anchor_durable_sst_bytes: u64,
    /// Live-router SST files published by anchor flushes.
    pub(crate) anchor_router_sst_files: usize,
    /// Rows encoded in live-router SSTs.
    pub(crate) anchor_router_sst_entries: usize,
    /// Bytes encoded in live-router SSTs.
    pub(crate) anchor_router_sst_bytes: u64,
    /// Handoffs that required a complete physical CF inventory because the
    /// durable completion marker was absent or behind the current manifest.
    pub(crate) anchor_router_handoff_full_inventories: usize,
    /// Active router memtable rows byte-matched to durable SSTs.
    pub(crate) anchor_router_handoff_memtable_rows_verified: usize,
    /// Covered router-flush files independently verified before retirement.
    pub(crate) anchor_router_handoff_flush_files_verified: usize,
    /// Covered router-flush rows independently verified before retirement.
    pub(crate) anchor_router_handoff_flush_entries_verified: usize,
    /// Covered router-flush files physically retired and read back absent.
    pub(crate) anchor_router_handoff_flush_files_retired: usize,
    /// Covered router-flush bytes physically retired and read back absent.
    pub(crate) anchor_router_handoff_flush_bytes_retired: u64,
    /// Manifest-covered router-flush debt remaining after the latest handoff.
    pub(crate) anchor_router_handoff_debt_files_after: usize,
    /// Manifest-covered router-flush debt bytes remaining after the latest handoff.
    pub(crate) anchor_router_handoff_debt_bytes_after: u64,
    /// Wall time spent inside ordered anchor group commits, flushes, and readback.
    pub(crate) anchor_batch_wall_ms: u64,
    /// Wall time for historical extraction/admission plus anchor persistence.
    pub(crate) index_loop_wall_ms: u64,
    /// Native process counter delta and final memory state for the index loop.
    pub(crate) index_loop_usage: VaultPhaseUsage,
}

/// Provenance source label for a `parent_repo` corpus (subtree of an enclosing repo).
pub(crate) const ARCHAEOLOGY_SOURCE_PARENT_REPO: &str = "parent_repo";
/// Provenance source label for an `own_repo` corpus (corpus IS its git toplevel).
pub(crate) const ARCHAEOLOGY_SOURCE_OWN_REPO: &str = "own_repo";

pub(crate) fn run_git_archaeology<C: Clock>(
    repo: &Path,
    project: &str,
    cache_dir: &Path,
    vault: &AsterVault<C>,
    mode: GitMineMode,
) -> Result<GitArchaeologyImportReport, DynError> {
    let mode_name = match &mode {
        GitMineMode::Full => "full",
        GitMineMode::Since { .. } => "incremental",
    };
    let (anchor_batch_limit, historical_batch_group_limit, diff_tree_batch_limit) =
        preflight_git_archaeology_persistence_limits()?;
    // Member-corpus scoping key (#403 + #381): resolve the requested corpus relative
    // to its git toplevel ONCE, up front. It drives three things: (a) it pathspec-
    // limits the history mine to the member subtree via
    // `GitArchaeologyConfig::member_prefix`, so the whole monorepo history is never
    // walked and out-of-subtree commits never enter the evidence set at the source;
    // (b) it drives the sparse historical checkout (only the member subtree
    // materializes on disk instead of the full ~5,500-file toplevel tree); and
    // (c) it re-anchors CBM's subtree-relative node paths back to the toplevel
    // namespace. Empty (corpus IS the toplevel) => whole-repo control path,
    // byte-identical to pre-scoping behavior on every axis.
    let corpus_rel = git_show_prefix(repo)?;
    let git_root = git_toplevel(repo)?;
    // Resolve, validate, bind, and read back the one explicit scratch namespace
    // before the history mine or any historical Git mutation. Fleet supplies this
    // root to every child; direct server launches must configure it themselves.
    // No alternate path is attempted on any failure.
    let scratch_scope = archaeology_scratch_scope(&git_root, project)?;
    // #434 phase-internal timing: opt-in via ASTRO_ARCH_TIMING, off by default so
    // production indexing is byte-for-byte unaffected. When set, the mine vs the
    // per-evidence-commit historical-reindex loop are timed separately (with counts)
    // so the 53.8s M-scale git_archaeology phase can be attributed to a real sub-phase
    // instead of guessed. Emitted once per pass, never per-row.
    let arch_timing = std::env::var_os("ASTRO_ARCH_TIMING").is_some();
    let mine_start = std::time::Instant::now();
    let config = GitArchaeologyConfig {
        member_prefix: (!corpus_rel.is_empty()).then(|| corpus_rel.clone()),
        diff_tree_batch_commits: diff_tree_batch_limit,
        ..GitArchaeologyConfig::default()
    };
    let mined = mine_git_archaeology(repo, &config, &mode)?;
    if arch_timing {
        eprintln!(
            "astro.arch.timing phase=mine ms={} szz={} reverts={} force_removed={} member_prefix={:?}",
            mine_start.elapsed().as_millis(),
            mined.szz_findings.len(),
            mined.revert_findings.len(),
            mined.force_removed_commits.len(),
            config.member_prefix,
        );
    }
    let mut evidence = Vec::new();
    for finding in &mined.szz_findings {
        evidence.push(Evidence {
            commit: finding.blamed_commit.clone(),
            range: GitLineRange {
                path: finding.path.clone(),
                start_line: finding.line,
                line_count: 1,
            },
            source: format!("git:fix:{}", finding.fix_commit),
            observed_at: finding.observed_at,
            confidence: finding.confidence,
            label: "bug_touch",
        });
    }
    for finding in &mined.revert_findings {
        evidence.push(Evidence {
            commit: finding.target_commit.clone(),
            range: finding.target_range.clone(),
            source: format!("git:revert:{}", finding.revert_commit),
            observed_at: finding.observed_at,
            confidence: 1.0,
            label: "reverted",
        });
    }
    let force_observed_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // #440 mass-change cap on the force_removed path: mirror the #434 fix/revert caps
    // that `mine_git_archaeology` already applies. `changed_new_ranges(repo, removed)`
    // below generates the WHOLE-commit `git diff --unified=0` for each force-removed
    // commit; a force-move that made a mass-change (relocation / bulk rename / tree
    // delete) commit unreachable would otherwise pay that full uncapped
    // diff-and-parse cost here — the exact cost the #434 cap removes on the fix/revert
    // paths, left uncapped on this one only because `force_removed=0` on the measured
    // cbm/ corpus. Gate it with the cheap `git diff --name-only` pre-count, scoped to
    // the WHOLE commit (`None`) to match the whole-commit `changed_new_ranges` it
    // precedes so the count reflects exactly the work being gated. Over the cap => the
    // commit is excluded from the reverted-anchor evidence set and counted as a labeled
    // skip (invariant 3), never silent. `0` disables the cap (pre-#440 behavior — mine
    // every force-removed commit regardless of size). The `config` built above already
    // carries the registry-declared `max_commit_changed_files`.
    let file_cap = config.max_commit_changed_files;
    let mut force_removed_skipped_large = 0usize;
    let mut force_removed_skipped_gitlink = 0usize;
    for removed in &mined.force_removed_commits {
        if file_cap != 0
            && astrolabe_anchors::archaeology::changed_file_count_for_commit(repo, removed, None)?
                > file_cap
        {
            force_removed_skipped_large += 1;
            continue;
        }
        let changed = astrolabe_anchors::archaeology::changed_new_ranges(repo, removed)?;
        force_removed_skipped_gitlink += changed.skipped_gitlink_paths;
        for range in changed.ranges {
            evidence.push(Evidence {
                commit: removed.clone(),
                range,
                source: format!("git:revert:{}", mined.head),
                observed_at: force_observed_at,
                confidence: 1.0,
                label: "reverted",
            });
        }
    }
    if arch_timing && !mined.force_removed_commits.is_empty() {
        eprintln!(
            "astro.arch.timing phase=force_removed commits={} skipped_large_commits={} file_cap={}",
            mined.force_removed_commits.len(),
            force_removed_skipped_large,
            file_cap,
        );
    }
    evidence.sort_by(|left, right| {
        left.commit
            .cmp(&right.commit)
            .then_with(|| left.range.cmp(&right.range))
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.label.cmp(right.label))
    });

    // Corpus scoping defense-in-depth (#403 + #381): the mine above is already
    // pathspec-limited to `member_prefix`, so out-of-subtree evidence should not
    // exist. This retain is the belt-and-suspenders net — it drops any residual
    // toplevel-relative path that fell outside the corpus subtree (e.g. a path
    // normalization corner the git pathspec and this string prefix disagree on),
    // so `index_historical_commit` below is never handed out-of-corpus evidence.
    // Empty `corpus_rel` (corpus IS the toplevel) is behavior-neutral.
    //
    // Unify the identity path convention (#418): the mine emits TOPLEVEL-relative
    // evidence paths (git blame/SZZ speak the repo-root namespace), but both the
    // historical CBM index — scoped to the member subtree — and the LIVE shadow
    // import emit SUBTREE-relative paths, and `rel_file_path` is framed into
    // `canonical_input_bytes` → the CxId (see `astrolabe_domain::canonical_input_bytes`).
    // If evidence stayed toplevel-relative while nodes are subtree-relative, attribution
    // would miss; if — as #403 did — historical nodes were re-anchored UP to the toplevel
    // namespace to match the evidence, their CxIds would diverge from the live graph and an
    // unchanged member symbol could never reuse its live constellation (reused == 0). We
    // therefore re-anchor the evidence DOWN into the one convention the live graph uses
    // (strip the corpus prefix) and leave historical nodes subtree-relative. Attribution
    // (`node_overlaps`/`location_overlaps`) and identity then both live in the
    // subtree-relative namespace, so anchors attach to live-graph CxIds. The corpus_rel
    // prefix survives ONLY on disk (the worktree checkout / `scoped_root`), never in the
    // in-memory paths that derive identity. Empty `corpus_rel` (toplevel corpus) skips this
    // block entirely, so the #413 whole-repo control path is byte-identical.
    if !corpus_rel.is_empty() {
        let corpus_prefix = format!("{corpus_rel}/");
        evidence.retain(|item| normalized_path(&item.range.path).starts_with(&corpus_prefix));
        for item in &mut evidence {
            // `retain` above guarantees the prefix is present; `unwrap_or` keeps this
            // fail-safe (never a silent mis-anchor) rather than assuming it.
            let normalized = normalized_path(&item.range.path);
            item.range.path = normalized
                .strip_prefix(&corpus_prefix)
                .map(str::to_string)
                .unwrap_or(normalized);
        }
    }

    // Provenance labeling (#434): a non-empty corpus_rel means the corpus is a
    // subtree of an enclosing repository whose `.git` we mined — the mined history
    // is PARENT-derived, and every walk above was pathspec-limited to `corpus_rel`
    // (#381). An empty corpus_rel means the corpus IS its own git toplevel. Persist
    // the discovered git root + the subtree pathspec so a consumer sees
    // `parent_repo(<root>) pathspec=<subtree>` rather than an unlabeled implicit walk
    // (invariant 1: no unlabeled claim; invariant 3: no silent fallback).
    let (archaeology_source, pathspec) = if corpus_rel.is_empty() {
        (ARCHAEOLOGY_SOURCE_OWN_REPO, None)
    } else {
        (ARCHAEOLOGY_SOURCE_PARENT_REPO, Some(corpus_rel.clone()))
    };
    let mut report = GitArchaeologyImportReport {
        head: mined.head,
        mode: mode_name,
        evidence: evidence.len(),
        skipped_merge_fixes: mined.skipped_merge_fixes,
        // #434 mine-side (fix/revert) mass-change skips PLUS #440 force_removed-path
        // mass-change skips — both surfaced in one labeled counter on the persisted
        // git_archaeology summary (invariant 3: every skip counted, never silent).
        skipped_large_commits: mined.skipped_large_commits + force_removed_skipped_large,
        skipped_unresolvable_reverts: mined.skipped_unresolvable_reverts,
        // #514 mine-side gitlink skips PLUS this path's force_removed-side gitlink
        // skips — one labeled counter on the persisted summary (invariant 3).
        skipped_gitlink_paths: mined.skipped_gitlink_paths + force_removed_skipped_gitlink,
        skipped_unblamable_paths: mined.skipped_unblamable_paths,
        diff_tree_count_requested_commits: mined.diff_tree.count_requested_commits,
        diff_tree_count_processes: mined.diff_tree.count_processes,
        diff_tree_count_processes_avoided: mined.diff_tree.count_processes_avoided,
        diff_tree_count_stdout_bytes: mined.diff_tree.count_stdout_bytes,
        diff_tree_ranges_requested_commits: mined.diff_tree.ranges_requested_commits,
        diff_tree_ranges_processes: mined.diff_tree.ranges_processes,
        diff_tree_ranges_processes_avoided: mined.diff_tree.ranges_processes_avoided,
        diff_tree_ranges_stdout_bytes: mined.diff_tree.ranges_stdout_bytes,
        diff_tree_count_wall_ms: mined.diff_tree.count_wall_ms,
        diff_tree_ranges_wall_ms: mined.diff_tree.ranges_wall_ms,
        diff_tree_batch_limit_commits: mined.diff_tree.batch_limit_commits,
        blame_requested_ranges: mined.blame.requested_ranges,
        blame_effective_ranges: mined.blame.effective_ranges,
        blame_groups: mined.blame.groups,
        blame_group_cache_hits: mined.blame.group_cache_hits,
        blame_processes: mined.blame.processes,
        blame_processes_avoided: mined.blame.processes_avoided,
        blame_cat_file_processes: mined.blame.cat_file_processes,
        blame_cat_file_stdout_bytes: mined.blame.cat_file_stdout_bytes,
        blame_path_absent_groups: mined.blame.path_absent_groups,
        blame_returned_spans: mined.blame.returned_spans,
        blame_returned_lines: mined.blame.returned_lines,
        blame_stdout_bytes: mined.blame.stdout_bytes,
        blame_wall_ms: mined.blame.wall_ms,
        blame_cat_file_wall_ms: mined.blame.cat_file_wall_ms,
        archaeology_source,
        git_root: git_root.clone(),
        pathspec,
        anchor_batch_registry_version:
            astrolabe_domain::knobs::ARCHAEOLOGY_PERSIST_KNOB_REGISTRY_VERSION,
        anchor_batch_limit,
        historical_batch_group_limit,
        ..GitArchaeologyImportReport::default()
    };
    let worktree_home = scratch_scope.worktree_home;
    // Best-effort, PID-gated sweep of worktrees left at this shared home by a prior
    // pass that crashed before cleanup (invariant 3: counted telemetry, never a
    // silent skip). Only dead-PID orphans are removed, so a concurrently-running
    // pass — its own live PID stamped in the name — is never disturbed.
    sweep_orphan_worktrees(repo, &worktree_home);

    let file_scoped = historical_index_file_scoped();
    // #530 pooled historical-extraction worker: ONE persistent child serves the whole
    // index_loop over an atomic request/response file handshake, so the #515 per-commit
    // spawn+init cost (measured ~4.2 s/commit on rtk by wave-25) is paid once per recycle
    // interval instead of once per commit. The #515 containment contract keeps a C-level
    // worker death/hang/malformed response from hard-exiting the host, but it is not a
    // publication fallback: a child fault is an index-wide correctness failure with exact
    // commit/detail remediation. The worker is proactively recycled (killed + respawned)
    // every [`ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT`] commits to bound the cumulative
    // C-heap damage of the #515 fault class to one interval.
    let mut pool = HistoricalExtractionPool::new(&scratch_scope.pool_home)?;
    // One archaeology pass owns one stable vault/panel contract. Reuse its validated
    // legacy-state decision, panel driver, retention decision, and Rayon's already-live
    // worker pool across every historical commit instead of cold-loading them per group.
    let historical_admission = HistoricalSymbolAdmissionSession::open(vault, SHADOW_PANEL_VERSION)?;
    let index_loop_start = std::time::Instant::now();
    let index_loop_usage_before = vault.process_usage_snapshot()?;
    let mut index_calls = 0usize;
    let mut index_ms_total = 0u128;
    let mut persistence_window: Option<ArchaeologyPersistenceWindow> = None;
    for (commit, group) in group_evidence_by_commit(&evidence) {
        // #439 file-scoped historical index: the DISTINCT set of subtree-relative
        // implicated files this evidence group touches. Multiple ranges hitting one
        // file collapse to a single checkout (BTreeSet de-dup); an empty set never
        // occurs because `group_evidence_by_commit` yields only non-empty groups.
        // Ignored entirely when `file_scoped` is false (pre-#439 whole-subtree path).
        let implicated_files: BTreeSet<String> =
            group.iter().map(|item| item.range.path.clone()).collect();
        let one_index_start = std::time::Instant::now();
        let indexed = index_historical_commit(
            repo,
            cache_dir,
            &worktree_home,
            project,
            commit,
            &corpus_rel,
            file_scoped,
            &implicated_files,
            &mut pool,
        )?;
        if arch_timing {
            index_calls += 1;
            index_ms_total += one_index_start.elapsed().as_millis();
        }
        report.cleanup_remnants += indexed.cleanup_remnants;
        report.historical_paths_windows_invalid += indexed.windows_invalid_excluded;
        report.historical_git_inventory_processes += indexed.git_inventory_processes;
        report.historical_git_checkout_processes += indexed.git_checkout_processes;
        report.historical_git_cat_file_processes += indexed.git_cat_file_processes;
        report.historical_git_cat_file_stdout_bytes += indexed.git_cat_file_stdout_bytes;
        report.historical_git_files_materialized += indexed.files_materialized;
        report.historical_dependency_files_materialized += indexed.dependency_files_materialized;
        report.historical_dependency_candidate_paths_absent +=
            indexed.dependency_candidate_paths_absent;
        report.historical_dependency_edges += indexed.dependency_edges;
        report.historical_dependency_revisits += indexed.dependency_revisits;
        report.historical_dependency_max_depth = report
            .historical_dependency_max_depth
            .max(indexed.dependency_depth);
        report.historical_git_paths_absent += indexed.paths_absent;
        report.historical_git_source_files_materialized += indexed.source_files_materialized;
        report.historical_commits_without_materialized_source +=
            usize::from(indexed.source_files_materialized == 0);
        report.historical_git_object_probe_processes_avoided +=
            indexed.object_probe_processes_avoided;
        report.historical_git_worktree_mutations_avoided += 2;
        // #515: the isolated extraction child died on a C-level pipeline fault for
        // this commit's checkout. It is CONTAINED (the host process survives) instead
        // of the pre-#515 in-process fault that hard-exited `index_repository` with a
        // silent empty-stdout rc=127, but Astrolabe must not publish a partial kernel
        // that pretends this commit has no historical symbols. Fail closed with enough
        // physical context to reproduce the exact materialization and fix CBM.
        if let Some(detail) = indexed.crashed {
            report.historical_commits_crashed += 1;
            eprintln!(
                "astro.archaeology.historical_index_failed commit={commit} \
                 evidence_in_group={} outcome=fail_closed cleanup_remnants={} \
                 files_materialized={} source_files_materialized={} detail={detail}",
                group.len(),
                report.cleanup_remnants,
                indexed.files_materialized,
                indexed.source_files_materialized
            );
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_HISTORICAL_INDEX_FAILED: commit={commit} \
                 evidence_in_group={} historical_commits_crashed={} cleanup_remnants={} \
                 windows_invalid_excluded={} files_materialized={} \
                 source_files_materialized={} paths_absent={} git_inventory_processes={} \
                 git_checkout_processes={} git_cat_file_processes={} \
                 git_cat_file_stdout_bytes={} object_probe_processes_avoided={} \
                 worktree_mutations_avoided={} evidence_total={} \
                 evidence_without_symbol_before={} detail={detail}; \
                 remediation=\"preserve the vault and archaeology scratch evidence; \
                 reproduce this exact commit/materialization and fix the CBM extraction \
                 fault before rerunning; no partial historical archaeology was published\"",
                group.len(),
                report.historical_commits_crashed,
                report.cleanup_remnants,
                report.historical_paths_windows_invalid,
                indexed.files_materialized,
                indexed.source_files_materialized,
                indexed.paths_absent,
                report.historical_git_inventory_processes,
                report.historical_git_checkout_processes,
                report.historical_git_cat_file_processes,
                report.historical_git_cat_file_stdout_bytes,
                indexed.object_probe_processes_avoided,
                report.historical_git_worktree_mutations_avoided,
                evidence.len(),
                report.evidence_without_symbol
            )
            .into());
        }
        let selected = select_implicated_rows(indexed.rows, group);
        if selected.nodes.is_empty() {
            report.evidence_without_symbol += group.len();
            continue;
        }
        let pending_upper_bound = match persistence_window.as_ref() {
            Some(window) => Some(window.anchor_entries.checked_add(group.len()).ok_or_else(
                || -> DynError {
                    "ASTRO_ARCHAEOLOGY_BATCH_OVERFLOW: pending anchor entry count overflowed usize; preserve the vault and reduce the declared batch limits"
                        .into()
                },
            )?),
            None => None,
        };
        if persistence_window.as_ref().is_some_and(|window| {
            window.groups.len() >= historical_batch_group_limit
                || pending_upper_bound.is_some_and(|count| count > anchor_batch_limit)
        }) {
            flush_archaeology_persistence_window(vault, &mut persistence_window, &mut report)?;
        }
        let snapshot = pipeline_rows_to_graph_snapshot(selected);
        // Historical constellations dedup against the live shadow vault, so they must
        // be minted under the same roster version as the main shadow import
        // (SHADOW_PANEL_VERSION) — a v1/v2 mismatch would derive divergent CxIds and
        // defeat reuse (#336).
        let options = SqliteImportOptions::new(project, commit, SHADOW_PANEL_VERSION)
            .with_available_slots(shadow_available_slots());
        if persistence_window.is_none() {
            persistence_window = Some(ArchaeologyPersistenceWindow {
                historical_batch: historical_admission.begin_batch(vault)?,
                groups: Vec::new(),
                anchor_entries: 0,
            });
        }
        let window = persistence_window.as_mut().expect("window initialized");
        let historical = historical_admission.prepare(
            &snapshot,
            vault,
            &ShadowSlotRuntime,
            &options,
            &mut window.historical_batch,
        )?;
        let anchors = build_anchor_admissions(group, historical.locations(), &mut report)?;
        report.historical_admission_groups += 1;

        if anchors.len() > anchor_batch_limit {
            if !window.groups.is_empty() || window.anchor_entries != 0 {
                return Err(
                    "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: oversized group reached a non-empty persistence window after preflight; preserve the vault and inspect window accounting"
                        .into(),
                );
            }
            let mut chunks = anchors.into_iter();
            let first = chunks.by_ref().take(anchor_batch_limit).collect::<Vec<_>>();
            window.groups.push(PendingArchaeologyPersistenceGroup {
                historical: Some(historical),
                anchors: first,
            });
            window.anchor_entries = anchor_batch_limit;
            flush_archaeology_persistence_window(vault, &mut persistence_window, &mut report)?;

            let mut remaining = chunks.collect::<Vec<_>>().into_iter();
            loop {
                let chunk = remaining
                    .by_ref()
                    .take(anchor_batch_limit)
                    .collect::<Vec<_>>();
                if chunk.is_empty() {
                    break;
                }
                let chunk_len = chunk.len();
                persistence_window = Some(ArchaeologyPersistenceWindow {
                    historical_batch: historical_admission.begin_batch(vault)?,
                    groups: vec![PendingArchaeologyPersistenceGroup {
                        historical: None,
                        anchors: chunk,
                    }],
                    anchor_entries: chunk_len,
                });
                flush_archaeology_persistence_window(vault, &mut persistence_window, &mut report)?;
            }
            continue;
        }

        window.anchor_entries = window
            .anchor_entries
            .checked_add(anchors.len())
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_BATCH_OVERFLOW: persistence window anchor entry count overflowed usize; preserve the vault and reduce the declared limits"
                    .into()
            })?;
        window.groups.push(PendingArchaeologyPersistenceGroup {
            historical: Some(historical),
            anchors,
        });
    }
    flush_archaeology_persistence_window(vault, &mut persistence_window, &mut report)?;
    // #530: retire the pooled worker and its scratch dir. Idempotent with Drop, but
    // called explicitly here so the served/spawn telemetry lands inside the pass and any
    // dir remnant is counted before the report is finalized.
    report.historical_post_success_worker_recycles += pool.post_success_recycles;
    report.historical_post_success_cleanup_timeouts += pool.post_success_cleanup_timeouts;
    report.cleanup_remnants += pool.finish();
    report.index_loop_wall_ms = elapsed_ms(index_loop_start.elapsed());
    report.index_loop_usage = vault
        .process_usage_snapshot()?
        .phase_since(index_loop_usage_before);
    if arch_timing {
        eprintln!(
            "astro.arch.timing phase=index_loop file_scoped={file_scoped} ms={} \
             distinct_commits={index_calls} sum_per_commit_ms={index_ms_total} evidence={} \
             constellations_written={} constellations_reused={} evidence_without_symbol={}",
            index_loop_start.elapsed().as_millis(),
            report.evidence,
            report.historical_constellations_written,
            report.historical_constellations_reused,
            report.evidence_without_symbol,
        );
    }
    Ok(report)
}

fn archaeology_anchor_batch_entries() -> Result<usize, DynError> {
    archaeology_persist_limit(
        astrolabe_domain::knobs::ARCHAEOLOGY_ANCHOR_BATCH_ENTRIES_KNOB,
        ARCHAEOLOGY_ANCHOR_BATCH_ENV,
        "logical anchor entries",
    )
}

fn archaeology_historical_batch_groups() -> Result<usize, DynError> {
    archaeology_persist_limit(
        astrolabe_domain::knobs::ARCHAEOLOGY_HISTORICAL_BATCH_GROUPS_KNOB,
        ARCHAEOLOGY_HISTORICAL_BATCH_ENV,
        "historical commit groups",
    )
}

fn archaeology_diff_tree_batch_commits() -> Result<usize, DynError> {
    archaeology_persist_limit(
        astrolabe_domain::knobs::ARCHAEOLOGY_DIFF_TREE_BATCH_COMMITS_KNOB,
        ARCHAEOLOGY_DIFF_TREE_BATCH_ENV,
        "commits",
    )
}

/// Validate every operator-controlled archaeology persistence bound before an
/// index transition or staging publication can mutate durable state.
pub(crate) fn preflight_git_archaeology_persistence_limits()
-> Result<(usize, usize, usize), DynError> {
    Ok((
        archaeology_anchor_batch_entries()?,
        archaeology_historical_batch_groups()?,
        archaeology_diff_tree_batch_commits()?,
    ))
}

fn archaeology_persist_limit(knob: &str, environment: &str, unit: &str) -> Result<usize, DynError> {
    let declaration = astrolabe_domain::knobs::archaeology_persist_knob(knob).ok_or_else(
        || -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_PERSIST_REGISTRY_MISSING: {knob} is absent; restore the {} registry before indexing",
                astrolabe_domain::knobs::ARCHAEOLOGY_PERSIST_KNOB_REGISTRY_VERSION
            )
            .into()
        },
    )?;
    let Some(raw) = std::env::var_os(environment) else {
        return usize::try_from(declaration.default).map_err(|_| {
            format!(
                "ASTRO_ARCHAEOLOGY_PERSIST_LIMIT_INVALID: registry default {} for {knob} cannot be represented as usize; correct {}",
                declaration.default, declaration.registry_version
            )
            .into()
        });
    };
    let value = raw.into_string().map_err(|raw| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_PERSIST_LIMIT_INVALID: {environment} is not Unicode ({raw:?}); remove it or set an ASCII decimal integer in {}..={} {unit}",
            declaration.min, declaration.max
        )
        .into()
    })?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_PERSIST_LIMIT_INVALID: {environment}={value:?} is not a non-empty ASCII decimal integer; remove it or set {}..={} {unit}",
            declaration.min, declaration.max
        )
        .into());
    }
    let parsed = value.parse::<u64>().map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_PERSIST_LIMIT_INVALID: {environment}={value:?} cannot be represented as u64 ({error}); set {}..={} {unit}",
            declaration.min, declaration.max
        )
        .into()
    })?;
    if !declaration.accepts(parsed) {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_PERSIST_LIMIT_INVALID: {environment}={parsed} is outside the declared {}..={} {unit} bound; correct the value before indexing",
            declaration.min, declaration.max
        )
        .into());
    }
    usize::try_from(parsed).map_err(|_| {
        format!(
            "ASTRO_ARCHAEOLOGY_PERSIST_LIMIT_INVALID: {environment}={parsed} cannot be represented by this process; lower it within the declared bound"
        )
        .into()
    })
}

fn build_anchor_admissions(
    evidence: &[Evidence],
    admitted: &[HistoricalSymbolLocation],
    report: &mut GitArchaeologyImportReport,
) -> Result<Vec<PendingAnchorAdmission>, DynError> {
    let mut pending = Vec::with_capacity(evidence.len());
    for item in evidence {
        let locations = admitted
            .iter()
            .filter(|location| location_overlaps(location, &item.range))
            .collect::<Vec<_>>();
        if locations.is_empty() {
            report.evidence_without_symbol += 1;
            continue;
        }
        let mut cx_ids = BTreeMap::new();
        let mut subjects = Vec::new();
        for location in locations {
            let subject_id = historical_subject_id(location);
            if cx_ids.insert(subject_id.clone(), location.cx_id).is_none() {
                subjects.push(OutcomeSubject {
                    subject_id,
                    anchor_kind: AnchorKind::Label(item.label.to_string()),
                    value: AnchorValue::Bool(true),
                });
            }
        }
        let request = OutcomeAnchorRequest::new(
            OutcomeKind::GitArchaeology,
            item.source.clone(),
            item.observed_at,
            Some(item.confidence),
            subjects,
        )?;
        pending.push(PendingAnchorAdmission { request, cx_ids });
    }
    Ok(pending)
}

fn flush_archaeology_persistence_window<C: Clock>(
    vault: &AsterVault<C>,
    window: &mut Option<ArchaeologyPersistenceWindow>,
    report: &mut GitArchaeologyImportReport,
) -> Result<(), DynError> {
    let Some(window) = window.take() else {
        return Ok(());
    };
    if window.groups.is_empty() {
        if window.anchor_entries != 0 {
            return Err(
                "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: empty persistence window retained nonzero anchor accounting; preserve the vault and inspect window construction"
                    .into(),
            );
        }
        return Ok(());
    }
    let started = std::time::Instant::now();
    let snapshot = window.historical_batch.snapshot();
    let historical_groups = window
        .groups
        .iter()
        .filter(|group| group.historical.is_some())
        .count();
    let historical_entries = window
        .groups
        .iter()
        .filter_map(|group| group.historical.as_ref())
        .filter(|prepared| prepared.has_write_group())
        .count();
    let anchor_items = window
        .groups
        .iter()
        .flat_map(|group| &group.anchors)
        .map(|item| OutcomeAnchorBatchItem::new(&item.request, &item.cx_ids))
        .collect::<Vec<_>>();
    if anchor_items.len() != window.anchor_entries {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: window counted {} anchor entries but retained {}; preserve the vault and inspect ordered staging",
            window.anchor_entries,
            anchor_items.len()
        )
        .into());
    }
    let mut prepared_anchors = if anchor_items.is_empty() {
        None
    } else {
        Some(prepare_outcome_anchor_batch(
            vault,
            &anchor_items,
            ARCHAEOLOGY_ACTOR,
        )?)
    };
    let mut anchor_groups = prepared_anchors
        .as_mut()
        .map(PreparedOutcomeAnchorBatch::take_write_groups)
        .unwrap_or_default()
        .into_iter();
    let mut ordered = Vec::<LedgerBoundWriteGroup>::new();
    let mut completion = Vec::with_capacity(window.groups.len());
    for mut group in window.groups {
        let historical_has_receipt = group
            .historical
            .as_ref()
            .is_some_and(PreparedHistoricalSymbolAdmission::has_write_group);
        if let Some(write) = group
            .historical
            .as_mut()
            .and_then(PreparedHistoricalSymbolAdmission::take_write_group)
        {
            ordered.push(write);
        }
        let anchor_count = group.anchors.len();
        for _ in 0..anchor_count {
            ordered.push(anchor_groups.next().ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: prepared anchor groups ended before their owning evidence group; preserve the vault and inspect ordered staging"
                    .into()
            })?);
        }
        completion.push((group.historical, historical_has_receipt, anchor_count));
    }
    if anchor_groups.next().is_some() {
        return Err(
            "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: prepared anchor groups remained after ordered window assembly; preserve the vault and inspect group accounting"
                .into(),
        );
    }

    if ordered.is_empty() {
        for (historical, _, _) in completion {
            if let Some(historical) = historical {
                let admission = historical.complete(vault, snapshot, None, None)?;
                record_historical_admission(report, admission);
            }
        }
        return Ok(());
    }

    let commit = vault.write_ledger_bound_groups_if_seq(snapshot, ordered)?;
    let flush = vault.flush_with_report()?;
    let wanted = commit
        .groups
        .iter()
        .map(|receipt| receipt.ledger_ref.seq)
        .collect::<BTreeSet<_>>();
    let (ledger_rows, ledger_trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let complete_scan_wanted = ledger_trace
        .tiers
        .iter()
        .filter(|tier| tier.tier == "complete_scan")
        .map(|tier| tier.wanted)
        .sum::<usize>();
    if complete_scan_wanted != 0 {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_LEDGER_POINT_READ_DEGRADED: just-published ordered window required complete-scan resolution for {complete_scan_wanted} Ledger rows; preserve the vault and repair the commit-ordered index before continuing"
        )
        .into());
    }
    report.persistence_ledger_files_opened += ledger_trace
        .tiers
        .iter()
        .map(|tier| tier.files_opened)
        .sum::<usize>();
    report.persistence_ledger_complete_scan_wanted += complete_scan_wanted;
    report.persistence_atomic_commits += 1;
    report.persistence_flushes += 1;
    report.persistence_durable_sst_files += flush.durable_ssts.len();
    report.persistence_durable_sst_entries += flush
        .durable_ssts
        .iter()
        .map(|summary| summary.entries)
        .sum::<usize>();
    report.persistence_durable_sst_bytes = report.persistence_durable_sst_bytes.saturating_add(
        flush
            .durable_ssts
            .iter()
            .map(|summary| summary.bytes)
            .sum::<u64>(),
    );
    if historical_entries != 0 {
        report.historical_admission_logical_entries += historical_entries;
        report.historical_admission_atomic_commits += 1;
        report.historical_admission_flushes += 1;
        report.historical_admission_max_window_groups = report
            .historical_admission_max_window_groups
            .max(historical_groups);
    }

    let anchor_entries = window.anchor_entries;
    if anchor_entries != 0 {
        record_anchor_flush(report, anchor_entries, &flush);
    }
    let mut receipts = commit.groups.into_iter();
    let mut anchor_receipts = Vec::<LedgerBoundGroupReceipt>::with_capacity(anchor_entries);
    for (historical, historical_has_receipt, anchor_count) in completion {
        if let Some(historical) = historical {
            let historical_receipt = if historical_has_receipt {
                Some(receipts.next().ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: committed receipts omitted a historical Ingest group; preserve the vault and inspect ordered staging"
                        .into()
                })?)
            } else {
                None
            };
            let admission_seq = if historical_has_receipt {
                commit.seq
            } else {
                historical.snapshot()
            };
            let admission = historical.complete(
                vault,
                admission_seq,
                historical_receipt,
                historical_has_receipt.then_some(&ledger_rows),
            )?;
            record_historical_admission(report, admission);
        }
        for _ in 0..anchor_count {
            anchor_receipts.push(receipts.next().ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: committed receipts omitted a Grounding group; preserve the vault and inspect ordered staging"
                    .into()
            })?);
        }
    }
    if receipts.next().is_some() {
        return Err(
            "ASTRO_ARCHAEOLOGY_BATCH_ORDER_INVALID: committed logical receipts remained after window finalization; preserve the vault and inspect ordered staging"
                .into(),
        );
    }
    if let Some(prepared) = prepared_anchors {
        let batch = prepared.complete(
            vault,
            commit.seq,
            anchor_receipts,
            &ledger_rows,
            ledger_trace,
            flush,
        )?;
        report.anchor_rows_written += batch.rows_written;
        report.anchor_ledger_refs_verified += batch.ledger_refs_verified;
        for item in batch.items {
            report.anchors_written += item.anchors_written;
            report.anchors_deduplicated += item.anchors_deduplicated;
        }
    }
    report.anchor_batch_wall_ms = report
        .anchor_batch_wall_ms
        .saturating_add(elapsed_ms(started.elapsed()));
    Ok(())
}

fn record_historical_admission(
    report: &mut GitArchaeologyImportReport,
    admission: astrolabe_ingest::HistoricalSymbolAdmissionReport,
) {
    report.historical_constellations_written += admission.constellations_written;
    report.historical_constellations_reused += admission.constellations_reused;
    report.historical_admission_rows_written += admission.rows_written;
    report.historical_admission_ledger_refs_verified += usize::from(admission.ledger_ref.is_some());
}

fn record_anchor_flush(
    report: &mut GitArchaeologyImportReport,
    logical_entries: usize,
    flush: &calyx_aster::vault::VaultFlushReport,
) {
    report.anchor_logical_entries += logical_entries;
    report.anchor_atomic_commits += 1;
    report.anchor_flushes += 1;
    report.anchor_max_batch_entries = report.anchor_max_batch_entries.max(logical_entries);
    report.anchor_durable_sst_files += flush.durable_ssts.len();
    report.anchor_durable_sst_entries += flush
        .durable_ssts
        .iter()
        .map(|summary| summary.entries)
        .sum::<usize>();
    report.anchor_durable_sst_bytes = report.anchor_durable_sst_bytes.saturating_add(
        flush
            .durable_ssts
            .iter()
            .map(|summary| summary.bytes)
            .sum::<u64>(),
    );
    report.anchor_router_sst_files += flush.router_ssts.len();
    report.anchor_router_sst_entries += flush
        .router_ssts
        .iter()
        .map(|summary| summary.entries)
        .sum::<usize>();
    report.anchor_router_sst_bytes = report.anchor_router_sst_bytes.saturating_add(
        flush
            .router_ssts
            .iter()
            .map(|summary| summary.bytes)
            .sum::<u64>(),
    );
    if let Some(handoff) = &flush.router_handoff {
        report.anchor_router_handoff_full_inventories += usize::from(handoff.full_inventory);
        report.anchor_router_handoff_memtable_rows_verified += handoff.memtable_rows_verified;
        report.anchor_router_handoff_flush_files_verified += handoff.flush_sst_files_verified;
        report.anchor_router_handoff_flush_entries_verified += handoff.flush_sst_entries_verified;
        report.anchor_router_handoff_flush_files_retired += handoff.flush_sst_files_retired;
        report.anchor_router_handoff_flush_bytes_retired = report
            .anchor_router_handoff_flush_bytes_retired
            .saturating_add(handoff.flush_sst_bytes_retired);
        report.anchor_router_handoff_debt_files_after = handoff.covered_flush_debt_files_after;
        report.anchor_router_handoff_debt_bytes_after = handoff.covered_flush_debt_bytes_after;
    }
}

fn elapsed_ms(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Validate and durably bind the exact archaeology scratch scope before the
/// shadow publication or native index pass starts. A non-git corpus never calls
/// this preflight; its archaeology result remains explicitly unavailable.
pub(crate) fn preflight_git_archaeology_scratch(
    repo: &Path,
    project: &str,
) -> Result<(), DynError> {
    let git_root = git_toplevel(repo)?;
    let _ = archaeology_scratch_scope(&git_root, project)?;
    Ok(())
}

/// #515 fail-closed ceiling for one isolated historical-commit extraction child.
/// File-scoped historical indexing (#439) materializes only the handful of files an
/// evidence group touches, so a single extraction is sub-second in practice; this
/// bound is not a tuned throughput knob but a hang guard — a child still running
/// after it is killed and reported as a contained fault rather than stalling the
/// whole import on an unbounded wait (invariant 3: the degradation is labeled/counted,
/// never a silent indefinite block).
const ARCHAEOLOGY_EXTRACT_TIMEOUT: Duration = Duration::from_secs(300);

/// #858 bounded diagnostic tail retained in a contained archaeology-worker fault.
/// The previous short tail could drop the corrupting phase markers on large Rust
/// repositories where warnings and telemetry are both active. This is still a fixed
/// evidence budget, not an unbounded log dump.
const ARCHAEOLOGY_EXTRACT_STDERR_TAIL_CHARS: usize = 12_000;

/// #515 poll granularity while waiting on the isolated extraction child. Short so a
/// sub-second extraction is not padded, bounded so the wait loop never spins hot.
const ARCHAEOLOGY_EXTRACT_POLL: Duration = Duration::from_millis(25);

/// #530 registry-declared recycle interval: the maximum number of commits ONE pooled
/// extraction worker serves before it is proactively killed and respawned. This is not
/// a throughput tuning knob but a fail-closed damage bound: the #515 fault class is
/// CUMULATIVE C-heap corruption, so serving an unbounded number of commits in one
/// long-lived worker would let that damage accumulate exactly as the pre-#515
/// in-process loop did. Recycling every N commits caps the cumulative exposure of any
/// one worker to N commits' worth of extractions while still amortizing the spawn+init
/// cost over the whole interval (instead of paying it once per commit). Overridable per
/// run via `ASTRO_ARCHAEOLOGY_POOL_RECYCLE_AFTER` (a decimal count; `0` disables
/// proactive recycle so one worker serves the whole loop, recycled only on crash). An
/// unparseable value falls back to this default (never a silent flip).
const ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT: u64 = 64;

/// Reads the effective #530 pooled-worker recycle interval: the
/// [`ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT`] registry default, overridable per run via
/// `ASTRO_ARCHAEOLOGY_POOL_RECYCLE_AFTER` so a probe can force frequent recycles on a
/// small corpus. `0` disables proactive recycle. An unrecognized value falls back to the
/// default (invariant 3: never a silent flip to some other bound).
fn archaeology_pool_recycle_after() -> u64 {
    match std::env::var("ASTRO_ARCHAEOLOGY_POOL_RECYCLE_AFTER") {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .unwrap_or(ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT),
        Err(_) => ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT,
    }
}

/// Directory-name prefix for a transient git-archaeology extraction POOL dir (#530),
/// rooted under the repo+project-bound compact namespace returned by
/// [`archaeology_scratch_scope`]. The embedded owner PID is
/// the sweep's concurrency discriminator: [`sweep_orphan_pools`] removes a leftover pool
/// dir only when its PID is dead, so a concurrent live archaeology pass is never swept
/// out from under itself.
const ARCHAEOLOGY_POOL_PREFIX: &str = "p-";

/// Categorized read of one pooled-worker response file (#530), so the caller can tell a
/// clean extraction from a RECOVERABLE Rust-level pipeline error (the worker stays warm)
/// from a MALFORMED response (the worker is suspect and is recycled).
enum PoolResponse {
    /// The worker extracted rows cleanly; it stays warm to serve the next commit.
    Rows(CbmPipelineRows),
    /// The worker caught a Rust-level pipeline error (e.g. the scratch db could not be
    /// opened) and reported it as a structured `{ok:false,error}` response WITHOUT dying.
    /// The commit yields no rows (counted as a contained fault, exactly as the pre-#530
    /// nonzero-exit child was) but the worker is still healthy, so it is NOT recycled.
    RecoverableError(String),
    /// The response bytes were present but not a well-formed rows/error envelope. The
    /// worker's output cannot be trusted, so it is recycled defensively.
    Malformed(String),
}

/// Interprets one pooled-worker response file's bytes (#530). An `{ok:false,...}`
/// envelope is a recoverable Rust-level pipeline error the warm worker reported; any
/// other well-formed body is parsed as rows; a body that is neither is malformed.
fn interpret_pool_response(bytes: &[u8], project: &str) -> PoolResponse {
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => return PoolResponse::Malformed(format!("response JSON parse: {error}")),
    };
    if value.get("ok").and_then(Value::as_bool) == Some(false) {
        let error = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("archaeology_extract_error: unspecified pooled extraction error")
            .to_string();
        return PoolResponse::RecoverableError(error);
    }
    match parse_extract_response(bytes, project) {
        Ok(rows) => PoolResponse::Rows(rows),
        Err(detail) => PoolResponse::Malformed(detail),
    }
}

/// #530 pooled historical-extraction worker: ONE persistent child process that serves
/// every evidence commit's CBM extraction serially over an atomic request/response FILE
/// handshake, replacing the #515 per-commit spawn.
///
/// This is the crash-isolation boundary (#515) AND the spawn-cost amortizer (#530). The
/// main shadow import already runs CBM out-of-process in a supervised worker (#405); the
/// per-commit historical re-index did not, so a C-level pipeline fault (abort / access
/// violation / heap-corruption class) on one of a large repo's historical checkouts
/// hard-exited the ENTIRE host `index_repository` — an empty-stdout `rc=127` silent
/// termination with no structured error (issue #515, reproduced on rtk-ai/rtk after the
/// live CBM graph was already complete). #515 contained that by spawning a fresh child
/// per commit; measured at ~4.2 s/commit spawn+init on rtk (511 commits ≈ 36 min of a
/// 44-min run), that isolation dominated M-scale runs. #530 pays the spawn+init cost
/// ONCE per recycle interval instead: the parent writes `request-<seq>.json` (atomic
/// temp-then-rename), the warm worker reads it, runs the identical `CbmPipeline` (same
/// `scoped_root`, scratch `database`, Fast mode — so emitted subtree-relative node paths
/// and thus CxIds are byte-identical to the pre-#530 path), and writes
/// `response-<seq>.json` (atomic). The #515 containment contract is PRESERVED as
/// host-process isolation, not as a partial-publication fallback:
///   * worker death mid-request (C-level fault) — detected via `try_wait` — is a
///     [`HistoricalExtract::Crashed`] on exactly the in-flight commit; the caller fails
///     the index-wide request with exact detail, and the host never dies;
///   * a worker that does not answer within [`ARCHAEOLOGY_EXTRACT_TIMEOUT`] is killed as
///     hung and treated the same way;
///   * a RECOVERABLE Rust-level pipeline error is answered as a structured
///     `{ok:false,error}` response so the warm worker can report it deterministically;
///     the caller still fails the index-wide request rather than inventing empty rows.
///
/// The worker is proactively recycled (killed + respawned) every
/// [`ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT`] commits to bound the cumulative C-heap
/// damage of the #515 fault class to one interval.
struct HistoricalExtractionPool {
    /// The running astrolabe executable, re-spawned as the serve worker.
    exe: PathBuf,
    /// Nonce'd scratch dir holding the handshake files and the worker log.
    pool_dir: PathBuf,
    /// Combined stdout+stderr log of the current/last worker (fault-detail source).
    log_path: PathBuf,
    /// Proactive recycle interval; `0` disables proactive recycle (crash-only).
    recycle_after: u64,
    /// The live worker, or `None` before the first spawn / after a crash or recycle.
    child: Option<Child>,
    /// Request/response sequence for the CURRENT worker. Reset to 0 on every spawn so the
    /// parent and the fresh worker (which starts its own counter at 0) agree on the
    /// `request-<seq>.json`/`response-<seq>.json` filenames.
    seq: u64,
    /// Commits the CURRENT worker has served since spawn; drives proactive recycle.
    served: u64,
    /// Total workers spawned across the whole pass (telemetry only).
    spawns: u64,
    /// Workers that published a complete success response but were not reusable
    /// after the response because native teardown exited/faulted or was killed.
    post_success_recycles: usize,
    /// Post-success workers killed because cleanup did not return to the serve
    /// loop before the existing extraction timeout.
    post_success_cleanup_timeouts: usize,
}

impl HistoricalExtractionPool {
    /// Creates the pool (its nonce'd scratch dir) but does NOT spawn a worker yet — the
    /// first [`extract`](Self::extract) spawns lazily, so a pass with zero evidence
    /// commits never pays a spawn. Sweeps dead-PID orphan pool dirs first (#530), the
    /// same PID-gated discipline the scratch worktrees use (#427).
    fn new(home: &Path) -> Result<Self, DynError> {
        let exe = std::env::current_exe().map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_POOL_EXE_UNRESOLVED: could not resolve the running astrolabe \
                 executable to spawn the pooled historical-index worker: {error}; remediation: \
                 this is an internal invariant of index_repository — retry the run"
            )
            .into()
        })?;
        sweep_orphan_pools(home);
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let pool_dir = home.join(format!("{ARCHAEOLOGY_POOL_PREFIX}{nonce}"));
        fs::create_dir_all(&pool_dir).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_POOL_DIR_UNUSABLE: could not create the archaeology \
                 extraction-pool dir {}: {error}; remediation: ensure {ARCHAEOLOGY_ROOT_ENV} \
                 names a writable local directory and re-run index_repository",
                pool_dir.display()
            )
            .into()
        })?;
        let log_path = pool_dir.join("worker.log");
        Ok(Self {
            exe,
            pool_dir,
            log_path,
            recycle_after: archaeology_pool_recycle_after(),
            child: None,
            seq: 0,
            served: 0,
            spawns: 0,
            post_success_recycles: 0,
            post_success_cleanup_timeouts: 0,
        })
    }

    /// Spawns a fresh serve worker, resetting the per-worker sequence/served counters and
    /// clearing any leftover handshake files so the fresh worker (seq=0) and this parent
    /// (seq=0) start from an empty dir.
    fn spawn_worker(&mut self) -> Result<(), DynError> {
        self.clear_handshake_files();
        let log = fs::File::create(&self.log_path).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_POOL_LOG_UNUSABLE: could not create the pooled worker log {}: \
                 {error}; remediation: ensure {ARCHAEOLOGY_ROOT_ENV} names a writable local \
                 directory and re-run",
                self.log_path.display()
            )
            .into()
        })?;
        let log_clone = log.try_clone()?;
        let spawn_start = Instant::now();
        let child = Command::new(&self.exe)
            .args(["cli", "--archaeology-extract-serve", "--pool-dir"])
            .arg(&self.pool_dir)
            // The archaeology worker is an isolated crash boundary. Its stderr is
            // the preserved fault ledger, so native C phase markers must be emitted
            // even when the general CBM log level is raised to WARN/ERROR for a long
            // fleet run. This is diagnostic tracing only; it does not change the
            // extraction result or provide a fallback path.
            .env("ASTRO_CBM_PIPELINE_PHASE_TRACE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_clone))
            .spawn()
            .map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_POOL_SPAWN_FAILED: could not spawn the pooled \
                     historical-index worker {}: {error}; remediation: ensure the astrolabe \
                     binary is present and executable on this host",
                    self.exe.display()
                )
                .into()
            })?;
        let worker_pid = child.id();
        self.child = Some(child);
        self.seq = 0;
        self.served = 0;
        self.spawns += 1;
        eprintln!(
            "astro.archaeology.pool event=spawn worker_pid={worker_pid} spawns={} \
             recycle_after={} spawn_ms={}",
            self.spawns,
            self.recycle_after,
            spawn_start.elapsed().as_millis(),
        );
        Ok(())
    }

    /// Ensures a live worker exists, spawning one if the pool has none (first use, or
    /// after a crash/recycle set `child` to `None`).
    fn ensure_worker(&mut self) -> Result<(), DynError> {
        if self.child.is_none() {
            self.spawn_worker()?;
        }
        Ok(())
    }

    /// Kills the current worker (if any) and forgets it, so the next
    /// [`ensure_worker`](Self::ensure_worker) spawns a fresh one. Emits recycle telemetry.
    fn recycle(&mut self, reason: &str) {
        if let Some(mut child) = self.child.take() {
            let worker_pid = child.id();
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "astro.archaeology.pool event=recycle reason={reason} worker_pid={worker_pid} \
                 served={}",
                self.served,
            );
        }
    }

    /// Removes any leftover `request-*`/`response-*` handshake files from the pool dir
    /// (belt-and-suspenders before a spawn; extraction removes them per request).
    fn clear_handshake_files(&self) {
        let Ok(entries) = fs::read_dir(&self.pool_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with("request-") || name.starts_with("response-") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn wait_for_worker_after_response(
        &mut self,
        commit: &str,
        request_path: &Path,
        deadline: Instant,
    ) -> bool {
        loop {
            let request_removed = !request_path.exists();
            let Some(child) = self.child.as_mut() else {
                return false;
            };
            let worker_pid = child.id();
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child = None;
                    self.post_success_recycles += 1;
                    eprintln!(
                        "astro.archaeology.pool event=post_success_worker_recycle \
                         reason=worker_exited_after_response commit={commit} \
                         worker_pid={worker_pid} request_removed={request_removed} exit={}",
                        worker_exit_text(status),
                    );
                    return false;
                }
                Ok(None) if request_removed => return true,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        self.post_success_recycles += 1;
                        self.post_success_cleanup_timeouts += 1;
                        eprintln!(
                            "astro.archaeology.pool event=post_success_worker_recycle \
                             reason=cleanup_timeout_after_response commit={commit} \
                             worker_pid={worker_pid} timeout_seconds={}",
                            ARCHAEOLOGY_EXTRACT_TIMEOUT.as_secs(),
                        );
                        self.recycle("post_success_cleanup_timeout");
                        return false;
                    }
                    thread::sleep(ARCHAEOLOGY_EXTRACT_POLL);
                }
                Err(error) => {
                    self.post_success_recycles += 1;
                    eprintln!(
                        "astro.archaeology.pool event=post_success_worker_recycle \
                         reason=wait_failed_after_response commit={commit} \
                         worker_pid={worker_pid} error={error}"
                    );
                    self.recycle("post_success_wait_failed");
                    return false;
                }
            }
        }
    }

    /// Runs one historical commit's CBM extraction on the pooled worker (#530). Spawns or
    /// recycles the worker as needed, writes the request atomically, then waits for the
    /// response file, the worker's death, or the per-extraction timeout — whichever comes
    /// first. Returns [`HistoricalExtract::Rows`] on a clean extraction, or
    /// [`HistoricalExtract::Crashed`] (a contained, labeled child fault) on a worker
    /// death / hang / recoverable pipeline error / malformed response. The caller must
    /// fail the index-wide request with the returned detail; `scoped_root`/`database`
    /// are absolute scratch paths; the worker resolves them itself.
    fn extract(
        &mut self,
        scoped_root: &Path,
        database: &Path,
        identity_root: &Path,
        project: &str,
        commit: &str,
    ) -> Result<HistoricalExtract, DynError> {
        // Proactive recycle BEFORE the next request bounds cumulative C-heap damage (the
        // #515 fault class) to `recycle_after` commits per worker.
        if self.recycle_after != 0 && self.child.is_some() && self.served >= self.recycle_after {
            self.recycle("interval");
        }
        self.ensure_worker()?;
        let seq = self.seq;
        let request_path = self.pool_dir.join(format!("request-{seq}.json"));
        let request_tmp = self.pool_dir.join(format!("request-{seq}.json.tmp"));
        let response_path = self.pool_dir.join(format!("response-{seq}.json"));
        let response_tmp = self.pool_dir.join(format!("response-{seq}.json.tmp"));
        // A stale response from a prior seq collision cannot exist (files are removed per
        // request and on spawn), but remove defensively so `exists()` below is unambiguous.
        let _ = fs::remove_file(&response_path);
        let request = json!({
            "scoped_root": path_str(scoped_root)?,
            "database": path_str(database)?,
            "identity_root": path_str(identity_root)?,
            "project": project,
            "mode": "fast",
            "commit": commit,
            "parent_seq": seq,
        });
        // Atomic appearance for the worker: write the temp, then rename into place, so the
        // worker never reads a half-written request.
        let request_bytes = serde_json::to_vec(&request)?;
        let request_sha256 = hex_lower(&Sha256::digest(&request_bytes));
        fs::write(&request_tmp, &request_bytes)?;
        fs::rename(&request_tmp, &request_path)?;
        log_archaeology_serve_trace(
            "parent_request_published",
            json!({
                "seq": seq,
                "commit": commit,
                "worker_pid": self.child.as_ref().map(Child::id),
                "request_sha256": request_sha256,
                "request_bytes": request_bytes.len(),
                "request": path_state_json(&request_path, false),
                "response": path_state_json(&response_path, false),
                "response_tmp": path_state_json(&response_tmp, false),
                "database_family": database_family_state_json(database),
            }),
        );

        let deadline = Instant::now() + ARCHAEOLOGY_EXTRACT_TIMEOUT;
        // `(outcome, worker_survived)`: only a surviving worker advances `seq`/`served`.
        let (outcome, worker_survived): (HistoricalExtract, bool) = loop {
            if response_path.exists() {
                log_archaeology_serve_trace(
                    "parent_response_observed",
                    json!({
                        "seq": seq,
                        "commit": commit,
                        "worker_pid": self.child.as_ref().map(Child::id),
                        "request": path_state_json(&request_path, false),
                        "response": path_state_json(&response_path, true),
                        "response_tmp": path_state_json(&response_tmp, false),
                        "database_family": database_family_state_json(database),
                    }),
                );
                match fs::read(&response_path) {
                    Ok(bytes) => match interpret_pool_response(&bytes, project) {
                        PoolResponse::Rows(rows) => {
                            let reusable = self.wait_for_worker_after_response(
                                commit,
                                &request_path,
                                deadline,
                            );
                            break (HistoricalExtract::Rows(rows), reusable);
                        }
                        PoolResponse::RecoverableError(message) => {
                            let reusable = self.wait_for_worker_after_response(
                                commit,
                                &request_path,
                                deadline,
                            );
                            break (
                                HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                                    commit,
                                    None,
                                    &self.log_path,
                                    &format!(
                                        "the pooled worker reported a recoverable pipeline error \
                                         before producing rows: {message}"
                                    ),
                                )),
                                reusable,
                            );
                        }
                        PoolResponse::Malformed(detail) => {
                            log_archaeology_serve_trace(
                                "parent_malformed_response",
                                json!({
                                    "seq": seq,
                                    "commit": commit,
                                    "detail": detail,
                                    "request": path_state_json(&request_path, false),
                                    "response": path_state_json(&response_path, true),
                                    "response_tmp": path_state_json(&response_tmp, false),
                                    "database_family": database_family_state_json(database),
                                }),
                            );
                            self.recycle("malformed_response");
                            break (
                                HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                                    commit,
                                    None,
                                    &self.log_path,
                                    &format!(
                                        "the pooled worker wrote a malformed response and was \
                                         recycled: {detail}"
                                    ),
                                )),
                                false,
                            );
                        }
                    },
                    Err(error) => {
                        log_archaeology_serve_trace(
                            "parent_response_unreadable",
                            json!({
                                "seq": seq,
                                "commit": commit,
                                "error": error.to_string(),
                                "request": path_state_json(&request_path, false),
                                "response": path_state_json(&response_path, false),
                                "response_tmp": path_state_json(&response_tmp, false),
                                "database_family": database_family_state_json(database),
                            }),
                        );
                        self.recycle("response_unreadable");
                        break (
                            HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                                commit,
                                None,
                                &self.log_path,
                                &format!(
                                    "the pooled worker's response file was present but unreadable \
                                     and the worker was recycled: {error}"
                                ),
                            )),
                            false,
                        );
                    }
                }
            }
            match self
                .child
                .as_mut()
                .expect("worker ensured above")
                .try_wait()
            {
                Ok(Some(status)) => {
                    // The worker died mid-request: a CONTAINED #515 C-level fault on THIS
                    // commit. Forget the dead child so the next call respawns; the host lives.
                    let worker_pid = self.child.as_ref().map(Child::id);
                    self.child = None;
                    let exit_code = status.code();
                    let exit_text = worker_exit_text(status);
                    log_archaeology_serve_trace(
                        "parent_worker_died_mid_request",
                        json!({
                            "seq": seq,
                            "commit": commit,
                            "worker_pid": worker_pid,
                            "exit": exit_text,
                            "request": path_state_json(&request_path, true),
                            "response": path_state_json(&response_path, true),
                            "response_tmp": path_state_json(&response_tmp, true),
                            "database_family": database_family_state_json(database),
                        }),
                    );
                    break (
                        HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                            commit,
                            exit_code,
                            &self.log_path,
                            "the pooled CBM extraction worker died mid-request (C-level pipeline \
                             fault: abort / access violation / heap-corruption class); it will be \
                             respawned for the next commit",
                        )),
                        false,
                    );
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        self.recycle("hung");
                        break (
                            HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                                commit,
                                None,
                                &self.log_path,
                                &format!(
                                    "the pooled CBM extraction worker did not answer within {}s \
                                     and was killed as hung",
                                    ARCHAEOLOGY_EXTRACT_TIMEOUT.as_secs()
                                ),
                            )),
                            false,
                        );
                    }
                    thread::sleep(ARCHAEOLOGY_EXTRACT_POLL);
                }
                Err(error) => {
                    log_archaeology_serve_trace(
                        "parent_worker_wait_failed",
                        json!({
                            "seq": seq,
                            "commit": commit,
                            "error": error.to_string(),
                            "request": path_state_json(&request_path, false),
                            "response": path_state_json(&response_path, true),
                            "response_tmp": path_state_json(&response_tmp, true),
                            "database_family": database_family_state_json(database),
                        }),
                    );
                    self.recycle("wait_failed");
                    break (
                        HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                            commit,
                            None,
                            &self.log_path,
                            &format!(
                                "could not poll the pooled worker's liveness and it was recycled: \
                                 {error}"
                            ),
                        )),
                        false,
                    );
                }
            }
        };

        // Remove this request/response pair so the pool dir never grows unbounded across
        // a long loop (the worker also removes the request it consumed; double-remove is
        // harmless). On a contained crash, preserve the handshake files until
        // `preserve_historical_crash_artifacts` copies the pool state; deleting them here
        // would erase the only direct proof of whether a response/temp existed.
        if matches!(outcome, HistoricalExtract::Crashed(_)) {
            log_archaeology_serve_trace(
                "parent_preserving_failed_handshake",
                json!({
                    "seq": seq,
                    "commit": commit,
                    "pool_dir": self.pool_dir.display().to_string(),
                    "request": path_state_json(&request_path, true),
                    "response": path_state_json(&response_path, true),
                    "response_tmp": path_state_json(&response_tmp, true),
                    "database_family": database_family_state_json(database),
                }),
            );
        } else {
            let _ = fs::remove_file(&request_path);
            let _ = fs::remove_file(&response_path);
        }
        if worker_survived {
            self.seq += 1;
            self.served += 1;
        }
        Ok(outcome)
    }

    /// Retires the worker and removes the scratch pool dir; returns the number of scratch
    /// paths that survived cleanup (labeled remnant count, invariant 3). Idempotent — safe
    /// to call explicitly at end of loop and again from `Drop`.
    fn finish(&mut self) -> usize {
        self.recycle("pool_drop");
        let mut remnants = 0;
        if !remove_path_with_retry(&self.pool_dir, |path| fs::remove_dir_all(path)) {
            remnants += 1;
            eprintln!(
                "astro.archaeology.pool event=dir_remnant pool_dir={}",
                self.pool_dir.display(),
            );
        }
        remnants
    }
}

impl Drop for HistoricalExtractionPool {
    fn drop(&mut self) {
        // Guarantees the worker is killed and the scratch dir removed even if
        // `run_git_archaeology` returns early with an error before its explicit `finish()`.
        let _ = self.finish();
    }
}

fn worker_exit_text(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("{code} (0x{:08X})", code as u32),
        None => "none".to_string(),
    }
}

fn log_archaeology_serve_trace(event: &str, details: Value) {
    let payload = json!({
        "schema": "astrolabe.archaeology-serve-trace.v1",
        "event": event,
        "pid": std::process::id(),
        "unix_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0),
        "details": details,
    });
    match serde_json::to_string(&payload) {
        Ok(line) => eprintln!("ASTRO_ARCHAEOLOGY_SERVE_TRACE {line}"),
        Err(error) => {
            eprintln!("ASTRO_ARCHAEOLOGY_SERVE_TRACE_SERIALIZE_FAILED event={event} error={error}")
        }
    }
}

fn path_state_json(path: &Path, hash_file: bool) -> Value {
    let mut state = Map::new();
    state.insert(
        "path".to_string(),
        Value::String(path.display().to_string()),
    );
    match fs::metadata(path) {
        Ok(metadata) => {
            state.insert("exists".to_string(), Value::Bool(true));
            state.insert("is_file".to_string(), Value::Bool(metadata.is_file()));
            state.insert("is_dir".to_string(), Value::Bool(metadata.is_dir()));
            if metadata.is_file() {
                state.insert("bytes".to_string(), Value::from(metadata.len()));
                if hash_file {
                    match fs::read(path) {
                        Ok(bytes) => {
                            state.insert(
                                "sha256".to_string(),
                                Value::String(hex_lower(&Sha256::digest(bytes))),
                            );
                        }
                        Err(error) => {
                            state.insert(
                                "sha256_error".to_string(),
                                Value::String(error.to_string()),
                            );
                        }
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            state.insert("exists".to_string(), Value::Bool(false));
        }
        Err(error) => {
            state.insert("exists".to_string(), Value::Bool(false));
            state.insert(
                "metadata_error".to_string(),
                Value::String(error.to_string()),
            );
        }
    }
    Value::Object(state)
}

fn database_family_state_json(database: &Path) -> Value {
    let base = database.as_os_str().to_string_lossy();
    Value::Array(
        ["", "-wal", "-shm", "-journal"]
            .into_iter()
            .map(|suffix| {
                let path = PathBuf::from(format!("{base}{suffix}"));
                path_state_json(&path, suffix.is_empty())
            })
            .collect(),
    )
}

/// Best-effort PID-gated sweep of archaeology extraction pool dirs left at the shared
/// temp home by a prior pass that crashed before cleanup (#530). Only dirs whose embedded
/// owner PID is dead are removed, so a concurrently-running pass — its own live PID
/// stamped in the name — is never swept out from under itself. Mirrors
/// [`sweep_orphan_worktrees`]; every outcome is counted telemetry, never a silent skip.
fn sweep_orphan_pools(home: &Path) {
    let entries = match fs::read_dir(home) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!(
                "astro.archaeology.pool_sweep home={} status=unreadable error={error}",
                home.display()
            );
            return;
        }
    };
    let self_pid = std::process::id();
    let mut swept = 0usize;
    let mut skipped_live = 0usize;
    let mut remnants = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(nonce) = name.strip_prefix(ARCHAEOLOGY_POOL_PREFIX) else {
            continue;
        };
        let Some(pid) = nonce
            .split('-')
            .next()
            .and_then(|field| field.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == self_pid || process_is_alive(pid) {
            skipped_live += 1;
            continue;
        }
        if remove_path_with_retry(&entry.path(), |target| fs::remove_dir_all(target)) {
            swept += 1;
        } else {
            remnants += 1;
        }
    }
    eprintln!(
        "astro.archaeology.pool_sweep home={} swept={swept} skipped_live={skipped_live} \
         remnants={remnants}",
        home.display(),
    );
}

/// Builds the structured, single-line fault detail for a contained isolated-extraction
/// crash (#515): a fail-closed `{code, exit, reason, phase, remediation}` record plus a
/// bounded child-stderr tail so the offending C-level fault is auditable on the driving
/// issue without the host having died to surface it.
fn archaeology_extract_fault_detail(
    commit: &str,
    exit_code: Option<i32>,
    stderr_path: &Path,
    reason: &str,
) -> String {
    let exit = match exit_code {
        Some(code) => format!("{code} (0x{:08X})", code as u32),
        None => "none (killed_as_hung)".to_string(),
    };
    let stderr_tail = fs::read_to_string(stderr_path)
        .map(|text| {
            let chars: Vec<char> = text.chars().collect();
            let start = chars
                .len()
                .saturating_sub(ARCHAEOLOGY_EXTRACT_STDERR_TAIL_CHARS);
            chars[start..].iter().collect::<String>()
        })
        .unwrap_or_else(|_| "<child stderr unreadable>".to_string());
    format!(
        "ASTRO_ARCHAEOLOGY_HISTORICAL_INDEX_CRASHED commit={commit} exit={exit} \
         phase=git_archaeology.historical_reindex reason=\"{reason}\" \
         remediation=\"the fault was contained in the isolated extraction child so the host \
         can fail closed with structured evidence; no partial historical archaeology should \
         be published; inspect the child stderr tail to find the offending input\" \
         stderr_tail=<<{stderr_tail}>>"
    )
}

struct HistoricalExtractionRequest<'a> {
    scoped_root: &'a str,
    database: &'a str,
    identity_root: &'a str,
    project: &'a str,
    commit: &'a str,
    seq: u64,
    mode: CbmIndexMode,
    response_tmp: &'a Path,
    response_path: &'a Path,
}

/// Runs one historical checkout's CBM extraction in THIS process and returns the
/// pipeline rows (#530). Shared body of the pooled serve worker. A C-level pipeline fault
/// (abort / access violation / heap-corruption class) terminates the process here — that
/// is the #515 containment boundary the parent pool relies on (it detects the death and
/// counts the in-flight commit). A RECOVERABLE Rust error (e.g. the scratch db could not
/// be opened) is returned as `Err` so the serve worker can answer it as a structured
/// `{ok:false}` response WITHOUT dying. The pipeline (and CBM's SQLite handle) is dropped
/// before returning so the parent can remove the scratch db, mirroring the pre-#515
/// in-process ordering.
fn extract_rows_once(
    request: HistoricalExtractionRequest<'_>,
) -> Result<CbmPipelineRows, DynError> {
    let HistoricalExtractionRequest {
        scoped_root,
        database,
        identity_root,
        project,
        commit,
        seq,
        mode,
        response_tmp,
        response_path,
    } = request;
    log_archaeology_serve_trace(
        "worker_extract_begin",
        json!({
            "seq": seq,
            "commit": commit,
            "scoped_root": scoped_root,
            "database": database,
            "identity_root": identity_root,
            "project": project,
            "mode": match mode {
                CbmIndexMode::Full => "full",
                CbmIndexMode::Moderate => "moderate",
                CbmIndexMode::Fast => "fast",
            },
            "checkout": path_state_json(Path::new(scoped_root), false),
            "database_family": database_family_state_json(Path::new(database)),
            "response": path_state_json(response_path, false),
            "response_tmp": path_state_json(response_tmp, false),
        }),
    );
    let mut pipeline = CbmPipeline::new(scoped_root, database, mode)?;
    log_archaeology_serve_trace(
        "worker_pipeline_created",
        json!({
            "seq": seq,
            "commit": commit,
            "database_family": database_family_state_json(Path::new(database)),
        }),
    );
    pipeline.bind_project_identity_root(identity_root, project)?;
    log_archaeology_serve_trace(
        "worker_identity_bound",
        json!({
            "seq": seq,
            "commit": commit,
            "project": project,
        }),
    );
    let rows = pipeline.collect_rows_with_post_success_response(response_tmp, response_path)?;
    log_archaeology_serve_trace(
        "worker_collect_returned",
        json!({
            "seq": seq,
            "commit": commit,
            "nodes": rows.nodes.len(),
            "edges": rows.edges.len(),
            "file_hashes": rows.file_hashes.len(),
            "database_family": database_family_state_json(Path::new(database)),
            "response": path_state_json(response_path, true),
            "response_tmp": path_state_json(response_tmp, true),
        }),
    );
    drop(pipeline);
    log_archaeology_serve_trace(
        "worker_pipeline_dropped",
        json!({
            "seq": seq,
            "commit": commit,
            "database_family": database_family_state_json(Path::new(database)),
        }),
    );
    Ok(rows)
}

/// Builds one pooled serve-worker response (#530) for a decoded request `Value`. A clean
/// extraction yields the `{ok:true, project, nodes, edges}` rows envelope; a request
/// missing a required field, or a RECOVERABLE Rust-level pipeline error, yields a
/// structured `{ok:false, error}` envelope so the WARM worker can report it without
/// dying (the parent then counts that commit as a contained fault, identical accounting
/// to the pre-#530 nonzero-exit child).
fn build_serve_response(
    seq: u64,
    request: &Value,
    response_tmp: &Path,
    response_path: &Path,
) -> Result<Option<Value>, DynError> {
    if response_path.exists() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_COLLISION: response path {} already exists before \
             processing request; remediation: preserve the colliding response file and start a \
             fresh worker sequence from an absent response namespace",
            response_path.display()
        )
        .into());
    }
    if response_tmp.exists() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_TEMP_COLLISION: response temp path {} already \
             exists before processing request; remediation: preserve the stale temp file and \
             start a fresh worker sequence from an absent response namespace",
            response_tmp.display()
        )
        .into());
    }
    let field = |key: &str| request.get(key).and_then(Value::as_str);
    let (scoped_root, database, identity_root, project, commit, parent_seq) = match (
        field("scoped_root"),
        field("database"),
        field("identity_root"),
        field("project"),
        field("commit"),
        request.get("parent_seq").and_then(Value::as_u64),
    ) {
        (
            Some(scoped_root),
            Some(database),
            Some(identity_root),
            Some(project),
            Some(commit),
            Some(parent_seq),
        ) => (
            scoped_root,
            database,
            identity_root,
            project,
            commit,
            parent_seq,
        ),
        _ => {
            log_archaeology_serve_trace(
                "worker_request_missing_field",
                json!({
                    "seq": seq,
                    "request_keys": request
                        .as_object()
                        .map(|object| object.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default(),
                }),
            );
            return Ok(Some(json!({
                "ok": false,
                "error": "archaeology_extract_error: request missing required string field \
                          (scoped_root/database/identity_root/project/commit) or numeric \
                          parent_seq",
            })));
        }
    };
    if parent_seq != seq {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_SERVE_SEQUENCE_MISMATCH: worker seq {seq} does not match request \
             parent_seq {parent_seq}; remediation: preserve the pool directory and restart from \
             an absent request/response namespace"
        )
        .into());
    }
    let mode = match request.get("mode").and_then(Value::as_str) {
        Some("full") => CbmIndexMode::Full,
        Some("moderate") => CbmIndexMode::Moderate,
        // Historical re-index is always Fast; anything else (incl. absent) maps to it.
        _ => CbmIndexMode::Fast,
    };
    log_archaeology_serve_trace(
        "worker_request_decoded",
        json!({
            "seq": seq,
            "commit": commit,
            "scoped_root": scoped_root,
            "database": database,
            "identity_root": identity_root,
            "project": project,
            "mode": request.get("mode").and_then(Value::as_str).unwrap_or("fast"),
            "checkout": path_state_json(Path::new(scoped_root), false),
            "database_family": database_family_state_json(Path::new(database)),
            "response": path_state_json(response_path, false),
            "response_tmp": path_state_json(response_tmp, false),
        }),
    );
    match extract_rows_once(HistoricalExtractionRequest {
        scoped_root,
        database,
        identity_root,
        project,
        commit,
        seq,
        mode,
        response_tmp,
        response_path,
    }) {
        Ok(rows) => {
            log_archaeology_serve_trace(
                "worker_extract_success",
                json!({
                    "seq": seq,
                    "commit": commit,
                    "nodes": rows.nodes.len(),
                    "edges": rows.edges.len(),
                    "file_hashes": rows.file_hashes.len(),
                    "database_family": database_family_state_json(Path::new(database)),
                    "response": path_state_json(response_path, true),
                    "response_tmp": path_state_json(response_tmp, true),
                }),
            );
            Ok(None)
        }
        Err(error) if response_path.exists() => {
            eprintln!(
                "astro.archaeology.serve event=post_success_cleanup_error \
                 response_path={} error={error}",
                response_path.display(),
            );
            log_archaeology_serve_trace(
                "worker_post_success_cleanup_error",
                json!({
                    "seq": seq,
                    "commit": commit,
                    "error": error.to_string(),
                    "database_family": database_family_state_json(Path::new(database)),
                    "response": path_state_json(response_path, true),
                    "response_tmp": path_state_json(response_tmp, true),
                }),
            );
            Ok(None)
        }
        Err(error) => {
            log_archaeology_serve_trace(
                "worker_extract_error",
                json!({
                    "seq": seq,
                    "commit": commit,
                    "error": error.to_string(),
                    "database_family": database_family_state_json(Path::new(database)),
                    "response": path_state_json(response_path, false),
                    "response_tmp": path_state_json(response_tmp, true),
                }),
            );
            Ok(Some(json!({
                "ok": false,
                "error": format!("archaeology_extract_error: {error}"),
            })))
        }
    }
}

fn publish_pool_response(
    response_tmp: &Path,
    response_path: &Path,
    response: &Value,
) -> Result<(), DynError> {
    if response_path.exists() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_COLLISION: response path {} already exists before \
             publication; remediation: preserve the colliding file and start a fresh worker \
             sequence from an absent response namespace",
            response_path.display()
        )
        .into());
    }
    let bytes = serde_json::to_vec(response)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(response_tmp)
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_TEMP_OPEN_FAILED: could not create {}: \
                 {error}; remediation: ensure the pool directory is writable and contains no \
                 stale response temp",
                response_tmp.display()
            )
            .into()
        })?;
    file.write_all(&bytes).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_TEMP_WRITE_FAILED: could not write complete \
             response temp {}: {error}; remediation: inspect storage and retry with preserved \
             state",
            response_tmp.display()
        )
        .into()
    })?;
    file.sync_all().map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_TEMP_SYNC_FAILED: could not flush response temp {}: \
             {error}; remediation: inspect storage before trusting worker response publication",
            response_tmp.display()
        )
        .into()
    })?;
    drop(file);
    fs::rename(response_tmp, response_path).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_SERVE_RESPONSE_RENAME_FAILED: could not atomically publish {} -> \
             {}: {error}; remediation: preserve both paths and retry only after the response \
             namespace is absent",
            response_tmp.display(),
            response_path.display()
        )
        .into()
    })
}

/// Persistent serve-worker entry (#530) for `astrolabe cli --archaeology-extract-serve
/// --pool-dir <dir>`: processes historical extraction requests serially in THIS one
/// isolated process over an atomic request/response FILE handshake, so the #515 per-commit
/// spawn+init cost is paid once per recycle interval instead of once per commit. Not a
/// user-facing tool.
///
/// Protocol (parent = [`HistoricalExtractionPool`]): the parent writes
/// `request-<seq>.json` (atomic temp-then-rename) for seq = 0, 1, 2, …; this worker polls
/// for the next `request-<seq>.json`, extracts, and writes `response-<seq>.json` (atomic
/// temp-then-rename), then removes the consumed request. A `{"stop":true}` request exits
/// cleanly. A C-level pipeline fault dies with THIS process (the #515 boundary): the
/// parent detects the death via `try_wait`, counts the in-flight commit, and respawns.
/// The idle wait is bounded by [`ARCHAEOLOGY_EXTRACT_TIMEOUT`] so a parent that died
/// without the [`ParentWatchdog`](crate) noticing never spins forever — the worker exits
/// fail-closed instead.
pub(crate) fn run_archaeology_extract_serve(pool_dir: &str) -> Result<i32, DynError> {
    let pool_dir = PathBuf::from(pool_dir);
    let mut seq: u64 = 0;
    loop {
        let request_path = pool_dir.join(format!("request-{seq}.json"));
        // Wait for the next request, bounded so a dead parent never spins this worker hot
        // forever (invariant 3: a fail-closed exit, never a silent infinite loop).
        let idle_deadline = Instant::now() + ARCHAEOLOGY_EXTRACT_TIMEOUT;
        loop {
            if request_path.exists() {
                break;
            }
            if Instant::now() >= idle_deadline {
                // The parent is presumed gone (no request within the idle bound). Exit
                // cleanly rather than poll indefinitely.
                return Ok(0);
            }
            thread::sleep(ARCHAEOLOGY_EXTRACT_POLL);
        }
        let bytes = fs::read(&request_path).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_SERVE_REQUEST_UNREADABLE: could not read pooled request {}: \
                 {error}",
                request_path.display()
            )
            .into()
        })?;
        log_archaeology_serve_trace(
            "worker_request_observed",
            json!({
                "seq": seq,
                "request": path_state_json(&request_path, true),
                "request_sha256": hex_lower(&Sha256::digest(&bytes)),
                "request_bytes": bytes.len(),
            }),
        );
        let request: Value = serde_json::from_slice(&bytes).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_SERVE_REQUEST_INVALID: pooled request {} is not valid JSON: \
                 {error}",
                request_path.display()
            )
            .into()
        })?;
        if request.get("stop").and_then(Value::as_bool) == Some(true) {
            log_archaeology_serve_trace(
                "worker_stop_observed",
                json!({
                    "seq": seq,
                    "request": path_state_json(&request_path, true),
                }),
            );
            let _ = fs::remove_file(&request_path);
            return Ok(0);
        }
        let response_path = pool_dir.join(format!("response-{seq}.json"));
        let response_tmp = pool_dir.join(format!("response-{seq}.json.tmp"));
        match build_serve_response(seq, &request, &response_tmp, &response_path)? {
            Some(response) => {
                log_archaeology_serve_trace(
                    "worker_error_response_publish_begin",
                    json!({
                        "seq": seq,
                        "response": path_state_json(&response_path, false),
                        "response_tmp": path_state_json(&response_tmp, false),
                    }),
                );
                publish_pool_response(&response_tmp, &response_path, &response)?;
                log_archaeology_serve_trace(
                    "worker_error_response_published",
                    json!({
                        "seq": seq,
                        "response": path_state_json(&response_path, true),
                        "response_tmp": path_state_json(&response_tmp, false),
                    }),
                );
            }
            None => {
                if !response_path.exists() {
                    return Err(format!(
                        "ASTRO_ARCHAEOLOGY_SERVE_SUCCESS_RESPONSE_MISSING: CBM completed the \
                         pooled extraction but the post-success response {} is absent; \
                         remediation: preserve the pool directory and inspect row-sink \
                         publication diagnostics",
                        response_path.display()
                    )
                    .into());
                }
                log_archaeology_serve_trace(
                    "worker_success_response_present",
                    json!({
                        "seq": seq,
                        "response": path_state_json(&response_path, true),
                        "response_tmp": path_state_json(&response_tmp, true),
                    }),
                );
            }
        }
        // Drop the consumed request so the dir does not grow unbounded (the parent also
        // removes it; double-remove is harmless).
        let _ = fs::remove_file(&request_path);
        log_archaeology_serve_trace(
            "worker_request_removed",
            json!({
                "seq": seq,
                "request": path_state_json(&request_path, false),
                "response": path_state_json(&response_path, true),
            }),
        );
        seq += 1;
    }
}

/// Reconstructs [`CbmPipelineRows`] from the isolated-extraction child's response
/// bytes (#515). A missing/mistyped field fails closed with a labeled `Err(String)`
/// so a truncated or malformed response is reported as a contained fault, never
/// silently treated as "no rows".
fn parse_extract_response(bytes: &[u8], project: &str) -> Result<CbmPipelineRows, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("response JSON parse: {error}"))?;
    let response_project = value["project"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "response missing non-empty 'project' string".to_string())?;
    if response_project != project {
        return Err(format!(
            "response project {response_project:?} does not match requested project {project:?}"
        ));
    }
    let nodes = value["nodes"]
        .as_array()
        .ok_or_else(|| "response missing 'nodes' array".to_string())?
        .iter()
        .map(parse_extract_node)
        .collect::<Result<Vec<_>, String>>()?;
    let edges = value["edges"]
        .as_array()
        .ok_or_else(|| "response missing 'edges' array".to_string())?
        .iter()
        .map(parse_extract_edge)
        .collect::<Result<Vec<_>, String>>()?;
    let file_hashes = value["file_hashes"]
        .as_array()
        .ok_or_else(|| "response missing 'file_hashes' array".to_string())?
        .iter()
        .map(parse_extract_file_hash)
        .collect::<Result<Vec<_>, String>>()?;
    let manifest = value
        .get("manifest")
        .filter(|manifest| !manifest.is_null())
        .map(parse_extract_manifest)
        .transpose()?
        .ok_or_else(|| "response missing mandatory completion manifest".to_string())?;
    let rows = CbmPipelineRows {
        project: response_project.to_string(),
        nodes,
        edges,
        file_hashes,
        manifest: Some(manifest),
    };
    validate_extract_pipeline_rows(&rows, project)?;
    Ok(rows)
}

fn validate_extract_pipeline_rows(rows: &CbmPipelineRows, project: &str) -> Result<(), String> {
    let manifest = rows
        .manifest
        .as_ref()
        .ok_or_else(|| "response missing mandatory completion manifest".to_string())?;
    if manifest.project != project
        || manifest.node_count != rows.nodes.len()
        || manifest.edge_count != rows.edges.len()
        || manifest.file_hash_count != rows.file_hashes.len()
        || manifest.graph_schema_version != astrolabe_ingest::CBM_SQLITE_SCHEMA_VERSION as u32
    {
        return Err(format!(
            "response completion manifest does not match observed snapshot: \
             project={:?}/{project:?}, nodes={}/{}, edges={}/{}, file_hashes={}/{}, schema={}/{}",
            manifest.project,
            manifest.node_count,
            rows.nodes.len(),
            manifest.edge_count,
            rows.edges.len(),
            manifest.file_hash_count,
            rows.file_hashes.len(),
            manifest.graph_schema_version,
            astrolabe_ingest::CBM_SQLITE_SCHEMA_VERSION as u32,
        ));
    }
    if let Some(row_project) = rows
        .nodes
        .iter()
        .map(|row| row.project.as_str())
        .chain(rows.edges.iter().map(|row| row.project.as_str()))
        .chain(rows.file_hashes.iter().map(|row| row.project.as_str()))
        .find(|row_project| *row_project != project)
    {
        return Err(format!(
            "response contains row for project {row_project:?}, not {project:?}"
        ));
    }

    let mut file_paths = BTreeSet::new();
    for file_hash in &rows.file_hashes {
        if file_hash.rel_path.is_empty()
            || file_hash.rel_path.contains('\\')
            || file_hash.size < 0
            || file_hash.sha256.len() != 64
            || !file_hash
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "response file-hash row for {:?} is noncanonical",
                file_hash.rel_path
            ));
        }
        if !file_paths.insert(file_hash.rel_path.as_str()) {
            return Err(format!(
                "response repeats file-hash path {:?}",
                file_hash.rel_path
            ));
        }
    }
    Ok(())
}

fn parse_extract_node(value: &Value) -> Result<CbmPipelineNodeRow, String> {
    let str_field = |key: &str| -> Result<String, String> {
        value[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("node row missing string field '{key}'"))
    };
    let i64_field = |key: &str| -> Result<i64, String> {
        value[key]
            .as_i64()
            .ok_or_else(|| format!("node row missing integer field '{key}'"))
    };
    let u64_field = |key: &str| -> Result<u64, String> {
        value[key]
            .as_u64()
            .ok_or_else(|| format!("node row missing unsigned integer field '{key}'"))
    };
    let bool_field = |key: &str| -> Result<bool, String> {
        value[key]
            .as_bool()
            .ok_or_else(|| format!("node row missing boolean field '{key}'"))
    };
    let source_bytes = value["source_bytes"]
        .as_array()
        .ok_or_else(|| "node row missing byte-array field 'source_bytes'".to_string())?
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            let value = byte
                .as_u64()
                .ok_or_else(|| format!("node source_bytes[{index}] is not an unsigned integer"))?;
            u8::try_from(value)
                .map_err(|_| format!("node source_bytes[{index}] value {value} exceeds one byte"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CbmPipelineNodeRow {
        id: i64_field("id")?,
        project: str_field("project")?,
        label: str_field("label")?,
        name: str_field("name")?,
        atom_id: str_field("atom_id")?,
        qualified_name: str_field("qualified_name")?,
        file_path: str_field("file_path")?,
        start_line: i64_field("start_line")?,
        end_line: i64_field("end_line")?,
        source_present: bool_field("source_present")?,
        source_bytes,
        source_sha256: str_field("source_sha256")?,
        start_byte: u64_field("start_byte")?,
        end_byte: u64_field("end_byte")?,
        properties_json: str_field("properties_json")?,
    })
}

fn parse_extract_edge(value: &Value) -> Result<CbmPipelineEdgeRow, String> {
    let str_field = |key: &str| -> Result<String, String> {
        value[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("edge row missing string field '{key}'"))
    };
    let i64_field = |key: &str| -> Result<i64, String> {
        value[key]
            .as_i64()
            .ok_or_else(|| format!("edge row missing integer field '{key}'"))
    };
    Ok(CbmPipelineEdgeRow {
        id: i64_field("id")?,
        project: str_field("project")?,
        source_id: i64_field("source_id")?,
        target_id: i64_field("target_id")?,
        edge_type: str_field("edge_type")?,
        properties_json: str_field("properties_json")?,
        url_path_gen: str_field("url_path_gen")?,
        local_name_gen: str_field("local_name_gen")?,
        preprocess_context_id_gen: str_field("preprocess_context_id_gen")?,
    })
}

fn parse_extract_file_hash(value: &Value) -> Result<CbmPipelineFileHashRow, String> {
    let str_field = |key: &str| -> Result<String, String> {
        value[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("file-hash row missing string field '{key}'"))
    };
    let i64_field = |key: &str| -> Result<i64, String> {
        value[key]
            .as_i64()
            .ok_or_else(|| format!("file-hash row missing integer field '{key}'"))
    };
    Ok(CbmPipelineFileHashRow {
        project: str_field("project")?,
        rel_path: str_field("rel_path")?,
        sha256: str_field("sha256")?,
        mtime_ns: i64_field("mtime_ns")?,
        size: i64_field("size")?,
    })
}

fn parse_extract_manifest(value: &Value) -> Result<CbmPipelineRowManifest, String> {
    let usize_field = |key: &str| -> Result<usize, String> {
        let raw = value[key]
            .as_u64()
            .ok_or_else(|| format!("manifest missing unsigned integer field '{key}'"))?;
        usize::try_from(raw).map_err(|_| format!("manifest field '{key}' exceeds usize"))
    };
    let graph_schema_version = value["graph_schema_version"]
        .as_u64()
        .ok_or_else(|| "manifest missing unsigned integer field 'graph_schema_version'".to_string())
        .and_then(|raw| {
            u32::try_from(raw).map_err(|_| "manifest graph_schema_version exceeds u32".to_string())
        })?;
    Ok(CbmPipelineRowManifest {
        project: value["project"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "manifest missing string field 'project'".to_string())?,
        node_count: usize_field("node_count")?,
        edge_count: usize_field("edge_count")?,
        file_hash_count: usize_field("file_hash_count")?,
        graph_schema_version,
    })
}

fn group_evidence_by_commit(evidence: &[Evidence]) -> Vec<(&str, &[Evidence])> {
    let mut groups = Vec::new();
    let mut start = 0;
    while start < evidence.len() {
        let mut end = start + 1;
        while end < evidence.len() && evidence[end].commit == evidence[start].commit {
            end += 1;
        }
        groups.push((evidence[start].commit.as_str(), &evidence[start..end]));
        start = end;
    }
    groups
}

/// Number of removal attempts (initial + retries) for each archaeology scratch
/// path before it is declared a remnant.
const ARCHAEOLOGY_CLEANUP_ATTEMPTS: u32 = 6;
/// Base backoff between cleanup retries; doubled each attempt (10, 20, 40, 80,
/// 160 ms), bounded so a genuinely stuck handle never blocks the import.
const ARCHAEOLOGY_CLEANUP_BACKOFF_BASE: Duration = Duration::from_millis(10);

/// Outcome of indexing one historical commit: the pipeline rows, the count of
/// scratch paths that could not be removed after the bounded retry budget, and the
/// count of implicated files excluded as Windows-invalid (#502) at this commit.
struct HistoricalCommitIndex {
    rows: CbmPipelineRows,
    cleanup_remnants: usize,
    windows_invalid_excluded: usize,
    git_inventory_processes: usize,
    git_checkout_processes: usize,
    git_cat_file_processes: usize,
    git_cat_file_stdout_bytes: u64,
    files_materialized: usize,
    paths_absent: usize,
    source_files_materialized: usize,
    object_probe_processes_avoided: usize,
    dependency_files_materialized: usize,
    dependency_candidate_paths_absent: usize,
    dependency_edges: usize,
    dependency_revisits: usize,
    dependency_depth: usize,
    /// #515: `Some(detail)` when the isolated CBM extraction child died without
    /// producing rows (a contained C-level pipeline fault on this commit). The host
    /// survives so the caller can fail the index-wide request with exact evidence
    /// instead of publishing a partial kernel that invents empty historical rows.
    /// `None` on a clean extraction (`rows` carries the real result).
    crashed: Option<String>,
}

#[derive(Debug)]
struct HistoricalMaterialization {
    windows_invalid_excluded: usize,
    git_inventory_processes: usize,
    git_checkout_processes: usize,
    git_cat_file_processes: usize,
    git_cat_file_stdout_bytes: u64,
    files_materialized: usize,
    paths_absent: usize,
    object_probe_processes_avoided: usize,
    dependency_files_materialized: usize,
    dependency_candidate_paths_absent: usize,
    dependency_edges: usize,
    dependency_revisits: usize,
    dependency_depth: usize,
}

/// Outcome of the pooled historical CBM extraction ([`HistoricalExtractionPool::extract`]):
/// either the extracted pipeline rows, or a contained worker fault carrying the
/// structured detail (exit code + worker-log tail) for the fail-closed index error.
enum HistoricalExtract {
    Rows(CbmPipelineRows),
    Crashed(String),
}

#[allow(clippy::too_many_arguments)]
fn index_historical_commit(
    repo: &Path,
    cache_dir: &Path,
    worktree_home: &Path,
    project: &str,
    commit: &str,
    corpus_rel: &str,
    file_scoped: bool,
    implicated_files: &BTreeSet<String>,
    pool: &mut HistoricalExtractionPool,
) -> Result<HistoricalCommitIndex, DynError> {
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    // Commit-bound materialization scope at the compact explicit home (#427/#809);
    // the temporary index and checked-out tree are private children, so no shared Git
    // worktree registration or per-path object process is needed.
    let worktree = worktree_home.join(format!("{ARCHAEOLOGY_WORKTREE_PREFIX}{nonce}"));
    let checkout_root = worktree.join("tree");
    let worktree_len = windows_path_units(&checkout_root);
    if worktree_len > ARCHAEOLOGY_WORKTREE_CWD_BUDGET {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_WORKTREE_BASE_TOO_DEEP: archaeology scratch-worktree root {root} is \
             {worktree_len} UTF-16 units, over the \
             {ARCHAEOLOGY_WORKTREE_CWD_BUDGET}-unit budget that \
             keeps git's chdir into the worktree under the Windows MAX_PATH (260) cap (no \\\\?\\ \
             form or git config lifts the chdir limit); remediation: configure a shorter \
             {ARCHAEOLOGY_ROOT_ENV} and re-run index_repository",
            root = worktree.display(),
        )
        .into());
    }
    let database = cache_dir.join(format!("{ARCHAEOLOGY_DB_PREFIX}{nonce}.db"));
    let identity_root = if corpus_rel.is_empty() {
        repo.to_path_buf()
    } else {
        repo.join(corpus_rel)
    };
    let materialized = match materialize_historical_tree(
        repo,
        &worktree,
        &checkout_root,
        commit,
        corpus_rel,
        file_scoped,
        implicated_files,
    ) {
        Ok(materialized) => materialized,
        Err(error) => {
            let removed = remove_path_with_retry(&worktree, |path| fs::remove_dir_all(path));
            if !removed {
                return Err(format!(
                    "{error}; ASTRO_ARCHAEOLOGY_MATERIALIZATION_CLEANUP_FAILED: exact scratch scope {} survived the bounded cleanup budget; preserve and inspect it before retrying",
                    worktree.display()
                )
                .into());
            }
            return Err(error);
        }
    };
    let mut source_files_materialized = 0usize;
    let indexed = (|| -> Result<HistoricalExtract, DynError> {
        // Scope the historical index to the requested corpus subtree within the
        // whole-repo worktree (#403). A git worktree is always the full repository
        // tree, so indexing `worktree` itself walked the entire enclosing
        // workspace — the spurious wrong-corpus pass. `worktree.join(corpus_rel)`
        // restricts CBM discovery to exactly the requested corpus; an empty
        // `corpus_rel` (corpus IS the toplevel) leaves this behavior-neutral.
        let scoped_root = if corpus_rel.is_empty() {
            checkout_root.clone()
        } else {
            checkout_root.join(corpus_rel)
        };
        // The corpus subtree may not exist at this historical commit (created or
        // renamed later). CBM cannot index a path that is not there; treat it as
        // "no historical rows for this commit" (the evidence then lands as
        // evidence_without_symbol) rather than letting CBM abort on a missing root.
        if !scoped_root.exists() {
            return Ok(HistoricalExtract::Rows(CbmPipelineRows {
                project: project.to_string(),
                nodes: Vec::new(),
                edges: Vec::new(),
                file_hashes: Vec::new(),
                manifest: None,
            }));
        }
        // Ask libcbm's own discovery path whether this exact materialized view has a
        // non-auxiliary Fast-mode source. This is deliberately not predicted from
        // filename extensions: discovery also applies mode filters, ignore policy,
        // directory policy, and auxiliary classification, and those rules must have
        // one owner. The selected view is tiny, so this in-process walk avoids an
        // unnecessary worker request without adding a process or parsing source twice.
        let discovery = discover_pipeline_files(path_str(&scoped_root)?, CbmIndexMode::Fast)?;
        source_files_materialized = discovery.source_files;
        if source_files_materialized == 0 {
            eprintln!(
                "astro.archaeology.no_materialized_source commit={commit} files_materialized={} discovered_files={} outcome=explicit_empty_rows",
                materialized.files_materialized, discovery.discovered_files
            );
            return Ok(HistoricalExtract::Rows(CbmPipelineRows {
                project: project.to_string(),
                nodes: Vec::new(),
                edges: Vec::new(),
                file_hashes: Vec::new(),
                manifest: None,
            }));
        }
        // #515 crash isolation + #530 pooling: run the CBM extraction in the POOLED
        // out-of-process worker, not in-process. Unlike the main shadow import — already
        // crash-isolated in a supervised out-of-process worker (#405) — this per-commit
        // historical re-index used to call `CbmPipeline::collect_rows()` on THIS host
        // thread. A C-level pipeline fault (abort / access violation / heap-corruption
        // class) on one of a large repo's historical checkouts therefore terminated the
        // ENTIRE host `index_repository` process: an empty-stdout `rc=127` silent
        // hard-exit with no structured {code,message,remediation} (issue #515, reproduced
        // on rtk-ai/rtk deep in this loop after the CBM graph was already complete). #515
        // first contained that by spawning a fresh child PER commit; #530 replaces the
        // per-commit spawn with ONE pooled worker that serves every commit serially and
        // is recycled on crash or every N commits — the spawn+init cost is amortized while
        // the containment is preserved. The pooled worker runs the exact same
        // `CbmPipeline` (same `scoped_root`, same scratch `database`, same Fast mode) so
        // the emitted subtree-relative node paths — and thus the CxIds framed from
        // `rel_file_path` via `canonical_input_bytes` — are byte-identical to the old
        // in-process path (#418/#439 identity contract). A fault is CONTAINED as
        // `HistoricalExtract::Crashed` so the host survives long enough to return a
        // structured fail-closed index error instead of dying silently or publishing a
        // partial kernel.
        pool.extract(&scoped_root, &database, &identity_root, project, commit)
    })();
    match indexed {
        Ok(HistoricalExtract::Rows(rows)) => {
            let mut cleanup_remnants = cleanup_archaeology_database(&database);
            if !remove_path_with_retry(&worktree, |path| fs::remove_dir_all(path)) {
                cleanup_remnants += 1;
            }
            Ok(HistoricalCommitIndex {
                rows,
                cleanup_remnants,
                windows_invalid_excluded: materialized.windows_invalid_excluded,
                git_inventory_processes: materialized.git_inventory_processes,
                git_checkout_processes: materialized.git_checkout_processes,
                git_cat_file_processes: materialized.git_cat_file_processes,
                git_cat_file_stdout_bytes: materialized.git_cat_file_stdout_bytes,
                files_materialized: materialized.files_materialized,
                paths_absent: materialized.paths_absent,
                source_files_materialized,
                object_probe_processes_avoided: materialized.object_probe_processes_avoided,
                dependency_files_materialized: materialized.dependency_files_materialized,
                dependency_candidate_paths_absent: materialized.dependency_candidate_paths_absent,
                dependency_edges: materialized.dependency_edges,
                dependency_revisits: materialized.dependency_revisits,
                dependency_depth: materialized.dependency_depth,
                crashed: None,
            })
        }
        // #515 contained child fault: the extraction child died without rows. Return
        // exact crash detail and preserve the exact materialized input so the caller
        // can fail closed with enough physical state to reproduce the C fault. This
        // intentionally does NOT clean the checkout/database on the crash path; normal
        // success cleanup remains unchanged.
        Ok(HistoricalExtract::Crashed(detail)) => {
            let preservation = preserve_historical_crash_artifacts(HistoricalCrashPreservation {
                worktree: &worktree,
                database: &database,
                worker_log: &pool.log_path,
                pool_dir: &pool.pool_dir,
                project,
                commit,
                checkout_root: &checkout_root,
                materialized: &materialized,
                source_files_materialized,
            });
            let detail = format!("{detail} preserved_input=<<{preservation}>>");
            Ok(HistoricalCommitIndex {
                rows: CbmPipelineRows {
                    project: project.to_string(),
                    nodes: Vec::new(),
                    edges: Vec::new(),
                    file_hashes: Vec::new(),
                    manifest: None,
                },
                cleanup_remnants: 0,
                windows_invalid_excluded: materialized.windows_invalid_excluded,
                git_inventory_processes: materialized.git_inventory_processes,
                git_checkout_processes: materialized.git_checkout_processes,
                git_cat_file_processes: materialized.git_cat_file_processes,
                git_cat_file_stdout_bytes: materialized.git_cat_file_stdout_bytes,
                files_materialized: materialized.files_materialized,
                paths_absent: materialized.paths_absent,
                source_files_materialized,
                object_probe_processes_avoided: materialized.object_probe_processes_avoided,
                dependency_files_materialized: materialized.dependency_files_materialized,
                dependency_candidate_paths_absent: materialized.dependency_candidate_paths_absent,
                dependency_edges: materialized.dependency_edges,
                dependency_revisits: materialized.dependency_revisits,
                dependency_depth: materialized.dependency_depth,
                crashed: Some(detail),
            })
        }
        Err(error) => Err(error),
    }
}

struct HistoricalCrashPreservation<'a> {
    worktree: &'a Path,
    database: &'a Path,
    worker_log: &'a Path,
    pool_dir: &'a Path,
    project: &'a str,
    commit: &'a str,
    checkout_root: &'a Path,
    materialized: &'a HistoricalMaterialization,
    source_files_materialized: usize,
}

fn preserve_historical_crash_artifacts(context: HistoricalCrashPreservation<'_>) -> String {
    let HistoricalCrashPreservation {
        worktree,
        database,
        worker_log,
        pool_dir,
        project,
        commit,
        checkout_root,
        materialized,
        source_files_materialized,
    } = context;
    let result = (|| -> Result<Value, DynError> {
        let parent = worktree.parent().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_PARENT_MISSING: worktree {} has no parent",
                worktree.display()
            )
            .into()
        })?;
        let worktree_name = worktree
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_WORKTREE_NAME_INVALID: worktree {} has no UTF-8 final component",
                    worktree.display()
                )
                .into()
            })?;
        let preserved = parent.join(format!("crash-{}-{worktree_name}", &commit[..12]));
        fs::rename(worktree, &preserved).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_RENAME_FAILED: could not rename {} to {}: {error}; original checkout is intentionally left in place",
                worktree.display(),
                preserved.display()
            )
            .into()
        })?;
        let preserved_checkout = preserved.join(
            checkout_root
                .file_name()
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_CHECKOUT_NAME_INVALID: checkout root has no final component"
                        .into()
                })?,
        );
        let tree_inventory = inventory_directory_for_preservation(&preserved_checkout)?;

        let database_dir = preserved.join("database");
        fs::create_dir(&database_dir).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_DB_DIR_FAILED: could not create {}: {error}; preserved checkout remains at {}",
                database_dir.display(),
                preserved.display()
            )
            .into()
        })?;
        let mut database_paths = Vec::new();
        for path in archaeology_database_family_paths(database) {
            if !path.exists() {
                continue;
            }
            let file_name = path.file_name().ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_DB_NAME_INVALID: database sidecar {} has no file name",
                    path.display()
                )
                .into()
            })?;
            let destination = database_dir.join(file_name);
            fs::rename(&path, &destination).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_DB_RENAME_FAILED: could not rename {} to {}: {error}; preserved checkout remains at {}",
                    path.display(),
                    destination.display(),
                    preserved.display()
                )
                .into()
            })?;
            database_paths.push(destination.display().to_string());
        }
        let database_inventory = inventory_directory_for_preservation(&database_dir)?;

        let preserved_pool_dir = preserved.join("pool");
        fs::create_dir(&preserved_pool_dir).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_POOL_DIR_FAILED: could not create {}: {error}; preserved checkout remains at {}",
                preserved_pool_dir.display(),
                preserved.display()
            )
            .into()
        })?;
        let mut pool_paths = Vec::new();
        if pool_dir.exists() {
            for entry in fs::read_dir(pool_dir).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_POOL_READ_FAILED: could not read pool dir {}: {error}; preserved checkout remains at {}",
                    pool_dir.display(),
                    preserved.display()
                )
                .into()
            })? {
                let entry = entry.map_err(|error| -> DynError {
                    format!(
                        "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_POOL_ENTRY_FAILED: could not read a pool dir entry in {}: {error}; preserved checkout remains at {}",
                        pool_dir.display(),
                        preserved.display()
                    )
                    .into()
                })?;
                let metadata = entry.metadata().map_err(|error| -> DynError {
                    format!(
                        "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_POOL_METADATA_FAILED: could not stat {}: {error}; preserved checkout remains at {}",
                        entry.path().display(),
                        preserved.display()
                    )
                    .into()
                })?;
                if !metadata.is_file() {
                    continue;
                }
                let file_name = entry.file_name();
                let destination = preserved_pool_dir.join(&file_name);
                fs::copy(entry.path(), &destination).map_err(|error| -> DynError {
                    format!(
                        "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_POOL_COPY_FAILED: could not copy {} to {}: {error}; preserved checkout remains at {}",
                        entry.path().display(),
                        destination.display(),
                        preserved.display()
                    )
                    .into()
                })?;
                pool_paths.push(destination.display().to_string());
            }
        }
        let pool_inventory = inventory_directory_for_preservation(&preserved_pool_dir)?;

        let worker_log_path = preserved.join("worker.log");
        let worker_log_sha256 = if worker_log.exists() {
            fs::copy(worker_log, &worker_log_path).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_LOG_COPY_FAILED: could not copy {} to {}: {error}; preserved checkout remains at {}",
                    worker_log.display(),
                    worker_log_path.display(),
                    preserved.display()
                )
                .into()
            })?;
            Some(hex_lower(&Sha256::digest(fs::read(&worker_log_path)?)))
        } else {
            None
        };

        let manifest_path = preserved.join("crash-preservation.json");
        let manifest_tmp = preserved.join("crash-preservation.json.tmp");
        let manifest = json!({
            "schema": "astrolabe.archaeology-crash-preservation.v1",
            "status": "preserved",
            "project": project,
            "commit": commit,
            "preserved_root": preserved.display().to_string(),
            "checkout_root": preserved_checkout.display().to_string(),
            "database_dir": database_dir.display().to_string(),
            "database_paths": database_paths,
            "pool_dir": preserved_pool_dir.display().to_string(),
            "pool_paths": pool_paths,
            "worker_log": worker_log.exists().then(|| worker_log_path.display().to_string()),
            "worker_log_sha256": worker_log_sha256,
            "files_materialized": materialized.files_materialized,
            "source_files_materialized": source_files_materialized,
            "windows_invalid_excluded": materialized.windows_invalid_excluded,
            "git_inventory_processes": materialized.git_inventory_processes,
            "git_checkout_processes": materialized.git_checkout_processes,
            "git_cat_file_processes": materialized.git_cat_file_processes,
            "git_cat_file_stdout_bytes": materialized.git_cat_file_stdout_bytes,
            "object_probe_processes_avoided": materialized.object_probe_processes_avoided,
            "paths_absent": materialized.paths_absent,
            "checkout_inventory": tree_inventory.to_json(),
            "database_inventory": database_inventory.to_json(),
            "pool_inventory": pool_inventory.to_json(),
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        fs::write(&manifest_tmp, &manifest_bytes)?;
        fs::rename(&manifest_tmp, &manifest_path)?;
        let readback_bytes = fs::read(&manifest_path)?;
        let readback: Value = serde_json::from_slice(&readback_bytes)?;
        if readback != manifest {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_MANIFEST_DRIFT: readback of {} did not match the written manifest; preserved checkout remains at {}",
                manifest_path.display(),
                preserved.display()
            )
            .into());
        }
        Ok(json!({
            "schema": "astrolabe.archaeology-crash-preservation-result.v1",
            "status": "preserved",
            "root": preserved.display().to_string(),
            "manifest": manifest_path.display().to_string(),
            "manifest_sha256": hex_lower(&Sha256::digest(readback_bytes)),
            "checkout_files": tree_inventory.files,
            "checkout_bytes": tree_inventory.bytes,
            "checkout_inventory_sha256": tree_inventory.inventory_sha256,
            "database_files": database_inventory.files,
            "database_bytes": database_inventory.bytes,
            "database_inventory_sha256": database_inventory.inventory_sha256,
            "pool_files": pool_inventory.files,
            "pool_bytes": pool_inventory.bytes,
            "pool_inventory_sha256": pool_inventory.inventory_sha256,
            "worker_log_sha256": worker_log_sha256,
        }))
    })();
    let payload = match result {
        Ok(value) => value,
        Err(error) => json!({
            "schema": "astrolabe.archaeology-crash-preservation-result.v1",
            "status": "preservation_failed",
            "error": error.to_string(),
            "original_worktree": worktree.display().to_string(),
            "original_database": database.display().to_string(),
            "worker_log": worker_log.display().to_string(),
            "pool_dir": pool_dir.display().to_string(),
        }),
    };
    serde_json::to_string(&payload).unwrap_or_else(|error| {
        format!(
            "{{\"schema\":\"astrolabe.archaeology-crash-preservation-result.v1\",\"status\":\"serialization_failed\",\"error\":{error:?}}}"
        )
    })
}

#[derive(Debug, Clone)]
struct PreservationInventory {
    files: usize,
    bytes: u64,
    inventory_sha256: String,
}

impl PreservationInventory {
    fn to_json(&self) -> Value {
        json!({
            "files": self.files,
            "bytes": self.bytes,
            "inventory_sha256": self.inventory_sha256,
        })
    }
}

fn inventory_directory_for_preservation(root: &Path) -> Result<PreservationInventory, DynError> {
    let mut records = Vec::new();
    let mut bytes = 0u64;
    inventory_directory_inner(root, root, &mut records, &mut bytes)?;
    records.sort();
    let mut hasher = Sha256::new();
    for record in &records {
        hasher.update(record.as_bytes());
        hasher.update([0]);
    }
    Ok(PreservationInventory {
        files: records.len(),
        bytes,
        inventory_sha256: hex_lower(&hasher.finalize()),
    })
}

fn inventory_directory_inner(
    root: &Path,
    current: &Path,
    records: &mut Vec<String>,
    bytes: &mut u64,
) -> Result<(), DynError> {
    let entries = fs::read_dir(current).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_INVENTORY_UNREADABLE: could not read {}: {error}",
            current.display()
        )
        .into()
    })?;
    let mut entries = entries.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            inventory_directory_inner(root, &path, records, bytes)?;
            continue;
        }
        let rel = path.strip_prefix(root).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_INVENTORY_RELATIVE_FAILED: {} is not below {}: {error}",
                path.display(),
                root.display()
            )
            .into()
        })?;
        let rel = rel.to_string_lossy().replace('\\', "/");
        if metadata.is_file() {
            let data = fs::read(&path)?;
            let len = u64::try_from(data.len()).map_err(|_| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_FILE_TOO_LARGE: {} length cannot be represented as u64",
                    path.display()
                )
                .into()
            })?;
            *bytes = bytes.checked_add(len).ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CRASH_PRESERVE_INVENTORY_BYTES_OVERFLOW: preserved byte count overflowed u64"
                    .into()
            })?;
            records.push(format!(
                "file\t{rel}\t{len}\t{}",
                hex_lower(&Sha256::digest(data))
            ));
        } else {
            records.push(format!(
                "special\t{rel}\t{}",
                metadata.file_type().is_symlink()
            ));
        }
    }
    Ok(())
}

fn archaeology_database_family_paths(database: &Path) -> Vec<PathBuf> {
    let mut paths = vec![database.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = database.as_os_str().to_os_string();
        sidecar.push(suffix);
        paths.push(PathBuf::from(sidecar));
    }
    paths
}

/// Removes the SQLite database and its `-wal`/`-shm`/`-journal` sidecars with a
/// bounded retry, returning the number that survived (labeled remnant count).
fn cleanup_archaeology_database(path: &Path) -> usize {
    let mut remnants = 0;
    if !remove_path_with_retry(path, |target| fs::remove_file(target)) {
        remnants += 1;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if !remove_path_with_retry(&sidecar, |target| fs::remove_file(target)) {
            remnants += 1;
        }
    }
    remnants
}

/// Removes `path` with the archaeology retry budget. Returns `true` when the
/// path is gone (removed, or already absent), `false` when it survived every
/// attempt — in which case the caller records it as a labeled remnant rather
/// than swallowing the error. Windows releases file handles asynchronously after
/// a close, so a scratch file/dir can linger briefly after the owning handle is
/// dropped; the exponential backoff absorbs that latency.
fn remove_path_with_retry(path: &Path, remove: impl Fn(&Path) -> std::io::Result<()>) -> bool {
    for attempt in 0..ARCHAEOLOGY_CLEANUP_ATTEMPTS {
        match remove(path) {
            Ok(()) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) if attempt + 1 < ARCHAEOLOGY_CLEANUP_ATTEMPTS => {
                thread::sleep(ARCHAEOLOGY_CLEANUP_BACKOFF_BASE * (1u32 << attempt));
            }
            Err(_) => {}
        }
    }
    !path.exists()
}

struct ArchaeologyScratchScope {
    worktree_home: PathBuf,
    pool_home: PathBuf,
}

/// Resolve the one explicit archaeology root and bind one compact physical scope
/// to the exact `(git toplevel, path-derived project)` identity. The scope
/// manifest is durable state: a hash collision, torn write, or manually reused
/// directory refuses without sweeping any existing child.
fn archaeology_scratch_scope(
    git_root: &str,
    project: &str,
) -> Result<ArchaeologyScratchScope, DynError> {
    let raw = std::env::var_os(ARCHAEOLOGY_ROOT_ENV).ok_or_else(|| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_ROOT_MISSING: {ARCHAEOLOGY_ROOT_ENV} is not set; remediation: \
             configure one short absolute local archaeology scratch root and re-run \
             index_repository"
        )
        .into()
    })?;
    if raw.is_empty() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_ROOT_EMPTY: {ARCHAEOLOGY_ROOT_ENV} is empty; remediation: \
             configure one short absolute local archaeology scratch root and re-run \
             index_repository"
        )
        .into());
    }
    let root = PathBuf::from(raw);
    if !root.is_absolute()
        || root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_ROOT_INVALID: {ARCHAEOLOGY_ROOT_ENV}={} is not a normalized \
             absolute path; remediation: configure one absolute path without . or .. components",
            root.display()
        )
        .into());
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        match root.components().next() {
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => {}
            _ => {
                return Err(format!(
                    "ASTRO_ARCHAEOLOGY_ROOT_NOT_LOCAL: {ARCHAEOLOGY_ROOT_ENV}={} is not a local \
                     drive path accepted by Git's Windows current-directory handling; \
                     remediation: configure a short drive-qualified path such as C:\\astro-arch",
                    root.display()
                )
                .into());
            }
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(git_root.as_bytes());
    hasher.update([0]);
    hasher.update(project.as_bytes());
    let digest = hex_lower(&hasher.finalize());
    let scope_key = format!("s-{}", &digest[..16]);
    let scope_dir = root.join(&scope_key);
    let worktree_home = scope_dir.join("w");
    let pool_home = scope_dir.join("p");
    let longest_owner = "4294967295-18446744073709551615";
    let worktree_preview =
        worktree_home.join(format!("{ARCHAEOLOGY_WORKTREE_PREFIX}{longest_owner}"));
    let pool_preview = pool_home
        .join(format!("{ARCHAEOLOGY_POOL_PREFIX}{longest_owner}"))
        .join("response-18446744073709551615.json");
    for (kind, preview) in [
        ("worktree", &worktree_preview),
        ("pool-handshake", &pool_preview),
    ] {
        let units = windows_path_units(preview);
        if units > ARCHAEOLOGY_WORKTREE_CWD_BUDGET {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_ROOT_TOO_DEEP: configured {ARCHAEOLOGY_ROOT_ENV}={} makes the \
                 longest {kind} path {} UTF-16 units, over the \
                 {ARCHAEOLOGY_WORKTREE_CWD_BUDGET}-unit Windows budget; remediation: configure \
                 one shorter absolute local root",
                root.display(),
                units
            )
            .into());
        }
    }

    fs::create_dir_all(&scope_dir).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_ROOT_UNUSABLE: could not create bound scratch scope {}: {error}; \
             remediation: make {ARCHAEOLOGY_ROOT_ENV} writable or configure another explicit root",
            scope_dir.display()
        )
        .into()
    })?;
    let manifest_path = scope_dir.join("scope.json");
    let binding = json!({
        "git_root": git_root,
        "project": project,
        "schema": ARCHAEOLOGY_SCOPE_SCHEMA,
        "scope_key": scope_key,
    });
    let binding_bytes = serde_json::to_vec_pretty(&binding)?;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
    {
        Ok(mut manifest) => {
            manifest.write_all(&binding_bytes)?;
            manifest.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_SCOPE_MANIFEST_UNUSABLE: could not publish {}: {error}; \
                 remediation: preserve the scope and repair its filesystem before retrying",
                manifest_path.display()
            )
            .into());
        }
    }
    let readback_bytes = fs::read(&manifest_path).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_SCOPE_MANIFEST_UNREADABLE: could not read back {}: {error}; \
             remediation: preserve the scope and repair its manifest before retrying",
            manifest_path.display()
        )
        .into()
    })?;
    let readback: Value = serde_json::from_slice(&readback_bytes).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_SCOPE_MANIFEST_MALFORMED: {} is not valid JSON: {error}; \
             remediation: preserve the scope and inspect the torn or foreign manifest",
            manifest_path.display()
        )
        .into()
    })?;
    if readback != binding {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_SCOPE_IDENTITY_MISMATCH: {} does not bind the requested git root \
             and project; remediation: preserve the existing scope and configure a distinct root",
            manifest_path.display()
        )
        .into());
    }
    fs::create_dir_all(&worktree_home).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_WORKTREE_HOME_UNUSABLE: could not create {}: {error}; \
             remediation: preserve the scope and repair its local filesystem before retrying",
            worktree_home.display()
        )
        .into()
    })?;
    fs::create_dir_all(&pool_home).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_POOL_HOME_UNUSABLE: could not create {}: {error}; remediation: \
             preserve the scope and repair its local filesystem before retrying",
            pool_home.display()
        )
        .into()
    })?;
    let manifest_sha256 = hex_lower(&Sha256::digest(&readback_bytes));
    eprintln!(
        "astro.archaeology.scratch_scope root={} scope={} project={} git_root={} manifest={} \
         manifest_sha256={}",
        root.display(),
        scope_dir.display(),
        project,
        git_root,
        manifest_path.display(),
        manifest_sha256,
    );
    Ok(ArchaeologyScratchScope {
        worktree_home,
        pool_home,
    })
}

#[cfg(windows)]
fn windows_path_units(path: &Path) -> usize {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().count()
}

#[cfg(not(windows))]
fn windows_path_units(path: &Path) -> usize {
    path.as_os_str().len()
}

/// Best-effort sweep of archaeology scratch worktrees left in this exact
/// repo+project-bound scope by a prior pass that crashed between `git worktree add`
/// and cleanup (#427/#809).
/// Only worktrees whose embedded owner PID is dead are removed, so a
/// concurrently-running pass — its own live PID stamped in the directory name — is
/// never swept out from under itself. After removing stale directories, `git
/// worktree prune` drops the now-dangling administrative registrations from `repo`.
/// This is best-effort maintenance: it never aborts the import, but every outcome
/// is surfaced as counted telemetry (invariant 3), never a silent `let _`.
fn sweep_orphan_worktrees(repo: &Path, home: &Path) {
    let entries = match fs::read_dir(home) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!(
                "astro.archaeology.orphan_sweep home={} status=unreadable error={error}",
                home.display()
            );
            return;
        }
    };
    let self_pid = std::process::id();
    let mut swept = 0usize;
    let mut skipped_live = 0usize;
    let mut remnants = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(nonce) = name.strip_prefix(ARCHAEOLOGY_WORKTREE_PREFIX) else {
            continue;
        };
        // Nonce is `<pid>-<nanos>`; the owner PID is the leading integer field.
        let Some(pid) = nonce
            .split('-')
            .next()
            .and_then(|field| field.parse::<u32>().ok())
        else {
            continue;
        };
        // Never remove our own or a live owner's worktree (concurrency safety).
        if pid == self_pid || process_is_alive(pid) {
            skipped_live += 1;
            continue;
        }
        if remove_path_with_retry(&entry.path(), |target| fs::remove_dir_all(target)) {
            swept += 1;
        } else {
            remnants += 1;
        }
    }
    // Drop administrative registrations for worktrees whose working directory is now
    // gone (those swept here plus any removed by a prior pass' inline cleanup). Prune
    // only touches registrations with a missing dir, so a live worktree is untouched.
    let prune = git_checked(repo, &["-c", "core.longpaths=true", "worktree", "prune"]);
    eprintln!(
        "astro.archaeology.orphan_sweep home={} swept={swept} skipped_live={skipped_live} \
         remnants={remnants} prune={}",
        home.display(),
        if prune.is_ok() { "ok" } else { "failed" }
    );
}

/// Whether `pid` currently names a live process. Gates the orphan-worktree sweep
/// only (#427); the probe itself lives in `astrolabe_bridge::process_is_alive`
/// because this crate is `#![forbid(unsafe_code)]` and the bridge owns all FFI.
fn process_is_alive(pid: u32) -> bool {
    astrolabe_bridge::process_is_alive(pid)
}

fn path_str(path: &Path) -> Result<&str, DynError> {
    path.to_str()
        .ok_or_else(|| format!("archaeology path is not valid UTF-8: {}", path.display()).into())
}

fn git_checked(repo: &Path, args: &[&str]) -> Result<(), DynError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Git archaeology command {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into())
    }
}

/// Materializes one historical view without registering a shared Git worktree.
///
/// The default file-scoped path does not create a temporary Git index. It resolves
/// exact `commit:path` blobs with one bounded `cat-file --batch-command --buffer
/// -Z` object-info process, then streams the verified raw blob objects with one
/// `cat-file --batch -Z --buffer` process. The raw-object stream keeps Git's
/// `%objectsize` and content terminator contract exact; checkout filters can
/// expand bytes beyond the reported object size and make the batch stream
/// ambiguous. The non-default whole-subtree measurement path keeps the older
/// scope-private index + `checkout-index` route because it intentionally
/// materializes a complete subtree for parity measurements.
fn materialize_historical_tree(
    repo: &Path,
    scope: &Path,
    checkout_root: &Path,
    commit: &str,
    corpus_rel: &str,
    file_scoped: bool,
    implicated_files: &BTreeSet<String>,
) -> Result<HistoricalMaterialization, DynError> {
    fs::create_dir(scope).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_MATERIALIZATION_SCOPE_CREATE_FAILED: could not create fresh scope {}: {error}",
            scope.display()
        )
        .into()
    })?;
    fs::create_dir(checkout_root).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_MATERIALIZATION_TREE_CREATE_FAILED: could not create checkout root {}: {error}",
            checkout_root.display()
        )
        .into()
    })?;
    let mut windows_invalid_excluded = 0usize;
    let mut object_probe_processes_avoided = 0usize;
    if file_scoped {
        let mut requested = BTreeSet::new();
        for rel in implicated_files {
            let toplevel_path = if corpus_rel.is_empty() {
                rel.clone()
            } else {
                format!("{corpus_rel}/{rel}")
            };
            if toplevel_path.is_empty()
                || toplevel_path.starts_with('/')
                || toplevel_path
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
            {
                return Err(format!(
                    "ASTRO_ARCHAEOLOGY_PATH_INVALID: commit {commit} has an implicated path outside the corpus: {toplevel_path:?}; correct the mined evidence before retrying"
                )
                .into());
            }
            if let Some(reason) = windows_invalid_path(toplevel_path.as_bytes()) {
                eprintln!(
                    "astro.archaeology.windows_invalid_path commit={commit} path={toplevel_path:?} reason={reason}"
                );
                windows_invalid_excluded += 1;
                continue;
            }
            requested.insert(toplevel_path);
        }
        object_probe_processes_avoided = requested.len();
        let materialized = materialize_file_scoped_historical_closure(
            repo,
            checkout_root,
            commit,
            corpus_rel,
            &requested,
        )?;
        object_probe_processes_avoided = object_probe_processes_avoided
            .checked_add(materialized.dependency_files_materialized)
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_DEPENDENCY_TELEMETRY_OVERFLOW: avoided object probe count overflowed usize"
                    .into()
            })?;
        return Ok(HistoricalMaterialization {
            windows_invalid_excluded,
            git_inventory_processes: 0,
            git_checkout_processes: 0,
            git_cat_file_processes: materialized.git_cat_file_processes,
            git_cat_file_stdout_bytes: materialized.stdout_bytes,
            files_materialized: materialized.files_materialized,
            paths_absent: materialized.paths_absent,
            object_probe_processes_avoided,
            dependency_files_materialized: materialized.dependency_files_materialized,
            dependency_candidate_paths_absent: materialized.dependency_candidate_paths_absent,
            dependency_edges: materialized.dependency_edges,
            dependency_revisits: materialized.dependency_revisits,
            dependency_depth: materialized.dependency_depth,
        });
    }

    let index = scope.join("index");
    git_index_checked(repo, &index, &["read-tree", commit])?;

    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.longpaths=true", "ls-files", "--cached", "-z"])
        .env("GIT_INDEX_FILE", &index)
        .output()
        .map_err(|error| -> DynError {
            format!("ASTRO_ARCHAEOLOGY_GIT_INDEX_INVENTORY_SPAWN_FAILED: commit {commit}: {error}")
                .into()
        })?;
    if !output.status.success() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_GIT_INDEX_INVENTORY_FAILED: commit {commit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let mut inventory = BTreeSet::new();
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = std::str::from_utf8(raw).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_GIT_INDEX_PATH_INVALID_UTF8: commit {commit} contains a path that cannot be represented by the code-domain identity contract: {error}"
            )
            .into()
        })?;
        inventory.insert(path.to_string());
    }

    let prefix = if corpus_rel.is_empty() {
        None
    } else {
        Some(format!("{corpus_rel}/"))
    };
    let selected = inventory
        .into_iter()
        .filter(|path| {
            corpus_rel.is_empty()
                || path == corpus_rel
                || prefix
                    .as_ref()
                    .is_some_and(|prefix| path.starts_with(prefix))
        })
        .map(|path| {
            if let Some(reason) = windows_invalid_path(path.as_bytes()) {
                Err(format!(
                    "ASTRO_ARCHAEOLOGY_WINDOWS_PATH_UNREPRESENTABLE: commit {commit} path {path:?} cannot be materialized on Windows ({reason}); use file-scoped archaeology or correct the corpus before retrying"
                )
                .into())
            } else {
                Ok(path)
            }
        })
        .collect::<Result<BTreeSet<_>, DynError>>()?;

    let git_checkout_processes = usize::from(!selected.is_empty());
    if !selected.is_empty() {
        let mut input = Vec::new();
        for path in &selected {
            input.extend_from_slice(path.as_bytes());
            input.push(0);
        }
        let prefix = format!("{}/", path_str(checkout_root)?.replace('\\', "/"));
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "core.longpaths=true",
                "checkout-index",
                "--force",
                "-z",
                "--stdin",
            ])
            .arg(format!("--prefix={prefix}"))
            .env("GIT_INDEX_FILE", &index)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| -> DynError {
                format!("ASTRO_ARCHAEOLOGY_GIT_CHECKOUT_SPAWN_FAILED: commit {commit}: {error}")
                    .into()
            })?;
        child
            .stdin
            .take()
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_GIT_CHECKOUT_STDIN_MISSING: checkout-index did not expose its requested stdin".into()
            })?
            .write_all(&input)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_GIT_CHECKOUT_FAILED: commit {commit}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
    }

    Ok(HistoricalMaterialization {
        windows_invalid_excluded,
        git_inventory_processes: 2,
        git_checkout_processes,
        git_cat_file_processes: 0,
        git_cat_file_stdout_bytes: 0,
        files_materialized: selected.len(),
        paths_absent: 0,
        object_probe_processes_avoided,
        dependency_files_materialized: 0,
        dependency_candidate_paths_absent: 0,
        dependency_edges: 0,
        dependency_revisits: 0,
        dependency_depth: 0,
    })
}

struct FileScopedHistoricalBlobMaterialization {
    git_cat_file_processes: usize,
    stdout_bytes: u64,
    files_materialized: usize,
    paths_absent: usize,
    absent_paths: Vec<String>,
    dependency_files_materialized: usize,
    dependency_candidate_paths_absent: usize,
    dependency_edges: usize,
    dependency_revisits: usize,
    dependency_depth: usize,
    dependency_closure_sha256: String,
}

#[derive(Debug, Clone)]
struct HistoricalBlobObject {
    path: String,
    object_oid: String,
    object_mode: String,
    object_size: u64,
}

fn materialize_file_scoped_historical_blobs(
    repo: &Path,
    checkout_root: &Path,
    commit: &str,
    requested: &BTreeSet<String>,
) -> Result<FileScopedHistoricalBlobMaterialization, DynError> {
    let mut report = FileScopedHistoricalBlobMaterialization {
        git_cat_file_processes: 0,
        stdout_bytes: 0,
        files_materialized: 0,
        paths_absent: 0,
        absent_paths: Vec::new(),
        dependency_files_materialized: 0,
        dependency_candidate_paths_absent: 0,
        dependency_edges: 0,
        dependency_revisits: 0,
        dependency_depth: 0,
        dependency_closure_sha256: String::new(),
    };
    if requested.is_empty() {
        return Ok(report);
    }

    let requested_paths = requested.iter().map(String::as_str).collect::<Vec<_>>();
    for chunk in requested_paths.chunks(HISTORICAL_CAT_FILE_BATCH_PATHS) {
        let (objects, info_stdout_bytes, absent_paths) =
            resolve_file_scoped_historical_blobs(repo, commit, chunk)?;
        report.git_cat_file_processes = report.git_cat_file_processes.checked_add(1).ok_or_else(
            || -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: cat-file process count overflowed"
                    .into()
            },
        )?;
        report.stdout_bytes = report
            .stdout_bytes
            .checked_add(info_stdout_bytes)
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: cat-file stdout bytes overflowed"
                    .into()
            })?;
        report.paths_absent = report
                .paths_absent
                .checked_add(absent_paths.len())
                .ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_ARCHAEOLOGY_CAT_FILE_ABSENT_OVERFLOW: commit {commit} absent path count overflowed"
                    )
                    .into()
                })?;
        report.absent_paths.extend(absent_paths);
        if objects.is_empty() {
            continue;
        }

        let streamed = stream_file_scoped_historical_blobs(repo, checkout_root, &objects)?;
        report.git_cat_file_processes = report.git_cat_file_processes.checked_add(1).ok_or_else(
            || -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: cat-file process count overflowed"
                    .into()
            },
        )?;
        report.stdout_bytes = report
            .stdout_bytes
            .checked_add(streamed.stdout_bytes)
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: cat-file stdout bytes overflowed"
                    .into()
            })?;
        report.files_materialized = report
            .files_materialized
            .checked_add(streamed.files_materialized)
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_MATERIALIZED_OVERFLOW: materialized file count overflowed"
                    .into()
            })?;
    }
    Ok(report)
}

#[derive(Clone, Copy)]
enum DependencyCardinality {
    ExactlyOne,
    AtMostOne,
}

struct HistoricalDependencyRequest {
    source_path: String,
    module_path: String,
    kind: String,
    candidates: Vec<String>,
    cardinality: DependencyCardinality,
}

fn plan_historical_dependency(
    source_path: &str,
    source_rel: &str,
    import: &Import,
) -> Result<Option<HistoricalDependencyRequest>, DynError> {
    let (candidates, cardinality, default_kind) = match import.resolution {
        ImportResolution::ExactSource => (
            vec![normalize_exact_source_dependency(
                source_rel,
                &import.module_path,
            )?],
            DependencyCardinality::ExactlyOne,
            "exact_source",
        ),
        ImportResolution::RustModule => (
            rust_module_dependency_candidates(source_rel, &import.module_path)?,
            DependencyCardinality::ExactlyOne,
            "rust_module",
        ),
        ImportResolution::EsSource if is_relative_source_request(&import.module_path) => (
            es_source_dependency_candidates(source_rel, &import.module_path)?,
            DependencyCardinality::ExactlyOne,
            "es_source",
        ),
        ImportResolution::BrowserUrl
            if is_relative_source_request(&import.module_path)
                && !import.module_path.contains(['?', '#', '%', '\\']) =>
        {
            (
                vec![normalize_exact_source_dependency(
                    source_rel,
                    &import.module_path,
                )?],
                DependencyCardinality::AtMostOne,
                "browser_source",
            )
        }
        ImportResolution::Semantic
        | ImportResolution::ExternalSource
        | ImportResolution::EsSource
        | ImportResolution::BrowserUrl => return Ok(None),
    };
    let candidates = candidates.into_iter().collect::<BTreeSet<_>>();
    if candidates.is_empty() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_DEPENDENCY_PLAN_EMPTY: source {source_rel:?} dependency {:?} produced no immutable-tree candidates; remediation=repair the typed CBM dependency planner before retrying",
            import.module_path
        )
        .into());
    }
    Ok(Some(HistoricalDependencyRequest {
        source_path: source_path.to_string(),
        module_path: import.module_path.clone(),
        kind: import
            .dependency_kind
            .clone()
            .unwrap_or_else(|| default_kind.to_string()),
        candidates: candidates.into_iter().collect(),
        cardinality,
    }))
}

fn is_relative_source_request(module_path: &str) -> bool {
    module_path.starts_with("./") || module_path.starts_with("../")
}

fn es_source_dependency_candidates(
    source_rel: &str,
    module_path: &str,
) -> Result<Vec<String>, DynError> {
    let family: Option<(&str, &[&str])> = if module_path.ends_with(".mjs") {
        Some((".mjs", &[".mts", ".d.mts", ".mjs"]))
    } else if module_path.ends_with(".cjs") {
        Some((".cjs", &[".cts", ".d.cts", ".cjs"]))
    } else if module_path.ends_with(".jsx") {
        Some((".jsx", &[".tsx", ".d.ts", ".jsx"]))
    } else if module_path.ends_with(".js") {
        Some((".js", &[".ts", ".tsx", ".d.ts", ".js", ".jsx"]))
    } else {
        None
    };
    let Some((suffix, replacements)) = family else {
        return Ok(vec![normalize_exact_source_dependency(
            source_rel,
            module_path,
        )?]);
    };
    let stem = module_path.strip_suffix(suffix).ok_or_else(|| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_DEPENDENCY_ES_SUFFIX_INVALID: source {source_rel:?} module {module_path:?} lost its matched runtime suffix; remediation=repair the ordered ES substitution planner"
        )
        .into()
    })?;
    replacements
        .iter()
        .map(|replacement| {
            normalize_exact_source_dependency(source_rel, &format!("{stem}{replacement}"))
        })
        .collect()
}

fn rust_module_dependency_candidates(
    source_rel: &str,
    module_path: &str,
) -> Result<Vec<String>, DynError> {
    Ok(vec![
        normalize_exact_source_dependency(source_rel, &format!("{module_path}.rs"))?,
        normalize_exact_source_dependency(source_rel, &format!("{module_path}/mod.rs"))?,
    ])
}

fn historical_cargo_manifest_candidates(source_path: &str) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    let mut parent = Path::new(source_path).parent();
    while let Some(directory) = parent {
        let candidate = directory.join("Cargo.toml");
        candidates.insert(path_to_slash_string(&candidate));
        parent = directory.parent();
    }
    candidates
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_historical_cargo_path(base: &str, relative: &str) -> Result<String, DynError> {
    if relative.is_empty()
        || relative.starts_with(['/', '\\'])
        || relative.as_bytes().get(1) == Some(&b':')
    {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CARGO_TARGET_PATH_INVALID: base {base:?} target path {relative:?} is not repository-relative; remediation=repair the Cargo target path before retrying"
        )
        .into());
    }
    let mut parts = base
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for part in relative.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!(
                        "ASTRO_ARCHAEOLOGY_CARGO_TARGET_PATH_ESCAPE: base {base:?} target path {relative:?} escapes the immutable repository; remediation=repair the Cargo path before retrying"
                    )
                    .into());
                }
            }
            value => parts.push(value.to_string()),
        }
    }
    Ok(parts.join("/"))
}

fn cargo_auto_root(path: &str, prefix: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    match rest.split('/').collect::<Vec<_>>().as_slice() {
        [file] => file.ends_with(".rs"),
        [_directory, "main.rs"] => true,
        _ => false,
    }
}

fn cargo_bool(package: &toml::value::Table, key: &str) -> Result<(bool, bool), DynError> {
    match package.get(key) {
        None => Ok((true, false)),
        Some(value) => value.as_bool().map(|value| (value, true)).ok_or_else(|| {
            format!(
                "ASTRO_ARCHAEOLOGY_CARGO_BOOLEAN_INVALID: package.{key} must be a boolean; remediation=repair the immutable Cargo manifest before retrying"
            )
            .into()
        }),
    }
}

fn cargo_target_tables<'a>(
    manifest: &'a toml::Value,
    key: &str,
) -> Result<Vec<&'a toml::value::Table>, DynError> {
    let Some(value) = manifest.get(key) else {
        return Ok(Vec::new());
    };
    if key == "lib" {
        return value.as_table().map(|table| vec![table]).ok_or_else(|| {
            "ASTRO_ARCHAEOLOGY_CARGO_TARGET_TABLE_INVALID: [lib] is not a TOML table; remediation=repair the immutable Cargo manifest before retrying"
                .into()
        });
    }
    value
        .as_array()
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CARGO_TARGET_TABLE_INVALID: [[{key}]] is not an array of tables; remediation=repair the immutable Cargo manifest before retrying"
            )
            .into()
        })?
        .iter()
        .map(|entry| {
            entry.as_table().ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CARGO_TARGET_TABLE_INVALID: [[{key}]] contains a non-table entry; remediation=repair the immutable Cargo manifest before retrying"
                )
                .into()
            })
        })
        .collect()
}

fn inferred_named_cargo_target(
    source_path: &str,
    package_dir: &str,
    package_name: &str,
    kind: &str,
    target: &toml::value::Table,
) -> Result<bool, DynError> {
    if let Some(path) = target.get("path") {
        let path = path.as_str().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CARGO_TARGET_PATH_INVALID: {kind}.path is not a string; remediation=repair the immutable Cargo manifest before retrying"
            )
            .into()
        })?;
        return Ok(normalize_historical_cargo_path(package_dir, path)? == source_path);
    }
    if kind == "lib" {
        return Ok(normalize_historical_cargo_path(package_dir, "src/lib.rs")? == source_path);
    }
    let name = target.get("name").and_then(toml::Value::as_str).ok_or_else(
        || -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CARGO_TARGET_NAME_MISSING: [[{kind}]] without path has no string name; remediation=repair the immutable Cargo manifest before retrying"
            )
            .into()
        },
    )?;
    let family = match kind {
        "bin" => "src/bin",
        "example" => "examples",
        "test" => "tests",
        "bench" => "benches",
        _ => unreachable!(),
    };
    if normalize_historical_cargo_path(package_dir, &format!("{family}/{name}.rs"))? == source_path
        || normalize_historical_cargo_path(package_dir, &format!("{family}/{name}/main.rs"))?
            == source_path
    {
        return Ok(true);
    }
    Ok(kind == "bin"
        && name == package_name
        && normalize_historical_cargo_path(package_dir, "src/main.rs")? == source_path)
}

fn historical_package_edition_is_2015(
    checkout_root: &Path,
    package_dir: &str,
    package: &toml::value::Table,
) -> Result<bool, DynError> {
    match package.get("edition") {
        None => return Ok(true),
        Some(value) if value.as_str().is_some() => return Ok(value.as_str() == Some("2015")),
        Some(value)
            if value
                .as_table()
                .and_then(|table| table.get("workspace"))
                .and_then(toml::Value::as_bool)
                == Some(true) => {}
        Some(_) => {
            return Err(
                "ASTRO_ARCHAEOLOGY_CARGO_EDITION_INVALID: package.edition is neither a string nor `{ workspace = true }`; remediation=repair the immutable Cargo manifest before retrying"
                    .into(),
            );
        }
    }
    let explicit_workspace = package
        .get("workspace")
        .map(|value| {
            value.as_str().ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CARGO_WORKSPACE_PATH_INVALID: package.workspace is not a string; remediation=repair the immutable Cargo manifest before retrying"
                    .into()
            })
        })
        .transpose()?;
    let mut directory = if let Some(workspace) = explicit_workspace {
        Some(PathBuf::from(normalize_historical_cargo_path(
            package_dir,
            workspace,
        )?))
    } else {
        Some(PathBuf::from(package_dir))
    };
    while let Some(candidate_dir) = directory {
        let manifest_path = checkout_root.join(&candidate_dir).join("Cargo.toml");
        if manifest_path.is_file() {
            let text = fs::read_to_string(&manifest_path).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CARGO_MANIFEST_READ_FAILED: could not read {}: {error}; remediation=preserve the immutable checkout and repair the exact read before retrying",
                    manifest_path.display()
                )
                .into()
            })?;
            let manifest = text.parse::<toml::Value>().map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CARGO_MANIFEST_INVALID: {} is not valid TOML: {error}; remediation=repair the immutable manifest before retrying",
                    manifest_path.display()
                )
                .into()
            })?;
            if let Some(edition) = manifest
                .get("workspace")
                .and_then(|workspace| workspace.get("package"))
                .and_then(|package| package.get("edition"))
                .and_then(toml::Value::as_str)
            {
                return Ok(edition == "2015");
            }
        }
        if explicit_workspace.is_some() {
            break;
        }
        directory = candidate_dir.parent().map(Path::to_path_buf);
    }
    Err(format!(
        "ASTRO_ARCHAEOLOGY_CARGO_WORKSPACE_EDITION_MISSING: package {package_dir:?} inherits edition but no immutable workspace.package.edition was found; remediation=materialize and repair the exact workspace manifest before retrying"
    )
    .into())
}

fn historical_rust_is_crate_root(
    checkout_root: &Path,
    source_path: &str,
) -> Result<bool, DynError> {
    let mut parent = Path::new(source_path).parent();
    let (manifest_path, package_dir, manifest, package) = loop {
        let Some(directory) = parent else {
            return Ok(false);
        };
        let candidate = directory.join("Cargo.toml");
        let physical = checkout_root.join(&candidate);
        if physical.is_file() {
            let text = fs::read_to_string(&physical).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CARGO_MANIFEST_READ_FAILED: could not read {}: {error}; remediation=preserve the immutable checkout and repair the exact read before retrying",
                    physical.display()
                )
                .into()
            })?;
            let parsed = text.parse::<toml::Value>().map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CARGO_MANIFEST_INVALID: {} is not valid TOML: {error}; remediation=repair the immutable manifest before retrying",
                    physical.display()
                )
                .into()
            })?;
            if let Some(package) = parsed
                .get("package")
                .and_then(toml::Value::as_table)
                .cloned()
            {
                break (
                    path_to_slash_string(&candidate),
                    path_to_slash_string(directory),
                    parsed,
                    package,
                );
            }
        }
        parent = directory.parent();
    };
    let package_name = package
        .get("name")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CARGO_PACKAGE_NAME_MISSING: {manifest_path:?} has [package] without a string name; remediation=repair the immutable manifest before retrying"
            )
            .into()
        })?;

    match package.get("build") {
        None => {
            if normalize_historical_cargo_path(&package_dir, "build.rs")? == source_path {
                return Ok(true);
            }
        }
        Some(value) if value.as_bool() == Some(false) => {}
        Some(value) => {
            let build = value.as_str().ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CARGO_BUILD_VALUE_INVALID: {manifest_path:?} package.build is neither false nor a string; remediation=repair the immutable manifest before retrying"
                )
                .into()
            })?;
            if normalize_historical_cargo_path(&package_dir, build)? == source_path {
                return Ok(true);
            }
        }
    }

    let mut manual_target_count = 0usize;
    for kind in ["lib", "bin", "example", "test", "bench"] {
        for target in cargo_target_tables(&manifest, kind)? {
            manual_target_count += 1;
            if inferred_named_cargo_target(source_path, &package_dir, package_name, kind, target)? {
                return Ok(true);
            }
        }
    }

    let edition_2015 = historical_package_edition_is_2015(checkout_root, &package_dir, &package)?;
    let (autolib, autolib_declared) = cargo_bool(&package, "autolib")?;
    let (autobins, autobins_declared) = cargo_bool(&package, "autobins")?;
    let (autoexamples, autoexamples_declared) = cargo_bool(&package, "autoexamples")?;
    let (autotests, autotests_declared) = cargo_bool(&package, "autotests")?;
    let (autobenches, autobenches_declared) = cargo_bool(&package, "autobenches")?;
    let manual_disables_auto = edition_2015 && manual_target_count > 0;
    let package_rel = source_path
        .strip_prefix(&package_dir)
        .and_then(|path| path.strip_prefix('/').or(Some(path)))
        .unwrap_or(source_path);
    Ok(
        (autolib && (autolib_declared || !manual_disables_auto) && package_rel == "src/lib.rs")
            || (autobins
                && (autobins_declared || !manual_disables_auto)
                && (package_rel == "src/main.rs" || cargo_auto_root(package_rel, "src/bin/")))
            || (autoexamples
                && (autoexamples_declared || !manual_disables_auto)
                && cargo_auto_root(package_rel, "examples/"))
            || (autotests
                && (autotests_declared || !manual_disables_auto)
                && cargo_auto_root(package_rel, "tests/"))
            || (autobenches
                && (autobenches_declared || !manual_disables_auto)
                && cargo_auto_root(package_rel, "benches/")),
    )
}

/// Materialize the evidence seed set and then close every exact repository-local
/// source dependency using libcbm's own extraction semantics. The ordinary CBM
/// pipeline remains fail-closed; this planner makes its filesystem view truthful
/// instead of asking it to resolve a deliberately incomplete checkout.
fn materialize_file_scoped_historical_closure(
    repo: &Path,
    checkout_root: &Path,
    commit: &str,
    corpus_rel: &str,
    requested: &BTreeSet<String>,
) -> Result<FileScopedHistoricalBlobMaterialization, DynError> {
    let mut report =
        materialize_file_scoped_historical_blobs(repo, checkout_root, commit, requested)?;
    let mut visited = requested.clone();
    let mut probed = requested.clone();
    let mut frontier = requested
        .iter()
        .filter(|path| checkout_root.join(path.as_str()).is_file())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut dependency_edges = BTreeSet::<(String, String, String)>::new();
    let mut depth = 0usize;

    while !frontier.is_empty() {
        let cargo_manifest_candidates = frontier
            .iter()
            .flat_map(|source_path| historical_cargo_manifest_candidates(source_path))
            .filter(|path| !probed.contains(path))
            .collect::<BTreeSet<_>>();
        if !cargo_manifest_candidates.is_empty() {
            let materialized = materialize_file_scoped_historical_blobs(
                repo,
                checkout_root,
                commit,
                &cargo_manifest_candidates,
            )?;
            probed.extend(cargo_manifest_candidates);
            report.git_cat_file_processes = report
                .git_cat_file_processes
                .checked_add(materialized.git_cat_file_processes)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: Cargo-context cat-file process count overflowed"
                        .into()
                })?;
            report.stdout_bytes = report
                .stdout_bytes
                .checked_add(materialized.stdout_bytes)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: Cargo-context cat-file stdout bytes overflowed"
                        .into()
                })?;
            report.files_materialized = report
                .files_materialized
                .checked_add(materialized.files_materialized)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_MATERIALIZED_OVERFLOW: Cargo-context materialized file count overflowed"
                        .into()
                })?;
            report.dependency_files_materialized = report
                .dependency_files_materialized
                .checked_add(materialized.files_materialized)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_FILE_OVERFLOW: Cargo-context materialized file count overflowed"
                        .into()
                })?;
            report.dependency_candidate_paths_absent = report
                .dependency_candidate_paths_absent
                .checked_add(materialized.paths_absent)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_CANDIDATE_ABSENT_OVERFLOW: absent Cargo-context candidate count overflowed usize"
                        .into()
                })?;
        }
        let mut requests = Vec::<HistoricalDependencyRequest>::new();
        let mut candidates_to_probe = BTreeSet::new();
        for source_path in &frontier {
            let source_rel = corpus_relative_materialized_path(source_path, corpus_rel)?;
            let Some(language) = Language::from_filename(source_rel) else {
                continue;
            };
            let physical_path = checkout_root.join(source_path);
            let source_bytes = fs::read(&physical_path).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_SOURCE_READ_FAILED: commit {commit} could not read materialized source {}: {error}; remediation=preserve the checkout and repair the exact filesystem read before retrying",
                    physical_path.display()
                )
                .into()
            })?;
            let source = std::str::from_utf8(&source_bytes).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_SOURCE_INVALID_UTF8: commit {commit} source {source_rel:?} is not valid UTF-8: {error}; remediation=extend the CBM extraction bridge with the source's authoritative byte encoding before historical indexing"
                )
                .into()
            })?;
            let rust_is_crate_root = language == Language::RUST
                && historical_rust_is_crate_root(checkout_root, source_path)?;
            let extracted = ExtractedFile::extract_with_rust_context(
                source,
                language,
                "astrolabe-historical-dependency-plan",
                source_rel,
                rust_is_crate_root,
                HISTORICAL_DEPENDENCY_EXTRACT_TIMEOUT_MICROS,
            )
            .map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_EXTRACT_FAILED: commit {commit} source {source_rel:?} could not produce its exact dependency plan: {error}; remediation=fix the authoritative CBM extraction fault before retrying"
                )
                .into()
            })?;
            for import in extracted.imports().map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_IMPORT_READ_FAILED: commit {commit} source {source_rel:?} returned an invalid import record: {error}; remediation=repair the CBM/Rust import contract before retrying"
                )
                .into()
            })? {
                let Some(request) = plan_historical_dependency(source_path, source_rel, &import)?
                else {
                    continue;
                };
                for candidate in &request.candidates {
                    let materialized = corpus_materialized_path(corpus_rel, candidate);
                    if let Some(reason) = windows_invalid_path(materialized.as_bytes()) {
                        return Err(format!(
                            "ASTRO_ARCHAEOLOGY_DEPENDENCY_WINDOWS_PATH_INVALID: commit {commit} source {source_rel:?} dependency {:?} resolves to Windows-unrepresentable path {materialized:?} ({reason}); remediation=repair the dependency path or index this commit on a filesystem that can represent it",
                            import.module_path
                        )
                        .into());
                    }
                    if !probed.contains(&materialized) {
                        candidates_to_probe.insert(materialized);
                    }
                }
                requests.push(request);
            }
        }

        if !candidates_to_probe.is_empty() {
            let materialized = materialize_file_scoped_historical_blobs(
                repo,
                checkout_root,
                commit,
                &candidates_to_probe,
            )?;
            probed.extend(candidates_to_probe);
            report.git_cat_file_processes = report
                .git_cat_file_processes
                .checked_add(materialized.git_cat_file_processes)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: dependency cat-file process count overflowed"
                        .into()
                })?;
            report.stdout_bytes = report
                .stdout_bytes
                .checked_add(materialized.stdout_bytes)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: dependency cat-file stdout bytes overflowed"
                        .into()
                })?;
            report.files_materialized = report
                .files_materialized
                .checked_add(materialized.files_materialized)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_MATERIALIZED_OVERFLOW: dependency materialized file count overflowed"
                        .into()
                })?;
            report.dependency_files_materialized = report
                .dependency_files_materialized
                .checked_add(materialized.files_materialized)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_FILE_OVERFLOW: materialized dependency file count overflowed"
                        .into()
                })?;
            report.dependency_candidate_paths_absent = report
                .dependency_candidate_paths_absent
                .checked_add(materialized.paths_absent)
                .ok_or_else(|| -> DynError {
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_CANDIDATE_ABSENT_OVERFLOW: absent dependency candidate count overflowed usize"
                        .into()
                })?;
        }

        let mut next = BTreeSet::new();
        for request in requests {
            let matches = request
                .candidates
                .iter()
                .map(|candidate| corpus_materialized_path(corpus_rel, candidate))
                .filter(|candidate| checkout_root.join(candidate).is_file())
                .collect::<Vec<_>>();
            let selected = match (request.cardinality, matches.as_slice()) {
                (DependencyCardinality::ExactlyOne, [selected])
                | (DependencyCardinality::AtMostOne, [selected]) => Some(selected.clone()),
                (DependencyCardinality::AtMostOne, []) => None,
                (DependencyCardinality::ExactlyOne, []) => {
                    return Err(format!(
                        "ASTRO_ARCHAEOLOGY_DEPENDENCY_SOURCE_MISSING: commit {commit} source {:?} {} dependency {:?} has no source among {:?}; remediation=restore the exact source file or repair the importing path before retrying; no partial historical view was indexed",
                        request.source_path, request.kind, request.module_path, request.candidates
                    )
                    .into());
                }
                (_, _) => {
                    return Err(format!(
                        "ASTRO_ARCHAEOLOGY_DEPENDENCY_SOURCE_AMBIGUOUS: commit {commit} source {:?} {} dependency {:?} matches multiple immutable-tree sources {:?}; remediation=remove the conflicting source candidates before retrying; no partial historical view was indexed",
                        request.source_path, request.kind, request.module_path, matches
                    )
                    .into());
                }
            };
            let Some(selected) = selected else {
                continue;
            };
            report.dependency_edges = report.dependency_edges.checked_add(1).ok_or_else(
                || -> DynError {
                    "ASTRO_ARCHAEOLOGY_DEPENDENCY_EDGE_OVERFLOW: source dependency edge count overflowed usize"
                        .into()
                },
            )?;
            dependency_edges.insert((request.source_path, selected.clone(), request.kind));
            if visited.insert(selected.clone()) {
                if visited.len() > HISTORICAL_DEPENDENCY_CLOSURE_MAX_FILES {
                    return Err(format!(
                        "ASTRO_ARCHAEOLOGY_DEPENDENCY_CLOSURE_LIMIT: commit {commit} source dependency closure exceeded {HISTORICAL_DEPENDENCY_CLOSURE_MAX_FILES} unique files at {selected:?}; remediation=inspect the closure for a malformed/generated dependency fanout and raise the compile-time bound only with measured memory and object-stream evidence"
                    )
                    .into());
                }
                next.insert(selected);
            } else {
                report.dependency_revisits = report
                    .dependency_revisits
                    .checked_add(1)
                    .ok_or_else(|| -> DynError {
                        "ASTRO_ARCHAEOLOGY_DEPENDENCY_REVISIT_OVERFLOW: dependency revisit count overflowed usize"
                            .into()
                    })?;
            }
        }
        if next.is_empty() {
            break;
        }
        depth = depth.checked_add(1).ok_or_else(|| -> DynError {
            "ASTRO_ARCHAEOLOGY_DEPENDENCY_DEPTH_OVERFLOW: dependency closure depth overflowed usize"
                .into()
        })?;
        frontier = next;
    }

    report.dependency_depth = depth;
    let mut hasher = Sha256::new();
    hash_dependency_closure_part(&mut hasher, b"astrolabe.historical-dependency-closure.v1")?;
    for path in &visited {
        hash_dependency_closure_part(&mut hasher, b"file")?;
        hash_dependency_closure_part(&mut hasher, path.as_bytes())?;
    }
    for (source, target, kind) in &dependency_edges {
        hash_dependency_closure_part(&mut hasher, b"edge")?;
        hash_dependency_closure_part(&mut hasher, source.as_bytes())?;
        hash_dependency_closure_part(&mut hasher, target.as_bytes())?;
        hash_dependency_closure_part(&mut hasher, kind.as_bytes())?;
    }
    report.dependency_closure_sha256 = hex_lower(&hasher.finalize());
    eprintln!(
        "astro.archaeology.dependency_closure commit={commit} seeds={} dependencies={} candidate_paths_absent={} edges={} revisits={} depth={} closure_sha256={}",
        requested.len(),
        report.dependency_files_materialized,
        report.dependency_candidate_paths_absent,
        report.dependency_edges,
        report.dependency_revisits,
        report.dependency_depth,
        report.dependency_closure_sha256
    );
    Ok(report)
}

fn corpus_relative_materialized_path<'a>(
    materialized_path: &'a str,
    corpus_rel: &str,
) -> Result<&'a str, DynError> {
    if corpus_rel.is_empty() {
        return Ok(materialized_path);
    }
    let prefix = format!("{corpus_rel}/");
    materialized_path.strip_prefix(&prefix).ok_or_else(|| {
        format!(
            "ASTRO_ARCHAEOLOGY_DEPENDENCY_SCOPE_MISMATCH: materialized path {materialized_path:?} is outside corpus {corpus_rel:?}; remediation=repair the commit-bound path framing before extraction"
        )
        .into()
    })
}

fn corpus_materialized_path(corpus_rel: &str, dependency_rel: &str) -> String {
    if corpus_rel.is_empty() {
        dependency_rel.to_string()
    } else {
        format!("{corpus_rel}/{dependency_rel}")
    }
}

/// Mirrors libcbm's `normalize_source_candidate` contract for exact-source
/// imports: separator normalization, dot removal, and fail-closed corpus escape.
fn normalize_exact_source_dependency(
    source_rel: &str,
    module_path: &str,
) -> Result<String, DynError> {
    let module_path = module_path.replace('\\', "/");
    if module_path.is_empty()
        || module_path.starts_with('/')
        || module_path.as_bytes().get(1) == Some(&b':')
    {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_DEPENDENCY_PATH_INVALID: source {source_rel:?} exact dependency {module_path:?} cannot identify a repository-relative source; remediation=repair the exact import spelling"
        )
        .into());
    }
    let parent = source_rel.rsplit_once('/').map_or("", |(parent, _)| parent);
    let joined = if parent.is_empty() {
        module_path.clone()
    } else {
        format!("{parent}/{module_path}")
    };
    let mut components = Vec::new();
    for component in joined.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(format!(
                        "ASTRO_ARCHAEOLOGY_DEPENDENCY_SCOPE_ESCAPE: source {source_rel:?} exact dependency {module_path:?} escapes the indexed corpus; remediation=keep the import inside the corpus or widen the explicitly indexed corpus"
                    )
                    .into());
                }
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_DEPENDENCY_PATH_INVALID: source {source_rel:?} exact dependency {module_path:?} normalizes to an empty path; remediation=repair the exact import spelling"
        )
        .into());
    }
    Ok(components.join("/"))
}

fn hash_dependency_closure_part(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), DynError> {
    let len = u64::try_from(bytes.len()).map_err(|_| -> DynError {
        "ASTRO_ARCHAEOLOGY_DEPENDENCY_HASH_LENGTH_OVERFLOW: closure component length exceeds u64; remediation=preserve the scratch generation and inspect the impossible platform width mismatch"
            .into()
    })?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn resolve_file_scoped_historical_blobs(
    repo: &Path,
    commit: &str,
    requested: &[&str],
) -> Result<(Vec<HistoricalBlobObject>, u64, Vec<String>), DynError> {
    let mut input = Vec::new();
    for path in requested {
        input.extend_from_slice(b"info ");
        input.extend_from_slice(commit.as_bytes());
        input.push(b':');
        input.extend_from_slice(path.as_bytes());
        input.push(0);
    }
    input.extend_from_slice(b"flush");
    input.push(0);
    let output = git_cat_file_with_stdin(
        repo,
        &[
            "cat-file",
            "--batch-command=%(objectname) %(objecttype) %(objectmode) %(objectsize)",
            "--buffer",
            "-Z",
        ],
        &input,
        commit,
        "historical file-scoped blob preflight",
    )?;
    let stdout_bytes = u64::try_from(output.len()).map_err(|_| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_STDOUT_TOO_LARGE: commit {commit} cat-file stdout length cannot fit u64"
        )
        .into()
    })?;
    let mut records = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    while records.last().is_some_and(|record| record.is_empty()) {
        records.pop();
    }
    if records.len() != requested.len() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_RECORD_COUNT_MISMATCH: commit {commit} preflight returned {} records for {} requested paths",
            records.len(),
            requested.len()
        )
        .into());
    }
    let mut objects = Vec::new();
    let mut absent_paths = Vec::new();
    for (path, record) in requested.iter().zip(records) {
        let record = std::str::from_utf8(record).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_INVALID_UTF8: commit {commit} path {path:?}: {error}"
            )
            .into()
        })?;
        let query = format!("{commit}:{path}");
        if record == format!("{query} missing") {
            absent_paths.push((*path).to_string());
            continue;
        }
        let (object_oid, object_type, object_mode, object_size) =
            parse_cat_file_blob_info_record(commit, path, record)?;
        if object_type != "blob" || !matches!(object_mode, "100644" | "100755") {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_OBJECT_UNSUPPORTED: commit {commit} path {path:?} expected a regular blob mode 100644/100755 or explicit missing record, got type={object_type:?} mode={object_mode:?}; remediation=\"preserve the scratch evidence and inspect the exact Git tree mode before extending materialization semantics\""
            )
            .into());
        }
        objects.push(HistoricalBlobObject {
            path: (*path).to_string(),
            object_oid: object_oid.to_string(),
            object_mode: object_mode.to_string(),
            object_size,
        });
    }
    Ok((objects, stdout_bytes, absent_paths))
}

fn parse_cat_file_blob_info_record<'a>(
    commit: &str,
    path: &str,
    record: &'a str,
) -> Result<(&'a str, &'a str, &'a str, u64), DynError> {
    let mut fields = record.split(' ');
    let object_id = fields.next().unwrap_or_default();
    let object_type = fields.next().unwrap_or_default();
    let object_mode = fields.next().unwrap_or_default();
    let size = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || !git_object_id_like(object_id)
        || object_type.is_empty()
        || object_mode.is_empty()
    {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_INVALID: commit {commit} path {path:?} returned malformed preflight record {record:?}"
        )
        .into());
    }
    let size = size.parse::<u64>().map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_SIZE_INVALID: commit {commit} path {path:?} returned invalid blob size {size:?}: {error}"
        )
        .into()
    })?;
    Ok((object_id, object_type, object_mode, size))
}

fn git_object_id_like(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn stream_file_scoped_historical_blobs(
    repo: &Path,
    checkout_root: &Path,
    objects: &[HistoricalBlobObject],
) -> Result<FileScopedHistoricalBlobMaterialization, DynError> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "core.longpaths=true",
            "cat-file",
            "--batch",
            "--buffer",
            "-Z",
        ])
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_SPAWN_FAILED: failed to spawn historical content stream in {}: {error}",
                repo.display()
            )
            .into()
        })?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| -> DynError {
            "ASTRO_ARCHAEOLOGY_CAT_FILE_STDIN_MISSING: historical content stream did not expose stdin"
                .into()
        })?;
        for object in objects {
            stdin.write_all(object.object_oid.as_bytes())?;
            stdin.write_all(&[0])?;
        }
    }

    let stderr = child.stderr.take().ok_or_else(|| -> DynError {
        "ASTRO_ARCHAEOLOGY_CAT_FILE_STDERR_MISSING: historical content stream did not expose stderr"
            .into()
    })?;
    let stderr_reader = std::thread::spawn(move || {
        let mut reader = stderr;
        let mut bytes = Vec::new();
        let result = reader.read_to_end(&mut bytes);
        (result, bytes)
    });
    let stdout = child.stdout.take().ok_or_else(|| -> DynError {
        "ASTRO_ARCHAEOLOGY_CAT_FILE_STDOUT_MISSING: historical content stream did not expose stdout"
            .into()
    })?;
    let mut reader = BufReader::new(stdout);
    let parse_result =
        parse_file_scoped_historical_blob_stream(&mut reader, checkout_root, objects);
    if parse_result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_WAIT_FAILED: historical content stream wait failed: {error}"
        )
        .into()
    })?;
    let (stderr_result, stderr_bytes) = stderr_reader.join().map_err(|_| -> DynError {
        "ASTRO_ARCHAEOLOGY_CAT_FILE_STDERR_JOIN_FAILED: stderr reader panicked".into()
    })?;
    stderr_result.map_err(|error| -> DynError {
        format!("ASTRO_ARCHAEOLOGY_CAT_FILE_STDERR_READ_FAILED: {error}").into()
    })?;
    let parsed = match parse_result {
        Ok(parsed) => parsed,
        Err(error) => {
            if !status.success() {
                return Err(format!(
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_STREAM_FAILED: historical content stream exited {:?} while parsing stdout: parse_error={error}; stderr={}",
                    status.code(),
                    String::from_utf8_lossy(&stderr_bytes).trim()
                )
                .into());
            }
            return Err(error);
        }
    };
    if !status.success() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_STREAM_FAILED: historical content stream exited {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&stderr_bytes).trim()
        )
        .into());
    }
    Ok(parsed)
}

fn parse_file_scoped_historical_blob_stream<R: BufRead>(
    reader: &mut R,
    checkout_root: &Path,
    objects: &[HistoricalBlobObject],
) -> Result<FileScopedHistoricalBlobMaterialization, DynError> {
    let mut stdout_bytes = 0u64;
    let mut files_materialized = 0usize;
    let mut buffer = vec![0u8; 1024 * 1024];
    for object in objects {
        let mut header = Vec::new();
        let header_bytes = reader
            .read_until(0, &mut header)
            .map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_READ_FAILED: path {:?}: {error}",
                    object.path
                )
                .into()
            })?;
        if header_bytes == 0 {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_MISSING: path {:?} ended before its header",
                object.path
            )
            .into());
        }
        stdout_bytes = stdout_bytes
            .checked_add(u64::try_from(header_bytes).map_err(|_| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: header length cannot fit u64".into()
            })?)
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: stdout bytes overflowed".into()
            })?;
        if header.last() != Some(&0) {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_TERMINATOR_MISSING: path {:?} header was not NUL-terminated",
                object.path
            )
            .into());
        }
        header.pop();
        let header = std::str::from_utf8(&header).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_INVALID_UTF8: path {:?}: {error}",
                object.path
            )
            .into()
        })?;
        let (streamed_oid, streamed_type, streamed_size) =
            parse_cat_file_blob_stream_header(&object.path, header)?;
        if streamed_oid != object.object_oid || streamed_type != "blob" {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_INVALID: expected object {} blob for path {:?} (mode {}, source_size {}), got {header:?}",
                object.object_oid,
                object.path,
                object.object_mode,
                object.object_size
            )
            .into());
        }
        let path = checked_join_repo_path(checkout_root, &object.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_WRITE_DIR_FAILED: cannot create {}: {error}",
                    parent.display()
                )
                .into()
            })?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_WRITE_FAILED: cannot create {}: {error}",
                    path.display()
                )
                .into()
            })?;
        let mut remaining = streamed_size;
        while remaining > 0 {
            let cap = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            reader
                .read_exact(&mut buffer[..cap])
                .map_err(|error| -> DynError {
                    format!(
                        "ASTRO_ARCHAEOLOGY_CAT_FILE_BLOB_TRUNCATED: path {:?} expected {streamed_size} bytes: {error}",
                        object.path
                    )
                    .into()
                })?;
            file.write_all(&buffer[..cap])
                .map_err(|error| -> DynError {
                    format!(
                        "ASTRO_ARCHAEOLOGY_CAT_FILE_WRITE_FAILED: cannot write {}: {error}",
                        path.display()
                    )
                    .into()
                })?;
            remaining -= u64::try_from(cap).map_err(|_| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: chunk length cannot fit u64".into()
            })?;
        }
        let mut terminator = [0u8; 1];
        reader
            .read_exact(&mut terminator)
            .map_err(|error| -> DynError {
                format!(
                    "ASTRO_ARCHAEOLOGY_CAT_FILE_CONTENT_TERMINATOR_MISSING: path {:?}: {error}",
                    object.path
                )
                .into()
            })?;
        if terminator[0] != 0 {
            return Err(format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_CONTENT_TERMINATOR_INVALID: path {:?} terminator byte was {} not NUL",
                object.path, terminator[0]
            )
            .into());
        }
        stdout_bytes = stdout_bytes
            .checked_add(streamed_size)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| -> DynError {
                "ASTRO_ARCHAEOLOGY_CAT_FILE_TELEMETRY_OVERFLOW: stdout bytes overflowed".into()
            })?;
        files_materialized = files_materialized.checked_add(1).ok_or_else(|| -> DynError {
            "ASTRO_ARCHAEOLOGY_CAT_FILE_MATERIALIZED_OVERFLOW: materialized file count overflowed"
                .into()
        })?;
    }
    let mut trailing = Vec::new();
    reader
        .read_to_end(&mut trailing)
        .map_err(|error| -> DynError {
            format!("ASTRO_ARCHAEOLOGY_CAT_FILE_TRAILING_READ_FAILED: {error}").into()
        })?;
    if !trailing.is_empty() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_TRAILING_BYTES: historical content stream emitted {} unexpected trailing byte(s)",
            trailing.len()
        )
        .into());
    }
    Ok(FileScopedHistoricalBlobMaterialization {
        git_cat_file_processes: 0,
        stdout_bytes,
        files_materialized,
        paths_absent: 0,
        absent_paths: Vec::new(),
        dependency_files_materialized: 0,
        dependency_candidate_paths_absent: 0,
        dependency_edges: 0,
        dependency_revisits: 0,
        dependency_depth: 0,
        dependency_closure_sha256: String::new(),
    })
}

fn parse_cat_file_blob_stream_header<'a>(
    path: &str,
    header: &'a str,
) -> Result<(&'a str, &'a str, u64), DynError> {
    let mut fields = header.split(' ');
    let object_id = fields.next().unwrap_or_default();
    let object_type = fields.next().unwrap_or_default();
    let size = fields.next().unwrap_or_default();
    if fields.next().is_some() || !git_object_id_like(object_id) || object_type.is_empty() {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_HEADER_INVALID: path {path:?} returned malformed stream header {header:?}"
        )
        .into());
    }
    let size = size.parse::<u64>().map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_SIZE_INVALID: path {path:?} returned invalid stream size {size:?}: {error}"
        )
        .into()
    })?;
    Ok((object_id, object_type, size))
}

fn checked_join_repo_path(checkout_root: &Path, path: &str) -> Result<PathBuf, DynError> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains('\0')
        || path.starts_with('/')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_WRITE_PATH_INVALID: materialized path {path:?} is not normalized repo-relative"
        )
        .into());
    }
    Ok(path
        .split('/')
        .fold(checkout_root.to_path_buf(), |path, component| {
            path.join(component)
        }))
}

fn git_cat_file_with_stdin(
    repo: &Path,
    args: &[&str],
    input: &[u8],
    commit: &str,
    label: &str,
) -> Result<Vec<u8>, DynError> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.longpaths=true"])
        .args(args)
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| -> DynError {
            format!("ASTRO_ARCHAEOLOGY_CAT_FILE_SPAWN_FAILED: commit {commit} {label}: {error}")
                .into()
        })?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_CAT_FILE_STDIN_MISSING: commit {commit} {label} did not expose stdin"
            )
            .into()
        })?;
        stdin.write_all(input).map_err(|error| -> DynError {
            format!("ASTRO_ARCHAEOLOGY_CAT_FILE_STDIN_FAILED: commit {commit} {label}: {error}")
                .into()
        })?;
    }
    let output = child.wait_with_output().map_err(|error| -> DynError {
        format!("ASTRO_ARCHAEOLOGY_CAT_FILE_WAIT_FAILED: commit {commit} {label}: {error}").into()
    })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "ASTRO_ARCHAEOLOGY_CAT_FILE_FAILED: commit {commit} {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into())
    }
}

fn git_index_checked(repo: &Path, index: &Path, args: &[&str]) -> Result<(), DynError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.longpaths=true"])
        .args(args)
        .env("GIT_INDEX_FILE", index)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ASTRO_ARCHAEOLOGY_GIT_TEMP_INDEX_FAILED: command {:?}, index {}, error {}",
            args,
            index.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into())
    }
}

/// The requested corpus path relative to its git repository toplevel, forward-slash
/// normalized with no trailing slash (`git rev-parse --show-prefix`). Empty when the
/// corpus IS the toplevel. This is the corpus-scoping key (#403): archaeology mines
/// from the toplevel but must index and attribute only the requested subtree. Fails
/// closed with a structured error if `repo` is not inside a git work tree — never a
/// silent fallback to the enclosing repo.
fn git_show_prefix(repo: &Path) -> Result<String, DynError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--show-prefix"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse --show-prefix failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string())
}

/// The absolute path of the git toplevel that contains `repo` (`git rev-parse
/// --show-toplevel`), forward-slash normalized. For a subtree corpus this is the
/// ENCLOSING repository root (#434 provenance labeling), not the corpus dir. Fails
/// closed if `repo` is not inside a git work tree — never a silent fallback.
fn git_toplevel(repo: &Path) -> Result<String, DynError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse --show-toplevel failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .replace('\\', "/")
        .to_string())
}

fn select_implicated_rows(mut rows: CbmPipelineRows, evidence: &[Evidence]) -> CbmPipelineRows {
    rows.nodes.retain(|node| {
        !matches!(node.label.as_str(), "Project" | "Branch" | "Folder")
            && evidence.iter().any(|item| node_overlaps(node, &item.range))
    });
    rows.nodes.sort_by_key(|node| node.id);
    rows.nodes.dedup_by(|left, right| left.id == right.id);
    rows.edges.clear();
    rows.file_hashes.clear();
    rows.manifest = None;
    rows
}

fn node_overlaps(node: &CbmPipelineNodeRow, range: &GitLineRange) -> bool {
    normalized_path(&node.file_path) == normalized_path(&range.path)
        && node.start_line > 0
        && node.end_line >= node.start_line
        && (node.start_line as u64) <= range_end(range)
        && (node.end_line as u64) >= u64::from(range.start_line)
}

fn location_overlaps(location: &HistoricalSymbolLocation, range: &GitLineRange) -> bool {
    normalized_path(&location.file_path) == normalized_path(&range.path)
        && u64::from(location.start_line) <= range_end(range)
        && u64::from(location.end_line) >= u64::from(range.start_line)
}

fn range_end(range: &GitLineRange) -> u64 {
    u64::from(range.start_line)
        .saturating_add(u64::from(range.line_count))
        .saturating_sub(1)
}

fn normalized_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

fn historical_subject_id(location: &HistoricalSymbolLocation) -> String {
    format!(
        "{}:{}:{}:{}",
        normalized_path(&location.file_path),
        location.start_line,
        location.end_line,
        location.qualified_name
    )
}

pub(crate) fn git_archaeology_summary(report: &GitArchaeologyImportReport) -> Value {
    let mut summary = json!({
        "status": "imported",
        "mode": report.mode,
        "head": report.head,
        "evidence": report.evidence,
        "historical_constellations_written": report.historical_constellations_written,
        "historical_constellations_reused": report.historical_constellations_reused,
        "anchors_written": report.anchors_written,
        "anchors_deduplicated": report.anchors_deduplicated,
        "evidence_without_symbol": report.evidence_without_symbol,
        "skipped_merge_fixes": report.skipped_merge_fixes,
        "skipped_large_commits": report.skipped_large_commits,
        "skipped_unresolvable_reverts": report.skipped_unresolvable_reverts,
        // #514 labeled degradations: gitlink (submodule pointer) diff files excluded
        // from line mining, and blame targets absent at the blamed parent — both
        // counted here instead of aborting the whole pass repo-fatally (invariant 3).
        "skipped_gitlink_paths": report.skipped_gitlink_paths,
        "skipped_unblamable_paths": report.skipped_unblamable_paths,
        "cleanup_remnants": report.cleanup_remnants,
        // #502 labeled degradation: implicated committed filenames NTFS cannot represent,
        // excluded from the historical checkout and counted here instead of aborting the
        // whole pass repo-fatally (invariant 3: every skip counted, never silent).
        "historical_paths_windows_invalid": report.historical_paths_windows_invalid,
        // #515 fail-closed counter: successful persisted summaries must keep this at
        // zero. A nonzero value means the isolated CBM extraction child died on a
        // C-level pipeline fault; the host survives with structured evidence, but the
        // index-wide request aborts before publishing partial historical archaeology.
        "historical_commits_crashed": report.historical_commits_crashed,
        "historical_post_success_worker_recycles": report.historical_post_success_worker_recycles,
        "historical_post_success_cleanup_timeouts": report.historical_post_success_cleanup_timeouts,
        "trust": "mixed",
        "provenance": "git_history",
        // #434 provenance labeling: the discovered git root, whether it is the
        // corpus's OWN repo or an enclosing PARENT repo, and the toplevel-relative
        // subtree pathspec every history walk was limited to. Persisted with the
        // archaeology summary (config `git_archaeology_json`) so a consumer never
        // mistakes parent-repo-derived anchors for the corpus's own history, and can
        // see exactly which subtree of which repository they were mined from.
        "archaeology_source": report.archaeology_source,
        "git_root": report.git_root,
        "pathspec": report.pathspec,
    });
    let object = summary
        .as_object_mut()
        .expect("git archaeology summary literal is an object");
    macro_rules! insert_number {
        ($name:literal, $value:expr) => {
            object.insert($name.to_string(), Value::from($value));
        };
    }
    object.insert(
        "anchor_batch_registry_version".to_string(),
        Value::from(report.anchor_batch_registry_version),
    );
    insert_number!("anchor_batch_limit", report.anchor_batch_limit);
    insert_number!(
        "historical_batch_group_limit",
        report.historical_batch_group_limit
    );
    insert_number!(
        "historical_admission_groups",
        report.historical_admission_groups
    );
    insert_number!(
        "historical_admission_logical_entries",
        report.historical_admission_logical_entries
    );
    insert_number!(
        "historical_admission_atomic_commits",
        report.historical_admission_atomic_commits
    );
    insert_number!(
        "historical_admission_flushes",
        report.historical_admission_flushes
    );
    insert_number!(
        "historical_admission_max_window_groups",
        report.historical_admission_max_window_groups
    );
    insert_number!(
        "historical_admission_rows_written",
        report.historical_admission_rows_written
    );
    insert_number!(
        "historical_admission_ledger_refs_verified",
        report.historical_admission_ledger_refs_verified
    );
    insert_number!(
        "persistence_ledger_files_opened",
        report.persistence_ledger_files_opened
    );
    insert_number!(
        "persistence_ledger_complete_scan_wanted",
        report.persistence_ledger_complete_scan_wanted
    );
    insert_number!(
        "persistence_atomic_commits",
        report.persistence_atomic_commits
    );
    insert_number!("persistence_flushes", report.persistence_flushes);
    insert_number!(
        "persistence_durable_sst_files",
        report.persistence_durable_sst_files
    );
    insert_number!(
        "persistence_durable_sst_entries",
        report.persistence_durable_sst_entries
    );
    insert_number!(
        "persistence_durable_sst_bytes",
        report.persistence_durable_sst_bytes
    );
    insert_number!("anchor_logical_entries", report.anchor_logical_entries);
    insert_number!("anchor_atomic_commits", report.anchor_atomic_commits);
    insert_number!("anchor_flushes", report.anchor_flushes);
    insert_number!("anchor_max_batch_entries", report.anchor_max_batch_entries);
    insert_number!("anchor_rows_written", report.anchor_rows_written);
    insert_number!(
        "anchor_ledger_refs_verified",
        report.anchor_ledger_refs_verified
    );
    insert_number!("anchor_durable_sst_files", report.anchor_durable_sst_files);
    insert_number!(
        "anchor_durable_sst_entries",
        report.anchor_durable_sst_entries
    );
    insert_number!("anchor_durable_sst_bytes", report.anchor_durable_sst_bytes);
    insert_number!("anchor_router_sst_files", report.anchor_router_sst_files);
    insert_number!(
        "anchor_router_sst_entries",
        report.anchor_router_sst_entries
    );
    insert_number!("anchor_router_sst_bytes", report.anchor_router_sst_bytes);
    insert_number!(
        "anchor_router_handoff_full_inventories",
        report.anchor_router_handoff_full_inventories
    );
    insert_number!(
        "anchor_router_handoff_memtable_rows_verified",
        report.anchor_router_handoff_memtable_rows_verified
    );
    insert_number!(
        "anchor_router_handoff_flush_files_verified",
        report.anchor_router_handoff_flush_files_verified
    );
    insert_number!(
        "anchor_router_handoff_flush_entries_verified",
        report.anchor_router_handoff_flush_entries_verified
    );
    insert_number!(
        "anchor_router_handoff_flush_files_retired",
        report.anchor_router_handoff_flush_files_retired
    );
    insert_number!(
        "anchor_router_handoff_flush_bytes_retired",
        report.anchor_router_handoff_flush_bytes_retired
    );
    insert_number!(
        "anchor_router_handoff_debt_files_after",
        report.anchor_router_handoff_debt_files_after
    );
    insert_number!(
        "anchor_router_handoff_debt_bytes_after",
        report.anchor_router_handoff_debt_bytes_after
    );
    insert_number!("anchor_batch_wall_ms", report.anchor_batch_wall_ms);
    insert_number!("index_loop_wall_ms", report.index_loop_wall_ms);
    insert_number!(
        "diff_tree_count_requested_commits",
        report.diff_tree_count_requested_commits
    );
    insert_number!(
        "diff_tree_count_processes",
        report.diff_tree_count_processes
    );
    insert_number!(
        "diff_tree_count_processes_avoided",
        report.diff_tree_count_processes_avoided
    );
    insert_number!(
        "diff_tree_count_stdout_bytes",
        report.diff_tree_count_stdout_bytes
    );
    insert_number!(
        "diff_tree_ranges_requested_commits",
        report.diff_tree_ranges_requested_commits
    );
    insert_number!(
        "diff_tree_ranges_processes",
        report.diff_tree_ranges_processes
    );
    insert_number!(
        "diff_tree_ranges_processes_avoided",
        report.diff_tree_ranges_processes_avoided
    );
    insert_number!(
        "diff_tree_ranges_stdout_bytes",
        report.diff_tree_ranges_stdout_bytes
    );
    insert_number!("diff_tree_count_wall_ms", report.diff_tree_count_wall_ms);
    insert_number!("diff_tree_ranges_wall_ms", report.diff_tree_ranges_wall_ms);
    insert_number!(
        "diff_tree_batch_limit_commits",
        report.diff_tree_batch_limit_commits
    );
    insert_number!("blame_requested_ranges", report.blame_requested_ranges);
    insert_number!("blame_effective_ranges", report.blame_effective_ranges);
    insert_number!("blame_groups", report.blame_groups);
    insert_number!("blame_group_cache_hits", report.blame_group_cache_hits);
    insert_number!("blame_processes", report.blame_processes);
    insert_number!("blame_processes_avoided", report.blame_processes_avoided);
    insert_number!("blame_cat_file_processes", report.blame_cat_file_processes);
    insert_number!(
        "blame_cat_file_stdout_bytes",
        report.blame_cat_file_stdout_bytes
    );
    insert_number!("blame_path_absent_groups", report.blame_path_absent_groups);
    insert_number!("blame_returned_spans", report.blame_returned_spans);
    insert_number!("blame_returned_lines", report.blame_returned_lines);
    insert_number!("blame_stdout_bytes", report.blame_stdout_bytes);
    insert_number!("blame_wall_ms", report.blame_wall_ms);
    insert_number!("blame_cat_file_wall_ms", report.blame_cat_file_wall_ms);
    insert_number!(
        "historical_git_inventory_processes",
        report.historical_git_inventory_processes
    );
    insert_number!(
        "historical_git_checkout_processes",
        report.historical_git_checkout_processes
    );
    insert_number!(
        "historical_git_cat_file_processes",
        report.historical_git_cat_file_processes
    );
    insert_number!(
        "historical_git_cat_file_stdout_bytes",
        report.historical_git_cat_file_stdout_bytes
    );
    insert_number!(
        "historical_git_files_materialized",
        report.historical_git_files_materialized
    );
    insert_number!(
        "historical_dependency_files_materialized",
        report.historical_dependency_files_materialized
    );
    insert_number!(
        "historical_dependency_candidate_paths_absent",
        report.historical_dependency_candidate_paths_absent
    );
    insert_number!(
        "historical_dependency_edges",
        report.historical_dependency_edges
    );
    insert_number!(
        "historical_dependency_revisits",
        report.historical_dependency_revisits
    );
    insert_number!(
        "historical_dependency_max_depth",
        report.historical_dependency_max_depth
    );
    insert_number!(
        "historical_git_paths_absent",
        report.historical_git_paths_absent
    );
    insert_number!(
        "historical_git_source_files_materialized",
        report.historical_git_source_files_materialized
    );
    insert_number!(
        "historical_commits_without_materialized_source",
        report.historical_commits_without_materialized_source
    );
    insert_number!(
        "historical_git_object_probe_processes_avoided",
        report.historical_git_object_probe_processes_avoided
    );
    insert_number!(
        "historical_git_worktree_mutations_avoided",
        report.historical_git_worktree_mutations_avoided
    );
    let mut usage = serde_json::Map::new();
    usage.insert(
        "kernel_time_100ns".to_string(),
        Value::from(report.index_loop_usage.kernel_time_100ns),
    );
    usage.insert(
        "user_time_100ns".to_string(),
        Value::from(report.index_loop_usage.user_time_100ns),
    );
    usage.insert(
        "read_operations".to_string(),
        Value::from(report.index_loop_usage.read_operations),
    );
    usage.insert(
        "read_bytes".to_string(),
        Value::from(report.index_loop_usage.read_bytes),
    );
    usage.insert(
        "write_operations".to_string(),
        Value::from(report.index_loop_usage.write_operations),
    );
    usage.insert(
        "write_bytes".to_string(),
        Value::from(report.index_loop_usage.write_bytes),
    );
    usage.insert(
        "page_faults".to_string(),
        Value::from(report.index_loop_usage.page_faults),
    );
    usage.insert(
        "working_set_bytes_after".to_string(),
        Value::from(report.index_loop_usage.working_set_bytes_after),
    );
    usage.insert(
        "peak_working_set_bytes_after".to_string(),
        Value::from(report.index_loop_usage.peak_working_set_bytes_after),
    );
    usage.insert(
        "private_bytes_after".to_string(),
        Value::from(report.index_loop_usage.private_bytes_after),
    );
    usage.insert(
        "peak_private_bytes_after".to_string(),
        Value::from(report.index_loop_usage.peak_private_bytes_after),
    );
    object.insert("index_loop_usage".to_string(), Value::Object(usage));
    summary
}
