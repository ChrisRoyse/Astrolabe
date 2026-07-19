use super::*;

use std::process::{Child, Command, Stdio};

use astrolabe_anchors::archaeology::{
    GitArchaeologyConfig, GitLineRange, GitMineMode, mine_git_archaeology,
};
use astrolabe_anchors::{
    OutcomeAnchorRequest, OutcomeKind, OutcomeSubject, ingest_outcome_anchors,
};
use astrolabe_bridge::{
    CbmIndexMode, CbmPipeline, CbmPipelineEdgeRow, CbmPipelineNodeRow, CbmPipelineRows,
};
// #502: share the clone farm's #480 Windows-invalid-path classifier so the historical
// checkout and the farm never disagree on what NTFS can hold.
use astrolabe_fleet::clone_farm::windows_invalid_path;
use astrolabe_ingest::{HistoricalSymbolLocation, admit_historical_symbol_snapshot};
use calyx_core::{AnchorKind, AnchorValue};

const ARCHAEOLOGY_ACTOR: &str = "astrolabe-git-archaeology";

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
/// is relocated to a short temp base ([`archaeology_worktree_home`], #427); only the
/// `\\?\`-safe scratch `.db` (SQLite, #412) stays under the store.
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

/// Directory-name prefix for the transient git-archaeology scratch WORKTREE, now
/// rooted under a short temp base ([`archaeology_worktree_home`]) rather than the
/// (possibly deep) CBM store dir (#427). The embedded owner PID is the sweep's
/// concurrency discriminator: [`sweep_orphan_worktrees`] removes a leftover
/// worktree only when its PID is dead, so a concurrent live archaeology pass is
/// never swept out from under itself. Unlike the scratch `.db`, this name carries
/// no C-side enumeration contract — it never lands in a CBM store dir.
const ARCHAEOLOGY_WORKTREE_PREFIX: &str = "astrolabe-archaeology-worktree-";

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
    // #434 phase-internal timing: opt-in via ASTRO_ARCH_TIMING, off by default so
    // production indexing is byte-for-byte unaffected. When set, the mine vs the
    // per-evidence-commit historical-reindex loop are timed separately (with counts)
    // so the 53.8s M-scale git_archaeology phase can be attributed to a real sub-phase
    // instead of guessed. Emitted once per pass, never per-row.
    let arch_timing = std::env::var_os("ASTRO_ARCH_TIMING").is_some();
    let mine_start = std::time::Instant::now();
    let config = GitArchaeologyConfig {
        member_prefix: (!corpus_rel.is_empty()).then(|| corpus_rel.clone()),
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
    let git_root = git_toplevel(repo)?;
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
        archaeology_source,
        git_root,
        pathspec,
        ..GitArchaeologyImportReport::default()
    };
    // Relocate archaeology scratch worktrees to a short temp base (#427): a deep
    // store dir would push the worktree root past the Windows `chdir` MAX_PATH cap
    // that `git -C <worktree> checkout` hits (`core.longpaths` does not cover
    // `chdir`). The scratch `.db` stays under the store dir (`\\?\`-safe, #412).
    let worktree_home = archaeology_worktree_home();
    fs::create_dir_all(&worktree_home).map_err(|error| -> DynError {
        format!(
            "ASTRO_ARCHAEOLOGY_WORKTREE_HOME_UNUSABLE: could not create the archaeology \
             scratch-worktree base {}: {error}; remediation: point TMP/TEMP at a writable, \
             short directory and re-run index_repository",
            worktree_home.display()
        )
        .into()
    })?;
    // Best-effort, PID-gated sweep of worktrees left at this shared home by a prior
    // pass that crashed before cleanup (invariant 3: counted telemetry, never a
    // silent skip). Only dead-PID orphans are removed, so a concurrently-running
    // pass — its own live PID stamped in the name — is never disturbed.
    sweep_orphan_worktrees(repo, &worktree_home);

    let file_scoped = historical_index_file_scoped();
    // #530 pooled historical-extraction worker: ONE persistent child serves the whole
    // index_loop over an atomic request/response file handshake, so the #515 per-commit
    // spawn+init cost (measured ~4.2 s/commit on rtk by wave-25) is paid once per recycle
    // interval instead of once per commit. The #515 containment contract is preserved —
    // a worker death/hang/malformed response is a counted, labeled
    // `historical_commits_crashed` skip on exactly the in-flight commit plus an automatic
    // respawn for the next, never a host exit. The worker is proactively recycled (killed
    // + respawned) every [`ARCHAEOLOGY_POOL_RECYCLE_AFTER_DEFAULT`] commits to bound the
    // cumulative C-heap damage of the #515 fault class to one interval.
    let mut pool = HistoricalExtractionPool::new()?;
    let index_loop_start = std::time::Instant::now();
    let mut index_calls = 0usize;
    let mut index_ms_total = 0u128;
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
        // #515: the isolated extraction child died on a C-level pipeline fault for
        // this commit's checkout. It is CONTAINED (the host process survives) instead
        // of the pre-#515 in-process fault that hard-exited the whole index_repository
        // with a silent empty-stdout rc=127. Count it, land this commit's evidence as
        // evidence_without_symbol, log a labeled line (invariant 3: never a silent
        // skip), and continue — the remaining commits and the kernel still complete.
        if let Some(detail) = indexed.crashed {
            report.historical_commits_crashed += 1;
            report.evidence_without_symbol += group.len();
            eprintln!(
                "astro.archaeology.historical_index_crashed commit={commit} \
                 evidence_in_group={} outcome=contained_child_fault detail={detail}",
                group.len()
            );
            continue;
        }
        let selected = select_implicated_rows(indexed.rows, group);
        if selected.nodes.is_empty() {
            report.evidence_without_symbol += group.len();
            continue;
        }
        let snapshot = pipeline_rows_to_graph_snapshot(selected);
        // Historical constellations dedup against the live shadow vault, so they must
        // be minted under the same roster version as the main shadow import
        // (SHADOW_PANEL_VERSION) — a v1/v2 mismatch would derive divergent CxIds and
        // defeat reuse (#336).
        let options = SqliteImportOptions::new(project, commit, SHADOW_PANEL_VERSION)
            .with_available_slots(shadow_available_slots());
        let admission =
            admit_historical_symbol_snapshot(&snapshot, vault, &ShadowSlotRuntime, &options)?;
        report.historical_constellations_written += admission.constellations_written;
        report.historical_constellations_reused += admission.constellations_reused;

        for item in group {
            let locations = admission
                .locations
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
            let anchored = ingest_outcome_anchors(vault, &request, &cx_ids, ARCHAEOLOGY_ACTOR)?;
            report.anchors_written += anchored.anchors_written;
            report.anchors_deduplicated += anchored.anchors_deduplicated;
        }
    }
    // #530: retire the pooled worker and its scratch dir. Idempotent with Drop, but
    // called explicitly here so the served/spawn telemetry lands inside the pass and any
    // dir remnant is counted before the report is finalized.
    report.cleanup_remnants += pool.finish();
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

/// #515 fail-closed ceiling for one isolated historical-commit extraction child.
/// File-scoped historical indexing (#439) materializes only the handful of files an
/// evidence group touches, so a single extraction is sub-second in practice; this
/// bound is not a tuned throughput knob but a hang guard — a child still running
/// after it is killed and reported as a contained fault rather than stalling the
/// whole import on an unbounded wait (invariant 3: the degradation is labeled/counted,
/// never a silent indefinite block).
const ARCHAEOLOGY_EXTRACT_TIMEOUT: Duration = Duration::from_secs(300);

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
/// rooted under the short temp base [`archaeology_pool_home`]. The embedded owner PID is
/// the sweep's concurrency discriminator: [`sweep_orphan_pools`] removes a leftover pool
/// dir only when its PID is dead, so a concurrent live archaeology pass is never swept
/// out from under itself.
const ARCHAEOLOGY_POOL_PREFIX: &str = "astrolabe-archaeology-pool-";

/// Short, collision-safe base directory for archaeology extraction pool dirs (#530),
/// deliberately OUTSIDE the CBM store dir (mirroring [`archaeology_worktree_home`], #427)
/// so a deep store never pushes the pool handshake files past the Windows MAX_PATH cap.
/// One shared temp subdirectory serves all owners; per-pool collision-safety comes from
/// the `<pid>-<nanos>` nonce, and cross-process safety from PID-gated orphan sweeping
/// ([`sweep_orphan_pools`]).
fn archaeology_pool_home() -> PathBuf {
    std::env::temp_dir().join("astrolabe-archaeology-pools")
}

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
/// `response-<seq>.json` (atomic). The #515 containment contract is PRESERVED:
///   * worker death mid-request (C-level fault) — detected via `try_wait` — is a
///     [`HistoricalExtract::Crashed`] on exactly the in-flight commit plus an automatic
///     respawn; the host never dies;
///   * a worker that does not answer within [`ARCHAEOLOGY_EXTRACT_TIMEOUT`] is killed as
///     hung and treated the same way;
///   * a RECOVERABLE Rust-level pipeline error is answered as a structured
///     `{ok:false,error}` response so the warm worker survives it, while the commit is
///     still counted as a contained fault (identical accounting to the pre-#530
///     nonzero-exit child).
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
}

impl HistoricalExtractionPool {
    /// Creates the pool (its nonce'd scratch dir) but does NOT spawn a worker yet — the
    /// first [`extract`](Self::extract) spawns lazily, so a pass with zero evidence
    /// commits never pays a spawn. Sweeps dead-PID orphan pool dirs first (#530), the
    /// same PID-gated discipline the scratch worktrees use (#427).
    fn new() -> Result<Self, DynError> {
        let exe = std::env::current_exe().map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_POOL_EXE_UNRESOLVED: could not resolve the running astrolabe \
                 executable to spawn the pooled historical-index worker: {error}; remediation: \
                 this is an internal invariant of index_repository — retry the run"
            )
            .into()
        })?;
        let home = archaeology_pool_home();
        fs::create_dir_all(&home).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_POOL_HOME_UNUSABLE: could not create the archaeology \
                 extraction-pool base {}: {error}; remediation: point TMP/TEMP at a writable, \
                 short directory and re-run index_repository",
                home.display()
            )
            .into()
        })?;
        sweep_orphan_pools(&home);
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let pool_dir = home.join(format!("{ARCHAEOLOGY_POOL_PREFIX}{nonce}"));
        fs::create_dir_all(&pool_dir).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_POOL_DIR_UNUSABLE: could not create the archaeology \
                 extraction-pool dir {}: {error}; remediation: point TMP/TEMP at a writable \
                 directory and re-run index_repository",
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
                 {error}; remediation: point TMP/TEMP at a writable directory and re-run",
                self.log_path.display()
            )
            .into()
        })?;
        let log_clone = log.try_clone()?;
        let spawn_start = Instant::now();
        let child = Command::new(&self.exe)
            .args(["cli", "--archaeology-extract-serve", "--pool-dir"])
            .arg(&self.pool_dir)
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

    /// Runs one historical commit's CBM extraction on the pooled worker (#530). Spawns or
    /// recycles the worker as needed, writes the request atomically, then waits for the
    /// response file, the worker's death, or the per-extraction timeout — whichever comes
    /// first. Returns [`HistoricalExtract::Rows`] on a clean extraction, or
    /// [`HistoricalExtract::Crashed`] (a contained, labeled, counted fault) on a worker
    /// death / hang / recoverable pipeline error / malformed response, exactly matching
    /// the pre-#530 per-commit child's accounting. `scoped_root`/`database` are absolute
    /// scratch paths; the worker resolves them itself.
    fn extract(
        &mut self,
        scoped_root: &Path,
        database: &Path,
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
        // A stale response from a prior seq collision cannot exist (files are removed per
        // request and on spawn), but remove defensively so `exists()` below is unambiguous.
        let _ = fs::remove_file(&response_path);
        let request = json!({
            "scoped_root": path_str(scoped_root)?,
            "database": path_str(database)?,
            "project": project,
            "mode": "fast",
        });
        // Atomic appearance for the worker: write the temp, then rename into place, so the
        // worker never reads a half-written request.
        fs::write(&request_tmp, serde_json::to_vec(&request)?)?;
        fs::rename(&request_tmp, &request_path)?;

        let deadline = Instant::now() + ARCHAEOLOGY_EXTRACT_TIMEOUT;
        // `(outcome, worker_survived)`: only a surviving worker advances `seq`/`served`.
        let (outcome, worker_survived): (HistoricalExtract, bool) = loop {
            if response_path.exists() {
                match fs::read(&response_path) {
                    Ok(bytes) => match interpret_pool_response(&bytes, project) {
                        PoolResponse::Rows(rows) => break (HistoricalExtract::Rows(rows), true),
                        PoolResponse::RecoverableError(message) => {
                            break (
                                HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                                    commit,
                                    None,
                                    &self.log_path,
                                    &format!(
                                        "the pooled worker reported a recoverable pipeline error \
                                         and stayed warm: {message}"
                                    ),
                                )),
                                true,
                            );
                        }
                        PoolResponse::Malformed(detail) => {
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
                    self.child = None;
                    break (
                        HistoricalExtract::Crashed(archaeology_extract_fault_detail(
                            commit,
                            status.code(),
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
        // harmless).
        let _ = fs::remove_file(&request_path);
        let _ = fs::remove_file(&response_path);
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
            let start = chars.len().saturating_sub(600);
            chars[start..].iter().collect::<String>()
        })
        .unwrap_or_else(|_| "<child stderr unreadable>".to_string());
    format!(
        "ASTRO_ARCHAEOLOGY_HISTORICAL_INDEX_CRASHED commit={commit} exit={exit} \
         phase=git_archaeology.historical_reindex reason=\"{reason}\" \
         remediation=\"the fault was contained in the isolated extraction child; the host \
         index_repository completed and this commit is counted in historical_commits_crashed; \
         inspect the child stderr tail to find the offending input\" stderr_tail=<<{stderr_tail}>>"
    )
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
    scoped_root: &str,
    database: &str,
    project: &str,
    mode: CbmIndexMode,
) -> Result<CbmPipelineRows, DynError> {
    let mut pipeline = CbmPipeline::new(scoped_root, database, mode)?;
    pipeline.set_project_name(project)?;
    let rows = pipeline.collect_rows()?;
    drop(pipeline);
    Ok(rows)
}

/// Builds one pooled serve-worker response (#530) for a decoded request `Value`. A clean
/// extraction yields the `{ok:true, project, nodes, edges}` rows envelope; a request
/// missing a required field, or a RECOVERABLE Rust-level pipeline error, yields a
/// structured `{ok:false, error}` envelope so the WARM worker can report it without
/// dying (the parent then counts that commit as a contained fault, identical accounting
/// to the pre-#530 nonzero-exit child).
fn build_serve_response(request: &Value) -> Value {
    let field = |key: &str| request.get(key).and_then(Value::as_str);
    let (scoped_root, database, project) =
        match (field("scoped_root"), field("database"), field("project")) {
            (Some(scoped_root), Some(database), Some(project)) => (scoped_root, database, project),
            _ => {
                return json!({
                    "ok": false,
                    "error": "archaeology_extract_error: request missing required string field \
                              (scoped_root/database/project)",
                });
            }
        };
    let mode = match request.get("mode").and_then(Value::as_str) {
        Some("full") => CbmIndexMode::Full,
        Some("moderate") => CbmIndexMode::Moderate,
        // Historical re-index is always Fast; anything else (incl. absent) maps to it.
        _ => CbmIndexMode::Fast,
    };
    match extract_rows_once(scoped_root, database, project, mode) {
        Ok(rows) => {
            let mut envelope = serialize_pipeline_rows(&rows);
            if let Value::Object(map) = &mut envelope {
                map.insert("ok".to_string(), Value::Bool(true));
            }
            envelope
        }
        Err(error) => json!({
            "ok": false,
            "error": format!("archaeology_extract_error: {error}"),
        }),
    }
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
        let request: Value = serde_json::from_slice(&bytes).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHAEOLOGY_SERVE_REQUEST_INVALID: pooled request {} is not valid JSON: \
                 {error}",
                request_path.display()
            )
            .into()
        })?;
        if request.get("stop").and_then(Value::as_bool) == Some(true) {
            let _ = fs::remove_file(&request_path);
            return Ok(0);
        }
        let response = build_serve_response(&request);
        let response_path = pool_dir.join(format!("response-{seq}.json"));
        let response_tmp = pool_dir.join(format!("response-{seq}.json.tmp"));
        fs::write(&response_tmp, serde_json::to_vec(&response)?)?;
        // Atomic appearance for the parent: the parent never reads a half-written response.
        fs::rename(&response_tmp, &response_path)?;
        // Drop the consumed request so the dir does not grow unbounded (the parent also
        // removes it; double-remove is harmless).
        let _ = fs::remove_file(&request_path);
        seq += 1;
    }
}

/// Serializes [`CbmPipelineRows`] to the isolated-extraction wire JSON. Manual
/// `json!` construction (no serde derive dependency) over the flat, string/i64-only
/// row fields — the child writes it, [`parse_extract_response`] reads it, and both
/// preserve every field verbatim so the isolated path is byte-parity with the old
/// in-process rows.
fn serialize_pipeline_rows(rows: &CbmPipelineRows) -> Value {
    json!({
        "project": rows.project,
        "nodes": rows.nodes.iter().map(|n| json!({
            "id": n.id,
            "project": n.project,
            "label": n.label,
            "name": n.name,
            "qualified_name": n.qualified_name,
            "file_path": n.file_path,
            "start_line": n.start_line,
            "end_line": n.end_line,
            "properties_json": n.properties_json,
        })).collect::<Vec<_>>(),
        "edges": rows.edges.iter().map(|e| json!({
            "id": e.id,
            "project": e.project,
            "source_id": e.source_id,
            "target_id": e.target_id,
            "edge_type": e.edge_type,
            "properties_json": e.properties_json,
            "url_path_gen": e.url_path_gen,
            "local_name_gen": e.local_name_gen,
        })).collect::<Vec<_>>(),
    })
}

/// Reconstructs [`CbmPipelineRows`] from the isolated-extraction child's response
/// bytes (#515). A missing/mistyped field fails closed with a labeled `Err(String)`
/// so a truncated or malformed response is reported as a contained fault, never
/// silently treated as "no rows".
fn parse_extract_response(bytes: &[u8], project: &str) -> Result<CbmPipelineRows, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("response JSON parse: {error}"))?;
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
    Ok(CbmPipelineRows {
        project: value["project"].as_str().unwrap_or(project).to_string(),
        nodes,
        edges,
    })
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
    Ok(CbmPipelineNodeRow {
        id: i64_field("id")?,
        project: str_field("project")?,
        label: str_field("label")?,
        name: str_field("name")?,
        qualified_name: str_field("qualified_name")?,
        file_path: str_field("file_path")?,
        start_line: i64_field("start_line")?,
        end_line: i64_field("end_line")?,
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
    /// #515: `Some(detail)` when the isolated CBM extraction child died without
    /// producing rows (a contained C-level pipeline fault on this commit). The
    /// caller counts it, lands the evidence as `evidence_without_symbol`, and
    /// continues rather than the pre-#515 in-process fault killing the whole host.
    /// `None` on a clean extraction (`rows` carries the real result).
    crashed: Option<String>,
}

/// Outcome of the pooled historical CBM extraction ([`HistoricalExtractionPool::extract`]):
/// either the extracted pipeline rows, or a contained worker fault carrying the
/// structured detail (exit code + worker-log tail) for the labeled skip.
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
    // Worktree at the short temp home (#427); the `.db` scratch store stays under
    // the store dir where the C enumerator's reserved-prefix filter can see it.
    let worktree = worktree_home.join(format!("{ARCHAEOLOGY_WORKTREE_PREFIX}{nonce}"));
    let worktree_len = worktree.as_os_str().len();
    if worktree_len > ARCHAEOLOGY_WORKTREE_CWD_BUDGET {
        return Err(format!(
            "ASTRO_ARCHAEOLOGY_WORKTREE_BASE_TOO_DEEP: archaeology scratch-worktree root {root} is \
             {worktree_len} bytes, over the {ARCHAEOLOGY_WORKTREE_CWD_BUDGET}-byte budget that \
             keeps git's chdir into the worktree under the Windows MAX_PATH (260) cap (no \\\\?\\ \
             form or git config lifts the chdir limit); remediation: point TMP/TEMP at a shorter \
             directory (e.g. C:\\t) so the archaeology temp base is short, then re-run \
             index_repository",
            root = worktree.display(),
        )
        .into());
    }
    let database = cache_dir.join(format!("{ARCHAEOLOGY_DB_PREFIX}{nonce}.db"));
    // #439: materialize ONLY the implicated files (file-scoped) or the whole member
    // subtree (pre-#439). Both leave `scoped_root` (below) at the same base, so CBM
    // emits byte-identical subtree-relative node paths in either mode.
    // #502: the file-scoped path filters out committed filenames NTFS cannot represent
    // and returns how many it excluded at this commit; the whole-subtree path materializes
    // a full checkout git already validated, so it excludes none.
    let windows_invalid_excluded = if file_scoped {
        add_historical_worktree_files(repo, &worktree, commit, corpus_rel, implicated_files)?
    } else {
        add_historical_worktree(repo, &worktree, commit, corpus_rel)?;
        0
    };
    let indexed = (|| -> Result<HistoricalExtract, DynError> {
        // Scope the historical index to the requested corpus subtree within the
        // whole-repo worktree (#403). A git worktree is always the full repository
        // tree, so indexing `worktree` itself walked the entire enclosing
        // workspace — the spurious wrong-corpus pass. `worktree.join(corpus_rel)`
        // restricts CBM discovery to exactly the requested corpus; an empty
        // `corpus_rel` (corpus IS the toplevel) leaves this behavior-neutral.
        let scoped_root = if corpus_rel.is_empty() {
            worktree.clone()
        } else {
            worktree.join(corpus_rel)
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
        // `HistoricalExtract::Crashed`, the host survives, and the caller degrades this
        // one commit (labeled, counted) instead of the whole index dying silently.
        pool.extract(&scoped_root, &database, project, commit)
    })();
    // Ask git to release and remove its worktree registration first; retries below
    // sweep any file/dir it leaves behind under Windows handle latency.
    let cleanup = git_checked(
        repo,
        &[
            "-c",
            "core.longpaths=true",
            "worktree",
            "remove",
            "--force",
            path_str(&worktree)?,
        ],
    );
    let mut cleanup_remnants = cleanup_archaeology_database(&database);
    if !remove_path_with_retry(&worktree, |path| fs::remove_dir_all(path)) {
        cleanup_remnants += 1;
    }
    match (indexed, cleanup) {
        (Ok(HistoricalExtract::Rows(rows)), Ok(())) => Ok(HistoricalCommitIndex {
            rows,
            cleanup_remnants,
            windows_invalid_excluded,
            crashed: None,
        }),
        // #515 contained child fault: the extraction child died without rows. Report
        // it as a labeled skip (the caller counts it and continues); the host lives.
        // Any cleanup error is subsumed — the child already released its handles when
        // it died, and the crash detail is the headline, remnants counted separately.
        (Ok(HistoricalExtract::Crashed(detail)), _) => Ok(HistoricalCommitIndex {
            rows: CbmPipelineRows {
                project: project.to_string(),
                nodes: Vec::new(),
                edges: Vec::new(),
            },
            cleanup_remnants,
            windows_invalid_excluded,
            crashed: Some(detail),
        }),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
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

/// Short, collision-safe base directory for archaeology scratch worktrees,
/// deliberately OUTSIDE the CBM store dir so a deep store never pushes the
/// worktree root past the Windows `chdir` MAX_PATH cap (#427). One shared temp
/// subdirectory serves all owners; per-worktree collision-safety comes from the
/// `<pid>-<nanos>` nonce, and cross-process safety from PID-gated orphan sweeping
/// ([`sweep_orphan_worktrees`]). Exactly ONE home is chosen — no store-dir-then-temp
/// fallback chain (issue #427: pick one home for the worktree). `std::env::temp_dir`
/// is normally short (`%LOCALAPPDATA%\Temp`) but not guaranteed so; the per-commit
/// [`ARCHAEOLOGY_WORKTREE_CWD_BUDGET`] guard fails closed if this base is itself deep.
fn archaeology_worktree_home() -> PathBuf {
    std::env::temp_dir().join("astrolabe-archaeology-worktrees")
}

/// Best-effort sweep of archaeology scratch worktrees left at the shared temp
/// home by a prior pass that crashed between `git worktree add` and cleanup (#427).
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

/// Adds the scratch worktree that materializes a historical commit for indexing.
///
/// Whole-repo corpus (`corpus_rel` empty): the pre-#381 full detached checkout —
/// byte-identical control behavior, the whole historical toplevel tree on disk.
///
/// Monorepo-member corpus (#381): materialize ONLY the member subtree, not the full
/// historical toplevel tree (for `cbm/` that is ~5,500 files per evidence commit).
/// Add the worktree with `--no-checkout` (index only, no working files), then
/// `checkout <commit> -- <corpus_rel>` restores exactly the member subtree from the
/// commit's tree. Nothing else lands on disk — not even repo-root files — and, unlike
/// `sparse-checkout init` (which force-enables `extensions.worktreeConfig` in the
/// enclosing repo's SHARED `.git/config`), no per-worktree sparse state is written, so
/// the canonical repo config is never mutated. `core.longpaths=true` guards every
/// tree-touching call: even joined to the short temp worktree base (#427), deep
/// member file paths still exceed the Windows 260-char limit for git's file I/O
/// (the worktree ROOT is separately kept under the `chdir` cap by
/// [`ARCHAEOLOGY_WORKTREE_CWD_BUDGET`], which `core.longpaths` cannot reach).
///
/// The member subtree may be absent at this historical commit (created or renamed
/// later); it is probed with [`git_tree_has_path`] first and only checked out when
/// present, so a "pathspec did not match" never aborts the import. The absent case
/// materializes nothing, and `index_historical_commit`'s `scoped_root.exists()` gate
/// then yields zero rows (counted as `evidence_without_symbol` upstream).
fn add_historical_worktree(
    repo: &Path,
    worktree: &Path,
    commit: &str,
    corpus_rel: &str,
) -> Result<(), DynError> {
    if corpus_rel.is_empty() {
        git_checked(
            repo,
            &[
                "-c",
                "core.longpaths=true",
                "worktree",
                "add",
                "--detach",
                path_str(worktree)?,
                commit,
            ],
        )?;
        return Ok(());
    }
    git_checked(
        repo,
        &[
            "-c",
            "core.longpaths=true",
            "worktree",
            "add",
            "--no-checkout",
            "--detach",
            path_str(worktree)?,
            commit,
        ],
    )?;
    if git_tree_has_path(repo, commit, corpus_rel)? {
        git_checked(
            worktree,
            &[
                "-c",
                "core.longpaths=true",
                "checkout",
                commit,
                "--",
                corpus_rel,
            ],
        )?;
    }
    Ok(())
}

/// Adds a scratch worktree that materializes ONLY the implicated files of one
/// evidence commit (#439 file-scoped historical index), instead of the whole member
/// subtree.
///
/// `implicated_files` are the DISTINCT subtree-relative paths the evidence group hits
/// (already stripped of the corpus prefix and, via the `run_git_archaeology` retain,
/// confined to the corpus). Each is rejoined to `corpus_rel` to form the toplevel
/// pathspec git checks out; an empty `corpus_rel` (corpus IS the toplevel) uses the
/// path as-is. The worktree is added `--no-checkout` (index only, no working files),
/// then a SINGLE `checkout <commit> -- <present files…>` materializes exactly those
/// files at their real subtree-relative locations under `worktree/<corpus_rel>` — so
/// `scoped_root` (in [`index_historical_commit`]) and every emitted node path are
/// byte-identical to the whole-subtree mode; only the non-implicated files CBM would
/// parse and then discard are absent.
///
/// A pathspec that would escape the corpus is skipped defensively (the retain upstream
/// already guarantees in-corpus paths; this never silently materializes out-of-corpus
/// files). An implicated file ABSENT at this commit (deleted/created later, or the
/// subtree itself absent) is filtered by [`git_tree_has_path`] before checkout, so a
/// "pathspec did not match" never aborts the pass — the file simply is not materialized
/// and its evidence lands as `evidence_without_symbol`, exactly as whole-subtree mode
/// (which indexes the subtree without that file). When no implicated file is present
/// at the commit, nothing is checked out and `scoped_root.exists()` is false, yielding
/// zero rows — the same graceful zero-evidence outcome as an absent subtree.
///
/// A committed filename NTFS cannot represent — control bytes, reserved characters
/// (`: < > " | ? *`), reserved device names, trailing dot/space (exactly the class
/// [`astrolabe_fleet::clone_farm::windows_invalid_path`] detects, shared with the
/// clone farm's #480 checkout classifier) — can never be checked out on Windows: a
/// batched `git checkout` that includes it dies with `error: invalid path`, which
/// before #502 aborted the whole historical-index pass (repo-fatal). Such paths are
/// filtered out here and returned as a LABELED, COUNTED exclusion (invariant 3), never
/// a quarantine and never a silent drop: the excluded file simply is not materialized,
/// its evidence lands as `evidence_without_symbol` upstream exactly as an absent file,
/// and the remaining representable implicated files still check out and mine normally.
/// A genuine `git checkout` failure on a REPRESENTABLE path stays fail-closed.
///
/// Returns the number of implicated paths excluded as Windows-invalid at this commit.
fn add_historical_worktree_files(
    repo: &Path,
    worktree: &Path,
    commit: &str,
    corpus_rel: &str,
    implicated_files: &BTreeSet<String>,
) -> Result<usize, DynError> {
    git_checked(
        repo,
        &[
            "-c",
            "core.longpaths=true",
            "worktree",
            "add",
            "--no-checkout",
            "--detach",
            path_str(worktree)?,
            commit,
        ],
    )?;
    // Build the toplevel pathspec for each implicated file, dropping any that would
    // escape the corpus, any NTFS cannot represent (#502), and any not present in this
    // commit's tree.
    let mut present: Vec<String> = Vec::new();
    let mut windows_invalid_excluded = 0usize;
    for rel in implicated_files {
        let toplevel_path = if corpus_rel.is_empty() {
            rel.clone()
        } else {
            format!("{corpus_rel}/{rel}")
        };
        // Defense-in-depth: never let a `..`/absolute/empty path escape the corpus into
        // the enclosing worktree. The upstream retain already scopes evidence to the
        // corpus, so this only ever drops a malformed residue — counted by absence, not
        // silently indexed.
        if toplevel_path.is_empty()
            || toplevel_path.starts_with('/')
            || toplevel_path.split('/').any(|component| component == "..")
        {
            continue;
        }
        // #502: a committed filename NTFS cannot represent can never materialize on this
        // host, so a `git checkout` that names it aborts the entire pass. Exclude it as a
        // labeled, counted degradation (never a repo-fatal abort, never a quarantine); the
        // dropped file's evidence lands as `evidence_without_symbol` upstream, matching the
        // absent-file path. This mirrors the clone farm's #480 tree classifier, sharing the
        // exact same predicate so the two never disagree on what Windows can hold.
        if let Some(reason) = windows_invalid_path(toplevel_path.as_bytes()) {
            eprintln!(
                "astro.archaeology.windows_invalid_path commit={commit} path={toplevel_path:?} \
                 reason={reason}"
            );
            windows_invalid_excluded += 1;
            continue;
        }
        if git_tree_has_path(repo, commit, &toplevel_path)? {
            present.push(toplevel_path);
        }
    }
    if present.is_empty() {
        // No representable implicated file exists at this commit: materialize nothing. The
        // caller's `scoped_root.exists()` gate then yields zero rows (evidence_without_symbol),
        // matching the absent-subtree path — never an aborting empty checkout. Any
        // Windows-invalid exclusions are still surfaced through the returned count.
        return Ok(windows_invalid_excluded);
    }
    // One batched checkout of exactly the present implicated files. All pathspecs are
    // pre-filtered to exist and to be Windows-representable, so git never errors on an
    // unmatched pathspec or an invalid path.
    let mut args: Vec<&str> = vec!["-c", "core.longpaths=true", "checkout", commit, "--"];
    for path in &present {
        args.push(path.as_str());
    }
    git_checked(worktree, &args)?;
    Ok(windows_invalid_excluded)
}

/// Whether `commit`'s tree contains `path` (a toplevel-relative directory or file).
/// Uses `git cat-file -e <commit>:<path>`, which exits zero iff the object exists; a
/// missing path exits non-zero — not an error here, since an absent member subtree at
/// a historical commit is an expected, gracefully-handled case (the caller then skips
/// materialization). Only a genuine spawn failure propagates.
fn git_tree_has_path(repo: &Path, commit: &str, path: &str) -> Result<bool, DynError> {
    let spec = format!("{commit}:{path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &spec])
        .stderr(std::process::Stdio::null())
        .output()?;
    Ok(output.status.success())
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
    json!({
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
        // #515 labeled degradation: historical evidence commits whose isolated CBM
        // extraction child died on a C-level pipeline fault. Contained (the host
        // survives with a structured result) instead of the pre-#515 silent rc=127
        // host hard-exit; the commit's evidence lands as evidence_without_symbol.
        "historical_commits_crashed": report.historical_commits_crashed,
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
    })
}
