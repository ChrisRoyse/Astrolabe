use super::*;

use std::process::Command;

use astrolabe_anchors::archaeology::{
    GitArchaeologyConfig, GitLineRange, GitMineMode, mine_git_archaeology,
};
use astrolabe_anchors::{
    OutcomeAnchorRequest, OutcomeKind, OutcomeSubject, ingest_outcome_anchors,
};
use astrolabe_bridge::{CbmIndexMode, CbmPipeline, CbmPipelineNodeRow, CbmPipelineRows};
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
    /// Scratch worktrees / SQLite files that survived the bounded cleanup retry
    /// budget and were left on disk. Surfaced as a labeled count (invariant 3):
    /// a cleanup that cannot complete degrades to a counted remnant, never a
    /// silently swallowed `let _`.
    pub(crate) cleanup_remnants: usize,
}

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
    let config = GitArchaeologyConfig {
        member_prefix: (!corpus_rel.is_empty()).then(|| corpus_rel.clone()),
        ..GitArchaeologyConfig::default()
    };
    let mined = mine_git_archaeology(repo, &config, &mode)?;
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
    for removed in &mined.force_removed_commits {
        for range in astrolabe_anchors::archaeology::changed_new_ranges(repo, removed)? {
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

    let mut report = GitArchaeologyImportReport {
        head: mined.head,
        mode: mode_name,
        evidence: evidence.len(),
        skipped_merge_fixes: mined.skipped_merge_fixes,
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

    for (commit, group) in group_evidence_by_commit(&evidence) {
        let indexed = index_historical_commit(
            repo,
            cache_dir,
            &worktree_home,
            project,
            commit,
            &corpus_rel,
        )?;
        report.cleanup_remnants += indexed.cleanup_remnants;
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
    Ok(report)
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

/// Outcome of indexing one historical commit: the pipeline rows plus the count
/// of scratch paths that could not be removed after the bounded retry budget.
struct HistoricalCommitIndex {
    rows: CbmPipelineRows,
    cleanup_remnants: usize,
}

fn index_historical_commit(
    repo: &Path,
    cache_dir: &Path,
    worktree_home: &Path,
    project: &str,
    commit: &str,
    corpus_rel: &str,
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
    add_historical_worktree(repo, &worktree, commit, corpus_rel)?;
    let indexed = (|| -> Result<CbmPipelineRows, DynError> {
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
        // evidence_without_symbol) rather than letting CBM abort on a missing
        // root — the in-process abort would take the whole shadow import with it.
        if !scoped_root.exists() {
            return Ok(CbmPipelineRows {
                project: project.to_string(),
                nodes: Vec::new(),
                edges: Vec::new(),
            });
        }
        let mut pipeline = CbmPipeline::new(
            path_str(&scoped_root)?,
            path_str(&database)?,
            CbmIndexMode::Fast,
        )?;
        pipeline.set_project_name(project)?;
        let rows = pipeline.collect_rows()?;
        // Drop the pipeline (and with it CBM's SQLite handle) explicitly before
        // cleanup so the removals below race only Windows' async handle release,
        // which the bounded retry absorbs — not a still-open handle.
        drop(pipeline);
        // Keep historical node paths SUBTREE-relative — exactly as CBM emits them from
        // `scoped_root`, and byte-for-byte what the LIVE shadow import records as
        // `rel_file_path` when it indexes the member corpus directory directly (both go
        // through the same `extract_nodes` → `canonical_input_bytes` identity path). Because
        // `rel_file_path` is framed into the CxId, the historical and live conventions MUST
        // coincide or an unchanged member symbol can never share a CxId — the #403
        // re-anchoring UP to the toplevel namespace broke exactly this (#418). Attribution
        // still lines up because the mined evidence is re-anchored DOWN into this same
        // subtree-relative namespace in `run_git_archaeology`. The corpus_rel prefix lives
        // only on disk (the worktree checkout / `scoped_root`), never in identity-bearing
        // paths. Empty `corpus_rel` (toplevel corpus) never re-anchored either side, so that
        // #413 control path stays byte-identical.
        Ok(rows)
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
        (Ok(rows), Ok(())) => Ok(HistoricalCommitIndex {
            rows,
            cleanup_remnants,
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
        "cleanup_remnants": report.cleanup_remnants,
        "trust": "mixed",
        "provenance": "git_history",
    })
}
