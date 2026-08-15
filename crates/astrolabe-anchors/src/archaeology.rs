//! Shell-free Git archaeology mining for bug-touch and revert anchors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

/// Stable failure code for invalid archaeology configuration.
pub const ASTRO_ARCHAEOLOGY_CONFIG_INVALID: &str = "ASTRO_ARCHAEOLOGY_CONFIG_INVALID";
/// Stable failure code for a failed or malformed Git query.
pub const ASTRO_ARCHAEOLOGY_GIT_FAILED: &str = "ASTRO_ARCHAEOLOGY_GIT_FAILED";
/// Stable failure code for Git output that cannot be interpreted safely.
pub const ASTRO_ARCHAEOLOGY_OUTPUT_INVALID: &str = "ASTRO_ARCHAEOLOGY_OUTPUT_INVALID";
/// Stable failure code for a disagreement between an old-side diff range and
/// the immutable parent tree that range was derived from.
pub const ASTRO_ARCHAEOLOGY_OBJECT_VIEW_INCONSISTENT: &str =
    "ASTRO_ARCHAEOLOGY_OBJECT_VIEW_INCONSISTENT";
/// Stable failure code for a requested history operation that contradicts the
/// repository's measured history state.
pub const ASTRO_ARCHAEOLOGY_HISTORY_STATE_INVALID: &str = "ASTRO_ARCHAEOLOGY_HISTORY_STATE_INVALID";

const REMEDIATION: &str =
    "verify the repository and Git objects, then rerun archaeology with a validated configuration";
const BLAME_CAT_FILE_BATCH_GROUPS: usize = 4096;

/// Configurable, bounded Git-history policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitArchaeologyConfig {
    /// Case-insensitive whole-word tokens that identify likely fixes.
    pub fix_keywords: Vec<String>,
    /// Case-insensitive message prefixes that identify issue-closing fixes.
    pub issue_markers: Vec<String>,
    /// Git date expression for a full pass.
    pub since: String,
    /// Maximum commits considered per pass.
    pub max_count: usize,
    /// Optional toplevel-relative member prefix (forward-slash normalized, no
    /// leading or trailing slash) that pathspec-limits ALL history mining to a
    /// monorepo-member subtree (#381) — e.g. `cbm` when the corpus is `cbm/`
    /// inside the enclosing Astrolabe repo. `None` mines the whole repository
    /// (the corpus IS the git toplevel): the control path, byte-identical to
    /// pre-#381 behavior. `Some(prefix)` appends `-- <prefix>` to every
    /// `git log`/`git diff`/`rev-list` walk so out-of-subtree commits and ranges
    /// never enter the evidence set at the source, rather than being mined across
    /// the whole monorepo and filtered afterward.
    pub member_prefix: Option<String>,
    /// Changed-file cap per fix/revert commit above which the commit is treated as
    /// a MASS-CHANGE (relocation, bulk rename, mass reformat, tree deletion) and
    /// EXCLUDED from SZZ line-range mining — labeled and counted, never silent
    /// (#434, invariant 3/4).
    ///
    /// MEASURED lever (#434): on the full `cbm/` corpus the git_archaeology phase
    /// (53.8s of 156.3s at M scale, #422) was dominated by ONE fix-classified
    /// mass-change commit — the #286 `vendor/cbm` → `cbm` relocation (1821 changed
    /// files in the subtree). Its `git diff --unified=0 … -- cbm` emits a ~600k-line
    /// diff that costs ~38s to generate and parse, yet yields ZERO SZZ findings: the
    /// relocation is pure additions in `cbm/`, so every hunk's OLD side is
    /// `/dev/null` and no blamable parent range exists. SZZ bug-origin blame on a
    /// mass-change is meaningless by construction (a 1000-file move is not a targeted
    /// bug fix); excluding it is a signal improvement, not a loss. A cheap
    /// `git diff --name-only` pre-count gates the expensive content diff so the mine
    /// never pays the mass-change cost.
    ///
    /// Default 256: two orders of magnitude above any targeted bug fix observed on
    /// the corpus (genuine fixes touch a handful of files) and below every
    /// mass-change (relocation 1821), so it cleanly separates the two. It echoes the
    /// changed-path threshold Git's own changed-path Bloom-filter design uses to mark
    /// a commit "too large" (Azure DevOps VSTS: 512 changed paths). `0` disables the
    /// cap (mine every commit regardless of size — the pre-#434 behavior).
    pub max_commit_changed_files: usize,
    /// Registry-declared number of commits fed to one `git diff-tree --stdin`
    /// child for mine-side changed-file counts and unified diff generation (#858).
    ///
    /// This is a process/memory bound, not an accuracy tradeoff: every commit is
    /// still diffed by Git with the same pathspec and the same unified-diff parser,
    /// but process startup is amortized across the batch and the parser fails closed
    /// if any commit header or raw record is missing/malformed.
    pub diff_tree_batch_commits: usize,
}

/// Registry-declared default for [`GitArchaeologyConfig::max_commit_changed_files`]
/// (#434). See that field's docs for the measured rationale.
pub const DEFAULT_MAX_COMMIT_CHANGED_FILES: usize = 256;

impl Default for GitArchaeologyConfig {
    fn default() -> Self {
        Self {
            fix_keywords: vec!["fix", "bug", "hotfix", "patch"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            issue_markers: vec!["closes #".to_string(), "fixes #".to_string()],
            since: "1 year ago".to_string(),
            max_count: 10_000,
            member_prefix: None,
            max_commit_changed_files: DEFAULT_MAX_COMMIT_CHANGED_FILES,
            diff_tree_batch_commits: usize::try_from(
                astrolabe_domain::knobs::ARCHAEOLOGY_DEFAULT_DIFF_TREE_BATCH_COMMITS,
            )
            .expect("diff-tree batch default fits usize"),
        }
    }
}

impl GitArchaeologyConfig {
    /// Refuses empty, unbounded, or structurally unsafe configuration.
    pub fn validate(&self) -> Result<(), ArchaeologyError> {
        if self.fix_keywords.is_empty()
            || self.max_count == 0
            || self.max_count > 100_000
            || self.since.trim().is_empty()
            || self
                .fix_keywords
                .iter()
                .any(|value| value.trim().is_empty() || !value.is_ascii())
            || self
                .issue_markers
                .iter()
                .any(|value| value.trim().is_empty() || !value.is_ascii())
            || self.diff_tree_batch_commits
                < usize::try_from(astrolabe_domain::knobs::ARCHAEOLOGY_MIN_DIFF_TREE_BATCH_COMMITS)
                    .expect("diff-tree batch min fits usize")
            || self.diff_tree_batch_commits
                > usize::try_from(astrolabe_domain::knobs::ARCHAEOLOGY_MAX_DIFF_TREE_BATCH_COMMITS)
                    .expect("diff-tree batch max fits usize")
        {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_CONFIG_INVALID,
                "Git archaeology configuration is empty, unbounded, non-ASCII, or outside the diff-tree batch registry",
            ));
        }
        // A member prefix, when present, is a git pathspec appended after `--` on
        // every mining walk (#381). Refuse an empty, non-ASCII, absolute, or
        // NUL-bearing prefix rather than silently scoping to a nonsense path; a
        // leading slash or `..` component is not a valid toplevel-relative subtree.
        if let Some(prefix) = &self.member_prefix
            && (prefix.trim().is_empty()
                || !prefix.is_ascii()
                || prefix.starts_with('/')
                || prefix.contains('\0')
                || prefix.split('/').any(|component| component == ".."))
        {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_CONFIG_INVALID,
                "Git archaeology member prefix is empty, non-ASCII, absolute, or path-escaping",
            ));
        }
        Ok(())
    }
}

/// History range to mine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitMineMode {
    /// CBM-compatible bounded full pass.
    Full,
    /// Commits after a previously persisted watcher checkpoint.
    Since { previous_head: String },
}

/// One source range changed by a commit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitLineRange {
    pub path: String,
    pub start_line: u32,
    pub line_count: u32,
}

/// One blamed parent line implicated by a fix commit.
#[derive(Debug, Clone, PartialEq)]
pub struct SzzFinding {
    pub fix_commit: String,
    pub blamed_commit: String,
    pub path: String,
    pub line: u32,
    pub observed_at: u64,
    pub confidence: f32,
}

impl Eq for SzzFinding {}

impl Ord for SzzFinding {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.fix_commit,
            &self.blamed_commit,
            &self.path,
            self.line,
            self.confidence.to_bits(),
        )
            .cmp(&(
                &other.fix_commit,
                &other.blamed_commit,
                &other.path,
                other.line,
                other.confidence.to_bits(),
            ))
    }
}

impl PartialOrd for SzzFinding {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A validated standard revert and the target-version ranges it removed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RevertFinding {
    pub revert_commit: String,
    pub target_commit: String,
    pub target_range: GitLineRange,
    pub observed_at: u64,
}

/// Line ranges parsed from one unified diff, with gitlink exclusions counted.
///
/// `skipped_gitlink_paths` is the number of diffed files whose mined side is a
/// submodule pointer (mode 160000) — excluded from `ranges` because a gitlink
/// is a tree entry, not a blamable blob, and a pointer bump is never line
/// evidence (#514). Surfaced so no consumer drops them silently (invariant 3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangedRanges {
    pub ranges: Vec<GitLineRange>,
    pub skipped_gitlink_paths: usize,
}

/// Equality-stable process/output telemetry for grouped Git blame work.
#[derive(Debug, Clone, Default)]
pub struct GitBlameBatchTelemetry {
    /// Original changed-line ranges requested by the SZZ miner.
    pub requested_ranges: usize,
    /// Exact union ranges after overlapping/adjacent requests are coalesced.
    pub effective_ranges: usize,
    /// Distinct `(parent, path)` groups submitted to Git blame after the full SZZ
    /// plan is collected.
    pub groups: usize,
    /// Commit-local blame groups served from an already-mined `(parent, path)`
    /// group instead of spawning their own Git process.
    pub group_cache_hits: usize,
    /// Native Git blame processes spawned after grouping by `(parent, path)`.
    pub processes: usize,
    /// Per-request blame processes avoided by cross-commit `(parent, path)`
    /// grouping.
    pub processes_avoided: usize,
    /// `git cat-file --batch-command --buffer -Z` preflight processes spawned for
    /// exact parent/path existence and type checks.
    pub cat_file_processes: usize,
    /// Exact stdout bytes emitted by cat-file preflight.
    pub cat_file_stdout_bytes: u64,
    /// Parent/path groups whose preflight proved the blamed path absent.
    pub path_absent_groups: usize,
    /// Incremental protocol records returned and strictly parsed.
    pub returned_spans: usize,
    /// Distinct `(commit, final-line)` attributions returned to SZZ.
    pub returned_lines: usize,
    /// Exact stdout bytes emitted by all incremental blame children.
    pub stdout_bytes: u64,
    /// Observed wall time. Deliberately excluded from equality because two
    /// byte-identical mining passes need not take the same duration.
    pub wall_ms: u64,
    /// Observed wall time for cat-file preflight. Deliberately excluded from
    /// equality.
    pub cat_file_wall_ms: u64,
}

impl PartialEq for GitBlameBatchTelemetry {
    fn eq(&self, other: &Self) -> bool {
        self.requested_ranges == other.requested_ranges
            && self.effective_ranges == other.effective_ranges
            && self.groups == other.groups
            && self.group_cache_hits == other.group_cache_hits
            && self.processes == other.processes
            && self.processes_avoided == other.processes_avoided
            && self.cat_file_processes == other.cat_file_processes
            && self.cat_file_stdout_bytes == other.cat_file_stdout_bytes
            && self.path_absent_groups == other.path_absent_groups
            && self.returned_spans == other.returned_spans
            && self.returned_lines == other.returned_lines
            && self.stdout_bytes == other.stdout_bytes
    }
}

/// Equality-stable process/output telemetry for batched Git diff-tree work.
#[derive(Debug, Clone, Default)]
pub struct GitDiffTreeBatchTelemetry {
    /// Fix-like single-parent commits submitted to the cheap changed-file count phase.
    pub count_requested_commits: usize,
    /// `git diff-tree --stdin --raw -z` children used for the count phase.
    pub count_processes: usize,
    /// Per-commit count children avoided by batching.
    pub count_processes_avoided: usize,
    /// Exact stdout bytes emitted by the raw count children.
    pub count_stdout_bytes: u64,
    /// Fix-like single-parent, under-cap commits submitted to the unified-diff phase.
    pub ranges_requested_commits: usize,
    /// `git diff-tree --stdin --unified=0` children used for the range phase.
    pub ranges_processes: usize,
    /// Per-commit content-diff children avoided by batching.
    pub ranges_processes_avoided: usize,
    /// Exact stdout bytes emitted by the unified-diff children.
    pub ranges_stdout_bytes: u64,
    /// Observed wall time for count batches. Deliberately excluded from equality.
    pub count_wall_ms: u64,
    /// Observed wall time for range batches. Deliberately excluded from equality.
    pub ranges_wall_ms: u64,
    /// Effective registry-declared batch bound used by this pass.
    pub batch_limit_commits: usize,
}

impl PartialEq for GitDiffTreeBatchTelemetry {
    fn eq(&self, other: &Self) -> bool {
        self.count_requested_commits == other.count_requested_commits
            && self.count_processes == other.count_processes
            && self.count_processes_avoided == other.count_processes_avoided
            && self.count_stdout_bytes == other.count_stdout_bytes
            && self.ranges_requested_commits == other.ranges_requested_commits
            && self.ranges_processes == other.ranges_processes
            && self.ranges_processes_avoided == other.ranges_processes_avoided
            && self.ranges_stdout_bytes == other.ranges_stdout_bytes
            && self.batch_limit_commits == other.batch_limit_commits
    }
}

/// Exact state of the repository history named by `HEAD`.
///
/// An unborn repository has a real symbolic `HEAD` and real working-tree/index
/// bytes, but no commit object. Keeping that state distinct from a commit makes
/// it impossible for history consumers to manufacture an object id for absent
/// history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GitHistoryState {
    /// `HEAD^{commit}` resolved to this exact immutable commit object. The
    /// optional immediate symbolic ref distinguishes a checked-out branch from
    /// detached HEAD even when both name the same object.
    Committed {
        oid: String,
        symbolic_ref: Option<String>,
    },
    /// Immediate symbolic `HEAD` names this exact absent branch ref.
    Unborn { symbolic_ref: String },
}

impl GitHistoryState {
    /// Validates the persisted representation without consulting repository state.
    pub fn validate(&self) -> Result<(), ArchaeologyError> {
        match self {
            Self::Committed { oid, symbolic_ref } => {
                validate_oid(oid)?;
                if let Some(symbolic_ref) = symbolic_ref
                    && !valid_branch_ref(symbolic_ref)
                {
                    return Err(ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!("invalid committed symbolic branch ref {symbolic_ref:?}"),
                    ));
                }
                Ok(())
            }
            Self::Unborn { symbolic_ref } if valid_branch_ref(symbolic_ref) => Ok(()),
            Self::Unborn { symbolic_ref } => Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("invalid unborn symbolic branch ref {symbolic_ref:?}"),
            )),
        }
    }

    /// Returns the current commit object id only when history exists.
    pub fn commit_oid(&self) -> Option<&str> {
        match self {
            Self::Committed { oid, .. } => Some(oid),
            Self::Unborn { .. } => None,
        }
    }

    /// Returns the exact symbolic branch ref only when history is absent.
    pub fn unborn_symbolic_ref(&self) -> Option<&str> {
        match self {
            Self::Committed { .. } => None,
            Self::Unborn { symbolic_ref } => Some(symbolic_ref),
        }
    }

    /// Returns the immediate symbolic branch ref for either committed or
    /// unborn HEAD. `None` is an explicitly detached committed HEAD.
    pub fn symbolic_ref(&self) -> Option<&str> {
        match self {
            Self::Committed { symbolic_ref, .. } => symbolic_ref.as_deref(),
            Self::Unborn { symbolic_ref } => Some(symbolic_ref),
        }
    }
}

fn valid_branch_ref(reference: &str) -> bool {
    let Some(branch) = reference.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && branch != "@"
        && !branch.ends_with('.')
        && !branch.ends_with('/')
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.contains("//")
        && !branch
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || b"~^:?*[\\".contains(&byte))
        && branch.split('/').all(|component| {
            !component.is_empty() && !component.starts_with('.') && !component.ends_with(".lock")
        })
}

/// Exact Git source observation used by publication, preservation, and
/// freshness consumers. Both fields are measured in one operation so callers
/// cannot classify history independently from the bytes they fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRepositorySnapshot {
    /// Exact committed-or-unborn state observed for `HEAD`.
    pub history: GitHistoryState,
    /// Versioned digest over the history identity and current source bytes.
    pub source_fingerprint: String,
}

/// Deterministic result of one mining pass.
#[derive(Debug, Clone, PartialEq)]
pub struct GitArchaeologyReport {
    pub history: GitHistoryState,
    pub head: Option<String>,
    pub szz_findings: Vec<SzzFinding>,
    pub revert_findings: Vec<RevertFinding>,
    /// Commits that became unreachable from the tracked head after a force move.
    pub force_removed_commits: Vec<String>,
    /// Fix-like merge commits skipped rather than blending parent histories.
    pub skipped_merge_fixes: usize,
    /// Fix/revert commits EXCLUDED from SZZ line mining because their changed-file
    /// count exceeded [`GitArchaeologyConfig::max_commit_changed_files`] — mass
    /// changes (relocation, bulk rename/delete, mass reformat) whose blame is
    /// meaningless (#434). Counted and surfaced, never a silent skip (invariant 3).
    pub skipped_large_commits: usize,
    /// Revert commits whose message-mined target hash does not resolve to a
    /// commit in this clone (#467) — squash-merged reverts routinely reference
    /// commits that only ever existed on a PR branch. The revert is skipped for
    /// mining (its target's diff cannot be read), counted here per invariant 3.
    pub skipped_unresolvable_reverts: usize,
    /// Diff files excluded from range mining because the mined side is a gitlink
    /// (mode 160000) — a submodule pointer bump diffs as `-Subproject commit …`
    /// and its path is a tree entry, not a blamable blob, so it is never line
    /// evidence (#514: mise `aqua-registry`, spacedrive `apps/cloud`). Counted
    /// per invariant 3, never a silent drop.
    pub skipped_gitlink_paths: usize,
    /// Blame targets refused by git as `no such path` at the blamed parent —
    /// a path the diff names but the parent commit does not contain (rename/move
    /// history, directory↔file swaps) (#514). Each is a counted, labeled skip;
    /// every other git blame failure stays fail-closed.
    pub skipped_unblamable_paths: usize,
    /// Capability-preserving batching/read-volume telemetry for Git diff-tree.
    pub diff_tree: GitDiffTreeBatchTelemetry,
    /// Capability-preserving batching/read-volume telemetry for Git blame.
    pub blame: GitBlameBatchTelemetry,
}

/// Coded, remediable archaeology error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchaeologyError {
    pub code: &'static str,
    pub message: String,
    pub remediation: &'static str,
}

impl ArchaeologyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            remediation: REMEDIATION,
        }
    }
}

impl fmt::Display for ArchaeologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ArchaeologyError {}

#[derive(Debug)]
struct CommitRecord {
    sha: String,
    parents: Vec<String>,
    timestamp: u64,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DiffTreeCandidate {
    commit: String,
    parent: String,
}

#[derive(Debug, Clone)]
struct PendingBlameRequest {
    fix_commit: String,
    parent: String,
    path: String,
    ranges: Vec<GitLineRange>,
    observed_at: u64,
    confidence: f32,
}

#[derive(Debug, Clone, Default)]
struct BlamePlanGroup {
    request_indexes: Vec<usize>,
    ranges: Vec<GitLineRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlameTargetPreflight;

/// Mines the configured Git history using native argv-only child processes.
pub fn mine_git_archaeology(
    repo: &Path,
    config: &GitArchaeologyConfig,
    mode: &GitMineMode,
) -> Result<GitArchaeologyReport, ArchaeologyError> {
    let history = git_history_state(repo)?;
    mine_git_archaeology_at_history(repo, config, mode, &history)
}

/// Mines Git history from an already measured repository-history identity.
///
/// Publication paths use this form so source fingerprinting and archaeology
/// consume one observation rather than independently resolving `HEAD`.
pub fn mine_git_archaeology_at_history(
    repo: &Path,
    config: &GitArchaeologyConfig,
    mode: &GitMineMode,
    history: &GitHistoryState,
) -> Result<GitArchaeologyReport, ArchaeologyError> {
    config.validate()?;
    history.validate()?;
    // Path-namespace correctness for monorepo-member corpora (e.g. cbm/ inside
    // the Astrolabe repo): `git diff`/`git log` emit TOPLEVEL-relative paths,
    // but a pathspec passed back to `git blame` is resolved relative to the
    // command's working directory. With the corpus subdirectory as cwd, every
    // mined path gets the subtree prefix silently prepended (CLAUDE.md ->
    // cbm/CLAUDE.md) and blame fails on paths that never existed. Run the whole
    // mining pass from the repository toplevel so the two namespaces coincide;
    // for a corpus that IS the toplevel this is byte-identical behavior.
    let toplevel = PathBuf::from(
        git_text(repo, &["rev-parse", "--show-toplevel"])?
            .trim()
            .to_string(),
    );
    let repo: &Path = &toplevel;
    let history = history.clone();
    let head = match &history {
        GitHistoryState::Committed { oid, .. } => oid.clone(),
        GitHistoryState::Unborn { symbolic_ref } => {
            if let GitMineMode::Since { previous_head } = mode {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_HISTORY_STATE_INVALID,
                    format!(
                        "incremental archaeology from commit {previous_head} was requested while HEAD names absent branch ref {symbolic_ref:?}"
                    ),
                ));
            }
            return Ok(GitArchaeologyReport {
                history,
                head: None,
                szz_findings: Vec::new(),
                revert_findings: Vec::new(),
                force_removed_commits: Vec::new(),
                skipped_merge_fixes: 0,
                skipped_large_commits: 0,
                skipped_unresolvable_reverts: 0,
                skipped_gitlink_paths: 0,
                skipped_unblamable_paths: 0,
                diff_tree: GitDiffTreeBatchTelemetry {
                    batch_limit_commits: config.diff_tree_batch_commits,
                    ..GitDiffTreeBatchTelemetry::default()
                },
                blame: GitBlameBatchTelemetry::default(),
            });
        }
    };

    // Monorepo-member pathspec (#381): every history walk below is limited to the
    // member subtree so only commits (and, via the scoped diffs, only ranges) that
    // touch the requested corpus enter the evidence set — the whole-monorepo mine
    // never happens. `None` (corpus IS the toplevel) leaves each walk unscoped:
    // byte-identical to pre-#381 behavior.
    let pathspec = config.member_prefix.as_deref();

    let (range, force_removed_commits) = match mode {
        GitMineMode::Full => (None, Vec::new()),
        GitMineMode::Since { previous_head } => {
            validate_oid(previous_head)?;
            let ancestor =
                git_status(repo, &["merge-base", "--is-ancestor", previous_head, &head])?;
            let removed = if ancestor {
                Vec::new()
            } else {
                // Force-removed scan (#381): scope the unreachable-commit walk to the
                // member subtree so a force move that only rewrote out-of-subtree
                // history never manufactures reverted-anchor evidence for this corpus.
                let mut args = vec![
                    "rev-list",
                    "--reverse",
                    previous_head.as_str(),
                    "--not",
                    head.as_str(),
                ];
                if let Some(prefix) = pathspec {
                    args.push("--");
                    args.push(prefix);
                }
                oid_lines(&git_bytes(repo, &args)?)?
            };
            (Some(format!("{previous_head}..{head}")), removed)
        }
    };

    // #434 phase-internal timing: opt-in via ASTRO_ARCH_TIMING (off by default;
    // behavior-neutral). Attributes the mine cost to read_commits vs diff vs blame so
    // the dominant sub-phase is measured, not guessed.
    let arch_timing = std::env::var_os("ASTRO_ARCH_TIMING").is_some();
    let read_start = std::time::Instant::now();
    let commits = read_commits(repo, config, range.as_deref())?;
    let read_commits_ms = read_start.elapsed().as_millis();
    let commit_count = commits.len();
    // #434 mass-change cap: 0 disables the cap (pre-#434 behavior — mine every commit).
    let file_cap = config.max_commit_changed_files;
    let mut diff_tree = GitDiffTreeBatchTelemetry {
        batch_limit_commits: config.diff_tree_batch_commits,
        ..GitDiffTreeBatchTelemetry::default()
    };
    let fix_diff_candidates = commits
        .iter()
        .filter_map(|commit| {
            classify_fix_confidence(&commit.message, config)?;
            if commit.parents.len() == 1 {
                Some(DiffTreeCandidate {
                    commit: commit.sha.clone(),
                    parent: commit.parents[0].clone(),
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let changed_file_counts = if file_cap != 0 {
        changed_file_counts_for_commits(repo, &fix_diff_candidates, pathspec, &mut diff_tree)?
    } else {
        BTreeMap::new()
    };
    let old_range_candidates = fix_diff_candidates
        .iter()
        .filter(|candidate| {
            file_cap == 0
                || changed_file_counts
                    .get(&candidate.commit)
                    .is_some_and(|count| *count <= file_cap)
        })
        .cloned()
        .collect::<Vec<_>>();
    let changed_old_ranges_by_commit =
        changed_old_ranges_for_commits(repo, &old_range_candidates, pathspec, &mut diff_tree)?;
    let mut blame = GitBlameBatchTelemetry::default();
    let mut pending_blame_requests = Vec::new();
    let mut szz = BTreeSet::new();
    let mut reverts = BTreeSet::new();
    let mut skipped_merge_fixes = 0usize;
    let mut skipped_large_commits = 0usize;
    let mut skipped_unresolvable_reverts = 0usize;
    let mut skipped_gitlink_paths = 0usize;
    // A stable old-side diff range must resolve to a blob in the immutable parent
    // tree. Keep the persisted compatibility counter at zero; any disagreement now
    // fails closed with ASTRO_ARCHAEOLOGY_OBJECT_VIEW_INCONSISTENT.
    let skipped_unblamable_paths = 0usize;
    for commit in commits {
        let revert_target = match canonical_revert_target(&commit.message) {
            RevertTarget::Absent => None,
            // A revert line whose object id we cannot extract (abbreviated,
            // reworded) is prose, not malformed git output: count it with the
            // unresolvable reverts (invariant 3) and keep mining the repo (#496).
            RevertTarget::Unparseable => {
                skipped_unresolvable_reverts += 1;
                None
            }
            RevertTarget::Oid(target) => Some(target),
        };
        if let Some(target) = revert_target {
            validate_oid(&target)?;
            // Existence gate FIRST (#467): the target hash is mined from prose and
            // may not exist in this clone at all (squash-merged reverts reference
            // commits that only ever lived on a PR branch). Every query below —
            // the cap pre-count's `%P` lookup included — fails fatally on a
            // missing object, so resolve existence before touching the target.
            if !git_commit_exists(repo, &target)? {
                skipped_unresolvable_reverts += 1;
            } else {
                // Mass-change cap (#434): a revert whose TARGET touched more than the
                // cap of files within the pathspec is a bulk revert; its per-line
                // blame/range mining is meaningless and, as with the relocation fix
                // commit, dominated by diff generation+parse cost. Gate with the cheap
                // `--name-only` pre-count before the expensive content diff, and count
                // the skip (invariant 3). The target's parent is the diff old side that
                // `changed_new_ranges_impl` derives, so count against that same pair.
                let target_over_cap = file_cap != 0
                    && changed_file_count_for_commit(repo, &target, pathspec)? > file_cap;
                if target_over_cap {
                    skipped_large_commits += 1;
                } else if revert_patch_matches(repo, &target, &commit.sha)? {
                    let changed = changed_new_ranges_impl(repo, &target, pathspec)?;
                    skipped_gitlink_paths += changed.skipped_gitlink_paths;
                    for target_range in changed.ranges {
                        reverts.insert(RevertFinding {
                            revert_commit: commit.sha.clone(),
                            target_commit: target.clone(),
                            target_range,
                            observed_at: commit.timestamp,
                        });
                    }
                }
            }
        }

        let Some(confidence) = classify_fix_confidence(&commit.message, config) else {
            continue;
        };
        if commit.parents.len() != 1 {
            skipped_merge_fixes += 1;
            continue;
        }
        let parent = &commit.parents[0];
        // Mass-change cap (#434): before the expensive `git diff --unified=0` content
        // diff, cheaply count the files this fix commit changed within the pathspec
        // (`git diff --name-only`, a tree compare with no content). Over the cap => a
        // relocation / bulk rewrite / mass delete, NOT a targeted bug fix: exclude it
        // from SZZ (its blame is meaningless and — for a pure-addition relocation —
        // yields zero old-side ranges anyway), count the skip, and never pay the
        // ~600k-line diff-and-parse cost that dominated the M-scale phase (#422).
        if file_cap != 0
            && *changed_file_counts.get(&commit.sha).ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "batched Git changed-file count is missing for fix commit {}",
                        commit.sha
                    ),
                )
            })? > file_cap
        {
            skipped_large_commits += 1;
            continue;
        }
        let old_changed = changed_old_ranges_by_commit
            .get(&commit.sha)
            .cloned()
            .ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "batched Git old-side range output is missing for fix commit {}",
                        commit.sha
                    ),
                )
            })?;
        skipped_gitlink_paths += old_changed.skipped_gitlink_paths;
        blame.requested_ranges = blame
            .requested_ranges
            .checked_add(old_changed.ranges.len())
            .ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git blame requested-range telemetry overflowed usize",
                )
            })?;
        let mut ranges_by_path = BTreeMap::<String, Vec<GitLineRange>>::new();
        for range in old_changed.ranges {
            ranges_by_path
                .entry(range.path.clone())
                .or_default()
                .push(range);
        }
        for (path, requested) in ranges_by_path {
            pending_blame_requests.push(PendingBlameRequest {
                fix_commit: commit.sha.clone(),
                parent: parent.clone(),
                path,
                ranges: requested,
                observed_at: commit.timestamp,
                confidence,
            });
        }
    }
    execute_grouped_blame_plan(repo, &pending_blame_requests, &mut blame, &mut szz)?;
    if arch_timing {
        eprintln!(
            "astro.arch.timing phase=mine_internal read_commits_ms={read_commits_ms} \
             commits={commit_count} diff_count_ms={} diff_ranges_ms={} blame_ms={} \
             diff_count_requested_commits={} diff_count_processes={} \
             diff_count_processes_avoided={} diff_count_stdout_bytes={} \
             diff_ranges_requested_commits={} diff_ranges_processes={} \
             diff_ranges_processes_avoided={} diff_ranges_stdout_bytes={} \
             diff_tree_batch_limit_commits={} \
             blame_requested_ranges={} blame_effective_ranges={} blame_groups={} \
             blame_group_cache_hits={} blame_processes={} blame_processes_avoided={} \
             blame_cat_file_processes={} blame_cat_file_stdout_bytes={} \
             blame_cat_file_ms={} blame_path_absent_groups={} \
             blame_returned_spans={} blame_returned_lines={} blame_stdout_bytes={} \
             skipped_merge_fixes={skipped_merge_fixes} \
             skipped_large_commits={skipped_large_commits} \
             skipped_unresolvable_reverts={skipped_unresolvable_reverts} \
             skipped_gitlink_paths={skipped_gitlink_paths} \
             skipped_unblamable_paths={skipped_unblamable_paths} file_cap={file_cap}",
            diff_tree.count_wall_ms,
            diff_tree.ranges_wall_ms,
            blame.wall_ms,
            diff_tree.count_requested_commits,
            diff_tree.count_processes,
            diff_tree.count_processes_avoided,
            diff_tree.count_stdout_bytes,
            diff_tree.ranges_requested_commits,
            diff_tree.ranges_processes,
            diff_tree.ranges_processes_avoided,
            diff_tree.ranges_stdout_bytes,
            diff_tree.batch_limit_commits,
            blame.requested_ranges,
            blame.effective_ranges,
            blame.groups,
            blame.group_cache_hits,
            blame.processes,
            blame.processes_avoided,
            blame.cat_file_processes,
            blame.cat_file_stdout_bytes,
            blame.cat_file_wall_ms,
            blame.path_absent_groups,
            blame.returned_spans,
            blame.returned_lines,
            blame.stdout_bytes,
        );
    }
    Ok(GitArchaeologyReport {
        history,
        head: Some(head),
        szz_findings: szz.into_iter().collect(),
        revert_findings: reverts.into_iter().collect(),
        force_removed_commits,
        skipped_merge_fixes,
        skipped_large_commits,
        skipped_unresolvable_reverts,
        skipped_gitlink_paths,
        skipped_unblamable_paths,
        diff_tree,
        blame,
    })
}

/// Measures the exact committed-or-unborn state named by `HEAD`.
///
/// A failed commit lookup is classified as unborn only when `HEAD` is an
/// immediate symbolic branch ref and Git independently proves that exact ref is
/// absent. Detached, malformed, present-but-unresolvable, and ref-query fault
/// states retain the original coded Git failure.
pub fn git_history_state(repo: &Path) -> Result<GitHistoryState, ArchaeologyError> {
    let head_args = ["rev-parse", "--verify", "HEAD^{commit}"];
    let head_output = git_command(repo, &head_args)
        .output()
        .map_err(|error| git_spawn_error(&head_args, error))?;
    if head_output.status.success() {
        let oid = utf8_trim(&head_output.stdout)?;
        validate_oid(&oid)?;
        let symbolic_ref =
            git_optional_text(repo, &["symbolic-ref", "--quiet", "--no-recurse", "HEAD"])?
                .map(|value| value.trim().to_string());
        let history = GitHistoryState::Committed { oid, symbolic_ref };
        history.validate()?;
        return Ok(history);
    }

    let Some(symbolic_ref) =
        git_optional_text(repo, &["symbolic-ref", "--quiet", "--no-recurse", "HEAD"])?
    else {
        return Err(git_exit_error(
            &head_args,
            head_output.status.code(),
            &head_output.stderr,
        ));
    };
    let symbolic_ref = symbolic_ref.trim().to_string();
    if !symbolic_ref.starts_with("refs/heads/") || symbolic_ref.len() == "refs/heads/".len() {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "Git HEAD names non-branch symbolic ref {symbolic_ref:?} after HEAD^{{commit}} failed"
            ),
        ));
    }
    if git_ref_exists(repo, &symbolic_ref)? {
        return Err(git_exit_error(
            &head_args,
            head_output.status.code(),
            &head_output.stderr,
        ));
    }
    let history = GitHistoryState::Unborn { symbolic_ref };
    history.validate()?;
    Ok(history)
}

/// Reports whether `repo` is inside a real Git work tree.
///
/// Runs `git -C <repo> rev-parse --is-inside-work-tree` and returns `true` only
/// when Git exits zero with stdout trimming to exactly `true`. Any non-zero exit
/// (a plain directory that is not a repository, a bare repository, a spawn
/// failure) yields `false`.
///
/// This is a caller-side "is this even a repository" gate, deliberately *not* a
/// fail-closed archaeology query: it lets a non-git corpus route through the
/// graceful archaeology-unavailable path instead of hard-erroring. It does not
/// weaken the fail-closed behavior of the mining queries — a genuine Git fault
/// inside a real repository still surfaces as an [`ArchaeologyError`] from those
/// callers.
pub fn is_git_work_tree(repo: &Path) -> bool {
    match git_command(repo, &["rev-parse", "--is-inside-work-tree"])
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) => {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
        }
        Err(_) => false,
    }
}

/// Self-describing algorithm tag for the git source fingerprint (#347).
pub const GIT_SOURCE_FINGERPRINT_ALGO: &str = "blake3";
/// Self-describing version tag for the git source fingerprint (#347/#858/#1082).
///
/// v2 replaces textual patch hashing with exact current bytes for every changed
/// tracked or untracked path. A textual Git diff deliberately does not contain
/// binary-file bytes, so two different binary edits could previously produce the
/// same status + `Binary files differ` payload. v4 additionally binds the
/// immediate symbolic/detached HEAD identity for committed history; branch
/// structure is a publication input even when its commit OID is unchanged.
/// Persisted older values are therefore never compared to this stronger domain.
pub const GIT_SOURCE_FINGERPRINT_VERSION: &str = "v4";

/// Content fingerprint of the live git working tree at `repo` — the source-of-truth
/// freshness signal for shadow imports (#347).
///
/// The derived CBM `<project>.db` only changes when `index_repository` re-runs, so
/// fingerprinting it cannot detect an out-of-band `git commit` or working-tree edit:
/// the freshness verdict stays Fresh and the reconcile path never engages. This
/// fingerprints the *real source of truth* instead — the git working tree — so any
/// out-of-band mutation moves the digest:
///
/// * the HEAD commit oid (catches commits / checkouts / resets),
/// * the porcelain working-tree status (catches staged/unstaged/untracked/renamed
///   entries appearing or disappearing),
/// * the exact current bytes/type of every tracked path changed from HEAD, and
/// * the exact current bytes/type of every untracked, non-ignored path.
///
/// The returned value is `blake3:v3:<hex>` — self-describing so a persisted watermark
/// can be domain-gated exactly like the CBM-db watermark. Fails closed with a coded
/// error when `repo` is not a usable git repository (so a missing/renamed source tree
/// is reported, never silently treated as Fresh).
pub fn git_source_fingerprint(repo: &Path) -> Result<String, ArchaeologyError> {
    Ok(git_repository_snapshot(repo)?.source_fingerprint)
}

/// Measures one coherent repository history/source snapshot.
pub fn git_repository_snapshot(repo: &Path) -> Result<GitRepositorySnapshot, ArchaeologyError> {
    let history = git_history_state(repo)?;
    let source_fingerprint = git_source_fingerprint_at_history(repo, &history)?;
    let history_after = git_history_state(repo)?;
    if history_after != history {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_HISTORY_STATE_INVALID,
            format!(
                "Git history changed while its source fingerprint was measured: before={history:?}, after={history_after:?}"
            ),
        ));
    }
    Ok(GitRepositorySnapshot {
        history,
        source_fingerprint,
    })
}

fn git_source_fingerprint_at_history(
    repo: &Path,
    history: &GitHistoryState,
) -> Result<String, ArchaeologyError> {
    // NUL-delimited machine status over all untracked files. This is the fail-closed
    // gate: it errors if `repo` is not a git repository, so we never fingerprint a
    // non-source directory as if it were fresh.
    let status = git_bytes(
        repo,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    // Enumerate tracked paths changed from HEAD (staged + unstaged) rather than
    // hashing a textual patch. Git intentionally summarizes binary patches as
    // `Binary files differ`; that representation cannot distinguish two different
    // current byte streams with the same status. `--no-renames` names both sides of
    // a rename, so the absent old path and exact new bytes are both represented.
    // An explicitly classified unborn repository has no HEAD tree to diff.
    let changed_tracked = match history {
        GitHistoryState::Unborn { .. } => {
            // Every index entry is new relative to the absent HEAD tree. Include
            // staged files as well as the untracked inventory below.
            git_bytes(repo, &["ls-files", "-z"])?
        }
        GitHistoryState::Committed { oid, .. } => git_bytes(
            repo,
            &[
                "diff",
                oid,
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-renames",
            ],
        )?,
    };
    // Untracked, non-ignored paths (NUL-delimited). `--others` enumerates the
    // current files and `--exclude-standard` applies the same repository ignore
    // policy used by ordinary Git tooling.
    let untracked = git_bytes(repo, &["ls-files", "--others", "--exclude-standard", "-z"])?;

    let mut hasher = blake3::Hasher::new();
    let mut section = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    section(GIT_SOURCE_FINGERPRINT_VERSION.as_bytes());
    match history {
        GitHistoryState::Committed { oid, symbolic_ref } => {
            section(b"committed");
            section(oid.as_bytes());
            match symbolic_ref {
                Some(symbolic_ref) => {
                    section(b"symbolic");
                    section(symbolic_ref.as_bytes());
                }
                None => section(b"detached"),
            }
        }
        GitHistoryState::Unborn { symbolic_ref } => {
            section(b"unborn");
            section(symbolic_ref.as_bytes());
        }
    }
    section(&status);
    let mut changed_paths = BTreeSet::new();
    for raw in changed_tracked
        .split(|byte| *byte == 0)
        .chain(untracked.split(|byte| *byte == 0))
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(raw).map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("Git changed-path output is not UTF-8: {error}"),
            )
        })?;
        changed_paths.insert(path.to_string());
    }
    for relative in changed_paths {
        section(relative.as_bytes());
        fingerprint_worktree_path(repo, &relative, &mut section)?;
    }
    Ok(format!(
        "{GIT_SOURCE_FINGERPRINT_ALGO}:{GIT_SOURCE_FINGERPRINT_VERSION}:{}",
        hasher.finalize().to_hex()
    ))
}

fn fingerprint_worktree_path(
    repo: &Path,
    relative: &str,
    section: &mut impl FnMut(&[u8]),
) -> Result<(), ArchaeologyError> {
    let path = repo.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            section(b"missing");
            return Ok(());
        }
        Err(error) => {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_GIT_FAILED,
                format!(
                    "cannot inspect changed working-tree path {relative:?} at {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_file() {
        section(b"file");
        let bytes = std::fs::read(&path).map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_GIT_FAILED,
                format!(
                    "cannot read changed working-tree file {relative:?} at {}: {error}",
                    path.display()
                ),
            )
        })?;
        section(&bytes);
        return Ok(());
    }
    if file_type.is_symlink() {
        section(b"symlink");
        let target = std::fs::read_link(&path).map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_GIT_FAILED,
                format!(
                    "cannot read changed symlink target {relative:?} at {}: {error}",
                    path.display()
                ),
            )
        })?;
        let target = target.to_str().ok_or_else(|| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "changed symlink target for {relative:?} is not Unicode: {}",
                    target.display()
                ),
            )
        })?;
        section(target.as_bytes());
        return Ok(());
    }
    if file_type.is_dir() {
        // A tracked directory is a gitlink/submodule. Fold its complete live Git
        // fingerprint in recursively so two different dirty submodule states can
        // never collapse to the same parent ` M path` status record.
        section(b"gitlink");
        let nested = git_source_fingerprint(&path)?;
        section(nested.as_bytes());
        return Ok(());
    }
    Err(ArchaeologyError::new(
        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
        format!(
            "changed working-tree path {relative:?} at {} is not a file, symlink, directory, or missing path",
            path.display()
        ),
    ))
}

/// Returns the new-side ranges introduced by `commit` for exact version lookup,
/// with gitlink exclusions counted ([`ChangedRanges`], #514).
pub fn changed_new_ranges(repo: &Path, commit: &str) -> Result<ChangedRanges, ArchaeologyError> {
    changed_new_ranges_impl(repo, commit, None)
}

/// Shared implementation of [`changed_new_ranges`] with an optional member-subtree
/// pathspec (#381). `pathspec: Some(prefix)` limits the underlying `git diff` to the
/// subtree so a fix/revert commit that also touched files outside the corpus does not
/// contribute out-of-subtree ranges to the evidence set; `None` keeps the whole-commit
/// behavior for whole-repo callers.
fn changed_new_ranges_impl(
    repo: &Path,
    commit: &str,
    pathspec: Option<&str>,
) -> Result<ChangedRanges, ArchaeologyError> {
    validate_oid(commit)?;
    let parents = git_text(repo, &["show", "-s", "--format=%P", commit])?;
    let Some(parent) = parents.split_whitespace().next() else {
        return Ok(ChangedRanges::default());
    };
    changed_ranges(repo, parent, commit, false, pathspec)
}

/// Returns the new-side ranges introduced between two arbitrary commits
/// (`git diff old..new`), for callers that track a last-processed baseline
/// which may span multiple commits — e.g. the guard commit-OOD producer
/// diffing `last-processed..HEAD` (#368). Unlike [`changed_new_ranges`] this
/// does not derive the old side from the commit's parent, so a baseline that
/// fell several commits behind still yields exactly the lines that changed
/// since it was recorded.
pub fn changed_new_ranges_between(
    repo: &Path,
    old: &str,
    new: &str,
) -> Result<ChangedRanges, ArchaeologyError> {
    validate_oid(old)?;
    validate_oid(new)?;
    changed_ranges(repo, old, new, false, None)
}

fn changed_file_counts_for_commits(
    repo: &Path,
    candidates: &[DiffTreeCandidate],
    pathspec: Option<&str>,
    telemetry: &mut GitDiffTreeBatchTelemetry,
) -> Result<BTreeMap<String, usize>, ArchaeologyError> {
    validate_diff_tree_candidates(candidates)?;
    telemetry.count_requested_commits = telemetry
        .count_requested_commits
        .checked_add(candidates.len())
        .ok_or_else(|| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                "Git diff-tree count requested-commit telemetry overflowed usize",
            )
        })?;
    let mut counts = BTreeMap::new();
    if candidates.is_empty() {
        return Ok(counts);
    }
    for chunk in candidates.chunks(telemetry.batch_limit_commits) {
        let mut args = vec!["diff-tree", "--stdin", "--always", "--raw", "-z", "-r"];
        if let Some(prefix) = pathspec {
            args.push("--");
            args.push(prefix);
        }
        let stdin = diff_tree_stdin(chunk);
        let start = std::time::Instant::now();
        let output = git_with_stdin(repo, &args, stdin.as_bytes())?;
        telemetry.count_wall_ms = telemetry
            .count_wall_ms
            .saturating_add(elapsed_u64_ms(start.elapsed()));
        telemetry.count_processes = telemetry.count_processes.checked_add(1).ok_or_else(|| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                "Git diff-tree count process telemetry overflowed usize",
            )
        })?;
        telemetry.count_stdout_bytes = telemetry
            .count_stdout_bytes
            .checked_add(u64::try_from(output.len()).map_err(|_| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git diff-tree raw count stdout length cannot be represented as u64",
                )
            })?)
            .ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git diff-tree count stdout-byte telemetry overflowed u64",
                )
            })?;
        counts.extend(parse_diff_tree_raw_counts(&output, chunk)?);
    }
    telemetry.count_processes_avoided = telemetry
        .count_requested_commits
        .saturating_sub(telemetry.count_processes);
    Ok(counts)
}

fn changed_old_ranges_for_commits(
    repo: &Path,
    candidates: &[DiffTreeCandidate],
    pathspec: Option<&str>,
    telemetry: &mut GitDiffTreeBatchTelemetry,
) -> Result<BTreeMap<String, ChangedRanges>, ArchaeologyError> {
    validate_diff_tree_candidates(candidates)?;
    telemetry.ranges_requested_commits = telemetry
        .ranges_requested_commits
        .checked_add(candidates.len())
        .ok_or_else(|| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                "Git diff-tree range requested-commit telemetry overflowed usize",
            )
        })?;
    let mut ranges = BTreeMap::new();
    if candidates.is_empty() {
        return Ok(ranges);
    }
    for chunk in candidates.chunks(telemetry.batch_limit_commits) {
        let mut args = vec![
            "diff-tree",
            "--stdin",
            "--always",
            "--unified=0",
            "--no-prefix",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "-r",
        ];
        if let Some(prefix) = pathspec {
            args.push("--");
            args.push(prefix);
        }
        let stdin = diff_tree_stdin(chunk);
        let start = std::time::Instant::now();
        let output = git_with_stdin(repo, &args, stdin.as_bytes())?;
        telemetry.ranges_wall_ms = telemetry
            .ranges_wall_ms
            .saturating_add(elapsed_u64_ms(start.elapsed()));
        telemetry.ranges_processes =
            telemetry.ranges_processes.checked_add(1).ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git diff-tree range process telemetry overflowed usize",
                )
            })?;
        telemetry.ranges_stdout_bytes = telemetry
            .ranges_stdout_bytes
            .checked_add(u64::try_from(output.len()).map_err(|_| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git diff-tree unified stdout length cannot be represented as u64",
                )
            })?)
            .ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git diff-tree range stdout-byte telemetry overflowed u64",
                )
            })?;
        let output = String::from_utf8(output).map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("Git output is not UTF-8: {error}"),
            )
        })?;
        ranges.extend(parse_diff_tree_patch_ranges(&output, chunk, true)?);
    }
    telemetry.ranges_processes_avoided = telemetry
        .ranges_requested_commits
        .saturating_sub(telemetry.ranges_processes);
    Ok(ranges)
}

fn validate_diff_tree_candidates(candidates: &[DiffTreeCandidate]) -> Result<(), ArchaeologyError> {
    for candidate in candidates {
        validate_oid(&candidate.parent)?;
        validate_oid(&candidate.commit)?;
    }
    Ok(())
}

fn diff_tree_stdin(candidates: &[DiffTreeCandidate]) -> String {
    let mut stdin = String::new();
    for candidate in candidates {
        stdin.push_str(&candidate.commit);
        stdin.push('\n');
    }
    stdin
}

fn parse_diff_tree_raw_counts(
    output: &[u8],
    candidates: &[DiffTreeCandidate],
) -> Result<BTreeMap<String, usize>, ArchaeologyError> {
    let mut tokens = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    while tokens.last().is_some_and(|token| token.is_empty()) {
        tokens.pop();
    }
    let mut index = 0usize;
    let mut counts = BTreeMap::new();
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        let Some(header) = tokens.get(index) else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git diff-tree raw output ended before commit header {}",
                    candidate.commit
                ),
            ));
        };
        let header = utf8_trim(header)?;
        if header != candidate.commit {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git diff-tree raw output header mismatch at batch index {candidate_index}: expected {}, got {header}",
                    candidate.commit
                ),
            ));
        }
        index += 1;
        let mut count = 0usize;
        let next_commit = candidates.get(candidate_index + 1);
        while let Some(token) = tokens.get(index) {
            if next_commit
                .is_some_and(|next| diff_tree_token_matches_commit(token, next.commit.as_str()))
            {
                break;
            }
            if !token.starts_with(b":") {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "Git diff-tree raw output for commit {} contained a non-record token before the next commit header",
                        candidate.commit
                    ),
                ));
            }
            let meta = std::str::from_utf8(token).map_err(|error| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git diff-tree raw metadata is not UTF-8: {error}"),
                )
            })?;
            let status = meta.split_whitespace().last().ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git diff-tree raw metadata is missing a status: {meta:?}"),
                )
            })?;
            let path_fields = if status.starts_with('R') || status.starts_with('C') {
                2
            } else {
                1
            };
            index += 1;
            for _ in 0..path_fields {
                let Some(path) = tokens.get(index) else {
                    return Err(ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!(
                            "Git diff-tree raw output for commit {} ended mid-path record",
                            candidate.commit
                        ),
                    ));
                };
                if path.is_empty() {
                    return Err(ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!(
                            "Git diff-tree raw output for commit {} contained an empty changed path",
                            candidate.commit
                        ),
                    ));
                }
                index += 1;
            }
            count = count.checked_add(1).ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git diff-tree changed-file count overflowed usize",
                )
            })?;
        }
        counts.insert(candidate.commit.clone(), count);
    }
    if index != tokens.len() {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            "Git diff-tree raw output contained trailing records after the expected commit batch",
        ));
    }
    Ok(counts)
}

fn diff_tree_token_matches_commit(token: &[u8], commit: &str) -> bool {
    std::str::from_utf8(token)
        .map(|value| value.trim() == commit)
        .unwrap_or(false)
}

fn parse_diff_tree_patch_ranges(
    output: &str,
    candidates: &[DiffTreeCandidate],
    old_side: bool,
) -> Result<BTreeMap<String, ChangedRanges>, ArchaeologyError> {
    let mut current_index = None::<usize>;
    let mut next_header = 0usize;
    let mut current_diff = String::new();
    let mut ranges = BTreeMap::new();
    for line in output.lines() {
        if next_header < candidates.len() && line == candidates[next_header].commit.as_str() {
            if let Some(index) = current_index.replace(next_header) {
                let parsed = parse_unified_ranges(&current_diff, old_side)?;
                ranges.insert(candidates[index].commit.clone(), parsed);
                current_diff.clear();
            }
            next_header += 1;
            continue;
        }
        let Some(index) = current_index else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git diff-tree patch output began before the expected commit header: {line:?}"
                ),
            ));
        };
        if is_oid(line) {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git diff-tree patch output for commit {} emitted unexpected commit-like header {line}",
                    candidates[index].commit
                ),
            ));
        }
        current_diff.push_str(line);
        current_diff.push('\n');
    }
    if let Some(index) = current_index {
        let parsed = parse_unified_ranges(&current_diff, old_side)?;
        ranges.insert(candidates[index].commit.clone(), parsed);
    }
    if next_header != candidates.len() {
        let expected = &candidates[next_header].commit;
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git diff-tree patch output did not include expected commit header {expected}"),
        ));
    }
    Ok(ranges)
}

/// Cheap changed-file count between `parent` and `commit`, limited to `pathspec`
/// (#434 mass-change cap). Uses `git diff --name-only`, a tree comparison with NO
/// content diff — so a mass-change commit (relocation, bulk delete) is detected in
/// milliseconds without ever generating the multi-hundred-thousand-line unified
/// diff that dominated the phase. Counts NUL-delimited paths (`-z`) so unusual
/// filenames never split a count.
fn changed_file_count(
    repo: &Path,
    parent: &str,
    commit: &str,
    pathspec: Option<&str>,
) -> Result<usize, ArchaeologyError> {
    let mut args = vec!["diff", "--name-only", "-z", parent, commit, "--"];
    if let Some(prefix) = pathspec {
        args.push(prefix);
    }
    let output = git_bytes(repo, &args)?;
    Ok(output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .count())
}

/// [`changed_file_count`] for a single commit versus its first parent — the
/// counterpart to [`changed_new_ranges_impl`], used to cap a bulk revert TARGET
/// before its content diff (#434). A root commit (no parent) counts as 0.
///
/// Public (#440) so the server's `run_git_archaeology` can pre-count a force-removed
/// commit before its whole-commit `changed_new_ranges` diff, applying the same
/// mass-change cap the fix/revert paths already enforce. `pathspec` should mirror the
/// scope of the content diff it gates: pass `None` to count the WHOLE commit (matching
/// [`changed_new_ranges`], which is unscoped) so the count reflects the exact work
/// being gated.
pub fn changed_file_count_for_commit(
    repo: &Path,
    commit: &str,
    pathspec: Option<&str>,
) -> Result<usize, ArchaeologyError> {
    validate_oid(commit)?;
    let parents = git_text(repo, &["show", "-s", "--format=%P", commit])?;
    let Some(parent) = parents.split_whitespace().next() else {
        return Ok(0);
    };
    changed_file_count(repo, parent, commit, pathspec)
}

fn changed_ranges(
    repo: &Path,
    parent: &str,
    commit: &str,
    old_side: bool,
    pathspec: Option<&str>,
) -> Result<ChangedRanges, ArchaeologyError> {
    // The trailing `--` separates the two revisions from any pathspec. When a
    // member-subtree pathspec is supplied (#381) it is appended after `--`, so the
    // diff — and thus every range the SZZ/revert miners derive — is confined to the
    // requested corpus. Without it the diff spans the whole commit (whole-repo).
    let mut args = vec![
        "diff",
        "--unified=0",
        "--no-prefix",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        parent,
        commit,
        "--",
    ];
    if let Some(prefix) = pathspec {
        args.push(prefix);
    }
    let output = git_text(repo, &args)?;
    parse_unified_ranges(&output, old_side)
}

fn parse_unified_ranges(diff: &str, old_side: bool) -> Result<ChangedRanges, ArchaeologyError> {
    let mut path = None::<String>;
    // Per-file mode headers (#514): `index a..b <mode>` carries the mode only when
    // it did not change; a type change emits explicit `old mode`/`new mode` lines,
    // and creation/deletion emit `new file mode`/`deleted file mode`. The mined
    // side's mode decides whether the file is a gitlink (160000).
    let mut index_mode = None::<String>;
    let mut explicit_side_mode = None::<String>;
    let mut gitlink_counted = false;
    let mut skipped_gitlink_paths = 0usize;
    // Hunk-body extents (#514, the vibe-kanban forgery): after `@@ -a,b +c,d @@`
    // exactly b removed (`-`) and d added (`+`) lines follow (`--unified=0` emits
    // no context lines), optionally interleaved with `\ No newline at end of
    // file` markers. While any body line is still owed, NOTHING is a header — a
    // removed SQL comment `-- NOTE: …` renders as `--- NOTE: …` and would
    // otherwise be swallowed as a file path and handed to `git blame` as prose.
    let mut pending_old = 0u32;
    let mut pending_new = 0u32;
    let mut ranges = BTreeSet::new();
    for line in diff.lines() {
        if pending_old > 0 || pending_new > 0 {
            match line.as_bytes().first() {
                Some(b'-') if pending_old > 0 => pending_old -= 1,
                Some(b'+') if pending_new > 0 => pending_new -= 1,
                // "\ No newline at end of file" — a marker, not a counted line.
                Some(b'\\') => {}
                _ => {
                    return Err(ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!(
                            "Git hunk body ended early at {line:?} \
                             (still owed {pending_old} removed / {pending_new} added lines)"
                        ),
                    ));
                }
            }
            continue;
        }
        if line.strip_prefix("diff --git ").is_some() {
            path = None;
            index_mode = None;
            explicit_side_mode = None;
            gitlink_counted = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("index ") {
            // `index <oid>..<oid> <mode>` — the trailing mode is present only when
            // both sides share it.
            index_mode = rest.rsplit_once(' ').map(|(_, mode)| mode.to_string());
            continue;
        }
        let side_mode_prefix = if old_side {
            ["old mode ", "deleted file mode "]
        } else {
            ["new mode ", "new file mode "]
        };
        if let Some(mode) = side_mode_prefix
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        {
            explicit_side_mode = Some(mode.to_string());
            continue;
        }
        if let Some(raw) = line.strip_prefix("--- ") {
            path = Some(parse_diff_path(raw)?);
            continue;
        }
        if !old_side && let Some(raw) = line.strip_prefix("+++ ") {
            path = Some(parse_diff_path(raw)?);
            continue;
        }
        let Some(header) = line.strip_prefix("@@ -") else {
            continue;
        };
        let Some((old, remainder)) = header.split_once(" +") else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("malformed Git hunk header {line:?}"),
            ));
        };
        let Some((new, _)) = remainder.split_once(" @@") else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("malformed Git hunk header {line:?}"),
            ));
        };
        let (old_start, old_count) = parse_range(old)?;
        let (new_start, new_count) = parse_range(new)?;
        pending_old = old_count;
        pending_new = new_count;
        let (start_line, line_count) = if old_side {
            (old_start, old_count)
        } else {
            (new_start, new_count)
        };
        if line_count == 0 {
            continue;
        }
        let Some(path) = path.clone() else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                "Git hunk appeared before a file path",
            ));
        };
        if path == "/dev/null" {
            continue;
        }
        // Gitlink exclusion (#514): the mined side is a submodule pointer, not a
        // blob — `-Subproject commit …` is never line evidence and `git blame`
        // refuses the path. Counted once per file, never a silent drop.
        if explicit_side_mode.as_deref().or(index_mode.as_deref()) == Some("160000") {
            if !gitlink_counted {
                skipped_gitlink_paths += 1;
                gitlink_counted = true;
            }
            continue;
        }
        ranges.insert(GitLineRange {
            path,
            start_line,
            line_count,
        });
    }
    if pending_old > 0 || pending_new > 0 {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "Git diff ended mid-hunk \
                 (still owed {pending_old} removed / {pending_new} added lines)"
            ),
        ));
    }
    Ok(ChangedRanges {
        ranges: ranges.into_iter().collect(),
        skipped_gitlink_paths,
    })
}

fn parse_diff_path(raw: &str) -> Result<String, ArchaeologyError> {
    if raw == "/dev/null" {
        return Ok(raw.to_string());
    }
    // GNU-patch compatibility: git appends exactly one TAB after a `---`/`+++`
    // name that contains spaces, and neither `-z` nor `core.quotePath=false`
    // suppresses it (#496 — tauri's `…{{ plugin_name }}.xcodeproj/project.pbxproj`).
    let raw = raw.strip_suffix('\t').unwrap_or(raw);
    // `core.quotePath` quoting: names containing control bytes, `"`, `\` or (by
    // default) non-ASCII bytes are emitted as one C-quoted string covering the
    // whole path. Decode it losslessly instead of refusing well-formed reality;
    // malformed quoting still fails closed inside `unquote_c_style`.
    if let Some(quoted) = raw.strip_prefix('"') {
        let inner = quoted.strip_suffix('"').ok_or_else(|| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("unterminated quoted diff path {raw:?}"),
            )
        })?;
        return unquote_c_style(inner);
    }
    // An unquoted name can never carry raw control bytes — git would have quoted
    // them — so their presence means the output is malformed, not unusual.
    if raw.contains('\t') || raw.contains('\r') {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git emitted an unquoted control-character diff path {raw:?}"),
        ));
    }
    Ok(raw.to_string())
}

/// Decodes git's `core.quotePath` C-style quoting: the standard escapes
/// (`\a \b \t \n \v \f \r \" \\`) plus 1–3-digit octal byte escapes. Fails
/// closed on malformed escapes and on decoded bytes that are not valid UTF-8 —
/// the mined path must round-trip into `git blame`/pathspec arguments, which
/// this crate passes as UTF-8 strings.
fn unquote_c_style(inner: &str) -> Result<String, ArchaeologyError> {
    let mut bytes = Vec::with_capacity(inner.len());
    let mut input = inner.bytes().peekable();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let Some(escape) = input.next() else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("truncated escape in quoted diff path {inner:?}"),
            ));
        };
        match escape {
            b'a' => bytes.push(0x07),
            b'b' => bytes.push(0x08),
            b't' => bytes.push(b'\t'),
            b'n' => bytes.push(b'\n'),
            b'v' => bytes.push(0x0b),
            b'f' => bytes.push(0x0c),
            b'r' => bytes.push(b'\r'),
            b'"' => bytes.push(b'"'),
            b'\\' => bytes.push(b'\\'),
            b'0'..=b'7' => {
                let mut value = u32::from(escape - b'0');
                for _ in 0..2 {
                    let Some(&digit) = input.peek() else { break };
                    if !(b'0'..=b'7').contains(&digit) {
                        break;
                    }
                    value = value * 8 + u32::from(digit - b'0');
                    input.next();
                }
                if value > 0xFF {
                    return Err(ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!("octal escape out of byte range in quoted diff path {inner:?}"),
                    ));
                }
                bytes.push(value as u8);
            }
            other => {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "unsupported escape \\{} in quoted diff path {inner:?}",
                        char::from(other)
                    ),
                ));
            }
        }
    }
    String::from_utf8(bytes).map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "quoted diff path decodes to non-UTF-8 bytes {:?} (from {inner:?})",
                error.as_bytes()
            ),
        )
    })
}

fn parse_range(raw: &str) -> Result<(u32, u32), ArchaeologyError> {
    let (start, count) = raw.split_once(',').unwrap_or((raw, "1"));
    let start = start.parse::<u32>().map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("invalid Git hunk start {raw:?}: {error}"),
        )
    })?;
    let count = count.parse::<u32>().map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("invalid Git hunk count {raw:?}: {error}"),
        )
    })?;
    Ok((start, count))
}

/// Verified output from one grouped blame leg.
struct BlameOutcome {
    findings: Vec<(String, u32)>,
    returned_spans: usize,
    stdout_bytes: u64,
}

fn coalesce_blame_ranges(
    path: &str,
    requested: &[GitLineRange],
) -> Result<Vec<GitLineRange>, ArchaeologyError> {
    if requested.is_empty() {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git blame range group for {path:?} is empty"),
        ));
    }
    let mut spans = requested
        .iter()
        .map(|range| {
            if range.path != path || range.start_line == 0 || range.line_count == 0 {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "Git blame range group {path:?} contains invalid range path={:?} start={} count={}",
                        range.path, range.start_line, range.line_count
                    ),
                ));
            }
            let end = range
                .start_line
                .checked_add(range.line_count - 1)
                .ok_or_else(|| {
                    ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!(
                            "Git blame range for {path:?} overflows u32: start={} count={}",
                            range.start_line, range.line_count
                        ),
                    )
                })?;
            Ok((range.start_line, end))
        })
        .collect::<Result<Vec<_>, ArchaeologyError>>()?;
    spans.sort_unstable();

    let mut merged = Vec::<(u32, u32)>::new();
    for (start, end) in spans {
        match merged.last_mut() {
            Some((_, prior_end)) if start <= prior_end.saturating_add(1) => {
                *prior_end = (*prior_end).max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    merged
        .into_iter()
        .map(|(start, end)| {
            let line_count = end
                .checked_sub(start)
                .and_then(|span| span.checked_add(1))
                .ok_or_else(|| {
                    ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!("coalesced Git blame range for {path:?} overflowed u32"),
                    )
                })?;
            Ok(GitLineRange {
                path: path.to_string(),
                start_line: start,
                line_count,
            })
        })
        .collect()
}

fn execute_grouped_blame_plan(
    repo: &Path,
    requests: &[PendingBlameRequest],
    telemetry: &mut GitBlameBatchTelemetry,
    szz: &mut BTreeSet<SzzFinding>,
) -> Result<(), ArchaeologyError> {
    if requests.is_empty() {
        return Ok(());
    }
    let mut groups = BTreeMap::<(String, String), BlamePlanGroup>::new();
    for (request_index, request) in requests.iter().enumerate() {
        if request.ranges.is_empty() {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "pending Git blame request for fix commit {} parent {} path {:?} has no ranges",
                    request.fix_commit, request.parent, request.path
                ),
            ));
        }
        let group = groups
            .entry((request.parent.clone(), request.path.clone()))
            .or_default();
        group.request_indexes.push(request_index);
        group.ranges.extend(request.ranges.iter().cloned());
    }
    checked_add_usize(
        &mut telemetry.groups,
        groups.len(),
        "Git blame grouped parent/path telemetry overflowed usize",
    )?;
    let avoided = requests.len().saturating_sub(groups.len());
    checked_add_usize(
        &mut telemetry.group_cache_hits,
        avoided,
        "Git blame group-cache-hit telemetry overflowed usize",
    )?;
    checked_add_usize(
        &mut telemetry.processes_avoided,
        avoided,
        "Git blame avoided-process telemetry overflowed usize",
    )?;

    let mut preflight = preflight_blame_targets(repo, &groups, telemetry)?;
    for ((parent, path), group) in groups {
        let _preflight = preflight
            .remove(&(parent.clone(), path.clone()))
            .ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git blame preflight omitted parent {parent} path {path:?}"),
                )
            })?;

        let effective = coalesce_blame_ranges(&path, &group.ranges)?;
        checked_add_usize(
            &mut telemetry.effective_ranges,
            effective.len(),
            "Git blame effective-range telemetry overflowed usize",
        )?;
        let blame_start = std::time::Instant::now();
        let outcome = blame_ranges(repo, &parent, &path, &effective)?;
        telemetry.wall_ms = telemetry
            .wall_ms
            .saturating_add(elapsed_u64_ms(blame_start.elapsed()));
        checked_add_usize(
            &mut telemetry.processes,
            1,
            "Git blame process telemetry overflowed usize",
        )?;
        let BlameOutcome {
            findings,
            returned_spans,
            stdout_bytes,
        } = outcome;
        checked_add_usize(
            &mut telemetry.returned_spans,
            returned_spans,
            "Git blame returned-span telemetry overflowed usize",
        )?;
        checked_add_usize(
            &mut telemetry.returned_lines,
            findings.len(),
            "Git blame returned-line telemetry overflowed usize",
        )?;
        checked_add_u64(
            &mut telemetry.stdout_bytes,
            stdout_bytes,
            "Git blame stdout-byte telemetry overflowed u64",
        )?;

        for request_index in group.request_indexes {
            let request = &requests[request_index];
            for (blamed_commit, line) in &findings {
                if line_is_in_ranges(&request.path, *line, &request.ranges)? {
                    szz.insert(SzzFinding {
                        fix_commit: request.fix_commit.clone(),
                        blamed_commit: blamed_commit.clone(),
                        path: request.path.clone(),
                        line: *line,
                        observed_at: request.observed_at,
                        confidence: request.confidence,
                    });
                }
            }
        }
    }
    if !preflight.is_empty() {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "Git blame preflight returned {} unexpected parent/path records",
                preflight.len()
            ),
        ));
    }
    Ok(())
}

fn line_is_in_ranges(
    path: &str,
    line: u32,
    ranges: &[GitLineRange],
) -> Result<bool, ArchaeologyError> {
    for range in ranges {
        if range.path != path || range.start_line == 0 || range.line_count == 0 {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git blame fanout range group {path:?} contains invalid range path={:?} start={} count={}",
                    range.path, range.start_line, range.line_count
                ),
            ));
        }
        let end = range
            .start_line
            .checked_add(range.line_count - 1)
            .ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "Git blame fanout range for {path:?} overflows u32: start={} count={}",
                        range.start_line, range.line_count
                    ),
                )
            })?;
        if range.start_line <= line && line <= end {
            return Ok(true);
        }
    }
    Ok(false)
}

fn preflight_blame_targets(
    repo: &Path,
    groups: &BTreeMap<(String, String), BlamePlanGroup>,
    telemetry: &mut GitBlameBatchTelemetry,
) -> Result<BTreeMap<(String, String), BlameTargetPreflight>, ArchaeologyError> {
    let mut states = BTreeMap::new();
    let keys = groups.keys().cloned().collect::<Vec<_>>();
    for chunk in keys.chunks(BLAME_CAT_FILE_BATCH_GROUPS) {
        let mut input = Vec::new();
        for (parent, path) in chunk {
            validate_oid(parent)?;
            if path.as_bytes().contains(&0) {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git path for blame preflight contains NUL: {path:?}"),
                ));
            }
            input.extend_from_slice(b"info ");
            input.extend_from_slice(parent.as_bytes());
            input.push(b':');
            input.extend_from_slice(path.as_bytes());
            input.push(0);
        }
        input.extend_from_slice(b"flush");
        input.push(0);
        let start = std::time::Instant::now();
        let output = git_with_stdin(
            repo,
            &["cat-file", "--batch-command", "--buffer", "-Z"],
            &input,
        )?;
        telemetry.cat_file_wall_ms = telemetry
            .cat_file_wall_ms
            .saturating_add(elapsed_u64_ms(start.elapsed()));
        checked_add_usize(
            &mut telemetry.cat_file_processes,
            1,
            "Git cat-file blame-preflight process telemetry overflowed usize",
        )?;
        checked_add_u64(
            &mut telemetry.cat_file_stdout_bytes,
            u64::try_from(output.len()).map_err(|_| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git cat-file blame-preflight stdout length cannot be represented as u64",
                )
            })?,
            "Git cat-file blame-preflight stdout-byte telemetry overflowed u64",
        )?;
        let mut records = output.split(|byte| *byte == 0).collect::<Vec<_>>();
        while records.last().is_some_and(|record| record.is_empty()) {
            records.pop();
        }
        if records.len() != chunk.len() {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git cat-file blame preflight returned {} records for {} requested parent/path groups",
                    records.len(),
                    chunk.len()
                ),
            ));
        }
        for ((parent, path), record) in chunk.iter().zip(records) {
            let state = parse_blame_target_preflight_record(parent, path, record)?;
            if states
                .insert((parent.clone(), path.clone()), state)
                .is_some()
            {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("duplicate Git blame preflight parent/path group {parent}:{path:?}"),
                ));
            }
        }
    }
    Ok(states)
}

fn parse_blame_target_preflight_record(
    parent: &str,
    path: &str,
    record: &[u8],
) -> Result<BlameTargetPreflight, ArchaeologyError> {
    let record = std::str::from_utf8(record).map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git cat-file blame preflight output is not UTF-8: {error}"),
        )
    })?;
    if record == format!("{parent}:{path} missing") {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OBJECT_VIEW_INCONSISTENT,
            format!(
                "Git cat-file could not resolve old-side blame target parent {parent} path {path:?}; the diff and parent-tree object views disagree"
            ),
        ));
    }
    let mut fields = record.split(' ');
    let resolved_oid = fields.next().unwrap_or_default();
    let object_type = fields.next().unwrap_or_default();
    let size = fields.next().unwrap_or_default();
    if fields.next().is_some() || !is_oid(resolved_oid) {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "Git cat-file blame preflight returned malformed output for parent {parent} path {path:?}: {record:?}"
            ),
        ));
    }
    if object_type != "blob" {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OBJECT_VIEW_INCONSISTENT,
            format!(
                "Git old-side blame target parent {parent} path {path:?} resolved to object {resolved_oid} of type {object_type:?}, not a blob"
            ),
        ));
    }
    size.parse::<u64>().map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "Git cat-file blame preflight returned invalid blob size for parent {parent} path {path:?}: {size:?}: {error}"
            ),
        )
    })?;
    Ok(BlameTargetPreflight)
}

fn checked_add_usize(
    slot: &mut usize,
    value: usize,
    message: &'static str,
) -> Result<(), ArchaeologyError> {
    *slot = slot
        .checked_add(value)
        .ok_or_else(|| ArchaeologyError::new(ASTRO_ARCHAEOLOGY_OUTPUT_INVALID, message))?;
    Ok(())
}

fn checked_add_u64(
    slot: &mut u64,
    value: u64,
    message: &'static str,
) -> Result<(), ArchaeologyError> {
    *slot = slot
        .checked_add(value)
        .ok_or_else(|| ArchaeologyError::new(ASTRO_ARCHAEOLOGY_OUTPUT_INVALID, message))?;
    Ok(())
}

fn blame_ranges(
    repo: &Path,
    parent: &str,
    path: &str,
    ranges: &[GitLineRange],
) -> Result<BlameOutcome, ArchaeologyError> {
    if ranges.is_empty() {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git blame range group for {path:?} is empty"),
        ));
    }
    let mut owned_args = vec!["blame".to_string(), "--incremental".to_string()];
    for range in ranges {
        if range.path != path || range.start_line == 0 || range.line_count == 0 {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!(
                    "Git blame range group {path:?} contains invalid effective range path={:?} start={} count={}",
                    range.path, range.start_line, range.line_count
                ),
            ));
        }
        owned_args.push("-L".to_string());
        owned_args.push(format!("{},+{}", range.start_line, range.line_count));
    }
    owned_args.push(parent.to_string());
    owned_args.push("--".to_string());
    owned_args.push(path.to_string());
    let args = owned_args.iter().map(String::as_str).collect::<Vec<_>>();
    let raw = git_command(repo, &args)
        .output()
        .map_err(|error| git_spawn_error(&args, error))?;
    if !raw.status.success() {
        if String::from_utf8_lossy(&raw.stderr).contains("no such path") {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OBJECT_VIEW_INCONSISTENT,
                format!(
                    "Git cat-file proved old-side target parent {parent} path {path:?} is a blob, but grouped blame could not resolve the same target: {}",
                    String::from_utf8_lossy(&raw.stderr).trim()
                ),
            ));
        }
        return Err(git_exit_error(&args, raw.status.code(), &raw.stderr));
    }
    let stdout_bytes = u64::try_from(raw.stdout.len()).map_err(|_| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            "Git blame stdout length cannot be represented as u64",
        )
    })?;
    let output = String::from_utf8(raw.stdout).map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git output is not UTF-8: {error}"),
        )
    })?;
    let allowed_lines = ranges
        .iter()
        .map(|range| {
            let end = range
                .start_line
                .checked_add(range.line_count - 1)
                .ok_or_else(|| {
                    ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!("effective Git blame range for {path:?} overflows u32"),
                    )
                })?;
            Ok((range.start_line, end))
        })
        .collect::<Result<Vec<_>, ArchaeologyError>>()?;
    let mut findings = BTreeSet::new();
    let mut pending: Option<(String, u32, u32)> = None;
    let mut returned_spans = 0usize;
    for (line_index, line) in output.lines().enumerate() {
        if pending.is_none() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 4 || !is_oid(fields[0]) {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "Git incremental blame entry {} for {path:?} has invalid header {line:?}",
                        line_index + 1
                    ),
                ));
            }
            let source_line = parse_blame_u32(fields[1], "source line", path, line_index)?;
            let result_line = parse_blame_u32(fields[2], "result line", path, line_index)?;
            let count = parse_blame_u32(fields[3], "line count", path, line_index)?;
            if source_line == 0 || result_line == 0 || count == 0 {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!(
                        "Git incremental blame header for {path:?} contains a zero source/result/count: {line:?}"
                    ),
                ));
            }
            let _ = source_line.checked_add(count - 1).ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git incremental blame source span for {path:?} overflows u32"),
                )
            })?;
            let _ = result_line.checked_add(count - 1).ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git incremental blame result span for {path:?} overflows u32"),
                )
            })?;
            pending = Some((fields[0].to_string(), result_line, count));
            continue;
        }
        if let Some(filename) = line.strip_prefix("filename ") {
            if filename.is_empty() {
                return Err(ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("Git incremental blame entry for {path:?} has an empty filename"),
                ));
            }
            let (oid, result_line, count) = pending.take().expect("pending entry checked");
            for offset in 0..count {
                let line = result_line.checked_add(offset).ok_or_else(|| {
                    ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!(
                            "Git incremental blame result expansion for {path:?} overflowed u32"
                        ),
                    )
                })?;
                if !allowed_lines
                    .iter()
                    .any(|(start, end)| *start <= line && line <= *end)
                {
                    return Err(ArchaeologyError::new(
                        ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                        format!(
                            "Git incremental blame returned result line {line} outside the requested union for {path:?}"
                        ),
                    ));
                }
                findings.insert((oid.clone(), line));
            }
            returned_spans = returned_spans.checked_add(1).ok_or_else(|| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    "Git blame returned-span count overflowed usize",
                )
            })?;
        } else if line.is_empty() {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("Git incremental blame entry for {path:?} contains an empty metadata line"),
            ));
        }
        // Git explicitly permits new tagged metadata. Unknown nonempty tags are
        // ignored until the mandatory `filename` terminator.
    }
    if pending.is_some() {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git incremental blame output for {path:?} ended before `filename`"),
        ));
    }
    if returned_spans == 0 {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git incremental blame returned no entries for non-empty ranges on {path:?}"),
        ));
    }
    Ok(BlameOutcome {
        findings: findings.into_iter().collect(),
        returned_spans,
        stdout_bytes,
    })
}

fn parse_blame_u32(
    value: &str,
    field: &str,
    path: &str,
    zero_based_line_index: usize,
) -> Result<u32, ArchaeologyError> {
    value.parse::<u32>().map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "Git incremental blame {field} at output line {} for {path:?} is invalid: {value:?}: {error}",
                zero_based_line_index + 1
            ),
        )
    })
}

fn elapsed_u64_ms(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn read_commits(
    repo: &Path,
    config: &GitArchaeologyConfig,
    range: Option<&str>,
) -> Result<Vec<CommitRecord>, ArchaeologyError> {
    let max_count = format!("--max-count={}", config.max_count);
    let since = format!("--since={}", config.since);
    let mut args = vec![
        "log",
        "--reverse",
        "--topo-order",
        "--format=%H%x00%P%x00%ct%x00%B%x00",
    ];
    args.push(&max_count);
    if range.is_none() {
        args.push(&since);
    }
    if let Some(range) = range {
        args.push(range);
    }
    // Member-subtree pathspec (#381): restrict the fix/revert commit walk to
    // commits that touched the requested corpus. Placed after `--` so it is an
    // unambiguous pathspec, never confused with a revision. Absent for a
    // whole-repo corpus, so the walk stays byte-identical there.
    if let Some(prefix) = config.member_prefix.as_deref() {
        args.push("--");
        args.push(prefix);
    }
    let output = git_bytes(repo, &args)?;
    let fields = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut commits = Vec::new();
    for chunk in fields.chunks(4) {
        if chunk.len() < 4 || chunk[0].iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let sha = utf8_trim(chunk[0])?;
        validate_oid(&sha)?;
        let parents = utf8_trim(chunk[1])?
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let timestamp = utf8_trim(chunk[2])?.parse::<u64>().map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("invalid commit timestamp: {error}"),
            )
        })?;
        let message = std::str::from_utf8(chunk[3])
            .map_err(|error| {
                ArchaeologyError::new(
                    ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                    format!("commit message is not UTF-8: {error}"),
                )
            })?
            .trim()
            .to_string();
        commits.push(CommitRecord {
            sha,
            parents,
            timestamp,
            message,
        });
    }
    Ok(commits)
}

fn classify_fix_confidence(message: &str, config: &GitArchaeologyConfig) -> Option<f32> {
    let lower = message.to_ascii_lowercase();
    let words = lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect::<BTreeSet<_>>();
    let keyword_hits = config
        .fix_keywords
        .iter()
        .filter(|keyword| words.contains(keyword.to_ascii_lowercase().as_str()))
        .count();
    let issue_hit = config
        .issue_markers
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()));
    if keyword_hits == 0 && !issue_hit {
        return None;
    }
    let strong = words.contains("bug") || words.contains("hotfix");
    Some(if (keyword_hits > 0 && issue_hit) || strong {
        0.9
    } else if issue_hit || keyword_hits > 1 {
        0.8
    } else {
        0.7
    })
}

/// Outcome of scanning a commit message for a canonical revert reference.
enum RevertTarget {
    /// No "This reverts commit" line in the message.
    Absent,
    /// The first revert line named a full 40/64-hex object id. Any prose after
    /// the id — git's own trailing `.`, the ` (#NNNN)` suffix GitHub squash
    /// merges fold into the line (#496 — uv's `(#19890)`) — is opaque.
    Oid(String),
    /// A revert line was present but named no full object id (abbreviated,
    /// truncated, or reworded by hand). Commit messages are prose, not machine
    /// output: this is a counted skip, never a fatal refusal.
    Unparseable,
}

fn canonical_revert_target(message: &str) -> RevertTarget {
    for line in message.lines() {
        let Some(value) = line.trim().strip_prefix("This reverts commit ") else {
            continue;
        };
        let hex_len = value.bytes().take_while(u8::is_ascii_hexdigit).count();
        if matches!(hex_len, 40 | 64) {
            return RevertTarget::Oid(value[..hex_len].to_string());
        }
        return RevertTarget::Unparseable;
    }
    RevertTarget::Absent
}

fn revert_patch_matches(repo: &Path, target: &str, revert: &str) -> Result<bool, ArchaeologyError> {
    let target_parent = git_text(repo, &["show", "-s", "--format=%P", target])?;
    let revert_parent = git_text(repo, &["show", "-s", "--format=%P", revert])?;
    let Some(target_parent) = target_parent.split_whitespace().next() else {
        return Ok(false);
    };
    let Some(revert_parent) = revert_parent.split_whitespace().next() else {
        return Ok(false);
    };
    let target_patch = git_bytes(repo, &["diff", "--binary", target_parent, target, "--"])?;
    let reverse_revert_patch = git_bytes(repo, &["diff", "--binary", revert, revert_parent, "--"])?;
    let target_id = patch_id(repo, &target_patch)?;
    let reverse_id = patch_id(repo, &reverse_revert_patch)?;
    Ok(!target_id.is_empty() && target_id == reverse_id)
}

fn patch_id(repo: &Path, patch: &[u8]) -> Result<String, ArchaeologyError> {
    let output = git_with_stdin(repo, &["patch-id", "--stable"], patch)?;
    Ok(String::from_utf8(output)
        .map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("patch-id output is not UTF-8: {error}"),
            )
        })?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string())
}

fn oid_lines(bytes: &[u8]) -> Result<Vec<String>, ArchaeologyError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("Git OID list is not UTF-8: {error}"),
            )
        })?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let oid = line.trim().to_string();
            validate_oid(&oid)?;
            Ok(oid)
        })
        .collect()
}

fn utf8_trim(bytes: &[u8]) -> Result<String, ArchaeologyError> {
    Ok(std::str::from_utf8(bytes)
        .map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("Git output is not UTF-8: {error}"),
            )
        })?
        .trim()
        .to_string())
}

fn validate_oid(oid: &str) -> Result<(), ArchaeologyError> {
    if is_oid(oid) {
        Ok(())
    } else {
        Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("invalid Git object id {oid:?}"),
        ))
    }
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Resolves an exact object id as a commit through Git's documented batch
/// protocol. `cat-file -e` promises only zero versus nonzero, so its numeric
/// failure status cannot distinguish an unavailable object from a command
/// failure. Batch mode represents expected absence as a successful, explicit
/// `<query> missing` record while real child failures remain errors.
fn git_commit_exists(repo: &Path, oid: &str) -> Result<bool, ArchaeologyError> {
    validate_oid(oid)?;
    let query = format!("{oid}^{{commit}}");
    let input = format!("{query}\n");
    let output = git_with_stdin(
        repo,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input.as_bytes(),
    )?;
    let text = String::from_utf8(output).map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("cat-file --batch-check output is not UTF-8: {error}"),
        )
    })?;
    let record = text.strip_suffix('\n').ok_or_else(|| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("cat-file --batch-check omitted the record terminator for {query:?}: {text:?}"),
        )
    })?;
    let record = record.strip_suffix('\r').unwrap_or(record);
    if record.contains('\r') || record.contains('\n') {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("cat-file --batch-check returned multiple records for {query:?}: {text:?}"),
        ));
    }
    if record == format!("{query} missing") {
        return Ok(false);
    }

    let mut fields = record.split(' ');
    let resolved_oid = fields.next().unwrap_or_default();
    let object_type = fields.next().unwrap_or_default();
    if fields.next().is_some() || object_type != "commit" || !is_oid(resolved_oid) {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!(
                "cat-file --batch-check returned an invalid commit-existence record for {query:?}: {record:?}"
            ),
        ));
    }
    Ok(true)
}

fn git_status(repo: &Path, args: &[&str]) -> Result<bool, ArchaeologyError> {
    let output = git_command(repo, args)
        .output()
        .map_err(|error| git_spawn_error(args, error))?;
    match output.status.code() {
        Some(0) => Ok(true),
        // Every predicate routed here documents exit 1 as false:
        // `merge-base --is-ancestor` for a non-ancestor and
        // `show-ref --verify --quiet` for a missing ref.
        // Every other exit is a Git fault, not a false predicate.
        Some(1) => Ok(false),
        _ => Err(git_exit_error(args, output.status.code(), &output.stderr)),
    }
}

/// Uses Git's exact ref-existence protocol. Unlike `show-ref --verify`, the
/// `--exists` form distinguishes an absent ref (2) from a lookup fault (1).
fn git_ref_exists(repo: &Path, reference: &str) -> Result<bool, ArchaeologyError> {
    let args = ["show-ref", "--exists", reference];
    let output = git_command(repo, &args)
        .output()
        .map_err(|error| git_spawn_error(&args, error))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        _ => Err(git_exit_error(&args, output.status.code(), &output.stderr)),
    }
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String, ArchaeologyError> {
    String::from_utf8(git_bytes(repo, args)?).map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git output is not UTF-8: {error}"),
        )
    })
}

/// Runs a Git query whose documented exit 1 means that the requested value is
/// absent. Every other nonzero exit remains a command fault with full diagnostics.
fn git_optional_text(repo: &Path, args: &[&str]) -> Result<Option<String>, ArchaeologyError> {
    let output = git_command(repo, args)
        .output()
        .map_err(|error| git_spawn_error(args, error))?;
    match output.status.code() {
        Some(0) => String::from_utf8(output.stdout).map(Some).map_err(|error| {
            ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                format!("Git output is not UTF-8: {error}"),
            )
        }),
        Some(1) => Ok(None),
        _ => Err(git_exit_error(args, output.status.code(), &output.stderr)),
    }
}

fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, ArchaeologyError> {
    let output = git_command(repo, args)
        .output()
        .map_err(|error| git_spawn_error(args, error))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(git_exit_error(args, output.status.code(), &output.stderr))
    }
}

fn git_with_stdin(repo: &Path, args: &[&str], stdin: &[u8]) -> Result<Vec<u8>, ArchaeologyError> {
    use std::io::Write;
    let mut child = git_command(repo, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| git_spawn_error(args, error))?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            ArchaeologyError::new(ASTRO_ARCHAEOLOGY_GIT_FAILED, "Git stdin was unavailable")
        })?
        .write_all(stdin)
        .map_err(|error| git_spawn_error(args, error))?;
    let output = child
        .wait_with_output()
        .map_err(|error| git_spawn_error(args, error))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(git_exit_error(args, output.status.code(), &output.stderr))
    }
}

fn git_command(repo: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    // Locale-stable stderr (#514): the blame containment classifies an absent
    // parent-side path by matching git's English message `fatal: no such path
    // <p> in <rev>`. Git localizes its `die(_())` diagnostics from
    // `share/locale`, so under a translated host locale (`LANG`/`LC_ALL` set)
    // that substring would not match and the counted skip would regress to the
    // fail-closed `ASTRO_ARCHAEOLOGY_GIT_FAILED` this issue fixes. Force the C
    // locale for every git child so the message contract holds on any host;
    // `LC_ALL` overrides any ambient `LANG`/`LC_*`. Path bytes are emitted
    // verbatim regardless of locale, so this does not alter mined ranges.
    command.env("LC_ALL", "C");
    // Every archaeology/freshness child is observational. Prevent commands such
    // as `git status` from taking the optional index refresh lock or rewriting
    // cached stat data; several Astrolabe clients may inspect distinct projects
    // concurrently, and a source fingerprint must never mutate its source of truth.
    command.env("GIT_OPTIONAL_LOCKS", "0");
    // Git archaeology is a non-interactive child of a long-lived JSON-RPC
    // server. `Command::status()` inherits stdin by default, which bound the
    // incremental `merge-base --is-ancestor` predicate to the MCP transport on
    // native Windows and kept Git alive until the client closed the session
    // (#830). No archaeology query consumes transport input: attach the null
    // stream explicitly. `git_with_stdin` overrides this one setting with its
    // intentional, finite patch pipe.
    command.stdin(Stdio::null());
    command.arg("--no-replace-objects").arg("-C").arg(repo);
    command.args(args);
    command
}

fn git_spawn_error(args: &[&str], error: std::io::Error) -> ArchaeologyError {
    ArchaeologyError::new(
        ASTRO_ARCHAEOLOGY_GIT_FAILED,
        format!("failed to spawn git {args:?}: {error}"),
    )
}

fn git_exit_error(args: &[&str], exit_code: Option<i32>, stderr: &[u8]) -> ArchaeologyError {
    ArchaeologyError::new(
        ASTRO_ARCHAEOLOGY_GIT_FAILED,
        format!(
            "Git child failed: phase=command_wait args={args:?} exit_code={exit_code:?} stderr={}",
            String::from_utf8_lossy(stderr).trim()
        ),
    )
}
