//! Shell-free Git archaeology mining for bug-touch and revert anchors.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Stable failure code for invalid archaeology configuration.
pub const ASTRO_ARCHAEOLOGY_CONFIG_INVALID: &str = "ASTRO_ARCHAEOLOGY_CONFIG_INVALID";
/// Stable failure code for a failed or malformed Git query.
pub const ASTRO_ARCHAEOLOGY_GIT_FAILED: &str = "ASTRO_ARCHAEOLOGY_GIT_FAILED";
/// Stable failure code for Git output that cannot be interpreted safely.
pub const ASTRO_ARCHAEOLOGY_OUTPUT_INVALID: &str = "ASTRO_ARCHAEOLOGY_OUTPUT_INVALID";

const REMEDIATION: &str =
    "verify the repository and Git objects, then rerun archaeology with a validated configuration";

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
}

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
        {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_CONFIG_INVALID,
                "Git archaeology configuration is empty, unbounded, or non-ASCII",
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

/// Deterministic result of one mining pass.
#[derive(Debug, Clone, PartialEq)]
pub struct GitArchaeologyReport {
    pub head: String,
    pub szz_findings: Vec<SzzFinding>,
    pub revert_findings: Vec<RevertFinding>,
    /// Commits that became unreachable from the tracked head after a force move.
    pub force_removed_commits: Vec<String>,
    /// Fix-like merge commits skipped rather than blending parent histories.
    pub skipped_merge_fixes: usize,
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

/// Mines the configured Git history using native argv-only child processes.
pub fn mine_git_archaeology(
    repo: &Path,
    config: &GitArchaeologyConfig,
    mode: &GitMineMode,
) -> Result<GitArchaeologyReport, ArchaeologyError> {
    config.validate()?;
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
    let head = git_text(repo, &["rev-parse", "--verify", "HEAD"])?
        .trim()
        .to_string();
    validate_oid(&head)?;

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
                let mut args =
                    vec!["rev-list", "--reverse", previous_head.as_str(), "--not", head.as_str()];
                if let Some(prefix) = pathspec {
                    args.push("--");
                    args.push(prefix);
                }
                oid_lines(&git_bytes(repo, &args)?)?
            };
            (Some(format!("{previous_head}..{head}")), removed)
        }
    };

    let commits = read_commits(repo, config, range.as_deref())?;
    let mut szz = BTreeSet::new();
    let mut reverts = BTreeSet::new();
    let mut skipped_merge_fixes = 0usize;
    for commit in commits {
        if let Some(target) = canonical_revert_target(&commit.message) {
            validate_oid(&target)?;
            if git_status(repo, &["cat-file", "-e", &format!("{target}^{{commit}}")])?
                && revert_patch_matches(repo, &target, &commit.sha)?
            {
                for target_range in changed_new_ranges_impl(repo, &target, pathspec)? {
                    reverts.insert(RevertFinding {
                        revert_commit: commit.sha.clone(),
                        target_commit: target.clone(),
                        target_range,
                        observed_at: commit.timestamp,
                    });
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
        for range in changed_old_ranges(repo, parent, &commit.sha, pathspec)? {
            for (blamed_commit, line) in blame_range(repo, parent, &range)? {
                szz.insert(SzzFinding {
                    fix_commit: commit.sha.clone(),
                    blamed_commit,
                    path: range.path.clone(),
                    line,
                    observed_at: commit.timestamp,
                    confidence,
                });
            }
        }
    }
    Ok(GitArchaeologyReport {
        head,
        szz_findings: szz.into_iter().collect(),
        revert_findings: reverts.into_iter().collect(),
        force_removed_commits,
        skipped_merge_fixes,
    })
}

/// Resolves and validates the repository's current immutable object id.
pub fn git_head(repo: &Path) -> Result<String, ArchaeologyError> {
    let head = git_text(repo, &["rev-parse", "--verify", "HEAD"])?
        .trim()
        .to_string();
    validate_oid(&head)?;
    Ok(head)
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
/// Self-describing version tag for the git source fingerprint (#347).
pub const GIT_SOURCE_FINGERPRINT_VERSION: &str = "v1";

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
/// * the tracked content diff vs HEAD (catches a content-only edit that leaves the
///   porcelain flag unchanged), and
/// * the bytes of each untracked, non-ignored file (catches new-file content).
///
/// The returned value is `blake3:v1:<hex>` — self-describing so a persisted watermark
/// can be domain-gated exactly like the CBM-db watermark. Fails closed with a coded
/// error when `repo` is not a usable git repository (so a missing/renamed source tree
/// is reported, never silently treated as Fresh).
pub fn git_source_fingerprint(repo: &Path) -> Result<String, ArchaeologyError> {
    // HEAD oid, or an explicit unborn-branch marker for a repo with no commit yet.
    // Any spawn/exit failure here is tolerated and disambiguated by the mandatory
    // `git status` below: a non-repository fails that call fail-closed.
    let head = match git_text(repo, &["rev-parse", "--verify", "HEAD"]) {
        Ok(text) => {
            let head = text.trim().to_string();
            validate_oid(&head)?;
            head
        }
        Err(_) => "unborn-head".to_string(),
    };
    // NUL-delimited machine status over all untracked files. This is the fail-closed
    // gate: it errors if `repo` is not a git repository, so we never fingerprint a
    // non-source directory as if it were fresh.
    let status = git_bytes(
        repo,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    // Tracked content changes vs HEAD (staged + unstaged). Empty on an unborn head or a
    // clean tree; a content-only re-edit still moves these bytes.
    let diff =
        git_bytes(repo, &["diff", "HEAD", "--no-color", "--no-ext-diff"]).unwrap_or_default();
    // Untracked, non-ignored paths (NUL-delimited). Their current bytes are folded in so
    // a brand-new file's content — not just its presence — participates in the digest.
    let untracked = git_bytes(repo, &["ls-files", "--others", "--exclude-standard", "-z"])?;

    let mut hasher = blake3::Hasher::new();
    let mut section = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    section(GIT_SOURCE_FINGERPRINT_VERSION.as_bytes());
    section(head.as_bytes());
    section(&status);
    section(&diff);
    for path in untracked.split(|byte| *byte == 0).filter(|p| !p.is_empty()) {
        section(path);
        let rel = String::from_utf8_lossy(path);
        match std::fs::read(repo.join(rel.as_ref())) {
            Ok(bytes) => section(&bytes),
            // A path git listed but we cannot read (race: deleted between listing and
            // read, or permissions) is folded in as a stable absence marker rather than
            // aborting: the next status call reflects the real state, and the marker
            // still differs from the file being present with content.
            Err(_) => section(b"<unreadable-untracked>"),
        }
    }
    Ok(format!(
        "{GIT_SOURCE_FINGERPRINT_ALGO}:{GIT_SOURCE_FINGERPRINT_VERSION}:{}",
        hasher.finalize().to_hex()
    ))
}

/// Returns the new-side ranges introduced by `commit` for exact version lookup.
pub fn changed_new_ranges(
    repo: &Path,
    commit: &str,
) -> Result<Vec<GitLineRange>, ArchaeologyError> {
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
) -> Result<Vec<GitLineRange>, ArchaeologyError> {
    validate_oid(commit)?;
    let parents = git_text(repo, &["show", "-s", "--format=%P", commit])?;
    let Some(parent) = parents.split_whitespace().next() else {
        return Ok(Vec::new());
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
) -> Result<Vec<GitLineRange>, ArchaeologyError> {
    validate_oid(old)?;
    validate_oid(new)?;
    changed_ranges(repo, old, new, false, None)
}

fn changed_old_ranges(
    repo: &Path,
    parent: &str,
    commit: &str,
    pathspec: Option<&str>,
) -> Result<Vec<GitLineRange>, ArchaeologyError> {
    changed_ranges(repo, parent, commit, true, pathspec)
}

fn changed_ranges(
    repo: &Path,
    parent: &str,
    commit: &str,
    old_side: bool,
    pathspec: Option<&str>,
) -> Result<Vec<GitLineRange>, ArchaeologyError> {
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

fn parse_unified_ranges(diff: &str, old_side: bool) -> Result<Vec<GitLineRange>, ArchaeologyError> {
    let mut path = None::<String>;
    let mut ranges = BTreeSet::new();
    for line in diff.lines() {
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
        let (start_line, line_count) = parse_range(if old_side { old } else { new })?;
        if line_count == 0 {
            continue;
        }
        let Some(path) = path.clone() else {
            return Err(ArchaeologyError::new(
                ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
                "Git hunk appeared before a file path",
            ));
        };
        if path != "/dev/null" {
            ranges.insert(GitLineRange {
                path,
                start_line,
                line_count,
            });
        }
    }
    Ok(ranges.into_iter().collect())
}

fn parse_diff_path(raw: &str) -> Result<String, ArchaeologyError> {
    if raw == "/dev/null" {
        return Ok(raw.to_string());
    }
    // `--no-prefix` makes ordinary paths lossless, including spaces. Git quotes
    // paths containing control bytes; refusing those is safer than blaming a
    // decoded-looking but different path.
    if raw.starts_with('"') || raw.contains('\t') || raw.contains('\r') {
        return Err(ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git emitted a quoted or control-character diff path {raw:?}"),
        ));
    }
    Ok(raw.to_string())
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

fn blame_range(
    repo: &Path,
    parent: &str,
    range: &GitLineRange,
) -> Result<Vec<(String, u32)>, ArchaeologyError> {
    let line_arg = format!("{},+{}", range.start_line, range.line_count);
    let output = git_text(
        repo,
        &[
            "blame",
            "--line-porcelain",
            "-L",
            &line_arg,
            parent,
            "--",
            &range.path,
        ],
    )?;
    let mut findings = BTreeSet::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(raw_oid) = fields.next() else {
            continue;
        };
        let oid = raw_oid.trim_start_matches('^');
        if !is_oid(oid) {
            continue;
        }
        let Some(_original) = fields.next() else {
            continue;
        };
        let Some(final_line) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        findings.insert((oid.to_string(), final_line));
    }
    Ok(findings.into_iter().collect())
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

fn canonical_revert_target(message: &str) -> Option<String> {
    message.lines().find_map(|line| {
        line.trim()
            .strip_prefix("This reverts commit ")
            .and_then(|value| value.strip_suffix('.'))
            .map(str::to_string)
    })
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

fn git_status(repo: &Path, args: &[&str]) -> Result<bool, ArchaeologyError> {
    let status = git_command(repo, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| git_spawn_error(args, error))?;
    Ok(status.success())
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String, ArchaeologyError> {
    String::from_utf8(git_bytes(repo, args)?).map_err(|error| {
        ArchaeologyError::new(
            ASTRO_ARCHAEOLOGY_OUTPUT_INVALID,
            format!("Git output is not UTF-8: {error}"),
        )
    })
}

fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, ArchaeologyError> {
    let output = git_command(repo, args)
        .output()
        .map_err(|error| git_spawn_error(args, error))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(git_exit_error(args, &output.stderr))
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
        Err(git_exit_error(args, &output.stderr))
    }
}

fn git_command(repo: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
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

fn git_exit_error(args: &[&str], stderr: &[u8]) -> ArchaeologyError {
    ArchaeologyError::new(
        ASTRO_ARCHAEOLOGY_GIT_FAILED,
        format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(stderr).trim()
        ),
    )
}
