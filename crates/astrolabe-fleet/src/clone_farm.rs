//! Clone farm — bounded-parallel full-history acquisition, update fetches,
//! and integrity gates (issue #451).
//!
//! Walks [`FleetCatalog`] records and materializes them on disk under the
//! farm root (`D:\astrolabe-fleet\repos\<org>__<repo>` by default):
//!
//! - **Acquire** (default): records at [`RepoState::Discovered`] are cloned
//!   with `git clone --no-checkout --single-branch --branch <default_branch>`
//!   and FULL history — no shallow, no blobless: git archaeology (SZZ) needs
//!   the commit graph and blobs. The committed tree is then enumerated from
//!   the object store (`git ls-tree -r -z`) and classified for Windows-invalid
//!   paths (#480) **before** anything touches the index or the working tree;
//!   clean trees take the porcelain `git reset --hard` checkout, trees
//!   carrying invalid paths are materialized through index plumbing minus
//!   exactly the invalid entries (see below). Before the record transitions
//!   to `cloned` the clone must pass the integrity gate (`git rev-parse
//!   HEAD` plus `git fsck --connectivity-only`); failures quarantine with
//!   the git stderr captured to a rejection report file.
//! - **Update** (`--update`): records at `cloned` or beyond are fetched
//!   (`git fetch origin <default_branch>`); an unchanged head is an explicit
//!   counted no-op, a moved head is applied with `git reset --hard FETCH_HEAD`
//!   (farm clones are never locally modified) and recorded through
//!   [`FleetCatalog::update_facts`].
//!
//! # Windows-invalid committed paths (#480)
//!
//! Some repositories commit paths NTFS cannot represent — reserved characters
//! (`: < > " | ? *`), reserved device names (`CON`, `AUX`, `NUL`, `COM1`…),
//! trailing dots/spaces, `:Zone.Identifier` ADS remnants. A plain checkout of
//! such a tree fails on Windows (`error: invalid path`), and the widely-cited
//! workaround (`core.protectNTFS=false`) disables git's defense against
//! CVE-2019-1353-class hostile-repo attacks — unacceptable for a farm cloning
//! arbitrary third-party code. Instead the farm keeps `core.protectNTFS` at
//! its secure default and never lets an invalid path near the index: the tree
//! is rebuilt entry-by-entry (`git read-tree --empty` + `git update-index
//! --index-info`) with the invalid paths omitted, then materialized with
//! `git checkout-index --all`. The omissions are a **labeled degradation**
//! (invariant 3): recorded on the catalog row (`checkout_exclusions`), in the
//! ledger payload, in the run report, and in full in
//! `runs/exclusions-<github_id>.txt`. If the classifier ever under-detects,
//! git itself still refuses at the plumbing step and the repo quarantines
//! with the full stderr — never a silent partial tree.
//!
//! # Pre-existing directories
//!
//! A target directory that already exists is **adopted** when it is a healthy
//! git clone whose `origin` URL matches the catalog record (integrity-gated
//! like a fresh clone). A directory git identifies as a broken clone (it has a
//! `.git` entry but `git rev-parse --git-dir` or the integrity gate fails) or
//! an empty directory is removed and re-cloned — the documented
//! interrupted-clone resume semantic: no corrupt farm entry survives. A
//! non-empty directory without `.git` is foreign content and refuses
//! fail-closed ([`ASTRO_FLEET_CLONE_TARGET_CONFLICT`]); the farm never
//! overwrites what it cannot prove is its own torn clone.
//!
//! # Safety of process kills
//!
//! A hung git process is killed through the [`std::process::Child`] handle the
//! farm itself spawned — file-identity-attributed by construction, never a
//! name-wide `taskkill` (#292 lesson) — retried once, then quarantined.
//!
//! # Catalog reason bounds
//!
//! Catalog-bound reasons pass through [`safe_reason`] for a deterministic
//! display-size cap; the untruncated git stderr lives in the rejection report
//! file named by the repo's numeric `github_id`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use calyx_core::CalyxError;
use serde::Serialize;
use serde_json::{Value, json};

use crate::catalog::FleetCatalog;
use crate::record::{FleetRepoRow, MAX_CATALOG_REASON_CHARS, TransitionContext};
use crate::state::RepoState;

/// Refusal code for a git invocation the farm could not spawn.
pub const ASTRO_FLEET_GIT_SPAWN: &str = "ASTRO_FLEET_GIT_SPAWN";
/// Refusal code when a pre-existing target directory holds foreign content.
pub const ASTRO_FLEET_CLONE_TARGET_CONFLICT: &str = "ASTRO_FLEET_CLONE_TARGET_CONFLICT";
/// Refusal code when the farm disk budget forbids further clones.
pub const ASTRO_FLEET_FARM_BUDGET_EXCEEDED: &str = "ASTRO_FLEET_FARM_BUDGET_EXCEEDED";
/// Refusal code when a clone pass finished with per-repo failures.
pub const ASTRO_FLEET_CLONE_PASS_INCOMPLETE: &str = "ASTRO_FLEET_CLONE_PASS_INCOMPLETE";

/// Declared default root of the clone farm on D: (issue #451).
pub const DEFAULT_FARM_ROOT: &str = r"D:\astrolabe-fleet\repos";
/// Declared per-repo size cap: reported or measured sizes above this
/// quarantine as `too-large` (never a partial clone).
pub const DEFAULT_SIZE_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Declared farm-wide disk budget for clone bytes.
pub const DEFAULT_FARM_BUDGET_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// Declared bounded clone parallelism.
pub const DEFAULT_PARALLELISM: usize = 4;
/// Declared per-repo git timeout (clone or fetch), seconds.
pub const DEFAULT_GIT_TIMEOUT_SECS: u64 = 1800;
/// Poll interval while waiting on a git child process.
const GIT_POLL: Duration = Duration::from_millis(200);
/// Declared knobs of one clone-farm pass.
#[derive(Clone, Debug, Serialize)]
pub struct FarmConfig {
    /// Farm root directory holding `<org>__<repo>` clones.
    pub farm_root: PathBuf,
    /// Per-repo size cap in bytes (reported pre-clone, measured post-clone).
    pub size_cap_bytes: u64,
    /// Farm-wide clone-bytes budget.
    pub budget_bytes: u64,
    /// Bounded clone parallelism.
    pub parallelism: usize,
    /// Per-repo git timeout in seconds.
    pub timeout_secs: u64,
    /// Mutation timestamp (unix seconds).
    pub at_unix_secs: u64,
}

impl Default for FarmConfig {
    fn default() -> Self {
        Self {
            farm_root: PathBuf::from(DEFAULT_FARM_ROOT),
            size_cap_bytes: DEFAULT_SIZE_CAP_BYTES,
            budget_bytes: DEFAULT_FARM_BUDGET_BYTES,
            parallelism: DEFAULT_PARALLELISM,
            timeout_secs: DEFAULT_GIT_TIMEOUT_SECS,
            at_unix_secs: 0,
        }
    }
}

/// Which records a pass operates on.
#[derive(Clone, Debug)]
pub enum Selection {
    /// Explicitly named `owner/name`s.
    Repos(Vec<String>),
    /// Every record in the mode's source state, optionally capped.
    All { limit: Option<usize> },
}

/// Per-repo outcome of a pass, recorded in the run report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Fresh full-history clone passed the gates; record now `cloned`.
    Acquired,
    /// Healthy pre-existing clone with a matching origin was adopted.
    Adopted,
    /// A torn/broken target directory was removed and re-cloned clean.
    Recovered,
    /// A deliberately retired kerneled source was cloned again without
    /// discarding its durable store/kernel history (#807).
    Rehydrated,
    /// Update fetch moved the head watermark.
    Updated,
    /// Update fetch found nothing new — explicit no-op.
    Noop,
    /// Acquire selected a record no longer at `discovered` — explicit skip.
    SkippedState,
    /// Repo quarantined (reason on the catalog row + rejection file).
    Quarantined,
    /// Farm budget refused the clone; record left untouched at `discovered`.
    RefusedBudget,
    /// Pre-existing target directory holds foreign content; refused.
    Conflict,
    /// Update fetch failed; state kept, failure recorded.
    UpdateFailed,
}

/// One repo's result row in the run report.
#[derive(Clone, Debug, Serialize)]
pub struct RepoOutcome {
    /// `owner/name`.
    pub full_name: String,
    /// GitHub numeric id (also the rejection-file stem).
    pub github_id: u64,
    /// What happened.
    pub outcome: Outcome,
    /// Catalog-safe reason/detail (full text in the rejection file if any).
    pub detail: String,
    /// Recorded HEAD after the pass, when known.
    pub head_commit_hash: Option<String>,
    /// Measured clone bytes, when measured.
    pub clone_bytes: Option<u64>,
    /// Wall seconds spent on this repo.
    pub secs: f64,
    /// Windows-invalid committed paths excluded from the checkout (#480):
    /// `None` = fact untouched, `Some(vec![])` = verified complete,
    /// non-empty = the labeled degradation applied to the catalog row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<Vec<String>>,
}

/// What the git phase of one job produced (thread → main).
struct JobResult {
    row: FleetRepoRow,
    outcome: Outcome,
    detail: String,
    head: Option<String>,
    bytes: Option<u64>,
    rejection_text: Option<String>,
    secs: f64,
    /// Checkout-exclusions fact to apply (#480); `None` leaves it untouched.
    exclusions: Option<Vec<String>>,
}

/// Runs one clone-farm pass. `update` selects update mode; otherwise acquire.
/// Returns the run report on success; a pass with quarantines/conflicts/
/// budget refusals persists its report and then fails closed naming the
/// counts (never a silent partial pass).
pub fn run_clone_pass(
    catalog: &FleetCatalog,
    config: &FarmConfig,
    selection: &Selection,
    update: bool,
) -> Result<Value, CalyxError> {
    let outcome = run_clone_pass_outcome(catalog, config, selection, update)?;
    match outcome.refusal {
        Some(refusal) => Err(refusal),
        None => Ok(outcome.report),
    }
}

/// One clone pass's persisted report plus its would-be fail-closed refusal,
/// for callers (the growth cycle, #457) that must contain per-repo failures
/// without losing the report. A caller that swallows `refusal` must count and
/// surface it — never drop it silently (invariant 3).
pub struct ClonePassOutcome {
    /// The run report (already persisted to the farm root and the catalog
    /// vault), with `commit_seq`/`ledger_seq`/`report_file` attached.
    pub report: Value,
    /// Repos that hard-failed this pass (quarantined/conflict/update_failed).
    pub failed: usize,
    /// The fail-closed refusal the pass would have raised, if any.
    pub refusal: Option<CalyxError>,
}

/// Runs one clone pass and returns its [`ClonePassOutcome`] instead of
/// failing closed on per-repo failures. Hard errors still refuse.
pub fn run_clone_pass_outcome(
    catalog: &FleetCatalog,
    config: &FarmConfig,
    selection: &Selection,
    update: bool,
) -> Result<ClonePassOutcome, CalyxError> {
    let started = Instant::now();
    fs::create_dir_all(config.farm_root.join("runs")).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_ROOT_UNAVAILABLE",
        message: format!(
            "cannot create farm root {}: {error}",
            config.farm_root.display()
        ),
        remediation: "pass a writable --farm-root for the clone farm",
    })?;

    // Select rows.
    let source_states: &[RepoState] = if update {
        &[
            RepoState::Cloned,
            RepoState::Indexed,
            RepoState::Kerneled,
            RepoState::Serving,
        ]
    } else {
        &[RepoState::Discovered]
    };
    let retired_source = |row: &FleetRepoRow| {
        row.state == RepoState::Kerneled
            && row.clone_path.is_none()
            && row.clone_bytes.is_none()
            && row.source_retirement.as_ref().is_some_and(|retirement| {
                retirement.stage == crate::record::SourceRetirementStage::Retired
            })
    };
    let eligible = |row: &FleetRepoRow, explicit: bool| {
        if update {
            source_states.contains(&row.state) && row.clone_path.is_some()
        } else {
            source_states.contains(&row.state) || (explicit && retired_source(row))
        }
    };
    let all_rows = catalog.query(None, None)?;
    let mut selected: Vec<FleetRepoRow> = Vec::new();
    let mut skipped_state: Vec<RepoOutcome> = Vec::new();
    match selection {
        Selection::Repos(names) => {
            let wanted: BTreeSet<&str> = names.iter().map(String::as_str).collect();
            for row in &all_rows {
                if wanted.contains(row.record.full_name.as_str()) {
                    if eligible(row, true) {
                        selected.push(row.clone());
                    } else {
                        skipped_state.push(RepoOutcome {
                            full_name: row.record.full_name.clone(),
                            github_id: row.record.github_id,
                            outcome: Outcome::SkippedState,
                            detail: format!(
                                "state {} is not a {} source state",
                                row.state.as_str(),
                                if update { "update" } else { "acquire" }
                            ),
                            head_commit_hash: row.head_commit_hash.clone(),
                            clone_bytes: row.clone_bytes,
                            secs: 0.0,
                            exclusions: None,
                        });
                    }
                }
            }
            let found: BTreeSet<&str> = all_rows
                .iter()
                .map(|row| row.record.full_name.as_str())
                .collect();
            if let Some(missing) = names.iter().find(|name| !found.contains(name.as_str())) {
                return Err(CalyxError {
                    code: crate::catalog::ASTRO_FLEET_RECORD_MISSING,
                    message: format!("--repo {missing} is not in the fleet catalog"),
                    remediation: "register the repository (discovery) before farming it",
                });
            }
        }
        Selection::All { limit } => {
            for row in &all_rows {
                if eligible(row, false) {
                    selected.push(row.clone());
                }
            }
            if let Some(limit) = limit {
                selected.truncate(*limit);
            }
        }
    }

    // Farm accounting: bytes already recorded on catalog rows.
    let mut farm_bytes: u64 = all_rows.iter().filter_map(|row| row.clone_bytes).sum();

    let mut outcomes: Vec<RepoOutcome> = skipped_state;
    let mut queue: std::collections::VecDeque<FleetRepoRow> = selected.into();
    let mut in_flight = 0_usize;
    let mut reserved: u64 = 0;
    let (tx, rx) = mpsc::channel::<JobResult>();

    let rejections_dir = config
        .farm_root
        .join("runs")
        .join(format!("rejections-{}", config.at_unix_secs));

    loop {
        // Dispatch while there is capacity.
        while in_flight < config.parallelism.max(1) {
            let Some(row) = queue.pop_front() else { break };
            let reported_bytes = row.record.size_kb.saturating_mul(1024);
            if !update {
                // Pre-clone size gate on the GitHub-reported size.
                if reported_bytes > config.size_cap_bytes {
                    let detail = format!(
                        "too-large: reported {reported_bytes} bytes exceeds the {}-byte size cap; no clone attempted",
                        config.size_cap_bytes
                    );
                    apply_quarantine(catalog, config, &row, &detail)?;
                    outcomes.push(RepoOutcome {
                        full_name: row.record.full_name.clone(),
                        github_id: row.record.github_id,
                        outcome: Outcome::Quarantined,
                        detail,
                        head_commit_hash: None,
                        clone_bytes: None,
                        secs: 0.0,
                        exclusions: None,
                    });
                    continue;
                }
                // Farm budget gate (recorded + reserved + incoming).
                if farm_bytes + reserved + reported_bytes > config.budget_bytes {
                    outcomes.push(RepoOutcome {
                        full_name: row.record.full_name.clone(),
                        github_id: row.record.github_id,
                        outcome: Outcome::RefusedBudget,
                        detail: format!(
                            "farm budget: {farm_bytes} recorded + {reserved} reserved + {reported_bytes} incoming > {} budget",
                            config.budget_bytes
                        ),
                        head_commit_hash: None,
                        clone_bytes: None,
                        secs: 0.0,
                        exclusions: None,
                    });
                    continue;
                }
                reserved += reported_bytes;
            }
            let tx = tx.clone();
            let config_for_job = config.clone();
            thread::spawn(move || {
                let result = if update {
                    update_job(&row, &config_for_job)
                } else {
                    acquire_job(&row, &config_for_job)
                };
                // A dropped receiver means the pass already failed; nothing to do.
                let _ = tx.send(result);
            });
            in_flight += 1;
        }
        if in_flight == 0 {
            break;
        }
        // Collect one result, apply its catalog mutation on this thread
        // (vault commits stay serialized), then loop to dispatch more. The
        // deadline generously exceeds the per-repo git timeout, so a worker
        // that dies without sending (panic) surfaces as a structured error
        // instead of a hung pass.
        let mut result = rx
            .recv_timeout(Duration::from_secs(config.timeout_secs.saturating_mul(2) + 120))
            .map_err(|error| CalyxError {
                code: ASTRO_FLEET_GIT_SPAWN,
                message: format!("clone worker did not report within the deadline: {error}"),
                remediation: "internal defect: a worker thread hung or panicked; re-run the pass — completed repos are idempotent",
            })?;
        in_flight -= 1;
        if !update {
            reserved = reserved.saturating_sub(result.row.record.size_kb.saturating_mul(1024));
        }
        if let Some(text) = &result.rejection_text {
            write_rejection(&rejections_dir, result.row.record.github_id, text);
        }
        match result.outcome {
            Outcome::Acquired | Outcome::Adopted | Outcome::Recovered => {
                let head = result.head.clone().expect("gated outcomes carry a head");
                let bytes = result.bytes.expect("gated outcomes carry bytes");
                let path = target_dir(&config.farm_root, &result.row.record.full_name)
                    .display()
                    .to_string();
                if retired_source(&result.row) {
                    let exclusions = result.exclusions.clone().ok_or_else(|| CalyxError {
                        code: ASTRO_FLEET_GIT_SPAWN,
                        message: format!(
                            "successful rehydration of {} carried no checkout-exclusions readback",
                            result.row.record.full_name
                        ),
                        remediation: "internal defect: every successful acquisition must report the exact checkout exclusions",
                    })?;
                    catalog.rehydrate_source(
                        result.row.record.github_id,
                        &result.row.record.full_name,
                        config.at_unix_secs,
                        path,
                        head,
                        bytes,
                        exclusions,
                    )?;
                    result.outcome = Outcome::Rehydrated;
                } else {
                    catalog.transition(
                        result.row.record.github_id,
                        &result.row.record.full_name,
                        RepoState::Cloned,
                        TransitionContext {
                            at_unix_secs: config.at_unix_secs,
                            clone_path: Some(path),
                            head_commit_hash: Some(head),
                            clone_bytes: Some(bytes),
                            checkout_exclusions: result.exclusions.clone(),
                            ..TransitionContext::default()
                        },
                    )?;
                }
                farm_bytes += bytes;
            }
            Outcome::Updated => {
                let head = result.head.clone().expect("updated outcome carries a head");
                let bytes = result.bytes.expect("updated outcome carries bytes");
                farm_bytes = farm_bytes
                    .saturating_sub(result.row.clone_bytes.unwrap_or(0))
                    .saturating_add(bytes);
                catalog.update_facts(
                    result.row.record.github_id,
                    &result.row.record.full_name,
                    TransitionContext {
                        at_unix_secs: config.at_unix_secs,
                        head_commit_hash: Some(head),
                        clone_bytes: Some(bytes),
                        checkout_exclusions: result.exclusions.clone(),
                        ..TransitionContext::default()
                    },
                )?;
            }
            Outcome::Quarantined => {
                apply_quarantine(catalog, config, &result.row, &result.detail)?;
            }
            // No catalog mutation: explicit no-op, foreign-content conflict,
            // or a kept-state update failure — all counted below.
            Outcome::Noop
            | Outcome::Rehydrated
            | Outcome::Conflict
            | Outcome::UpdateFailed
            | Outcome::SkippedState
            | Outcome::RefusedBudget => {}
        }
        outcomes.push(RepoOutcome {
            full_name: result.row.record.full_name.clone(),
            github_id: result.row.record.github_id,
            outcome: result.outcome,
            detail: result.detail,
            head_commit_hash: result.head,
            clone_bytes: result.bytes,
            secs: result.secs,
            exclusions: result.exclusions,
        });
    }
    drop(tx);

    // Reconciled counts.
    let count = |outcome: Outcome| outcomes.iter().filter(|o| o.outcome == outcome).count();
    let counts = json!({
        "acquired": count(Outcome::Acquired),
        "adopted": count(Outcome::Adopted),
        "recovered": count(Outcome::Recovered),
        "rehydrated": count(Outcome::Rehydrated),
        "updated": count(Outcome::Updated),
        "noop": count(Outcome::Noop),
        "skipped_state": count(Outcome::SkippedState),
        "quarantined": count(Outcome::Quarantined),
        "refused_budget": count(Outcome::RefusedBudget),
        "conflict": count(Outcome::Conflict),
        "update_failed": count(Outcome::UpdateFailed),
        "with_exclusions": outcomes
            .iter()
            .filter(|o| o.exclusions.as_ref().is_some_and(|e| !e.is_empty()))
            .count(),
        "total": outcomes.len(),
    });
    let run_id = format!("clone-{}-{}", config.at_unix_secs, std::process::id());
    let report = json!({
        "run_id": run_id,
        "kind": if update { "update" } else { "acquire" },
        "config": config,
        "counts": counts,
        "farm_bytes": farm_bytes,
        "outcomes": outcomes,
        "wall_secs": started.elapsed().as_secs_f64(),
    });

    // Persist: file under <farm_root>/runs/ + catalog vault row + ledger.
    let runs_dir = config.farm_root.join("runs");
    fs::create_dir_all(&runs_dir).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_ROOT_UNAVAILABLE",
        message: format!("cannot create runs dir {}: {error}", runs_dir.display()),
        remediation: "the farm root must be writable for run reports",
    })?;
    let report_path = runs_dir.join(format!("{run_id}.json"));
    let report_bytes = serde_json::to_vec_pretty(&report).expect("run report serializes");
    fs::write(&report_path, &report_bytes).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_ROOT_UNAVAILABLE",
        message: format!("cannot write run report {}: {error}", report_path.display()),
        remediation: "the farm root must be writable for run reports",
    })?;
    let summary = serde_json::to_vec(&json!({
        "event": "fleet_clone_run",
        "run_id": run_id,
        "kind": if update { "update" } else { "acquire" },
        "counts": counts,
        "farm_bytes": farm_bytes,
        "report_file": report_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }))
    .expect("run summary serializes");
    let (commit_seq, ledger_seq) = catalog.record_run_report(&run_id, report_bytes, summary)?;

    let refused = count(Outcome::RefusedBudget);
    let failed =
        count(Outcome::Quarantined) + count(Outcome::Conflict) + count(Outcome::UpdateFailed);
    let refusal = if refused > 0 {
        Some(CalyxError {
            code: ASTRO_FLEET_FARM_BUDGET_EXCEEDED,
            message: format!(
                "clone pass {run_id}: {refused} clone(s) refused by the {}-byte farm budget ({farm_bytes} bytes recorded); report {}",
                config.budget_bytes,
                report_path.display()
            ),
            remediation: "raise --budget-bytes, or evict repos (delete clone dirs and quarantine/depart their records) before re-running",
        })
    } else if failed > 0 {
        Some(CalyxError {
            code: ASTRO_FLEET_CLONE_PASS_INCOMPLETE,
            message: format!(
                "clone pass {run_id} finished with {failed} failed repo(s) (quarantined/conflict/update_failed); report {}",
                report_path.display()
            ),
            remediation: "inspect the run report and rejection files; quarantines are recorded on the catalog rows",
        })
    } else {
        None
    };

    let mut out = report;
    out["commit_seq"] = json!(commit_seq);
    out["ledger_seq"] = json!(ledger_seq);
    out["report_file"] = json!(report_path.display().to_string());
    Ok(ClonePassOutcome {
        report: out,
        failed,
        refusal,
    })
}

/// `<farm_root>\<org>__<repo>`.
pub fn target_dir(farm_root: &Path, full_name: &str) -> PathBuf {
    farm_root.join(full_name.replace('/', "__"))
}

fn apply_quarantine(
    catalog: &FleetCatalog,
    config: &FarmConfig,
    row: &FleetRepoRow,
    detail: &str,
) -> Result<(), CalyxError> {
    catalog.transition(
        row.record.github_id,
        &row.record.full_name,
        RepoState::Quarantined,
        TransitionContext {
            at_unix_secs: config.at_unix_secs,
            quarantine_reason: Some(safe_reason(detail)),
            ..TransitionContext::default()
        },
    )?;
    Ok(())
}

fn write_rejection(dir: &Path, github_id: u64, text: &str) {
    // Rejection files are evidence, not the gate: a write failure must not
    // mask the quarantine itself, so it is reported on stderr and moved on.
    if let Err(error) =
        fs::create_dir_all(dir).and_then(|()| fs::write(dir.join(format!("{github_id}.txt")), text))
    {
        eprintln!(
            "{}",
            json!({
                "code": "ASTRO_FLEET_REJECTION_FILE_UNWRITABLE",
                "message": format!("cannot write rejection file for github_id {github_id}: {error}"),
                "remediation": "the farm root must be writable; the quarantine itself is still recorded in the catalog",
            })
        );
    }
}

/// Catalog reason text capped to its declared display bound. Full text belongs
/// in the rejection file.
pub fn safe_reason(raw: &str) -> String {
    let mut chars = raw.chars();
    let mut out: String = chars.by_ref().take(MAX_CATALOG_REASON_CHARS).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// Runs one git command with a wall-clock timeout, stderr captured to a file
/// (a pipe would backpressure long clones), killing OUR child on timeout.
/// Returns (exit_ok, stderr_text) or an error if git could not be spawned.
fn run_git(
    args: &[&str],
    cwd: Option<&Path>,
    timeout: Duration,
    stderr_file: &Path,
) -> Result<(bool, String), CalyxError> {
    let stderr = fs::File::create(stderr_file).map_err(|error| CalyxError {
        code: ASTRO_FLEET_GIT_SPAWN,
        message: format!(
            "cannot create git stderr capture {}: {error}",
            stderr_file.display()
        ),
        remediation: "the farm scratch area must be writable",
    })?;
    let mut command = Command::new("git");
    command
        .args(["-c", "credential.helper="])
        .args(["-c", "core.longpaths=true"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    silence_credential_prompts(&mut command);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().map_err(|error| CalyxError {
        code: ASTRO_FLEET_GIT_SPAWN,
        message: format!("failed to spawn git {}: {error}", args.join(" ")),
        remediation: "git must be installed and on PATH for the clone farm",
    })?;
    let _job = match JobGuard::assign(&child) {
        Ok(guard) => guard,
        Err(why) => {
            // Fail closed: never run an unguarded git that could outlive the
            // farm and race a later recovery pass.
            let _ = child.kill();
            let _ = child.wait();
            return Err(CalyxError {
                code: ASTRO_FLEET_GIT_SPAWN,
                message: format!("could not tie git to the farm's job object: {why}"),
                remediation: "internal defect: Windows job-object assignment failed; re-run the pass",
            });
        }
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    // OUR child handle: file-identity-attributed kill.
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(GIT_POLL);
            }
            Err(error) => {
                return Err(CalyxError {
                    code: ASTRO_FLEET_GIT_SPAWN,
                    message: format!("waiting on git {}: {error}", args.join(" ")),
                    remediation: "internal defect: child wait failed; re-run the pass",
                });
            }
        }
    };
    let mut stderr_text = String::new();
    if let Ok(mut file) = fs::File::open(stderr_file) {
        let _ = file.read_to_string(&mut stderr_text);
    }
    match status {
        Some(status) => Ok((status.success(), stderr_text)),
        None => Ok((
            false,
            format!(
                "timeout: git {} exceeded {}s and was killed (stderr so far: {stderr_text})",
                args.join(" "),
                timeout.as_secs()
            ),
        )),
    }
}

/// Ties a spawned git child to a Windows Job Object configured with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: when the farm process exits for any
/// reason — including a hard kill — the job's last handle closes and the git
/// child (with its own helper children) dies with it. Caught live by FSV: a
/// hard-killed farm left an orphaned `git.exe` writing into a torn clone dir,
/// racing the next pass's recovery. Guarding is fail-closed — a git that
/// cannot be tied to the job is killed rather than left to run unguarded.
pub(crate) struct JobGuard(windows_sys::Win32::Foundation::HANDLE);

impl JobGuard {
    pub(crate) fn assign(child: &std::process::Child) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: plain Win32 handle plumbing — the job handle is owned by
        // the returned guard and closed exactly once in Drop; the child
        // handle is borrowed from a live `Child` for the duration of the
        // call; the info struct is a zeroed POD written before use.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err("CreateJobObjectW failed".to_string());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                CloseHandle(job);
                return Err("SetInformationJobObject failed".to_string());
            }
            if AssignProcessToJobObject(job, child.as_raw_handle()) == 0 {
                CloseHandle(job);
                return Err("AssignProcessToJobObject failed".to_string());
            }
            Ok(Self(job))
        }
    }
}

/// Current resident working-set (RSS) bytes of a LIVE child, read from its process
/// handle via `K32GetProcessMemoryInfo` (#515). A single cheap syscall on the handle
/// the `Child` already owns. Must be sampled while the process is alive — a Windows
/// process's working set is torn down at exit and reads stale afterward — so the
/// caller polls this during its existing wait loop and keeps the running maximum;
/// that captured peak then survives the child's death for the structured
/// child-without-a-tool-result failure detail (the rc=127 case this issue tracks).
/// `None` when the query fails (labeled degradation in the caller, never fabricated).
pub(crate) fn child_working_set_bytes(child: &std::process::Child) -> Option<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    // SAFETY: the child handle is borrowed from a live `Child` for the duration of
    // the call; `counters` is a zeroed POD the query fills; no handle is retained.
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        if K32GetProcessMemoryInfo(
            child.as_raw_handle(),
            &raw mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) == 0
        {
            return None;
        }
        Some(counters.WorkingSetSize as u64)
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        // SAFETY: the guard exclusively owns the job handle.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Never prompt, anywhere: a nonexistent/private repo must fail fast, not
/// hang on credentials — the farm clones public repos only. Terminal prompts,
/// the askpass GUI channel (Git for Windows exports `GIT_ASKPASS` into every
/// shell), and Git Credential Manager's interactive mode are all disabled;
/// `credential.helper=` (set per-invocation) resets config-declared helpers.
/// Caught live by FSV: a ghost-repo clone hung on a GUI credential prompt.
pub(crate) fn silence_credential_prompts(command: &mut Command) {
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "echo")
        .env("SSH_ASKPASS", "echo")
        .env("GCM_INTERACTIVE", "never");
}

/// Captured-output git helper for short read-only commands (rev-parse etc.).
/// Shared with the pipeline orchestrator (#452).
pub(crate) fn git_capture(args: &[&str], cwd: &Path) -> Result<(bool, String, String), CalyxError> {
    let mut command = Command::new("git");
    command
        .args(["-c", "credential.helper="])
        .args(["-c", "core.longpaths=true"])
        .current_dir(cwd)
        .args(args);
    silence_credential_prompts(&mut command);
    let output = command.output().map_err(|error| CalyxError {
        code: ASTRO_FLEET_GIT_SPAWN,
        message: format!("failed to spawn git {}: {error}", args.join(" ")),
        remediation: "git must be installed and on PATH for the clone farm",
    })?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

/// Raw-bytes variant of [`git_capture`] for output that is path data, not
/// text: `git ls-tree -z` paths are arbitrary bytes and a lossy UTF-8 pass
/// would corrupt them before they can be fed back to `update-index` (#480).
fn git_capture_raw(args: &[&str], cwd: &Path) -> Result<(bool, Vec<u8>, String), CalyxError> {
    let mut command = Command::new("git");
    command
        .args(["-c", "credential.helper="])
        .args(["-c", "core.longpaths=true"])
        .current_dir(cwd)
        .args(args);
    silence_credential_prompts(&mut command);
    let output = command.output().map_err(|error| CalyxError {
        code: ASTRO_FLEET_GIT_SPAWN,
        message: format!("failed to spawn git {}: {error}", args.join(" ")),
        remediation: "git must be installed and on PATH for the clone farm",
    })?;
    Ok((
        output.status.success(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

/// Runs a git plumbing command feeding `input` on stdin (#480:
/// `update-index --index-info`). Job-object guarded like every farm git; a
/// writer thread avoids the stdin/stderr pipe deadlock on large trees.
fn run_git_feed(args: &[&str], cwd: &Path, input: &[u8]) -> Result<(bool, String), CalyxError> {
    use std::io::Write;
    let spawn_err = |error: String| CalyxError {
        code: ASTRO_FLEET_GIT_SPAWN,
        message: format!("failed to run git {}: {error}", args.join(" ")),
        remediation: "git must be installed and on PATH for the clone farm",
    };
    let mut command = Command::new("git");
    command
        .args(["-c", "credential.helper="])
        .args(["-c", "core.longpaths=true"])
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    silence_credential_prompts(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| spawn_err(error.to_string()))?;
    let job = match JobGuard::assign(&child) {
        Ok(guard) => guard,
        Err(why) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(spawn_err(format!(
                "could not tie git to the farm's job object: {why}"
            )));
        }
    };
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let input = input.to_vec();
    let writer = thread::spawn(move || {
        // A write error here means git exited early; its stderr carries why.
        let _ = stdin.write_all(&input);
    });
    let output = child
        .wait_with_output()
        .map_err(|error| spawn_err(error.to_string()))?;
    let _ = writer.join();
    drop(job);
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

/// Maximum invalid-path entries recorded on the catalog row; the full list
/// always lives in `runs/exclusions-<github_id>.txt`.
const MAX_EXCLUSIONS_ON_ROW: usize = 32;

/// One blob/gitlink entry of `git ls-tree -r -z`: mode, object id, and the
/// raw path bytes (never lossy-decoded — they round-trip to `update-index`).
struct TreeEntry {
    mode: Vec<u8>,
    sha: Vec<u8>,
    path: Vec<u8>,
}

/// Why one slash-separated repo path cannot exist on a Windows filesystem,
/// or `None` when it can. Mirrors the Win32 naming rules that make
/// `git checkout` fail with `error: invalid path` under the secure
/// `core.protectNTFS=true` default: reserved characters, control bytes,
/// reserved device basenames (bare or with an extension), and components
/// ending in a dot or space (silently renamed by Win32 file creation).
/// Git itself remains the enforcer — anything this classifier misses still
/// fails closed at the plumbing step with the git stderr captured.
pub fn windows_invalid_path(path: &[u8]) -> Option<String> {
    for component in path.split(|&byte| byte == b'/') {
        if component.is_empty() {
            return Some("empty path component".to_string());
        }
        for &byte in component {
            if byte < 0x20 {
                return Some(format!("control byte 0x{byte:02x}"));
            }
            if matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*' | b'\\') {
                return Some(format!("reserved character '{}'", byte as char));
            }
        }
        match component[component.len() - 1] {
            b'.' => return Some("component ends with a dot".to_string()),
            b' ' => return Some("component ends with a space".to_string()),
            _ => {}
        }
        let base = component
            .split(|&byte| byte == b'.')
            .next()
            .unwrap_or(component);
        let upper = base.to_ascii_uppercase();
        let device = matches!(upper.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
            || (upper.len() == 4
                && (upper.starts_with(b"COM") || upper.starts_with(b"LPT"))
                && upper[3].is_ascii_digit()
                && upper[3] != b'0');
        if device {
            return Some(format!(
                "reserved device name {}",
                String::from_utf8_lossy(&upper)
            ));
        }
    }
    None
}

/// One tree scan's split: materializable entries plus Windows-invalid
/// offenders as `(display_path, why)` pairs.
type TreeScan = (Vec<TreeEntry>, Vec<(String, String)>);

/// Enumerates `commit`'s full tree from the object store (never the
/// filesystem) and splits it into materializable entries and Windows-invalid
/// offenders (#480).
fn scan_tree(dir: &Path, commit: &str) -> Result<TreeScan, String> {
    let (ok, stdout, stderr) =
        git_capture_raw(&["ls-tree", "-r", "-z", commit], dir).map_err(|error| error.message)?;
    if !ok {
        return Err(format!("git ls-tree -r {commit} failed: {stderr}"));
    }
    let mut entries = Vec::new();
    let mut offenders = Vec::new();
    for record in stdout.split(|&byte| byte == 0) {
        if record.is_empty() {
            continue;
        }
        let malformed = || {
            format!(
                "malformed ls-tree record: {:?}",
                String::from_utf8_lossy(record)
            )
        };
        let tab = record
            .iter()
            .position(|&byte| byte == b'\t')
            .ok_or_else(malformed)?;
        let (head, tail) = record.split_at(tab);
        let path = &tail[1..];
        let mut fields = head.split(|&byte| byte == b' ');
        let mode = fields.next().ok_or_else(malformed)?;
        let _object_type = fields.next().ok_or_else(malformed)?;
        let sha = fields.next().ok_or_else(malformed)?;
        if let Some(why) = windows_invalid_path(path) {
            offenders.push((String::from_utf8_lossy(path).into_owned(), why));
        } else {
            entries.push(TreeEntry {
                mode: mode.to_vec(),
                sha: sha.to_vec(),
                path: path.to_vec(),
            });
        }
    }
    Ok((entries, offenders))
}

/// Materializes the working tree of a clone whose index/worktree may not yet
/// exist (#480). A clean tree takes the porcelain path (`git reset --hard
/// <commit>`, exactly what a plain clone's checkout does, ref move included);
/// a tree with offenders is rebuilt through index plumbing so the invalid
/// paths never reach the index: empty the index, feed every valid entry,
/// write out the worktree, then drop worktree files the filtered index no
/// longer tracks (upstream deletions on the update path).
fn materialize(
    dir: &Path,
    config: &FarmConfig,
    commit: &str,
    entries: &[TreeEntry],
    offenders: &[(String, String)],
    stderr_file: &Path,
) -> Result<(), String> {
    let timeout = Duration::from_secs(config.timeout_secs);
    if offenders.is_empty() {
        let (ok, stderr) = run_git(
            &["reset", "--hard", commit],
            Some(dir),
            timeout,
            stderr_file,
        )
        .map_err(|error| error.message)?;
        if !ok {
            return Err(format!("git reset --hard {commit} failed: {stderr}"));
        }
        return Ok(());
    }
    let (ok, _out, stderr) =
        git_capture(&["read-tree", "--empty"], dir).map_err(|error| error.message)?;
    if !ok {
        return Err(format!("git read-tree --empty failed: {stderr}"));
    }
    // `<mode> SP <sha> TAB <path>` NUL-terminated — update-index --index-info
    // stage-0 form, raw path bytes preserved end-to-end.
    let mut input = Vec::new();
    for entry in entries {
        input.extend_from_slice(&entry.mode);
        input.push(b' ');
        input.extend_from_slice(&entry.sha);
        input.push(b'\t');
        input.extend_from_slice(&entry.path);
        input.push(0);
    }
    let (ok, stderr) = run_git_feed(&["update-index", "-z", "--index-info"], dir, &input)
        .map_err(|error| error.message)?;
    if !ok {
        return Err(format!(
            "git update-index --index-info refused the filtered tree ({} entries, {} excluded): {stderr}",
            entries.len(),
            offenders.len()
        ));
    }
    let (ok, stderr) = run_git(
        &["checkout-index", "--all", "--force"],
        Some(dir),
        timeout,
        stderr_file,
    )
    .map_err(|error| error.message)?;
    if !ok {
        return Err(format!("git checkout-index --all failed: {stderr}"));
    }
    let (ok, stderr) = run_git(
        &["clean", "-q", "-f", "-d", "-x"],
        Some(dir),
        timeout,
        stderr_file,
    )
    .map_err(|error| error.message)?;
    if !ok {
        return Err(format!("git clean -fdx failed: {stderr}"));
    }
    Ok(())
}

/// The catalog-row form of the exclusions: reason-annotated, ledger-safe
/// ([`safe_reason`]), capped at [`MAX_EXCLUSIONS_ON_ROW`] with an explicit
/// counted remainder. An empty offender list yields an empty vec, which
/// **clears** the row fact.
fn exclusions_row_fact(offenders: &[(String, String)], github_id: u64) -> Vec<String> {
    let mut fact: Vec<String> = offenders
        .iter()
        .take(MAX_EXCLUSIONS_ON_ROW)
        .map(|(path, why)| safe_reason(&format!("{path} ({why})")))
        .collect();
    if offenders.len() > MAX_EXCLUSIONS_ON_ROW {
        fact.push(format!(
            "… and {} more; full list in runs/exclusions-{github_id}.txt",
            offenders.len() - MAX_EXCLUSIONS_ON_ROW
        ));
    }
    fact
}

/// Persists the full, uncapped exclusion list beside the rejection files.
/// Evidence, not the gate: a write failure is reported and the (capped)
/// catalog-row fact still records the degradation.
fn write_exclusions_file(runs_dir: &Path, github_id: u64, offenders: &[(String, String)]) {
    let mut text = String::new();
    for (path, why) in offenders {
        text.push_str(path);
        text.push('\t');
        text.push_str(why);
        text.push('\n');
    }
    if let Err(error) = fs::create_dir_all(runs_dir)
        .and_then(|()| fs::write(runs_dir.join(format!("exclusions-{github_id}.txt")), text))
    {
        eprintln!(
            "{}",
            json!({
                "code": "ASTRO_FLEET_EXCLUSIONS_FILE_UNWRITABLE",
                "message": format!("cannot write exclusions file for github_id {github_id}: {error}"),
                "remediation": "the farm root must be writable; the capped exclusion fact is still on the catalog row",
            })
        );
    }
}

/// Recursive on-disk byte measure of a clone directory.
fn measure_dir_bytes(dir: &Path) -> u64 {
    let mut total = 0_u64;
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            total += measure_dir_bytes(&entry.path());
        } else if let Ok(meta) = entry.metadata() {
            total += meta.len();
        }
    }
    total
}

/// URL equivalence for adoption: scheme-insensitive host + path, tolerant of a
/// trailing `.git`.
pub(crate) fn same_remote(a: &str, b: &str) -> bool {
    let norm = |url: &str| {
        url.trim()
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("git://")
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// Integrity gate: `rev-parse HEAD` + `fsck --connectivity-only`.
/// Returns the head SHA or the failing detail.
pub(crate) fn integrity_gate(dir: &Path) -> Result<String, String> {
    let (ok, head, stderr) = match git_capture(&["rev-parse", "HEAD"], dir) {
        Ok(triple) => triple,
        Err(error) => return Err(format!("rev-parse spawn failed: {}", error.message)),
    };
    if !ok {
        return Err(format!("git rev-parse HEAD failed: {stderr}"));
    }
    let (ok, _out, stderr) = match git_capture(&["fsck", "--connectivity-only"], dir) {
        Ok(triple) => triple,
        Err(error) => return Err(format!("fsck spawn failed: {}", error.message)),
    };
    if !ok {
        return Err(format!("git fsck --connectivity-only failed: {stderr}"));
    }
    Ok(head)
}

/// The acquire job for one repo: clone (or adopt / recover), gate, measure.
fn acquire_job(row: &FleetRepoRow, config: &FarmConfig) -> JobResult {
    let started = Instant::now();
    let dir = target_dir(&config.farm_root, &row.record.full_name);
    let stderr_file = config
        .farm_root
        .join("runs")
        .join(format!("git-stderr-{}.txt", row.record.github_id));
    let done = |outcome: Outcome,
                detail: String,
                head: Option<String>,
                bytes: Option<u64>,
                rejection: Option<String>,
                exclusions: Option<Vec<String>>| {
        JobResult {
            row: row.clone(),
            outcome,
            detail,
            head,
            bytes,
            rejection_text: rejection,
            secs: started.elapsed().as_secs_f64(),
            exclusions,
        }
    };

    let mut recovered = false;
    if dir.exists() {
        let is_git = git_capture(&["rev-parse", "--git-dir"], &dir)
            .map(|(ok, _, _)| ok)
            .unwrap_or(false);
        if is_git {
            match git_capture(&["remote", "get-url", "origin"], &dir) {
                Ok((true, url, _)) if same_remote(&url, &row.record.clone_url) => {
                    // Healthy candidate for adoption: gate it like a clone.
                    match integrity_gate(&dir) {
                        Ok(head) => {
                            // #480: re-derive the exclusions fact from the
                            // committed tree — a dir the farm materialized
                            // with exclusions re-adopts with the fact intact,
                            // and one carrying offenders (e.g. cloned
                            // externally) is idempotently re-materialized.
                            let (entries, offenders) = match scan_tree(&dir, "HEAD") {
                                Ok(pair) => pair,
                                Err(why) => {
                                    return done(
                                        Outcome::Quarantined,
                                        safe_reason(&format!(
                                            "adopted clone tree scan failed; rejection file {}.txt has details",
                                            row.record.github_id
                                        )),
                                        None,
                                        None,
                                        Some(format!(
                                            "repo: {}\nphase: adoption tree scan\n{why}\n",
                                            row.record.full_name
                                        )),
                                        None,
                                    );
                                }
                            };
                            if !offenders.is_empty() {
                                if let Err(why) = materialize(
                                    &dir,
                                    config,
                                    "HEAD",
                                    &entries,
                                    &offenders,
                                    &stderr_file,
                                ) {
                                    return done(
                                        Outcome::Quarantined,
                                        safe_reason(&format!(
                                            "adopted clone re-materialization failed; rejection file {}.txt has details",
                                            row.record.github_id
                                        )),
                                        None,
                                        None,
                                        Some(format!(
                                            "repo: {}\nphase: adoption filtered materialization\n{why}\n",
                                            row.record.full_name
                                        )),
                                        None,
                                    );
                                }
                                write_exclusions_file(
                                    &config.farm_root.join("runs"),
                                    row.record.github_id,
                                    &offenders,
                                );
                            }
                            let bytes = measure_dir_bytes(&dir);
                            if bytes > config.size_cap_bytes {
                                return done(
                                    Outcome::Quarantined,
                                    format!(
                                        "too-large: adopted clone measures {bytes} bytes > {}-byte cap (clone dir kept for operator review)",
                                        config.size_cap_bytes
                                    ),
                                    None,
                                    None,
                                    None,
                                    None,
                                );
                            }
                            let detail = if offenders.is_empty() {
                                "pre-existing healthy clone with matching origin adopted"
                                    .to_string()
                            } else {
                                format!(
                                    "pre-existing healthy clone adopted; {} windows-invalid path(s) excluded from checkout (labeled)",
                                    offenders.len()
                                )
                            };
                            return done(
                                Outcome::Adopted,
                                detail,
                                Some(head),
                                Some(bytes),
                                None,
                                Some(exclusions_row_fact(&offenders, row.record.github_id)),
                            );
                        }
                        Err(_gate_fail) => {
                            // Broken git clone at OUR canonical path: torn
                            // remains — remove and re-clone below.
                            if fs::remove_dir_all(&dir).is_err() {
                                return done(
                                    Outcome::Quarantined,
                                    "torn clone dir could not be removed for recovery".into(),
                                    None,
                                    None,
                                    None,
                                    None,
                                );
                            }
                            recovered = true;
                        }
                    }
                }
                Ok((true, url, _)) => {
                    return done(
                        Outcome::Conflict,
                        safe_reason(&format!(
                            "target dir holds a git repo with origin {url}, expected {}; refusing to touch it",
                            row.record.clone_url
                        )),
                        None,
                        None,
                        Some(format!(
                            "target: {}\nexpected origin: {}\nactual origin: {url}\n",
                            dir.display(),
                            row.record.clone_url
                        )),
                        None,
                    );
                }
                _ => {
                    // .git present but git can't read it → torn clone.
                    if fs::remove_dir_all(&dir).is_err() {
                        return done(
                            Outcome::Quarantined,
                            "torn clone dir could not be removed for recovery".into(),
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                    recovered = true;
                }
            }
        } else {
            let has_git_entry = dir.join(".git").exists();
            let is_empty = fs::read_dir(&dir)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            if has_git_entry || is_empty {
                // A .git that git itself cannot open, or an empty stub:
                // torn clone remains at our canonical path — recover.
                if fs::remove_dir_all(&dir).is_err() {
                    return done(
                        Outcome::Quarantined,
                        "torn clone dir could not be removed for recovery".into(),
                        None,
                        None,
                        None,
                        None,
                    );
                }
                recovered = true;
            } else {
                return done(
                    Outcome::Conflict,
                    "target dir exists with non-git foreign content; refusing to overwrite".into(),
                    None,
                    None,
                    Some(format!(
                        "target: {}\nforeign non-git content present; farm will never delete it\n",
                        dir.display()
                    )),
                    None,
                );
            }
        }
    }

    // Fresh clone (checkout deferred, #480) with one retry on
    // timeout/transient failure.
    let url = row.record.clone_url.clone();
    let branch = row.record.default_branch.clone();
    let dir_str = dir.display().to_string();
    let mut last_stderr = String::new();
    for attempt in 1..=2 {
        let clone_args = [
            "clone",
            "--no-checkout",
            "--single-branch",
            "--branch",
            branch.as_str(),
            url.as_str(),
            dir_str.as_str(),
        ];
        let (ok, stderr) = match run_git(
            &clone_args,
            None,
            Duration::from_secs(config.timeout_secs),
            &stderr_file,
        ) {
            Ok(pair) => pair,
            Err(error) => (false, error.message),
        };
        if ok {
            // #480: enumerate + classify the committed tree from the object
            // store, then materialize — porcelain when clean, filtered index
            // plumbing when Windows-invalid paths exist. A failure here is
            // treated exactly like a clone failure: dir removed, one retry,
            // then quarantine with the captured detail.
            let materialized = scan_tree(&dir, "HEAD").and_then(|(entries, offenders)| {
                materialize(&dir, config, "HEAD", &entries, &offenders, &stderr_file)
                    .map(|()| offenders)
            });
            match materialized {
                Ok(offenders) => {
                    if !offenders.is_empty() {
                        write_exclusions_file(
                            &config.farm_root.join("runs"),
                            row.record.github_id,
                            &offenders,
                        );
                    }
                    // Post-checkout measured size cap.
                    let bytes = measure_dir_bytes(&dir);
                    if bytes > config.size_cap_bytes {
                        let _ = fs::remove_dir_all(&dir);
                        return done(
                            Outcome::Quarantined,
                            format!(
                                "too-large: measured {bytes} bytes > {}-byte cap (reported {} KiB); clone removed",
                                config.size_cap_bytes, row.record.size_kb
                            ),
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                    return match integrity_gate(&dir) {
                        Ok(head) => {
                            let mut detail = if recovered {
                                "torn clone removed and re-cloned clean".to_string()
                            } else {
                                "fresh full-history clone".to_string()
                            };
                            if !offenders.is_empty() {
                                detail.push_str(&format!(
                                    "; {} windows-invalid path(s) excluded from checkout (labeled; full list in runs/exclusions-{}.txt)",
                                    offenders.len(),
                                    row.record.github_id
                                ));
                            }
                            done(
                                if recovered {
                                    Outcome::Recovered
                                } else {
                                    Outcome::Acquired
                                },
                                detail,
                                Some(head),
                                Some(bytes),
                                None,
                                Some(exclusions_row_fact(&offenders, row.record.github_id)),
                            )
                        }
                        Err(gate_fail) => {
                            let detail =
                                safe_reason(&format!("clone integrity failure: {gate_fail}"));
                            done(
                                Outcome::Quarantined,
                                detail,
                                None,
                                None,
                                Some(format!(
                                    "repo: {}\nphase: integrity gate\n{gate_fail}\n",
                                    row.record.full_name
                                )),
                                None,
                            )
                        }
                    };
                }
                Err(why) => {
                    last_stderr = format!("tree scan / checkout materialization failed: {why}");
                }
            }
        } else {
            last_stderr = stderr;
        }
        // A failed attempt may leave a partial dir; a remove that itself
        // fails must surface, not silently feed the next attempt a dirty dir.
        if dir.exists()
            && let Err(error) = fs::remove_dir_all(&dir)
        {
            return done(
                Outcome::Quarantined,
                safe_reason(&format!(
                    "failed clone left remains that could not be removed: {error}"
                )),
                None,
                None,
                Some(format!(
                    "repo: {}\nphase: post-failure cleanup\nremove_dir_all: {error}\nclone stderr:\n{last_stderr}\n",
                    row.record.full_name
                )),
                None,
            );
        }
        if attempt == 1 {
            thread::sleep(Duration::from_secs(2));
        }
    }
    done(
        Outcome::Quarantined,
        safe_reason(&format!(
            "clone failed after 2 attempts; rejection file {}.txt has full git stderr",
            row.record.github_id
        )),
        None,
        None,
        Some(format!(
            "repo: {}\nphase: git clone/materialize\n{last_stderr}\n",
            row.record.full_name
        )),
        None,
    )
}

/// The update job for one repo: fetch, compare, fast-forward, gate. The new
/// head's tree is scanned like a fresh clone's (#480): a head that gains
/// Windows-invalid paths moves the branch with `reset --soft` and
/// re-materializes through the filtered index plumbing; one whose offenders
/// disappear clears the row's exclusions fact.
fn update_job(row: &FleetRepoRow, config: &FarmConfig) -> JobResult {
    let started = Instant::now();
    let done = |outcome: Outcome,
                detail: String,
                head: Option<String>,
                bytes: Option<u64>,
                rejection: Option<String>,
                exclusions: Option<Vec<String>>| {
        JobResult {
            row: row.clone(),
            outcome,
            detail,
            head,
            bytes,
            rejection_text: rejection,
            secs: started.elapsed().as_secs_f64(),
            exclusions,
        }
    };
    let Some(clone_path) = row.clone_path.as_deref() else {
        return done(
            Outcome::UpdateFailed,
            "record has no clone_path; cannot update".into(),
            None,
            None,
            None,
            None,
        );
    };
    let dir = PathBuf::from(clone_path);
    let stderr_file = config
        .farm_root
        .join("runs")
        .join(format!("git-stderr-{}.txt", row.record.github_id));
    let (ok, stderr) = match run_git(
        &["fetch", "origin", row.record.default_branch.as_str()],
        Some(&dir),
        Duration::from_secs(config.timeout_secs),
        &stderr_file,
    ) {
        Ok(pair) => pair,
        Err(error) => (false, error.message),
    };
    if !ok {
        return done(
            Outcome::UpdateFailed,
            safe_reason(&format!(
                "git fetch failed; rejection file {}.txt has full stderr",
                row.record.github_id
            )),
            None,
            None,
            Some(format!(
                "repo: {}\nphase: git fetch\n{stderr}\n",
                row.record.full_name
            )),
            None,
        );
    }
    let (ok, fetched_head, stderr) = match git_capture(&["rev-parse", "FETCH_HEAD"], &dir) {
        Ok(triple) => triple,
        Err(error) => (false, String::new(), error.message),
    };
    if !ok {
        return done(
            Outcome::UpdateFailed,
            safe_reason(&format!("rev-parse FETCH_HEAD failed: {stderr}")),
            None,
            None,
            None,
            None,
        );
    }
    if Some(fetched_head.as_str()) == row.head_commit_hash.as_deref() {
        return done(
            Outcome::Noop,
            "head watermark unchanged".into(),
            row.head_commit_hash.clone(),
            row.clone_bytes,
            None,
            None,
        );
    }
    // #480: classify the NEW head's tree before it touches index/worktree.
    let (entries, offenders) = match scan_tree(&dir, "FETCH_HEAD") {
        Ok(pair) => pair,
        Err(why) => {
            return done(
                Outcome::UpdateFailed,
                safe_reason(&format!(
                    "fetched-head tree scan failed; rejection file {}.txt has details",
                    row.record.github_id
                )),
                None,
                None,
                Some(format!(
                    "repo: {}\nphase: update tree scan\n{why}\n",
                    row.record.full_name
                )),
                None,
            );
        }
    };
    // Farm clones are never locally modified: apply the new head exactly.
    // Offender trees first move the branch ref alone (`reset --soft`), then
    // materialize minus the invalid paths; `materialize` handles the clean
    // case with the porcelain `reset --hard`.
    if !offenders.is_empty() {
        let (ok, _out, stderr) = match git_capture(&["reset", "--soft", "FETCH_HEAD"], &dir) {
            Ok(triple) => triple,
            Err(error) => (false, String::new(), error.message),
        };
        if !ok {
            return done(
                Outcome::UpdateFailed,
                safe_reason(&format!("reset --soft FETCH_HEAD failed: {stderr}")),
                None,
                None,
                None,
                None,
            );
        }
    }
    if let Err(why) = materialize(
        &dir,
        config,
        "FETCH_HEAD",
        &entries,
        &offenders,
        &stderr_file,
    ) {
        return done(
            Outcome::UpdateFailed,
            safe_reason(&format!(
                "update materialization failed; rejection file {}.txt has details",
                row.record.github_id
            )),
            None,
            None,
            Some(format!(
                "repo: {}\nphase: update materialization\n{why}\n",
                row.record.full_name
            )),
            None,
        );
    }
    if !offenders.is_empty() {
        write_exclusions_file(
            &config.farm_root.join("runs"),
            row.record.github_id,
            &offenders,
        );
    }
    match integrity_gate(&dir) {
        Ok(head) => {
            let bytes = measure_dir_bytes(&dir);
            let detail = if offenders.is_empty() {
                "head watermark advanced".to_string()
            } else {
                format!(
                    "head watermark advanced; {} windows-invalid path(s) excluded from checkout (labeled)",
                    offenders.len()
                )
            };
            done(
                Outcome::Updated,
                detail,
                Some(head),
                Some(bytes),
                None,
                Some(exclusions_row_fact(&offenders, row.record.github_id)),
            )
        }
        Err(gate_fail) => done(
            Outcome::UpdateFailed,
            safe_reason(&format!("post-update integrity failure: {gate_fail}")),
            None,
            None,
            Some(format!(
                "repo: {}\nphase: post-update integrity gate\n{gate_fail}\n",
                row.record.full_name
            )),
            None,
        ),
    }
}
