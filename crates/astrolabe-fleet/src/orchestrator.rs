//! Batch orchestrator — resumable fleet driver through the existing
//! repo→kernel pipeline with per-repo failure isolation (issue #452).
//!
//! Walks [`FleetCatalog`] records at [`RepoState::Cloned`] (and
//! [`RepoState::Indexed`], the crashed-run resume state) and drives each
//! through the existing per-repo pipeline, then advances the catalog
//! `cloned → indexed → kerneled` — each transition only after the stage's
//! persisted state has been independently read back.
//!
//! # Seam decision: subprocess, not in-process
//!
//! The pipeline is invoked as `astrolabe.exe cli --json index_repository
//! --args-file <file>` in a child process tied to a Windows Job Object
//! (`KILL_ON_JOB_CLOSE`, the #451 pattern) rather than calling
//! `handle_index_repository` in-process. Rationale, recorded per the issue:
//! the orchestrator's core obligation is *failure isolation*, and the CBM
//! index pass is a large C codebase that can and does crash on real corpora
//! (a real `ASTRO_SHADOW_INDEX_PASS_CRASHED` on a >2k-star C++ repo was
//! observed the day this module was written). A subprocess boundary contains
//! heap corruption, aborts, and leaks that would take an in-process driver —
//! and the whole fleet run — down with them; linking the server's C half into
//! the fleet binary would also drag `cbm-sys` into every catalog operation.
//! The cost is one process spawn per repo, noise against multi-minute
//! pipeline runs.
//!
//! # Shadow-vault addressing
//!
//! The independent readbacks open the per-repo shadow vault directly. The
//! vault identity constants ([`SHADOW_VAULT_ID`], [`shadow_vault_salt`],
//! [`kernel_scope_id`]) mirror `astrolabe-server/src/migration`
//! (`shadow_import.rs` / `mod.rs` / `kernel_context.rs`), which cannot be
//! depended on without linking the C half. Drift is self-arresting, not
//! silent: a wrong id or salt makes the vault open (or every row decode) fail
//! closed, so the readback can never "pass" against the wrong identity.
//!
//! # Per-repo store isolation
//!
//! Each repo's CBM cache/vault set lives under its own store directory
//! (`<store_root>\<org>__<repo>\` — `CBM_CACHE_DIR` per repo). This is a
//! deliberate pre-figuring of #454: the shared `_config.db` is a known
//! single-writer contention point, and per-repo stores sidestep it entirely
//! until #454 measures the real fix. It also makes quarantine cleanup and
//! disk accounting per-repo trivial.
//!
//! # Resume semantics
//!
//! Transitions land only after stage readback, so a crashed orchestrator
//! leaves every record at a truthful state:
//!
//! - `kerneled` + unchanged clone HEAD → **skipped** (idempotent re-run);
//!   `--force` re-runs the pipeline and refreshes the recorded facts.
//! - `kerneled` + advanced clone HEAD → **stale** (explicit, counted; the
//!   re-index belongs to the growth scheduler atom #457, not a silent redo).
//! - `indexed` (crashed between the two transitions) → the pipeline re-runs
//!   over the existing store (the import path is idempotent), then the
//!   missing `indexed → kerneled` transition completes.
//! - `cloned` with a leftover store directory (crashed mid-pipeline) → the
//!   partial store is **removed and redone**: nothing ever transitioned, so
//!   nothing is lost, and a torn CBM sqlite is never trusted as a base.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, VaultId};
use serde::Serialize;
use serde_json::{Value, json};

use crate::catalog::FleetCatalog;
use crate::clone_farm::{
    JobGuard, Selection, git_capture, safe_reason, silence_credential_prompts,
};
use crate::record::{FleetRepoRow, TransitionContext};
use crate::state::RepoState;

/// Refusal code when the pipeline child process could not be spawned/managed.
pub const ASTRO_FLEET_PIPELINE_SPAWN: &str = "ASTRO_FLEET_PIPELINE_SPAWN";
/// Refusal code when a pipeline pass finished with per-repo failures.
pub const ASTRO_FLEET_PIPELINE_INCOMPLETE: &str = "ASTRO_FLEET_PIPELINE_INCOMPLETE";
/// Refusal code when the fleet store root cannot be prepared.
pub const ASTRO_FLEET_STORE_UNAVAILABLE: &str = "ASTRO_FLEET_STORE_UNAVAILABLE";
/// Refusal code when the fleet store total exceeds the declared byte budget
/// (#454): the pass stops launching new repos and fails closed with an
/// eviction remediation — never a silent stop.
pub const ASTRO_FLEET_STORE_BUDGET: &str = "ASTRO_FLEET_STORE_BUDGET";
/// Refusal code when a repo's store directory pre-exists with content the
/// pipeline does not recognize as its own (#454): refuse, never overwrite.
pub const ASTRO_FLEET_STORE_FOREIGN: &str = "ASTRO_FLEET_STORE_FOREIGN";

/// Declared default fleet store root (per-repo CBM cache/vault sets).
pub const DEFAULT_STORE_ROOT: &str = r"D:\astrolabe-fleet\store";
/// Declared default nomic vector-blob directory (#442: a relocated
/// `astrolabe.exe` needs `ASTRO_NOMIC_DIR` or it fails with a structured
/// error; the orchestrator always sets it).
pub const DEFAULT_NOMIC_DIR: &str = r"C:\code\Astrolabe\cbm\vendored\nomic";
/// Declared bounded pipeline parallelism. Two, not four: each pipeline child
/// is itself multi-threaded and memory-hungry (weave + HNSW at M scale).
pub const DEFAULT_PIPELINE_PARALLELISM: usize = 2;
/// Declared per-repo pipeline timeout, seconds.
pub const DEFAULT_PIPELINE_TIMEOUT_SECS: u64 = 1800;
/// Poll interval while waiting on a pipeline child.
const CHILD_POLL: Duration = Duration::from_millis(500);

/// Shadow-vault ULID — mirrors `astrolabe-server::migration::shadow_import`
/// (see module docs: drift fails closed, never silently).
pub const SHADOW_VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// Shadow-vault salt for `project` — mirrors
/// `astrolabe-server::migration::vault_salt`.
pub fn shadow_vault_salt(project: &str) -> String {
    format!("astrolabe-shadow-v1:{project}")
}

/// Kernel artifact scope id for `project` — mirrors
/// `astrolabe-server::migration::kernel_context::kernel_artifact_scope_id`.
pub fn kernel_scope_id(project: &str) -> String {
    format!("repo:{project}")
}

/// CBM project name for a catalog record: `<org>__<repo>` (collision-free,
/// catalog-derived — the same mapping as the clone farm's directory name).
pub fn project_name(full_name: &str) -> String {
    full_name.replace('/', "__")
}

/// Declared knobs of one pipeline pass.
#[derive(Clone, Debug, Serialize)]
pub struct PipelineConfig {
    /// Fleet store root holding one `<org>__<repo>` store dir per repo.
    pub store_root: PathBuf,
    /// The pipeline binary (`astrolabe.exe`).
    pub astrolabe_bin: PathBuf,
    /// Nomic vector-blob directory exported as `ASTRO_NOMIC_DIR` (#442).
    pub nomic_dir: PathBuf,
    /// Bounded pipeline parallelism.
    pub parallelism: usize,
    /// Per-repo pipeline timeout in seconds.
    pub timeout_secs: u64,
    /// Re-run repos already `kerneled` and refresh their recorded facts.
    pub force: bool,
    /// Declared fleet store byte budget (#454). `None` = unbudgeted. When the
    /// measured store-root total reaches this, the pass stops launching new
    /// repos, drains in-flight work, and fails closed with an eviction
    /// remediation naming the largest stores.
    pub store_budget_bytes: Option<u64>,
    /// Mutation timestamp (unix seconds).
    pub at_unix_secs: u64,
}

impl PipelineConfig {
    /// Defaults with the pipeline binary resolved beside the running
    /// executable (override with `--astrolabe-bin`).
    pub fn with_default_bin(at_unix_secs: u64) -> Self {
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("astrolabe.exe")))
            .unwrap_or_else(|| PathBuf::from("astrolabe.exe"));
        Self {
            store_root: PathBuf::from(DEFAULT_STORE_ROOT),
            astrolabe_bin: sibling,
            nomic_dir: PathBuf::from(DEFAULT_NOMIC_DIR),
            parallelism: DEFAULT_PIPELINE_PARALLELISM,
            timeout_secs: DEFAULT_PIPELINE_TIMEOUT_SECS,
            force: false,
            store_budget_bytes: None,
            at_unix_secs,
        }
    }
}

/// Per-repo outcome of a pipeline pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Full pipeline ran; both transitions landed after readback.
    Kerneled,
    /// Record was `indexed` (crashed run); pipeline re-ran and the missing
    /// `indexed → kerneled` transition completed.
    Resumed,
    /// Already `kerneled` at the same clone HEAD — idempotent skip.
    Skipped,
    /// Already `kerneled` but the clone HEAD advanced; explicit stale verdict
    /// (re-index belongs to the growth scheduler, #457), no mutation.
    Stale,
    /// `--force` re-ran a `kerneled` repo and refreshed its recorded facts.
    Refreshed,
    /// Selected by name but not in a source state this pass operates on.
    SkippedState,
    /// Pipeline or verification failed; record quarantined with the stage.
    Quarantined,
}

/// One repo's verdict row in the run report.
#[derive(Clone, Debug, Serialize)]
pub struct RepoVerdict {
    /// `owner/name`.
    pub full_name: String,
    /// GitHub numeric id (also the verdict/rejection file stem).
    pub github_id: u64,
    /// What happened.
    pub outcome: Outcome,
    /// Failing stage when quarantined (`preflight`, `pipeline`, `timeout`,
    /// `parse`, `kernel`, `verify`).
    pub stage: Option<String>,
    /// Catalog-safe detail (full text in the rejection file if any).
    pub detail: String,
    /// Clone HEAD the work was grounded on.
    pub head_commit_hash: Option<String>,
    /// Independently counted CBM sqlite nodes/edges.
    pub sqlite_nodes: Option<u64>,
    /// Independently counted CBM sqlite edges.
    pub sqlite_edges: Option<u64>,
    /// Independently counted shadow-vault Base rows.
    pub vault_base_rows: Option<u64>,
    /// Kernel members-hash read back from the persisted artifact.
    pub kernel_members_hash: Option<String>,
    /// Kernel member count read back from the persisted artifact.
    pub kernel_member_count: Option<u64>,
    /// Top-level pipeline stage timings (ms) parsed from the timing stream.
    pub stage_ms: BTreeMap<String, u64>,
    /// A torn partial store dir from a crashed prior run was removed and the
    /// pipeline redone from scratch (the documented resume semantic) — labeled
    /// here so recovery is never a silent fallback (invariant 3).
    pub wiped_partial_store: bool,
    /// Measured on-disk bytes of the repo's store directory after the
    /// pipeline (#454); recorded on the catalog row at `kerneled`.
    pub store_bytes: Option<u64>,
    /// Wall seconds spent on this repo.
    pub secs: f64,
}

/// What one worker produced (thread → main).
struct JobResult {
    row: FleetRepoRow,
    verdict: RepoVerdict,
    rejection_text: Option<String>,
    /// Transitions the main thread must apply, in order.
    transitions: Vec<(RepoState, TransitionContext)>,
    /// `--force` fact refresh instead of transitions.
    fact_refresh: Option<TransitionContext>,
}

/// Runs one pipeline pass. Returns the run report on success; a pass with
/// quarantines persists its report and then fails closed naming the counts.
pub fn run_pipeline_pass(
    catalog: &FleetCatalog,
    config: &PipelineConfig,
    selection: &Selection,
) -> Result<Value, CalyxError> {
    let started = Instant::now();
    let runs_dir = config.store_root.join("runs");
    fs::create_dir_all(&runs_dir).map_err(|error| CalyxError {
        code: ASTRO_FLEET_STORE_UNAVAILABLE,
        message: format!("cannot create store root {}: {error}", runs_dir.display()),
        remediation: "pass a writable --store-root for the fleet store",
    })?;

    // Selection: default source states are `cloned` + `indexed` (resume).
    let source_states: &[RepoState] = &[RepoState::Cloned, RepoState::Indexed];
    let all_rows = catalog.query(None, None)?;
    let mut selected: Vec<FleetRepoRow> = Vec::new();
    let mut verdicts: Vec<RepoVerdict> = Vec::new();
    match selection {
        Selection::Repos(names) => {
            for name in names {
                let Some(row) = all_rows.iter().find(|row| &row.record.full_name == name) else {
                    return Err(CalyxError {
                        code: crate::catalog::ASTRO_FLEET_RECORD_MISSING,
                        message: format!("--repo {name} is not in the fleet catalog"),
                        remediation: "register + clone the repository before running the pipeline",
                    });
                };
                if source_states.contains(&row.state) || row.state == RepoState::Kerneled {
                    selected.push(row.clone());
                } else {
                    verdicts.push(RepoVerdict {
                        full_name: row.record.full_name.clone(),
                        github_id: row.record.github_id,
                        outcome: Outcome::SkippedState,
                        stage: None,
                        detail: format!(
                            "state {} is not a pipeline source state (cloned|indexed|kerneled)",
                            row.state.as_str()
                        ),
                        head_commit_hash: row.head_commit_hash.clone(),
                        sqlite_nodes: None,
                        sqlite_edges: None,
                        vault_base_rows: None,
                        kernel_members_hash: None,
                        kernel_member_count: None,
                        stage_ms: BTreeMap::new(),
                        wiped_partial_store: false,
                        store_bytes: None,
                        secs: 0.0,
                    });
                }
            }
        }
        Selection::All { limit } => {
            for row in &all_rows {
                if source_states.contains(&row.state) {
                    selected.push(row.clone());
                }
            }
            if let Some(limit) = limit {
                selected.truncate(*limit);
            }
        }
    }

    let verdicts_dir = runs_dir.join(format!("verdicts-{}", config.at_unix_secs));
    let rejections_dir = runs_dir.join(format!("rejections-{}", config.at_unix_secs));

    // #454 disk budget: measured once at pass start, then advanced by each
    // completed repo's measured store bytes — the walk stays O(store) once
    // per pass instead of once per repo.
    let mut store_total_bytes = match config.store_budget_bytes {
        Some(_) => Some(dir_size_bytes(&config.store_root).map_err(|error| CalyxError {
            code: ASTRO_FLEET_STORE_UNAVAILABLE,
            message: format!(
                "cannot measure store root {} for budget accounting: {error}",
                config.store_root.display()
            ),
            remediation: "the store root must be readable when --store-budget-bytes is set",
        })?),
        None => None,
    };
    let mut budget_exhausted_at: Option<u64> = None;

    let mut queue: std::collections::VecDeque<FleetRepoRow> = selected.into();
    let mut in_flight = 0_usize;
    let (tx, rx) = mpsc::channel::<JobResult>();
    loop {
        while in_flight < config.parallelism.max(1) {
            if let (Some(budget), Some(total)) = (config.store_budget_bytes, store_total_bytes)
                && total >= budget
            {
                // Stop launching; in-flight repos drain and are recorded, the
                // pass then fails closed below (nothing silent).
                budget_exhausted_at = Some(total);
                break;
            }
            let Some(row) = queue.pop_front() else { break };
            let tx = tx.clone();
            let config_for_job = config.clone();
            thread::spawn(move || {
                let result = pipeline_job(&row, &config_for_job);
                let _ = tx.send(result);
            });
            in_flight += 1;
        }
        if in_flight == 0 {
            break;
        }
        let result = rx
            .recv_timeout(Duration::from_secs(config.timeout_secs.saturating_mul(2) + 300))
            .map_err(|error| CalyxError {
                code: ASTRO_FLEET_PIPELINE_SPAWN,
                message: format!("pipeline worker did not report within the deadline: {error}"),
                remediation: "internal defect: a worker thread hung or panicked; re-run the pass — completed repos are idempotent",
            })?;
        in_flight -= 1;

        if let Some(text) = &result.rejection_text {
            write_side_file(&rejections_dir, result.row.record.github_id, "txt", text);
        }

        let mut verdict = result.verdict;
        // Catalog mutations stay on this thread, and a transition that fails
        // its own write-path FSV downgrades the verdict to quarantined — the
        // report never claims a state the vault refused to persist.
        let mut mutation_error: Option<CalyxError> = None;
        for (to, ctx) in result.transitions {
            if let Err(error) = catalog.transition(
                result.row.record.github_id,
                &result.row.record.full_name,
                to,
                ctx,
            ) {
                mutation_error = Some(error);
                break;
            }
        }
        if mutation_error.is_none()
            && let Some(ctx) = result.fact_refresh
            && let Err(error) = catalog.update_facts(
                result.row.record.github_id,
                &result.row.record.full_name,
                ctx,
            )
        {
            mutation_error = Some(error);
        }
        if let Some(error) = mutation_error {
            let detail = safe_reason(&format!(
                "catalog mutation failed after pipeline success: {} — {}",
                error.code, error.message
            ));
            // Quarantine so the failure is durable; if even that fails the
            // pass aborts with the structured error (nothing silent).
            catalog.transition(
                result.row.record.github_id,
                &result.row.record.full_name,
                RepoState::Quarantined,
                TransitionContext {
                    at_unix_secs: config.at_unix_secs,
                    quarantine_reason: Some(detail.clone()),
                    ..TransitionContext::default()
                },
            )?;
            verdict.outcome = Outcome::Quarantined;
            verdict.stage = Some("catalog".to_string());
            verdict.detail = detail;
        } else if verdict.outcome == Outcome::Quarantined {
            catalog.transition(
                result.row.record.github_id,
                &result.row.record.full_name,
                RepoState::Quarantined,
                TransitionContext {
                    at_unix_secs: config.at_unix_secs,
                    quarantine_reason: Some(format!(
                        "pipeline stage {}: {}",
                        verdict.stage.as_deref().unwrap_or("unknown"),
                        verdict.detail
                    )),
                    ..TransitionContext::default()
                },
            )?;
        }

        write_side_file(
            &verdicts_dir,
            verdict.github_id,
            "json",
            &serde_json::to_string_pretty(&verdict).expect("verdict serializes"),
        );
        // Advance the budget total by freshly created stores. Wiped-partial
        // and resumed stores make this a conservative overestimate (their torn
        // bytes were counted in the pass-start walk too) — the budget is a
        // guardrail, so overestimating is the safe direction.
        if let (Some(total), Some(bytes)) = (store_total_bytes.as_mut(), verdict.store_bytes)
            && matches!(verdict.outcome, Outcome::Kerneled | Outcome::Resumed)
        {
            *total += bytes;
        }
        verdicts.push(verdict);
    }
    drop(tx);
    let unattempted_budget = queue.len();

    let count = |outcome: Outcome| verdicts.iter().filter(|v| v.outcome == outcome).count();
    let wall_secs = started.elapsed().as_secs_f64();
    let kerneled_like =
        count(Outcome::Kerneled) + count(Outcome::Resumed) + count(Outcome::Refreshed);
    let counts = json!({
        "kerneled": count(Outcome::Kerneled),
        "resumed": count(Outcome::Resumed),
        "refreshed": count(Outcome::Refreshed),
        "skipped": count(Outcome::Skipped),
        "stale": count(Outcome::Stale),
        "skipped_state": count(Outcome::SkippedState),
        "quarantined": count(Outcome::Quarantined),
        "unattempted_budget": if budget_exhausted_at.is_some() { unattempted_budget } else { 0 },
        "total": verdicts.len(),
    });
    let repos_per_hour = if wall_secs > 0.0 {
        (kerneled_like as f64) * 3600.0 / wall_secs
    } else {
        0.0
    };
    let run_id = format!("pipeline-{}-{}", config.at_unix_secs, std::process::id());
    let report = json!({
        "run_id": run_id,
        "kind": "pipeline",
        "config": config,
        "counts": counts,
        "repos_per_hour": repos_per_hour,
        "verdicts": verdicts,
        "wall_secs": wall_secs,
    });

    let report_path = runs_dir.join(format!("{run_id}.json"));
    let report_bytes = serde_json::to_vec_pretty(&report).expect("run report serializes");
    fs::write(&report_path, &report_bytes).map_err(|error| CalyxError {
        code: ASTRO_FLEET_STORE_UNAVAILABLE,
        message: format!("cannot write run report {}: {error}", report_path.display()),
        remediation: "the store root must be writable for run reports",
    })?;
    let summary = serde_json::to_vec(&json!({
        "event": "fleet_pipeline_run",
        "run_id": run_id,
        "counts": counts,
        "repos_per_hour": repos_per_hour,
        "report_file": report_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }))
    .expect("run summary serializes");
    let (commit_seq, ledger_seq) = catalog.record_run_report(&run_id, report_bytes, summary)?;

    let failed = count(Outcome::Quarantined);
    if let Some(total) = budget_exhausted_at {
        let budget = config.store_budget_bytes.unwrap_or(0);
        let mut largest: Vec<(&str, u64)> = all_rows
            .iter()
            .filter_map(|row| {
                row.store_bytes
                    .map(|bytes| (row.record.full_name.as_str(), bytes))
            })
            .collect();
        largest.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
        largest.truncate(3);
        let largest_text = largest
            .iter()
            .map(|(name, bytes)| format!("{name}={bytes}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CalyxError {
            code: ASTRO_FLEET_STORE_BUDGET,
            message: format!(
                "fleet store total {total} bytes reached the declared budget {budget}; \
                 {unattempted_budget} selected repo(s) were not attempted ({failed} quarantined this pass); \
                 largest recorded stores: [{largest_text}]; report {}",
                report_path.display()
            ),
            remediation: "evict or archive the largest stores (catalog store_bytes, named in the message) or raise --store-budget-bytes, then re-run — completed repos are idempotent",
        });
    }
    if failed > 0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_PIPELINE_INCOMPLETE,
            message: format!(
                "pipeline pass {run_id} finished with {failed} quarantined repo(s); report {}",
                report_path.display()
            ),
            remediation: "inspect the run report, per-repo verdicts, and rejection files; quarantine reasons are on the catalog rows",
        });
    }

    let mut out = report;
    out["commit_seq"] = json!(commit_seq);
    out["ledger_seq"] = json!(ledger_seq);
    out["report_file"] = json!(report_path.display().to_string());
    Ok(out)
}

/// One repo's pipeline job, run on a worker thread. Catalog mutations are
/// returned to the main thread, never applied here.
fn pipeline_job(row: &FleetRepoRow, config: &PipelineConfig) -> JobResult {
    let started = Instant::now();
    let project = project_name(&row.record.full_name);
    let store_dir = config.store_root.join(&project);
    let wiped_partial_store = std::cell::Cell::new(false);
    let wiped_partial_store = &wiped_partial_store;
    let verdict_base = move |outcome: Outcome, stage: Option<&str>, detail: String| RepoVerdict {
        full_name: row.record.full_name.clone(),
        github_id: row.record.github_id,
        outcome,
        stage: stage.map(str::to_string),
        detail,
        head_commit_hash: None,
        sqlite_nodes: None,
        sqlite_edges: None,
        vault_base_rows: None,
        kernel_members_hash: None,
        kernel_member_count: None,
        stage_ms: BTreeMap::new(),
        wiped_partial_store: wiped_partial_store.get(),
        store_bytes: None,
        secs: started.elapsed().as_secs_f64(),
    };
    let fail = move |stage: &str, detail: String, rejection: Option<String>| JobResult {
        row: row.clone(),
        verdict: RepoVerdict {
            secs: started.elapsed().as_secs_f64(),
            ..verdict_base(Outcome::Quarantined, Some(stage), safe_reason(&detail))
        },
        rejection_text: rejection,
        transitions: Vec::new(),
        fact_refresh: None,
    };

    // Preflight: the clone must exist and be readable.
    let Some(clone_path) = row.clone_path.clone() else {
        return fail("preflight", "record has no clone_path".to_string(), None);
    };
    let clone_dir = PathBuf::from(&clone_path);
    if !clone_dir.is_dir() {
        return fail(
            "preflight",
            format!("clone_path {clone_path} does not exist"),
            None,
        );
    }
    let (ok, head, stderr) = match git_capture(&["rev-parse", "HEAD"], &clone_dir) {
        Ok(triple) => triple,
        Err(error) => return fail("preflight", error.message, None),
    };
    if !ok {
        return fail(
            "preflight",
            format!("git rev-parse HEAD failed in {clone_path}: {stderr}"),
            None,
        );
    }

    // Idempotent skip / stale / force on already-kerneled records.
    if row.state == RepoState::Kerneled {
        if !config.force {
            return if row.head_commit_hash.as_deref() == Some(head.as_str()) {
                JobResult {
                    row: row.clone(),
                    verdict: RepoVerdict {
                        head_commit_hash: Some(head),
                        ..verdict_base(
                            Outcome::Skipped,
                            None,
                            "already kerneled at this clone HEAD".to_string(),
                        )
                    },
                    rejection_text: None,
                    transitions: Vec::new(),
                    fact_refresh: None,
                }
            } else {
                JobResult {
                    row: row.clone(),
                    verdict: RepoVerdict {
                        head_commit_hash: Some(head.clone()),
                        ..verdict_base(
                            Outcome::Stale,
                            None,
                            format!(
                                "kerneled at {} but clone HEAD is {head}; re-index belongs to the growth cycle (#457) or --force",
                                row.head_commit_hash.as_deref().unwrap_or("<unset>")
                            ),
                        )
                    },
                    rejection_text: None,
                    transitions: Vec::new(),
                    fact_refresh: None,
                }
            };
        }
    } else if row.state == RepoState::Cloned {
        // Never-transitioned record: a leftover store dir is a torn partial
        // run — remove and redo (documented resume semantic, labeled in the
        // verdict via `wiped_partial_store`). But only a dir this pipeline
        // recognizes as its own may be wiped: anything else is foreign
        // content and the job refuses rather than overwrite (#454).
        if store_dir.exists() {
            if let Some(foreign) = foreign_store_entry(&store_dir, &project) {
                return fail(
                    "preflight",
                    format!(
                        "{ASTRO_FLEET_STORE_FOREIGN}: store dir {} pre-exists with unrecognized entry {foreign:?}; refusing to remove it — move the foreign content aside or point --store-root elsewhere",
                        store_dir.display()
                    ),
                    None,
                );
            }
            if let Err(error) = fs::remove_dir_all(&store_dir) {
                return fail(
                    "preflight",
                    format!(
                        "partial store dir {} could not be removed for a clean re-run: {error}",
                        store_dir.display()
                    ),
                    None,
                );
            }
            wiped_partial_store.set(true);
        }
    }

    if let Err(error) = fs::create_dir_all(&store_dir) {
        return fail(
            "preflight",
            format!("cannot create store dir {}: {error}", store_dir.display()),
            None,
        );
    }

    // Stage the args file and spawn the confined pipeline child.
    let args_path = store_dir.join("index-args.json");
    let args_json = json!({
        "repo_path": clone_path,
        "name": project,
        "calyx": "shadow",
        "mode": "fast",
    });
    if let Err(error) = fs::write(&args_path, args_json.to_string()) {
        return fail(
            "preflight",
            format!("cannot write args file {}: {error}", args_path.display()),
            None,
        );
    }
    let stdout_path = store_dir.join("pipeline-stdout.json");
    let stderr_path = store_dir.join("pipeline-stderr.txt");
    let (stdout_file, stderr_file) = match (
        fs::File::create(&stdout_path),
        fs::File::create(&stderr_path),
    ) {
        (Ok(out), Ok(err)) => (out, err),
        (Err(error), _) | (_, Err(error)) => {
            return fail(
                "preflight",
                format!("cannot create pipeline capture files: {error}"),
                None,
            );
        }
    };
    let mut command = Command::new(&config.astrolabe_bin);
    command
        .args(["cli", "--json", "index_repository", "--args-file"])
        .arg(&args_path)
        .env("CBM_CACHE_DIR", &store_dir)
        .env("ASTRO_NOMIC_DIR", &config.nomic_dir)
        .env("ASTRO_SHADOW_TIMING", "1")
        .stdin(Stdio::null())
        .stdout(stdout_file)
        .stderr(stderr_file);
    silence_credential_prompts(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return fail(
                "pipeline",
                format!(
                    "failed to spawn {}: {error}",
                    config.astrolabe_bin.display()
                ),
                None,
            );
        }
    };
    let _job = match JobGuard::assign(&child) {
        Ok(guard) => guard,
        Err(why) => {
            let _ = child.kill();
            let _ = child.wait();
            return fail(
                "pipeline",
                format!("could not tie the pipeline child to a job object: {why}"),
                None,
            );
        }
    };
    let deadline = Instant::now() + Duration::from_secs(config.timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(CHILD_POLL);
            }
            Err(error) => {
                return fail(
                    "pipeline",
                    format!("waiting on pipeline child: {error}"),
                    None,
                );
            }
        }
    };
    let stderr_text = fs::read_to_string(&stderr_path).unwrap_or_default();
    let stage_ms = parse_stage_timings(&stderr_text);
    let Some(status) = status else {
        return fail(
            "timeout",
            format!(
                "pipeline exceeded {}s and was killed (job-object confined)",
                config.timeout_secs
            ),
            Some(format!(
                "repo: {}\nphase: timeout after {}s\nstderr tail:\n{}\n",
                row.record.full_name,
                config.timeout_secs,
                tail(&stderr_text, 4000)
            )),
        );
    };
    let stdout_text = fs::read_to_string(&stdout_path).unwrap_or_default();
    if !status.success() {
        return fail(
            "pipeline",
            format!(
                "pipeline child exited nonzero ({status}); stdout head: {}",
                safe_reason(&head_of(&stdout_text, 200))
            ),
            Some(format!(
                "repo: {}\nphase: child exit {status}\nstdout head:\n{}\nstderr tail:\n{}\n",
                row.record.full_name,
                head_of(&stdout_text, 8000),
                tail(&stderr_text, 8000)
            )),
        );
    }

    // Parse the MCP envelope strictly.
    let envelope: Value = match serde_json::from_str(&stdout_text) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                "parse",
                format!("pipeline stdout is not JSON: {error}"),
                Some(format!(
                    "repo: {}\nphase: envelope parse\nstdout head:\n{}\n",
                    row.record.full_name,
                    head_of(&stdout_text, 8000)
                )),
            );
        }
    };
    if envelope["isError"].as_bool().unwrap_or(true) {
        let text = envelope["content"][0]["text"]
            .as_str()
            .unwrap_or("<no text>");
        return fail(
            "pipeline",
            format!("index_repository refused: {}", head_of(text, 300)),
            Some(format!(
                "repo: {}\nphase: tool error\n{text}\n",
                row.record.full_name
            )),
        );
    }
    let inner: Value = match envelope["content"][0]["text"]
        .as_str()
        .ok_or_else(|| "envelope carries no text content".to_string())
        .and_then(|text| serde_json::from_str(text).map_err(|error| error.to_string()))
    {
        Ok(value) => value,
        Err(error) => {
            return fail(
                "parse",
                format!("pipeline result did not parse: {error}"),
                None,
            );
        }
    };
    let inner_status = inner["status"].as_str().unwrap_or("<missing>");
    if inner_status != "indexed" {
        return fail(
            "pipeline",
            format!("index_repository status {inner_status:?}, expected \"indexed\""),
            Some(format!(
                "repo: {}\nphase: result status\n{}\n",
                row.record.full_name,
                head_of(&inner.to_string(), 8000)
            )),
        );
    }
    let vault_fingerprint = inner["vault_fingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let Some(kernel) = find_key(&inner, "kernel_artifact") else {
        return fail(
            "kernel",
            "pipeline result carries no kernel_artifact section".to_string(),
            None,
        );
    };
    if kernel["status"].as_str() != Some("persisted") {
        return fail(
            "kernel",
            format!(
                "kernel artifact not persisted: status {:?}, reason {:?}",
                kernel["status"].as_str().unwrap_or("<missing>"),
                kernel["reason"].as_str().unwrap_or("<none>")
            ),
            Some(format!(
                "repo: {}\nphase: kernel persist\n{kernel}\n",
                row.record.full_name
            )),
        );
    }
    let reported_members_hash = kernel["members_hash"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Independent persisted-state verification (the transition gate).
    let scope = kernel_scope_id(&project);
    let verify = verify_persisted(&store_dir, &project, &scope, &reported_members_hash);
    let (sqlite_nodes, sqlite_edges, vault_base_rows, kernel_member_count) = match verify {
        Ok(counts) => counts,
        Err(detail) => {
            return fail(
                "verify",
                detail.clone(),
                Some(format!(
                    "repo: {}\nphase: independent readback\n{detail}\n",
                    row.record.full_name
                )),
            );
        }
    };

    // #454 disk accounting: the store's measured on-disk bytes ride the
    // `kerneled` transition (or the `--force` fact refresh) onto the catalog
    // row. Measured after verification so the number covers the final store.
    let store_bytes = match dir_size_bytes(&store_dir) {
        Ok(bytes) => bytes,
        Err(error) => {
            return fail(
                "verify",
                format!(
                    "cannot measure store dir {} for disk accounting: {error}",
                    store_dir.display()
                ),
                None,
            );
        }
    };

    // Stage the catalog mutations for the main thread.
    let watermark = format!("vault:{vault_fingerprint}");
    let mut transitions = Vec::new();
    let mut fact_refresh = None;
    let outcome = match row.state {
        RepoState::Cloned => {
            transitions.push((
                RepoState::Indexed,
                TransitionContext {
                    at_unix_secs: config.at_unix_secs,
                    head_commit_hash: Some(head.clone()),
                    index_watermark: Some(watermark.clone()),
                    ..TransitionContext::default()
                },
            ));
            transitions.push((
                RepoState::Kerneled,
                TransitionContext {
                    at_unix_secs: config.at_unix_secs,
                    kernel_scope_id: Some(scope.clone()),
                    store_bytes: Some(store_bytes),
                    ..TransitionContext::default()
                },
            ));
            Outcome::Kerneled
        }
        RepoState::Indexed => {
            transitions.push((
                RepoState::Kerneled,
                TransitionContext {
                    at_unix_secs: config.at_unix_secs,
                    head_commit_hash: Some(head.clone()),
                    index_watermark: Some(watermark.clone()),
                    kernel_scope_id: Some(scope.clone()),
                    store_bytes: Some(store_bytes),
                    ..TransitionContext::default()
                },
            ));
            Outcome::Resumed
        }
        RepoState::Kerneled => {
            fact_refresh = Some(TransitionContext {
                at_unix_secs: config.at_unix_secs,
                head_commit_hash: Some(head.clone()),
                index_watermark: Some(watermark.clone()),
                kernel_scope_id: Some(scope.clone()),
                store_bytes: Some(store_bytes),
                ..TransitionContext::default()
            });
            Outcome::Refreshed
        }
        other => {
            return fail(
                "preflight",
                format!(
                    "unexpected source state {} reached the pipeline job",
                    other.as_str()
                ),
                None,
            );
        }
    };

    JobResult {
        row: row.clone(),
        verdict: RepoVerdict {
            full_name: row.record.full_name.clone(),
            github_id: row.record.github_id,
            outcome,
            stage: None,
            detail: format!("pipeline complete; kernel scope {scope}"),
            head_commit_hash: Some(head),
            sqlite_nodes: Some(sqlite_nodes),
            sqlite_edges: Some(sqlite_edges),
            vault_base_rows: Some(vault_base_rows),
            kernel_members_hash: Some(reported_members_hash),
            kernel_member_count: Some(kernel_member_count),
            stage_ms,
            wiped_partial_store: wiped_partial_store.get(),
            store_bytes: Some(store_bytes),
            secs: started.elapsed().as_secs_f64(),
        },
        rejection_text: None,
        transitions,
        fact_refresh,
    }
}

/// Reads back every Base-CF key of a project's shadow vault as lowercase hex,
/// sorted — the #454 SHADOW_VAULT_ID soundness probe primitive. Two projects
/// holding a byte-identical file must still produce disjoint key sets, because
/// CxId derivation is salted per project ([`shadow_vault_salt`]) even though
/// the vault ULID is shared; intersecting two projects' key dumps proves (or
/// falsifies) that independently of the writer.
pub fn vault_base_keys(store_root: &Path, project: &str) -> Result<Vec<String>, CalyxError> {
    let vault_dir = store_root.join(project).join(format!("{project}.astrolabe-vault"));
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID).map_err(|error| CalyxError {
        code: ASTRO_FLEET_STORE_UNAVAILABLE,
        message: format!("shadow vault id failed to parse: {error:?}"),
        remediation: "internal defect: SHADOW_VAULT_ID must be a valid ULID",
    })?;
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        shadow_vault_salt(project).into_bytes(),
        VaultOptions {
            read_only: true,
            ..VaultOptions::default()
        },
    )?;
    let mut keys: Vec<String> = vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::Base)?
        .into_iter()
        .map(|(key, _)| {
            key.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect();
    keys.sort();
    Ok(keys)
}

/// Recursive on-disk byte count of `dir` (regular files only; reparse points
/// are not followed). Used for #454 disk accounting and budget enforcement.
fn dir_size_bytes(dir: &Path) -> Result<u64, String> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut total = 0_u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|error| format!("read_dir {}: {error}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read_dir entry: {error}"))?;
            let meta = entry
                .metadata()
                .map_err(|error| format!("metadata {}: {error}", entry.path().display()))?;
            if meta.is_dir() && !meta.is_symlink() {
                stack.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}

/// Returns the first entry of `store_dir` this pipeline does not recognize as
/// its own output for `project`, or `None` when every entry is recognized
/// (#454: only a recognized store may be wiped for a clean re-run).
fn foreign_store_entry(store_dir: &Path, project: &str) -> Option<String> {
    const FIXED: [&str; 5] = [
        "_config.db",
        "index-args.json",
        "pipeline-stdout.json",
        "pipeline-stderr.txt",
        "logs",
    ];
    let entries = match fs::read_dir(store_dir) {
        Ok(entries) => entries,
        // Unreadable = unknown = foreign; the caller refuses.
        Err(error) => return Some(format!("<unreadable store dir: {error}>")),
    };
    for entry in entries {
        let name = match entry {
            Ok(entry) => entry.file_name().to_string_lossy().into_owned(),
            Err(error) => return Some(format!("<unreadable entry: {error}>")),
        };
        let recognized = FIXED.contains(&name.as_str())
            || name.starts_with(&format!("{project}."))
            || name.starts_with("_config.db");
        if !recognized {
            return Some(name);
        }
    }
    None
}

/// Independent persisted-state readback: CBM sqlite counts, shadow-vault Base
/// rows, and the persisted kernel artifact whose members-hash must equal the
/// pipeline's claim. Returns
/// `(sqlite_nodes, sqlite_edges, vault_base_rows, kernel_member_count)`.
fn verify_persisted(
    store_dir: &Path,
    project: &str,
    scope: &str,
    reported_members_hash: &str,
) -> Result<(u64, u64, u64, u64), String> {
    // (a) CBM sqlite. Opened read-write because a WAL-journaled SQLite may
    // need to recover its WAL on open; only SELECTs run here.
    let db_path = store_dir.join(format!("{project}.db"));
    let connection = rusqlite::Connection::open(&db_path)
        .map_err(|error| format!("open CBM sqlite {}: {error}", db_path.display()))?;
    let count = |sql: &str| -> Result<u64, String> {
        connection
            .query_row(sql, [], |row| row.get::<_, i64>(0))
            .map(|n| n as u64)
            .map_err(|error| format!("{sql}: {error}"))
    };
    let sqlite_nodes = count("SELECT COUNT(*) FROM nodes")?;
    let sqlite_edges = count("SELECT COUNT(*) FROM edges")?;
    if sqlite_nodes == 0 {
        return Err(format!(
            "CBM sqlite {} has zero nodes — the index pass persisted nothing",
            db_path.display()
        ));
    }
    drop(connection);

    // (b) Shadow vault Base rows.
    let vault_dir = store_dir.join(format!("{project}.astrolabe-vault"));
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID)
        .map_err(|error| format!("shadow vault id failed to parse: {error:?}"))?;
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        shadow_vault_salt(project).into_bytes(),
        VaultOptions {
            read_only: true,
            ..VaultOptions::default()
        },
    )
    .map_err(|error| {
        format!(
            "open shadow vault {}: {} — {}",
            vault_dir.display(),
            error.code,
            error.message
        )
    })?;
    let vault_base_rows = vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::Base)
        .map_err(|error| {
            format!(
                "scan shadow vault Base CF: {} — {}",
                error.code, error.message
            )
        })?
        .len() as u64;
    if vault_base_rows == 0 {
        return Err(format!(
            "shadow vault {} has zero Base rows — the import persisted nothing",
            vault_dir.display()
        ));
    }

    // (c) Persisted kernel artifact, read back independently of the write
    // path; its members-hash must match the pipeline's claim.
    let artifact = astrolabe_ingest::read_persisted_kernel_artifact(&vault, scope)
        .map_err(|error| format!("read persisted kernel artifact for {scope}: {error}"))?
        .ok_or_else(|| {
            format!("no persisted kernel artifact in the Kernel CF for scope {scope}")
        })?;
    if artifact.members_hash != reported_members_hash {
        return Err(format!(
            "persisted kernel members-hash {} != pipeline-reported {} for scope {scope}",
            artifact.members_hash, reported_members_hash
        ));
    }
    Ok((
        sqlite_nodes,
        sqlite_edges,
        vault_base_rows,
        artifact.member_count as u64,
    ))
}

/// Depth-first search for the first object under `key` anywhere in the tree.
fn find_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(key) {
                return Some(found);
            }
            map.values().find_map(|child| find_key(child, key))
        }
        Value::Array(items) => items.iter().find_map(|child| find_key(child, key)),
        _ => None,
    }
}

/// Extracts top-level `astro.shadow.timing phase=<p> ms=<n>` lines (phases
/// without a `.`, i.e. whole stages, plus `import_raw_total`).
fn parse_stage_timings(stderr_text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in stderr_text.lines() {
        let Some(rest) = line.trim().strip_prefix("astro.shadow.timing phase=") else {
            continue;
        };
        let Some((phase, ms)) = rest.split_once(" ms=") else {
            continue;
        };
        if phase.contains('.') && phase != "import_raw_total" {
            continue;
        }
        if let Ok(ms) = ms.trim().parse::<u64>() {
            out.insert(phase.to_string(), ms);
        }
    }
    out
}

fn write_side_file(dir: &Path, github_id: u64, ext: &str, text: &str) {
    if let Err(error) = fs::create_dir_all(dir)
        .and_then(|()| fs::write(dir.join(format!("{github_id}.{ext}")), text))
    {
        eprintln!(
            "{}",
            json!({
                "code": "ASTRO_FLEET_REPORT_FILE_UNWRITABLE",
                "message": format!("cannot write report side file for github_id {github_id}: {error}"),
                "remediation": "the store root must be writable; the catalog record itself is unaffected",
            })
        );
    }
}

fn head_of(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn tail(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let start = chars.len().saturating_sub(max);
    chars[start..].iter().collect()
}
