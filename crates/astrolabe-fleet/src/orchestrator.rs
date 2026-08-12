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
    JobGuard, Selection, child_working_set_bytes, git_capture, safe_reason,
    silence_credential_prompts,
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
/// Refusal code when the stable fleet store key and the server-derived inner
/// project identity cannot be bound through the durable kernel scope.
pub const ASTRO_FLEET_PROJECT_IDENTITY: &str = "ASTRO_FLEET_PROJECT_IDENTITY";
/// Refusal code when a finite fleet-only host admission wait expires without
/// starting any native index work. The source row remains in its prior state.
pub const ASTRO_FLEET_HOST_BUSY: &str = "ASTRO_FLEET_HOST_BUSY";
/// Refusal code for a pipeline scheduling/deadline configuration that cannot
/// be represented exactly by the native Windows admission primitive.
pub const ASTRO_FLEET_PIPELINE_CONFIG: &str = "ASTRO_FLEET_PIPELINE_CONFIG";

/// Declared default fleet store root (per-repo CBM cache/vault sets).
pub const DEFAULT_STORE_ROOT: &str = r"D:\astrolabe-fleet\store";
/// Declared product-owned scratch root for Git archaeology. Every pipeline child
/// receives this as `ASTRO_ARCHAEOLOGY_ROOT`; the server never consults ambient TEMP.
pub const DEFAULT_ARCHAEOLOGY_ROOT: &str = r"D:\astrolabe-fleet\scratch";
/// Declared default nomic vector-blob directory (#442: a relocated
/// `astrolabe.exe` needs `ASTRO_NOMIC_DIR` or it fails with a structured
/// error; the orchestrator always sets it).
pub const DEFAULT_NOMIC_DIR: &str = r"C:\code\Astrolabe\cbm\vendored\nomic";
/// Declared pipeline worklist concurrency. The expensive native index phase is
/// independently capped at [`EXPENSIVE_INDEX_HOST_CARDINALITY`].
pub const DEFAULT_PIPELINE_PARALLELISM: usize = 2;
/// Declared per-repo pipeline timeout, seconds.
pub const DEFAULT_PIPELINE_TIMEOUT_SECS: u64 = 1800;
/// Fleet-only finite wait for the authoritative host index slot. It derives
/// from the same measured per-repo budget rather than introducing a second
/// arbitrary duration. Ordinary MCP callers do not receive this setting.
pub const DEFAULT_HOST_ADMISSION_TIMEOUT_SECS: u64 = DEFAULT_PIPELINE_TIMEOUT_SECS;
/// #802 measured one full native index as consuming the host worker budget.
/// This is the scheduler's explicit expensive-stage capacity, not a tunable.
pub const EXPENSIVE_INDEX_HOST_CARDINALITY: usize = 1;
/// Private child-process transport understood by the native admission layer.
pub const FLEET_INDEX_ADMISSION_TIMEOUT_ENV: &str = "ASTRO_FLEET_INDEX_ADMISSION_TIMEOUT_MS";
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

/// Exact separation between one stable fleet catalog/store key and the
/// path-derived project identity used inside CBM, shadow-vault salts, and the
/// per-repo kernel scope (#808).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RepoStoreIdentity {
    /// Stable outer directory and fleet provenance key (`owner__repo`).
    pub store_key: String,
    /// Server-derived CBM/shadow identity.
    pub index_project: String,
    /// Durable per-repo kernel scope (`repo:<index_project>`).
    pub kernel_scope: String,
}

/// Decodes a kerneled catalog row's exact store/inner identity binding.
///
/// Legacy rows remain explicit rather than guessed: their already-durable
/// `kernel_scope_id` supplies the inner project, which happens to equal the
/// outer key for artifacts created before caller-selected names were retired.
pub fn repo_store_identity(row: &FleetRepoRow) -> Result<RepoStoreIdentity, CalyxError> {
    let store_key = project_name(&row.record.full_name);
    let kernel_scope = row.kernel_scope_id.as_deref().ok_or_else(|| {
        project_identity_error(
            &row.record.full_name,
            "catalog row has no durable kernel_scope_id",
        )
    })?;
    let index_project = kernel_scope
        .strip_prefix("repo:")
        .filter(|project| valid_index_project(project))
        .ok_or_else(|| {
            project_identity_error(
                &row.record.full_name,
                &format!(
                    "kernel_scope_id {kernel_scope:?} is not repo:<valid path-derived project>"
                ),
            )
        })?
        .to_string();
    Ok(RepoStoreIdentity {
        store_key,
        index_project,
        kernel_scope: kernel_scope.to_string(),
    })
}

/// Resolves one stable `owner__repo` key to its unique durable catalog
/// identity. No directory-name inference is permitted.
pub fn catalog_store_identity(
    catalog: &FleetCatalog,
    store_key: &str,
) -> Result<RepoStoreIdentity, CalyxError> {
    let mut matches = catalog
        .query(None, None)?
        .into_iter()
        .filter(|row| project_name(&row.record.full_name) == store_key);
    let row = matches.next().ok_or_else(|| {
        project_identity_error(
            store_key,
            "stable store key has no matching fleet catalog row",
        )
    })?;
    if matches.next().is_some() {
        return Err(project_identity_error(
            store_key,
            "stable store key maps to more than one fleet catalog row",
        ));
    }
    repo_store_identity(&row)
}

fn valid_index_project(project: &str) -> bool {
    !project.is_empty()
        && project.len() <= 255
        && !project.starts_with('.')
        && !project.ends_with('-')
        && !project.contains("..")
        && project
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn project_identity_error(subject: &str, detail: &str) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_PROJECT_IDENTITY,
        message: format!("fleet project identity for {subject} is inconsistent: {detail}"),
        remediation: "preserve the catalog and store bytes; re-run index_repository without a name override and bind only its returned project through the durable repo:<project> kernel scope",
    }
}

/// Declared knobs of one pipeline pass.
#[derive(Clone, Debug, Serialize)]
pub struct PipelineConfig {
    /// Fleet store root holding one `<org>__<repo>` store dir per repo.
    pub store_root: PathBuf,
    /// Compact local base for repo+project-bound archaeology worktree/pool scopes.
    pub archaeology_root: PathBuf,
    /// The pipeline binary (`astrolabe.exe`).
    pub astrolabe_bin: PathBuf,
    /// Nomic vector-blob directory exported as `ASTRO_NOMIC_DIR` (#442).
    pub nomic_dir: PathBuf,
    /// Bounded pipeline parallelism.
    pub parallelism: usize,
    /// Per-repo pipeline timeout in seconds.
    pub timeout_secs: u64,
    /// Finite fleet-only wait for externally owned host index capacity.
    pub host_admission_timeout_secs: u64,
    /// Re-run repos already `kerneled` and refresh their recorded facts.
    pub force: bool,
    /// Keep a pre-existing `kerneled` catalog row in that state when an
    /// explicit recovery pipeline fails. The failed verdict/report remains
    /// durable; this only prevents the failure recorder from making the exact
    /// recovery path inadmissible on its next attempt.
    pub retain_kerneled_state_on_failure: bool,
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
            archaeology_root: PathBuf::from(DEFAULT_ARCHAEOLOGY_ROOT),
            astrolabe_bin: sibling,
            nomic_dir: PathBuf::from(DEFAULT_NOMIC_DIR),
            parallelism: DEFAULT_PIPELINE_PARALLELISM,
            timeout_secs: DEFAULT_PIPELINE_TIMEOUT_SECS,
            host_admission_timeout_secs: DEFAULT_HOST_ADMISSION_TIMEOUT_SECS,
            force: false,
            retain_kerneled_state_on_failure: false,
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
    /// The finite fleet-only host admission wait expired before any native
    /// pipeline/publication work. The catalog source state is unchanged.
    DeferredHostBusy,
}

/// Authoritative native host-admission telemetry copied from the structured
/// CBM result only after exact schema/path validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IndexAdmissionTelemetry {
    /// Fleet-requested finite wait in milliseconds (zero for ordinary MCP).
    pub host_timeout_ms: u64,
    /// Monotonic time actually spent in the native mutex wait.
    pub host_waited_ms: u64,
    /// The native mutex granted capacity after observing an abandoned owner.
    pub recovered_abandoned_capacity: bool,
}

/// Typed, lossless account of every accepted per-corpus degradation emitted
/// by the native index generation. A nonzero field makes the generation a
/// `partial_success`; a zeroed account makes it `indexed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PipelineDegradation {
    /// Canonical `ContentDefect` nodes independently recounted in SQLite.
    pub content_defects: u64,
    /// Canonical `HAS_CONTENT_DEFECT` edges independently recounted in SQLite.
    pub content_defect_relationships: u64,
    /// Content defects diagnosed by this invocation (rather than retained
    /// from an incremental generation).
    pub content_defects_observed_this_run: u64,
    /// Reference edges withheld because one source resolved to several atoms.
    pub ambiguous_reference_skips: u64,
    /// Reference edges withheld because the asserted source atom was absent.
    pub unresolved_reference_source_skips: u64,
    /// Rust module declarations with neither compiler-defined target path.
    pub dangling_rust_module_skips: u64,
    /// Files for which tree-sitter persisted an exact recovery diagnostic.
    pub parse_recovery_diagnostics: u64,
}

impl PipelineDegradation {
    fn is_partial(&self) -> bool {
        self.content_defects > 0
            || self.ambiguous_reference_skips > 0
            || self.unresolved_reference_source_skips > 0
            || self.dangling_rust_module_skips > 0
            || self.parse_recovery_diagnostics > 0
    }
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
    /// Exact native completion class after counter/status consistency checks.
    pub pipeline_status: Option<String>,
    /// Typed native degradation account, with content-defect totals replaced
    /// by independent SQLite readback before publication.
    pub pipeline_degradation: Option<PipelineDegradation>,
    /// Kernel members-hash read back from the persisted artifact.
    pub kernel_members_hash: Option<String>,
    /// Kernel member count read back from the persisted artifact.
    pub kernel_member_count: Option<u64>,
    /// Top-level pipeline stage timings (ms) parsed from the timing stream.
    pub stage_ms: BTreeMap<String, u64>,
    /// Exact native host-admission timing when the child reached admission.
    pub index_admission: Option<IndexAdmissionTelemetry>,
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
    /// Exact structured capacity envelope for a scheduling deferral.
    scheduling_text: Option<String>,
    /// Transitions the main thread must apply, in order.
    transitions: Vec<(RepoState, TransitionContext)>,
    /// `--force` fact refresh instead of transitions.
    fact_refresh: Option<TransitionContext>,
}

/// One pass's persisted report plus its would-be fail-closed refusal, for
/// callers (the growth cycle, #457) that must contain per-repo failures
/// without losing the report. `refusal` is exactly the error
/// [`run_pipeline_pass`] would have returned; a caller that swallows it must
/// count and surface it — never drop it silently (invariant 3).
pub struct PassOutcome {
    /// The run report (already persisted to the store root and the catalog
    /// vault), with `commit_seq`/`ledger_seq`/`report_file` attached.
    pub report: Value,
    /// Repos that hard-failed this pass (quarantined).
    pub failed: usize,
    /// The fail-closed refusal the pass would have raised, if any.
    pub refusal: Option<CalyxError>,
}

/// Runs one pipeline pass. Returns the run report on success; a pass with
/// quarantines persists its report and then fails closed naming the counts.
pub fn run_pipeline_pass(
    catalog: &FleetCatalog,
    config: &PipelineConfig,
    selection: &Selection,
) -> Result<Value, CalyxError> {
    let outcome = run_pipeline_pass_outcome(catalog, config, selection)?;
    match outcome.refusal {
        Some(refusal) => Err(refusal),
        None => Ok(outcome.report),
    }
}

/// Runs one pipeline pass and returns its [`PassOutcome`]: the persisted
/// report together with the pass's would-be refusal instead of failing
/// closed. Hard errors (catalog/store unavailable, worker loss) still refuse.
pub fn run_pipeline_pass_outcome(
    catalog: &FleetCatalog,
    config: &PipelineConfig,
    selection: &Selection,
) -> Result<PassOutcome, CalyxError> {
    let started = Instant::now();
    let host_admission_timeout_ms = validate_pipeline_config(config)?;
    let effective_index_parallelism = config.parallelism.min(EXPENSIVE_INDEX_HOST_CARDINALITY);
    let child_budget_secs = config
        .timeout_secs
        .checked_add(config.host_admission_timeout_secs)
        .ok_or_else(|| pipeline_config_error("pipeline + host admission timeout overflow"))?;
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
                        pipeline_status: None,
                        pipeline_degradation: None,
                        kernel_members_hash: None,
                        kernel_member_count: None,
                        stage_ms: BTreeMap::new(),
                        index_admission: None,
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
    let scheduling_dir = runs_dir.join(format!("scheduling-{}", config.at_unix_secs));

    // #454 disk budget: measured once at pass start, then advanced by each
    // completed repo's measured store bytes — the walk stays O(store) once
    // per pass instead of once per repo.
    let mut store_total_bytes = match config.store_budget_bytes {
        Some(_) => Some(
            dir_size_bytes(&config.store_root).map_err(|error| CalyxError {
                code: ASTRO_FLEET_STORE_UNAVAILABLE,
                message: format!(
                    "cannot measure store root {} for budget accounting: {error}",
                    config.store_root.display()
                ),
                remediation: "the store root must be readable when --store-budget-bytes is set",
            })?,
        ),
        None => None,
    };
    let mut budget_exhausted_at: Option<u64> = None;

    let mut queue: std::collections::VecDeque<FleetRepoRow> = selected.into();
    let mut in_flight = 0_usize;
    let (tx, rx) = mpsc::channel::<JobResult>();
    loop {
        while in_flight < effective_index_parallelism {
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
                let result = pipeline_job(&row, &config_for_job, host_admission_timeout_ms);
                let _ = tx.send(result);
            });
            in_flight += 1;
        }
        if in_flight == 0 {
            break;
        }
        let result = rx
            .recv_timeout(Duration::from_secs(child_budget_secs.saturating_add(300)))
            .map_err(|error| CalyxError {
                code: ASTRO_FLEET_PIPELINE_SPAWN,
                message: format!("pipeline worker did not report within the deadline: {error}"),
                remediation: "internal defect: a worker thread hung or panicked; re-run the pass — completed repos are idempotent",
            })?;
        in_flight -= 1;

        if let Some(text) = &result.rejection_text {
            write_side_file(&rejections_dir, result.row.record.github_id, "txt", text);
        }
        if let Some(text) = &result.scheduling_text {
            write_side_file(&scheduling_dir, result.row.record.github_id, "json", text);
        }

        let mut verdict = result.verdict;
        let retain_kerneled_state =
            config.retain_kerneled_state_on_failure && result.row.state == RepoState::Kerneled;
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
            // Quarantine so the failure is durable. A refused quarantine
            // transition is contained to THIS repo (appended to its verdict
            // detail, counted in the run report) — one row's catalog fight
            // must never abort the remaining repos of a multi-repo pass
            // (2026-07-16: a concurrent pass's row write turned this `?` into
            // a whole-pass abort with 8 repos never attempted).
            verdict.outcome = Outcome::Quarantined;
            verdict.stage = Some("catalog".to_string());
            verdict.detail = detail.clone();
            if retain_kerneled_state {
                verdict.detail = safe_reason(&format!(
                    "{} — pre-existing kerneled state retained for explicit recovery",
                    verdict.detail
                ));
            } else if let Err(record_error) = catalog.transition(
                result.row.record.github_id,
                &result.row.record.full_name,
                RepoState::Quarantined,
                TransitionContext {
                    at_unix_secs: config.at_unix_secs,
                    quarantine_reason: Some(detail),
                    ..TransitionContext::default()
                },
            ) {
                verdict.detail = safe_reason(&format!(
                    "{} — AND recording the quarantine was refused: {} — {}",
                    verdict.detail, record_error.code, record_error.message
                ));
            }
        } else if verdict.outcome == Outcome::Quarantined {
            if retain_kerneled_state {
                verdict.detail = safe_reason(&format!(
                    "{} — pre-existing kerneled state retained for explicit recovery",
                    verdict.detail
                ));
            } else if let Err(record_error) = catalog.transition(
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
            ) {
                // Same containment: the verdict side-file + run report carry the
                // full story (labeled, counted); the pass continues.
                verdict.detail = safe_reason(&format!(
                    "{} — AND recording the quarantine was refused: {} — {}",
                    verdict.detail, record_error.code, record_error.message
                ));
            }
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
        "deferred_host_busy": count(Outcome::DeferredHostBusy),
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
        "scheduler": {
            "requested_parallelism": config.parallelism,
            "effective_expensive_index_parallelism": effective_index_parallelism,
            "expensive_index_host_cardinality": EXPENSIVE_INDEX_HOST_CARDINALITY,
            "host_admission_timeout_ms": host_admission_timeout_ms,
        },
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
    let deferred = count(Outcome::DeferredHostBusy);
    let refusal = if let Some(total) = budget_exhausted_at {
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
        Some(CalyxError {
            code: ASTRO_FLEET_STORE_BUDGET,
            message: format!(
                "fleet store total {total} bytes reached the declared budget {budget}; \
                 {unattempted_budget} selected repo(s) were not attempted ({failed} quarantined and {deferred} capacity-deferred this pass); \
                 largest recorded stores: [{largest_text}]; report {}",
                report_path.display()
            ),
            remediation: "evict or archive the largest stores (catalog store_bytes, named in the message) or raise --store-budget-bytes, then re-run — completed repos are idempotent",
        })
    } else if failed > 0 {
        Some(CalyxError {
            code: ASTRO_FLEET_PIPELINE_INCOMPLETE,
            message: format!(
                "pipeline pass {run_id} finished with {failed} quarantined repo(s); report {}",
                report_path.display()
            ),
            remediation: "inspect the run report, per-repo verdicts, and rejection files; quarantine reasons are on the catalog rows",
        })
    } else if deferred > 0 {
        Some(CalyxError {
            code: ASTRO_FLEET_HOST_BUSY,
            message: format!(
                "pipeline pass {run_id} reached its finite host admission budget for {deferred} repo(s) before native index work began; report {}",
                report_path.display()
            ),
            remediation: "the affected catalog rows and source stores were not classified as defective; let the active host index finish and run the next growth cycle, which naturally selects their unchanged source states",
        })
    } else {
        None
    };

    let mut out = report;
    out["commit_seq"] = json!(commit_seq);
    out["ledger_seq"] = json!(ledger_seq);
    out["report_file"] = json!(report_path.display().to_string());
    Ok(PassOutcome {
        report: out,
        failed,
        refusal,
    })
}

fn pipeline_config_error(detail: &str) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_PIPELINE_CONFIG,
        message: format!("fleet pipeline configuration is invalid: {detail}"),
        remediation: "pass positive pipeline parallelism/timeout values and a finite host admission wait representable as Windows milliseconds",
    }
}

fn validate_pipeline_config(config: &PipelineConfig) -> Result<u32, CalyxError> {
    if config.parallelism == 0 {
        return Err(pipeline_config_error(
            "parallelism must be at least one; zero cannot schedule a worklist",
        ));
    }
    if config.timeout_secs == 0 {
        return Err(pipeline_config_error(
            "pipeline timeout must be at least one second",
        ));
    }
    let child_timeout_secs = config
        .timeout_secs
        .checked_add(config.host_admission_timeout_secs)
        .ok_or_else(|| pipeline_config_error("pipeline + host admission timeout overflow"))?;
    if Instant::now()
        .checked_add(Duration::from_secs(child_timeout_secs))
        .is_none()
    {
        return Err(pipeline_config_error(
            "combined child deadline is not representable by the Windows monotonic clock",
        ));
    }
    let timeout_ms = config
        .host_admission_timeout_secs
        .checked_mul(1000)
        .filter(|value| *value < u64::from(u32::MAX))
        .ok_or_else(|| {
            pipeline_config_error(
                "host admission timeout exceeds the finite Windows wait range (INFINITE is forbidden)",
            )
        })?;
    Ok(timeout_ms as u32)
}

fn index_admission_telemetry(
    inner: &Value,
    expected_timeout_ms: u32,
    timed_out: bool,
) -> Result<IndexAdmissionTelemetry, String> {
    let object = inner
        .get("index_admission")
        .and_then(Value::as_object)
        .ok_or_else(|| "index_admission must be an object".to_string())?;
    let host_timeout_ms = object
        .get("host_timeout_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "index_admission.host_timeout_ms must be a u64".to_string())?;
    let host_waited_ms = object
        .get("host_waited_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "index_admission.host_waited_ms must be a u64".to_string())?;
    let recovered_abandoned_capacity = object
        .get("recovered_abandoned_capacity")
        .and_then(Value::as_bool)
        .ok_or_else(|| "index_admission.recovered_abandoned_capacity must be a bool".to_string())?;
    if host_timeout_ms != u64::from(expected_timeout_ms) {
        return Err(format!(
            "native host_timeout_ms {host_timeout_ms} differs from fleet request {expected_timeout_ms}"
        ));
    }
    if timed_out && recovered_abandoned_capacity {
        return Err(
            "a timed-out admission cannot also report recovered abandoned capacity".to_string(),
        );
    }
    Ok(IndexAdmissionTelemetry {
        host_timeout_ms,
        host_waited_ms,
        recovered_abandoned_capacity,
    })
}

fn exact_host_busy_outcome(
    stdout_text: &str,
    expected_repo: &Path,
    expected_timeout_ms: u32,
) -> Result<Option<IndexAdmissionTelemetry>, String> {
    let Ok(envelope) = serde_json::from_str::<Value>(stdout_text) else {
        return Ok(None);
    };
    let Some(content) = envelope.get("content").and_then(Value::as_array) else {
        return Ok(None);
    };
    let Some(text) = content
        .first()
        .and_then(Value::as_object)
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let Ok(inner) = serde_json::from_str::<Value>(text) else {
        return Ok(None);
    };
    if inner.get("code").and_then(Value::as_str) != Some("CBM_INDEX_HOST_BUSY") {
        return Ok(None);
    }

    if envelope.get("isError").and_then(Value::as_bool) != Some(true)
        || content.len() != 1
        || content[0].get("type").and_then(Value::as_str) != Some("text")
    {
        return Err("outer tool result must be one text item with isError=true".to_string());
    }
    if inner.get("status").and_then(Value::as_str) != Some("error")
        || inner.get("operation").and_then(Value::as_str) != Some("acquire_index_admission")
        || inner.get("pipeline_started").and_then(Value::as_bool) != Some(false)
        || inner
            .get("sqlite_publication_started")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(
            "inner status/operation/no-work flags do not describe an exact admission refusal"
                .to_string(),
        );
    }
    let _project = inner
        .get("project")
        .and_then(Value::as_str)
        .filter(|project| valid_index_project(project))
        .ok_or_else(|| "inner project is absent or invalid".to_string())?;
    let returned_repo = inner
        .get("repo_path")
        .and_then(Value::as_str)
        .ok_or_else(|| "inner repo_path is absent".to_string())?;
    let expected_canonical = fs::canonicalize(expected_repo).map_err(|error| {
        format!(
            "cannot canonicalize expected repo {}: {error}",
            expected_repo.display()
        )
    })?;
    let returned_canonical = fs::canonicalize(returned_repo).map_err(|error| {
        format!("cannot canonicalize returned repo_path {returned_repo:?}: {error}")
    })?;
    let expected_path = expected_canonical.to_string_lossy().replace('/', "\\");
    let returned_path = returned_canonical.to_string_lossy().replace('/', "\\");
    if !expected_path.eq_ignore_ascii_case(&returned_path) {
        return Err(format!(
            "returned repo_path {returned_repo:?} resolves to {returned_path:?}, expected {expected_path:?}"
        ));
    }
    if inner
        .get("message")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || inner
            .get("remediation")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("inner message/remediation must be non-empty strings".to_string());
    }
    let telemetry = index_admission_telemetry(&inner, expected_timeout_ms, true)?;
    Ok(Some(telemetry))
}

/// One repo's pipeline job, run on a worker thread. Catalog mutations are
/// returned to the main thread, never applied here.
fn pipeline_job(
    row: &FleetRepoRow,
    config: &PipelineConfig,
    host_admission_timeout_ms: u32,
) -> JobResult {
    let started = Instant::now();
    let store_key = project_name(&row.record.full_name);
    let store_dir = config.store_root.join(&store_key);
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
        pipeline_status: None,
        pipeline_degradation: None,
        kernel_members_hash: None,
        kernel_member_count: None,
        stage_ms: BTreeMap::new(),
        index_admission: None,
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
        scheduling_text: None,
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

    // Idempotent skip / stale / force on already-kerneled records. Grounding
    // (#457): the skip/stale verdict keys on `indexed_commit_hash` — the head
    // the persisted kernel was actually built at — because an update fetch
    // advances both the clone and `head_commit_hash`, which made a stale
    // kernel indistinguishable from a current one. A kerneled row without a
    // grounding fact (written before the fact existed and not yet backfilled
    // from the ledger) is treated as stale, never silently skipped.
    if row.state == RepoState::Kerneled {
        if !config.force {
            return match row.indexed_commit_hash.as_deref() {
                Some(grounded) if grounded == head.as_str() => JobResult {
                    row: row.clone(),
                    verdict: RepoVerdict {
                        head_commit_hash: Some(head),
                        ..verdict_base(
                            Outcome::Skipped,
                            None,
                            "already kerneled at this clone HEAD (grounding verified)"
                                .to_string(),
                        )
                    },
                    rejection_text: None,
                    scheduling_text: None,
                    transitions: Vec::new(),
                    fact_refresh: None,
                },
                Some(grounded) => JobResult {
                    row: row.clone(),
                    verdict: RepoVerdict {
                        head_commit_hash: Some(head.clone()),
                        ..verdict_base(
                            Outcome::Stale,
                            None,
                            format!(
                                "kernel grounded at {grounded} but clone HEAD is {head}; re-index belongs to the growth cycle (#457) or --force"
                            ),
                        )
                    },
                    rejection_text: None,
                    scheduling_text: None,
                    transitions: Vec::new(),
                    fact_refresh: None,
                },
                None => JobResult {
                    row: row.clone(),
                    verdict: RepoVerdict {
                        head_commit_hash: Some(head.clone()),
                        ..verdict_base(
                            Outcome::Stale,
                            None,
                            "kernel grounding unknown (row predates indexed_commit_hash and has no ledger backfill); run the growth cycle's backfill or --force".to_string(),
                        )
                    },
                    rejection_text: None,
                    scheduling_text: None,
                    transitions: Vec::new(),
                    fact_refresh: None,
                },
            };
        }
    } else if row.state == RepoState::Cloned {
        // Never-transitioned record: a leftover store dir is a torn partial
        // run — remove and redo (documented resume semantic, labeled in the
        // verdict via `wiped_partial_store`). But only a dir this pipeline
        // recognizes as its own may be wiped: anything else is foreign
        // content and the job refuses rather than overwrite (#454).
        if store_dir.exists() {
            if let Some(foreign) = foreign_store_entry(&store_dir, &store_key, clone_path.as_str())
            {
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
        .env("ASTRO_ARCHAEOLOGY_ROOT", &config.archaeology_root)
        .env("ASTRO_NOMIC_DIR", &config.nomic_dir)
        .env("ASTRO_SHADOW_TIMING", "1")
        .env(
            FLEET_INDEX_ADMISSION_TIMEOUT_ENV,
            host_admission_timeout_ms.to_string(),
        )
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
    // #515: track the peak resident working set (RSS) the child reached, sampled while
    // it is ALIVE during the existing poll loop and kept as a running maximum. A
    // Windows process's working set reads stale once it exits, so the peak MUST be
    // captured live; keeping the max here means it survives the child's death and is
    // available for the structured failure detail when a child vanishes without a tool
    // result (the rc=127 case this issue tracks). One cheap GetProcessMemoryInfo per
    // 500 ms poll — negligible against a multi-minute index.
    let mut peak_ws: u64 = 0;
    let mut peak_ws_seen = false;
    let child_timeout_secs = config
        .host_admission_timeout_secs
        .checked_add(config.timeout_secs)
        .expect("pipeline configuration was validated before worker dispatch");
    let Some(deadline) = Instant::now().checked_add(Duration::from_secs(child_timeout_secs)) else {
        return fail(
            "preflight",
            format!(
                "{ASTRO_FLEET_PIPELINE_CONFIG}: combined child deadline {child_timeout_secs}s is not representable by the Windows monotonic clock"
            ),
            None,
        );
    };
    let status = loop {
        if let Some(ws) = child_working_set_bytes(&child) {
            peak_ws_seen = true;
            peak_ws = peak_ws.max(ws);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    if let Some(ws) = child_working_set_bytes(&child) {
                        peak_ws_seen = true;
                        peak_ws = peak_ws.max(ws);
                    }
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
    // #515: the last pipeline phase the child announced before it died, plus the peak
    // resident working set (RSS) sampled live above. Both are cheap and both survive a
    // hard-exiting child — so a child that vanishes WITHOUT a tool result (the
    // empty-stdout rc=127 this issue tracks) still yields a structured detail that NAMES
    // the phase and the resource cost instead of an empty "stdout head:".
    let last_phase = last_observed_pipeline_phase(&stderr_text);
    let phase_label = last_phase
        .as_deref()
        .unwrap_or("<none emitted — died before the first phase line>");
    let mem_label = if peak_ws_seen {
        format!("{} MiB", peak_ws / (1024 * 1024))
    } else {
        "<unavailable>".to_string()
    };
    let Some(status) = status else {
        return fail(
            "timeout",
            format!(
                "pipeline child exceeded the combined {}s admission + {}s pipeline budgets and was killed (job-object confined); last phase={phase_label}; peak RSS={mem_label}",
                config.host_admission_timeout_secs, config.timeout_secs
            ),
            Some(format!(
                "repo: {}\nphase: timeout after {}s admission + {}s pipeline budgets\nlast pipeline phase: {phase_label}\npeak RSS (working set): {mem_label}\nstderr tail:\n{}\n",
                row.record.full_name,
                config.host_admission_timeout_secs,
                config.timeout_secs,
                tail(&stderr_text, 4000)
            )),
        );
    };
    let stdout_text = fs::read_to_string(&stdout_path).unwrap_or_default();
    if !status.success() {
        match exact_host_busy_outcome(&stdout_text, &clone_dir, host_admission_timeout_ms) {
            Ok(Some(index_admission)) => {
                return JobResult {
                    row: row.clone(),
                    verdict: RepoVerdict {
                        head_commit_hash: Some(head),
                        index_admission: Some(index_admission.clone()),
                        secs: started.elapsed().as_secs_f64(),
                        ..verdict_base(
                            Outcome::DeferredHostBusy,
                            Some("admission"),
                            format!(
                                "host index capacity remained busy for {}ms of the explicit {}ms fleet budget; native pipeline and SQLite publication did not start",
                                index_admission.host_waited_ms, index_admission.host_timeout_ms
                            ),
                        )
                    },
                    rejection_text: None,
                    scheduling_text: Some(stdout_text),
                    transitions: Vec::new(),
                    fact_refresh: None,
                };
            }
            Ok(None) => {}
            Err(detail) => {
                return fail(
                    "parse",
                    format!("malformed CBM_INDEX_HOST_BUSY envelope: {detail}"),
                    Some(format!(
                        "repo: {}\nphase: malformed host admission envelope\nstdout:\n{}\nstderr tail:\n{}\n",
                        row.record.full_name,
                        head_of(&stdout_text, 8000),
                        tail(&stderr_text, 8000)
                    )),
                );
            }
        }
        // The child exited without a usable tool result. Its stdout is frequently
        // EMPTY here (a C-level pipeline fault hard-exits before the JSON is printed —
        // e.g. the rc=127 silent termination deep in the vault/lowering/kernel phase on
        // rtk-class repos, #515), so "stdout head:" carried nothing actionable. Lead
        // with the exit code, the last phase the child announced, and its peak resident
        // working set — a structured {code,message,remediation}-grade detail that names
        // the phase and the resource cost even when the child produced no result at all.
        return fail(
            "pipeline",
            format!(
                "pipeline child exited without a tool result ({status}); last phase={phase_label}; peak RSS={mem_label}; stdout head: {}",
                safe_reason(&head_of(&stdout_text, 200))
            ),
            Some(format!(
                "repo: {}\nphase: child exit {status}\nlast pipeline phase: {phase_label}\npeak RSS (working set): {mem_label}\nstdout head:\n{}\nstderr tail:\n{}\n",
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
    let mut degradation = match pipeline_degradation(&inner) {
        Ok(degradation) => degradation,
        Err(detail) => {
            return fail(
                "parse",
                format!("index_repository degradation telemetry invalid: {detail}"),
                Some(format!(
                    "repo: {}\nphase: degradation telemetry\n{}\n",
                    row.record.full_name,
                    head_of(&inner.to_string(), 8000)
                )),
            );
        }
    };
    let status_consistent = matches!(inner_status, "partial_success") && degradation.is_partial()
        || matches!(inner_status, "indexed") && !degradation.is_partial();
    if !status_consistent {
        return fail(
            "pipeline",
            format!(
                "index_repository status {inner_status:?} disagrees with typed degradation counters {degradation:?}"
            ),
            Some(format!(
                "repo: {}\nphase: result status\n{}\n",
                row.record.full_name,
                head_of(&inner.to_string(), 8000)
            )),
        );
    }
    let index_admission = match index_admission_telemetry(&inner, host_admission_timeout_ms, false)
    {
        Ok(telemetry) => telemetry,
        Err(detail) => {
            return fail(
                "parse",
                format!("index_repository admission telemetry invalid: {detail}"),
                Some(format!(
                    "repo: {}\nphase: admission telemetry\n{}\n",
                    row.record.full_name,
                    head_of(&inner.to_string(), 8000)
                )),
            );
        }
    };
    let index_project = match inner["project"].as_str() {
        Some(project) if valid_index_project(project) => project.to_string(),
        Some(project) => {
            return fail(
                "identity",
                format!(
                    "{ASTRO_FLEET_PROJECT_IDENTITY}: index_repository returned invalid path-derived project {project:?}"
                ),
                Some(format!(
                    "repo: {}\nphase: returned project identity\nreturned project: {project:?}\n",
                    row.record.full_name
                )),
            );
        }
        None => {
            return fail(
                "identity",
                format!(
                    "{ASTRO_FLEET_PROJECT_IDENTITY}: index_repository result carries no project"
                ),
                Some(format!(
                    "repo: {}\nphase: returned project identity\nresult head:\n{}\n",
                    row.record.full_name,
                    head_of(&inner.to_string(), 8000)
                )),
            );
        }
    };
    let vault_fingerprint = inner["vault_fingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let scope = kernel_scope_id(&index_project);
    // Independent persisted-state verification is the transition gate. The
    // Kernel CF, not the bounded command response, is the source of truth:
    // routine responses intentionally replace large weave surfaces with a
    // compact persisted-surface reference. Reading the artifact here also
    // avoids coupling fleet correctness to response materialization policy.
    let persisted = match verify_persisted(&store_dir, &index_project, &scope) {
        Ok(readback) => readback,
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
    let PersistedPipelineReadback {
        sqlite_nodes,
        sqlite_edges,
        content_defects: sqlite_content_defects,
        content_defect_relationships: sqlite_content_defect_relationships,
        vault_base_rows,
        kernel_member_count,
        kernel_members_hash,
    } = persisted;
    if sqlite_content_defects != degradation.content_defects
        || sqlite_content_defect_relationships != degradation.content_defect_relationships
    {
        return fail(
            "verify",
            format!(
                "persisted content-defect state ({sqlite_content_defects} nodes, {sqlite_content_defect_relationships} relationships) differs from the native result ({} nodes, {} relationships)",
                degradation.content_defects, degradation.content_defect_relationships
            ),
            Some(format!(
                "repo: {}\nphase: independent content-defect readback\nproject: {index_project}\nreported nodes: {}\nreported relationships: {}\npersisted nodes: {sqlite_content_defects}\npersisted relationships: {sqlite_content_defect_relationships}\n",
                row.record.full_name,
                degradation.content_defects,
                degradation.content_defect_relationships,
            )),
        );
    }
    degradation.content_defects = sqlite_content_defects;
    degradation.content_defect_relationships = sqlite_content_defect_relationships;

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
                    indexed_commit_hash: Some(head.clone()),
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
                    indexed_commit_hash: Some(head.clone()),
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
                indexed_commit_hash: Some(head.clone()),
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
            detail: format!(
                "pipeline complete; stable store {store_key}, path-derived project {index_project}, kernel scope {scope}"
            ),
            head_commit_hash: Some(head),
            sqlite_nodes: Some(sqlite_nodes),
            sqlite_edges: Some(sqlite_edges),
            vault_base_rows: Some(vault_base_rows),
            pipeline_status: Some(inner_status.to_string()),
            pipeline_degradation: Some(degradation),
            kernel_members_hash: Some(kernel_members_hash),
            kernel_member_count: Some(kernel_member_count),
            stage_ms,
            index_admission: Some(index_admission),
            wiped_partial_store: wiped_partial_store.get(),
            store_bytes: Some(store_bytes),
            secs: started.elapsed().as_secs_f64(),
        },
        rejection_text: None,
        scheduling_text: None,
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
pub fn vault_base_keys(
    store_root: &Path,
    store_key: &str,
    index_project: &str,
) -> Result<Vec<String>, CalyxError> {
    let vault_dir = store_root
        .join(store_key)
        .join(format!("{index_project}.astrolabe-vault"));
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID).map_err(|error| CalyxError {
        code: ASTRO_FLEET_STORE_UNAVAILABLE,
        message: format!("shadow vault id failed to parse: {error:?}"),
        remediation: "internal defect: SHADOW_VAULT_ID must be a valid ULID",
    })?;
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        shadow_vault_salt(index_project).into_bytes(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![ColumnFamily::Base]),
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
fn foreign_store_entry(store_dir: &Path, store_key: &str, clone_path: &str) -> Option<String> {
    const FIXED: [&str; 7] = [
        "_config.db",
        "index-args.json",
        "pipeline-stdout.json",
        "pipeline-stderr.txt",
        "logs",
        ".astrolabe-shadow-publication",
        // #1037: a preserved staged CBM store from an aborted publication is this
        // pipeline's own output, not a foreign entry.
        ".astrolabe-shadow-preserved-stage",
    ];
    let index_project = recognized_pipeline_index_project(store_dir, clone_path);
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
            || name.starts_with(&format!("{store_key}."))
            || index_project
                .as_ref()
                .is_some_and(|project| name.starts_with(&format!("{project}.")))
            || name.starts_with("_config.db");
        if !recognized {
            return Some(name);
        }
    }
    None
}

/// Recovers the path-derived inner project identity from either a completed
/// successful response or an exact interrupted shadow-publication artifact
/// set. In both cases the args file must bind the current clone and contain no
/// caller-selected name.
///
/// The interrupted case derives identity from the product's exact paired
/// zero-byte guards. A lone/mismatched guard, symlink, nonempty guard, missing
/// error envelope, or incomplete publication scaffold remains foreign.
fn recognized_pipeline_index_project(store_dir: &Path, clone_path: &str) -> Option<String> {
    let args: Value =
        serde_json::from_slice(&fs::read(store_dir.join("index-args.json")).ok()?).ok()?;
    if args["repo_path"].as_str() != Some(clone_path)
        || args["calyx"].as_str() != Some("shadow")
        || args["mode"].as_str() != Some("fast")
        || args.get("name").is_some()
    {
        return None;
    }
    let envelope: Value =
        serde_json::from_slice(&fs::read(store_dir.join("pipeline-stdout.json")).ok()?).ok()?;
    if envelope["isError"].as_bool().unwrap_or(true) {
        return interrupted_pipeline_guard_project(store_dir);
    }
    let inner: Value = serde_json::from_str(envelope["content"][0]["text"].as_str()?).ok()?;
    if !matches!(
        inner["status"].as_str(),
        Some("indexed" | "partial_success")
    ) {
        return None;
    }
    let project = inner["project"].as_str()?;
    valid_index_project(project).then(|| project.to_string())
}

fn interrupted_pipeline_guard_project(store_dir: &Path) -> Option<String> {
    const LOWERED_GUARD: &str = ".astrolabe-lowered.lock.guard";
    const SHADOW_IMPORT_GUARD: &str = ".astrolabe-shadow-import.lock.guard";

    let stderr = fs::symlink_metadata(store_dir.join("pipeline-stderr.txt")).ok()?;
    let logs = fs::symlink_metadata(store_dir.join("logs")).ok()?;
    let publication = fs::symlink_metadata(store_dir.join(".astrolabe-shadow-publication")).ok()?;
    if !stderr.file_type().is_file()
        || !logs.file_type().is_dir()
        || !publication.file_type().is_dir()
        || fs::read_dir(store_dir.join(".astrolabe-shadow-publication"))
            .ok()?
            .next()
            .is_some()
    {
        return None;
    }

    let lowered = exact_zero_byte_guard_project(store_dir, LOWERED_GUARD)?;
    let shadow_import = exact_zero_byte_guard_project(store_dir, SHADOW_IMPORT_GUARD)?;
    (lowered == shadow_import && valid_index_project(&lowered)).then_some(lowered)
}

fn exact_zero_byte_guard_project(store_dir: &Path, suffix: &str) -> Option<String> {
    let mut project = None;
    for entry in fs::read_dir(store_dir).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_str()?;
        let Some(candidate) = name.strip_suffix(suffix) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path()).ok()?;
        if !metadata.file_type().is_file() || metadata.len() != 0 || project.is_some() {
            return None;
        }
        project = Some(candidate.to_string());
    }
    project
}

#[derive(Debug, PartialEq, Eq)]
struct PersistedPipelineReadback {
    sqlite_nodes: u64,
    sqlite_edges: u64,
    content_defects: u64,
    content_defect_relationships: u64,
    vault_base_rows: u64,
    kernel_member_count: u64,
    kernel_members_hash: String,
}

/// Independent persisted-state readback: CBM sqlite counts, shadow-vault Base
/// rows, and the exact persisted Kernel-CF artifact. The artifact's schema,
/// scope, member cardinality, and members hash are re-derived from the stored
/// member identities before the fleet transition can use them.
fn verify_persisted(
    store_dir: &Path,
    project: &str,
    scope: &str,
) -> Result<PersistedPipelineReadback, String> {
    // (a) CBM sqlite. The child has completed and closed publication before
    // this gate runs, so verification has no authority to recover or mutate
    // the store. A WAL/open-state fault refuses instead of silently upgrading
    // this source-of-truth read to write-capable access (#1064 PC-09/PC-43).
    let db_path = store_dir.join(format!("{project}.db"));
    let connection = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open CBM sqlite read-only {}: {error}", db_path.display()))?;
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
    // Cost receipt (2026-08-12): two covering-index probes over the measured
    // Astrolabe production store (N=192,772 nodes / 328,710 edges), using
    // idx_nodes_label(project,label) and idx_edges_type(project,type). This
    // opens no Calyx row family and restores no MVCC rows. The invariant is
    // one project identity and one diagnostic label/type per completed repo;
    // no per-file or per-node query is introduced (PC-35/PC-37/PC-41, #1064).
    let project_count = |sql: &str| -> Result<u64, String> {
        connection
            .query_row(sql, [project], |row| row.get::<_, i64>(0))
            .and_then(|count| {
                u64::try_from(count).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| format!("{sql}: {error}"))
    };
    let content_defects =
        project_count("SELECT COUNT(*) FROM nodes WHERE project = ?1 AND label = 'ContentDefect'")?;
    let content_defect_relationships = project_count(
        "SELECT COUNT(*) FROM edges WHERE project = ?1 AND type = 'HAS_CONTENT_DEFECT'",
    )?;
    if content_defects != content_defect_relationships {
        return Err(format!(
            "CBM sqlite {} has {content_defects} ContentDefect nodes but {content_defect_relationships} HAS_CONTENT_DEFECT relationships",
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
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![ColumnFamily::Base, ColumnFamily::Kernel]),
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
    // path. Its exact member identities are the source of truth for the hash
    // and count used by the fleet catalog (PC-32/PC-35/PC-37).
    let artifact = astrolabe_ingest::read_persisted_kernel_artifact(&vault, scope)
        .map_err(|error| format!("read persisted kernel artifact for {scope}: {error}"))?
        .ok_or_else(|| {
            format!("no persisted kernel artifact in the Kernel CF for scope {scope}")
        })?;
    if artifact.schema != astrolabe_kernel::KERNEL_ARTIFACT_SCHEMA {
        return Err(format!(
            "persisted kernel artifact for scope {scope} has schema {:?}, expected {:?}",
            artifact.schema,
            astrolabe_kernel::KERNEL_ARTIFACT_SCHEMA
        ));
    }
    if artifact.scope_id != scope {
        return Err(format!(
            "{ASTRO_FLEET_PROJECT_IDENTITY}: persisted Kernel-CF key for scope {scope:?} contains artifact scope {:?}",
            artifact.scope_id
        ));
    }
    if artifact.member_count != artifact.members.len() {
        return Err(format!(
            "persisted kernel artifact for scope {scope} declares {} members but contains {}",
            artifact.member_count,
            artifact.members.len()
        ));
    }
    let member_ids = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let derived_members_hash = astrolabe_kernel::members_hash(&member_ids);
    if artifact.members_hash != derived_members_hash {
        return Err(format!(
            "persisted kernel members-hash {} != re-derived {} for scope {scope}",
            artifact.members_hash, derived_members_hash
        ));
    }
    Ok(PersistedPipelineReadback {
        sqlite_nodes,
        sqlite_edges,
        content_defects,
        content_defect_relationships,
        vault_base_rows,
        kernel_member_count: artifact.member_count as u64,
        kernel_members_hash: derived_members_hash,
    })
}

fn pipeline_degradation(inner: &Value) -> Result<PipelineDegradation, String> {
    let count = |key: &str| -> Result<u64, String> {
        inner
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{key} must be a nonnegative integer"))
    };
    let degradation = PipelineDegradation {
        content_defects: count("content_defect_count")?,
        content_defect_relationships: count("content_defect_relationship_count")?,
        content_defects_observed_this_run: count("content_defects_observed_this_run")?,
        ambiguous_reference_skips: count("ambiguous_reference_skips")?,
        unresolved_reference_source_skips: count("unresolved_reference_source_skips")?,
        dangling_rust_module_skips: count("dangling_rust_module_skips")?,
        parse_recovery_diagnostics: count("parse_recovery_diagnostics")?,
    };
    if degradation.content_defects != degradation.content_defect_relationships {
        return Err(format!(
            "content defect nodes ({}) differ from relationships ({})",
            degradation.content_defects, degradation.content_defect_relationships
        ));
    }
    if degradation.content_defects_observed_this_run > degradation.content_defects {
        return Err(format!(
            "content defects observed this run ({}) exceed persisted defects ({})",
            degradation.content_defects_observed_this_run, degradation.content_defects
        ));
    }
    Ok(degradation)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipelinePhaseStream {
    Shadow,
    Index,
    Archaeology,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PipelinePhaseSample<'a> {
    stream: PipelinePhaseStream,
    phase: &'a str,
    elapsed_ms: Option<u64>,
}

/// Decodes one stable pipeline phase line. Current shadow telemetry uses
/// `elapsed_ms`; `ms` remains accepted for the pre-6d763bd6 shadow stream and
/// the archaeology stream so a current fleet binary can still diagnose a
/// preserved older pipeline artifact. An untimed line (currently
/// `index.preseed_noop`) remains useful to the last-phase diagnostic.
fn decode_pipeline_phase_line(line: &str) -> Option<PipelinePhaseSample<'_>> {
    let trimmed = line.trim();
    let (stream, fields) = if let Some(fields) = trimmed.strip_prefix("astro.shadow.phase ") {
        (PipelinePhaseStream::Shadow, fields)
    } else if let Some(fields) = trimmed.strip_prefix("astro.shadow.index_phase ") {
        (PipelinePhaseStream::Index, fields)
    } else if let Some(fields) = trimmed.strip_prefix("astro.shadow.timing ") {
        (PipelinePhaseStream::Shadow, fields)
    } else if let Some(fields) = trimmed.strip_prefix("astro.arch.timing ") {
        (PipelinePhaseStream::Archaeology, fields)
    } else {
        return None;
    };

    let mut phase = None;
    let mut elapsed_ms = None;
    let mut legacy_ms = None;
    for field in fields.split_whitespace() {
        if let Some(value) = field.strip_prefix("phase=") {
            if !value.is_empty() {
                phase = Some(value);
            }
        } else if let Some(value) = field.strip_prefix("elapsed_ms=") {
            elapsed_ms = value.parse::<u64>().ok();
        } else if let Some(value) = field.strip_prefix("ms=") {
            legacy_ms = value.parse::<u64>().ok();
        }
    }

    Some(PipelinePhaseSample {
        stream,
        phase: phase?,
        elapsed_ms: elapsed_ms.or(legacy_ms),
    })
}

/// Extracts top-level current and legacy shadow-stage durations. Detailed
/// `import_raw.*` rows remain out of the compact report; outer index phases use
/// an `index.` prefix so a future phase-name collision cannot overwrite an
/// import duration.
fn parse_stage_timings(stderr_text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in stderr_text.lines() {
        let Some(sample) = decode_pipeline_phase_line(line) else {
            continue;
        };
        let Some(elapsed_ms) = sample.elapsed_ms else {
            continue;
        };
        let phase = match sample.stream {
            PipelinePhaseStream::Shadow if !sample.phase.contains('.') => sample.phase.to_string(),
            PipelinePhaseStream::Index => format!("index.{}", sample.phase),
            PipelinePhaseStream::Shadow | PipelinePhaseStream::Archaeology => continue,
        };
        out.insert(phase, elapsed_ms);
    }
    out
}

/// #515: the LAST pipeline phase the child announced on stderr before it died.
/// Scans current shadow-import and outer index streams, the legacy shadow stream,
/// and git archaeology. Phase lines are emitted AFTER each phase completes, so
/// this is the completed phase immediately before the fatal one: the best
/// available name for where the child vanished. Returns `None` only when the
/// child emitted no recognized phase. Used solely for structured child-loss
/// detail, so a parse miss yields `None`, never a fabricated phase.
fn last_observed_pipeline_phase(stderr_text: &str) -> Option<String> {
    let mut last: Option<String> = None;
    for line in stderr_text.lines() {
        let Some(sample) = decode_pipeline_phase_line(line) else {
            continue;
        };
        last = Some(match sample.stream {
            PipelinePhaseStream::Index => format!("index.{}", sample.phase),
            PipelinePhaseStream::Shadow | PipelinePhaseStream::Archaeology => {
                sample.phase.to_string()
            }
        });
    }
    last
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
