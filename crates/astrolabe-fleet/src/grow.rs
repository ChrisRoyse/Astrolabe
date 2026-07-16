//! Continuous growth scheduler — discovery refresh, update fetch, incremental
//! re-kernel, debt-based fleet recomposition (issue #457, EPIC #461).
//!
//! Farming is continuous, not one-shot: new repos cross the star floor,
//! existing repos get commits, and the fleet kernel must keep growing. One
//! **growth cycle** is a bounded, resumable pass that composes the existing
//! fleet atoms (never re-implements them):
//!
//! ```text
//! backfill grounding → discovery refresh → quarantine retry release
//!   → update fetch → selection → clone acquire → pipeline (re-)index
//!   → debt accounting → fleet-kernel recomposition → reconciliation
//!   → cycle report (file + catalog Blob row + ledger entry)
//! ```
//!
//! # Selection owns re-index (the #454 gap)
//!
//! The batch orchestrator deliberately reports `stale` without mutating; this
//! module owns the decision of *what to re-run*. Selection is a pure catalog
//! computation over the grounding fact `indexed_commit_hash` (the head the
//! persisted kernel was built at, #457) versus `head_commit_hash` (the clone
//! head, which the update fetch advances). Classes, in priority order:
//!
//! 1. **forced** — operator-named `--force-repo` refreshes;
//! 2. **stale** — kerneled with `indexed_commit_hash != head_commit_hash`,
//!    plus kerneled rows with *unknown* grounding (pre-#457 rows the ledger
//!    backfill could not ground — they fail toward re-work, never toward a
//!    silent skip);
//! 3. **resume** — `cloned`/`indexed` rows a crashed run left mid-pipeline;
//! 4. **acquire** — `discovered` rows, only with `--acquire` (scale-wave
//!    intake is #460's go/no-go decision, not an implicit side effect).
//!
//! Within each class repos order by stars descending; the whole worklist is
//! bounded by the `fleet.grow.max_repos_per_cycle` knob and every deferred
//! repo is counted per class (bounded work per cycle — the machine stays
//! usable; the next cycle picks the tail up).
//!
//! # Grounding backfill (ledger-derived, never guessed)
//!
//! Rows written before `indexed_commit_hash` existed are grounded from the
//! catalog's own ledger: the latest `fleet_state_transition` entry to
//! `indexed`/`kerneled` for the repo carries the head the pipeline recorded
//! at that transition. A row the ledger cannot ground stays ungrounded and is
//! selected as stale (explicit re-work). Backfills are ordinary ledger-paired
//! `update_facts` mutations.
//!
//! # Debt-based recomposition (segment/LSM pattern)
//!
//! Per-repo kernels accumulate change **debt** against the fleet kernel's
//! compose sidecar baseline (`repos[].members_hash` pairs): a changed,
//! added, or removed pair is one unit of debt. Below the declared
//! `fleet.grow.debt_threshold_repos` knob the cycle records an explicit
//! `deferred_below_threshold` decision; at or above it, the cycle runs the
//! #456 compose path (itself an explicit full rebuild with an `unchanged`
//! no-op verdict). Both outcomes land in the cycle report and the ledger.
//!
//! # Failure containment and honesty
//!
//! One bad repo never stalls the cycle: the clone/pipeline passes isolate
//! per-repo failures (quarantine + report), and phase-level refusals are
//! captured as labeled cycle errors. The cycle report always persists; a
//! cycle with any recorded error then refuses fail-closed with
//! [`ASTRO_FLEET_GROW_INCOMPLETE`] naming the report. Reconciliation
//! independently re-queries the catalog and verifies that every observed
//! state change is attributed to a phase verdict of this cycle — an
//! unattributed change is a reconciliation error, not a shrug.
//!
//! # Scheduling substrate
//!
//! `grow --once` runs one cycle and exits nonzero on any recorded error —
//! the shape Windows Task Scheduler wants (registration is an operator
//! action; project tooling performs no OS servicing). `grow --cycles N
//! --interval-secs S` is the supervised long-running mode: cycles are
//! contained (a failed cycle is recorded and the loop continues), and the
//! final exit refuses if any cycle failed. There is no CI/CD substrate and
//! none may be added.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use astrolabe_ingest::read_persisted_kernel_artifact;
use astrolabe_kernel::U64KnobDeclaration;
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, VaultId};
use serde::Serialize;
use serde_json::{Value, json};

use crate::catalog::FleetCatalog;
use crate::clone_farm::{FarmConfig, Selection, run_clone_pass_outcome, safe_reason};
use crate::compose::{ComposeConfig, FLEET_KERNEL_REPORT_KIND, compose_fleet_kernel};
use crate::discover::run_discovery;
use crate::orchestrator::{
    PipelineConfig, SHADOW_VAULT_ID, kernel_scope_id, project_name, run_pipeline_pass_outcome,
    shadow_vault_salt,
};
use crate::record::TransitionContext;
use crate::state::RepoState;

/// Refusal code when a growth cycle (or the grow loop) recorded any error.
pub const ASTRO_FLEET_GROW_INCOMPLETE: &str = "ASTRO_FLEET_GROW_INCOMPLETE";
/// Refusal code for a grow knob outside its declared bounds.
pub const ASTRO_FLEET_GROW_KNOB_RANGE: &str = "ASTRO_FLEET_GROW_KNOB_RANGE";
/// Refusal code when a `--force-repo` names a repo the catalog does not hold.
pub const ASTRO_FLEET_GROW_FORCE_UNKNOWN: &str = "ASTRO_FLEET_GROW_FORCE_UNKNOWN";

/// Report kind under which growth-cycle reports persist in the fleet catalog.
pub const GROWTH_CYCLE_REPORT_KIND: &str = "growth-cycle";

/// Declared registry version for the grow knobs.
pub const FLEET_GROW_KNOB_REGISTRY_VERSION: &str = "astro.fleet.grow_knobs.v1";
/// Knob: bounded (re-)index work per cycle, in repos.
pub const KNOB_MAX_REPOS_PER_CYCLE: &str = "fleet.grow.max_repos_per_cycle";
/// Knob: recompose when at least this many per-repo kernel pairs changed.
pub const KNOB_DEBT_THRESHOLD: &str = "fleet.grow.debt_threshold_repos";
/// Knob: default interval between supervised cycles, seconds.
pub const KNOB_INTERVAL_SECS: &str = "fleet.grow.interval_secs";

/// Declared grow knobs (invariant 4: no constant that could be a knob).
pub const FLEET_GROW_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: FLEET_GROW_KNOB_REGISTRY_VERSION,
        name: KNOB_MAX_REPOS_PER_CYCLE,
        default: 25,
        min: 1,
        max: 10_000,
        unit: "repos",
        source: "declared",
        rationale: "bounded (re-)index work per cycle keeps the machine usable; \
                    every deferred repo is counted and picked up next cycle",
    },
    U64KnobDeclaration {
        registry_version: FLEET_GROW_KNOB_REGISTRY_VERSION,
        name: KNOB_DEBT_THRESHOLD,
        default: 1,
        min: 1,
        max: 10_000,
        unit: "repos",
        source: "declared",
        rationale: "fleet-kernel recomposition debt threshold (segment/LSM: \
                    incremental until debt, then rebuild); 1 recomposes on any \
                    per-repo kernel change",
    },
    U64KnobDeclaration {
        registry_version: FLEET_GROW_KNOB_REGISTRY_VERSION,
        name: KNOB_INTERVAL_SECS,
        default: 3_600,
        min: 60,
        max: 604_800,
        unit: "seconds",
        source: "declared",
        rationale: "supervised-mode pause between growth cycles; discovery and \
                    fetch load on the GitHub API scales inversely with this",
    },
];

fn knob_default(name: &str) -> u64 {
    FLEET_GROW_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("fleet grow knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<(), CalyxError> {
    let knob = FLEET_GROW_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("fleet grow knob is declared");
    if value < knob.min || value > knob.max {
        return Err(CalyxError {
            code: ASTRO_FLEET_GROW_KNOB_RANGE,
            message: format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            remediation: "set the fleet grow knob within its registered bounds",
        });
    }
    Ok(())
}

/// Declared knobs of one growth cycle.
#[derive(Clone, Debug, Serialize)]
pub struct GrowConfig {
    /// Catalog root (discovery run reports persist under `<root>/runs`).
    pub catalog_root: std::path::PathBuf,
    /// Fleet kernel scope the cycle recomposes (e.g. `fleet:rust:v1`).
    pub scope: String,
    /// Languages for the discovery refresh.
    pub languages: Vec<String>,
    /// Star floor for the discovery refresh.
    pub star_floor: u64,
    /// Run the discovery refresh phase (GitHub API traffic).
    pub discovery: bool,
    /// Acquire (clone + pipeline) `discovered` repos within the cycle bound.
    /// Off by default: scale-wave intake is #460's explicit decision.
    pub acquire: bool,
    /// Release quarantined repos back to `discovered` for a retry.
    pub retry_quarantined: bool,
    /// Operator-named kerneled repos to force-refresh this cycle.
    pub force_repos: Vec<String>,
    /// Bounded (re-)index work per cycle ([`KNOB_MAX_REPOS_PER_CYCLE`]).
    pub max_repos_per_cycle: u64,
    /// Recomposition debt threshold ([`KNOB_DEBT_THRESHOLD`]).
    pub debt_threshold_repos: u64,
    /// Clone-farm knobs for the update-fetch and acquire phases.
    pub farm: FarmConfig,
    /// Pipeline knobs for the (re-)index phase.
    pub pipeline: PipelineConfig,
}

impl GrowConfig {
    /// Registry defaults over the given farm/pipeline configs.
    pub fn with_registry_defaults(
        catalog_root: std::path::PathBuf,
        farm: FarmConfig,
        pipeline: PipelineConfig,
    ) -> Self {
        Self {
            catalog_root,
            scope: "fleet:rust:v1".to_string(),
            languages: vec!["rust".to_string()],
            star_floor: crate::discover::DEFAULT_STAR_FLOOR,
            discovery: false,
            acquire: false,
            retry_quarantined: false,
            force_repos: Vec::new(),
            max_repos_per_cycle: knob_default(KNOB_MAX_REPOS_PER_CYCLE),
            debt_threshold_repos: knob_default(KNOB_DEBT_THRESHOLD),
            farm,
            pipeline,
        }
    }

    /// Validates every knob against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<(), CalyxError> {
        check_range(KNOB_MAX_REPOS_PER_CYCLE, self.max_repos_per_cycle)?;
        check_range(KNOB_DEBT_THRESHOLD, self.debt_threshold_repos)?;
        Ok(())
    }
}

/// Opens a repo's shadow vault read-only and reads back its persisted kernel
/// artifact's members-hash — the light debt probe (no corpus/vector load).
/// `Ok(None)` when the vault or artifact does not exist.
fn repo_kernel_members_hash(
    store_root: &Path,
    project: &str,
) -> Result<Option<String>, CalyxError> {
    let vault_dir = store_root
        .join(project)
        .join(format!("{project}.astrolabe-vault"));
    if !vault_dir.exists() {
        return Ok(None);
    }
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_STORE_UNAVAILABLE",
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
    let scope = kernel_scope_id(project);
    let artifact = read_persisted_kernel_artifact(&vault, &scope).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_KERNEL_READBACK",
        message: format!("read per-repo kernel artifact for {scope}: {error}"),
        remediation: "the per-repo kernel row is unreadable; re-run the pipeline for this repo",
    })?;
    Ok(artifact.map(|artifact| artifact.members_hash))
}

/// Walks the catalog ledger once and returns, per `github_id`, the head the
/// latest `fleet_state_transition` to `indexed`/`kerneled` recorded — the
/// authoritative grounding source for rows that predate
/// `indexed_commit_hash`. Non-transition entries are not groundings and are
/// skipped by definition (this is a filter, not a fallback).
fn latest_grounding_from_ledger(
    catalog: &FleetCatalog,
) -> Result<BTreeMap<u64, String>, CalyxError> {
    let vault = catalog.vault();
    let mut out = BTreeMap::new();
    for (_key, bytes) in vault.scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)? {
        let entry = calyx_ledger::decode(&bytes)?;
        let Ok(payload) = serde_json::from_slice::<Value>(&entry.payload) else {
            continue;
        };
        if payload["event"].as_str() != Some("fleet_state_transition") {
            continue;
        }
        let to_state = payload["to_state"].as_str();
        if to_state != Some(RepoState::Indexed.as_str())
            && to_state != Some(RepoState::Kerneled.as_str())
        {
            continue;
        }
        let (Some(github_id), Some(head)) = (
            payload["github_id"].as_u64(),
            payload["head_commit_hash"].as_str(),
        ) else {
            continue;
        };
        // Ledger scan order is ascending; the last matching entry wins.
        out.insert(github_id, head.to_string());
    }
    Ok(out)
}

/// Read-only catalog-ledger scan for FSV readbacks: every decodable ledger
/// entry whose JSON payload matches the optional `github_id`/`event` filters,
/// in ledger order. This is the independent no-double-processing probe the
/// growth cycle's DoD names — one mutation, one entry, countable.
pub fn scan_ledger_events(
    catalog: &FleetCatalog,
    github_id: Option<u64>,
    event: Option<&str>,
) -> Result<Vec<Value>, CalyxError> {
    let vault = catalog.vault();
    let mut out = Vec::new();
    for (index, (_key, bytes)) in vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)?
        .into_iter()
        .enumerate()
    {
        let entry = calyx_ledger::decode(&bytes)?;
        let Ok(payload) = serde_json::from_slice::<Value>(&entry.payload) else {
            // Non-JSON payloads (e.g. raw kernel members-hash pairings) are
            // still countable rows; surface them labeled, never dropped.
            if github_id.is_none() && event.is_none() {
                out.push(json!({
                    "ledger_index": index,
                    "kind": format!("{:?}", entry.kind),
                    "payload": "<non-json>",
                }));
            }
            continue;
        };
        if let Some(wanted) = github_id
            && payload["github_id"].as_u64() != Some(wanted)
        {
            continue;
        }
        if let Some(wanted) = event
            && payload["event"].as_str() != Some(wanted)
        {
            continue;
        }
        out.push(json!({
            "ledger_index": index,
            "kind": format!("{:?}", entry.kind),
            "payload": payload,
        }));
    }
    Ok(out)
}

/// Grounds every `indexed`/`kerneled`/`serving` row lacking
/// `indexed_commit_hash` from the catalog's own ledger (see module docs).
/// Idempotent; a row the ledger cannot ground is counted `ungrounded` and
/// left for stale selection.
pub fn backfill_grounding(catalog: &FleetCatalog, at_unix_secs: u64) -> Result<Value, CalyxError> {
    let rows = catalog.query(None, None)?;
    let needing: Vec<_> = rows
        .iter()
        .filter(|row| {
            matches!(
                row.state,
                RepoState::Indexed | RepoState::Kerneled | RepoState::Serving
            ) && row.indexed_commit_hash.is_none()
        })
        .collect();
    if needing.is_empty() {
        return Ok(json!({"backfilled": 0, "ungrounded": 0, "repos": []}));
    }
    let grounding = latest_grounding_from_ledger(catalog)?;
    let mut backfilled = 0_u64;
    let mut ungrounded = 0_u64;
    let mut repos = Vec::new();
    for row in needing {
        match grounding.get(&row.record.github_id) {
            Some(head) => {
                catalog.update_facts(
                    row.record.github_id,
                    &row.record.full_name,
                    TransitionContext {
                        at_unix_secs,
                        indexed_commit_hash: Some(head.clone()),
                        ..TransitionContext::default()
                    },
                )?;
                backfilled += 1;
                repos.push(json!({
                    "full_name": row.record.full_name,
                    "action": "backfilled",
                    "indexed_commit_hash": head,
                }));
            }
            None => {
                ungrounded += 1;
                repos.push(json!({
                    "full_name": row.record.full_name,
                    "action": "ungrounded",
                    "note": "no indexed/kerneled transition with a head in the ledger; \
                             will be selected as stale (explicit re-work)",
                }));
            }
        }
    }
    Ok(json!({"backfilled": backfilled, "ungrounded": ungrounded, "repos": repos}))
}

/// One labeled cycle error (phase + structured code + safe message).
fn cycle_error(phase: &str, error: &CalyxError) -> Value {
    json!({
        "phase": phase,
        "code": error.code,
        "message": safe_reason(&error.message),
    })
}

/// Runs one growth cycle. The cycle report always persists (file under the
/// store root + catalog Blob row + ledger entry); a cycle with recorded
/// errors then refuses with [`ASTRO_FLEET_GROW_INCOMPLETE`].
#[allow(clippy::too_many_lines)]
pub fn run_growth_cycle(catalog: &FleetCatalog, config: &GrowConfig) -> Result<Value, CalyxError> {
    config.validate()?;
    let started = Instant::now();
    let at = config.pipeline.at_unix_secs;
    let cycle_id = format!("grow-{at}-{}", std::process::id());
    let mut errors: Vec<Value> = Vec::new();

    // Independent BEFORE snapshot (reconciliation baseline).
    let before_rows = catalog.query(None, None)?;
    let before: BTreeMap<u64, (RepoState, String)> = before_rows
        .iter()
        .map(|row| {
            (
                row.record.github_id,
                (row.state, row.record.full_name.clone()),
            )
        })
        .collect();
    let counts_before = catalog.counts_by_state()?;

    // Phase 0: ledger-grounded backfill (idempotent, cheap when converged).
    let backfill = match backfill_grounding(catalog, at) {
        Ok(report) => report,
        Err(error) => {
            errors.push(cycle_error("backfill", &error));
            json!({"error": error.code})
        }
    };

    // Phase 1: discovery refresh (optional; labeled error on failure — the
    // rest of the cycle still runs over the last-known catalog).
    let mut discovery_ran = false;
    let discovery = if config.discovery {
        discovery_ran = true;
        match run_discovery(
            catalog,
            &config.catalog_root,
            &config.languages,
            config.star_floor,
            true,
            at,
        ) {
            Ok(report) => {
                // The full report (with bucket trees) is already persisted by
                // the discovery pass itself; the cycle report keeps the counts.
                let per_language: Vec<Value> = report["languages"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|lr| {
                        json!({
                            "language": lr["language"],
                            "registered": lr["counts"]["registered"],
                            "refreshed": lr["counts"]["refreshed"],
                            "unchanged": lr["counts"]["unchanged"],
                            "departed": lr["departed"],
                            "reappeared": lr["reappeared"],
                        })
                    })
                    .collect();
                json!({
                    "run_id": report["run_id"],
                    "per_language": per_language,
                    "report_file": report["report_file"],
                })
            }
            Err(error) => {
                errors.push(cycle_error("discovery", &error));
                json!({"error": error.code})
            }
        }
    } else {
        json!({"skipped": "discovery not requested this cycle"})
    };

    // Phase 2: quarantine retry release (deliberate, flag-gated).
    let mut released: BTreeSet<u64> = BTreeSet::new();
    let retry = if config.retry_quarantined {
        let mut rows = Vec::new();
        for row in catalog.query(Some(RepoState::Quarantined), None)? {
            match catalog.transition(
                row.record.github_id,
                &row.record.full_name,
                RepoState::Discovered,
                TransitionContext {
                    at_unix_secs: at,
                    ..TransitionContext::default()
                },
            ) {
                Ok(_) => {
                    released.insert(row.record.github_id);
                    rows.push(json!({
                        "full_name": row.record.full_name,
                        "released_from_reason": row.quarantine_reason,
                    }));
                }
                Err(error) => errors.push(cycle_error("retry-release", &error)),
            }
        }
        json!({"released": rows.len(), "repos": rows})
    } else {
        json!({"skipped": "quarantine retry not requested this cycle"})
    };

    // Phase 3: update fetch over every cloned-or-later row. Advances clone
    // trees and `head_commit_hash`; staleness then falls out of the catalog
    // compare against `indexed_commit_hash`.
    let mut update_attribution: BTreeMap<u64, RepoState> = BTreeMap::new();
    let update = match run_clone_pass_outcome(
        catalog,
        &config.farm,
        &Selection::All { limit: None },
        true,
    ) {
        Ok(outcome) => {
            if let Some(refusal) = &outcome.refusal {
                errors.push(cycle_error("update-fetch", refusal));
            }
            for repo_outcome in outcome.report["outcomes"].as_array().unwrap_or(&Vec::new()) {
                if repo_outcome["outcome"].as_str() == Some("quarantined")
                    && let Some(github_id) = repo_outcome["github_id"].as_u64()
                {
                    update_attribution.insert(github_id, RepoState::Quarantined);
                }
            }
            let mut report = outcome.report;
            if let Some(map) = report.as_object_mut() {
                // Per-repo outcomes stay in the pass's own persisted report.
                map.remove("outcomes");
            }
            report
        }
        Err(error) => {
            errors.push(cycle_error("update-fetch", &error));
            json!({"error": error.code})
        }
    };

    // Phase 4: selection (pure catalog computation; see module docs).
    let rows = catalog.query(None, None)?;
    let known: BTreeSet<&str> = rows
        .iter()
        .map(|row| row.record.full_name.as_str())
        .collect();
    for forced in &config.force_repos {
        if !known.contains(forced.as_str()) {
            errors.push(cycle_error(
                "selection",
                &CalyxError {
                    code: ASTRO_FLEET_GROW_FORCE_UNKNOWN,
                    message: format!("--force-repo {forced} is not in the fleet catalog"),
                    remediation: "name a catalogued owner/name repo, or discover it first",
                },
            ));
        }
    }
    let forced_set: BTreeSet<&str> = config
        .force_repos
        .iter()
        .map(String::as_str)
        .filter(|name| known.contains(name))
        .collect();
    let mut forced: Vec<(u64, String)> = Vec::new();
    let mut stale: Vec<(u64, String, Value)> = Vec::new();
    let mut resume: Vec<(u64, String)> = Vec::new();
    let mut acquire: Vec<(u64, String)> = Vec::new();
    for row in &rows {
        let name = row.record.full_name.clone();
        if forced_set.contains(name.as_str()) {
            forced.push((row.record.stars, name));
            continue;
        }
        match row.state {
            RepoState::Kerneled => match (&row.indexed_commit_hash, &row.head_commit_hash) {
                (Some(grounded), Some(head)) if grounded != head => {
                    stale.push((
                        row.record.stars,
                        name,
                        json!({"reason": "head advanced", "grounded": grounded, "head": head}),
                    ));
                }
                (None, _) => {
                    stale.push((
                        row.record.stars,
                        name,
                        json!({"reason": "grounding unknown (ledger backfill found no transition head)"}),
                    ));
                }
                _ => {}
            },
            RepoState::Cloned | RepoState::Indexed => {
                resume.push((row.record.stars, name));
            }
            RepoState::Discovered if config.acquire => {
                acquire.push((row.record.stars, name));
            }
            _ => {}
        }
    }
    for class in [&mut forced, &mut resume, &mut acquire] {
        class.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    }
    stale.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    fn take_within(names: Vec<String>, remaining: &mut usize) -> (Vec<String>, usize) {
        let cut = names.len().min(*remaining);
        let deferred = names.len() - cut;
        let selected: Vec<String> = names.into_iter().take(cut).collect();
        *remaining -= cut;
        (selected, deferred)
    }
    let mut remaining = config.max_repos_per_cycle as usize;
    let (selected_forced, deferred_forced) = take_within(
        forced.iter().map(|(_, n)| n.clone()).collect(),
        &mut remaining,
    );
    let (selected_stale, deferred_stale) = take_within(
        stale.iter().map(|(_, n, _)| n.clone()).collect(),
        &mut remaining,
    );
    let (selected_resume, deferred_resume) = take_within(
        resume.iter().map(|(_, n)| n.clone()).collect(),
        &mut remaining,
    );
    let (selected_acquire, deferred_acquire) = take_within(
        acquire.iter().map(|(_, n)| n.clone()).collect(),
        &mut remaining,
    );
    let selection = json!({
        "candidates": {
            "forced": forced.len(),
            "stale": stale.len(),
            "resume": resume.len(),
            "acquire": acquire.len(),
        },
        "stale_detail": stale.iter().map(|(_, name, why)| json!({"full_name": name, "why": why})).collect::<Vec<_>>(),
        "selected": {
            "forced": selected_forced,
            "stale": selected_stale,
            "resume": selected_resume,
            "acquire": selected_acquire,
        },
        "deferred": {
            "forced": deferred_forced,
            "stale": deferred_stale,
            "resume": deferred_resume,
            "acquire": deferred_acquire,
            "total": deferred_forced + deferred_stale + deferred_resume + deferred_acquire,
        },
        "max_repos_per_cycle": config.max_repos_per_cycle,
    });

    // Phase 5: acquire clones for selected `discovered` rows.
    let mut clone_attribution: BTreeMap<u64, RepoState> = BTreeMap::new();
    let acquire_report = if selection["selected"]["acquire"]
        .as_array()
        .is_some_and(|list| !list.is_empty())
    {
        let names: Vec<String> = selection["selected"]["acquire"]
            .as_array()
            .expect("just checked")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        match run_clone_pass_outcome(catalog, &config.farm, &Selection::Repos(names), false) {
            Ok(outcome) => {
                if let Some(refusal) = &outcome.refusal {
                    errors.push(cycle_error("acquire", refusal));
                }
                for repo_outcome in outcome.report["outcomes"].as_array().unwrap_or(&Vec::new()) {
                    let Some(github_id) = repo_outcome["github_id"].as_u64() else {
                        continue;
                    };
                    match repo_outcome["outcome"].as_str() {
                        Some("acquired") | Some("adopted") | Some("recovered") => {
                            clone_attribution.insert(github_id, RepoState::Cloned);
                        }
                        Some("quarantined") => {
                            clone_attribution.insert(github_id, RepoState::Quarantined);
                        }
                        _ => {}
                    }
                }
                outcome.report
            }
            Err(error) => {
                errors.push(cycle_error("acquire", &error));
                json!({"error": error.code})
            }
        }
    } else {
        json!({"skipped": "no acquire selection this cycle"})
    };

    // Phase 6: pipeline (re-)index over the whole worklist. `force` is
    // correct pass-wide because the only kerneled rows selected are the
    // stale/forced ones that must re-run.
    let mut pipeline_attribution: BTreeMap<u64, RepoState> = BTreeMap::new();
    let mut worklist: Vec<String> = Vec::new();
    for list in ["forced", "stale", "resume", "acquire"] {
        if let Some(names) = selection["selected"][list].as_array() {
            worklist.extend(names.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
    }
    // Acquire failures never reach the pipeline source states; drop the ones
    // whose clone quarantined so the pass does not double-report them.
    let quarantined_by_clone: BTreeSet<String> = rows
        .iter()
        .filter(|row| clone_attribution.get(&row.record.github_id) == Some(&RepoState::Quarantined))
        .map(|row| row.record.full_name.clone())
        .collect();
    worklist.retain(|name| !quarantined_by_clone.contains(name));
    let pipeline_report = if worklist.is_empty() {
        json!({"skipped": "empty worklist this cycle (explicit all-no-op)"})
    } else {
        let mut pipeline_config = config.pipeline.clone();
        pipeline_config.force = true;
        match run_pipeline_pass_outcome(
            catalog,
            &pipeline_config,
            &Selection::Repos(worklist.clone()),
        ) {
            Ok(outcome) => {
                if let Some(refusal) = &outcome.refusal {
                    errors.push(cycle_error("pipeline", refusal));
                }
                for verdict in outcome.report["verdicts"].as_array().unwrap_or(&Vec::new()) {
                    let Some(github_id) = verdict["github_id"].as_u64() else {
                        continue;
                    };
                    match verdict["outcome"].as_str() {
                        Some("kerneled") | Some("resumed") => {
                            pipeline_attribution.insert(github_id, RepoState::Kerneled);
                        }
                        Some("quarantined") => {
                            pipeline_attribution.insert(github_id, RepoState::Quarantined);
                        }
                        _ => {}
                    }
                }
                let mut report = outcome.report;
                if let Some(map) = report.as_object_mut() {
                    // Per-repo verdicts stay in the pass's own persisted report.
                    map.remove("verdicts");
                }
                report
            }
            Err(error) => {
                errors.push(cycle_error("pipeline", &error));
                json!({"error": error.code})
            }
        }
    };

    // Phase 7: debt accounting against the compose sidecar baseline, then
    // debt-gated recomposition (both outcomes explicit).
    let kerneled_rows = catalog.query(Some(RepoState::Kerneled), None)?;
    let debt_report = if kerneled_rows.is_empty() {
        json!({"skipped": "no kerneled repos; nothing to compose"})
    } else {
        let baseline: BTreeMap<String, String> =
            match catalog.read_fleet_report(FLEET_KERNEL_REPORT_KIND, &config.scope)? {
                Some(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(sidecar) => sidecar["repos"]
                        .as_array()
                        .unwrap_or(&Vec::new())
                        .iter()
                        .filter_map(|repo| {
                            Some((
                                repo["project"].as_str()?.to_string(),
                                repo["members_hash"].as_str()?.to_string(),
                            ))
                        })
                        .collect(),
                    Err(error) => {
                        errors.push(cycle_error(
                        "debt",
                        &CalyxError {
                            code: "ASTRO_FLEET_KERNEL_READBACK",
                            message: format!(
                                "fleet-kernel sidecar for {} did not parse: {error}",
                                config.scope
                            ),
                            remediation: "recompose the fleet kernel; the sidecar row is corrupt",
                        },
                    ));
                        BTreeMap::new()
                    }
                },
                None => BTreeMap::new(),
            };
        let mut current: BTreeMap<String, String> = BTreeMap::new();
        for row in &kerneled_rows {
            let project = project_name(&row.record.full_name);
            match repo_kernel_members_hash(&config.pipeline.store_root, &project) {
                Ok(Some(hash)) => {
                    current.insert(project, hash);
                }
                Ok(None) => errors.push(cycle_error(
                    "debt",
                    &CalyxError {
                        code: "ASTRO_FLEET_KERNEL_MISSING",
                        message: format!(
                            "catalog row {} is kerneled but its store holds no kernel artifact",
                            row.record.full_name
                        ),
                        remediation: "re-run the pipeline for this repo; the catalog and store disagree",
                    },
                )),
                Err(error) => errors.push(cycle_error("debt", &error)),
            }
        }
        let changed: Vec<&String> = current
            .iter()
            .filter(|(project, hash)| baseline.get(*project).is_some_and(|b| &b != hash))
            .map(|(project, _)| project)
            .collect();
        let added: Vec<&String> = current
            .keys()
            .filter(|project| !baseline.contains_key(*project))
            .collect();
        let removed: Vec<&String> = baseline
            .keys()
            .filter(|project| !current.contains_key(*project))
            .collect();
        let debt = (changed.len() + added.len() + removed.len()) as u64;
        let decision;
        let compose_summary;
        if debt == 0 {
            decision = "no_debt";
            compose_summary = json!({"skipped": "compose input pairs match the sidecar baseline"});
        } else if debt < config.debt_threshold_repos {
            decision = "deferred_below_threshold";
            compose_summary = json!({
                "skipped": format!(
                    "debt {debt} below declared threshold {} — deferred (explicit)",
                    config.debt_threshold_repos
                ),
            });
        } else {
            decision = "recomposed";
            let mut projects: Vec<String> = current.keys().cloned().collect();
            projects.sort();
            compose_summary = match compose_fleet_kernel(
                catalog,
                &config.pipeline.store_root,
                &config.scope,
                &projects,
                &ComposeConfig::with_registry_defaults(),
            ) {
                Ok(summary) => summary,
                Err(error) => {
                    errors.push(cycle_error("compose", &error));
                    json!({"error": error.code})
                }
            };
        }
        json!({
            "baseline_pairs": baseline.len(),
            "current_pairs": current.len(),
            "changed": changed,
            "added": added,
            "removed": removed,
            "debt": debt,
            "debt_threshold_repos": config.debt_threshold_repos,
            "decision": decision,
            "compose": compose_summary,
        })
    };

    // Phase 8: reconciliation — independent AFTER snapshot; every observed
    // state change must be attributed to a phase verdict of this cycle.
    let after_rows = catalog.query(None, None)?;
    let counts_after = catalog.counts_by_state()?;
    let mut reconcile_errors: Vec<Value> = Vec::new();
    let mut unattributed_departed = 0_u64;
    let mut unattributed_reappeared = 0_u64;
    let mut new_rows = 0_u64;
    for row in &after_rows {
        let github_id = row.record.github_id;
        let Some((state_before, _)) = before.get(&github_id) else {
            new_rows += 1;
            if !discovery_ran {
                reconcile_errors.push(json!({
                    "full_name": row.record.full_name,
                    "problem": "row appeared without a discovery phase this cycle",
                }));
            }
            continue;
        };
        if *state_before == row.state {
            continue;
        }
        let attributed = pipeline_attribution
            .get(&github_id)
            .or_else(|| clone_attribution.get(&github_id))
            .or_else(|| update_attribution.get(&github_id));
        let explained = match attributed {
            Some(expected) => *expected == row.state,
            None => {
                if released.contains(&github_id) {
                    // Retry release: quarantined → discovered, possibly then
                    // re-advanced by acquire/pipeline attribution above.
                    row.state == RepoState::Discovered
                } else if row.state == RepoState::Departed && discovery_ran {
                    unattributed_departed += 1;
                    true
                } else if *state_before == RepoState::Departed
                    && row.state == RepoState::Discovered
                    && discovery_ran
                {
                    unattributed_reappeared += 1;
                    true
                } else {
                    false
                }
            }
        };
        if !explained {
            reconcile_errors.push(json!({
                "full_name": row.record.full_name,
                "from": state_before.as_str(),
                "to": row.state.as_str(),
                "problem": "state change not attributed to any phase of this cycle",
            }));
        }
    }
    if after_rows.len() < before.len() {
        reconcile_errors.push(json!({
            "problem": format!(
                "catalog shrank from {} to {} rows; the catalog never deletes",
                before.len(),
                after_rows.len()
            ),
        }));
    }
    let reconcile = json!({
        "counts_before": counts_before,
        "counts_after": counts_after,
        "new_rows": new_rows,
        "departed_via_discovery": unattributed_departed,
        "reappeared_via_discovery": unattributed_reappeared,
        "mismatches": reconcile_errors,
        "verdict": if reconcile_errors.is_empty() { "reconciled" } else { "MISMATCH" },
    });
    if !reconcile_errors.is_empty() {
        errors.push(json!({
            "phase": "reconcile",
            "code": "ASTRO_FLEET_GROW_RECONCILE",
            "message": format!("{} unattributed state change(s)", reconcile_errors.len()),
        }));
    }

    // Cycle report: file + catalog Blob row + ledger entry, always persisted.
    let report = json!({
        "cycle_id": cycle_id,
        "kind": GROWTH_CYCLE_REPORT_KIND,
        "at_unix_secs": at,
        "config": {
            "scope": config.scope,
            "languages": config.languages,
            "star_floor": config.star_floor,
            "discovery": config.discovery,
            "acquire": config.acquire,
            "retry_quarantined": config.retry_quarantined,
            "force_repos": config.force_repos,
            "max_repos_per_cycle": config.max_repos_per_cycle,
            "debt_threshold_repos": config.debt_threshold_repos,
            "knob_registry_version": FLEET_GROW_KNOB_REGISTRY_VERSION,
        },
        "backfill": backfill,
        "discovery_report": discovery,
        "retry": retry,
        "update": update,
        "selection": selection,
        "acquire_report": acquire_report,
        "pipeline": pipeline_report,
        "debt": debt_report,
        "reconcile": reconcile,
        "errors": errors,
        "wall_secs": started.elapsed().as_secs_f64(),
    });
    let runs_dir = config.pipeline.store_root.join("runs");
    fs::create_dir_all(&runs_dir).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_STORE_UNAVAILABLE",
        message: format!("cannot create runs dir {}: {error}", runs_dir.display()),
        remediation: "the store root must be writable for growth-cycle reports",
    })?;
    let report_path = runs_dir.join(format!("{cycle_id}.json"));
    let report_bytes = serde_json::to_vec_pretty(&report).expect("cycle report serializes");
    fs::write(&report_path, &report_bytes).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_STORE_UNAVAILABLE",
        message: format!(
            "cannot write cycle report {}: {error}",
            report_path.display()
        ),
        remediation: "the store root must be writable for growth-cycle reports",
    })?;
    let error_count = report["errors"].as_array().map_or(0, Vec::len);
    let summary = serde_json::to_vec(&json!({
        "event": "fleet_growth_cycle",
        "cycle_id": cycle_id,
        "selected": selection["selected"],
        "deferred_total": selection["deferred"]["total"],
        "debt": report["debt"]["debt"],
        "debt_decision": report["debt"]["decision"],
        "reconcile_verdict": report["reconcile"]["verdict"],
        "error_count": error_count,
        "report_file": report_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }))
    .expect("cycle summary serializes");
    let (commit_seq, ledger_seq) =
        catalog.record_fleet_report(GROWTH_CYCLE_REPORT_KIND, &cycle_id, report_bytes, summary)?;

    if error_count > 0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_GROW_INCOMPLETE,
            message: format!(
                "growth cycle {cycle_id} recorded {error_count} error(s); report {}",
                report_path.display()
            ),
            remediation: "inspect the cycle report's errors[] and the per-phase run reports; completed work is idempotent — re-running the cycle converges",
        });
    }
    let mut out = report;
    out["commit_seq"] = json!(commit_seq);
    out["ledger_seq"] = json!(ledger_seq);
    out["report_file"] = json!(report_path.display().to_string());
    Ok(out)
}

/// Supervised multi-cycle driver: runs `cycles` growth cycles `interval_secs`
/// apart. A failed cycle is contained (recorded, loop continues); the final
/// result refuses if any cycle failed. Timestamps are stamped per cycle.
pub fn run_grow(
    catalog: &FleetCatalog,
    base: &GrowConfig,
    cycles: u64,
    interval_secs: u64,
    at_override: Option<u64>,
) -> Result<Value, CalyxError> {
    check_range(KNOB_INTERVAL_SECS, interval_secs)?;
    let mut summaries = Vec::new();
    let mut failed_cycles = Vec::new();
    for cycle_index in 0..cycles {
        let at = match at_override {
            Some(at) if cycles == 1 => at,
            _ => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after 1970")
                .as_secs(),
        };
        let mut config = base.clone();
        config.farm.at_unix_secs = at;
        config.pipeline.at_unix_secs = at;
        match run_growth_cycle(catalog, &config) {
            Ok(report) => {
                println!(
                    "{}",
                    json!({
                        "cycle_index": cycle_index,
                        "cycle_id": report["cycle_id"],
                        "verdict": "ok",
                        "selected": report["selection"]["selected"],
                        "debt_decision": report["debt"]["decision"],
                        "report_file": report["report_file"],
                    })
                );
                summaries.push(report);
            }
            Err(error) => {
                println!(
                    "{}",
                    json!({
                        "cycle_index": cycle_index,
                        "verdict": "failed",
                        "code": error.code,
                        "message": error.message,
                    })
                );
                failed_cycles.push((cycle_index, error));
            }
        }
        if cycle_index + 1 < cycles {
            std::thread::sleep(std::time::Duration::from_secs(interval_secs));
        }
    }
    if let Some((index, error)) = failed_cycles.first() {
        return Err(CalyxError {
            code: ASTRO_FLEET_GROW_INCOMPLETE,
            message: format!(
                "{} of {cycles} growth cycle(s) failed (first: cycle {index}: [{}] {})",
                failed_cycles.len(),
                error.code,
                error.message
            ),
            remediation: "inspect each failed cycle's persisted report; cycles are idempotent and re-running converges",
        });
    }
    Ok(json!({"cycles": cycles, "verdict": "ok"}))
}
