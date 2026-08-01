//! `astrolabe-fleet` — CLI surface over the fleet catalog vault (issue #449).
//!
//! Verbs (all output is JSON lines on stdout; failures print one structured
//! `{code,message,remediation}` JSON object on stderr and exit 1):
//!
//! ```text
//! astrolabe-fleet catalog-init [--root <dir>]
//! astrolabe-fleet register     [--root <dir>] (--json <record> | --stdin) [--at <unix-secs>]
//! astrolabe-fleet set-state    [--root <dir>] --github-id <id> --repo <owner/name> --to <state>
//!                              [--at <unix-secs>] [--clone-path <p>] [--head-commit-hash <sha>]
//!                              [--index-watermark <w>] [--indexed-commit-hash <sha>]
//!                              [--kernel-scope-id <k>] [--reason <r>]
//! astrolabe-fleet get          [--root <dir>] (--github-id <id> --repo <owner/name> | --cx <hex>)
//! astrolabe-fleet list         [--root <dir>] [--state <state>] [--language <lang>] [--counts]
//! astrolabe-fleet discover     [--root <dir>] [--language <csv>] [--star-floor <n>]
//!                              [--refresh] [--at <unix-secs>]
//! astrolabe-fleet clone        [--root <dir>] [--farm-root <dir>] [--update]
//!                              (--repo <owner/name> ... | --all-discovered) [--limit <n>]
//!                              [--size-cap-bytes <n>] [--budget-bytes <n>]
//!                              [--parallelism <n>] [--timeout-secs <n>] [--at <unix-secs>]
//! astrolabe-fleet pipeline     [--root <dir>] [--store-root <dir>] [--astrolabe-bin <exe>]
//!                              [--archaeology-root <dir>] [--nomic-dir <dir>]
//!                              (--repo <owner/name> ... | --all-cloned)
//!                              [--limit <n>] [--parallelism <n>] [--timeout-secs <n>]
//!                              [--host-admission-timeout-secs <n>]
//!                              [--force] [--at <unix-secs>]
//! astrolabe-fleet retire-source [--root <dir>] [--farm-root <dir>]
//!                              [--store-root <dir>] [--scope <fleet-scope>]
//!                              --repo <owner/name> ... [--at <unix-secs>]
//! astrolabe-fleet migrate-vault-wal [--root <dir>] [--store-root <dir>]
//!                              --repo <owner/name>
//! astrolabe-fleet upgrade-projection [--root <dir>] [--farm-root <dir>]
//!                              [--store-root <dir>] [--astrolabe-bin <exe>]
//!                              [--archaeology-root <dir>] [--nomic-dir <dir>]
//!                              [--timeout-secs <n>]
//!                              [--host-admission-timeout-secs <n>]
//!                              --repo <owner/name> [--at <unix-secs>]
//! astrolabe-fleet grow         [--root <dir>] (--once | --cycles <n>) [--interval-secs <n>]
//!                              [--scope <fleet-scope>] [--discovery] [--language <csv>]
//!                              [--star-floor <n>] [--acquire] [--retry-quarantined]
//!                              [--retire-sources]
//!                              [--force-repo <owner/name> ...] [--max-repos-per-cycle <n>]
//!                              [--debt-threshold-repos <n>] [--farm-root <dir>]
//!                              [--store-root <dir>] [--archaeology-root <dir>]
//!                              [--astrolabe-bin <exe>] [--nomic-dir <dir>]
//!                              [--size-cap-bytes <n>] [--budget-bytes <n>]
//!                              [--store-budget-bytes <n>] [--parallelism <n>]
//!                              [--timeout-secs <n>] [--host-admission-timeout-secs <n>]
//!                              [--at <unix-secs>]
//! astrolabe-fleet ledger-scan  [--root <dir>] [--github-id <id>] [--event <name>] [--limit <n>]
//! ```
//!
//! `grow` (#457) runs growth cycles: ledger-grounded backfill → optional
//! discovery refresh → optional quarantine retry release → update fetch →
//! bounded selection (forced > stale > resume > reentrant > acquire) → pipeline re-index
//! → debt-gated fleet recomposition → reconciliation → persisted cycle
//! report. `--once` is the Task-Scheduler-friendly single cycle; `--cycles N
//! --interval-secs S` is the supervised loop. `--parallelism` records the
//! pipeline worklist request while the measured whole-host native index stage
//! remains explicitly capped at one; clone/download work keeps the clone
//! farm's independent concurrency. `--timeout-secs` bounds clone and native
//! pipeline work, and `--host-admission-timeout-secs` is the fleet-only finite
//! wait for externally owned index capacity.
//!
//! `--root` defaults to the declared production catalog root
//! [`astrolabe_fleet::discover::DEFAULT_CATALOG_ROOT`] (`D:\astrolabe-fleet\catalog`).
//!
//! `register --stdin` reads one JSON [`RepoRecord`] per line, so external
//! tools can stream records straight into the catalog. `discover` (#450) runs
//! the star-bucket bisection enumeration against the live GitHub API via the
//! authenticated `gh` CLI and registers everything it finds; `--refresh`
//! additionally marks catalog repos absent from a complete enumeration as
//! `departed` and returns reappeared repos to `discovered`.
//! `set-state --to departed` records `--reason` as the departure reason;
//! `--to quarantined` records it as the quarantine reason.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use astrolabe_fleet::catalog::FleetCatalog;
use astrolabe_fleet::record::{RepoRecord, TransitionContext};
use astrolabe_fleet::state::RepoState;
use calyx_aster::cf::ColumnFamily;
use calyx_core::{CalyxError, CxId};
use serde::Serialize;
use serde_json::json;

const USAGE: &str = "usage: astrolabe-fleet <catalog-init|register|set-state|get|list|discover|clone|pipeline|retire-source|migrate-vault-wal|upgrade-projection|grow|ledger-scan|report|report-read|report-list|run-report-read|probe-vault-keys|dedup-census|compose|kernel-read> [--root <dir>] [verb options]; see crate docs";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                json!({
                    "code": error.code,
                    "message": error.message,
                    "remediation": error.remediation,
                })
            );
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), CalyxError> {
    let verb = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| usage("missing verb"))?;
    let opts = Options::parse(&args[1..])?;
    let root = PathBuf::from(
        opts.get("root")
            .unwrap_or(astrolabe_fleet::discover::DEFAULT_CATALOG_ROOT),
    );
    // Farm lock (#527): every MUTATING verb takes the single-writer kernel lock
    // for the whole pass; read verbs stay lock-free. A second mutating pass on
    // the same root refuses fail-closed (ASTRO_FLEET_FARM_LOCKED) instead of
    // racing the store the way the 2026-07-16 dual retry-release did (#460).
    const MUTATING_VERBS: [&str; 13] = [
        "catalog-init",
        "register",
        "set-state",
        "discover",
        "clone",
        "pipeline",
        "retire-source",
        "migrate-vault-wal",
        "upgrade-projection",
        "grow",
        "report",
        "dedup-census",
        "compose",
    ];
    let read_cfs = read_verb_cfs(verb);
    if !MUTATING_VERBS.contains(&verb) && read_cfs.is_none() {
        return Err(usage(&format!("unknown verb {verb:?}")));
    }
    let command_metrics_before = (verb == "kernel-read")
        .then(current_process_metrics)
        .transpose()?;
    let _farm_lock = MUTATING_VERBS
        .contains(&verb)
        .then(|| astrolabe_fleet::farm_lock::FarmLock::acquire(&root, verb))
        .transpose()?;
    let catalog_open_started = Instant::now();
    let catalog = match read_cfs {
        Some(cfs) => FleetCatalog::open_read_only(&root, cfs)?,
        None => FleetCatalog::open(&root)?,
    };
    let catalog_open_wall_us =
        u64::try_from(catalog_open_started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match verb {
        "catalog-init" => {
            opts.reject_unknown(&["root"])?;
            let counts = catalog.counts_by_state()?;
            println!("{}", json!({"catalog": "open", "counts_by_state": counts}));
            Ok(())
        }
        "register" => {
            opts.reject_unknown(&["root", "json", "stdin", "at"])?;
            let at = opts.at_or_now()?;
            let mut records = Vec::new();
            match (opts.get("json"), opts.flag("stdin")) {
                (Some(line), false) => records.push(parse_record(line)?),
                (None, true) => {
                    for line in std::io::stdin().lock().lines() {
                        let line = line.map_err(|error| usage(&format!("read stdin: {error}")))?;
                        if !line.trim().is_empty() {
                            records.push(parse_record(&line)?);
                        }
                    }
                }
                _ => {
                    return Err(usage(
                        "register needs exactly one of --json <record> or --stdin",
                    ));
                }
            }
            for record in records {
                let report = catalog.register(record, at)?;
                println!(
                    "{}",
                    serde_json::to_value(&report).expect("register report serializes")
                );
            }
            Ok(())
        }
        "set-state" => {
            opts.reject_unknown(&[
                "root",
                "github-id",
                "repo",
                "to",
                "at",
                "clone-path",
                "head-commit-hash",
                "index-watermark",
                "indexed-commit-hash",
                "kernel-scope-id",
                "reason",
                "clone-bytes",
                "store-bytes",
            ])?;
            let github_id = opts.require_u64("github-id")?;
            let full_name = opts.require("repo")?;
            let to = RepoState::parse(opts.require("to")?)?;
            let reason = opts.get("reason").map(str::to_string);
            let ctx = TransitionContext {
                at_unix_secs: opts.at_or_now()?,
                clone_path: opts.get("clone-path").map(str::to_string),
                head_commit_hash: opts.get("head-commit-hash").map(str::to_string),
                index_watermark: opts.get("index-watermark").map(str::to_string),
                indexed_commit_hash: opts.get("indexed-commit-hash").map(str::to_string),
                kernel_scope_id: opts.get("kernel-scope-id").map(str::to_string),
                quarantine_reason: (to == RepoState::Quarantined)
                    .then(|| reason.clone())
                    .flatten(),
                departed_reason: (to == RepoState::Departed)
                    .then(|| reason.clone())
                    .flatten(),
                clone_bytes: opts
                    .get("clone-bytes")
                    .map(|raw| {
                        raw.parse::<u64>().map_err(|error| {
                            usage(&format!("--clone-bytes must be a u64: {error}"))
                        })
                    })
                    .transpose()?,
                store_bytes: opts
                    .get("store-bytes")
                    .map(|raw| {
                        raw.parse::<u64>().map_err(|error| {
                            usage(&format!("--store-bytes must be a u64: {error}"))
                        })
                    })
                    .transpose()?,
                // Farm-owned fact (#480): set only by real clone/update passes,
                // never by hand — set-state leaves it untouched.
                checkout_exclusions: None,
            };
            let report = catalog.transition(github_id, full_name, to, ctx)?;
            println!(
                "{}",
                serde_json::to_value(&report).expect("transition report serializes")
            );
            Ok(())
        }
        "get" => {
            opts.reject_unknown(&["root", "github-id", "repo", "cx"])?;
            let row = match (opts.get("cx"), opts.get("github-id"), opts.get("repo")) {
                (Some(cx), None, None) => {
                    let cx_id = cx
                        .parse::<CxId>()
                        .map_err(|error| usage(&format!("--cx {cx:?} is not a CxId: {error}")))?;
                    catalog.get(cx_id)?
                }
                (None, Some(_), Some(_)) => catalog
                    .get_by_identity(opts.require_u64("github-id")?, opts.require("repo")?)?,
                _ => return Err(usage("get needs --cx <hex> or both --github-id and --repo")),
            };
            println!("{}", serde_json::to_value(&row).expect("row serializes"));
            Ok(())
        }
        "list" => {
            opts.reject_unknown(&["root", "state", "language", "counts"])?;
            let state = opts.get("state").map(RepoState::parse).transpose()?;
            let rows = catalog.query(state, opts.get("language"))?;
            if opts.flag("counts") {
                println!(
                    "{}",
                    json!({
                        "total": rows.len(),
                        "counts_by_state": catalog.counts_by_state()?,
                    })
                );
                return Ok(());
            }
            println!("{}", json!({"total": rows.len()}));
            for row in rows {
                println!("{}", serde_json::to_value(&row).expect("row serializes"));
            }
            Ok(())
        }
        "discover" => {
            opts.reject_unknown(&["root", "language", "star-floor", "refresh", "at"])?;
            let languages: Vec<String> = opts
                .get("language")
                .map(|csv| {
                    csv.split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| {
                    astrolabe_fleet::discover::DEFAULT_LANGUAGES
                        .iter()
                        .map(|lang| (*lang).to_string())
                        .collect()
                });
            if languages.is_empty() {
                return Err(usage("--language must name at least one language"));
            }
            let star_floor = match opts.get("star-floor") {
                Some(raw) => raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--star-floor must be a u64: {error}")))?,
                None => astrolabe_fleet::discover::DEFAULT_STAR_FLOOR,
            };
            let report = astrolabe_fleet::discover::run_discovery(
                &catalog,
                &root,
                &languages,
                star_floor,
                opts.flag("refresh"),
                opts.at_or_now()?,
            )?;
            println!("{report}");
            Ok(())
        }
        "clone" => {
            opts.reject_unknown(&[
                "root",
                "farm-root",
                "update",
                "repo",
                "all-discovered",
                "limit",
                "size-cap-bytes",
                "budget-bytes",
                "parallelism",
                "timeout-secs",
                "at",
            ])?;
            let mut config = astrolabe_fleet::clone_farm::FarmConfig {
                at_unix_secs: opts.at_or_now()?,
                ..astrolabe_fleet::clone_farm::FarmConfig::default()
            };
            if let Some(farm_root) = opts.get("farm-root") {
                config.farm_root = PathBuf::from(farm_root);
            }
            if let Some(raw) = opts.get("size-cap-bytes") {
                config.size_cap_bytes = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--size-cap-bytes must be a u64: {error}")))?;
            }
            if let Some(raw) = opts.get("budget-bytes") {
                config.budget_bytes = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--budget-bytes must be a u64: {error}")))?;
            }
            if let Some(raw) = opts.get("parallelism") {
                config.parallelism = raw
                    .parse::<usize>()
                    .map_err(|error| usage(&format!("--parallelism must be a usize: {error}")))?;
            }
            if let Some(raw) = opts.get("timeout-secs") {
                config.timeout_secs = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--timeout-secs must be a u64: {error}")))?;
            }
            let repos = opts.get_all("repo");
            let selection = if !repos.is_empty() {
                if opts.flag("all-discovered") {
                    return Err(usage(
                        "pass either --repo ... or --all-discovered, not both",
                    ));
                }
                astrolabe_fleet::clone_farm::Selection::Repos(
                    repos.into_iter().map(str::to_string).collect(),
                )
            } else if opts.flag("all-discovered") || opts.flag("update") {
                let limit = opts
                    .get("limit")
                    .map(|raw| {
                        raw.parse::<usize>()
                            .map_err(|error| usage(&format!("--limit must be a usize: {error}")))
                    })
                    .transpose()?;
                astrolabe_fleet::clone_farm::Selection::All { limit }
            } else {
                return Err(usage(
                    "clone needs --repo <owner/name> (repeatable) or --all-discovered (or --update for the update pass)",
                ));
            };
            let report = astrolabe_fleet::clone_farm::run_clone_pass(
                &catalog,
                &config,
                &selection,
                opts.flag("update"),
            )?;
            println!("{report}");
            Ok(())
        }
        "pipeline" => {
            opts.reject_unknown(&[
                "root",
                "store-root",
                "archaeology-root",
                "astrolabe-bin",
                "nomic-dir",
                "repo",
                "all-cloned",
                "limit",
                "parallelism",
                "timeout-secs",
                "host-admission-timeout-secs",
                "force",
                "store-budget-bytes",
                "at",
            ])?;
            let mut config =
                astrolabe_fleet::orchestrator::PipelineConfig::with_default_bin(opts.at_or_now()?);
            if let Some(store_root) = opts.get("store-root") {
                config.store_root = PathBuf::from(store_root);
            }
            if let Some(archaeology_root) = opts.get("archaeology-root") {
                config.archaeology_root = PathBuf::from(archaeology_root);
            }
            if let Some(bin) = opts.get("astrolabe-bin") {
                config.astrolabe_bin = PathBuf::from(bin);
            }
            if let Some(nomic) = opts.get("nomic-dir") {
                config.nomic_dir = PathBuf::from(nomic);
            }
            if let Some(raw) = opts.get("parallelism") {
                config.parallelism = raw
                    .parse::<usize>()
                    .map_err(|error| usage(&format!("--parallelism must be a usize: {error}")))?;
            }
            if let Some(raw) = opts.get("timeout-secs") {
                config.timeout_secs = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--timeout-secs must be a u64: {error}")))?;
                if opts.get("host-admission-timeout-secs").is_none() {
                    config.host_admission_timeout_secs = config.timeout_secs;
                }
            }
            if let Some(raw) = opts.get("host-admission-timeout-secs") {
                config.host_admission_timeout_secs = raw.parse::<u64>().map_err(|error| {
                    usage(&format!(
                        "--host-admission-timeout-secs must be a u64: {error}"
                    ))
                })?;
            }
            config.force = opts.flag("force");
            if let Some(raw) = opts.get("store-budget-bytes") {
                config.store_budget_bytes = Some(raw.parse::<u64>().map_err(|error| {
                    usage(&format!("--store-budget-bytes must be a u64: {error}"))
                })?);
            }
            let repos = opts.get_all("repo");
            let selection = if !repos.is_empty() {
                if opts.flag("all-cloned") {
                    return Err(usage("pass either --repo ... or --all-cloned, not both"));
                }
                astrolabe_fleet::clone_farm::Selection::Repos(
                    repos.into_iter().map(str::to_string).collect(),
                )
            } else if opts.flag("all-cloned") {
                let limit = opts
                    .get("limit")
                    .map(|raw| {
                        raw.parse::<usize>()
                            .map_err(|error| usage(&format!("--limit must be a usize: {error}")))
                    })
                    .transpose()?;
                astrolabe_fleet::clone_farm::Selection::All { limit }
            } else {
                return Err(usage(
                    "pipeline needs --repo <owner/name> (repeatable) or --all-cloned",
                ));
            };
            let report =
                astrolabe_fleet::orchestrator::run_pipeline_pass(&catalog, &config, &selection)?;
            println!("{report}");
            Ok(())
        }
        "retire-source" => {
            opts.reject_unknown(&["root", "farm-root", "store-root", "scope", "repo", "at"])?;
            let repos: Vec<String> = opts
                .get_all("repo")
                .into_iter()
                .map(str::to_string)
                .collect();
            if repos.is_empty() {
                return Err(usage(
                    "retire-source needs at least one --repo <owner/name>",
                ));
            }
            let config = astrolabe_fleet::retirement::RetirementConfig {
                farm_root: PathBuf::from(
                    opts.get("farm-root")
                        .unwrap_or(astrolabe_fleet::clone_farm::DEFAULT_FARM_ROOT),
                ),
                store_root: PathBuf::from(
                    opts.get("store-root")
                        .unwrap_or(astrolabe_fleet::orchestrator::DEFAULT_STORE_ROOT),
                ),
                scope: opts.get("scope").unwrap_or("fleet:rust:v1").to_string(),
                at_unix_secs: opts.at_or_now()?,
            };
            let outcome =
                astrolabe_fleet::retirement::run_source_retirement_pass(&catalog, &config, &repos)?;
            if let Some(refusal) = outcome.refusal {
                return Err(refusal);
            }
            println!("{}", outcome.report);
            Ok(())
        }
        "migrate-vault-wal" => {
            opts.reject_unknown(&["root", "store-root", "repo"])?;
            let repos = opts.get_all("repo");
            if repos.len() != 1 {
                return Err(usage(
                    "migrate-vault-wal needs exactly one --repo <owner/name>",
                ));
            }
            let repo = repos[0];
            let row = catalog
                .query(None, None)?
                .into_iter()
                .find(|row| row.record.full_name == repo)
                .ok_or_else(|| CalyxError {
                    code: "ASTRO_FLEET_PROJECT_IDENTITY",
                    message: format!("fleet catalog has no exact repository {repo:?}"),
                    remediation: "pass the exact owner/name stored in the fleet catalog",
                })?;
            let identity = astrolabe_fleet::orchestrator::repo_store_identity(&row)?;
            let store_root = PathBuf::from(
                opts.get("store-root")
                    .unwrap_or(astrolabe_fleet::orchestrator::DEFAULT_STORE_ROOT),
            );
            let vault_path = store_root
                .join(&identity.store_key)
                .join(format!("{}.astrolabe-vault", identity.index_project));
            let migration = calyx_aster::wal::migrate_legacy_wal_tail(&vault_path)?;
            let kernel = astrolabe_fleet::compose::read_repo_kernel_artifact(
                &store_root,
                &identity.store_key,
                &identity.index_project,
            )?
            .ok_or_else(|| CalyxError {
                code: astrolabe_fleet::compose::ASTRO_FLEET_KERNEL_MISSING,
                message: format!(
                    "vault {} reopened after WAL migration but has no persisted per-repo kernel",
                    vault_path.display()
                ),
                remediation: "preserve the migrated vault and re-run the real pipeline to persist its per-repo kernel before source retirement",
            })?;
            println!(
                "{}",
                serde_json::json!({
                    "verb": "migrate-vault-wal",
                    "repo": repo,
                    "store_key": identity.store_key,
                    "index_project": identity.index_project,
                    "kernel_scope": identity.kernel_scope,
                    "migration": migration,
                    "kernel_readback": {
                        "members_hash": kernel.members_hash,
                        "member_count": kernel.member_count,
                        "node_count": kernel.node_count,
                        "recall_permille": kernel.recall.permille,
                        "selected_cfs": ["kernel"],
                        "full_compose_materialization": false,
                    },
                })
            );
            Ok(())
        }
        "upgrade-projection" => {
            opts.reject_unknown(&[
                "root",
                "farm-root",
                "store-root",
                "archaeology-root",
                "astrolabe-bin",
                "nomic-dir",
                "repo",
                "timeout-secs",
                "host-admission-timeout-secs",
                "store-budget-bytes",
                "at",
            ])?;
            let repos = opts.get_all("repo");
            if repos.len() != 1 {
                return Err(usage(
                    "upgrade-projection needs exactly one --repo <owner/name>",
                ));
            }
            let repo = repos[0];
            let at = opts.at_or_now()?;
            let upgrade_config = astrolabe_fleet::projection_upgrade::ProjectionUpgradeConfig {
                farm_root: PathBuf::from(
                    opts.get("farm-root")
                        .unwrap_or(astrolabe_fleet::clone_farm::DEFAULT_FARM_ROOT),
                ),
                store_root: PathBuf::from(
                    opts.get("store-root")
                        .unwrap_or(astrolabe_fleet::orchestrator::DEFAULT_STORE_ROOT),
                ),
                at_unix_secs: at,
            };
            let preparation = astrolabe_fleet::projection_upgrade::prepare_projection_upgrade(
                &catalog,
                &upgrade_config,
                repo,
            )?;
            let pipeline_report = if preparation.reindex_required {
                let mut pipeline =
                    astrolabe_fleet::orchestrator::PipelineConfig::with_default_bin(at);
                pipeline.store_root = upgrade_config.store_root.clone();
                if let Some(archaeology_root) = opts.get("archaeology-root") {
                    pipeline.archaeology_root = PathBuf::from(archaeology_root);
                }
                if let Some(bin) = opts.get("astrolabe-bin") {
                    pipeline.astrolabe_bin = PathBuf::from(bin);
                }
                if let Some(nomic) = opts.get("nomic-dir") {
                    pipeline.nomic_dir = PathBuf::from(nomic);
                }
                if let Some(raw) = opts.get("timeout-secs") {
                    pipeline.timeout_secs = raw.parse::<u64>().map_err(|error| {
                        usage(&format!("--timeout-secs must be a u64: {error}"))
                    })?;
                    if opts.get("host-admission-timeout-secs").is_none() {
                        pipeline.host_admission_timeout_secs = pipeline.timeout_secs;
                    }
                }
                if let Some(raw) = opts.get("host-admission-timeout-secs") {
                    pipeline.host_admission_timeout_secs = raw.parse::<u64>().map_err(|error| {
                        usage(&format!(
                            "--host-admission-timeout-secs must be a u64: {error}"
                        ))
                    })?;
                }
                if let Some(raw) = opts.get("store-budget-bytes") {
                    pipeline.store_budget_bytes = Some(raw.parse::<u64>().map_err(|error| {
                        usage(&format!("--store-budget-bytes must be a u64: {error}"))
                    })?);
                }
                pipeline.parallelism = 1;
                pipeline.force = true;
                pipeline.retain_kerneled_state_on_failure = true;
                Some(astrolabe_fleet::orchestrator::run_pipeline_pass(
                    &catalog,
                    &pipeline,
                    &astrolabe_fleet::clone_farm::Selection::Repos(vec![repo.to_string()]),
                )?)
            } else {
                None
            };
            let current_identity =
                astrolabe_fleet::projection_upgrade::read_current_projection_identity(
                    &catalog,
                    &upgrade_config,
                    &preparation,
                )?;
            let kernel = astrolabe_fleet::compose::load_repo_kernel(
                &upgrade_config.store_root,
                &current_identity.store_key,
                &current_identity.index_project,
            )?
            .ok_or_else(|| CalyxError {
                code: astrolabe_fleet::compose::ASTRO_FLEET_KERNEL_MISSING,
                message: format!(
                    "projection upgrade reopened current store {} but no per-repo kernel is persisted",
                    current_identity.store_key
                ),
                remediation: "preserve the projection and transaction; inspect the ordinary pipeline report before retrying the exact upgrade",
            })?;
            let recovery_report = serde_json::json!({
                "outcome": preparation.outcome,
                "source": "current_projection_readback",
                "current_identity": &current_identity,
                "source_head": preparation.source_head,
                "database_sha256": preparation.database_sha256,
            });
            let completion = astrolabe_fleet::projection_upgrade::complete_projection_upgrade(
                &upgrade_config,
                &preparation,
                &current_identity,
                &kernel.members_hash,
                kernel.occurrences.len(),
                pipeline_report.as_ref().unwrap_or(&recovery_report),
            )?;
            println!(
                "{}",
                serde_json::json!({
                    "verb": "upgrade-projection",
                    "preparation": preparation,
                    "current_identity": current_identity,
                    "pipeline_report": pipeline_report,
                    "kernel_readback": {
                        "members_hash": kernel.members_hash,
                        "member_count": kernel.occurrences.len(),
                        "node_count": kernel.node_count,
                        "recall_permille": kernel.recall_permille,
                    },
                    "completion": completion,
                })
            );
            Ok(())
        }
        "grow" => {
            opts.reject_unknown(&[
                "root",
                "farm-root",
                "store-root",
                "archaeology-root",
                "astrolabe-bin",
                "nomic-dir",
                "scope",
                "language",
                "star-floor",
                "once",
                "cycles",
                "interval-secs",
                "discovery",
                "acquire",
                "retry-quarantined",
                "retire-sources",
                "force-repo",
                "max-repos-per-cycle",
                "debt-threshold-repos",
                "size-cap-bytes",
                "budget-bytes",
                "store-budget-bytes",
                "parallelism",
                "timeout-secs",
                "host-admission-timeout-secs",
                "at",
            ])?;
            let once = opts.flag("once");
            let cycles = match (once, opts.get("cycles")) {
                (true, None) => 1,
                (false, Some(raw)) => {
                    let n = raw
                        .parse::<u64>()
                        .map_err(|error| usage(&format!("--cycles must be a u64: {error}")))?;
                    if n == 0 {
                        return Err(usage("--cycles must be at least 1"));
                    }
                    n
                }
                (true, Some(_)) => {
                    return Err(usage("pass either --once or --cycles <n>, not both"));
                }
                (false, None) => {
                    return Err(usage(
                        "grow needs --once (single cycle) or --cycles <n> (supervised loop)",
                    ));
                }
            };
            if opts.get("at").is_some() && cycles != 1 {
                return Err(usage(
                    "--at pins one deterministic timestamp and is only valid with --once",
                ));
            }
            let interval_secs = match opts.get("interval-secs") {
                Some(raw) => raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--interval-secs must be a u64: {error}")))?,
                None => {
                    astrolabe_fleet::grow::FLEET_GROW_KNOBS
                        .iter()
                        .find(|knob| knob.name == astrolabe_fleet::grow::KNOB_INTERVAL_SECS)
                        .expect("interval knob is declared")
                        .default
                }
            };
            let at_override = opts
                .get("at")
                .map(|raw| {
                    raw.parse::<u64>()
                        .map_err(|error| usage(&format!("--at must be unix seconds: {error}")))
                })
                .transpose()?;

            let mut farm = astrolabe_fleet::clone_farm::FarmConfig::default();
            if let Some(farm_root) = opts.get("farm-root") {
                farm.farm_root = PathBuf::from(farm_root);
            }
            if let Some(raw) = opts.get("size-cap-bytes") {
                farm.size_cap_bytes = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--size-cap-bytes must be a u64: {error}")))?;
            }
            if let Some(raw) = opts.get("budget-bytes") {
                farm.budget_bytes = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--budget-bytes must be a u64: {error}")))?;
            }
            if let Some(raw) = opts.get("timeout-secs") {
                farm.timeout_secs = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--timeout-secs must be a u64: {error}")))?;
            }
            let mut pipeline = astrolabe_fleet::orchestrator::PipelineConfig::with_default_bin(0);
            if let Some(store_root) = opts.get("store-root") {
                pipeline.store_root = PathBuf::from(store_root);
            }
            if let Some(archaeology_root) = opts.get("archaeology-root") {
                pipeline.archaeology_root = PathBuf::from(archaeology_root);
            }
            if let Some(bin) = opts.get("astrolabe-bin") {
                pipeline.astrolabe_bin = PathBuf::from(bin);
            }
            if let Some(nomic) = opts.get("nomic-dir") {
                pipeline.nomic_dir = PathBuf::from(nomic);
            }
            if let Some(raw) = opts.get("parallelism") {
                pipeline.parallelism = raw
                    .parse::<usize>()
                    .map_err(|error| usage(&format!("--parallelism must be a usize: {error}")))?;
            }
            if let Some(raw) = opts.get("timeout-secs") {
                pipeline.timeout_secs = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--timeout-secs must be a u64: {error}")))?;
                if opts.get("host-admission-timeout-secs").is_none() {
                    pipeline.host_admission_timeout_secs = pipeline.timeout_secs;
                }
            }
            if let Some(raw) = opts.get("host-admission-timeout-secs") {
                pipeline.host_admission_timeout_secs = raw.parse::<u64>().map_err(|error| {
                    usage(&format!(
                        "--host-admission-timeout-secs must be a u64: {error}"
                    ))
                })?;
            }
            if let Some(raw) = opts.get("store-budget-bytes") {
                pipeline.store_budget_bytes = Some(raw.parse::<u64>().map_err(|error| {
                    usage(&format!("--store-budget-bytes must be a u64: {error}"))
                })?);
            }

            let mut config = astrolabe_fleet::grow::GrowConfig::with_registry_defaults(
                root.clone(),
                farm,
                pipeline,
            );
            if let Some(scope) = opts.get("scope") {
                config.scope = scope.to_string();
            }
            if let Some(languages) = opts.get("language") {
                config.languages = languages
                    .split(',')
                    .map(|part| part.trim().to_lowercase())
                    .filter(|part| !part.is_empty())
                    .collect();
                if config.languages.is_empty() {
                    return Err(usage("--language must name at least one language"));
                }
            }
            if let Some(raw) = opts.get("star-floor") {
                config.star_floor = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--star-floor must be a u64: {error}")))?;
            }
            config.discovery = opts.flag("discovery");
            config.acquire = opts.flag("acquire");
            config.retry_quarantined = opts.flag("retry-quarantined");
            config.retire_sources = opts.flag("retire-sources");
            config.force_repos = opts
                .get_all("force-repo")
                .into_iter()
                .map(str::to_string)
                .collect();
            if let Some(raw) = opts.get("max-repos-per-cycle") {
                config.max_repos_per_cycle = raw.parse::<u64>().map_err(|error| {
                    usage(&format!("--max-repos-per-cycle must be a u64: {error}"))
                })?;
            }
            if let Some(raw) = opts.get("debt-threshold-repos") {
                config.debt_threshold_repos = raw.parse::<u64>().map_err(|error| {
                    usage(&format!("--debt-threshold-repos must be a u64: {error}"))
                })?;
            }
            let report = astrolabe_fleet::grow::run_grow(
                &catalog,
                &config,
                cycles,
                interval_secs,
                at_override,
            )?;
            println!("{report}");
            Ok(())
        }
        "ledger-scan" => {
            opts.reject_unknown(&["root", "github-id", "event", "limit"])?;
            let github_id = opts
                .get("github-id")
                .map(|raw| {
                    raw.parse::<u64>()
                        .map_err(|error| usage(&format!("--github-id must be a u64: {error}")))
                })
                .transpose()?;
            let event = opts.get("event");
            let mut entries =
                astrolabe_fleet::grow::scan_ledger_events(&catalog, github_id, event)?;
            if let Some(raw) = opts.get("limit") {
                let limit = raw
                    .parse::<usize>()
                    .map_err(|error| usage(&format!("--limit must be a usize: {error}")))?;
                let skip = entries.len().saturating_sub(limit);
                entries.drain(..skip);
            }
            println!("{}", json!({"total": entries.len()}));
            for entry in entries {
                println!("{entry}");
            }
            Ok(())
        }
        "report" => {
            opts.reject_unknown(&["root", "kind", "id", "file", "summary"])?;
            let kind = opts
                .get("kind")
                .ok_or_else(|| usage("report needs --kind <slug>"))?;
            let id = opts.get("id").ok_or_else(|| usage("report needs --id"))?;
            let file = opts
                .get("file")
                .ok_or_else(|| usage("report needs --file <json path>"))?;
            let bytes = std::fs::read(file).map_err(|error| CalyxError {
                code: "ASTRO_FLEET_REPORT_READ",
                message: format!("read report file {file}: {error}"),
                remediation: "pass a readable JSON file as --file",
            })?;
            // The payload must be JSON: reports are queryable data, not opaque blobs.
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| CalyxError {
                code: "ASTRO_FLEET_REPORT_PARSE",
                message: format!("report file {file} is not valid JSON: {error}"),
                remediation: "fleet reports are queryable JSON; fix the file",
            })?;
            let summary = opts
                .get("summary")
                .map(str::to_string)
                .unwrap_or_else(|| format!("fleet report {kind}:{id} recorded"));
            let summary_payload = serde_json::json!({
                "event": "fleet_report_recorded",
                "kind": kind,
                "report_id": id,
                "bytes": bytes.len(),
                "summary": summary,
            })
            .to_string()
            .into_bytes();
            let (commit_seq, ledger_seq) =
                catalog.record_fleet_report(kind, id, bytes.clone(), summary_payload)?;
            // Post-commit readback (FSV in the write path, beyond record's own).
            let persisted = catalog.read_fleet_report(kind, id)?.ok_or(CalyxError {
                code: astrolabe_fleet::catalog::ASTRO_FLEET_FSV_MISMATCH,
                message: format!("fleet report {kind}:{id} absent immediately after commit"),
                remediation: "audit the catalog vault; do not trust this write",
            })?;
            if persisted != bytes {
                return Err(CalyxError {
                    code: astrolabe_fleet::catalog::ASTRO_FLEET_FSV_MISMATCH,
                    message: format!("fleet report {kind}:{id} readback diverges from the file"),
                    remediation: "audit the catalog vault; do not trust this write",
                });
            }
            println!(
                "{}",
                serde_json::json!({
                    "kind": kind,
                    "report_id": id,
                    "bytes": bytes.len(),
                    "commit_seq": commit_seq,
                    "ledger_seq": ledger_seq,
                    "readback": "byte-identical",
                })
            );
            Ok(())
        }
        "report-read" => {
            opts.reject_unknown(&["root", "kind", "id", "latest"])?;
            let kind = opts
                .get("kind")
                .ok_or_else(|| usage("report-read needs --kind <slug>"))?;
            let id = if opts.flag("latest") {
                catalog
                    .list_fleet_reports(kind)?
                    .pop()
                    .ok_or_else(|| CalyxError {
                        code: "ASTRO_FLEET_REPORT_MISSING",
                        message: format!("no fleet reports recorded under kind {kind:?}"),
                        remediation: "record one with the report verb first",
                    })?
            } else {
                opts.get("id")
                    .ok_or_else(|| usage("report-read needs --id or --latest"))?
                    .to_string()
            };
            let bytes = catalog
                .read_fleet_report(kind, &id)?
                .ok_or_else(|| CalyxError {
                    code: "ASTRO_FLEET_REPORT_MISSING",
                    message: format!("no fleet report {kind}:{id}"),
                    remediation: "list ids with report-list --kind",
                })?;
            use std::io::Write as _;
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|error| CalyxError {
                    code: "ASTRO_FLEET_REPORT_READ",
                    message: format!("write report bytes to stdout: {error}"),
                    remediation: "retry with a writable stdout",
                })?;
            Ok(())
        }
        "report-list" => {
            opts.reject_unknown(&["root", "kind"])?;
            let kind = opts
                .get("kind")
                .ok_or_else(|| usage("report-list needs --kind <slug>"))?;
            let ids = catalog.list_fleet_reports(kind)?;
            println!(
                "{}",
                serde_json::json!({ "kind": kind, "total": ids.len(), "report_ids": ids })
            );
            Ok(())
        }
        "dedup-census" => {
            opts.reject_unknown(&["root", "store-root", "project", "id"])?;
            let store_root = PathBuf::from(opts.get("store-root").ok_or_else(|| {
                usage("dedup-census needs --store-root <dir> (the fleet store root)")
            })?);
            let report_id = opts
                .get("id")
                .ok_or_else(|| usage("dedup-census needs --id <report-id>"))?;
            let named = opts.get_all("project");
            let projects: Vec<String> = if named.is_empty() {
                let mut projects: Vec<String> = catalog
                    .query(Some(RepoState::Kerneled), None)?
                    .into_iter()
                    .map(|row| row.record.full_name.replace('/', "__"))
                    .collect();
                projects.sort();
                if projects.is_empty() {
                    return Err(CalyxError {
                        code: "ASTRO_FLEET_DEDUP_EMPTY",
                        message: "no kerneled repos in the catalog and no --project named"
                            .to_string(),
                        remediation: "kernel at least one repo or name --project <org__repo> explicitly",
                    });
                }
                projects
            } else {
                named.into_iter().map(str::to_string).collect()
            };
            let mut per_project = Vec::with_capacity(projects.len());
            for project in &projects {
                let identity =
                    astrolabe_fleet::orchestrator::catalog_store_identity(&catalog, project)?;
                let atoms = astrolabe_fleet::dedup::project_atoms(
                    &store_root,
                    &identity.store_key,
                    &identity.index_project,
                )?;
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "project": project,
                        "index_project": identity.index_project,
                        "kernel_scope": identity.kernel_scope,
                        "atoms": atoms.len(),
                    })
                );
                per_project.push((project.clone(), atoms));
            }
            let artifact = astrolabe_fleet::dedup::census_artifact(&per_project);
            let bytes = serde_json::to_vec_pretty(&artifact).expect("census serializes");
            let summary = serde_json::to_vec(&serde_json::json!({
                "event": "fleet_dedup_census",
                "report_id": report_id,
                "projects": projects.len(),
                "atoms_total": artifact["atoms_total"],
                "distinct_contents": artifact["distinct_contents"],
                "cross_repo_classes": artifact["cross_repo_classes"],
            }))
            .expect("census summary serializes");
            let (commit_seq, ledger_seq) =
                catalog.record_fleet_report("dedup-census", report_id, bytes, summary)?;
            println!(
                "{}",
                serde_json::json!({
                    "kind": "dedup-census",
                    "report_id": report_id,
                    "commit_seq": commit_seq,
                    "ledger_seq": ledger_seq,
                    "atoms_total": artifact["atoms_total"],
                    "distinct_contents": artifact["distinct_contents"],
                    "dedup_ratio": artifact["dedup_ratio"],
                    "cross_repo_classes": artifact["cross_repo_classes"],
                    "projects": artifact["projects"],
                })
            );
            Ok(())
        }
        "compose" => {
            opts.reject_unknown(&[
                "root",
                "store-root",
                "scope",
                "repo",
                "sim-min-permille",
                "sim-top-k",
                "repo-recall-min-permille",
                "cross-repo-support-weight-permille",
            ])?;
            let store_root =
                PathBuf::from(opts.get("store-root").ok_or_else(|| {
                    usage("compose needs --store-root <dir> (the fleet store root)")
                })?);
            let scope = opts
                .get("scope")
                .ok_or_else(|| usage("compose needs --scope <scope-id> (e.g. fleet:rust:v1)"))?;
            let named = opts.get_all("repo");
            let projects: Vec<String> = if named.is_empty() {
                let mut projects: Vec<String> = catalog
                    .query(Some(RepoState::Kerneled), None)?
                    .into_iter()
                    .map(|row| row.record.full_name.replace('/', "__"))
                    .collect();
                projects.sort();
                if projects.is_empty() {
                    return Err(CalyxError {
                        code: "ASTRO_FLEET_COMPOSE_EMPTY",
                        message: "no kerneled repos in the catalog and no --repo named".to_string(),
                        remediation: "kernel at least one repo or name --repo <org__repo> explicitly",
                    });
                }
                projects
            } else {
                named.into_iter().map(str::to_string).collect()
            };
            let mut config = astrolabe_fleet::compose::ComposeConfig::with_registry_defaults();
            if let Some(raw) = opts.get("sim-min-permille") {
                config.similarity_min_permille = raw.parse::<u64>().map_err(|error| {
                    usage(&format!("--sim-min-permille must be a u64: {error}"))
                })?;
            }
            if let Some(raw) = opts.get("sim-top-k") {
                config.similarity_top_k = raw
                    .parse::<u64>()
                    .map_err(|error| usage(&format!("--sim-top-k must be a u64: {error}")))?;
            }
            if let Some(raw) = opts.get("repo-recall-min-permille") {
                config.per_repo_recall_min_permille = raw.parse::<u64>().map_err(|error| {
                    usage(&format!(
                        "--repo-recall-min-permille must be a u64: {error}"
                    ))
                })?;
            }
            if let Some(raw) = opts.get("cross-repo-support-weight-permille") {
                config.cross_repo_support_weight_permille =
                    raw.parse::<u64>().map_err(|error| {
                        usage(&format!(
                            "--cross-repo-support-weight-permille must be a u64: {error}"
                        ))
                    })?;
            }
            let summary = astrolabe_fleet::compose::compose_fleet_kernel(
                &catalog,
                &store_root,
                scope,
                &projects,
                &config,
            )?;
            println!("{summary}");
            Ok(())
        }
        "kernel-read" => {
            opts.reject_unknown(&["root", "scope", "raw", "verify-provenance", "store-root"])?;
            let scope = opts
                .get("scope")
                .ok_or_else(|| usage("kernel-read needs --scope <scope-id>"))?;
            let (summary, raw) = astrolabe_fleet::compose::read_fleet_kernel(&catalog, scope)?;
            if opts.flag("raw") {
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(&raw)
                    .map_err(|error| CalyxError {
                        code: "ASTRO_FLEET_REPORT_READ",
                        message: format!("write kernel.json bytes to stdout: {error}"),
                        remediation: "retry with a writable stdout",
                    })?;
                return Ok(());
            }
            let mut out = summary;
            if let Some(sample) = opts.get("verify-provenance") {
                let sample_n = sample.parse::<usize>().map_err(|error| {
                    usage(&format!("--verify-provenance must be a usize: {error}"))
                })?;
                let store_root = PathBuf::from(opts.get("store-root").ok_or_else(|| {
                    usage("kernel-read --verify-provenance needs --store-root <dir>")
                })?);
                let verify = astrolabe_fleet::compose::verify_member_provenance(
                    &catalog,
                    &store_root,
                    scope,
                    sample_n,
                )?;
                out["provenance"] = verify;
            }
            let command_metrics_after = current_process_metrics()?;
            let command_metrics_before = command_metrics_before
                .expect("kernel-read always captures process metrics before catalog open");
            let open = catalog.vault().open_diagnostics();
            out["performance"] = json!({
                "catalog_open_wall_us": catalog_open_wall_us,
                "catalog_open": {
                    "read_snapshot_lock_us": open.read_snapshot_lock_us,
                    "read_snapshot_lock_usage": phase_usage_json(open.read_snapshot_lock_usage),
                    "recovery_us": open.recovery_us,
                    "recovery_usage": phase_usage_json(open.recovery_usage),
                    "ledger_hook_us": open.ledger_hook_us,
                    "ledger_hook_usage": phase_usage_json(open.ledger_hook_usage),
                    "router_us": open.router_us,
                    "router_usage": phase_usage_json(open.router_usage),
                    "total_us": open.total_us,
                    "total_usage": phase_usage_json(open.total_usage),
                },
                "process_before": command_metrics_before,
                "process_after": command_metrics_after,
                "process_delta": command_metrics_after.delta(command_metrics_before),
            });
            println!("{out}");
            Ok(())
        }
        "probe-vault-keys" => {
            opts.reject_unknown(&["root", "store-root", "project"])?;
            let store_root = PathBuf::from(opts.get("store-root").ok_or_else(|| {
                usage("probe-vault-keys needs --store-root <dir> (the fleet store root)")
            })?);
            let project = opts
                .get("project")
                .ok_or_else(|| usage("probe-vault-keys needs --project <org__repo>"))?;
            let identity =
                astrolabe_fleet::orchestrator::catalog_store_identity(&catalog, project)?;
            let keys = astrolabe_fleet::orchestrator::vault_base_keys(
                &store_root,
                &identity.store_key,
                &identity.index_project,
            )?;
            for key in &keys {
                println!("{key}");
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "project": project,
                    "index_project": identity.index_project,
                    "kernel_scope": identity.kernel_scope,
                    "base_keys": keys.len(),
                })
            );
            Ok(())
        }
        "run-report-read" => {
            opts.reject_unknown(&["root", "run-id", "raw"])?;
            let run_id = opts
                .get("run-id")
                .ok_or_else(|| usage("run-report-read needs --run-id <id>"))?;
            let readback = catalog.read_run_report(run_id)?.ok_or_else(|| CalyxError {
                code: "ASTRO_FLEET_REPORT_MISSING",
                message: format!("no run report persisted for run id {run_id:?}"),
                remediation: "run ids come from the discover/pipeline run output",
            })?;
            let (bytes, ledger_seq, ledger_payload) = (
                readback.report_bytes,
                readback.ledger_seq,
                readback.ledger_payload,
            );
            if opts.flag("raw") {
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(&bytes)
                    .map_err(|error| CalyxError {
                        code: "ASTRO_FLEET_REPORT_READ",
                        message: format!("write report bytes to stdout: {error}"),
                        remediation: "retry with a writable stdout",
                    })?;
            } else {
                println!(
                    "{}",
                    serde_json::json!({
                        "run_id": run_id,
                        "blob_bytes": bytes.len(),
                        "blob_blake3": blake3::hash(&bytes).to_hex().as_str(),
                        "ledger_seq": ledger_seq,
                        "ledger_payload": serde_json::from_slice::<serde_json::Value>(&ledger_payload)
                            .unwrap_or_else(|_| serde_json::Value::String(
                                String::from_utf8_lossy(&ledger_payload).into_owned()
                            )),
                    })
                );
            }
            Ok(())
        }
        other => Err(usage(&format!("unknown verb {other:?}"))),
    }
}

fn read_verb_cfs(verb: &str) -> Option<Vec<ColumnFamily>> {
    let cfs = match verb {
        "get" | "list" | "probe-vault-keys" => vec![ColumnFamily::Base],
        "ledger-scan" => vec![ColumnFamily::Ledger],
        "report-read" | "report-list" => vec![ColumnFamily::Blob],
        "run-report-read" => vec![ColumnFamily::Blob, ColumnFamily::Ledger],
        "kernel-read" => vec![
            ColumnFamily::Base,
            ColumnFamily::Blob,
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
        ],
        _ => return None,
    };
    Some(cfs)
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ProcessMetrics {
    kernel_time_100ns: u64,
    user_time_100ns: u64,
    read_operations: u64,
    read_bytes: u64,
    write_operations: u64,
    write_bytes: u64,
    page_faults: u64,
    working_set_bytes: u64,
    peak_working_set_bytes: u64,
    pagefile_bytes: u64,
    peak_pagefile_bytes: u64,
}

impl ProcessMetrics {
    fn delta(self, before: Self) -> Self {
        Self {
            kernel_time_100ns: self
                .kernel_time_100ns
                .saturating_sub(before.kernel_time_100ns),
            user_time_100ns: self.user_time_100ns.saturating_sub(before.user_time_100ns),
            read_operations: self.read_operations.saturating_sub(before.read_operations),
            read_bytes: self.read_bytes.saturating_sub(before.read_bytes),
            write_operations: self
                .write_operations
                .saturating_sub(before.write_operations),
            write_bytes: self.write_bytes.saturating_sub(before.write_bytes),
            page_faults: self.page_faults.saturating_sub(before.page_faults),
            working_set_bytes: self
                .working_set_bytes
                .saturating_sub(before.working_set_bytes),
            peak_working_set_bytes: self
                .peak_working_set_bytes
                .saturating_sub(before.peak_working_set_bytes),
            pagefile_bytes: self.pagefile_bytes.saturating_sub(before.pagefile_bytes),
            peak_pagefile_bytes: self
                .peak_pagefile_bytes
                .saturating_sub(before.peak_pagefile_bytes),
        }
    }
}

/// Darwin per-process metrics for the kernel-read diagnostics (#895).
///
/// `proc_pid_rusage(RUSAGE_INFO_V4)` supplies byte-exact cumulative disk I/O and
/// the current/lifetime-peak memory footprint; `getrusage` supplies the I/O
/// operation counts and page faults that the Darwin rusage record omits. Every
/// value is measured — a failed query is a hard error, because these
/// diagnostics are mandatory.
#[cfg(target_os = "macos")]
fn current_process_metrics() -> Result<ProcessMetrics, CalyxError> {
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a correctly sized writable POD matching the flavor.
    let rc = unsafe {
        libc::proc_pid_rusage(
            std::process::id() as libc::c_int,
            libc::RUSAGE_INFO_V4,
            (&raw mut info).cast::<libc::rusage_info_t>(),
        )
    };
    if rc != 0 {
        return Err(process_metric_error(
            "proc_pid_rusage",
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default() as u32,
        ));
    }
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a correctly sized writable POD for RUSAGE_SELF.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) } != 0 {
        return Err(process_metric_error(
            "getrusage",
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default() as u32,
        ));
    }
    Ok(ProcessMetrics {
        // Darwin reports these totals in nanoseconds; the contract is 100ns units.
        kernel_time_100ns: info.ri_system_time / 100,
        user_time_100ns: info.ri_user_time / 100,
        read_operations: u64::try_from(usage.ru_inblock).unwrap_or(0),
        read_bytes: info.ri_diskio_bytesread,
        write_operations: u64::try_from(usage.ru_oublock).unwrap_or(0),
        write_bytes: info.ri_diskio_byteswritten,
        page_faults: u64::try_from(usage.ru_majflt).unwrap_or(0)
            + u64::try_from(usage.ru_minflt).unwrap_or(0),
        working_set_bytes: info.ri_resident_size,
        peak_working_set_bytes: info.ri_lifetime_max_phys_footprint,
        pagefile_bytes: info.ri_phys_footprint,
        // Darwin retains one lifetime peak footprint rather than separate
        // working-set and pagefile peaks.
        peak_pagefile_bytes: info.ri_lifetime_max_phys_footprint,
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn current_process_metrics() -> Result<ProcessMetrics, CalyxError> {
    Err(CalyxError {
        code: "ASTRO_FLEET_PROCESS_METRICS",
        message: "no exact per-process accounting source is implemented for this target".to_string(),
        remediation: "implement current_process_metrics for this host; kernel-read diagnostics are mandatory",
    })
}

#[cfg(windows)]
fn current_process_metrics() -> Result<ProcessMetrics, CalyxError> {
    use windows_sys::Win32::Foundation::{FILETIME, GetLastError};
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
    };

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let mut io = IO_COUNTERS::default();
    let mut memory: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the pseudo-handle is valid in this process and every output
    // pointer names a correctly sized writable Windows POD for the call.
    unsafe {
        if GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) == 0 {
            return Err(process_metric_error("GetProcessTimes", GetLastError()));
        }
        if GetProcessIoCounters(process, &mut io) == 0 {
            return Err(process_metric_error("GetProcessIoCounters", GetLastError()));
        }
        if K32GetProcessMemoryInfo(
            process,
            &raw mut memory,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) == 0
        {
            return Err(process_metric_error(
                "K32GetProcessMemoryInfo",
                GetLastError(),
            ));
        }
    }
    Ok(ProcessMetrics {
        kernel_time_100ns: filetime_u64(kernel),
        user_time_100ns: filetime_u64(user),
        read_operations: io.ReadOperationCount,
        read_bytes: io.ReadTransferCount,
        write_operations: io.WriteOperationCount,
        write_bytes: io.WriteTransferCount,
        page_faults: u64::from(memory.PageFaultCount),
        working_set_bytes: memory.WorkingSetSize as u64,
        peak_working_set_bytes: memory.PeakWorkingSetSize as u64,
        pagefile_bytes: memory.PagefileUsage as u64,
        peak_pagefile_bytes: memory.PeakPagefileUsage as u64,
    })
}

fn phase_usage_json(usage: calyx_aster::vault::VaultPhaseUsage) -> serde_json::Value {
    json!({
        "kernel_time_100ns": usage.kernel_time_100ns,
        "user_time_100ns": usage.user_time_100ns,
        "read_operations": usage.read_operations,
        "read_bytes": usage.read_bytes,
        "write_operations": usage.write_operations,
        "write_bytes": usage.write_bytes,
        "page_faults": usage.page_faults,
        "working_set_bytes_after": usage.working_set_bytes_after,
        "peak_working_set_bytes_after": usage.peak_working_set_bytes_after,
        "private_bytes_after": usage.private_bytes_after,
        "peak_private_bytes_after": usage.peak_private_bytes_after,
    })
}

#[cfg(windows)]
fn filetime_u64(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn process_metric_error(operation: &str, os_code: u32) -> CalyxError {
    CalyxError {
        code: "ASTRO_FLEET_PROCESS_METRICS",
        message: format!("{operation} failed with OS error {os_code}"),
        remediation: "inspect the native process-query failure; kernel-read diagnostics are mandatory",
    }
}

fn parse_record(line: &str) -> Result<RepoRecord, CalyxError> {
    serde_json::from_str(line).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_RECORD_PARSE",
        message: format!("repo record JSON did not parse: {error}"),
        remediation: "pass one JSON object per record with the RepoRecord fields (github_id, full_name, clone_url, default_branch, stars, language, size_kb, pushed_at, optional license_spdx/etag)",
    })
}

fn usage(what: &str) -> CalyxError {
    CalyxError {
        code: "ASTRO_FLEET_USAGE",
        message: format!("{what}; {USAGE}"),
        remediation: "invoke with a valid verb and its required flags",
    }
}

/// Minimal declarative flag parser: `--name value` pairs plus bare `--name`
/// switches (`stdin`, `counts`).
struct Options {
    pairs: Vec<(String, Option<String>)>,
}

impl Options {
    const SWITCHES: [&'static str; 13] = [
        "stdin",
        "counts",
        "refresh",
        "update",
        "all-discovered",
        "all-cloned",
        "force",
        "latest",
        "raw",
        "once",
        "discovery",
        "acquire",
        "retry-quarantined",
    ];

    fn parse(args: &[String]) -> Result<Self, CalyxError> {
        let mut pairs = Vec::new();
        let mut idx = 0;
        while idx < args.len() {
            let flag = args[idx]
                .strip_prefix("--")
                .ok_or_else(|| usage(&format!("expected --flag, got {:?}", args[idx])))?;
            if Self::SWITCHES.contains(&flag) {
                pairs.push((flag.to_string(), None));
                idx += 1;
                continue;
            }
            let value = args
                .get(idx + 1)
                .ok_or_else(|| usage(&format!("--{flag} needs a value")))?;
            pairs.push((flag.to_string(), Some(value.clone())));
            idx += 2;
        }
        Ok(Self { pairs })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(flag, _)| flag == name)
            .and_then(|(_, value)| value.as_deref())
    }

    fn flag(&self, name: &str) -> bool {
        self.pairs.iter().any(|(flag, _)| flag == name)
    }

    fn get_all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(flag, _)| flag == name)
            .filter_map(|(_, value)| value.as_deref())
            .collect()
    }

    fn require(&self, name: &str) -> Result<&str, CalyxError> {
        self.get(name)
            .ok_or_else(|| usage(&format!("--{name} is required")))
    }

    fn require_u64(&self, name: &str) -> Result<u64, CalyxError> {
        self.require(name)?
            .parse::<u64>()
            .map_err(|error| usage(&format!("--{name} must be a u64: {error}")))
    }

    fn at_or_now(&self) -> Result<u64, CalyxError> {
        match self.get("at") {
            Some(raw) => raw
                .parse::<u64>()
                .map_err(|error| usage(&format!("--at must be unix seconds: {error}"))),
            None => Ok(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after 1970")
                .as_secs()),
        }
    }

    fn reject_unknown(&self, known: &[&str]) -> Result<(), CalyxError> {
        for (flag, _) in &self.pairs {
            if !known.contains(&flag.as_str()) {
                return Err(usage(&format!("unknown flag --{flag} for this verb")));
            }
        }
        Ok(())
    }
}
