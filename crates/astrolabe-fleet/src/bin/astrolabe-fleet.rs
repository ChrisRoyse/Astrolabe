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
//!                              [--index-watermark <w>] [--kernel-scope-id <k>] [--reason <r>]
//! astrolabe-fleet get          [--root <dir>] (--github-id <id> --repo <owner/name> | --cx <hex>)
//! astrolabe-fleet list         [--root <dir>] [--state <state>] [--language <lang>] [--counts]
//! astrolabe-fleet discover     [--root <dir>] [--language <csv>] [--star-floor <n>]
//!                              [--refresh] [--at <unix-secs>]
//! astrolabe-fleet clone        [--root <dir>] [--farm-root <dir>] [--update]
//!                              (--repo <owner/name> ... | --all-discovered) [--limit <n>]
//!                              [--size-cap-bytes <n>] [--budget-bytes <n>]
//!                              [--parallelism <n>] [--timeout-secs <n>] [--at <unix-secs>]
//! astrolabe-fleet pipeline     [--root <dir>] [--store-root <dir>] [--astrolabe-bin <exe>]
//!                              [--nomic-dir <dir>] (--repo <owner/name> ... | --all-cloned)
//!                              [--limit <n>] [--parallelism <n>] [--timeout-secs <n>]
//!                              [--force] [--at <unix-secs>]
//! ```
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
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_fleet::catalog::FleetCatalog;
use astrolabe_fleet::record::{RepoRecord, TransitionContext};
use astrolabe_fleet::state::RepoState;
use calyx_core::{CalyxError, CxId};
use serde_json::json;

const USAGE: &str = "usage: astrolabe-fleet <catalog-init|register|set-state|get|list|discover|clone|pipeline|report|report-read|report-list|run-report-read|probe-vault-keys> [--root <dir>] [verb options]; see crate docs";

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
    let catalog = FleetCatalog::open(&root)?;
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
                "kernel-scope-id",
                "reason",
                "clone-bytes",
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
                "astrolabe-bin",
                "nomic-dir",
                "repo",
                "all-cloned",
                "limit",
                "parallelism",
                "timeout-secs",
                "force",
                "store-budget-bytes",
                "at",
            ])?;
            let mut config =
                astrolabe_fleet::orchestrator::PipelineConfig::with_default_bin(opts.at_or_now()?);
            if let Some(store_root) = opts.get("store-root") {
                config.store_root = PathBuf::from(store_root);
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
        "probe-vault-keys" => {
            opts.reject_unknown(&["root", "store-root", "project"])?;
            let store_root = PathBuf::from(opts.get("store-root").ok_or_else(|| {
                usage("probe-vault-keys needs --store-root <dir> (the fleet store root)")
            })?);
            let project = opts
                .get("project")
                .ok_or_else(|| usage("probe-vault-keys needs --project <org__repo>"))?;
            let keys =
                astrolabe_fleet::orchestrator::vault_base_keys(&store_root, project)?;
            for key in &keys {
                println!("{key}");
            }
            eprintln!(
                "{}",
                serde_json::json!({ "project": project, "base_keys": keys.len() })
            );
            Ok(())
        }
        "run-report-read" => {
            opts.reject_unknown(&["root", "run-id", "raw"])?;
            let run_id = opts
                .get("run-id")
                .ok_or_else(|| usage("run-report-read needs --run-id <id>"))?;
            let readback = catalog
                .read_run_report(run_id)?
                .ok_or_else(|| CalyxError {
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
    const SWITCHES: [&'static str; 9] = [
        "stdin",
        "counts",
        "refresh",
        "update",
        "all-discovered",
        "all-cloned",
        "force",
        "latest",
        "raw",
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
