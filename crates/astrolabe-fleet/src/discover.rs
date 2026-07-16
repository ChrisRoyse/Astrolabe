//! GitHub discovery — star-bucket bisection enumeration (issue #450).
//!
//! Enumerates every GitHub repository above the star floor per language,
//! despite the Search API's 1,000-results-per-query cap, and registers each
//! into the [`FleetCatalog`] at `discovered`.
//!
//! # Client
//!
//! GitHub is reached through an authenticated `gh api` subprocess. `gh` is the
//! operator-authenticated GitHub client already pinned on this host; embedding
//! an HTTP client (octocrab) would add a token-management and TLS surface for
//! zero gain on a single-host fleet. `gh` is invoked with explicit arguments
//! (no shell string interpolation); a nonzero exit or unparseable stdout is a
//! structured error after bounded retries.
//!
//! # Bisection
//!
//! For each language, the query `language:<lang> stars:>=<floor>` is probed
//! for its `total_count`. Any bucket over [`SEARCH_RESULT_CAP`] is split —
//! an open bucket `>=lo` at `lo * 2`, a closed bucket at its midpoint — until
//! every leaf is `<= SEARCH_RESULT_CAP`, then paginated at
//! [`SEARCH_PAGE_SIZE`] with `sort=stars order=asc` (low → high: repos gain
//! stars more often than they lose them, so scraping upward cannot skip a
//! repo that crosses a boundary mid-run; the global github_id dedup absorbs
//! double-sightings). If a single star value ever exceeds the cap the bucket
//! is re-split by `created:` date ranges down to single days; a single
//! star+day bucket over the cap fails closed as
//! [`ASTRO_FLEET_DISCOVERY_INCOMPLETE`] naming the range.
//!
//! # Completeness
//!
//! The run report records the full bucket tree (every probe and split), the
//! instant top-level `total_count`, the sum of leaf counts, and the unique
//! `github_id` count. Leaf sums can drift from the instant total while the
//! enumeration runs (stars move); both numbers are recorded, and the unique
//! id count is the completeness figure. A bucket that cannot complete marks
//! the run incomplete and the error names the range — never a silent partial
//! enumeration.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use calyx_core::CalyxError;
use serde::Serialize;
use serde_json::{Value, json};

use crate::catalog::{FleetCatalog, RegisterOutcome};
use crate::record::{RepoRecord, TransitionContext};
use crate::state::RepoState;

/// Refusal code when an enumeration cannot be completed (a bucket failed after
/// bounded retries, or items could not be converted to catalog records).
pub const ASTRO_FLEET_DISCOVERY_INCOMPLETE: &str = "ASTRO_FLEET_DISCOVERY_INCOMPLETE";
/// Refusal code for a `gh api` invocation that failed after bounded retries.
pub const ASTRO_FLEET_GH_API: &str = "ASTRO_FLEET_GH_API";

/// Declared star floor knob (invariant 4): repos at or above this star count
/// are fleet candidates.
pub const DEFAULT_STAR_FLOOR: u64 = 2000;
/// Declared language rollout knob: Rust first (EPIC #461).
pub const DEFAULT_LANGUAGES: &[&str] = &["rust"];
/// Declared default root of the production fleet catalog vault.
pub const DEFAULT_CATALOG_ROOT: &str = r"D:\astrolabe-fleet\catalog";
/// GitHub Search API hard cap on retrievable results per query.
pub const SEARCH_RESULT_CAP: u64 = 1000;
/// Search page size (GitHub maximum).
pub const SEARCH_PAGE_SIZE: u64 = 100;
/// Bounded attempts per API request before failing closed.
pub const MAX_REQUEST_ATTEMPTS: u32 = 5;
/// Cap on a single rate-limit wait; the search window resets every 60s.
pub const MAX_RATE_WAIT_SECS: u64 = 120;
/// Defensive bound on bisection depth.
pub const MAX_BISECT_DEPTH: u32 = 64;
/// Earliest `created:` date used by the date-bisection fallback.
pub const CREATED_EPOCH: &str = "2007-01-01";

/// One node of the star-range bisection tree, recorded in the run report.
#[derive(Clone, Debug, Serialize)]
pub struct BucketNode {
    /// Star range, e.g. `2000..2999` or `>=15000` (optionally `created:` scoped).
    pub range: String,
    /// `total_count` GitHub reported for this bucket at probe time.
    pub total_count: u64,
    /// `leaf`, `split`, `split_created`, or `zero`.
    pub action: &'static str,
    /// Pages fetched (leaves only).
    pub pages: u64,
    /// Items fetched (leaves only).
    pub items: u64,
    /// Child buckets (splits only).
    pub children: Vec<BucketNode>,
}

/// Outcome counters of registering one language's enumeration into the catalog.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct RegisterCounts {
    /// Brand-new records persisted at `discovered`.
    pub registered: u64,
    /// Existing records whose discovery facts were updated.
    pub refreshed: u64,
    /// Existing records with identical facts; no write.
    pub unchanged: u64,
}

/// Per-language enumeration result recorded in the run report.
#[derive(Clone, Debug, Serialize)]
pub struct LanguageReport {
    /// The queried language.
    pub language: String,
    /// Instant top-level `total_count` for `language:<lang> stars:>=<floor>`.
    pub top_level_total: u64,
    /// Sum of leaf `total_count`s (may drift from `top_level_total`; recorded).
    pub leaf_sum: u64,
    /// Unique `github_id`s fetched — the completeness figure.
    pub unique_count: u64,
    /// Registration outcome counters.
    pub counts: RegisterCounts,
    /// Repos transitioned to `departed` on refresh.
    pub departed: u64,
    /// Departed repos that reappeared and returned to `discovered`.
    pub reappeared: u64,
    /// Items that could not be converted to catalog records (fail-closed:
    /// any entry here makes the run incomplete).
    pub invalid_items: Vec<String>,
    /// The bisection tree.
    pub buckets: BucketNode,
}

/// The authenticated `gh api` client with bounded retries and rate-limit
/// awareness. Public so edge probes can point [`GH_BIN`] overrides at it.
pub struct GhClient {
    /// Executable to invoke; the declared default is `gh` on `PATH`. The
    /// `ASTRO_FLEET_GH_BIN` environment override exists so failure-path
    /// probes can interpose a wrapper without touching the happy path.
    pub gh_bin: String,
    /// Requests issued (recorded in the run report).
    pub requests: u64,
    /// Rate-limit waits taken (recorded in the run report).
    pub rate_waits: u64,
}

/// Environment override for the `gh` executable (failure-path probes only).
pub const GH_BIN_ENV: &str = "ASTRO_FLEET_GH_BIN";

impl Default for GhClient {
    fn default() -> Self {
        Self {
            gh_bin: std::env::var(GH_BIN_ENV).unwrap_or_else(|_| "gh".to_string()),
            requests: 0,
            rate_waits: 0,
        }
    }
}

impl GhClient {
    /// Runs `gh api <args>` once, returning (exit_ok, stdout, stderr).
    fn invoke(&mut self, args: &[String]) -> Result<(bool, String, String), CalyxError> {
        self.requests += 1;
        let output = Command::new(&self.gh_bin)
            .arg("api")
            .args(args)
            .output()
            .map_err(|error| CalyxError {
                code: ASTRO_FLEET_GH_API,
                message: format!("failed to spawn {}: {error}", self.gh_bin),
                remediation: "install the GitHub CLI and authenticate it (gh auth login); it is the declared GitHub client for fleet discovery",
            })?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }

    /// GETs a GitHub API `path` with raw query `fields`, retrying through
    /// rate limits (sleeping until the reported reset) and transient failures
    /// up to [`MAX_REQUEST_ATTEMPTS`], then failing closed.
    pub fn get_json(&mut self, path: &str, fields: &[(&str, &str)]) -> Result<Value, CalyxError> {
        let mut args: Vec<String> = vec!["-X".into(), "GET".into(), path.into()];
        for (key, value) in fields {
            args.push("-f".into());
            args.push(format!("{key}={value}"));
        }
        let mut last_error = String::new();
        for attempt in 1..=MAX_REQUEST_ATTEMPTS {
            let (ok, stdout, stderr) = self.invoke(&args)?;
            if ok {
                return serde_json::from_str(&stdout).map_err(|error| CalyxError {
                    code: ASTRO_FLEET_GH_API,
                    message: format!(
                        "gh api {path} returned unparseable JSON: {error}; first bytes: {:?}",
                        &stdout[..stdout.len().min(200)]
                    ),
                    remediation: "the GitHub API response shape changed or gh emitted non-JSON; inspect the raw output",
                });
            }
            last_error = format!(
                "stderr: {stderr}; stdout: {}",
                &stdout[..stdout.len().min(400)]
            );
            let lower = format!("{stderr}\n{stdout}").to_ascii_lowercase();
            if lower.contains("rate limit")
                || lower.contains("http 403")
                || lower.contains("http 429")
            {
                self.wait_for_rate_reset()?;
            } else {
                // Transient network/API flake: bounded exponential backoff.
                sleep(Duration::from_secs(1 << attempt.min(4)));
            }
        }
        Err(CalyxError {
            code: ASTRO_FLEET_GH_API,
            message: format!(
                "gh api {path} failed after {MAX_REQUEST_ATTEMPTS} attempts; last: {last_error}"
            ),
            remediation: "check gh auth status and network reachability, then re-run discovery; completed buckets are idempotent",
        })
    }

    /// Sleeps until the search rate window resets (capped, counted).
    fn wait_for_rate_reset(&mut self) -> Result<(), CalyxError> {
        self.rate_waits += 1;
        let args: Vec<String> = vec!["rate_limit".into()];
        let wait_secs = match self.invoke(&args) {
            Ok((true, stdout, _)) => serde_json::from_str::<Value>(&stdout)
                .ok()
                .and_then(|v| v["resources"]["search"]["reset"].as_u64())
                .map(|reset| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("system clock after 1970")
                        .as_secs();
                    reset.saturating_sub(now) + 2
                })
                .unwrap_or(30),
            _ => 30,
        };
        sleep(Duration::from_secs(wait_secs.clamp(1, MAX_RATE_WAIT_SECS)));
        Ok(())
    }
}

/// Probes the `total_count` of a search query without fetching items.
fn probe_count(gh: &mut GhClient, query: &str) -> Result<u64, CalyxError> {
    let value = gh.get_json(
        "search/repositories",
        &[("q", query), ("per_page", "1"), ("page", "1")],
    )?;
    value["total_count"].as_u64().ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_GH_API,
        message: format!("search response for {query:?} lacks a numeric total_count"),
        remediation: "the GitHub search API response shape changed; inspect the raw response",
    })
}

/// Fetches every page of a leaf bucket (`count <= SEARCH_RESULT_CAP`),
/// appending raw items to `items`. Returns pages fetched.
fn fetch_leaf(
    gh: &mut GhClient,
    query: &str,
    count: u64,
    items: &mut Vec<Value>,
) -> Result<u64, CalyxError> {
    let pages = count.div_ceil(SEARCH_PAGE_SIZE);
    let per_page = SEARCH_PAGE_SIZE.to_string();
    for page in 1..=pages {
        let page_str = page.to_string();
        let value = gh.get_json(
            "search/repositories",
            &[
                ("q", query),
                ("per_page", per_page.as_str()),
                ("page", page_str.as_str()),
                ("sort", "stars"),
                ("order", "asc"),
            ],
        )?;
        let batch = value["items"].as_array().ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_GH_API,
            message: format!("search response for {query:?} page {page} lacks items[]"),
            remediation: "the GitHub search API response shape changed; inspect the raw response",
        })?;
        items.extend(batch.iter().cloned());
        if batch.len() < SEARCH_PAGE_SIZE as usize {
            return Ok(page);
        }
    }
    Ok(pages)
}

/// Star range of one bucket: closed `lo..hi` or open `>=lo`.
#[derive(Clone, Copy)]
struct StarRange {
    lo: u64,
    hi: Option<u64>,
}

impl StarRange {
    fn label(self) -> String {
        match self.hi {
            Some(hi) => format!("{}..{hi}", self.lo),
            None => format!(">={}", self.lo),
        }
    }

    fn query(self, language: &str) -> String {
        match self.hi {
            Some(hi) => format!("language:{language} stars:{}..{hi}", self.lo),
            None => format!("language:{language} stars:>={}", self.lo),
        }
    }
}

/// Recursively enumerates one star bucket, splitting until every leaf fits
/// under the cap, appending raw items and recording the tree.
fn enumerate_bucket(
    gh: &mut GhClient,
    language: &str,
    range: StarRange,
    depth: u32,
    items: &mut Vec<Value>,
) -> Result<BucketNode, CalyxError> {
    if depth > MAX_BISECT_DEPTH {
        return Err(incomplete(format!(
            "star bucket {} for language:{language} exceeded bisection depth {MAX_BISECT_DEPTH}",
            range.label()
        )));
    }
    let query = range.query(language);
    let count = probe_count(gh, &query)?;
    if count == 0 {
        return Ok(BucketNode {
            range: range.label(),
            total_count: 0,
            action: "zero",
            pages: 0,
            items: 0,
            children: Vec::new(),
        });
    }
    if count <= SEARCH_RESULT_CAP {
        let before = items.len();
        let pages = fetch_leaf(gh, &query, count, items)?;
        return Ok(BucketNode {
            range: range.label(),
            total_count: count,
            action: "leaf",
            pages,
            items: (items.len() - before) as u64,
            children: Vec::new(),
        });
    }
    // Over the cap: split.
    let children_ranges: Option<(StarRange, StarRange)> = match range.hi {
        None => {
            let mid = range.lo.saturating_mul(2).max(range.lo + 1);
            Some((
                StarRange {
                    lo: range.lo,
                    hi: Some(mid - 1),
                },
                StarRange { lo: mid, hi: None },
            ))
        }
        Some(hi) if hi > range.lo => {
            let mid = range.lo + (hi - range.lo) / 2;
            Some((
                StarRange {
                    lo: range.lo,
                    hi: Some(mid),
                },
                StarRange {
                    lo: mid + 1,
                    hi: Some(hi),
                },
            ))
        }
        Some(_) => None, // single star value over the cap: date fallback
    };
    if let Some((left, right)) = children_ranges {
        let children = vec![
            enumerate_bucket(gh, language, left, depth + 1, items)?,
            enumerate_bucket(gh, language, right, depth + 1, items)?,
        ];
        return Ok(BucketNode {
            range: range.label(),
            total_count: count,
            action: "split",
            pages: 0,
            items: 0,
            children,
        });
    }
    let today = civil_today();
    let children = enumerate_created(
        gh,
        language,
        range,
        (CREATED_EPOCH.to_string(), today),
        depth + 1,
        items,
    )?;
    Ok(BucketNode {
        range: range.label(),
        total_count: count,
        action: "split_created",
        pages: 0,
        items: 0,
        children,
    })
}

/// Date-bisection fallback for a single star value over the cap: splits the
/// `created:` range in half (by days) until each slice fits, failing closed
/// on a single-day slice over the cap.
fn enumerate_created(
    gh: &mut GhClient,
    language: &str,
    stars: StarRange,
    dates: (String, String),
    depth: u32,
    items: &mut Vec<Value>,
) -> Result<Vec<BucketNode>, CalyxError> {
    if depth > MAX_BISECT_DEPTH {
        return Err(incomplete(format!(
            "created-range bisection for stars:{} language:{language} exceeded depth {MAX_BISECT_DEPTH}",
            stars.label()
        )));
    }
    let (lo, hi) = &dates;
    let label = format!("{} created:{lo}..{hi}", stars.label());
    let query = format!("{} created:{lo}..{hi}", stars.query(language));
    let count = probe_count(gh, &query)?;
    if count == 0 {
        return Ok(vec![BucketNode {
            range: label,
            total_count: 0,
            action: "zero",
            pages: 0,
            items: 0,
            children: Vec::new(),
        }]);
    }
    if count <= SEARCH_RESULT_CAP {
        let before = items.len();
        let pages = fetch_leaf(gh, &query, count, items)?;
        return Ok(vec![BucketNode {
            range: label,
            total_count: count,
            action: "leaf",
            pages,
            items: (items.len() - before) as u64,
            children: Vec::new(),
        }]);
    }
    let lo_days = days_from_civil_str(lo)?;
    let hi_days = days_from_civil_str(hi)?;
    if lo_days >= hi_days {
        return Err(incomplete(format!(
            "single-day bucket {label} still exceeds the {SEARCH_RESULT_CAP}-result cap"
        )));
    }
    let mid_days = lo_days + (hi_days - lo_days) / 2;
    let mut nodes = enumerate_created(
        gh,
        language,
        stars,
        (lo.clone(), civil_from_days(mid_days)),
        depth + 1,
        items,
    )?;
    nodes.extend(enumerate_created(
        gh,
        language,
        stars,
        (civil_from_days(mid_days + 1), hi.clone()),
        depth + 1,
        items,
    )?);
    Ok(nodes)
}

/// Converts a raw search item into a catalog record, or explains why not.
fn to_record(item: &Value, queried_language: &str) -> Result<RepoRecord, String> {
    let str_field = |key: &str| -> Result<String, String> {
        item[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("item lacks string field {key:?}: {}", item[key]))
    };
    let github_id = item["id"]
        .as_u64()
        .ok_or_else(|| format!("item lacks numeric id: {}", item["id"]))?;
    Ok(RepoRecord {
        github_id,
        full_name: str_field("full_name")?,
        clone_url: str_field("clone_url")?,
        default_branch: str_field("default_branch")?,
        stars: item["stargazers_count"]
            .as_u64()
            .ok_or_else(|| "item lacks numeric stargazers_count".to_string())?,
        language: item["language"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| queried_language.to_string()),
        license_spdx: item["license"]["spdx_id"].as_str().map(str::to_string),
        size_kb: item["size"].as_u64().unwrap_or(0),
        pushed_at: str_field("pushed_at")?,
        etag: None,
    })
}

/// Full discovery run: enumerate each language, register everything, apply
/// refresh semantics, persist the run report (file + vault row + ledger), and
/// fail closed if any part was incomplete.
///
/// Returns the run report value (also persisted) on success.
pub fn run_discovery(
    catalog: &FleetCatalog,
    root: &Path,
    languages: &[String],
    star_floor: u64,
    refresh: bool,
    at_unix_secs: u64,
) -> Result<Value, CalyxError> {
    let started = now_secs();
    let mut gh = GhClient::default();
    let mut language_reports: Vec<LanguageReport> = Vec::new();
    let mut incomplete_ranges: Vec<String> = Vec::new();

    for language in languages {
        let top_query = format!("language:{language} stars:>={star_floor}");
        let top_level_total = probe_count(&mut gh, &top_query)?;
        let mut raw_items: Vec<Value> = Vec::new();
        let bucket_result = enumerate_bucket(
            &mut gh,
            language,
            StarRange {
                lo: star_floor,
                hi: None,
            },
            0,
            &mut raw_items,
        );
        let buckets = match bucket_result {
            Ok(node) => node,
            Err(error) if error.code == ASTRO_FLEET_DISCOVERY_INCOMPLETE => {
                incomplete_ranges.push(error.message.clone());
                BucketNode {
                    range: format!(">={star_floor}"),
                    total_count: top_level_total,
                    action: "split",
                    pages: 0,
                    items: 0,
                    children: Vec::new(),
                }
            }
            Err(error) => return Err(error),
        };
        let leaf_sum = sum_leaves(&buckets);

        // Global dedup by github_id.
        let mut unique: BTreeMap<u64, Value> = BTreeMap::new();
        for item in raw_items {
            if let Some(id) = item["id"].as_u64() {
                unique.insert(id, item);
            }
        }
        let unique_count = unique.len() as u64;

        let mut counts = RegisterCounts::default();
        let mut invalid_items = Vec::new();
        let mut seen_ids: Vec<u64> = Vec::with_capacity(unique.len());
        for (id, item) in &unique {
            match to_record(item, language) {
                Ok(record) => {
                    seen_ids.push(*id);
                    let report = catalog.register(record, at_unix_secs)?;
                    match report.outcome {
                        RegisterOutcome::Registered => counts.registered += 1,
                        RegisterOutcome::Refreshed => counts.refreshed += 1,
                        RegisterOutcome::Unchanged => counts.unchanged += 1,
                    }
                }
                Err(why) => invalid_items.push(format!("github_id={id}: {why}")),
            }
        }
        if !invalid_items.is_empty() {
            incomplete_ranges.extend(invalid_items.iter().cloned());
        }

        // Refresh semantics: only against a COMPLETE enumeration of this
        // language (anything incomplete must never mark repos departed).
        let mut departed = 0_u64;
        let mut reappeared = 0_u64;
        if refresh && incomplete_ranges.is_empty() {
            let seen: std::collections::BTreeSet<u64> = seen_ids.iter().copied().collect();
            for row in catalog.query(None, Some(language))? {
                let in_enumeration = seen.contains(&row.record.github_id);
                if !in_enumeration
                    && row.state != RepoState::Departed
                    && row.state != RepoState::Quarantined
                {
                    catalog.transition(
                        row.record.github_id,
                        &row.record.full_name,
                        RepoState::Departed,
                        TransitionContext {
                            at_unix_secs,
                            departed_reason: Some(format!(
                                "absent from complete enumeration language:{language} stars:>={star_floor} at {at_unix_secs}"
                            )),
                            ..TransitionContext::default()
                        },
                    )?;
                    departed += 1;
                }
                if in_enumeration && row.state == RepoState::Departed {
                    catalog.transition(
                        row.record.github_id,
                        &row.record.full_name,
                        RepoState::Discovered,
                        TransitionContext {
                            at_unix_secs,
                            ..TransitionContext::default()
                        },
                    )?;
                    reappeared += 1;
                }
            }
        }

        language_reports.push(LanguageReport {
            language: language.clone(),
            top_level_total,
            leaf_sum,
            unique_count,
            counts,
            departed,
            reappeared,
            invalid_items,
            buckets,
        });
    }

    let finished = now_secs();
    let run_id = format!("{started}-{}", std::process::id());
    let report = json!({
        "run_id": run_id,
        "kind": if refresh { "refresh" } else { "enumerate" },
        "star_floor": star_floor,
        "languages": language_reports,
        "requests": gh.requests,
        "rate_waits": gh.rate_waits,
        "started_unix_secs": started,
        "finished_unix_secs": finished,
        "incomplete_ranges": incomplete_ranges,
    });

    // Persist: file under <root>/runs/ + vault row + ledger entry.
    let runs_dir = root.join("runs");
    std::fs::create_dir_all(&runs_dir).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_ROOT_UNAVAILABLE",
        message: format!(
            "cannot create run-report dir {}: {error}",
            runs_dir.display()
        ),
        remediation: "the catalog root must be writable for run reports",
    })?;
    let report_path = runs_dir.join(format!("discovery-{run_id}.json"));
    let report_bytes = serde_json::to_vec_pretty(&report).expect("run report serializes");
    std::fs::write(&report_path, &report_bytes).map_err(|error| CalyxError {
        code: "ASTRO_FLEET_ROOT_UNAVAILABLE",
        message: format!("cannot write run report {}: {error}", report_path.display()),
        remediation: "the catalog root must be writable for run reports",
    })?;
    let summary = serde_json::to_vec(&json!({
        "event": "fleet_discovery_run",
        "run_id": run_id,
        "kind": if refresh { "refresh" } else { "enumerate" },
        "star_floor": star_floor,
        "languages": languages,
        "per_language": language_reports.iter().map(|lr| json!({
            "language": lr.language,
            "top_level_total": lr.top_level_total,
            "leaf_sum": lr.leaf_sum,
            "unique_count": lr.unique_count,
            "registered": lr.counts.registered,
            "refreshed": lr.counts.refreshed,
            "unchanged": lr.counts.unchanged,
            "departed": lr.departed,
            "reappeared": lr.reappeared,
        })).collect::<Vec<_>>(),
        "incomplete_ranges": incomplete_ranges,
        "report_file": report_path.display().to_string(),
    }))
    .expect("run summary serializes");
    let (commit_seq, ledger_seq) = catalog.record_run_report(&run_id, report_bytes, summary)?;

    if !incomplete_ranges.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_DISCOVERY_INCOMPLETE,
            message: format!(
                "discovery run {run_id} is INCOMPLETE; unfinished: {}",
                incomplete_ranges.join(" | ")
            ),
            remediation: "re-run discovery once the named ranges are reachable; completed registrations are idempotent",
        });
    }

    let mut out = report;
    out["commit_seq"] = json!(commit_seq);
    out["ledger_seq"] = json!(ledger_seq);
    out["report_file"] = json!(report_path.display().to_string());
    Ok(out)
}

fn sum_leaves(node: &BucketNode) -> u64 {
    if node.children.is_empty() {
        if node.action == "leaf" {
            node.total_count
        } else {
            0
        }
    } else {
        node.children.iter().map(sum_leaves).sum()
    }
}

fn incomplete(message: String) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_DISCOVERY_INCOMPLETE,
        message,
        remediation: "narrow the enumeration (higher star floor) or re-run when the API permits; never treat a partial enumeration as complete",
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after 1970")
        .as_secs()
}

// Civil-date helpers for the created-range fallback (Howard Hinnant's
// days_from_civil / civil_from_days), avoiding a chrono dependency.

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + i64::from(doy);
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> String {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn days_from_civil_str(date: &str) -> Result<i64, CalyxError> {
    let mut parts = date.splitn(3, '-');
    let parse = |part: Option<&str>| -> Option<i64> { part?.parse::<i64>().ok() };
    match (
        parse(parts.next()),
        parse(parts.next()),
        parse(parts.next()),
    ) {
        (Some(y), Some(m), Some(d)) if (1..=12).contains(&m) && (1..=31).contains(&d) => {
            Ok(days_from_civil(y, m as u32, d as u32))
        }
        _ => Err(CalyxError {
            code: ASTRO_FLEET_GH_API,
            message: format!("date {date:?} is not YYYY-MM-DD"),
            remediation: "internal defect: created-range dates are generated, not user input",
        }),
    }
}

fn civil_today() -> String {
    let days = (now_secs() / 86_400) as i64;
    civil_from_days(days)
}
