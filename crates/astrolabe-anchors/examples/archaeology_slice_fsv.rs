//! Manual real-history archaeology slice inspector.
//!
//! This artifact runs the production Git archaeology miner, filters its exact
//! findings by blamed commit, and emits a compact JSON receipt. It is intended
//! for reducing a real historical-indexing fault without substituting fixture
//! or synthetic history.

use std::collections::BTreeSet;
use std::path::PathBuf;

use astrolabe_anchors::archaeology::{GitArchaeologyConfig, GitMineMode, mine_git_archaeology};
use serde_json::json;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let repository = arguments
        .next()
        .map(PathBuf::from)
        .expect("usage: archaeology_slice_fsv <repository> <blamed-commit> <receipt-path>");
    let blamed_commit = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .expect("blamed commit must be valid UTF-8");
    let receipt_path = arguments
        .next()
        .map(PathBuf::from)
        .expect("receipt path is required");
    assert!(arguments.next().is_none(), "unexpected trailing argument");

    let report = mine_git_archaeology(
        &repository,
        &GitArchaeologyConfig::default(),
        &GitMineMode::Full,
    )
    .expect("mine real Git archaeology");
    let findings = report
        .szz_findings
        .iter()
        .filter(|finding| finding.blamed_commit == blamed_commit)
        .map(|finding| {
            json!({
                "fix_commit": finding.fix_commit,
                "blamed_commit": finding.blamed_commit,
                "path": finding.path,
                "line": finding.line,
                "observed_at": finding.observed_at,
                "confidence_bits": finding.confidence.to_bits(),
            })
        })
        .collect::<Vec<_>>();
    let paths = findings
        .iter()
        .filter_map(|finding| finding["path"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let fix_commits = findings
        .iter()
        .filter_map(|finding| finding["fix_commit"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert!(
        !findings.is_empty(),
        "the production archaeology report contains no finding for {blamed_commit}"
    );
    let receipt = json!({
        "schema": "astrolabe.archaeology-slice-fsv.v1",
        "repository": repository,
        "head": report.head,
        "history_state": report.history,
        "history_present": report.history.commit_oid().is_some(),
        "symbolic_head": report.history.symbolic_ref(),
        "blamed_commit": blamed_commit,
        "matching_findings": findings.len(),
        "paths": paths,
        "fix_commits": fix_commits,
        "findings": findings,
        "full_report": {
            "szz_findings": report.szz_findings.len(),
            "revert_findings": report.revert_findings.len(),
            "skipped_merge_fixes": report.skipped_merge_fixes,
            "skipped_large_commits": report.skipped_large_commits,
            "skipped_unresolvable_reverts": report.skipped_unresolvable_reverts,
            "skipped_gitlink_paths": report.skipped_gitlink_paths,
            "skipped_unblamable_paths": report.skipped_unblamable_paths,
            "blame_requested_ranges": report.blame.requested_ranges,
            "blame_effective_ranges": report.blame.effective_ranges,
            "blame_groups": report.blame.groups,
            "blame_group_cache_hits": report.blame.group_cache_hits,
            "blame_processes": report.blame.processes,
            "blame_processes_avoided": report.blame.processes_avoided,
            "blame_cat_file_processes": report.blame.cat_file_processes,
            "blame_cat_file_stdout_bytes": report.blame.cat_file_stdout_bytes,
            "blame_cat_file_wall_ms": report.blame.cat_file_wall_ms,
            "blame_path_absent_groups": report.blame.path_absent_groups,
            "blame_returned_spans": report.blame.returned_spans,
            "blame_returned_lines": report.blame.returned_lines,
            "blame_stdout_bytes": report.blame.stdout_bytes,
            "blame_wall_ms": report.blame.wall_ms,
        },
    });
    std::fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&receipt).expect("encode archaeology receipt"),
    )
    .expect("write archaeology receipt");
    println!(
        "{}",
        serde_json::to_string(&receipt).expect("encode archaeology slice")
    );
}
