//! Manual real-history archaeology report inspector.
//!
//! This artifact runs the production Git archaeology miner and writes its full
//! equality-stable telemetry to a receipt. It is intended for manual FSV cases
//! where the expected result may be zero findings.

use std::path::PathBuf;

use astrolabe_anchors::archaeology::{GitArchaeologyConfig, GitMineMode, mine_git_archaeology};
use serde_json::json;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let repository = arguments
        .next()
        .map(PathBuf::from)
        .expect("usage: archaeology_report_fsv <repository> <receipt-path>");
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
    let receipt = json!({
        "schema": "astrolabe.archaeology-report-fsv.v1",
        "repository": repository,
        "head": report.head,
        "szz_findings": report.szz_findings.iter().map(|finding| {
            json!({
                "fix_commit": finding.fix_commit,
                "blamed_commit": finding.blamed_commit,
                "path": finding.path,
                "line": finding.line,
                "observed_at": finding.observed_at,
                "confidence_bits": finding.confidence.to_bits(),
            })
        }).collect::<Vec<_>>(),
        "revert_findings": report.revert_findings.iter().map(|finding| {
            json!({
                "revert_commit": finding.revert_commit,
                "target_commit": finding.target_commit,
                "path": finding.target_range.path,
                "start_line": finding.target_range.start_line,
                "line_count": finding.target_range.line_count,
                "observed_at": finding.observed_at,
            })
        }).collect::<Vec<_>>(),
        "skips": {
            "skipped_merge_fixes": report.skipped_merge_fixes,
            "skipped_large_commits": report.skipped_large_commits,
            "skipped_unresolvable_reverts": report.skipped_unresolvable_reverts,
            "skipped_gitlink_paths": report.skipped_gitlink_paths,
            "skipped_unblamable_paths": report.skipped_unblamable_paths,
        },
        "diff_tree": {
            "count_requested_commits": report.diff_tree.count_requested_commits,
            "count_processes": report.diff_tree.count_processes,
            "count_processes_avoided": report.diff_tree.count_processes_avoided,
            "count_stdout_bytes": report.diff_tree.count_stdout_bytes,
            "count_wall_ms": report.diff_tree.count_wall_ms,
            "ranges_requested_commits": report.diff_tree.ranges_requested_commits,
            "ranges_processes": report.diff_tree.ranges_processes,
            "ranges_processes_avoided": report.diff_tree.ranges_processes_avoided,
            "ranges_stdout_bytes": report.diff_tree.ranges_stdout_bytes,
            "ranges_wall_ms": report.diff_tree.ranges_wall_ms,
            "batch_limit_commits": report.diff_tree.batch_limit_commits,
        },
        "blame": {
            "requested_ranges": report.blame.requested_ranges,
            "effective_ranges": report.blame.effective_ranges,
            "groups": report.blame.groups,
            "group_cache_hits": report.blame.group_cache_hits,
            "processes": report.blame.processes,
            "processes_avoided": report.blame.processes_avoided,
            "cat_file_processes": report.blame.cat_file_processes,
            "cat_file_stdout_bytes": report.blame.cat_file_stdout_bytes,
            "cat_file_wall_ms": report.blame.cat_file_wall_ms,
            "path_absent_groups": report.blame.path_absent_groups,
            "returned_spans": report.blame.returned_spans,
            "returned_lines": report.blame.returned_lines,
            "stdout_bytes": report.blame.stdout_bytes,
            "wall_ms": report.blame.wall_ms,
        },
    });
    std::fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&receipt).expect("encode archaeology receipt"),
    )
    .expect("write archaeology receipt");
    println!(
        "{}",
        serde_json::to_string(&receipt).expect("print archaeology report")
    );
}
