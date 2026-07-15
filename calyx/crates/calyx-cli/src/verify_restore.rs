//! `calyx verify-restore --vault <path> [--json]` (PH67 T03).
//!
//! Owns its exit codes ahead of the generic CLI matcher, per the DR-drill
//! contract: 0 = chain intact AND constellations/anchors/WAL bytes present;
//! 1 = any verification or usage failure, with the exact `CALYX_*` code on
//! stderr (never a silent pass).

use std::path::PathBuf;
use std::process::ExitCode;

use calyxd::verify::{VerifyRestoreReport, verify_restore};

const USAGE: &str = "usage: calyx verify-restore --vault <path> [--json]";

/// Intercepts the `verify-restore` subcommand; returns `None` for all others.
pub fn try_run(args: &[String]) -> Option<ExitCode> {
    let (first, rest) = args.split_first()?;
    (first == "verify-restore").then(|| run(rest))
}

fn run(rest: &[String]) -> ExitCode {
    let (vault, json) = match parse(rest) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(1);
        }
    };
    let report = match verify_restore(&vault) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("error: cannot serialize verify-restore report: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_text(&report);
    }
    if report.success() {
        ExitCode::SUCCESS
    } else {
        for reason in report.failure_reasons() {
            eprintln!("error: {reason}");
        }
        ExitCode::from(1)
    }
}

fn parse(rest: &[String]) -> Result<(PathBuf, bool), String> {
    match rest {
        [vault_flag, vault] if vault_flag == "--vault" => Ok((PathBuf::from(vault), false)),
        [vault_flag, vault, json_flag] if vault_flag == "--vault" && json_flag == "--json" => {
            Ok((PathBuf::from(vault), true))
        }
        _ => Err(USAGE.to_string()),
    }
}

fn print_text(report: &VerifyRestoreReport) {
    println!("VERIFY_RESTORE vault={}", report.vault_path.display());
    println!(
        "constellations={} anchors={} ledger_entries={} wal_bytes={}",
        report.constellation_count,
        report.anchor_count,
        report.ledger_entry_count,
        report.wal_bytes_present
    );
    println!(
        "chain={} tip={}",
        if report.chain_intact {
            "INTACT"
        } else {
            "BROKEN"
        },
        report.ledger_tip_hash
    );
    println!(
        "first_cx_id={}",
        report.first_cx_id.as_deref().unwrap_or("<none>")
    );
    println!("RESULT {}", if report.success() { "OK" } else { "FAIL" });
}

