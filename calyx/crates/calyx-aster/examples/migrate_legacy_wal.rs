//! Explicit low-level operator surface for one Aster vault WAL migration.

use std::process::ExitCode;

use calyx_aster::wal::migrate_legacy_wal_tail;

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 1 {
        eprintln!(
            "{}",
            serde_json::json!({
                "code": "CALYX_ASTER_WAL_MIGRATION_USAGE",
                "message": "usage: migrate_legacy_wal <vault-directory>",
                "remediation": "pass exactly one existing Aster vault directory",
            })
        );
        return ExitCode::FAILURE;
    }
    match migrate_legacy_wal_tail(&args[0]) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_value(report).expect("migration report serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "code": error.code,
                    "message": error.message,
                    "remediation": error.remediation,
                })
            );
            ExitCode::FAILURE
        }
    }
}
