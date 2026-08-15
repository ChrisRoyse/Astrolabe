//! Manual Full State Verification for #1127's empty signal-card transaction.
//!
//! The executable creates a real durable Aster vault, drives the production
//! CardLedger/SQLite transaction with an empty request set, independently reads
//! the prepared marker while its ledger lock remains live, and exposes a
//! separate committed-state inspection operation for post-relocation readback.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{VaultId, VaultStore};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROJECT: &str = "issue-1127-empty-transaction";
const PRODUCED_AT: u64 = 1_787_000_127;

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn file_state(path: &Path) -> AnyResult<Value> {
    match fs::read(path) {
        Ok(bytes) => Ok(json!({
            "exists": true,
            "bytes": bytes.len(),
            "sha256": sha256_hex(&bytes),
            "blake3": blake3::hash(&bytes).to_hex().to_string(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "exists": false,
            "bytes": 0,
            "sha256": null,
            "blake3": null,
        })),
        Err(error) => Err(error.into()),
    }
}

fn paths(cache_dir: &Path) -> (PathBuf, PathBuf) {
    (
        cache_dir.join("_config.db"),
        cache_dir
            .join(format!("{PROJECT}.astrolabe-vault"))
            .join("signal-cards.ndjson"),
    )
}

fn print_state(case: &str, phase: &str, cache_dir: &Path) -> AnyResult<()> {
    let (config, ledger) = paths(cache_dir);
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": phase,
            "cache_dir": cache_dir,
            "config": file_state(&config)?,
            "ledger": file_state(&ledger)?,
        }))?
    );
    Ok(())
}

fn read_only_config_rows(path: &Path) -> AnyResult<Vec<(String, String)>> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(format!("prepared config integrity_check returned {integrity:?}").into());
    }
    let mut statement = connection.prepare("SELECT key, value FROM config ORDER BY key")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<(String, String)>, _>>()?;
    Ok(rows)
}

fn run(cache_dir: PathBuf) -> AnyResult<()> {
    if cache_dir.exists() {
        return Err(format!(
            "run cache must begin absent so before-state is unambiguous: {}",
            cache_dir.display()
        )
        .into());
    }
    fs::create_dir_all(&cache_dir)?;
    let vault_dir = cache_dir.join(format!("{PROJECT}.astrolabe-vault"));
    let vault_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>()?;
    let vault = AsterVault::new_durable(
        &vault_dir,
        vault_id,
        b"issue-1127-empty-transaction-fsv-v1".to_vec(),
        VaultOptions::default(),
    )?;
    let base_seq = vault.latest_seq();
    drop(vault);

    print_state("empty_transaction", "before", &cache_dir)?;
    let committed = astrolabe_server::migration::manual_fsv_commit_empty_signal_card_transaction(
        &cache_dir,
        PROJECT,
        vault_id,
        base_seq,
        PRODUCED_AT,
        |expected_marker| {
            let (config_path, ledger_path) = paths(&cache_dir);
            let rows = read_only_config_rows(&config_path)?;
            if rows.len() != 1 {
                return Err(format!(
                    "prepared independent SQLite read found {} rows, expected one marker",
                    rows.len()
                )
                .into());
            }
            let observed: Value = serde_json::from_str(&rows[0].1)?;
            if &observed != expected_marker
                || observed.get("state").and_then(Value::as_str) != Some("prepared")
                || observed
                    .get("cards")
                    .and_then(Value::as_array)
                    .is_none_or(|cards| !cards.is_empty())
            {
                return Err(
                    "prepared independent SQLite readback disagrees with the exact empty marker"
                        .into(),
                );
            }
            let ledger_metadata = fs::symlink_metadata(&ledger_path)?;
            if !ledger_metadata.file_type().is_file() || ledger_metadata.len() != 0 {
                return Err("prepared ledger is not the exact zero-byte ordinary file".into());
            }
            let external_read = match fs::read(&ledger_path) {
                Err(error) if error.raw_os_error() == Some(33) => json!({
                    "state": "exclusive_ledger_lock_refused_external_read",
                    "native_error": 33,
                    "message": error.to_string(),
                }),
                Err(error) => {
                    return Err(format!(
                        "prepared ledger external read failed with unexpected native error {:?}: {error}",
                        error.raw_os_error()
                    )
                    .into());
                }
                Ok(bytes) => {
                    return Err(format!(
                        "prepared ledger external read bypassed the exclusive lock and returned {} bytes",
                        bytes.len()
                    )
                    .into());
                }
            };
            let ledger = json!({
                "exists": true,
                "ordinary_file": true,
                "bytes": ledger_metadata.len(),
                "external_read": external_read,
            });
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "case": "empty_transaction",
                    "phase": "prepared_independent_read",
                    "sqlite_integrity_check": "ok",
                    "config_rows": rows,
                    "ledger": ledger,
                }))?
            );
            Ok(())
        },
    )?;
    print_state("empty_transaction", "after", &cache_dir)?;
    let readback = astrolabe_server::migration::manual_fsv_read_committed_signal_card_transaction(
        &cache_dir, PROJECT,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "empty_transaction",
            "phase": "committed_production_read",
            "committed": committed,
            "readback": readback,
        }))?
    );
    Ok(())
}

fn inspect(cache_dir: PathBuf) -> AnyResult<()> {
    print_state("empty_transaction", "inspect_before", &cache_dir)?;
    let readback = astrolabe_server::migration::manual_fsv_read_committed_signal_card_transaction(
        &cache_dir, PROJECT,
    )?;
    let (config_path, _) = paths(&cache_dir);
    let rows = read_only_config_rows(&config_path)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "empty_transaction",
            "phase": "inspect_after",
            "sqlite_integrity_check": "ok",
            "config_rows": rows,
            "production_readback": readback,
        }))?
    );
    Ok(())
}

fn main() -> AnyResult<()> {
    let mut args = std::env::args_os().skip(1);
    let operation = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("usage: issue_1127_empty_transaction_fsv <run|inspect> <cache-dir>")?;
    let cache_dir = PathBuf::from(
        args.next()
            .ok_or("usage: issue_1127_empty_transaction_fsv <run|inspect> <cache-dir>")?,
    );
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    match operation.as_str() {
        "run" => run(cache_dir),
        "inspect" => inspect(cache_dir),
        _ => Err(format!("unknown operation {operation:?}; expected run or inspect").into()),
    }
}
