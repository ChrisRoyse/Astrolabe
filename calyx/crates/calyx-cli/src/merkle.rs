use std::env;
use std::ops::Range;
use std::path::Path;

use calyx_ledger::{DirectoryLedgerStore, merkle_root};

use crate::cf_read::hex_bytes;
use crate::error::CliError;
use crate::ledger_store::AsterLedgerCfStore;

pub fn print_root(ledger_dir: &Path, range: Range<u64>) -> crate::error::CliResult {
    let store = DirectoryLedgerStore::open(ledger_dir)?;
    let root = merkle_root(&store, range)?;
    println!("{}", hex_bytes(&root));
    Ok(())
}

pub fn print_root_from_env(range: Range<u64>) -> crate::error::CliResult {
    let ledger_dir = env::var("CALYX_LEDGER_DIR")
        .map_err(|_| CliError::usage("CALYX_LEDGER_DIR is required when --ledger is omitted"))?;
    print_root(Path::new(&ledger_dir), range)
}

pub fn print_root_from_vault(vault: &Path, range: Range<u64>) -> crate::error::CliResult {
    let store = AsterLedgerCfStore::open(vault)?;
    let root = merkle_root(&store, range)?;
    println!("{}", hex_bytes(&root));
    Ok(())
}

pub fn parse_range(value: &str) -> crate::error::CliResult<Range<u64>> {
    let (start, end) = value
        .split_once("..")
        .ok_or_else(|| CliError::usage("range must use a..b syntax"))?;
    let start = start
        .parse::<u64>()
        .map_err(|error| CliError::usage(format!("invalid range start: {error}")))?;
    let end = end
        .parse::<u64>()
        .map_err(|error| CliError::usage(format!("invalid range end: {error}")))?;
    if start > end {
        return Err(CliError::usage(format!("range start {start} > end {end}")));
    }
    Ok(start..end)
}
