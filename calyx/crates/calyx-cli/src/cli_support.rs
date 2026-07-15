use std::fs;
use std::path::Path;

use crate::error::{CliError, CliResult};
use crate::output::print_hex_dump;
use crate::{budget_readback, tripwire_readback};

pub(crate) fn readback_hex(path: &Path) -> CliResult {
    let bytes = fs::read(path)?;
    print_hex_dump(0, &bytes).map(|_| ())
}

pub(crate) fn parse_i64(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|error| format!("invalid i64 value {value}: {error}"))
}

pub(crate) fn parse_i32(value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|error| format!("invalid i32 value {value}: {error}"))
}

pub(crate) fn readback_config(name: &str, vault: &Path) -> CliResult {
    match name {
        "tripwire" => tripwire_readback::readback_tripwire_config(vault),
        "budget" => budget_readback::readback_budget_config(vault),
        _ => Err(CliError::usage(format!("unknown config readback: {name}"))),
    }
}
