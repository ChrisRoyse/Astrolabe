use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::output;

pub(crate) fn abundance(vault: &Path) -> CliResult {
    let report = read_abundance_report(vault)?;
    output::print_json(&report)
}

pub(crate) fn read_abundance_report(vault: &Path) -> CliResult<Value> {
    let path = abundance_report_path(vault);
    let bytes = fs::read(&path).map_err(|error| {
        CliError::io(format!(
            "read abundance report {} failed: {error}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError::usage(format!(
            "parse abundance report {} failed: {error}",
            path.display()
        ))
    })
}

fn abundance_report_path(vault: &Path) -> PathBuf {
    vault.join("intelligence").join("abundance.json")
}
