//! `calyx build-info` prints the embedded build identity as JSON (#1108).
//!
//! Deploy tooling compares `git_sha` against `origin/main` to detect a stale
//! runner binary, so this command must never touch a vault, the panel, or the
//! GPU — it reads only compile-time constants plus the executable path.

use calyx_buildinfo::BuildInfo;
use calyx_core::CalyxError;
use serde::Serialize;

use crate::error::{CliError, CliResult};
use crate::output::print_json;

#[derive(Debug, Serialize)]
struct BuildInfoReport {
    binary: &'static str,
    #[serde(flatten)]
    info: BuildInfo,
    executable: String,
}

pub(crate) fn try_run(args: &[String]) -> Option<CliResult> {
    let (command, rest) = args.split_first()?;
    if command != "build-info" {
        return None;
    }
    if let [flag] = rest
        && matches!(flag.as_str(), "--help" | "-h")
    {
        return Some(crate::usage::print_command_usage(command));
    }
    Some(run(rest))
}

fn run(rest: &[String]) -> CliResult {
    if !rest.is_empty() {
        return Err(CliError::usage(format!(
            "build-info takes no arguments, got {:?}",
            rest.join(" ")
        )));
    }
    let executable = std::env::current_exe().map_err(|error| {
        CliError::from(CalyxError::forge_device_unavailable(format!(
            "current executable path unavailable: {error}"
        )))
    })?;
    print_json(&BuildInfoReport {
        binary: "calyx",
        info: calyx_buildinfo::build_info!(capabilities: crate::capabilities::COMPILED),
        executable: executable.display().to_string(),
    })
}
