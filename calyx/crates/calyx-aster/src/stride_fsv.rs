//! STRIDE defense FSV proofs for PH61 T06.

use calyx_core::{CalyxError, Result};

/// Module-local fail-closed code for non-allowlisted external commands.
pub const CALYX_EXTERNAL_CMD_NOT_ALLOWED: &str = "CALYX_EXTERNAL_CMD_NOT_ALLOWED";

/// Minimal external-command allowlist gate for lens sandbox execution.
pub fn run_external_cmd(cmd: &str, allowlist: &[&str]) -> Result<()> {
    if allowlist.contains(&cmd) {
        Ok(())
    } else {
        Err(CalyxError {
            code: CALYX_EXTERNAL_CMD_NOT_ALLOWED,
            message: format!("external command {cmd:?} is not in the allowlist"),
            remediation: "register the command in the explicit lens sandbox allowlist before use",
        })
    }
}
