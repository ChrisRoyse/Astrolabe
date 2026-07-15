use calyx_core::CalyxError;

use crate::error::{CliError, CliResult};

pub(super) fn enforce(required: bool, truth_n: usize, has_scale_truth: bool) -> CliResult {
    if !required || truth_n == 0 || has_scale_truth {
        return Ok(());
    }
    Err(CliError::Calyx(CalyxError {
        code: "CALYX_FSV_PARTITIONED_RRF_SCALE_TRUTH_REQUIRED",
        message:
            "gate-bearing partitioned-rrf recall requires byte-readable accepted-reference truth"
                .to_string(),
        remediation: "pass --slot-ground-truth-cf-root with its DB association key, or legacy fused/slot file truth only as migration diagnostics; CPU brute force is diagnostic-only",
    }))
}
