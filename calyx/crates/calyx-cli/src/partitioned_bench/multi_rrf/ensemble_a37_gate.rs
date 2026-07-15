use calyx_assay::{A37_DIVERSITY_GATE_PASSED, A37DiversityGate};
use calyx_core::CalyxError;

use crate::error::{CliError, CliResult};

pub(super) fn validate(gate: &A37DiversityGate, required: bool) -> CliResult {
    if !required {
        return Ok(());
    }
    if gate.status == A37_DIVERSITY_GATE_PASSED
        && gate.family_span_pass
        && gate.redundancy_bound_pass
        && gate.no_collapse_pass
    {
        return Ok(());
    }
    Err(CliError::Calyx(CalyxError {
        code: "CALYX_FSV_A37_ENSEMBLE_CARD_REFUSED",
        message: format!(
            "A37 ensemble card refused: status={} family_span_pass={} redundancy_bound_pass={} no_collapse_pass={} n_eff={:.6} n_eff_floor={:.6} mean_pairwise_corr={:.6} mean_pairwise_nmi={:.6}",
            gate.status,
            gate.family_span_pass,
            gate.redundancy_bound_pass,
            gate.no_collapse_pass,
            gate.n_eff,
            gate.n_eff_floor,
            gate.mean_pairwise_corr,
            gate.mean_pairwise_nmi
        ),
        remediation: "pass an A37 gate_passed EnsembleCard before using partitioned-rrf recall/SLO as gate evidence",
    }))
}
