use calyx_core::{CalyxError, Result};

pub(crate) const FASTEMBED_CUDA_EXECUTION: &str = "cuda_fail_loud";
pub(crate) const FASTEMBED_CPU_EXECUTION: &str = "cpu_explicit";

pub(crate) fn is_in_process_fastembed_runtime(runtime: &str) -> bool {
    matches!(
        runtime,
        "onnx-fastembed"
            | "fastembed-sparse"
            | "fastembed-bgem3-dense"
            | "fastembed-bgem3-sparse"
            | "fastembed-bgem3-colbert"
            | "fastembed-reranker"
    )
}

/// Canonicalizes the persisted execution policy for in-process FastEmbed lenses.
///
/// Placement-bound manifests must state this policy explicitly. Absence is
/// historical, execution-unbound provenance and can only be recommissioned.
pub(crate) fn canonical_fastembed_execution(raw: Option<&str>) -> Result<String> {
    let Some(raw) = raw else {
        return Err(CalyxError {
            code: "CALYX_FASTEMBED_LEGACY_EXECUTION_UNBOUND",
            message: "FastEmbed manifest has no explicit execution policy".into(),
            remediation: "recommission the manifest with execution_device set explicitly to cuda_fail_loud or cpu_explicit; never infer placement from historical constructors",
        });
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "cuda" | "cuda_fail_loud" => Ok(FASTEMBED_CUDA_EXECUTION.to_string()),
        "cpu" | "cpu_explicit" => Ok(FASTEMBED_CPU_EXECUTION.to_string()),
        other => Err(CalyxError {
            code: "CALYX_LENS_CONFIG_INVALID",
            message: format!(
                "unsupported FastEmbed execution policy {other:?}; expected cuda_fail_loud or cpu_explicit"
            ),
            remediation: "recommission the manifest with execution_device set explicitly to cuda_fail_loud or cpu_explicit; never encode an ordinal or infer CPU from a CUDA failure",
        }),
    }
}

#[cfg(feature = "ml-runtime")]
pub(crate) fn validate_frozen_fastembed_execution(raw: &str) -> Result<&str> {
    let canonical = canonical_fastembed_execution(Some(raw))?;
    if canonical != raw {
        return Err(CalyxError {
            code: "CALYX_FASTEMBED_EXECUTION_IDENTITY_NONCANONICAL",
            message: format!(
                "persisted FastEmbed execution token {raw:?} is not canonical; expected {canonical:?}"
            ),
            remediation: "recommission the manifest so the persisted execution token is canonical; never rewrite frozen identity in place",
        });
    }
    Ok(raw)
}
