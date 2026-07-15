use calyx_core::{CalyxError, Result};

const PIPELINE_ENV: &str = "CALYX_ONNX_CUSTOM_PIPELINE";
const BATCH_WINDOW_ENV: &str = "CALYX_ONNX_CUSTOM_PIPELINE_BATCH_WINDOW";
const OUTPUT_WINDOW_ENV: &str = "CALYX_ONNX_CUSTOM_PIPELINE_OUTPUT_WINDOW";
const DEFAULT_BATCH_WINDOW: usize = 16;
const DEFAULT_OUTPUT_WINDOW: usize = 2;

pub(super) fn custom_pipeline_enabled() -> bool {
    match std::env::var(PIPELINE_ENV) {
        Ok(value) => {
            let value = value.trim();
            !(value.eq_ignore_ascii_case("0")
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("off")
                || value.eq_ignore_ascii_case("no"))
        }
        Err(_) => true,
    }
}

pub(super) fn should_pipeline(input_len: usize, max_batch: Option<usize>) -> bool {
    custom_pipeline_enabled() && max_batch.is_some_and(|limit| input_len > limit)
}

pub(super) fn pipeline_batch_window() -> Result<usize> {
    positive_env_usize(BATCH_WINDOW_ENV, DEFAULT_BATCH_WINDOW)
}

pub(super) fn pipeline_output_window() -> Result<usize> {
    positive_env_usize(OUTPUT_WINDOW_ENV, DEFAULT_OUTPUT_WINDOW)
}

pub(super) fn log_pipeline_start(
    inputs: usize,
    batch_window: usize,
    output_window: usize,
    max_batch: Option<usize>,
) {
    eprintln!(
        "CALYX_ONNX_RUNTIME phase=custom_pipeline_start inputs={inputs} batch_window={batch_window} output_window={output_window} internal_max_batch={}",
        max_batch
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
}

fn positive_env_usize(name: &str, default: usize) -> Result<usize> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(default);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(default);
    }
    raw.parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_CUSTOM_PIPELINE_WINDOW_INVALID",
            message: format!("{name}={raw} is not a positive integer"),
            remediation: "set custom ONNX pipeline window env vars to positive integers",
        })
}
