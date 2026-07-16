use std::fs;
use std::path::Path;

use calyx_registry::resolve_safetensors_weight_set;
use serde_json::json;

use super::artifact::{
    Artifact, add_optional, artifact, find_all_by_extension, read_hidden_size, require_named,
};
use super::log::{ConversionLog, run_command};
use super::options::CommissionFlags;
use crate::error::CliResult;

pub(super) fn commission(
    flags: &CommissionFlags,
    out: &Path,
    log: &mut ConversionLog,
) -> CliResult<Vec<Artifact>> {
    let artifact_dir = out.join("hf-candle");
    fs::create_dir_all(&artifact_dir)?;
    run_command(
        log,
        "hf",
        &[
            "download",
            &flags.hf,
            "--local-dir",
            &artifact_dir.display().to_string(),
            "--include",
            "config.json",
            "--include",
            "tokenizer.json",
            "--include",
            "tokenizer_config.json",
            "--include",
            "special_tokens_map.json",
            "--include",
            "*.safetensors",
        ],
    )?;
    let downloaded_weights = find_all_by_extension(&artifact_dir, "safetensors")?;
    let weights = resolve_safetensors_weight_set("candle", &downloaded_weights)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            crate::error::CliError::runtime(
                "Candle weight resolver returned an empty set after validation",
            )
        })?;
    let tokenizer = require_named(&artifact_dir, "tokenizer.json")?;
    let config = require_named(&artifact_dir, "config.json")?;
    let dim = flags.dim.unwrap_or(read_hidden_size(&config)?);
    log.event(json!({"event": "candle_artifacts_ready", "dim": dim}))?;
    let mut artifacts = vec![
        artifact("model", weights)?,
        artifact("tokenizer", tokenizer)?,
        artifact("config", config)?,
    ];
    add_optional(
        &mut artifacts,
        "tokenizer_config",
        artifact_dir.join("tokenizer_config.json"),
    )?;
    add_optional(
        &mut artifacts,
        "special_tokens_map",
        artifact_dir.join("special_tokens_map.json"),
    )?;
    Ok(artifacts)
}
