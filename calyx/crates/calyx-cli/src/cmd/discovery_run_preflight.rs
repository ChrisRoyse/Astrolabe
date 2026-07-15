//! Shared discovery-run manifest preflight for biomedical stage CLIs.

use std::fs;
use std::path::{Path, PathBuf};

use calyx_lodestar::{
    DiscoveryRunManifest, LodestarError, manifest_sha256, validate_discovery_run_manifest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CliError, CliResult};

pub(crate) const RUN_MANIFEST_FLAG: &str = "--run-manifest";
pub(crate) const RUN_STAGE_ID_FLAG: &str = "--run-stage-id";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DiscoveryRunPreflightArgs {
    pub manifest: Option<PathBuf>,
    pub stage_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DiscoveryRunPreflightReadback {
    pub manifest: PathBuf,
    pub manifest_sha256: String,
    pub stage_id: String,
    pub upstream_stage_id: Option<String>,
    pub expected_input_sha256: String,
    pub observed_input_sha256: String,
}

pub(crate) struct PreflightInput<'a> {
    pub path: &'a Path,
    pub bytes: &'a [u8],
}

impl<'a> PreflightInput<'a> {
    pub(crate) fn new(path: &'a Path, bytes: &'a [u8]) -> Self {
        Self { path, bytes }
    }
}

impl DiscoveryRunPreflightArgs {
    pub(crate) fn validate_for_command(&self, command: &str) -> CliResult {
        match (&self.manifest, &self.stage_id) {
            (None, None) | (Some(_), Some(_)) => Ok(()),
            (Some(_), None) => Err(CliError::usage(format!(
                "{command} requires {RUN_STAGE_ID_FLAG} when {RUN_MANIFEST_FLAG} is set"
            ))),
            (None, Some(_)) => Err(CliError::usage(format!(
                "{command} requires {RUN_MANIFEST_FLAG} when {RUN_STAGE_ID_FLAG} is set"
            ))),
        }
    }
}

pub(crate) fn preflight_input_bytes(
    preflight: &DiscoveryRunPreflightArgs,
    input_bytes: &[u8],
) -> CliResult<Option<DiscoveryRunPreflightReadback>> {
    preflight_input_sha256(preflight, sha256_hex(input_bytes))
}

pub(crate) fn preflight_input_files(
    preflight: &DiscoveryRunPreflightArgs,
    inputs: &[PreflightInput<'_>],
) -> CliResult<Option<DiscoveryRunPreflightReadback>> {
    let observed = match inputs {
        [] => {
            return Err(CliError::usage(
                "discovery-run preflight requires at least one input",
            ));
        }
        [single] => sha256_hex(single.bytes),
        many => combined_input_sha256(many),
    };
    preflight_input_sha256(preflight, observed)
}

pub(crate) fn preflight_input_sha256(
    preflight: &DiscoveryRunPreflightArgs,
    observed_input_sha256: String,
) -> CliResult<Option<DiscoveryRunPreflightReadback>> {
    preflight.validate_for_command("discovery-run preflight")?;
    let Some(manifest_path) = preflight.manifest.as_ref() else {
        return Ok(None);
    };
    let stage_id = preflight
        .stage_id
        .as_ref()
        .expect("validated preflight stage id")
        .clone();
    let manifest_bytes = fs::read(manifest_path).map_err(|error| {
        CliError::io(format!(
            "read {RUN_MANIFEST_FLAG} {}: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest: DiscoveryRunManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            CliError::runtime(format!(
                "parse {RUN_MANIFEST_FLAG} {}: {error}",
                manifest_path.display()
            ))
        })?;
    validate_discovery_run_manifest(&manifest)?;
    let stage = manifest
        .stages
        .iter()
        .find(|stage| stage.stage_id == stage_id)
        .ok_or_else(|| LodestarError::DiscoveryRunManifestMissingUpstream {
            stage: stage_id.clone(),
            upstream: stage_id.clone(),
        })?;
    if stage.input_sha256 != observed_input_sha256 {
        return Err(LodestarError::DiscoveryRunManifestChainBroken {
            stage: stage.stage_id.clone(),
            expected: stage.input_sha256.clone(),
            found: observed_input_sha256,
        }
        .into());
    }
    Ok(Some(DiscoveryRunPreflightReadback {
        manifest: manifest_path.clone(),
        manifest_sha256: manifest_sha256(&manifest)?,
        stage_id: stage.stage_id.clone(),
        upstream_stage_id: stage.upstream_stage_id.clone(),
        expected_input_sha256: stage.input_sha256.clone(),
        observed_input_sha256: stage.input_sha256.clone(),
    }))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn combined_input_sha256(inputs: &[PreflightInput<'_>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-discovery-run-preflight-inputs-v1\0");
    for input in inputs {
        hasher.update(input.path.display().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(sha256_hex(input.bytes).as_bytes());
        hasher.update([0]);
    }
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

