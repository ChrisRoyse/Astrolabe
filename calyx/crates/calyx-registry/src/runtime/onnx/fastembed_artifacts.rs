use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use calyx_core::{CalyxError, Result};
use fastembed::{ExternalInitializerFile, TokenizerFiles};
use sha2::{Digest, Sha256};

use super::{OnnxModelFiles, OnnxProviderPolicy};
use crate::frozen::LengthDelimitedSha256;

#[derive(Clone, Debug)]
pub(super) struct FrozenFastembedReceipt {
    pub(super) weights_sha256: [u8; 32],
    pub(super) artifact_bytes: u64,
    pub(super) model_sha256: String,
    pub(super) tokenizer_sha256: String,
    pub(super) external_sha256: String,
    pub(super) frozen_operators: String,
}

/// Exact model inputs shared by identity, attestation, and session construction.
///
/// Cache paths are provenance only after this value is created. All consumers use
/// these owned bytes so a cache mutation cannot make the LensId describe different
/// data from the committed ONNX Runtime session.
pub(super) struct FrozenFastembedArtifacts {
    model: Vec<u8>,
    tokenizer: TokenizerFiles,
    external_initializers: Vec<ExternalInitializerFile>,
    receipt: FrozenFastembedReceipt,
}

/// Reconstructs the exact frozen file-role mapping persisted in a `LensSpec`.
///
/// Persisted paths are already the source of truth. This path must not resolve a
/// model repository again because doing so could construct a session from bytes
/// other than those whose hash was admitted by the static contract.
pub(super) fn persisted_model_files(
    model_code: &str,
    paths: &[PathBuf],
    logical_model_file: &str,
    logical_additional_files: &[String],
) -> Result<OnnxModelFiles> {
    validate_logical_file_set(logical_model_file, logical_additional_files)?;
    if model_code.trim().is_empty() {
        return Err(artifact_invalid("persisted FastEmbed model code is empty"));
    }
    let expected_len = 5usize
        .checked_add(logical_additional_files.len())
        .ok_or_else(|| artifact_invalid("external initializer count exceeds usize"))?;
    if paths.len() != expected_len {
        return Err(artifact_invalid(format!(
            "persisted FastEmbed artifact path count {} != expected {expected_len}",
            paths.len()
        )));
    }
    for (index, path) in paths.iter().enumerate() {
        if path.as_os_str().is_empty() {
            return Err(artifact_invalid(format!(
                "persisted FastEmbed artifact path {index} is empty"
            )));
        }
        if path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(artifact_invalid(format!(
                "persisted FastEmbed artifact path {index} contains a relative alias: {}",
                path.display()
            )));
        }
    }

    let cache_dir = common_artifact_root(paths)?;
    let model_file = paths[0].clone();
    Ok(OnnxModelFiles {
        cache_dir,
        model_code: model_code.to_string(),
        model_file,
        tokenizer: paths[1].clone(),
        config: paths[2].clone(),
        tokenizer_config: paths[3].clone(),
        special_tokens_map: paths[4].clone(),
        contract_paths: paths.to_vec(),
    })
}

impl FrozenFastembedArtifacts {
    pub(super) fn snapshot(
        files: &OnnxModelFiles,
        logical_model_file: &str,
        logical_additional_files: &[String],
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let frozen_bytes =
            immutable_artifact_bytes(files, logical_additional_files.len(), provider_policy)?;
        let mut frozen_bytes = frozen_bytes.into_iter();

        let model = next_artifact_bytes(&mut frozen_bytes, "ONNX model")?;
        if model.is_empty() {
            return Err(artifact_invalid("resolved ONNX model is empty"));
        }
        let tokenizer_file = next_artifact_bytes(&mut frozen_bytes, "tokenizer.json")?;
        let config_file = next_artifact_bytes(&mut frozen_bytes, "config.json")?;
        let tokenizer_config_file =
            next_artifact_bytes(&mut frozen_bytes, "tokenizer_config.json")?;
        let special_tokens_map_file =
            next_artifact_bytes(&mut frozen_bytes, "special_tokens_map.json")?;

        let mut additional = Vec::with_capacity(logical_additional_files.len());
        for logical_name in logical_additional_files {
            additional.push((
                logical_name.clone(),
                next_artifact_bytes(&mut frozen_bytes, logical_name)?,
            ));
        }
        if frozen_bytes.next().is_some() {
            return Err(artifact_invalid(
                "immutable FastEmbed snapshot contains undeclared artifact bytes",
            ));
        }

        let inspection = super::fastembed_attestation::inspect_frozen_model(&model)
            .map_err(|reason| artifact_invalid(format!("invalid frozen ONNX graph: {reason}")))?;
        let supplied = map_external_initializers(
            logical_model_file,
            additional,
            &inspection.external_locations,
        )?;
        validate_external_ranges(&inspection.external_references, &supplied)?;

        let mut weights = LengthDelimitedSha256::new();
        weights.update_part(&model);
        weights.update_part(&tokenizer_file);
        weights.update_part(&config_file);
        weights.update_part(&tokenizer_config_file);
        weights.update_part(&special_tokens_map_file);
        for logical_name in logical_additional_files {
            let canonical = model_relative_external_name(logical_model_file, logical_name)?;
            let bytes = supplied.get(&canonical).ok_or_else(|| {
                artifact_invalid(format!(
                    "validated external initializer {canonical} is missing from the frozen set"
                ))
            })?;
            weights.update_part(bytes);
        }

        let tokenizer_sha256 = length_delimited_hex([
            tokenizer_file.as_slice(),
            config_file.as_slice(),
            tokenizer_config_file.as_slice(),
            special_tokens_map_file.as_slice(),
        ]);
        let external_sha256 = external_bundle_hash(&supplied);
        let artifact_bytes = checked_total_bytes(
            [
                &model,
                &tokenizer_file,
                &config_file,
                &tokenizer_config_file,
                &special_tokens_map_file,
            ]
            .into_iter()
            .chain(supplied.values()),
        )?;
        let external_initializers = supplied
            .into_iter()
            .map(|(name, buffer)| ExternalInitializerFile::new(name, buffer))
            .collect();
        let receipt = FrozenFastembedReceipt {
            weights_sha256: weights.finalize(),
            artifact_bytes,
            model_sha256: sha256_hex(&model),
            tokenizer_sha256,
            external_sha256,
            frozen_operators: inspection.operator_inventory,
        };
        let tokenizer = TokenizerFiles {
            tokenizer_file,
            config_file,
            special_tokens_map_file,
            tokenizer_config_file,
        };
        Ok(Self {
            model,
            tokenizer,
            external_initializers,
            receipt,
        })
    }

    pub(super) fn receipt(&self) -> &FrozenFastembedReceipt {
        &self.receipt
    }

    pub(super) fn into_parts(self) -> (Vec<u8>, TokenizerFiles, Vec<ExternalInitializerFile>) {
        (self.model, self.tokenizer, self.external_initializers)
    }
}

pub(super) fn validate_logical_file_set(
    logical_model_file: &str,
    logical_additional_files: &[String],
) -> Result<()> {
    canonical_posix_parts(logical_model_file, "model_file")?;
    let mut names = BTreeSet::new();
    for file in logical_additional_files {
        let name = model_relative_external_name(logical_model_file, file)?;
        if !names.insert(name.clone()) {
            return Err(artifact_invalid(format!(
                "duplicate logical external initializer name {name}"
            )));
        }
    }
    Ok(())
}

fn validate_contract_paths(files: &OnnxModelFiles, additional_count: usize) -> Result<()> {
    let expected_len = 5usize
        .checked_add(additional_count)
        .ok_or_else(|| artifact_invalid("external initializer count exceeds usize"))?;
    if files.contract_paths.len() != expected_len {
        return Err(artifact_invalid(format!(
            "resolved artifact path count {} != expected {expected_len}",
            files.contract_paths.len()
        )));
    }
    let expected = [
        &files.model_file,
        &files.tokenizer,
        &files.config,
        &files.tokenizer_config,
        &files.special_tokens_map,
    ];
    for (index, path) in expected.into_iter().enumerate() {
        if files.contract_paths.get(index) != Some(path) {
            return Err(artifact_invalid(format!(
                "resolved artifact path {index} does not match its frozen role"
            )));
        }
    }
    Ok(())
}

fn immutable_artifact_bytes(
    files: &OnnxModelFiles,
    additional_count: usize,
    provider_policy: OnnxProviderPolicy,
) -> Result<Vec<Vec<u8>>> {
    validate_contract_paths(files, additional_count)?;
    let root = calyx_onnx_runtime::open_immutable_directory(&files.cache_dir)?;
    let mut remaining_bytes = artifact_read_budget(provider_policy)?;
    let mut identities =
        BTreeMap::<calyx_onnx_runtime::ImmutableFileIdentity, (usize, PathBuf)>::new();
    let mut frozen_bytes = Vec::with_capacity(files.contract_paths.len());
    for (index, path) in files.contract_paths.iter().enumerate() {
        if remaining_bytes == 0 {
            return Err(artifact_invalid(format!(
                "FastEmbed artifact read budget was exhausted before declared path {index} at {}",
                path.display()
            )));
        }
        let snapshot =
            calyx_onnx_runtime::snapshot_immutable_file(path, Some(&root), remaining_bytes)?;
        if let Some((existing_index, existing_path)) = identities.get(&snapshot.identity) {
            return Err(artifact_invalid(format!(
                "FastEmbed artifact path {index} at {} aliases declared path {existing_index} at {} by physical file identity {:?}",
                snapshot.final_path.display(),
                existing_path.display(),
                snapshot.identity
            )));
        }
        let byte_len = u64::try_from(snapshot.bytes.len())
            .map_err(|_| artifact_invalid("frozen FastEmbed artifact length exceeds u64"))?;
        remaining_bytes = remaining_bytes.checked_sub(byte_len).ok_or_else(|| {
            artifact_invalid(format!(
                "FastEmbed artifact path {index} consumed {byte_len} bytes beyond its remaining {remaining_bytes}-byte budget"
            ))
        })?;
        identities.insert(snapshot.identity, (index, snapshot.final_path));
        frozen_bytes.push(snapshot.bytes);
    }
    Ok(frozen_bytes)
}

fn artifact_read_budget(provider_policy: OnnxProviderPolicy) -> Result<u64> {
    let host_bytes = calyx_onnx_runtime::available_host_memory_bytes()?;
    let selected_cuda = super::runtime_bundle::selected_cuda_device(provider_policy)?;
    let mut budget = selected_cuda
        .as_ref()
        .map_or(host_bytes, |device| host_bytes.min(device.total_vram_bytes));
    if selected_cuda.is_some() {
        if let Some(configured_bytes) = super::arena::configured_gpu_mem_limit()? {
            let configured_bytes = u64::try_from(configured_bytes).map_err(|_| {
                artifact_invalid("configured FastEmbed GPU memory limit exceeds u64")
            })?;
            budget = budget.min(configured_bytes);
        }
    }
    if budget == 0 {
        return Err(artifact_invalid(
            "live host/device memory reports a zero-byte FastEmbed artifact read budget",
        ));
    }
    Ok(budget)
}

fn next_artifact_bytes(
    frozen_bytes: &mut impl Iterator<Item = Vec<u8>>,
    role: impl AsRef<str>,
) -> Result<Vec<u8>> {
    let role = role.as_ref();
    frozen_bytes.next().ok_or_else(|| {
        artifact_invalid(format!(
            "immutable FastEmbed snapshot is missing declared {role} bytes"
        ))
    })
}

fn common_artifact_root(paths: &[PathBuf]) -> Result<PathBuf> {
    let first = paths
        .first()
        .and_then(|path| path.parent())
        .ok_or_else(|| artifact_invalid("persisted FastEmbed artifacts have no parent root"))?;
    let mut root = first.to_path_buf();
    for path in &paths[1..] {
        while !path_is_within(path, &root) {
            root = root.parent().map(Path::to_path_buf).ok_or_else(|| {
                artifact_invalid("persisted FastEmbed artifacts have no common bounded root")
            })?;
        }
    }
    if root.parent().is_none() {
        return Err(artifact_invalid(format!(
            "persisted FastEmbed artifacts share only unbounded filesystem root {}",
            root.display()
        )));
    }
    Ok(root)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    root.components().all(|root_component| {
        path_components.next().is_some_and(|path_component| {
            os_eq(path_component.as_os_str(), root_component.as_os_str())
        })
    })
}

#[cfg(windows)]
fn os_eq(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
fn os_eq(left: &OsStr, right: &OsStr) -> bool {
    left == right
}

fn map_external_initializers(
    logical_model_file: &str,
    additional: Vec<(String, Vec<u8>)>,
    referenced: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut supplied = BTreeMap::new();
    for (logical_name, bytes) in additional {
        let relative = model_relative_external_name(logical_model_file, &logical_name)?;
        if supplied.insert(relative.clone(), bytes).is_some() {
            return Err(artifact_invalid(format!(
                "duplicate external initializer name {relative}"
            )));
        }
    }
    let supplied_names = supplied.keys().cloned().collect::<BTreeSet<_>>();
    if &supplied_names != referenced {
        let missing = referenced
            .difference(&supplied_names)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let undeclared = supplied_names
            .difference(referenced)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        return Err(artifact_invalid(format!(
            "external initializer set mismatch; missing=[{missing}] undeclared=[{undeclared}]"
        )));
    }
    Ok(supplied)
}

fn model_relative_external_name(model: &str, additional: &str) -> Result<String> {
    let model = canonical_posix_parts(model, "model_file")?;
    let additional = canonical_posix_parts(additional, "additional_file")?;
    let model_dir = &model[..model.len() - 1];
    if !additional.starts_with(model_dir) || additional.len() <= model_dir.len() {
        return Err(artifact_invalid(format!(
            "additional file {} is not beneath model directory {}",
            additional.join("/"),
            model_dir.join("/")
        )));
    }
    Ok(additional[model_dir.len()..].join("/"))
}

fn canonical_posix_parts<'a>(raw: &'a str, role: &str) -> Result<Vec<&'a str>> {
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(artifact_invalid(format!(
            "{role} must be a non-empty relative POSIX path: {raw:?}"
        )));
    }
    let parts = raw.split('/').collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == ".." || part.contains(':'))
    {
        return Err(artifact_invalid(format!(
            "{role} contains an empty, absolute, or traversing component: {raw:?}"
        )));
    }
    Ok(parts)
}

fn validate_external_ranges(
    references: &[super::fastembed_attestation::ExternalTensorReference],
    supplied: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let mut sha1_by_location = BTreeMap::new();
    for reference in references {
        let buffer = supplied.get(&reference.location).ok_or_else(|| {
            artifact_invalid(format!(
                "ONNX tensor references missing external file {}",
                reference.location
            ))
        })?;
        let file_len = u64::try_from(buffer.len())
            .map_err(|_| artifact_invalid("external initializer length exceeds u64"))?;
        let offset = reference.offset.unwrap_or(0);
        let length = reference
            .length
            .unwrap_or_else(|| file_len.saturating_sub(offset));
        let end = offset.checked_add(length).ok_or_else(|| {
            artifact_invalid(format!(
                "external initializer range overflows for {}",
                reference.location
            ))
        })?;
        if offset > file_len || end > file_len {
            return Err(artifact_invalid(format!(
                "external initializer range {offset}..{end} exceeds {} byte file {}",
                file_len, reference.location
            )));
        }
        if let Some(checksum) = &reference.checksum {
            let observed = sha1_by_location
                .entry(reference.location.clone())
                .or_insert_with(|| sha1_hex(buffer));
            if !checksum.eq_ignore_ascii_case(observed.as_str()) {
                return Err(artifact_invalid(format!(
                    "external initializer SHA1 mismatch for {}; declared={} observed={observed}",
                    reference.location, checksum
                )));
            }
        }
    }
    Ok(())
}

fn external_bundle_hash(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = LengthDelimitedSha256::new();
    for (name, bytes) in files {
        hasher.update_part(name.as_bytes());
        hasher.update_part(bytes);
    }
    hex(&hasher.finalize())
}

fn checked_total_bytes<'a>(parts: impl IntoIterator<Item = &'a Vec<u8>>) -> Result<u64> {
    let mut total = 0_u64;
    for part in parts {
        let len = u64::try_from(part.len())
            .map_err(|_| artifact_invalid("frozen artifact length exceeds u64"))?;
        total = total
            .checked_add(len)
            .ok_or_else(|| artifact_invalid("frozen artifact byte total exceeds u64"))?;
    }
    Ok(total)
}

fn length_delimited_hex<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = LengthDelimitedSha256::new();
    for part in parts {
        hasher.update_part(part);
    }
    hex(&hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    hex(&digest)
}

fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Sha1;

    let digest = Sha1::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn artifact_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_FASTEMBED_ARTIFACT_INVALID",
        message: message.into(),
        remediation: "repair the pinned model bundle so its exact model, tokenizer, and external-data bytes match the frozen ONNX graph; do not retry with path-based or CPU loading",
    }
}
