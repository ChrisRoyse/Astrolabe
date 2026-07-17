use super::*;
use std::collections::BTreeSet;
use std::path::Component;

use crate::fastembed_execution::{canonical_fastembed_execution, is_in_process_fastembed_runtime};
use crate::identity::{FastembedNamedArtifactDigest, fastembed_named_weights_sha256};

pub(super) fn read_and_verify_files(
    manifest: &LensForgeManifest,
    base_dir: &Path,
) -> Result<Vec<VerifiedFile>> {
    let mut files = Vec::with_capacity(manifest.files.len());
    for file in ordered_manifest_files(&manifest.files) {
        let path = resolve_manifest_path(base_dir, &file.path);
        let actual = plain_sha256_file(&path)?;
        if !hex_eq(&actual.sha256, &file.sha256) {
            return Err(CalyxError::lens_frozen_violation(format!(
                "lensforge artifact {} sha256 {} != manifest {}",
                path.display(),
                actual.sha256,
                file.sha256
            )));
        }
        if file.bytes != 0 && file.bytes != actual.bytes {
            return Err(config_invalid(format!(
                "lensforge artifact {} byte count {} != manifest {}",
                path.display(),
                actual.bytes,
                file.bytes
            )));
        }
        files.push(VerifiedFile {
            role: file.role.clone(),
            path,
            sha256: actual.sha256,
            bytes: actual.bytes,
        });
    }
    Ok(files)
}

pub(super) fn spec_weights_sha256(
    manifest: &LensForgeManifest,
    artifacts: &[VerifiedFile],
) -> Result<[u8; 32]> {
    if is_algorithmic_runtime(&manifest.runtime) && artifacts.is_empty() {
        return Ok(sha256_digest(&[
            b"lensforge-algorithmic-v1",
            manifest.name.as_bytes(),
            manifest.runtime.as_bytes(),
            &manifest.dim.to_be_bytes(),
            modality_token(manifest.modality).as_bytes(),
        ]));
    }
    let model = weight_anchor(manifest, artifacts)?;
    if !hex_eq(&model.sha256, &manifest.weights_sha256) {
        return Err(CalyxError::lens_frozen_violation(format!(
            "lensforge model weights sha256 {} != manifest {}",
            model.sha256, manifest.weights_sha256
        )));
    }
    let generic_weights = if let Some(expected) = &manifest.artifact_set_sha256 {
        let contract_artifacts = contract_artifacts(manifest, artifacts)?;
        let actual = artifact_set_sha256_hex(&contract_artifacts)?;
        if !hex_eq(&actual, expected) {
            return Err(CalyxError::lens_frozen_violation(format!(
                "lensforge artifact_set_sha256 {actual} != manifest {expected}"
            )));
        }
        parse_hex_32(expected)?
    } else {
        parse_hex_32(&manifest.weights_sha256)?
    };
    if is_in_process_fastembed_runtime(&manifest.runtime) {
        return named_fastembed_weights_from_verified(manifest, artifacts);
    }
    Ok(generic_weights)
}

pub(in crate::commission) fn metadata_fastembed_weights_sha256(
    manifest: &LensForgeManifest,
    base_dir: &Path,
) -> Result<Option<[u8; 32]>> {
    if !is_in_process_fastembed_runtime(&manifest.runtime) {
        return Ok(None);
    }
    let artifacts = ordered_manifest_files(&manifest.files)
        .into_iter()
        .map(|file| {
            Ok(ManifestFastembedArtifact {
                role: file.role.as_str(),
                path: resolve_manifest_path(base_dir, &file.path),
                sha256: parse_hex_32(&file.sha256)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    named_fastembed_weights(
        manifest,
        artifacts,
        canonical_fastembed_execution(manifest.execution_device.as_deref())?,
    )
    .map(Some)
}

fn named_fastembed_weights_from_verified(
    manifest: &LensForgeManifest,
    artifacts: &[VerifiedFile],
) -> Result<[u8; 32]> {
    let artifacts = artifacts
        .iter()
        .map(|file| {
            Ok(ManifestFastembedArtifact {
                role: file.role.as_str(),
                path: file.path.clone(),
                sha256: parse_hex_32(&file.sha256)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    named_fastembed_weights(
        manifest,
        artifacts,
        canonical_fastembed_execution(manifest.execution_device.as_deref())?,
    )
}

struct ManifestFastembedArtifact<'a> {
    role: &'a str,
    path: PathBuf,
    sha256: [u8; 32],
}

fn named_fastembed_weights(
    manifest: &LensForgeManifest,
    artifacts: Vec<ManifestFastembedArtifact<'_>>,
    execution: String,
) -> Result<[u8; 32]> {
    let tokenizer = artifact_for_exact_role(&artifacts, "tokenizer")?;
    let root = tokenizer
        .path
        .parent()
        .ok_or_else(|| {
            config_invalid("FastEmbed tokenizer.json artifact has no model repository root")
        })?
        .to_path_buf();
    let mut logical_names = BTreeSet::new();
    let mut physical_paths = BTreeSet::new();
    let mut named = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let (identity_role, required_name) = match artifact.role {
            "model" => ("model", None),
            "model_sidecar" => ("model_sidecar", None),
            "tokenizer" => ("tokenizer", Some("tokenizer.json")),
            "config" => ("config", Some("config.json")),
            "tokenizer_config" => ("tokenizer_config", Some("tokenizer_config.json")),
            "special_tokens_map" => ("special_tokens_map", Some("special_tokens_map.json")),
            other => {
                return Err(config_invalid(format!(
                    "FastEmbed manifest contains undeclared artifact role {other:?}"
                )));
            }
        };
        validate_manifest_artifact_path(&artifact.path)?;
        let logical_name = root_relative_manifest_name(&artifact.path, &root)?;
        if let Some(required_name) = required_name
            && logical_name != required_name
        {
            return Err(config_invalid(format!(
                "FastEmbed role {identity_role} must bind model-root-relative {required_name}, got {logical_name}"
            )));
        }
        let physical_key = canonical_physical_key(&artifact.path);
        if !physical_paths.insert(physical_key) {
            return Err(config_invalid(format!(
                "FastEmbed manifest path {} is declared more than once",
                artifact.path.display()
            )));
        }
        if !logical_names.insert(logical_name.clone()) {
            return Err(config_invalid(format!(
                "FastEmbed manifest logical path {logical_name} is declared more than once"
            )));
        }
        named.push(FastembedNamedArtifactDigest {
            role: identity_role.to_string(),
            logical_name,
            sha256: artifact.sha256,
        });
    }
    for role in [
        "model",
        "tokenizer",
        "config",
        "tokenizer_config",
        "special_tokens_map",
    ] {
        artifact_for_exact_role_from_named(&named, role)?;
    }
    fastembed_named_weights_sha256(&execution, named).map_err(|error| {
        CalyxError::lens_frozen_violation(format!(
            "FastEmbed manifest {} named artifact identity is invalid: {}",
            manifest.name, error.message
        ))
    })
}

fn artifact_for_exact_role<'a, 'b>(
    artifacts: &'a [ManifestFastembedArtifact<'b>],
    role: &str,
) -> Result<&'a ManifestFastembedArtifact<'b>> {
    let mut matches = artifacts.iter().filter(|artifact| artifact.role == role);
    let artifact = matches
        .next()
        .ok_or_else(|| config_invalid(format!("FastEmbed manifest is missing role {role}")))?;
    if matches.next().is_some() {
        return Err(config_invalid(format!(
            "FastEmbed manifest declares role {role} more than once"
        )));
    }
    Ok(artifact)
}

fn artifact_for_exact_role_from_named(
    artifacts: &[FastembedNamedArtifactDigest],
    role: &str,
) -> Result<()> {
    let count = artifacts
        .iter()
        .filter(|artifact| artifact.role == role)
        .count();
    if count != 1 {
        return Err(config_invalid(format!(
            "FastEmbed manifest role {role} count {count} != 1"
        )));
    }
    Ok(())
}

fn validate_manifest_artifact_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(config_invalid(format!(
            "FastEmbed manifest artifact path is empty or noncanonical: {}",
            path.display()
        )));
    }
    Ok(())
}

fn root_relative_manifest_name(path: &Path, root: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        config_invalid(format!(
            "FastEmbed artifact {} is outside tokenizer root {}",
            path.display(),
            root.display()
        ))
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(config_invalid(format!(
                "FastEmbed artifact {} has a noncanonical model-relative path",
                path.display()
            )));
        };
        let part = component.to_str().ok_or_else(|| {
            config_invalid(format!(
                "FastEmbed artifact {} has a non-UTF-8 logical path",
                path.display()
            ))
        })?;
        if part.is_empty()
            || part
                .chars()
                .any(|character| matches!(character, '/' | '\\' | ':') || character.is_control())
        {
            return Err(config_invalid(format!(
                "FastEmbed artifact {} has invalid logical component {part:?}",
                path.display()
            )));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(config_invalid(format!(
            "FastEmbed artifact {} resolves to the model root",
            path.display()
        )));
    }
    Ok(parts.join("/"))
}

#[cfg(windows)]
fn canonical_physical_key(path: &Path) -> String {
    path.as_os_str().to_string_lossy().to_ascii_lowercase()
}

#[cfg(not(windows))]
fn canonical_physical_key(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

fn weight_anchor<'a>(
    manifest: &LensForgeManifest,
    artifacts: &'a [VerifiedFile],
) -> Result<&'a VerifiedFile> {
    artifacts
        .iter()
        .find(|file| is_model_role(&file.role))
        .or_else(|| {
            is_adapter_runtime(&manifest.runtime)
                .then(|| artifacts.iter().find(|file| file.role == "adapter"))
                .flatten()
        })
        .ok_or_else(|| config_invalid("lensforge manifest requires a model file"))
}

pub(super) fn is_tei_runtime(runtime: &str) -> bool {
    matches!(runtime, "tei" | "tei-http" | "tei_http")
}

fn is_adapter_runtime(runtime: &str) -> bool {
    matches!(
        runtime,
        "adapter" | "multimodal-adapter" | "multimodal_adapter"
    )
}

fn ordered_manifest_files(files: &[LensForgeFile]) -> Vec<&LensForgeFile> {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|file| (role_rank(&file.role), file.path.clone()));
    ordered
}

fn role_rank(role: &str) -> u8 {
    match role {
        "model" | "weights" | "embeddings" => 0,
        "tokenizer" => 1,
        "config" => 2,
        "preprocessor" => 3,
        "tokenizer_config" => 4,
        "special_tokens_map" => 5,
        _ => 9,
    }
}

fn contract_artifacts<'a>(
    manifest: &LensForgeManifest,
    artifacts: &'a [VerifiedFile],
) -> Result<Vec<&'a VerifiedFile>> {
    match manifest.runtime.as_str() {
        "model2vec" | "static_lookup" | "static-lookup" => Ok(vec![
            artifact_ref_by_role(artifacts, is_model_role)?,
            artifact_ref_by_role(artifacts, |role| role == "tokenizer")?,
        ]),
        _ => Ok(artifacts.iter().collect()),
    }
}

fn artifact_ref_by_role(
    artifacts: &[VerifiedFile],
    predicate: impl Fn(&str) -> bool,
) -> Result<&VerifiedFile> {
    artifacts
        .iter()
        .find(|file| predicate(&file.role))
        .ok_or_else(|| config_invalid("lensforge manifest missing static lookup artifact"))
}

fn is_model_role(role: &str) -> bool {
    matches!(role, "model" | "weights" | "embeddings")
}

fn resolve_manifest_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

struct FileDigest {
    sha256: String,
    bytes: u64,
}

fn plain_sha256_file(path: &Path) -> Result<FileDigest> {
    let file = fs::File::open(path).map_err(|err| {
        config_invalid(format!(
            "open lensforge artifact {} for hashing failed: {err}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|err| {
        config_invalid(format!(
            "stat lensforge artifact {} for hashing failed: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; STREAM_HASH_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            config_invalid(format!(
                "read lensforge artifact {} while hashing failed: {err}",
                path.display()
            ))
        })?;
        if read == 0 {
            let digest: [u8; 32] = hasher.finalize().into();
            return Ok(FileDigest {
                sha256: hex_from_bytes(&digest),
                bytes: metadata.len(),
            });
        }
        hasher.update(&buffer[..read]);
    }
}

fn artifact_set_sha256_hex(files: &[&VerifiedFile]) -> Result<String> {
    let mut contract = LengthDelimitedSha256::new();
    let mut buffer = vec![0_u8; STREAM_HASH_BUFFER_BYTES];
    for file in files {
        hash_verified_file_into(file, &mut contract, &mut buffer)?;
    }
    Ok(hex_from_bytes(&contract.finalize()))
}

fn hash_verified_file_into(
    file: &VerifiedFile,
    contract: &mut LengthDelimitedSha256,
    buffer: &mut [u8],
) -> Result<()> {
    let handle = fs::File::open(&file.path).map_err(|err| {
        config_invalid(format!(
            "open lensforge artifact {} for artifact_set hashing failed: {err}",
            file.path.display()
        ))
    })?;
    let metadata = handle.metadata().map_err(|err| {
        config_invalid(format!(
            "stat lensforge artifact {} for artifact_set hashing failed: {err}",
            file.path.display()
        ))
    })?;
    if metadata.len() != file.bytes {
        return Err(config_invalid(format!(
            "lensforge artifact {} byte count changed from {} to {} while hashing artifact_set",
            file.path.display(),
            file.bytes,
            metadata.len()
        )));
    }
    contract.begin_part(file.bytes);
    let mut plain = Sha256::new();
    let mut reader = BufReader::new(handle);
    loop {
        let read = reader.read(buffer).map_err(|err| {
            config_invalid(format!(
                "read lensforge artifact {} while hashing artifact_set failed: {err}",
                file.path.display()
            ))
        })?;
        if read == 0 {
            let digest: [u8; 32] = plain.finalize().into();
            let actual = hex_from_bytes(&digest);
            if !hex_eq(&actual, &file.sha256) {
                return Err(CalyxError::lens_frozen_violation(format!(
                    "lensforge artifact {} sha256 changed from {} to {} while hashing artifact_set",
                    file.path.display(),
                    file.sha256,
                    actual
                )));
            }
            return Ok(());
        }
        let chunk = &buffer[..read];
        plain.update(chunk);
        contract.update_chunk(chunk);
    }
}
