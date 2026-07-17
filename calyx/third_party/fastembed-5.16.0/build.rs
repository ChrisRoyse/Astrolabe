use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const RECEIPT_FILE: &str = "ASTROLABE_SOURCE.json";
const RECEIPT_SCHEMA: &str = "astrolabe.owned-crate-source.v2";
const HASH_ALGORITHM: &str = "sha256-domain-u64le-path-u64le-content-v1";
const HASH_DOMAIN: &[u8] = b"astrolabe.owned-crate-source.v2\0";
const CRATES_IO_ARCHIVE_SHA256: &str =
    "add59222e7bc3787285f993744b244cd454d78571845623606bdc45b22b23a4e";
const UPSTREAM_GIT_COMMIT: &str = "a500072fbcd4f0d16ec4e50e44d3b3fb0b8a034a";
const REMEDIATION: &str =
    "restore calyx/third_party/fastembed-5.16.0 from the reviewed Astrolabe commit";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceReceipt {
    schema: String,
    package: String,
    version: String,
    crates_io_archive_sha256: String,
    upstream_repository: String,
    upstream_git_commit: String,
    upstream_issue: String,
    license: String,
    hash_algorithm: String,
    attested_file_count: usize,
    attested_source_tree_sha256: String,
    files: Vec<SourceFileReceipt>,
    owned_deltas: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFileReceipt {
    path: String,
    bytes: u64,
    sha256: String,
}

fn main() {
    if let Err((code, detail)) = verify_owned_source() {
        panic!("FASTEMBED_SOURCE_ATTESTATION[{code}] detail={detail}; remediation={REMEDIATION}");
    }
}

fn verify_owned_source() -> Result<(), (&'static str, String)> {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        failure(
            "MANIFEST_ROOT_MISSING",
            "CARGO_MANIFEST_DIR is absent".to_string(),
        )
    })?);
    let root = fs::canonicalize(&root).map_err(|error| {
        failure(
            "MANIFEST_ROOT_UNREADABLE",
            format!("canonicalize {}: {error}", root.display()),
        )
    })?;
    let receipt_path = root.join(RECEIPT_FILE);
    println!("cargo:rerun-if-changed={}", receipt_path.display());
    let receipt_bytes = fs::read(&receipt_path).map_err(|error| {
        failure(
            "RECEIPT_UNREADABLE",
            format!("read {}: {error}", receipt_path.display()),
        )
    })?;
    let receipt: SourceReceipt = serde_json::from_slice(&receipt_bytes).map_err(|error| {
        failure(
            "RECEIPT_INVALID",
            format!("parse {}: {error}", receipt_path.display()),
        )
    })?;
    validate_receipt_identity(&receipt)?;

    let observed = enumerate_files(&root)?;
    let expected = receipt
        .files
        .iter()
        .map(|file| (file.path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != receipt.files.len() {
        return Err(failure(
            "RECEIPT_DUPLICATE_PATH",
            "receipt contains duplicate file paths".to_string(),
        ));
    }
    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    let observed_paths = observed.keys().cloned().collect::<BTreeSet<_>>();
    if expected_paths != observed_paths {
        let missing = expected_paths
            .difference(&observed_paths)
            .cloned()
            .collect::<Vec<_>>();
        let extra = observed_paths
            .difference(&expected_paths)
            .cloned()
            .collect::<Vec<_>>();
        return Err(failure(
            "FILE_SET_MISMATCH",
            format!("missing={missing:?} extra={extra:?}"),
        ));
    }
    if receipt.attested_file_count != observed.len() {
        return Err(failure(
            "FILE_COUNT_MISMATCH",
            format!(
                "receipt={} observed={}",
                receipt.attested_file_count,
                observed.len()
            ),
        ));
    }

    for (path, bytes) in &observed {
        println!(
            "cargo:rerun-if-changed={}",
            root.join(native_path(path)).display()
        );
        let expected_file = expected
            .get(path)
            .expect("file-set equality established above");
        let observed_len = u64::try_from(bytes.len()).map_err(|_| {
            failure(
                "FILE_SIZE_OVERFLOW",
                format!("{path} length does not fit u64"),
            )
        })?;
        if observed_len != expected_file.bytes {
            return Err(failure(
                "FILE_SIZE_MISMATCH",
                format!(
                    "{path} receipt={} observed={observed_len}",
                    expected_file.bytes
                ),
            ));
        }
        let observed_sha = sha256_hex(bytes);
        if observed_sha != expected_file.sha256 {
            return Err(failure(
                "FILE_HASH_MISMATCH",
                format!(
                    "{path} receipt={} observed={observed_sha}",
                    expected_file.sha256
                ),
            ));
        }
    }

    let tree_sha = source_tree_sha256(&observed)?;
    if tree_sha != receipt.attested_source_tree_sha256 {
        return Err(failure(
            "TREE_HASH_MISMATCH",
            format!(
                "receipt={} observed={tree_sha}",
                receipt.attested_source_tree_sha256
            ),
        ));
    }
    validate_manifest(
        observed
            .get("Cargo.toml")
            .expect("Cargo.toml is required by the receipt"),
    )?;
    Ok(())
}

fn validate_receipt_identity(receipt: &SourceReceipt) -> Result<(), (&'static str, String)> {
    let identity_ok = receipt.schema == RECEIPT_SCHEMA
        && receipt.package == "fastembed"
        && receipt.version == "5.16.0"
        && receipt.hash_algorithm == HASH_ALGORITHM
        && receipt.license == "Apache-2.0"
        && receipt.upstream_repository == "https://github.com/Anush008/fastembed-rs"
        && receipt.upstream_git_commit == UPSTREAM_GIT_COMMIT
        && receipt.upstream_issue == "https://github.com/ChrisRoyse/Astrolabe/issues/483"
        && receipt.crates_io_archive_sha256 == CRATES_IO_ARCHIVE_SHA256
        && !receipt.owned_deltas.is_empty()
        && receipt
            .owned_deltas
            .iter()
            .all(|delta| !delta.trim().is_empty());
    if !identity_ok
        || !is_lower_sha256(&receipt.crates_io_archive_sha256)
        || !is_lower_sha256(&receipt.attested_source_tree_sha256)
    {
        return Err(failure(
            "RECEIPT_IDENTITY_MISMATCH",
            "receipt identity, provenance, or hash contract is invalid".to_string(),
        ));
    }
    let paths = receipt
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    if !paths.is_sorted() {
        return Err(failure(
            "RECEIPT_PATH_ORDER",
            "receipt file paths are not ordinal-sorted".to_string(),
        ));
    }
    for file in &receipt.files {
        validate_relative_path(&file.path)?;
        if !is_lower_sha256(&file.sha256) {
            return Err(failure(
                "RECEIPT_FILE_HASH_INVALID",
                format!("{} SHA-256 is not lowercase hexadecimal", file.path),
            ));
        }
    }
    Ok(())
}

fn enumerate_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, (&'static str, String)> {
    fn visit(
        root: &Path,
        directory: &Path,
        out: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), (&'static str, String)> {
        // Watching every existing directory makes new files and directories
        // rerun this exact-file-set verifier during incremental builds.
        println!("cargo:rerun-if-changed={}", directory.display());
        for entry in fs::read_dir(directory).map_err(|error| {
            failure(
                "SOURCE_DIRECTORY_UNREADABLE",
                format!("read {}: {error}", directory.display()),
            )
        })? {
            let entry = entry.map_err(|error| {
                failure(
                    "SOURCE_DIRECTORY_UNREADABLE",
                    format!("read entry under {}: {error}", directory.display()),
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                failure(
                    "SOURCE_METADATA_UNREADABLE",
                    format!("metadata {}: {error}", path.display()),
                )
            })?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(failure(
                    "SOURCE_REPARSE_REFUSED",
                    format!("{} is a symbolic/reparse entry", path.display()),
                ));
            }
            let canonical = fs::canonicalize(&path).map_err(|error| {
                failure(
                    "SOURCE_PATH_UNREADABLE",
                    format!("canonicalize {}: {error}", path.display()),
                )
            })?;
            if !canonical.starts_with(root) {
                return Err(failure(
                    "SOURCE_PATH_ESCAPE",
                    format!("{} escapes {}", canonical.display(), root.display()),
                ));
            }
            if metadata.is_dir() {
                visit(root, &path, out)?;
                continue;
            }
            if !metadata.is_file() {
                return Err(failure(
                    "SOURCE_ENTRY_INVALID",
                    format!("{} is neither a file nor directory", path.display()),
                ));
            }
            let relative = normalized_path(path.strip_prefix(root).map_err(|error| {
                failure(
                    "SOURCE_PATH_ESCAPE",
                    format!("strip {}: {error}", path.display()),
                )
            })?)?;
            if relative == RECEIPT_FILE {
                continue;
            }
            let bytes = fs::read(&path).map_err(|error| {
                failure(
                    "SOURCE_FILE_UNREADABLE",
                    format!("read {}: {error}", path.display()),
                )
            })?;
            if out.insert(relative.clone(), bytes).is_some() {
                return Err(failure(
                    "SOURCE_DUPLICATE_PATH",
                    format!("duplicate normalized path {relative}"),
                ));
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

fn validate_manifest(bytes: &[u8]) -> Result<(), (&'static str, String)> {
    let manifest = std::str::from_utf8(bytes).map_err(|error| {
        failure(
            "ORT_DEPENDENCY_CONTRACT",
            format!("Cargo.toml is not UTF-8: {error}"),
        )
    })?;
    let value: toml::Value = toml::from_str(manifest).map_err(|error| {
        failure(
            "ORT_DEPENDENCY_CONTRACT",
            format!("parse Cargo.toml: {error}"),
        )
    })?;
    let package = value
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            failure(
                "ORT_DEPENDENCY_CONTRACT",
                "package table missing".to_string(),
            )
        })?;
    if package.get("build").and_then(toml::Value::as_str) != Some("build.rs") {
        return Err(failure(
            "ORT_DEPENDENCY_CONTRACT",
            "package.build must be build.rs".to_string(),
        ));
    }
    let ort = value
        .get("dependencies")
        .and_then(|dependencies| dependencies.get("ort"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            failure(
                "ORT_DEPENDENCY_CONTRACT",
                "ort dependency table missing".to_string(),
            )
        })?;
    let version = ort.get("version").and_then(toml::Value::as_str);
    let default_features = ort.get("default-features").and_then(toml::Value::as_bool);
    let features = ort
        .get("features")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            failure(
                "ORT_DEPENDENCY_CONTRACT",
                "ort features missing".to_string(),
            )
        })?
        .iter()
        .map(|feature| {
            feature.as_str().map(str::to_string).ok_or_else(|| {
                failure(
                    "ORT_DEPENDENCY_CONTRACT",
                    "ort feature is not a string".to_string(),
                )
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = BTreeSet::from([
        "api-24".to_string(),
        "ndarray".to_string(),
        "std".to_string(),
    ]);
    let doctest = value
        .get("lib")
        .and_then(toml::Value::as_table)
        .and_then(|library| library.get("doctest"))
        .and_then(toml::Value::as_bool);
    if version != Some("=2.0.0-rc.12")
        || default_features != Some(false)
        || features != expected
        || doctest != Some(false)
        || value.get("test").is_some()
    {
        return Err(failure(
            "ORT_DEPENDENCY_CONTRACT",
            format!(
                "ort requires version =2.0.0-rc.12, default-features=false, exact api-24/ndarray/std features, lib.doctest=false, and no test targets; observed version={version:?} default_features={default_features:?} features={features:?} doctest={doctest:?}"
            ),
        ));
    }
    Ok(())
}

fn source_tree_sha256(files: &BTreeMap<String, Vec<u8>>) -> Result<String, (&'static str, String)> {
    let count = u64::try_from(files.len()).map_err(|_| {
        failure(
            "FILE_COUNT_OVERFLOW",
            "attested file count does not fit u64".to_string(),
        )
    })?;
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update(count.to_le_bytes());
    for (path, bytes) in files {
        let path_bytes = path.as_bytes();
        let path_len = u64::try_from(path_bytes.len()).map_err(|_| {
            failure(
                "PATH_LENGTH_OVERFLOW",
                format!("{path} length does not fit u64"),
            )
        })?;
        let content_len = u64::try_from(bytes.len()).map_err(|_| {
            failure(
                "FILE_SIZE_OVERFLOW",
                format!("{path} length does not fit u64"),
            )
        })?;
        hash.update(path_len.to_le_bytes());
        hash.update(path_bytes);
        hash.update(content_len.to_le_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn normalized_path(path: &Path) -> Result<String, (&'static str, String)> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(failure(
                "SOURCE_PATH_INVALID",
                format!("{} is not a normal relative path", path.display()),
            ));
        };
        parts.push(part.to_str().ok_or_else(|| {
            failure(
                "SOURCE_PATH_NON_UTF8",
                format!("{} is not UTF-8", path.display()),
            )
        })?);
    }
    Ok(parts.join("/"))
}

fn validate_relative_path(path: &str) -> Result<(), (&'static str, String)> {
    let native = native_path(path);
    if path.is_empty()
        || path.contains('\\')
        || native.is_absolute()
        || native
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path == RECEIPT_FILE
    {
        return Err(failure(
            "RECEIPT_PATH_INVALID",
            format!("receipt path is not safe and normalized: {path}"),
        ));
    }
    Ok(())
}

fn native_path(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn failure(code: &'static str, detail: String) -> (&'static str, String) {
    (code, detail)
}
