//! Shared-object Git materialization for kernel-farm probes (#907).
//!
//! This is deliberately a strict source-repo read model, not a convenience clone
//! wrapper: the source repository is the source of truth, the destination borrows
//! its object store through Git alternates, and post-action readback verifies that
//! no destination pack was created.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use calyx_core::CalyxError;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const ASTRO_FLEET_SHARED_CHECKOUT_CONFIG: &str = "ASTRO_FLEET_SHARED_CHECKOUT_CONFIG";
pub const ASTRO_FLEET_SHARED_CHECKOUT_GIT: &str = "ASTRO_FLEET_SHARED_CHECKOUT_GIT";
pub const ASTRO_FLEET_SHARED_CHECKOUT_VERIFY: &str = "ASTRO_FLEET_SHARED_CHECKOUT_VERIFY";
pub const ASTRO_FLEET_SHARED_CHECKOUT_DRIFT: &str = "ASTRO_FLEET_SHARED_CHECKOUT_DRIFT";
pub const ASTRO_FLEET_SHARED_CHECKOUT_OUTPUT: &str = "ASTRO_FLEET_SHARED_CHECKOUT_OUTPUT";

const REMEDIATE_CONFIG: &str = "pass an existing local Git source, an absent destination, a valid commit, and repo-relative paths";
const REMEDIATE_GIT: &str =
    "inspect the structured Git stderr/stdout detail, fix the source repository, then rerun";
const REMEDIATE_VERIFY: &str =
    "inspect the destination alternates/pack readback; the shared checkout must not copy Git packs";
const REMEDIATE_DRIFT: &str =
    "stop concurrent source-repo mutation, re-read the source pack inventory, then rerun";
pub const REMEDIATE_OUTPUT: &str =
    "inspect the shared checkout report schema and fix non-serializable output fields";

#[derive(Debug, Clone)]
pub struct SharedCheckoutConfig {
    pub source_repo: PathBuf,
    pub destination: PathBuf,
    pub commit: Option<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedCheckoutReport {
    pub mode: &'static str,
    pub source_repo: String,
    pub source_git_dir: String,
    pub source_objects_dir: String,
    pub destination: String,
    pub destination_git_dir: String,
    pub destination_objects_dir: String,
    pub requested_commit: String,
    pub resolved_commit: String,
    pub destination_head_commit: String,
    pub requested_paths: Vec<String>,
    pub requested_path_objects: Vec<PathObject>,
    pub source_pack_inventory_before: FileInventory,
    pub source_pack_inventory_after: FileInventory,
    pub destination_pack_inventory: FileInventory,
    pub destination_alternates: Vec<String>,
    pub checkout_config: CheckoutConfigReadback,
    pub sparse_checkout: SparseCheckoutReadback,
    pub working_tree_status: Vec<String>,
    pub materialized: MaterializedInventory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileInventory {
    pub root: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub sha256: String,
    pub files: Vec<FileInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileInventoryEntry {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaterializedInventory {
    pub root: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub sha256: String,
    pub files: Vec<MaterializedFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaterializedFile {
    pub relative_path: String,
    pub kind: &'static str,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathObject {
    pub path: String,
    pub object_oid: String,
    pub object_type: String,
    pub object_mode: String,
    pub object_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckoutConfigReadback {
    pub source_effective: Vec<GitConfigEntry>,
    pub destination_effective: Vec<GitConfigEntry>,
    pub source_local_filters: Vec<GitConfigEntry>,
    pub destination_local_filters: Vec<GitConfigEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitConfigEntry {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SparseCheckoutReadback {
    pub core_sparse_checkout: Option<String>,
    pub core_sparse_checkout_cone: Option<String>,
    pub index_sparse: Option<String>,
    pub patterns: Vec<String>,
}

pub fn create_shared_checkout(
    config: &SharedCheckoutConfig,
) -> Result<SharedCheckoutReport, CalyxError> {
    validate_destination_absent(&config.destination)?;
    let source_repo = canonical_dir(&config.source_repo, "source repo")?;
    ensure_git_work_tree(&source_repo)?;
    let requested_commit = config.commit.clone().unwrap_or_else(|| "HEAD".to_string());
    let resolved_commit = resolve_commit(&source_repo, &requested_commit)?;
    let requested_paths = normalize_requested_paths(&config.paths)?;
    let requested_path_objects = if requested_paths.is_empty() {
        Vec::new()
    } else {
        preflight_requested_paths(&source_repo, &resolved_commit, &requested_paths)?
    };
    let source_git_dir = git_absolute_path(&source_repo, &["rev-parse", "--absolute-git-dir"])?;
    let source_objects_dir = git_absolute_path(
        &source_repo,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    )?;
    let source_pack_inventory_before = pack_inventory(&source_objects_dir)?;
    let destination_parent = config.destination.parent().ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!(
            "destination {} has no parent directory",
            config.destination.display()
        ),
        remediation: REMEDIATE_CONFIG,
    })?;
    fs::create_dir_all(destination_parent).map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!(
            "cannot create destination parent {}: {error}",
            destination_parent.display()
        ),
        remediation: REMEDIATE_CONFIG,
    })?;

    let source_clone_arg = git_cli_path_arg(&source_repo)?;
    let destination_clone_arg = git_cli_path_arg(&config.destination)?;
    git_run(
        None,
        &[
            "clone",
            "--shared",
            "--no-checkout",
            "--",
            source_clone_arg.as_str(),
            destination_clone_arg.as_str(),
        ],
    )?;
    let destination = canonical_dir(&config.destination, "destination")?;
    let destination_git_dir =
        git_absolute_path(&destination, &["rev-parse", "--absolute-git-dir"])?;
    let destination_objects_dir = git_absolute_path(
        &destination,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    )?;
    verify_alternates(&destination_objects_dir, &source_objects_dir)?;
    verify_no_destination_packs(&destination_objects_dir)?;
    let checkout_config = mirror_checkout_config(&source_repo, &destination)?;

    if requested_paths.is_empty() {
        git_run(
            Some(&destination),
            &["checkout", "--force", resolved_commit.as_str()],
        )?;
    } else {
        configure_sparse_checkout(&destination, &requested_paths)?;
        git_run(
            Some(&destination),
            &["checkout", "--force", resolved_commit.as_str()],
        )?;
    }

    let destination_head_commit =
        git_text(&destination, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let source_pack_inventory_after = pack_inventory(&source_objects_dir)?;
    if source_pack_inventory_before != source_pack_inventory_after {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_DRIFT,
            message: format!(
                "source pack inventory changed while materializing shared checkout from {}",
                source_repo.display()
            ),
            remediation: REMEDIATE_DRIFT,
        });
    }
    let destination_pack_inventory = pack_inventory(&destination_objects_dir)?;
    if destination_pack_inventory.file_count != 0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "shared checkout at {} created {} destination pack file(s)",
                destination.display(),
                destination_pack_inventory.file_count
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    let destination_alternates = read_alternates(&destination_objects_dir)?;
    let materialized = materialized_inventory(&destination)?;
    verify_materialized_paths(&requested_paths, &materialized)?;
    let sparse_checkout = read_sparse_checkout(&destination, &destination_git_dir)?;
    verify_sparse_checkout(&requested_paths, &sparse_checkout)?;
    let working_tree_status = git_status_porcelain(&destination)?;
    if !working_tree_status.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "shared checkout at {} is dirty after materialization: {:?}",
                destination.display(),
                working_tree_status
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    Ok(SharedCheckoutReport {
        mode: if requested_paths.is_empty() {
            "full_commit"
        } else {
            "path_subset"
        },
        source_repo: display_path(&source_repo)?,
        source_git_dir: display_path(&source_git_dir)?,
        source_objects_dir: display_path(&source_objects_dir)?,
        destination: display_path(&destination)?,
        destination_git_dir: display_path(&destination_git_dir)?,
        destination_objects_dir: display_path(&destination_objects_dir)?,
        requested_commit,
        resolved_commit,
        destination_head_commit,
        requested_paths,
        requested_path_objects,
        source_pack_inventory_before,
        source_pack_inventory_after,
        destination_pack_inventory,
        destination_alternates,
        checkout_config,
        sparse_checkout,
        working_tree_status,
        materialized,
    })
}

fn validate_destination_absent(destination: &Path) -> Result<(), CalyxError> {
    match destination.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!(
                "destination {} already exists; shared checkout requires an absent destination",
                destination.display()
            ),
            remediation: REMEDIATE_CONFIG,
        }),
        Err(error) => Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!(
                "cannot inspect destination {}: {error}",
                destination.display()
            ),
            remediation: REMEDIATE_CONFIG,
        }),
    }
}

fn canonical_dir(path: &Path, role: &str) -> Result<PathBuf, CalyxError> {
    let canonical = fs::canonicalize(path).map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!("cannot canonicalize {role} {}: {error}", path.display()),
        remediation: REMEDIATE_CONFIG,
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!("cannot inspect {role} {}: {error}", canonical.display()),
        remediation: REMEDIATE_CONFIG,
    })?;
    if !metadata.is_dir() {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!("{role} {} is not a directory", canonical.display()),
            remediation: REMEDIATE_CONFIG,
        });
    }
    Ok(canonical)
}

fn ensure_git_work_tree(repo: &Path) -> Result<(), CalyxError> {
    let inside = git_text(repo, &["rev-parse", "--is-inside-work-tree"])?;
    if inside == "true" {
        Ok(())
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!("source {} is not a Git work tree", repo.display()),
            remediation: REMEDIATE_CONFIG,
        })
    }
}

fn resolve_commit(repo: &Path, commit: &str) -> Result<String, CalyxError> {
    if commit.trim().is_empty() || commit.contains('\0') {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: "requested commit is empty or contains NUL".to_string(),
            remediation: REMEDIATE_CONFIG,
        });
    }
    let query = format!("{commit}^{{commit}}");
    let resolved = git_text(repo, &["rev-parse", "--verify", query.as_str()])?;
    if is_oid(&resolved) {
        Ok(resolved)
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!("Git resolved {commit:?} to non-OID output {resolved:?}"),
            remediation: REMEDIATE_VERIFY,
        })
    }
}

fn normalize_requested_paths(paths: &[String]) -> Result<Vec<String>, CalyxError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for path in paths {
        if path.is_empty()
            || path.contains('\0')
            || path.contains('\n')
            || path.contains('\r')
            || path.contains('\\')
            || Path::new(path).is_absolute()
            || path
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
                message: format!(
                    "requested materialized path {path:?} is not a normalized repo-relative path"
                ),
                remediation: REMEDIATE_CONFIG,
            });
        }
        if seen.insert(path.clone()) {
            normalized.push(path.clone());
        }
    }
    Ok(normalized)
}

fn preflight_requested_paths(
    repo: &Path,
    commit: &str,
    paths: &[String],
) -> Result<Vec<PathObject>, CalyxError> {
    let mut input = Vec::new();
    for path in paths {
        input.extend_from_slice(b"info ");
        input.extend_from_slice(commit.as_bytes());
        input.push(b':');
        input.extend_from_slice(path.as_bytes());
        input.push(0);
    }
    input.extend_from_slice(b"flush");
    input.push(0);
    let output = git_with_stdin(
        repo,
        &[
            "cat-file",
            "--batch-command=%(objectname) %(objecttype) %(objectmode) %(objectsize)",
            "--buffer",
            "-Z",
        ],
        &input,
    )?;
    let mut records = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    while records.last().is_some_and(|record| record.is_empty()) {
        records.pop();
    }
    if records.len() != paths.len() {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "Git cat-file path preflight returned {} records for {} requested paths",
                records.len(),
                paths.len()
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    let mut objects = Vec::new();
    for (path, record) in paths.iter().zip(records) {
        let record = std::str::from_utf8(record).map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!("Git cat-file path preflight output is not UTF-8: {error}"),
            remediation: REMEDIATE_VERIFY,
        })?;
        let query = format!("{commit}:{path}");
        if record == format!("{query} missing") {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
                message: format!("requested path {path:?} is absent at commit {commit}"),
                remediation: REMEDIATE_CONFIG,
            });
        }
        let mut fields = record.split(' ');
        let object_oid = fields.next().unwrap_or_default();
        let object_type = fields.next().unwrap_or_default();
        let object_mode = fields.next().unwrap_or_default();
        let object_size = fields.next().unwrap_or_default();
        if fields.next().is_some() || !is_oid(object_oid) || object_mode.is_empty() {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                message: format!(
                    "Git cat-file path preflight returned an invalid record for {query:?}: {record:?}"
                ),
                remediation: REMEDIATE_VERIFY,
            });
        }
        if object_type != "blob" {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
                message: format!(
                    "requested path {path:?} at commit {commit} is a {object_type}, not a blob"
                ),
                remediation: REMEDIATE_CONFIG,
            });
        }
        if !matches!(object_mode, "100644" | "100755") {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
                message: format!(
                    "requested path {path:?} at commit {commit} has unsupported mode {object_mode}; only regular file modes 100644 and 100755 are materialized"
                ),
                remediation: REMEDIATE_CONFIG,
            });
        }
        let object_size = object_size.parse::<u64>().map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "Git cat-file path preflight returned invalid object size for {query:?}: {object_size:?}: {error}"
            ),
            remediation: REMEDIATE_VERIFY,
        })?;
        objects.push(PathObject {
            path: path.clone(),
            object_oid: object_oid.to_string(),
            object_type: object_type.to_string(),
            object_mode: object_mode.to_string(),
            object_size,
        });
    }
    Ok(objects)
}

fn verify_alternates(
    destination_objects_dir: &Path,
    source_objects_dir: &Path,
) -> Result<(), CalyxError> {
    let source_objects_dir = canonical_dir(source_objects_dir, "source objects dir")?;
    let alternates = read_alternates(destination_objects_dir)?;
    if alternates.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "destination {} has no Git alternates file",
                destination_objects_dir.display()
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    for alternate in &alternates {
        let alternate_path = PathBuf::from(alternate);
        let canonical = fs::canonicalize(&alternate_path).map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!("cannot canonicalize alternate object path {alternate:?}: {error}"),
            remediation: REMEDIATE_VERIFY,
        })?;
        if canonical == source_objects_dir {
            return Ok(());
        }
    }
    Err(CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
        message: format!(
            "destination alternates {:?} do not point at source object store {}",
            alternates,
            source_objects_dir.display()
        ),
        remediation: REMEDIATE_VERIFY,
    })
}

fn verify_no_destination_packs(destination_objects_dir: &Path) -> Result<(), CalyxError> {
    let inventory = pack_inventory(destination_objects_dir)?;
    if inventory.file_count == 0 {
        Ok(())
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "destination object store {} contains {} pack file(s)",
                destination_objects_dir.display(),
                inventory.file_count
            ),
            remediation: REMEDIATE_VERIFY,
        })
    }
}

fn read_alternates(destination_objects_dir: &Path) -> Result<Vec<String>, CalyxError> {
    let path = destination_objects_dir.join("info").join("alternates");
    let text = fs::read_to_string(&path).map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
        message: format!(
            "cannot read destination alternates {}: {error}",
            path.display()
        ),
        remediation: REMEDIATE_VERIFY,
    })?;
    let mut lines = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    Ok(lines)
}

fn mirror_checkout_config(
    source_repo: &Path,
    destination: &Path,
) -> Result<CheckoutConfigReadback, CalyxError> {
    let source_effective = read_effective_checkout_config(source_repo)?;
    for entry in &source_effective {
        if let Some(value) = &entry.value {
            git_run(
                Some(destination),
                &["config", "--local", entry.key.as_str(), value.as_str()],
            )?;
        }
    }
    let source_local_filters = read_local_filter_config(source_repo)?;
    for entry in &source_local_filters {
        let value = entry.value.as_deref().ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "source filter config {} unexpectedly had no value",
                entry.key
            ),
            remediation: REMEDIATE_VERIFY,
        })?;
        git_run(
            Some(destination),
            &["config", "--local", entry.key.as_str(), value],
        )?;
    }
    let destination_effective = read_effective_checkout_config(destination)?;
    let destination_local_filters = read_local_filter_config(destination)?;
    if source_effective != destination_effective {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "destination checkout config does not match source after mirror: source={source_effective:?} destination={destination_effective:?}"
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    if source_local_filters != destination_local_filters {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "destination local filter config does not match source after mirror: source={source_local_filters:?} destination={destination_local_filters:?}"
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    Ok(CheckoutConfigReadback {
        source_effective,
        destination_effective,
        source_local_filters,
        destination_local_filters,
    })
}

fn configure_sparse_checkout(destination: &Path, paths: &[String]) -> Result<(), CalyxError> {
    let patterns = sparse_checkout_patterns(paths);
    let mut args = vec![
        "sparse-checkout",
        "set",
        "--no-cone",
        "--no-sparse-index",
        "--",
    ];
    for pattern in &patterns {
        args.push(pattern.as_str());
    }
    git_run(Some(destination), &args)
}

fn sparse_checkout_patterns(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .map(|path| {
            let mut pattern = String::from("/");
            for ch in path.chars() {
                if matches!(ch, '*' | '?' | '[' | ']') {
                    pattern.push('\\');
                }
                pattern.push(ch);
            }
            pattern
        })
        .collect()
}

fn read_sparse_checkout(
    destination: &Path,
    destination_git_dir: &Path,
) -> Result<SparseCheckoutReadback, CalyxError> {
    let sparse_checkout_path = destination_git_dir.join("info").join("sparse-checkout");
    let patterns = if sparse_checkout_path
        .try_exists()
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "cannot inspect sparse-checkout file {}: {error}",
                sparse_checkout_path.display()
            ),
            remediation: REMEDIATE_VERIFY,
        })? {
        fs::read_to_string(&sparse_checkout_path)
            .map_err(|error| CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                message: format!(
                    "cannot read sparse-checkout file {}: {error}",
                    sparse_checkout_path.display()
                ),
                remediation: REMEDIATE_VERIFY,
            })?
            .lines()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    Ok(SparseCheckoutReadback {
        core_sparse_checkout: git_config_optional(
            destination,
            &["config", "--get", "--bool", "core.sparseCheckout"],
        )?,
        core_sparse_checkout_cone: git_config_optional(
            destination,
            &["config", "--get", "--bool", "core.sparseCheckoutCone"],
        )?,
        index_sparse: git_config_optional(
            destination,
            &["config", "--get", "--bool", "index.sparse"],
        )?,
        patterns,
    })
}

fn verify_sparse_checkout(
    requested_paths: &[String],
    readback: &SparseCheckoutReadback,
) -> Result<(), CalyxError> {
    if requested_paths.is_empty() {
        if readback.core_sparse_checkout.as_deref() == Some("true") || !readback.patterns.is_empty()
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                message: format!(
                    "full shared checkout unexpectedly has sparse-checkout state: {readback:?}"
                ),
                remediation: REMEDIATE_VERIFY,
            });
        }
        return Ok(());
    }

    let expected_patterns = sparse_checkout_patterns(requested_paths);
    if readback.core_sparse_checkout.as_deref() != Some("true")
        || readback.core_sparse_checkout_cone.as_deref() != Some("false")
        || readback.index_sparse.as_deref() == Some("true")
        || readback.patterns != expected_patterns
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "path-subset shared checkout sparse state mismatch: expected patterns {:?}, readback {:?}",
                expected_patterns, readback
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    Ok(())
}

fn verify_materialized_paths(
    requested_paths: &[String],
    materialized: &MaterializedInventory,
) -> Result<(), CalyxError> {
    if requested_paths.is_empty() {
        return Ok(());
    }
    let requested = requested_paths.iter().cloned().collect::<BTreeSet<_>>();
    let actual = materialized
        .files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    if actual != requested {
        return Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "path-subset shared checkout materialized wrong file set: requested {:?}, actual {:?}",
                requested, actual
            ),
            remediation: REMEDIATE_VERIFY,
        });
    }
    Ok(())
}

fn git_status_porcelain(repo: &Path) -> Result<Vec<String>, CalyxError> {
    let text = git_text(repo, &["status", "--porcelain=v1"])?;
    if text.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(text.lines().map(str::to_string).collect())
    }
}

fn read_effective_checkout_config(repo: &Path) -> Result<Vec<GitConfigEntry>, CalyxError> {
    const CHECKOUT_CONFIG_KEYS: &[&str] = &[
        "core.autocrlf",
        "core.eol",
        "core.attributesfile",
        "attr.tree",
    ];

    let mut entries = Vec::new();
    for key in CHECKOUT_CONFIG_KEYS {
        entries.push(GitConfigEntry {
            key: (*key).to_string(),
            value: git_config_optional(repo, &["config", "--get", key])?,
        });
    }
    Ok(entries)
}

fn read_local_filter_config(repo: &Path) -> Result<Vec<GitConfigEntry>, CalyxError> {
    let output = git_config_optional(
        repo,
        &[
            "config",
            "--local",
            "--get-regexp",
            r"^filter\..*\.\(clean\|smudge\|process\|required\)$",
        ],
    )?;
    let Some(output) = output else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                message: format!("Git filter config line has no value: {line:?}"),
                remediation: REMEDIATE_VERIFY,
            });
        };
        entries.push(GitConfigEntry {
            key: key.to_ascii_lowercase(),
            value: Some(value.to_string()),
        });
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(entries)
}

fn git_config_optional(repo: &Path, args: &[&str]) -> Result<Option<String>, CalyxError> {
    let (ok, stdout, stderr) = git_capture(Some(repo), args)?;
    if ok {
        return Ok(Some(stdout.trim().to_string()));
    }
    if stdout.trim().is_empty() && stderr.trim().is_empty() {
        Ok(None)
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: format!(
                "git -C {} {} failed while reading checkout config: stdout={:?} stderr={:?}",
                repo.display(),
                args.join(" "),
                stdout.trim(),
                stderr.trim()
            ),
            remediation: REMEDIATE_GIT,
        })
    }
}

fn pack_inventory(objects_dir: &Path) -> Result<FileInventory, CalyxError> {
    let pack_dir = objects_dir.join("pack");
    let root = if pack_dir.try_exists().map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!("cannot inspect pack dir {}: {error}", pack_dir.display()),
        remediation: REMEDIATE_CONFIG,
    })? {
        canonical_dir(&pack_dir, "Git pack dir")?
    } else {
        pack_dir
    };
    let mut files = Vec::new();
    if root.try_exists().map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!(
            "cannot inspect pack inventory root {}: {error}",
            root.display()
        ),
        remediation: REMEDIATE_CONFIG,
    })? {
        collect_pack_files(&root, &root, &mut files)?;
    }
    finalize_file_inventory(root, files)
}

fn collect_pack_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<FileInventoryEntry>,
) -> Result<(), CalyxError> {
    let mut entries = fs::read_dir(dir)
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!("cannot read pack inventory dir {}: {error}", dir.display()),
            remediation: REMEDIATE_CONFIG,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!(
                "cannot enumerate pack inventory dir {}: {error}",
                dir.display()
            ),
            remediation: REMEDIATE_CONFIG,
        })?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
            message: format!(
                "cannot inspect pack inventory path {}: {error}",
                path.display()
            ),
            remediation: REMEDIATE_CONFIG,
        })?;
        if metadata.is_dir() {
            collect_pack_files(root, &path, files)?;
        } else if metadata.is_file()
            && matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("pack" | "idx" | "rev" | "bitmap")
            )
        {
            files.push(FileInventoryEntry {
                relative_path: relative_display(root, &path)?,
                bytes: metadata.len(),
                sha256: sha256_file(&path)?,
            });
        }
    }
    Ok(())
}

fn finalize_file_inventory(
    root: PathBuf,
    mut files: Vec<FileInventoryEntry>,
) -> Result<FileInventory, CalyxError> {
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let total_bytes = files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.bytes))
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "file inventory byte total overflowed for {}",
                root.display()
            ),
            remediation: REMEDIATE_VERIFY,
        })?;
    let mut hasher = Sha256::new();
    for file in &files {
        hash_field(&mut hasher, file.relative_path.as_bytes());
        hash_field(&mut hasher, &file.bytes.to_be_bytes());
        hash_field(&mut hasher, file.sha256.as_bytes());
    }
    Ok(FileInventory {
        root: display_path(&root)?,
        file_count: files.len(),
        total_bytes,
        sha256: hex_lower(&hasher.finalize()),
        files,
    })
}

fn materialized_inventory(root: &Path) -> Result<MaterializedInventory, CalyxError> {
    let mut files = Vec::new();
    collect_materialized_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let total_bytes = files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.bytes))
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "materialized file inventory byte total overflowed for {}",
                root.display()
            ),
            remediation: REMEDIATE_VERIFY,
        })?;
    let mut hasher = Sha256::new();
    for file in &files {
        hash_field(&mut hasher, file.relative_path.as_bytes());
        hash_field(&mut hasher, file.kind.as_bytes());
        hash_field(&mut hasher, &file.bytes.to_be_bytes());
        hash_field(&mut hasher, file.sha256.as_bytes());
    }
    Ok(MaterializedInventory {
        root: display_path(root)?,
        file_count: files.len(),
        total_bytes,
        sha256: hex_lower(&hasher.finalize()),
        files,
    })
}

fn collect_materialized_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<MaterializedFile>,
) -> Result<(), CalyxError> {
    let mut entries = fs::read_dir(dir)
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!("cannot read materialized dir {}: {error}", dir.display()),
            remediation: REMEDIATE_VERIFY,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "cannot enumerate materialized dir {}: {error}",
                dir.display()
            ),
            remediation: REMEDIATE_VERIFY,
        })?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some(".git") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!(
                "cannot inspect materialized path {}: {error}",
                path.display()
            ),
            remediation: REMEDIATE_VERIFY,
        })?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            collect_materialized_files(root, &path, files)?;
        } else if file_type.is_file() {
            files.push(MaterializedFile {
                relative_path: relative_display(root, &path)?,
                kind: "file",
                bytes: metadata.len(),
                sha256: sha256_file(&path)?,
            });
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|error| CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                message: format!(
                    "cannot read materialized symlink {}: {error}",
                    path.display()
                ),
                remediation: REMEDIATE_VERIFY,
            })?;
            let target = path_to_utf8(&target)?;
            files.push(MaterializedFile {
                relative_path: relative_display(root, &path)?,
                kind: "symlink",
                bytes: u64::try_from(target.len()).map_err(|_| CalyxError {
                    code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                    message: format!("symlink target length overflowed for {}", path.display()),
                    remediation: REMEDIATE_VERIFY,
                })?,
                sha256: sha256_bytes(target.as_bytes()),
            });
        } else {
            return Err(CalyxError {
                code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                message: format!(
                    "materialized path {} is not a file, directory, or symlink",
                    path.display()
                ),
                remediation: REMEDIATE_VERIFY,
            });
        }
    }
    Ok(())
}

fn git_absolute_path(repo: &Path, args: &[&str]) -> Result<PathBuf, CalyxError> {
    let text = git_text(repo, args)?;
    let path = PathBuf::from(text);
    canonical_dir(&path, "Git path")
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String, CalyxError> {
    let (ok, stdout, stderr) = git_capture(Some(repo), args)?;
    if ok {
        Ok(stdout.trim().to_string())
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: format!(
                "git -C {} {} failed: stdout={:?} stderr={:?}",
                repo.display(),
                args.join(" "),
                stdout.trim(),
                stderr.trim()
            ),
            remediation: REMEDIATE_GIT,
        })
    }
}

fn git_run(cwd: Option<&Path>, args: &[&str]) -> Result<(), CalyxError> {
    let (ok, stdout, stderr) = git_capture(cwd, args)?;
    if ok {
        Ok(())
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: format!(
                "git {} failed: cwd={} stdout={:?} stderr={:?}",
                args.join(" "),
                cwd.map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
                stdout.trim(),
                stderr.trim()
            ),
            remediation: REMEDIATE_GIT,
        })
    }
}

fn git_with_stdin(repo: &Path, args: &[&str], stdin: &[u8]) -> Result<Vec<u8>, CalyxError> {
    use std::io::Write;

    let mut command = git_command(Some(repo), args);
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = command.spawn().map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
        message: format!(
            "failed to spawn git -C {} {}: {error}",
            repo.display(),
            args.join(" ")
        ),
        remediation: REMEDIATE_GIT,
    })?;
    {
        let mut child_stdin = child.stdin.take().ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: "Git stdin was unavailable for shared-checkout preflight".to_string(),
            remediation: REMEDIATE_GIT,
        })?;
        child_stdin.write_all(stdin).map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: format!("failed to write git stdin for {}: {error}", args.join(" ")),
            remediation: REMEDIATE_GIT,
        })?;
    }
    let output = child.wait_with_output().map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
        message: format!("failed to wait for git {}: {error}", args.join(" ")),
        remediation: REMEDIATE_GIT,
    })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: format!(
                "git -C {} {} failed: stderr={:?}",
                repo.display(),
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            remediation: REMEDIATE_GIT,
        })
    }
}

fn git_capture(cwd: Option<&Path>, args: &[&str]) -> Result<(bool, String, String), CalyxError> {
    let output = git_command(cwd, args)
        .output()
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_GIT,
            message: format!("failed to spawn git {}: {error}", args.join(" ")),
            remediation: REMEDIATE_GIT,
        })?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

fn git_command(cwd: Option<&Path>, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .args(["-c", "credential.helper="])
        .args(["-c", "core.longpaths=true"])
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args);
    crate::clone_farm::silence_credential_prompts(&mut command);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
}

fn git_cli_path_arg(path: &Path) -> Result<String, CalyxError> {
    let text = path.to_str().ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!("path {} is not valid UTF-8", path.display()),
        remediation: REMEDIATE_CONFIG,
    })?;
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        Ok(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        Ok(rest.to_string())
    } else {
        Ok(text.to_string())
    }
}

fn path_to_utf8(path: &Path) -> Result<String, CalyxError> {
    path.to_str().map(str::to_string).ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
        message: format!("path {} is not valid UTF-8", path.display()),
        remediation: REMEDIATE_VERIFY,
    })
}

fn relative_display(root: &Path, path: &Path) -> Result<String, CalyxError> {
    let relative = path.strip_prefix(root).map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
        message: format!(
            "path {} is not below inventory root {}: {error}",
            path.display(),
            root.display()
        ),
        remediation: REMEDIATE_VERIFY,
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| CalyxError {
                    code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                    message: format!("relative path {} is not valid UTF-8", relative.display()),
                    remediation: REMEDIATE_VERIFY,
                })?;
                parts.push(part.to_string());
            }
            other => {
                return Err(CalyxError {
                    code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
                    message: format!(
                        "relative path {} contains unexpected component {other:?}",
                        relative.display()
                    ),
                    remediation: REMEDIATE_VERIFY,
                });
            }
        }
    }
    Ok(parts.join("/"))
}

fn display_path(path: &Path) -> Result<String, CalyxError> {
    path.to_str()
        .map(|text| text.replace('\\', "/"))
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!("path {} is not valid UTF-8", path.display()),
            remediation: REMEDIATE_VERIFY,
        })
}

fn sha256_file(path: &Path) -> Result<String, CalyxError> {
    let mut file = fs::File::open(path).map_err(|error| CalyxError {
        code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
        message: format!("cannot open {} for SHA-256: {error}", path.display()),
        remediation: REMEDIATE_VERIFY,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| CalyxError {
            code: ASTRO_FLEET_SHARED_CHECKOUT_VERIFY,
            message: format!("cannot read {} for SHA-256: {error}", path.display()),
            remediation: REMEDIATE_VERIFY,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
