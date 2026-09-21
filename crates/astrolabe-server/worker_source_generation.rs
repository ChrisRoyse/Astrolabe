use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

pub const SOURCE_GENERATION_SCHEMA: &str = "astrolabe.worker-source-generation.v1";
pub const SOURCE_INPUTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo",
    "crates",
    "calyx",
    "cbm",
    "patches",
];

#[derive(Debug)]
pub struct SourceGenerationError(String);

impl fmt::Display for SourceGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SourceGenerationError {}

fn error(message: impl Into<String>) -> SourceGenerationError {
    SourceGenerationError(message.into())
}

fn ordinary_file(metadata: &fs::Metadata) -> bool {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;
        metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0
    }
    #[cfg(not(windows))]
    {
        true
    }
}

fn git_executable() -> &'static str {
    if cfg!(windows) { "git.exe" } else { "git" }
}

fn git_output(root: &Path, args: &[&str]) -> Result<Output, SourceGenerationError> {
    let executable = git_executable();
    Command::new(executable)
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|cause| error(format!("could not execute {executable} {args:?}: {cause}")))
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, SourceGenerationError> {
    let executable = git_executable();
    let output = git_output(root, args)?;
    if !output.status.success() {
        return Err(error(format!(
            "{executable} {args:?} failed with exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

fn frame(digest: &mut Sha256, label: &[u8], value: &[u8]) {
    digest.update((label.len() as u64).to_le_bytes());
    digest.update(label);
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}

fn git_path(root: &Path, args: &[&str], context: &str) -> Result<PathBuf, SourceGenerationError> {
    let raw = git(root, args)?;
    let value = std::str::from_utf8(&raw)
        .map_err(|cause| error(format!("{context} is not UTF-8: {cause}")))?
        .trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err(error(format!("{context} is empty")));
    }
    Ok(PathBuf::from(value))
}

pub fn git_rerun_inputs(root: &Path) -> Result<Vec<PathBuf>, SourceGenerationError> {
    let git_dir = git_path(
        root,
        &["rev-parse", "--path-format=absolute", "--git-dir"],
        "absolute Git directory",
    )?;
    let common_dir = git_path(
        root,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        "absolute Git common directory",
    )?;
    let index = git_path(
        root,
        &["rev-parse", "--path-format=absolute", "--git-path", "index"],
        "absolute Git index path",
    )?;
    let mut paths = vec![
        git_dir.join("HEAD"),
        git_dir.join("commondir"),
        common_dir.join("packed-refs"),
        index,
    ];

    let symbolic_args = ["symbolic-ref", "--quiet", "HEAD"];
    let symbolic = git_output(root, &symbolic_args)?;
    match symbolic.status.code() {
        Some(0) => {
            let reference = std::str::from_utf8(&symbolic.stdout)
                .map_err(|cause| error(format!("symbolic HEAD is not UTF-8: {cause}")))?
                .trim_end_matches(['\r', '\n']);
            if reference.is_empty() {
                return Err(error("symbolic HEAD is empty"));
            }
            paths.push(git_path(
                root,
                &[
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    reference,
                ],
                "absolute symbolic HEAD reference path",
            )?);
        }
        Some(1) => {}
        other => {
            return Err(error(format!(
                "git {symbolic_args:?} failed with exit {other:?}: {}",
                String::from_utf8_lossy(&symbolic.stderr)
            )));
        }
    }
    if paths
        .iter()
        .any(|path| !path.is_absolute() || path.as_os_str().is_empty())
    {
        return Err(error(format!(
            "Git rerun inputs are not exact nonempty absolute paths: {paths:?}"
        )));
    }
    Ok(paths)
}

pub fn source_generation_sha256(root: &Path) -> Result<String, SourceGenerationError> {
    let head = git(root, &["rev-parse", "HEAD"])?;
    let mut diff_args = vec!["diff", "--binary", "HEAD", "--"];
    diff_args.extend_from_slice(SOURCE_INPUTS);
    let diff = git(root, &diff_args)?;
    let mut untracked_args = vec!["ls-files", "--others", "--exclude-standard", "-z", "--"];
    untracked_args.extend_from_slice(SOURCE_INPUTS);
    let untracked = git(root, &untracked_args)?;

    let mut digest = Sha256::new();
    frame(&mut digest, b"schema", SOURCE_GENERATION_SCHEMA.as_bytes());
    frame(&mut digest, b"head", &head);
    frame(&mut digest, b"diff", &diff);
    frame(&mut digest, b"untracked-roster", &untracked);
    for raw_path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let text = std::str::from_utf8(raw_path)
            .map_err(|cause| error(format!("untracked path is not UTF-8: {cause}")))?;
        let relative = PathBuf::from(text);
        if relative.is_absolute()
            || !relative
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(error(format!(
                "untracked source path is not one root-relative ordinary path: {text:?}"
            )));
        }
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|cause| {
            error(format!(
                "could not inspect untracked source {text:?}: {cause}"
            ))
        })?;
        if !ordinary_file(&metadata) {
            return Err(error(format!(
                "untracked source is not one ordinary file: {text:?}"
            )));
        }
        let bytes = fs::read(&path)
            .map_err(|cause| error(format!("could not read untracked source {text:?}: {cause}")))?;
        let byte_len = u64::try_from(bytes.len()).map_err(|cause| {
            error(format!(
                "untracked source length overflow: {text:?}: {cause}"
            ))
        })?;
        let readback = fs::symlink_metadata(&path).map_err(|cause| {
            error(format!(
                "could not re-read untracked source {text:?} after hashing: {cause}"
            ))
        })?;
        if !ordinary_file(&readback)
            || metadata.len() != byte_len
            || readback.len() != metadata.len()
        {
            return Err(error(format!(
                "untracked source changed type or length while hashing: {text:?}"
            )));
        }
        frame(&mut digest, raw_path, &bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}
