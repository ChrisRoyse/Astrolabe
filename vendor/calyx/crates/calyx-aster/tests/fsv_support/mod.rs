#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use calyx_fsv::ScratchDir;

// #260: every scratch root these helpers hand back is now a `calyx_fsv::ScratchDir`
// RAII guard. An unset `env_key` yields an *armed* fallback that removes its
// directory on drop — on normal return, early return, and panic unwind — closing
// the leak that flaked the aggregate (#237/#278). A configured `env_key` yields a
// *kept* (disarmed) guard so the operator's evidence survives for inspection.
// `ScratchDir` derefs to `Path`, so existing call sites (`root.join(..)`, `&root`,
// `reset_dir(&root)`) keep compiling once they bind the guard for the test's life.
// The returned `bool` (where present) is `is_kept()` — same meaning as before:
// `true` == operator-configured root, `false` == self-cleaning fallback.

pub(crate) fn fsv_root(env_key: &str, fallback_prefix: &str) -> (ScratchDir, bool) {
    let guard = calyx_fsv::scratch_or_temp(env_key, fallback_prefix);
    let kept = guard.is_kept();
    (guard, kept)
}

pub(crate) fn fsv_root_os(env_key: &str, fallback_prefix: &str) -> ScratchDir {
    calyx_fsv::scratch_or_temp(env_key, fallback_prefix)
}

pub(crate) fn fsv_root_env_subdir(
    env_key: &str,
    env_subdir: &str,
    fallback_prefix: &str,
) -> (ScratchDir, bool) {
    match calyx_fsv::fsv_root(env_key) {
        Some(root) => (ScratchDir::kept(root.join(env_subdir)), true),
        None => (fallback_scratch(fallback_prefix), false),
    }
}

pub(crate) fn named_fsv_root(env_key: &str, name: &str) -> (ScratchDir, bool) {
    match calyx_fsv::fsv_root(env_key) {
        Some(root) => (ScratchDir::kept(root), true),
        None => (named_temp_root(name), false),
    }
}

pub(crate) fn named_fsv_root_os(env_key: &str, name: &str) -> (ScratchDir, bool) {
    named_fsv_root(env_key, name)
}

fn named_temp_root(name: &str) -> ScratchDir {
    temp_root("calyx-aster", name)
}

pub(crate) fn temp_root(prefix: &str, name: &str) -> ScratchDir {
    fallback_scratch(&format!("{prefix}-{name}"))
}

pub(crate) fn prepared_temp_root(prefix: &str, name: &str) -> ScratchDir {
    // `ScratchDir::new_temp` already creates a fresh directory (removing any
    // stale predecessor first), so this is now identical to `temp_root`.
    temp_root(prefix, name)
}

pub(crate) fn env_or_temp_root(
    env_key: &str,
    fallback_prefix: &str,
    fallback_name: &str,
) -> ScratchDir {
    match calyx_fsv::fsv_root(env_key) {
        Some(root) => ScratchDir::kept(root),
        None => temp_root(fallback_prefix, fallback_name),
    }
}

pub(crate) fn env_or_prepared_temp_root(
    env_key: &str,
    fallback_prefix: &str,
    fallback_name: &str,
) -> ScratchDir {
    env_or_temp_root(env_key, fallback_prefix, fallback_name)
}

fn fallback_scratch(prefix: &str) -> ScratchDir {
    ScratchDir::new_temp(prefix).unwrap_or_else(|e| panic!("create fallback scratch {prefix}: {e}"))
}

pub(crate) fn reset_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).expect("create fsv root");
}

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("json")).expect("write json");
}

pub(crate) fn collect_physical_file_states(root: &Path, files: &mut Vec<serde_json::Value>) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_physical_file_states(&path, files);
        } else {
            files.push(serde_json::json!({
                "path": path.display().to_string(),
                "bytes": entry.metadata().unwrap().len(),
            }));
        }
    }
}

pub(crate) fn write_blake3_sums(root: &Path) {
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort();
    let mut lines = String::new();
    for relative in files {
        if relative == Path::new("BLAKE3SUMS.txt") {
            continue;
        }
        let bytes = fs::read(root.join(&relative)).expect("read checksum file");
        lines.push_str(&format!(
            "{}  {}\n",
            blake3_hex(&bytes),
            relative.to_string_lossy().replace('\\', "/")
        ));
    }
    fs::write(root.join("BLAKE3SUMS.txt"), lines).expect("write checksum manifest");
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else {
            files.push(
                path.strip_prefix(root)
                    .expect("relative path")
                    .to_path_buf(),
            );
        }
    }
}

pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
