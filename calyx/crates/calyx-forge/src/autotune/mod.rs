use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{BestConfig, ForgeError, Result};

const CACHE_REMEDIATION: &str = "Inspect the named cache operation and path, preserve malformed bytes for diagnosis, then regenerate the cache only from measured Anneal state and verify its published readback";
const AUTOTUNE_CACHE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutotuneKey {
    pub op: String,
    pub shape: Vec<usize>,
    pub dtype: String,
    pub device: String,
    pub recall_tgt: f32,
}

impl PartialEq for AutotuneKey {
    fn eq(&self, other: &Self) -> bool {
        self.op == other.op
            && self.shape == other.shape
            && self.dtype == other.dtype
            && self.device == other.device
            && self.recall_tgt.to_bits() == other.recall_tgt.to_bits()
    }
}

impl Eq for AutotuneKey {}

impl Hash for AutotuneKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.op.hash(state);
        self.shape.hash(state);
        self.dtype.hash(state);
        self.device.hash(state);
        self.recall_tgt.to_bits().hash(state);
    }
}

#[derive(Clone, Debug)]
pub struct AutotuneCache {
    entries: HashMap<AutotuneKey, BestConfig>,
    path: PathBuf,
    usable: bool,
}

impl AutotuneCache {
    /// Opens an already-published cache. Absence is a configuration error, not
    /// an implicit empty/default cache.
    pub fn open_existing(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|err| cache_error("open_existing", path, format!("read failed: {err}")))?;
        Self::from_bytes(path, &bytes)
    }

    /// Creates and independently reads back a new, explicitly empty cache.
    /// Existing paths are never overwritten by initialization.
    pub fn create_empty(path: &Path) -> Result<Self> {
        let cache = Self {
            entries: HashMap::new(),
            path: path.to_path_buf(),
            usable: true,
        };
        cache.publish_entries(&cache.entries, false)?;
        Ok(cache)
    }

    pub fn get(&self, key: &AutotuneKey) -> Result<Option<&BestConfig>> {
        self.ensure_usable("get")?;
        Ok(self.entries.get(key))
    }

    /// Publishes one candidate transactionally. The live in-memory map changes
    /// only after deterministic bytes have been atomically installed, read
    /// back, decoded, and matched to the staged candidate.
    pub fn apply_and_persist(
        &mut self,
        key: AutotuneKey,
        config: BestConfig,
    ) -> Result<Option<BestConfig>> {
        self.ensure_usable("apply_and_persist")?;
        let mut staged = self.entries.clone();
        let prior = staged.insert(key, config);
        if let Err(error) = self.publish_entries(&staged, true) {
            // Publication may already have replaced the durable path before a
            // readback fault is observed. The old in-memory map must never
            // remain readable as an apparent incumbent after that ambiguity.
            self.usable = false;
            return Err(error);
        }
        self.entries = staged;
        Ok(prior)
    }

    fn publish_entries(
        &self,
        entries: &HashMap<AutotuneKey, BestConfig>,
        replace_existing: bool,
    ) -> Result<()> {
        validate_entries(entries, &self.path)?;
        let bytes = serde_json::to_vec_pretty(&persisted(entries)).map_err(|err| {
            cache_error("persist", &self.path, format!("serialize failed: {err}"))
        })?;
        let tmp = tmp_path_for(&self.path)?;
        write_tmp(&tmp, &bytes)?;
        publish_tmp(&tmp, &self.path, replace_existing)?;
        let observed = fs::read(&self.path).map_err(|err| {
            cache_error(
                "persist_readback",
                &self.path,
                format!("published cache readback failed: {err}"),
            )
        })?;
        if observed != bytes {
            return Err(cache_error(
                "persist_readback",
                &self.path,
                format!(
                    "published cache bytes differ: expected={} observed={}",
                    bytes.len(),
                    observed.len()
                ),
            ));
        }
        let readback = Self::from_bytes(&self.path, &observed)?;
        if readback.entries != *entries {
            return Err(cache_error(
                "persist_readback",
                &self.path,
                "published cache decoded to different entries",
            ));
        }
        Ok(())
    }

    pub fn len(&self) -> Result<usize> {
        self.ensure_usable("len")?;
        Ok(self.entries.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.ensure_usable("is_empty")?;
        Ok(self.entries.is_empty())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_usable(&self, op: &str) -> Result<()> {
        if self.usable {
            return Ok(());
        }
        Err(cache_error(
            op,
            &self.path,
            "cache instance was invalidated by an ambiguous publication/readback failure; reopen the durable cache before any further read or write",
        ))
    }

    fn from_bytes(path: &Path, bytes: &[u8]) -> Result<Self> {
        let persisted: PersistedCache = serde_json::from_slice(bytes)
            .map_err(|err| cache_error("load", path, format!("malformed JSON: {err}")))?;
        if persisted.schema_version != AUTOTUNE_CACHE_SCHEMA_VERSION {
            return Err(cache_error(
                "load",
                path,
                format!(
                    "unsupported schema_version {}; expected {AUTOTUNE_CACHE_SCHEMA_VERSION}",
                    persisted.schema_version
                ),
            ));
        }
        let mut entries = HashMap::with_capacity(persisted.entries.len());
        for entry in persisted.entries {
            if entries.insert(entry.key, entry.config).is_some() {
                return Err(cache_error(
                    "load",
                    path,
                    "duplicate autotune key in persisted cache",
                ));
            }
        }
        validate_entries(&entries, path)?;
        Ok(Self {
            entries,
            path: path.to_path_buf(),
            usable: true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedCache {
    schema_version: u32,
    entries: Vec<PersistedEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedEntry {
    key: AutotuneKey,
    config: BestConfig,
}

fn persisted(entries: &HashMap<AutotuneKey, BestConfig>) -> PersistedCache {
    let mut entries = entries
        .iter()
        .map(|(key, config)| PersistedEntry {
            key: key.clone(),
            config: config.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| entry_sort_key(left).cmp(&entry_sort_key(right)));
    PersistedCache {
        schema_version: AUTOTUNE_CACHE_SCHEMA_VERSION,
        entries,
    }
}

fn entry_sort_key(entry: &PersistedEntry) -> (&str, &[usize], &str, &str, u32) {
    (
        &entry.key.op,
        &entry.key.shape,
        &entry.key.dtype,
        &entry.key.device,
        entry.key.recall_tgt.to_bits(),
    )
}

fn validate_entries(entries: &HashMap<AutotuneKey, BestConfig>, path: &Path) -> Result<()> {
    for (key, config) in entries {
        if key.op.trim().is_empty()
            || key.shape.is_empty()
            || key.shape.contains(&0)
            || key.dtype.trim().is_empty()
            || key.device.trim().is_empty()
            || !key.recall_tgt.is_finite()
            || !(0.0..=1.0).contains(&key.recall_tgt)
        {
            return Err(cache_error(
                "validate",
                path,
                format!("invalid autotune key for op {:?}", key.op),
            ));
        }
        if config.tile_m == 0
            || config.tile_n == 0
            || config.tile_k == 0
            || config.extra.keys().any(|name| name.trim().is_empty())
        {
            return Err(cache_error(
                "validate",
                path,
                format!("invalid autotune config for op {:?}", key.op),
            ));
        }
    }
    Ok(())
}

fn tmp_path_for(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        cache_error(
            "persist",
            path,
            "cache path must include a file name for same-directory temp writes",
        )
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    Ok(path.with_file_name(tmp_name))
}

fn write_tmp(path: &Path, bytes: &[u8]) -> Result<()> {
    let write_result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    write_result.map_err(|err| cache_error("persist", path, format!("write failed: {err}")))
}

#[cfg(windows)]
fn publish_tmp(source: &Path, target: &Path, replace_existing: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace_existing {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    if unsafe { MoveFileExW(source_wide.as_ptr(), target_wide.as_ptr(), flags) } == 0 {
        return Err(cache_error(
            "publish",
            target,
            format!(
                "MoveFileExW source={} replace_existing={} failed: {}",
                source.display(),
                replace_existing,
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn publish_tmp(source: &Path, target: &Path, replace_existing: bool) -> Result<()> {
    if replace_existing {
        fs::rename(source, target).map_err(|error| {
            cache_error(
                "publish",
                target,
                format!("atomic rename from {} failed: {error}", source.display()),
            )
        })
    } else {
        fs::hard_link(source, target).map_err(|error| {
            cache_error(
                "publish",
                target,
                format!(
                    "no-replace hard-link from {} failed: {error}",
                    source.display()
                ),
            )
        })?;
        fs::remove_file(source).map_err(|error| {
            cache_error(
                "publish",
                source,
                format!("remove published temporary link failed: {error}"),
            )
        })
    }
}

fn cache_error(op: &str, path: &Path, detail: impl Into<String>) -> ForgeError {
    ForgeError::CacheError {
        op: op.to_string(),
        path: path.display().to_string(),
        detail: detail.into(),
        remediation: CACHE_REMEDIATION.to_string(),
    }
}
