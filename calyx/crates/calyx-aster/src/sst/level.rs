use super::page;
use super::{SstEntry, SstKeyState, SstLookupMetadata, SstReader};
use calyx_core::Result;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SstLevel {
    pub(super) files: Vec<LevelFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LevelFile {
    pub(super) path: PathBuf,
    lookup: Option<Arc<SstLookupMetadata>>,
}

impl LevelFile {
    fn without_lookup(path: PathBuf) -> Self {
        Self { path, lookup: None }
    }

    fn with_lookup(path: PathBuf) -> Result<Self> {
        let lookup = SstReader::open(&path)?.lookup_metadata();
        Ok(Self {
            path,
            lookup: Some(lookup),
        })
    }

    fn may_contain(&self, key: &[u8]) -> bool {
        let Some(lookup) = &self.lookup else {
            return true;
        };
        let Some((first, last)) = lookup.key_range() else {
            return false;
        };
        key >= first && key <= last && lookup.bloom.may_contain(key)
    }

    fn contains_indexed_key(&self, key: &[u8]) -> Option<bool> {
        self.lookup.as_ref().map(|lookup| {
            lookup
                .index
                .binary_search_by(|entry| entry.key.as_slice().cmp(key))
                .is_ok()
        })
    }

    pub(super) fn open_reader(&self) -> Result<SstReader> {
        self.lookup.as_ref().map_or_else(
            || SstReader::open(&self.path),
            |lookup| SstReader::open_with_lookup(&self.path, Arc::clone(lookup)),
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SstPlanReadMetrics {
    pub files_opened: u64,
    pub max_value_bytes: u64,
    pub plan_index_bytes: u64,
}

impl SstLevel {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    pub fn from_oldest_first(files: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut files = files
            .into_iter()
            .map(LevelFile::without_lookup)
            .collect::<Vec<_>>();
        files.reverse();
        Self { files }
    }

    pub fn from_oldest_first_with_lookup(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let mut files = Vec::new();
        for path in paths {
            files.push(LevelFile::with_lookup(path)?);
        }
        files.reverse();
        Ok(Self { files })
    }

    pub fn push(&mut self, path: PathBuf) {
        self.files.insert(0, LevelFile::without_lookup(path));
    }

    pub fn push_with_lookup(&mut self, path: PathBuf) -> Result<()> {
        self.files.insert(0, LevelFile::with_lookup(path)?);
        Ok(())
    }

    /// Reconciles an oldest-first physical inventory while retaining validated
    /// lookup metadata for byte-identical paths that were already attached.
    /// Paths named in `refresh` are reopened even when their names match; this
    /// is required when a recovered checkpoint republishes a canonical batch
    /// path before the manifest-bound router handoff observes it.
    pub(crate) fn reconcile_oldest_first_with_lookup(
        &self,
        paths: impl IntoIterator<Item = PathBuf>,
        refresh: &BTreeSet<PathBuf>,
    ) -> Result<Self> {
        let existing = self
            .files
            .iter()
            .map(|file| (file.path.clone(), file.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut files = Vec::new();
        for path in paths {
            let file = if !refresh.contains(&path) {
                existing.get(&path).cloned()
            } else {
                None
            }
            .map_or_else(|| LevelFile::with_lookup(path), Ok)?;
            files.push(file);
        }
        files.reverse();
        Ok(Self { files })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        for file in &self.files {
            if !file.may_contain(key) {
                continue;
            }
            let reader = file.open_reader()?;
            if let Some(value) = reader.get(key)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    /// Visits an arbitrary set of stable plan ordinals while opening each
    /// candidate immutable SST at most once.
    ///
    /// Files are newest-first, so the first physical occurrence wins. Values
    /// are borrowed from the mapped SST only for the callback duration; a
    /// corpus-sized result vector is never assembled.
    pub(crate) fn visit_key_plan<E, F>(
        &self,
        keys: &[(usize, &[u8])],
        resolved: &mut [bool],
        on_value: &mut F,
    ) -> std::result::Result<SstPlanReadMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        if keys.len() != resolved.len() {
            return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                "SST ordered-readback key/resolution cardinality mismatch",
            )));
        }
        let mut metrics = SstPlanReadMetrics::default();
        for file in &self.files {
            let candidates = keys
                .iter()
                .enumerate()
                .filter_map(|(position, (_, key))| {
                    if resolved[position] || !file.may_contain(key) {
                        return None;
                    }
                    match file.contains_indexed_key(key) {
                        Some(false) => None,
                        Some(true) | None => Some(position),
                    }
                })
                .collect::<Vec<_>>();
            let candidate_bytes = candidates
                .capacity()
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(|| {
                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                        "SST ordered-readback candidate-index byte count overflow",
                    ))
                })?;
            metrics.plan_index_bytes = metrics.plan_index_bytes.max(candidate_bytes);
            if candidates.is_empty() {
                continue;
            }
            let reader = file.open_reader().map_err(E::from)?;
            metrics.files_opened = metrics.files_opened.checked_add(1).ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "SST ordered-readback file-open counter overflow",
                ))
            })?;
            for position in candidates {
                let (ordinal, key) = keys[position];
                if let Some(value) = reader.get_ref(key).map_err(E::from)? {
                    metrics.max_value_bytes = metrics.max_value_bytes.max(value.len() as u64);
                    on_value(ordinal, Some(value))?;
                    resolved[position] = true;
                } else if file.contains_indexed_key(key) == Some(true) {
                    return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                        format!(
                            "SST lookup metadata named key but the mapped record was absent in {}",
                            file.path.display()
                        ),
                    )));
                }
            }
        }
        for (position, (ordinal, _)) in keys.iter().enumerate() {
            if !resolved[position] {
                on_value(*ordinal, None)?;
                resolved[position] = true;
            }
        }
        Ok(metrics)
    }

    /// Returns the newest value and the exact immutable file that supplied it.
    pub(crate) fn get_with_source(&self, key: &[u8]) -> Result<Option<(Vec<u8>, PathBuf)>> {
        for file in &self.files {
            if !file.may_contain(key) {
                continue;
            }
            let reader = file.open_reader()?;
            if let Some(value) = reader.get(key)? {
                return Ok(Some((value, file.path.clone())));
            }
        }
        Ok(None)
    }

    pub(crate) fn values_for_key(&self, key: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut values = Vec::new();
        for file in &self.files {
            if !file.may_contain(key) {
                continue;
            }
            let reader = file.open_reader()?;
            if let Some(value) = reader.get(key)? {
                values.push(value);
            }
        }
        Ok(values)
    }

    pub fn range(&self, start: &[u8], end: &[u8]) -> Result<Vec<SstEntry>> {
        let mut per_file = self
            .files
            .par_iter()
            .enumerate()
            .map(|(index, file)| -> Result<(usize, Vec<SstEntry>)> {
                Ok((index, file.open_reader()?.range(start, end)?))
            })
            .collect::<Result<Vec<_>>>()?;
        per_file.sort_by_key(|(index, _)| *index);

        let mut rows = BTreeMap::new();
        for (_, entries) in per_file {
            for entry in entries {
                rows.entry(entry.key).or_insert(entry.value);
            }
        }
        Ok(rows
            .into_iter()
            .map(|(key, value)| SstEntry { key, value })
            .collect())
    }

    pub fn range_keys(&self, start: &[u8], end: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.range_keys_until(start, Some(end))
    }

    pub fn range_keys_until(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Vec<u8>>> {
        let mut per_file = self
            .files
            .par_iter()
            .enumerate()
            .map(|(index, file)| -> Result<(usize, Vec<SstKeyState>)> {
                Ok((
                    index,
                    file.open_reader()?.range_key_states_until(start, end)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        per_file.sort_by_key(|(index, _)| *index);

        let mut rows = BTreeMap::<Vec<u8>, bool>::new();
        for (_, entries) in per_file {
            for entry in entries {
                rows.entry(entry.key).or_insert(entry.is_tombstone);
            }
        }
        Ok(rows
            .into_iter()
            .filter_map(|(key, is_tombstone)| (!is_tombstone).then_some(key))
            .collect())
    }

    pub fn range_page_until(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        after_key: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<SstEntry>> {
        self.range_page_with_overlay(start, end, after_key, limit, Vec::new())
    }

    pub(crate) fn range_page_with_overlay(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        after_key: Option<&[u8]>,
        limit: usize,
        overlay: Vec<SstEntry>,
    ) -> Result<Vec<SstEntry>> {
        page::range_page(self, start, end, after_key, limit, overlay)
    }

    pub(crate) fn range_pages_with_overlay<F, E>(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        after_key: Option<&[u8]>,
        limit: usize,
        overlay: Vec<SstEntry>,
        on_page: F,
    ) -> std::result::Result<(), E>
    where
        F: FnMut(Vec<SstEntry>) -> std::result::Result<(), E>,
        E: From<calyx_core::CalyxError>,
    {
        page::range_pages(self, start, end, after_key, limit, overlay, on_page)
    }

    pub fn iter(&self) -> Result<Vec<SstEntry>> {
        let mut rows = BTreeMap::new();
        for file in &self.files {
            for entry in file.open_reader()?.iter()? {
                rows.entry(entry.key).or_insert(entry.value);
            }
        }
        Ok(rows
            .into_iter()
            .map(|(key, value)| SstEntry { key, value })
            .collect())
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Immutable physical paths in newest-first lookup order.
    pub(crate) fn paths(&self) -> impl Iterator<Item = &std::path::Path> {
        self.files.iter().map(|file| file.path.as_path())
    }
}
