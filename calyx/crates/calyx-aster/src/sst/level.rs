use super::page;
use super::{SstEntry, SstKeyState, SstLookupMetadata, SstReader};
use calyx_core::Result;
use rayon::prelude::*;
use std::collections::BTreeMap;
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

    pub(super) fn open_reader(&self) -> Result<SstReader> {
        self.lookup.as_ref().map_or_else(
            || SstReader::open(&self.path),
            |lookup| SstReader::open_with_lookup(&self.path, Arc::clone(lookup)),
        )
    }
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
}
