use super::page;
use super::{SstEntry, SstKeyState, SstLookupMetadata, SstReader, ValidatedSstValueRange};
use calyx_core::{CalyxError, Result};
use rayon::prelude::*;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub struct SstLevel {
    /// Immutable generations in newest-first lookup order.
    pub(super) files: VecDeque<Arc<LevelFile>>,
    /// Complete newest-generation exact-key routes when every file carries
    /// validated lookup metadata. `None` preserves the legacy full-file scan
    /// for callers that deliberately constructed an unindexed level.
    exact_routes: Option<ExactKeyRoutes>,
}

impl Default for SstLevel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LevelFile {
    pub(super) path: PathBuf,
    lookup: Option<Arc<SstLookupMetadata>>,
}

/// One exact route whose ordering and equality are solely the immutable SST
/// key. The route retains its validated lookup metadata through `file`, so the
/// B-tree never clones corpus key bytes and has no self-referential lifetime.
#[derive(Clone)]
struct ExactKeyRoute {
    file: Arc<LevelFile>,
    key_index: usize,
}

impl ExactKeyRoute {
    fn key(&self) -> &[u8] {
        self.file
            .indexed_key(self.key_index)
            .expect("exact SST route retains its validated lookup key")
    }
}

impl Borrow<[u8]> for ExactKeyRoute {
    fn borrow(&self) -> &[u8] {
        self.key()
    }
}

impl PartialEq for ExactKeyRoute {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for ExactKeyRoute {}

impl PartialOrd for ExactKeyRoute {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExactKeyRoute {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(other.key())
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct ExactKeyRoutes {
    routes: BTreeSet<ExactKeyRoute>,
    logical_key_bytes: u64,
}

impl fmt::Debug for ExactKeyRoutes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactKeyRoutes")
            .field("entries", &self.routes.len())
            .field("logical_key_bytes", &self.logical_key_bytes)
            .finish()
    }
}

impl ExactKeyRoutes {
    fn from_newest_first(files: &VecDeque<Arc<LevelFile>>) -> Result<Self> {
        let mut routes = Self::default();
        // Each insertion represents a generation newer than the previous one,
        // so exact duplicate keys deterministically replace their older route.
        for file in files.iter().rev() {
            routes.insert_newest_file(Arc::clone(file))?;
        }
        Ok(routes)
    }

    fn insert_newest_file(&mut self, file: Arc<LevelFile>) -> Result<()> {
        let lookup = file.lookup.as_ref().ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "exact SST routes require validated lookup metadata for {}",
                file.path.display()
            ))
        })?;
        // Preflight every fallible byte-accounting operation before replacing
        // any route, so an overflow leaves the prior complete index untouched.
        let added_key_bytes = lookup.index.iter().try_fold(0_u64, |total, entry| {
            if self.routes.contains::<[u8]>(entry.key.as_slice()) {
                return Ok(total);
            }
            total
                .checked_add(u64::try_from(entry.key.len()).map_err(|_| {
                    CalyxError::aster_corrupt_shard("exact SST route key length exceeds u64")
                })?)
                .ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(
                        "exact SST route logical key-byte count overflow",
                    )
                })
        })?;
        let logical_key_bytes = self
            .logical_key_bytes
            .checked_add(added_key_bytes)
            .ok_or_else(|| {
                CalyxError::aster_corrupt_shard("exact SST route logical key-byte count overflow")
            })?;
        for key_index in 0..lookup.index.len() {
            self.routes.replace(ExactKeyRoute {
                file: Arc::clone(&file),
                key_index,
            });
        }
        self.logical_key_bytes = logical_key_bytes;
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Option<&ExactKeyRoute> {
        self.routes.get::<[u8]>(key)
    }
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

    fn indexed_key(&self, position: usize) -> Option<&[u8]> {
        self.lookup
            .as_ref()?
            .index
            .get(position)
            .map(|entry| entry.key.as_slice())
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
    pub key_probes: u64,
    pub map_reuses: u64,
    pub exact_route_lookups: u64,
    pub exact_route_hits: u64,
    pub fallback_file_key_checks: u64,
    pub max_value_bytes: u64,
    pub plan_index_bytes: u64,
}

impl SstLevel {
    pub fn new() -> Self {
        Self {
            files: VecDeque::new(),
            exact_routes: Some(ExactKeyRoutes::default()),
        }
    }

    pub fn from_oldest_first(files: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut newest_first = VecDeque::new();
        for path in files {
            newest_first.push_front(Arc::new(LevelFile::without_lookup(path)));
        }
        Self {
            files: newest_first,
            exact_routes: None,
        }
    }

    pub fn from_oldest_first_with_lookup(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let mut files = VecDeque::new();
        for path in paths {
            files.push_front(Arc::new(LevelFile::with_lookup(path)?));
        }
        let exact_routes = ExactKeyRoutes::from_newest_first(&files)?;
        Ok(Self {
            files,
            exact_routes: Some(exact_routes),
        })
    }

    pub fn push(&mut self, path: PathBuf) {
        self.files
            .push_front(Arc::new(LevelFile::without_lookup(path)));
        self.exact_routes = None;
    }

    pub fn push_with_lookup(&mut self, path: PathBuf) -> Result<()> {
        let file = Arc::new(LevelFile::with_lookup(path)?);
        if let Some(routes) = &mut self.exact_routes {
            routes.insert_newest_file(Arc::clone(&file))?;
        }
        self.files.push_front(file);
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
            .map(|file| (file.path.clone(), Arc::clone(file)))
            .collect::<BTreeMap<_, _>>();
        let mut files = VecDeque::new();
        for path in paths {
            let file = if !refresh.contains(&path) {
                existing
                    .get(&path)
                    .filter(|file| file.lookup.is_some())
                    .cloned()
            } else {
                None
            }
            .map_or_else(|| LevelFile::with_lookup(path).map(Arc::new), Ok)?;
            files.push_front(file);
        }
        let exact_routes = ExactKeyRoutes::from_newest_first(&files)?;
        Ok(Self {
            files,
            exact_routes: Some(exact_routes),
        })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(routes) = &self.exact_routes {
            let Some(route) = routes.get(key) else {
                return Ok(None);
            };
            let reader = route.file.open_reader()?;
            return reader.get(key)?.map(Some).ok_or_else(|| {
                CalyxError::aster_corrupt_shard(format!(
                    "exact SST route named key absent from {}",
                    route.file.path.display()
                ))
            });
        }
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
        match &self.exact_routes {
            Some(routes) => self.visit_exact_key_plan(routes, keys, resolved, on_value),
            None => self.visit_fallback_key_plan(keys, resolved, on_value),
        }
    }

    fn visit_exact_key_plan<E, F>(
        &self,
        routes: &ExactKeyRoutes,
        keys: &[(usize, &[u8])],
        resolved: &mut [bool],
        on_value: &mut F,
    ) -> std::result::Result<SstPlanReadMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        let mut metrics = SstPlanReadMetrics::default();
        let mut readers = Vec::new();
        let mut sources: Vec<Option<(usize, ValidatedSstValueRange)>> = vec![None; keys.len()];
        let source_bytes = sources
            .capacity()
            .checked_mul(std::mem::size_of::<Option<(usize, ValidatedSstValueRange)>>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "SST ordered-readback source-index byte count overflow",
                ))
            })?;
        let mut route_hits = Vec::<(usize, Arc<LevelFile>)>::new();
        for (position, (_, key)) in keys.iter().enumerate() {
            if resolved[position] {
                continue;
            }
            metrics.exact_route_lookups =
                metrics.exact_route_lookups.checked_add(1).ok_or_else(|| {
                    E::from(CalyxError::aster_corrupt_shard(
                        "SST exact-route lookup counter overflow",
                    ))
                })?;
            if let Some(route) = routes.get(key) {
                metrics.exact_route_hits =
                    metrics.exact_route_hits.checked_add(1).ok_or_else(|| {
                        E::from(CalyxError::aster_corrupt_shard(
                            "SST exact-route hit counter overflow",
                        ))
                    })?;
                route_hits.push((position, Arc::clone(&route.file)));
            }
        }
        route_hits.sort_by(|left, right| {
            left.1
                .path
                .cmp(&right.1.path)
                .then_with(|| left.0.cmp(&right.0))
        });
        let route_hit_bytes = route_hits
            .capacity()
            .checked_mul(std::mem::size_of::<(usize, Arc<LevelFile>)>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST exact-route plan-index byte count overflow",
                ))
            })?;
        metrics.plan_index_bytes = source_bytes.checked_add(route_hit_bytes).ok_or_else(|| {
            E::from(CalyxError::aster_corrupt_shard(
                "SST exact-route total plan-index byte count overflow",
            ))
        })?;
        let mut start = 0;
        while start < route_hits.len() {
            let file = Arc::clone(&route_hits[start].1);
            let mut end = start + 1;
            while end < route_hits.len() && route_hits[end].1.path == file.path {
                end += 1;
            }
            let reader = file.open_reader().map_err(E::from)?;
            let reader_index = readers.len();
            metrics.files_opened = metrics.files_opened.checked_add(1).ok_or_else(|| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST exact-route file-open counter overflow",
                ))
            })?;
            let candidate_count = u64::try_from(end - start).map_err(|_| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST exact-route candidate count exceeds u64",
                ))
            })?;
            metrics.key_probes =
                metrics
                    .key_probes
                    .checked_add(candidate_count)
                    .ok_or_else(|| {
                        E::from(CalyxError::aster_corrupt_shard(
                            "SST exact-route key-probe counter overflow",
                        ))
                    })?;
            metrics.map_reuses = metrics
                .map_reuses
                .checked_add(candidate_count.saturating_sub(1))
                .ok_or_else(|| {
                    E::from(CalyxError::aster_corrupt_shard(
                        "SST exact-route map-reuse counter overflow",
                    ))
                })?;
            for (position, _) in &route_hits[start..end] {
                let (_, key) = keys[*position];
                let range = reader
                    .validated_value_range(key)
                    .map_err(E::from)?
                    .ok_or_else(|| {
                        E::from(CalyxError::aster_corrupt_shard(format!(
                            "exact SST route named key absent from {}",
                            file.path.display()
                        )))
                    })?;
                metrics.max_value_bytes = metrics.max_value_bytes.max(range.len() as u64);
                sources[*position] = Some((reader_index, range));
                resolved[*position] = true;
            }
            readers.push(reader);
            start = end;
        }
        publish_key_plan(keys, resolved, &readers, &sources, on_value)?;
        Ok(metrics)
    }

    fn visit_fallback_key_plan<E, F>(
        &self,
        keys: &[(usize, &[u8])],
        resolved: &mut [bool],
        on_value: &mut F,
    ) -> std::result::Result<SstPlanReadMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        let mut metrics = SstPlanReadMetrics::default();
        let mut readers = Vec::new();
        let mut sources: Vec<Option<(usize, ValidatedSstValueRange)>> = vec![None; keys.len()];
        let source_bytes = sources
            .capacity()
            .checked_mul(std::mem::size_of::<Option<(usize, ValidatedSstValueRange)>>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST fallback source-index byte count overflow",
                ))
            })?;
        metrics.plan_index_bytes = source_bytes;
        for file in &self.files {
            if resolved.iter().all(|is_resolved| *is_resolved) {
                break;
            }
            let mut candidates = Vec::new();
            for (position, (_, key)) in keys.iter().enumerate() {
                if resolved[position] {
                    continue;
                }
                metrics.fallback_file_key_checks = metrics
                    .fallback_file_key_checks
                    .checked_add(1)
                    .ok_or_else(|| {
                        E::from(CalyxError::aster_corrupt_shard(
                            "SST fallback file-key check counter overflow",
                        ))
                    })?;
                if !file.may_contain(key) {
                    continue;
                }
                match file.contains_indexed_key(key) {
                    Some(false) => {}
                    Some(true) | None => candidates.push(position),
                }
            }
            let candidate_bytes = candidates
                .capacity()
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(|| {
                    E::from(CalyxError::aster_corrupt_shard(
                        "SST ordered-readback candidate-index byte count overflow",
                    ))
                })?;
            metrics.plan_index_bytes = metrics.plan_index_bytes.max(candidate_bytes);
            if candidates.is_empty() {
                continue;
            }
            let reader = file.open_reader().map_err(E::from)?;
            let reader_index = readers.len();
            metrics.files_opened = metrics.files_opened.checked_add(1).ok_or_else(|| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST ordered-readback file-open counter overflow",
                ))
            })?;
            let candidate_count = u64::try_from(candidates.len()).map_err(|_| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST ordered-readback candidate count exceeds u64",
                ))
            })?;
            metrics.key_probes =
                metrics
                    .key_probes
                    .checked_add(candidate_count)
                    .ok_or_else(|| {
                        E::from(CalyxError::aster_corrupt_shard(
                            "SST ordered-readback key-probe counter overflow",
                        ))
                    })?;
            metrics.map_reuses = metrics
                .map_reuses
                .checked_add(candidate_count.saturating_sub(1))
                .ok_or_else(|| {
                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                        "SST ordered-readback map-reuse counter overflow",
                    ))
                })?;
            for position in candidates {
                let (_, key) = keys[position];
                if let Some(range) = reader.validated_value_range(key).map_err(E::from)? {
                    metrics.max_value_bytes = metrics.max_value_bytes.max(range.len() as u64);
                    sources[position] = Some((reader_index, range));
                    resolved[position] = true;
                } else if file.contains_indexed_key(key) == Some(true) {
                    return Err(E::from(CalyxError::aster_corrupt_shard(format!(
                        "SST lookup metadata named key but the mapped record was absent in {}",
                        file.path.display()
                    ))));
                }
            }
            readers.push(reader);
        }
        publish_key_plan(keys, resolved, &readers, &sources, on_value)?;
        Ok(metrics)
    }

    /// Returns the newest value and the exact immutable file that supplied it.
    pub(crate) fn get_with_source(&self, key: &[u8]) -> Result<Option<(Vec<u8>, PathBuf)>> {
        if let Some(routes) = &self.exact_routes {
            let Some(route) = routes.get(key) else {
                return Ok(None);
            };
            let reader = route.file.open_reader()?;
            return reader
                .get(key)?
                .map(|value| Some((value, route.file.path.clone())))
                .ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "exact SST route named key absent from {}",
                        route.file.path.display()
                    ))
                });
        }
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

fn publish_key_plan<E, F>(
    keys: &[(usize, &[u8])],
    resolved: &mut [bool],
    readers: &[SstReader],
    sources: &[Option<(usize, ValidatedSstValueRange)>],
    on_value: &mut F,
) -> std::result::Result<(), E>
where
    E: From<CalyxError>,
    F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
{
    // No callback is invoked until every required generation has opened and
    // every selected record has passed its CRC/bounds validation. A corrupt,
    // replaced, or missing generation therefore aborts with zero partial
    // consumer output. Retained mappings make publication a pure slice replay.
    for (position, (ordinal, _)) in keys.iter().enumerate() {
        if let Some((reader_index, range)) = sources[position] {
            let reader = readers.get(reader_index).ok_or_else(|| {
                E::from(CalyxError::aster_corrupt_shard(
                    "SST plan source named an absent retained reader",
                ))
            })?;
            on_value(*ordinal, Some(reader.value_at_validated_range(range)))?;
        } else if !resolved[position] {
            on_value(*ordinal, None)?;
            resolved[position] = true;
        }
    }
    Ok(())
}
