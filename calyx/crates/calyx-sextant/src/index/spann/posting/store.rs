use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use calyx_core::{CxId, Result};

use super::codec::{PostingMutation, StoredRecord, validate_sparse_vector};
use super::config::{SpannIndexIdentity, SpannPostingLimits};
use super::format::{
    DecodedSegment, SegmentDescriptor, SegmentKind, build_posting_segment, build_state_segment,
    publish_segment, read_segment,
};
use super::lease::{ReaderLease, live_lease_targets};
use super::manifest::{
    PostingManifestState, create_genesis, load_manifest_state, load_manifest_state_at,
    manifest_for_update, publish_manifest, read_active_pointer,
};
use super::{PostingMember, corrupt, invalid, io};

const ACTIVE_FILE: &str = "postings.active";
const WRITE_LOCK_FILE: &str = "postings.write.lock";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpannPostingPhysicalStats {
    pub generation: u64,
    pub records: usize,
    pub declared_postings: usize,
    pub posting_segments: usize,
    pub state_segments: usize,
    pub posting_segment_bytes: u64,
    pub state_segment_bytes: u64,
    pub manifest_chain_bytes: u64,
    pub active_pointer_bytes: u64,
    pub active_physical_bytes: u64,
    pub directory_physical_bytes: u64,
    pub retained_reader_bytes: u64,
    pub reader_lease_bytes: u64,
    pub temporary_bytes: u64,
    pub orphan_bytes: u64,
    pub cache_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpannPostingWriteReceipt {
    pub generation: u64,
    pub logical_decoded_bytes: u64,
    pub physical_bytes_written: u64,
    pub compaction_bytes_written: u64,
    pub write_amplification: f64,
    pub compacted_postings: u32,
    pub state_compacted: bool,
    pub reclaimed_files: u32,
    pub reclaimed_bytes: u64,
}

#[derive(Debug)]
pub(super) struct PostingStore {
    dir: PathBuf,
    identity: SpannIndexIdentity,
    limits: SpannPostingLimits,
    manifest: PostingManifestState,
    records: BTreeMap<u32, StoredRecord>,
    cx_to_local: BTreeMap<CxId, u32>,
    _lease: ReaderLease,
    cache: Mutex<PostingCache>,
    last_write: Option<SpannPostingWriteReceipt>,
}

#[derive(Debug, Default)]
struct PostingCache {
    entries: BTreeMap<(u32, [u8; 32]), Arc<Vec<PostingMember>>>,
    lru: VecDeque<(u32, [u8; 32])>,
    bytes: u64,
    hits: u64,
    misses: u64,
}

struct StoreWriteLock {
    _file: File,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReclaimStats {
    files: u32,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct DirectoryPhysicalState {
    total_bytes: u64,
    retained_reader_bytes: u64,
    reader_lease_bytes: u64,
    temporary_bytes: u64,
    orphan_bytes: u64,
}

impl PostingStore {
    pub(super) fn create_or_open(
        dir: PathBuf,
        identity: SpannIndexIdentity,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        limits.validate()?;
        fs::create_dir_all(&dir).map_err(|error| io("create posting store", error))?;
        {
            let _lock = StoreWriteLock::acquire(&dir)?;
            if !dir.join(ACTIVE_FILE).exists() {
                create_genesis(&dir, &identity, &limits)?;
            }
        }
        Self::open_inner(dir, identity, limits)
    }

    pub(super) fn open_existing(
        dir: PathBuf,
        identity: SpannIndexIdentity,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        limits.validate()?;
        if !dir.join(ACTIVE_FILE).exists() {
            return Err(corrupt(format!(
                "declared SPANN posting store is absent: {}",
                dir.join(ACTIVE_FILE).display()
            )));
        }
        Self::open_inner(dir, identity, limits)
    }

    fn open_inner(
        dir: PathBuf,
        identity: SpannIndexIdentity,
        limits: SpannPostingLimits,
    ) -> Result<Self> {
        let _lock = StoreWriteLock::acquire(&dir)?;
        let existing_leases = live_lease_targets(&dir, &identity, &limits)?;
        if existing_leases.len() >= limits.max_reader_leases as usize {
            return Err(corrupt(format!(
                "live reader leases reached registry limit {}; close a reader before opening another",
                limits.max_reader_leases
            )));
        }
        let active = read_active_pointer(&dir, &identity)?;
        let lease = ReaderLease::acquire(&dir, &identity, &active)?;
        let manifest = load_manifest_state_at(&dir, &identity, &limits, &active)?;
        validate_declared_components(&manifest, &identity)?;
        let (records, cx_to_local) = load_records(&dir, &manifest, &identity, &limits)?;
        let store = Self {
            dir,
            identity,
            limits,
            manifest,
            records,
            cx_to_local,
            _lease: lease,
            cache: Mutex::new(PostingCache::default()),
            last_write: None,
        };
        store.verify_all_postings()?;
        store.reclaim_obsolete_files()?;
        Ok(store)
    }

    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(super) fn limits(&self) -> &SpannPostingLimits {
        &self.limits
    }

    pub(super) fn built_at_seq(&self) -> u64 {
        self.manifest.built_at_seq
    }

    pub(super) fn base_seq(&self) -> u64 {
        self.manifest.base_seq
    }

    pub(super) fn len(&self) -> usize {
        self.records.len()
    }

    pub(super) fn record_for_cx(&self, cx_id: CxId) -> Option<&StoredRecord> {
        self.cx_to_local
            .get(&cx_id)
            .and_then(|local| self.records.get(local))
    }

    pub(super) fn cx_for_local(&self, local: u32) -> Result<CxId> {
        self.records
            .get(&local)
            .map(|record| record.cx_id)
            .ok_or_else(|| {
                corrupt(format!(
                    "posting references unknown local id {local}; rebuild from the authoritative vault"
                ))
            })
    }

    pub(super) fn read_lists(
        &self,
        centroid_ids: impl IntoIterator<Item = u32>,
    ) -> Result<Vec<(u32, Arc<Vec<PostingMember>>)>> {
        let mut unique = centroid_ids.into_iter().collect::<Vec<_>>();
        unique.sort_unstable();
        unique.dedup();
        let mut decoded_budget = 0_u64;
        for centroid_id in &unique {
            let segments = self
                .manifest
                .postings
                .get(*centroid_id as usize)
                .ok_or_else(|| corrupt(format!("undeclared centroid posting {centroid_id}")))?;
            for segment in segments {
                decoded_budget = decoded_budget
                    .checked_add(segment.decoded_len)
                    .ok_or_else(|| invalid("query decoded-byte budget overflow"))?;
            }
        }
        if decoded_budget > self.limits.max_query_decoded_bytes {
            return Err(invalid(format!(
                "query posting bytes {decoded_budget} exceed registry limit {} for centroids {:?}",
                self.limits.max_query_decoded_bytes, unique
            )));
        }
        unique
            .into_iter()
            .map(|centroid_id| {
                let members = self.read_list(centroid_id)?;
                Ok((centroid_id, members))
            })
            .collect()
    }

    fn read_list(&self, centroid_id: u32) -> Result<Arc<Vec<PostingMember>>> {
        let segments = self
            .manifest
            .postings
            .get(centroid_id as usize)
            .ok_or_else(|| corrupt(format!("undeclared centroid posting {centroid_id}")))?;
        let key = (centroid_id, posting_fingerprint(segments));
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| corrupt("posting cache poisoned"))?;
            if let Some(value) = cache.entries.get(&key).cloned() {
                cache.hits += 1;
                touch_lru(&mut cache.lru, key);
                return Ok(value);
            }
            cache.misses += 1;
        }
        let members = Arc::new(materialize_posting(
            &self.dir,
            segments,
            &self.identity,
            &self.limits,
        )?);
        self.validate_materialized_posting(centroid_id, &members)?;
        let bytes = posting_memory_bytes(&members)?;
        if bytes <= self.limits.cache_capacity_bytes {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| corrupt("posting cache poisoned"))?;
            while cache.bytes.saturating_add(bytes) > self.limits.cache_capacity_bytes {
                let Some(evicted) = cache.lru.pop_front() else {
                    break;
                };
                if let Some(value) = cache.entries.remove(&evicted) {
                    cache.bytes = cache.bytes.saturating_sub(posting_memory_bytes(&value)?);
                }
            }
            cache.bytes = cache
                .bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("posting cache byte accounting overflow"))?;
            cache.entries.insert(key, Arc::clone(&members));
            touch_lru(&mut cache.lru, key);
        }
        Ok(members)
    }

    pub(super) fn upsert(
        &mut self,
        cx_id: CxId,
        vector: Vec<(u32, f32)>,
        mut memberships: Vec<u32>,
        seq: u64,
    ) -> Result<SpannPostingWriteReceipt> {
        validate_sparse_vector(&vector, self.identity.dim, &self.limits)?;
        memberships.sort_unstable();
        memberships.dedup();
        validate_memberships(&memberships, self.identity.centroid_count)?;
        let _lock = StoreWriteLock::acquire(&self.dir)?;
        let disk_state = load_manifest_state(&self.dir, &self.identity, &self.limits)?;
        if disk_state.generation != self.manifest.generation
            || disk_state.manifest_hash != self.manifest.manifest_hash
        {
            return Err(corrupt(format!(
                "SPANN writer generation changed from {} to {}; reopen before retry",
                self.manifest.generation, disk_state.generation
            )));
        }
        let local_id = match self.cx_to_local.get(&cx_id).copied() {
            Some(local) => local,
            None => u32::try_from(self.records.len())
                .map_err(|_| invalid("SPANN local id space exceeds u32"))?,
        };
        let old_memberships = self
            .records
            .get(&local_id)
            .map(|record| record.memberships.clone())
            .unwrap_or_default();
        if let Some(existing) = self.records.get(&local_id)
            && seq < existing.seq
        {
            return Err(invalid(format!(
                "stale update sequence {seq} is below persisted sequence {} for CxId {cx_id}",
                existing.seq
            )));
        }
        let next_record = StoredRecord {
            local_id,
            cx_id,
            vector: vector.clone(),
            memberships: memberships.clone(),
            seq,
        };
        let next_generation = self.manifest.generation + 1;
        let mut changed = BTreeMap::new();
        let mut published_bytes = 0_u64;
        let mut logical_bytes = 0_u64;
        let mut compaction_bytes = 0_u64;
        let mut compacted_postings = 0_u32;
        let affected = old_memberships
            .iter()
            .chain(&memberships)
            .copied()
            .collect::<BTreeSet<_>>();
        for centroid_id in affected {
            let mutation = if memberships.binary_search(&centroid_id).is_ok() {
                PostingMutation {
                    cx_id: local_id,
                    vector: Some(vector.clone()),
                }
            } else {
                PostingMutation::delete(local_id)
            };
            let current = &self.manifest.postings[centroid_id as usize];
            let (staged, compacted) =
                if current.len() + 1 > self.limits.max_segments_per_posting as usize {
                    let mut materialized =
                        materialize_posting(&self.dir, current, &self.identity, &self.limits)?
                            .into_iter()
                            .map(|member| (member.cx_id, member))
                            .collect::<BTreeMap<_, _>>();
                    apply_mutation(&mut materialized, mutation.clone());
                    let operations = materialized
                        .into_values()
                        .map(PostingMutation::upsert)
                        .collect::<Vec<_>>();
                    (
                        build_posting_segment(
                            &self.identity,
                            centroid_id,
                            next_generation,
                            &operations,
                            &self.limits,
                        )?,
                        true,
                    )
                } else {
                    (
                        build_posting_segment(
                            &self.identity,
                            centroid_id,
                            next_generation,
                            &[mutation],
                            &self.limits,
                        )?,
                        false,
                    )
                };
            logical_bytes = logical_bytes
                .checked_add(staged.descriptor.decoded_len)
                .ok_or_else(|| invalid("logical posting byte accounting overflow"))?;
            let descriptor = publish_segment(&self.dir, staged, &self.identity, &self.limits)?;
            published_bytes = published_bytes
                .checked_add(descriptor.file_len)
                .ok_or_else(|| invalid("physical posting byte accounting overflow"))?;
            let next_segments = if compacted {
                compacted_postings += 1;
                compaction_bytes = compaction_bytes
                    .checked_add(descriptor.file_len)
                    .ok_or_else(|| invalid("compaction byte accounting overflow"))?;
                vec![descriptor]
            } else {
                let mut segments = current.clone();
                segments.push(descriptor);
                segments
            };
            changed.insert(centroid_id, next_segments);
        }

        let mut next_records = self.records.clone();
        next_records.insert(local_id, next_record.clone());
        let mut next_state_segments = self.manifest.state_segments.clone();
        let mut state_compacted = false;
        if next_state_segments.len() + 1 > self.limits.max_state_segments as usize {
            state_compacted = true;
            next_state_segments = Vec::new();
            for chunk in state_compaction_chunks(next_records.values(), &self.limits)? {
                let staged =
                    build_state_segment(&self.identity, next_generation, &chunk, &self.limits)?;
                logical_bytes = logical_bytes
                    .checked_add(staged.descriptor.decoded_len)
                    .ok_or_else(|| invalid("logical state byte accounting overflow"))?;
                let descriptor = publish_segment(&self.dir, staged, &self.identity, &self.limits)?;
                published_bytes = published_bytes
                    .checked_add(descriptor.file_len)
                    .ok_or_else(|| invalid("physical state byte accounting overflow"))?;
                compaction_bytes = compaction_bytes
                    .checked_add(descriptor.file_len)
                    .ok_or_else(|| invalid("state compaction byte accounting overflow"))?;
                next_state_segments.push(descriptor);
            }
            if next_state_segments.len() > self.limits.max_state_segments as usize {
                return Err(invalid(format!(
                    "state compaction needs {} segments, above registry limit {}",
                    next_state_segments.len(),
                    self.limits.max_state_segments
                )));
            }
        } else {
            let staged = build_state_segment(
                &self.identity,
                next_generation,
                std::slice::from_ref(&next_record),
                &self.limits,
            )?;
            logical_bytes = logical_bytes
                .checked_add(staged.descriptor.decoded_len)
                .ok_or_else(|| invalid("logical state byte accounting overflow"))?;
            let descriptor = publish_segment(&self.dir, staged, &self.identity, &self.limits)?;
            published_bytes = published_bytes
                .checked_add(descriptor.file_len)
                .ok_or_else(|| invalid("physical state byte accounting overflow"))?;
            next_state_segments.push(descriptor);
        }

        let manifest = manifest_for_update(
            &self.manifest,
            &self.identity,
            &self.limits,
            self.manifest.built_at_seq.max(seq),
            self.manifest.base_seq.max(seq),
            changed,
            next_state_segments,
        );
        publish_manifest(&self.dir, &manifest, true)?;
        let active = read_active_pointer(&self.dir, &self.identity)?;
        let next_lease = ReaderLease::acquire(&self.dir, &self.identity, &active)?;
        let next_manifest =
            load_manifest_state_at(&self.dir, &self.identity, &self.limits, &active)?;
        let manifest_written = if next_manifest.chain_depth == 1 {
            next_manifest.manifest_bytes
        } else {
            next_manifest
                .manifest_bytes
                .checked_sub(self.manifest.manifest_bytes)
                .ok_or_else(|| invalid("manifest chain byte accounting regressed"))?
        };
        published_bytes = published_bytes
            .checked_add(manifest_written)
            .and_then(|bytes| bytes.checked_add(next_manifest.active_pointer_bytes))
            .ok_or_else(|| invalid("manifest write byte accounting overflow"))?;
        self.manifest = next_manifest;
        self._lease = next_lease;
        self.records = next_records;
        self.cx_to_local.insert(cx_id, local_id);
        self.invalidate_changed_cache(&old_memberships, &memberships)?;
        let reclaimed = self.reclaim_obsolete_files()?;
        let write_amplification = if logical_bytes == 0 {
            0.0
        } else {
            published_bytes as f64 / logical_bytes as f64
        };
        let receipt = SpannPostingWriteReceipt {
            generation: self.manifest.generation,
            logical_decoded_bytes: logical_bytes,
            physical_bytes_written: published_bytes,
            compaction_bytes_written: compaction_bytes,
            write_amplification,
            compacted_postings,
            state_compacted,
            reclaimed_files: reclaimed.files,
            reclaimed_bytes: reclaimed.bytes,
        };
        self.last_write = Some(receipt.clone());
        Ok(receipt)
    }

    pub(super) fn compact_all(&mut self) -> Result<SpannPostingWriteReceipt> {
        if self.records.is_empty() {
            return Err(invalid("cannot compact an empty SPANN index"));
        }
        let _lock = StoreWriteLock::acquire(&self.dir)?;
        let disk_state = load_manifest_state(&self.dir, &self.identity, &self.limits)?;
        if disk_state.manifest_hash != self.manifest.manifest_hash {
            return Err(corrupt("SPANN generation changed before compaction"));
        }
        let generation = self.manifest.generation + 1;
        let mut changed = BTreeMap::new();
        let mut physical = 0_u64;
        let mut logical = 0_u64;
        for centroid_id in 0..self.identity.centroid_count {
            let members = materialize_posting(
                &self.dir,
                &self.manifest.postings[centroid_id as usize],
                &self.identity,
                &self.limits,
            )?;
            let operations = members
                .into_iter()
                .map(PostingMutation::upsert)
                .collect::<Vec<_>>();
            if operations.is_empty() {
                changed.insert(centroid_id, Vec::new());
                continue;
            }
            let staged = build_posting_segment(
                &self.identity,
                centroid_id,
                generation,
                &operations,
                &self.limits,
            )?;
            logical += staged.descriptor.decoded_len;
            let descriptor = publish_segment(&self.dir, staged, &self.identity, &self.limits)?;
            physical += descriptor.file_len;
            changed.insert(centroid_id, vec![descriptor]);
        }
        let mut state_segments = Vec::new();
        for chunk in state_compaction_chunks(self.records.values(), &self.limits)? {
            let staged = build_state_segment(&self.identity, generation, &chunk, &self.limits)?;
            logical += staged.descriptor.decoded_len;
            let descriptor = publish_segment(&self.dir, staged, &self.identity, &self.limits)?;
            physical += descriptor.file_len;
            state_segments.push(descriptor);
        }
        let manifest = manifest_for_update(
            &self.manifest,
            &self.identity,
            &self.limits,
            self.manifest.built_at_seq,
            self.manifest.base_seq,
            changed,
            state_segments,
        );
        publish_manifest(&self.dir, &manifest, true)?;
        let active = read_active_pointer(&self.dir, &self.identity)?;
        let next_lease = ReaderLease::acquire(&self.dir, &self.identity, &active)?;
        self.manifest = load_manifest_state_at(&self.dir, &self.identity, &self.limits, &active)?;
        self._lease = next_lease;
        self.cache
            .lock()
            .map_err(|_| corrupt("posting cache poisoned"))?
            .clear();
        physical += self.manifest.active_pointer_bytes;
        let reclaimed = self.reclaim_obsolete_files()?;
        let receipt = SpannPostingWriteReceipt {
            generation: self.manifest.generation,
            logical_decoded_bytes: logical,
            physical_bytes_written: physical,
            compaction_bytes_written: physical,
            write_amplification: physical as f64 / logical.max(1) as f64,
            compacted_postings: self.identity.centroid_count,
            state_compacted: true,
            reclaimed_files: reclaimed.files,
            reclaimed_bytes: reclaimed.bytes,
        };
        self.last_write = Some(receipt.clone());
        Ok(receipt)
    }

    fn reclaim_obsolete_files(&self) -> Result<ReclaimStats> {
        let reachable = self.live_reachable_files()?;
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|error| io("scan reclaim directory", error))? {
            let entry = entry.map_err(|error| io("read reclaim directory entry", error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.ends_with(".spm") || name.ends_with(".spz") || name.ends_with(".tmp")) {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|error| io("stat reclaim candidate", error))?
                .is_file()
            {
                return Err(corrupt(format!(
                    "posting-owned reclaim path is not a file: {}",
                    entry.path().display()
                )));
            }
            if candidates.len() >= self.limits.max_reclaim_files as usize {
                return Err(corrupt(format!(
                    "posting-owned files exceed registry reclaim limit {}",
                    self.limits.max_reclaim_files
                )));
            }
            let bytes = entry
                .metadata()
                .map_err(|error| io("stat reclaim candidate", error))?
                .len();
            candidates.push((name, entry.path(), bytes));
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let mut reclaimed = ReclaimStats::default();
        for (name, path, bytes) in candidates {
            if reachable.contains(&name) {
                continue;
            }
            fs::remove_file(&path)
                .map_err(|error| io(&format!("reclaim obsolete file {}", path.display()), error))?;
            if path.exists() {
                return Err(corrupt(format!(
                    "reclaimed posting file still exists after delete: {}",
                    path.display()
                )));
            }
            reclaimed.files = reclaimed
                .files
                .checked_add(1)
                .ok_or_else(|| invalid("reclaimed file count overflow"))?;
            reclaimed.bytes = reclaimed
                .bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("reclaimed byte count overflow"))?;
        }
        Ok(reclaimed)
    }

    fn live_reachable_files(&self) -> Result<BTreeSet<String>> {
        let mut targets = live_lease_targets(&self.dir, &self.identity, &self.limits)?;
        targets.sort_by_key(|target| (target.generation, target.manifest_hash));
        targets.dedup_by_key(|target| (target.generation, target.manifest_hash));
        let mut reachable = BTreeSet::new();
        for target in targets {
            let state = load_manifest_state_at(&self.dir, &self.identity, &self.limits, &target)?;
            reachable.extend(reachable_files(&state));
        }
        Ok(reachable)
    }

    pub(super) fn last_write(&self) -> Option<&SpannPostingWriteReceipt> {
        self.last_write.as_ref()
    }

    pub(super) fn physical_stats(&self) -> Result<SpannPostingPhysicalStats> {
        let posting_segment_bytes = self
            .manifest
            .postings
            .iter()
            .flatten()
            .map(|segment| segment.file_len)
            .try_fold(0_u64, |sum, len| sum.checked_add(len))
            .ok_or_else(|| invalid("posting physical byte accounting overflow"))?;
        let state_segment_bytes = self
            .manifest
            .state_segments
            .iter()
            .map(|segment| segment.file_len)
            .try_fold(0_u64, |sum, len| sum.checked_add(len))
            .ok_or_else(|| invalid("state physical byte accounting overflow"))?;
        let active_physical_bytes = posting_segment_bytes
            .checked_add(state_segment_bytes)
            .and_then(|sum| sum.checked_add(self.manifest.manifest_bytes))
            .and_then(|sum| sum.checked_add(self.manifest.active_pointer_bytes))
            .ok_or_else(|| invalid("active physical byte accounting overflow"))?;
        let _lock = StoreWriteLock::acquire(&self.dir)?;
        let current_files = reachable_files(&self.manifest);
        let retained_files = self.live_reachable_files()?;
        let directory = directory_physical_state(
            &self.dir,
            &current_files,
            &retained_files,
            active_physical_bytes,
        )?;
        let cache = self
            .cache
            .lock()
            .map_err(|_| corrupt("posting cache poisoned"))?;
        Ok(SpannPostingPhysicalStats {
            generation: self.manifest.generation,
            records: self.records.len(),
            declared_postings: self.manifest.postings.len(),
            posting_segments: self.manifest.postings.iter().map(Vec::len).sum(),
            state_segments: self.manifest.state_segments.len(),
            posting_segment_bytes,
            state_segment_bytes,
            manifest_chain_bytes: self.manifest.manifest_bytes,
            active_pointer_bytes: self.manifest.active_pointer_bytes,
            active_physical_bytes,
            directory_physical_bytes: directory.total_bytes,
            retained_reader_bytes: directory.retained_reader_bytes,
            reader_lease_bytes: directory.reader_lease_bytes,
            temporary_bytes: directory.temporary_bytes,
            orphan_bytes: directory.orphan_bytes,
            cache_bytes: cache.bytes,
            cache_hits: cache.hits,
            cache_misses: cache.misses,
        })
    }

    pub(super) fn verify_all_postings(&self) -> Result<()> {
        let mut expected =
            vec![BTreeMap::<u32, Vec<(u32, f32)>>::new(); self.identity.centroid_count as usize];
        for record in self.records.values() {
            for centroid in &record.memberships {
                expected[*centroid as usize].insert(record.local_id, record.vector.clone());
            }
        }
        for centroid_id in 0..self.identity.centroid_count {
            let actual = self
                .read_list(centroid_id)?
                .iter()
                .map(|member| (member.cx_id, member.vector.clone()))
                .collect::<BTreeMap<_, _>>();
            if actual != expected[centroid_id as usize] {
                return Err(corrupt(format!(
                    "centroid {centroid_id} materialized membership disagrees with persisted record state"
                )));
            }
        }
        Ok(())
    }

    fn validate_materialized_posting(
        &self,
        centroid_id: u32,
        members: &[PostingMember],
    ) -> Result<()> {
        for member in members {
            let record = self.records.get(&member.cx_id).ok_or_else(|| {
                corrupt(format!(
                    "centroid {centroid_id} references unknown local id {}",
                    member.cx_id
                ))
            })?;
            if record.memberships.binary_search(&centroid_id).is_err()
                || record.vector != member.vector
            {
                return Err(corrupt(format!(
                    "centroid {centroid_id} membership/vector mismatch for local id {}",
                    member.cx_id
                )));
            }
        }
        Ok(())
    }

    fn invalidate_changed_cache(&self, old: &[u32], new: &[u32]) -> Result<()> {
        let changed = old.iter().chain(new).copied().collect::<BTreeSet<_>>();
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| corrupt("posting cache poisoned"))?;
        let keys = cache
            .entries
            .keys()
            .filter(|(centroid, _)| changed.contains(centroid))
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(value) = cache.entries.remove(&key) {
                cache.bytes = cache.bytes.saturating_sub(posting_memory_bytes(&value)?);
            }
            cache.lru.retain(|candidate| *candidate != key);
        }
        Ok(())
    }
}

impl PostingCache {
    fn clear(&mut self) {
        self.entries.clear();
        self.lru.clear();
        self.bytes = 0;
    }
}

impl StoreWriteLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(WRITE_LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            options.share_mode(0);
        }
        let file = options.open(&path).map_err(|error| {
            io(
                &format!(
                    "acquire exclusive posting writer lock {}; another live writer must finish",
                    path.display()
                ),
                error,
            )
        })?;
        Ok(Self { _file: file })
    }
}

fn validate_declared_components(
    manifest: &PostingManifestState,
    identity: &SpannIndexIdentity,
) -> Result<()> {
    if manifest.postings.len() != identity.centroid_count as usize {
        return Err(corrupt(format!(
            "manifest declares {} postings for {} centroids",
            manifest.postings.len(),
            identity.centroid_count
        )));
    }
    let mut names = BTreeSet::new();
    for descriptor in manifest
        .postings
        .iter()
        .flatten()
        .chain(&manifest.state_segments)
    {
        if !names.insert(descriptor.file_name.clone()) {
            return Err(corrupt(format!(
                "segment {} is declared more than once",
                descriptor.file_name
            )));
        }
    }
    Ok(())
}

fn load_records(
    dir: &Path,
    manifest: &PostingManifestState,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<(BTreeMap<u32, StoredRecord>, BTreeMap<CxId, u32>)> {
    let mut records = BTreeMap::new();
    for descriptor in &manifest.state_segments {
        let DecodedSegment::State(segment_records) =
            read_segment(dir, descriptor, identity, limits)?
        else {
            return Err(corrupt(format!(
                "state descriptor {} decoded as posting data",
                descriptor.file_name
            )));
        };
        for record in segment_records {
            records.insert(record.local_id, record);
        }
    }
    let mut cx_to_local = BTreeMap::new();
    for (expected, (local, record)) in (0_u32..).zip(&records) {
        if *local != expected || record.local_id != *local {
            return Err(corrupt(format!(
                "persisted local-id map has gap: expected {expected}, found {local}"
            )));
        }
        if cx_to_local.insert(record.cx_id, *local).is_some() {
            return Err(corrupt(format!(
                "persisted local-id map duplicates CxId {}",
                record.cx_id
            )));
        }
        validate_sparse_vector(&record.vector, identity.dim, limits)?;
        validate_memberships(&record.memberships, identity.centroid_count)?;
    }
    Ok((records, cx_to_local))
}

fn materialize_posting(
    dir: &Path,
    segments: &[SegmentDescriptor],
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<Vec<PostingMember>> {
    if segments.len() > limits.max_segments_per_posting as usize {
        return Err(corrupt(format!(
            "posting has {} segments above registry limit {}",
            segments.len(),
            limits.max_segments_per_posting
        )));
    }
    let mut entries = BTreeMap::new();
    let mut previous_generation = 0_u64;
    for descriptor in segments {
        if descriptor.kind != SegmentKind::Posting || descriptor.generation < previous_generation {
            return Err(corrupt(format!(
                "posting segment order/kind invalid at {}",
                descriptor.file_name
            )));
        }
        let DecodedSegment::Posting(operations) = read_segment(dir, descriptor, identity, limits)?
        else {
            return Err(corrupt(format!(
                "posting descriptor {} decoded as state data",
                descriptor.file_name
            )));
        };
        for operation in operations {
            apply_mutation(&mut entries, operation);
        }
        previous_generation = descriptor.generation;
    }
    Ok(entries.into_values().collect())
}

fn apply_mutation(entries: &mut BTreeMap<u32, PostingMember>, operation: PostingMutation) {
    match operation.vector {
        Some(vector) => {
            entries.insert(
                operation.cx_id,
                PostingMember {
                    cx_id: operation.cx_id,
                    vector,
                },
            );
        }
        None => {
            entries.remove(&operation.cx_id);
        }
    }
}

fn validate_memberships(memberships: &[u32], centroid_count: u32) -> Result<()> {
    if memberships.is_empty() {
        return Err(invalid(
            "SPANN record requires at least one centroid membership",
        ));
    }
    let mut previous = None;
    for centroid in memberships {
        if *centroid >= centroid_count || previous.is_some_and(|last| *centroid <= last) {
            return Err(invalid(format!(
                "SPANN memberships must be strictly increasing within 0..{centroid_count}: {memberships:?}"
            )));
        }
        previous = Some(*centroid);
    }
    Ok(())
}

fn state_compaction_chunks<'a>(
    records: impl Iterator<Item = &'a StoredRecord>,
    limits: &SpannPostingLimits,
) -> Result<Vec<Vec<StoredRecord>>> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 4_u64;
    for record in records {
        let record_bytes = estimate_state_record_bytes(record)?;
        if record_bytes + 4 > limits.max_decoded_segment_bytes {
            return Err(invalid(format!(
                "state record {} needs {record_bytes} bytes above segment limit {}",
                record.local_id, limits.max_decoded_segment_bytes
            )));
        }
        if !current.is_empty()
            && (current.len() >= limits.max_members_per_segment as usize
                || current_bytes + record_bytes > limits.max_decoded_segment_bytes)
        {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 4;
        }
        current.push(record.clone());
        current_bytes += record_bytes;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
}

fn estimate_state_record_bytes(record: &StoredRecord) -> Result<u64> {
    let mut bytes = varint_len(record.local_id) as u64 + 16 + 8;
    bytes += varint_len(record.memberships.len() as u32) as u64;
    let mut previous = 0_u32;
    for (ordinal, centroid) in record.memberships.iter().enumerate() {
        bytes += varint_len(if ordinal == 0 {
            *centroid
        } else {
            *centroid - previous
        }) as u64;
        previous = *centroid;
    }
    bytes += varint_len(record.vector.len() as u32) as u64;
    let mut previous_idx = 0_u32;
    for (ordinal, (idx, _)) in record.vector.iter().enumerate() {
        bytes += varint_len(if ordinal == 0 {
            *idx
        } else {
            *idx - previous_idx
        }) as u64
            + 4;
        previous_idx = *idx;
    }
    Ok(bytes)
}

const fn varint_len(mut value: u32) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn posting_fingerprint(segments: &[SegmentDescriptor]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx-spann-posting-view-v3");
    for segment in segments {
        hasher.update(&segment.file_hash);
    }
    *hasher.finalize().as_bytes()
}

fn posting_memory_bytes(members: &[PostingMember]) -> Result<u64> {
    members.iter().try_fold(0_u64, |sum, member| {
        let vector_bytes = u64::try_from(member.vector.len())
            .ok()
            .and_then(|len| len.checked_mul(8))
            .ok_or_else(|| invalid("posting cache vector byte overflow"))?;
        sum.checked_add(32)
            .and_then(|value| value.checked_add(vector_bytes))
            .ok_or_else(|| invalid("posting cache byte overflow"))
    })
}

fn touch_lru(lru: &mut VecDeque<(u32, [u8; 32])>, key: (u32, [u8; 32])) {
    lru.retain(|candidate| *candidate != key);
    lru.push_back(key);
}

fn reachable_files(manifest: &PostingManifestState) -> BTreeSet<String> {
    manifest
        .manifest_files
        .iter()
        .cloned()
        .chain(
            manifest
                .postings
                .iter()
                .flatten()
                .chain(&manifest.state_segments)
                .map(|descriptor| descriptor.file_name.clone()),
        )
        .collect()
}

fn directory_physical_state(
    dir: &Path,
    current_files: &BTreeSet<String>,
    retained_files: &BTreeSet<String>,
    expected_active_bytes: u64,
) -> Result<DirectoryPhysicalState> {
    let mut state = DirectoryPhysicalState::default();
    let mut observed_active_bytes = 0_u64;
    for entry in fs::read_dir(dir).map_err(|error| io("scan posting directory", error))? {
        let entry = entry.map_err(|error| io("read posting directory entry", error))?;
        let metadata = entry
            .metadata()
            .map_err(|error| io("stat posting directory entry", error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let posting_owned = name == ACTIVE_FILE
            || name == WRITE_LOCK_FILE
            || name.ends_with(".spz")
            || name.ends_with(".spm")
            || name.ends_with(".tmp")
            || name.ends_with(".lease");
        if !posting_owned {
            continue;
        }
        if !metadata.is_file() {
            return Err(corrupt(format!(
                "posting-owned path is not a file: {}",
                entry.path().display()
            )));
        }
        state.total_bytes = state
            .total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("posting directory byte accounting overflow"))?;
        if name == ACTIVE_FILE || current_files.contains(name.as_ref()) {
            observed_active_bytes = observed_active_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("active byte accounting overflow"))?;
        } else if retained_files.contains(name.as_ref()) {
            state.retained_reader_bytes =
                state
                    .retained_reader_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| invalid("retained-reader byte accounting overflow"))?;
        } else if name.ends_with(".lease") {
            state.reader_lease_bytes = state
                .reader_lease_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("reader-lease byte accounting overflow"))?;
        } else {
            state.orphan_bytes = state
                .orphan_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("orphan byte accounting overflow"))?;
            if name.ends_with(".tmp") {
                state.temporary_bytes = state
                    .temporary_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| invalid("temporary byte accounting overflow"))?;
            }
        }
    }
    if observed_active_bytes != expected_active_bytes {
        return Err(corrupt(format!(
            "physical active bytes {observed_active_bytes} != declared {expected_active_bytes}"
        )));
    }
    Ok(state)
}
