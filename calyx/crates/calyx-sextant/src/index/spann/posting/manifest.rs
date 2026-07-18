use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{Result, SlotId};

use super::config::{
    SPANN_ACTIVE_MAGIC, SPANN_MANIFEST_MAGIC, SPANN_POSTING_FORMAT_VERSION, SpannDistanceMetric,
    SpannIndexIdentity, SpannPostingLimits,
};
use super::format::{
    SegmentDescriptor, SegmentKind, limits_hash, move_file_write_through, safe_component_path,
};
use super::{corrupt, io};

const MANIFEST_HEADER_BYTES: usize = 248;
const ACTIVE_POINTER_BYTES: usize = 128;
const ACTIVE_SEAL_OFFSET: usize = 96;
const SEAL_BYTES: usize = 32;
const ACTIVE_FILE: &str = "postings.active";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ManifestKind {
    Snapshot = 1,
    Delta = 2,
}

impl ManifestKind {
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Delta),
            _ => Err(corrupt(format!("unknown SPANN manifest kind {tag}"))),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct PostingChange {
    pub centroid_id: u32,
    pub segments: Vec<SegmentDescriptor>,
}

#[derive(Clone, Debug)]
pub(super) struct PostingManifest {
    pub kind: ManifestKind,
    pub generation: u64,
    pub parent_generation: u64,
    pub parent_hash: [u8; 32],
    pub chain_depth: u16,
    pub built_at_seq: u64,
    pub base_seq: u64,
    pub identity: SpannIndexIdentity,
    pub limits: SpannPostingLimits,
    pub state_segments: Option<Vec<SegmentDescriptor>>,
    pub changes: Vec<PostingChange>,
}

#[derive(Clone, Debug)]
pub(super) struct PostingManifestState {
    pub generation: u64,
    pub manifest_hash: [u8; 32],
    pub chain_depth: u16,
    pub built_at_seq: u64,
    pub base_seq: u64,
    pub postings: Vec<Vec<SegmentDescriptor>>,
    pub state_segments: Vec<SegmentDescriptor>,
    pub manifest_files: Vec<String>,
    pub manifest_bytes: u64,
    pub active_pointer_bytes: u64,
}

impl PostingManifestState {
    pub(super) fn empty(identity: &SpannIndexIdentity) -> Self {
        Self {
            generation: 0,
            manifest_hash: [0; 32],
            chain_depth: 0,
            built_at_seq: 0,
            base_seq: 0,
            postings: vec![Vec::new(); identity.centroid_count as usize],
            state_segments: Vec::new(),
            manifest_files: Vec::new(),
            manifest_bytes: 0,
            active_pointer_bytes: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ActivePointer {
    pub generation: u64,
    pub manifest_len: u64,
    pub manifest_hash: [u8; 32],
    pub index_id: [u8; 32],
}

pub(super) fn create_genesis(
    dir: &Path,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<PostingManifestState> {
    if dir.join(ACTIVE_FILE).exists() {
        return Err(corrupt(format!(
            "SPANN active pointer already exists in {}",
            dir.display()
        )));
    }
    let changes = (0..identity.centroid_count)
        .map(|centroid_id| PostingChange {
            centroid_id,
            segments: Vec::new(),
        })
        .collect();
    let manifest = PostingManifest {
        kind: ManifestKind::Snapshot,
        generation: 1,
        parent_generation: 0,
        parent_hash: [0; 32],
        chain_depth: 1,
        built_at_seq: 0,
        base_seq: 0,
        identity: identity.clone(),
        limits: limits.clone(),
        state_segments: Some(Vec::new()),
        changes,
    };
    publish_manifest(dir, &manifest, false)?;
    load_manifest_state(dir, identity, limits)
}

pub(super) fn publish_manifest(
    dir: &Path,
    manifest: &PostingManifest,
    replace_active: bool,
) -> Result<[u8; 32]> {
    fs::create_dir_all(dir).map_err(|error| io("create manifest directory", error))?;
    let bytes = encode_manifest(manifest)?;
    let hash = *blake3::hash(&bytes).as_bytes();
    let manifest_name = manifest_file_name(manifest.generation, &hash);
    let manifest_path = safe_component_path(dir, &manifest_name)?;
    if manifest_path.exists() {
        return Err(corrupt(format!(
            "immutable manifest target already exists: {}",
            manifest_path.display()
        )));
    }
    let manifest_temp = unique_temp_path(&manifest_path)?;
    let active_path = dir.join(ACTIVE_FILE);
    let active_temp = unique_temp_path(&active_path)?;
    let result = (|| {
        write_synced_new(&manifest_temp, &bytes, "manifest")?;
        let manifest_readback = read_bounded_file(
            &manifest_temp,
            bytes.len() as u64,
            manifest.limits.max_manifest_bytes,
            "staged manifest",
        )?;
        if blake3::hash(&manifest_readback).as_bytes() != &hash {
            return Err(corrupt("staged manifest hash mismatch"));
        }
        decode_manifest(&manifest_readback, &manifest.identity, &manifest.limits)?;
        move_file_write_through(&manifest_temp, &manifest_path, false)?;

        let pointer = ActivePointer {
            generation: manifest.generation,
            manifest_len: bytes.len() as u64,
            manifest_hash: hash,
            index_id: manifest.identity.index_id,
        };
        let pointer_bytes = encode_active_pointer(&pointer);
        write_synced_new(&active_temp, &pointer_bytes, "active pointer")?;
        let pointer_readback = read_bounded_file(
            &active_temp,
            ACTIVE_POINTER_BYTES as u64,
            ACTIVE_POINTER_BYTES as u64,
            "staged active pointer",
        )?;
        if decode_active_pointer(&pointer_readback, &manifest.identity)? != pointer.manifest_hash {
            return Err(corrupt("staged active pointer readback changed"));
        }
        move_file_write_through(&active_temp, &active_path, replace_active)?;
        let final_pointer = read_bounded_file(
            &active_path,
            ACTIVE_POINTER_BYTES as u64,
            ACTIVE_POINTER_BYTES as u64,
            "published active pointer",
        )?;
        if decode_active_pointer(&final_pointer, &manifest.identity)? != hash {
            return Err(corrupt("published active pointer readback changed"));
        }
        Ok(hash)
    })();
    if result.is_err() {
        for temp in [&manifest_temp, &active_temp] {
            if temp.exists()
                && let Err(error) = fs::remove_file(temp)
            {
                tracing::error!(
                    path = %temp.display(),
                    %error,
                    "failed to remove uncommitted SPANN manifest temp"
                );
            }
        }
    }
    result
}

pub(super) fn load_manifest_state(
    dir: &Path,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<PostingManifestState> {
    limits.validate()?;
    let active = read_active_pointer(dir, identity)?;
    load_manifest_state_at(dir, identity, limits, &active)
}

pub(super) fn read_active_pointer(
    dir: &Path,
    identity: &SpannIndexIdentity,
) -> Result<ActivePointer> {
    let active_path = dir.join(ACTIVE_FILE);
    let active_bytes = read_bounded_file(
        &active_path,
        ACTIVE_POINTER_BYTES as u64,
        ACTIVE_POINTER_BYTES as u64,
        "active pointer",
    )?;
    parse_active_pointer(&active_bytes, identity)
}

pub(super) fn load_manifest_state_at(
    dir: &Path,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
    active: &ActivePointer,
) -> Result<PostingManifestState> {
    limits.validate()?;
    if active.index_id != identity.index_id {
        return Err(corrupt("leased manifest index identity mismatch"));
    }
    let mut expected_generation = active.generation;
    let mut expected_hash = active.manifest_hash;
    let mut expected_len = Some(active.manifest_len);
    let mut reverse_chain = Vec::new();
    loop {
        if reverse_chain.len() >= limits.max_manifest_chain as usize {
            return Err(corrupt(format!(
                "manifest chain exceeds registry limit {}",
                limits.max_manifest_chain
            )));
        }
        let name = manifest_file_name(expected_generation, &expected_hash);
        let path = safe_component_path(dir, &name)?;
        let bytes = match expected_len {
            Some(len) => read_bounded_file(&path, len, limits.max_manifest_bytes, "manifest")?,
            None => read_bounded_file_from_stat(&path, limits.max_manifest_bytes, "manifest")?,
        };
        let actual_hash = *blake3::hash(&bytes).as_bytes();
        if actual_hash != expected_hash {
            return Err(corrupt(format!("manifest {name} checksum mismatch")));
        }
        let manifest = decode_manifest(&bytes, identity, limits)?;
        if manifest.generation != expected_generation {
            return Err(corrupt(format!(
                "manifest {name} generation {} != expected {expected_generation}",
                manifest.generation
            )));
        }
        let is_snapshot = manifest.kind == ManifestKind::Snapshot;
        expected_generation = manifest.parent_generation;
        expected_hash = manifest.parent_hash;
        expected_len = None;
        reverse_chain.push((manifest, bytes.len() as u64, actual_hash, name));
        if is_snapshot {
            break;
        }
    }
    reverse_chain.reverse();
    let mut state = PostingManifestState::empty(identity);
    let mut total_manifest_bytes = 0_u64;
    let mut previous_generation = 0_u64;
    let mut previous_hash = [0_u8; 32];
    let mut current_hash = [0_u8; 32];
    for (ordinal, (manifest, manifest_bytes, manifest_hash, manifest_name)) in
        reverse_chain.into_iter().enumerate()
    {
        total_manifest_bytes = total_manifest_bytes
            .checked_add(manifest_bytes)
            .ok_or_else(|| corrupt("manifest byte accounting overflow"))?;
        if ordinal == 0 && manifest.kind != ManifestKind::Snapshot {
            return Err(corrupt("manifest chain does not terminate at a snapshot"));
        }
        if manifest.chain_depth as usize != ordinal + 1 {
            return Err(corrupt(format!(
                "manifest generation {} chain depth {} != {}",
                manifest.generation,
                manifest.chain_depth,
                ordinal + 1
            )));
        }
        if ordinal > 0
            && (manifest.parent_generation != previous_generation
                || manifest.parent_hash != previous_hash)
        {
            return Err(corrupt(format!(
                "manifest generation {} does not bind its exact parent",
                manifest.generation
            )));
        }
        if manifest.kind == ManifestKind::Snapshot {
            state.postings = vec![Vec::new(); identity.centroid_count as usize];
            let declared = manifest
                .changes
                .iter()
                .map(|change| change.centroid_id)
                .collect::<BTreeSet<_>>();
            if declared.len() != identity.centroid_count as usize
                || declared.iter().copied().ne(0..identity.centroid_count)
            {
                return Err(corrupt(
                    "snapshot does not declare every centroid exactly once",
                ));
            }
        }
        for change in manifest.changes {
            state.postings[change.centroid_id as usize] = change.segments;
        }
        if let Some(state_segments) = manifest.state_segments {
            state.state_segments = state_segments;
        } else if manifest.kind == ManifestKind::Snapshot {
            return Err(corrupt("snapshot omits state segment declaration"));
        }
        state.generation = manifest.generation;
        state.chain_depth = manifest.chain_depth;
        state.built_at_seq = manifest.built_at_seq;
        state.base_seq = manifest.base_seq;
        previous_generation = manifest.generation;
        previous_hash = manifest_hash;
        current_hash = manifest_hash;
        state.manifest_files.push(manifest_name);
    }
    if state.generation != active.generation || current_hash != active.manifest_hash {
        return Err(corrupt(
            "active generation/hash changed during manifest chain load",
        ));
    }
    state.manifest_hash = active.manifest_hash;
    state.manifest_bytes = total_manifest_bytes;
    state.active_pointer_bytes = ACTIVE_POINTER_BYTES as u64;
    Ok(state)
}

pub(super) fn manifest_for_update(
    current: &PostingManifestState,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
    built_at_seq: u64,
    base_seq: u64,
    changed: BTreeMap<u32, Vec<SegmentDescriptor>>,
    state_segments: Vec<SegmentDescriptor>,
) -> PostingManifest {
    let next_generation = current.generation + 1;
    let snapshot = current.chain_depth >= limits.max_manifest_chain;
    let (kind, parent_generation, parent_hash, chain_depth, changes) = if snapshot {
        let mut postings = current.postings.clone();
        for (centroid, segments) in changed {
            postings[centroid as usize] = segments;
        }
        (
            ManifestKind::Snapshot,
            0,
            [0; 32],
            1,
            postings
                .into_iter()
                .enumerate()
                .map(|(centroid_id, segments)| PostingChange {
                    centroid_id: centroid_id as u32,
                    segments,
                })
                .collect(),
        )
    } else {
        (
            ManifestKind::Delta,
            current.generation,
            current.manifest_hash,
            current.chain_depth + 1,
            changed
                .into_iter()
                .map(|(centroid_id, segments)| PostingChange {
                    centroid_id,
                    segments,
                })
                .collect(),
        )
    };
    PostingManifest {
        kind,
        generation: next_generation,
        parent_generation,
        parent_hash,
        chain_depth,
        built_at_seq,
        base_seq,
        identity: identity.clone(),
        limits: limits.clone(),
        state_segments: Some(state_segments),
        changes,
    }
}

fn encode_manifest(manifest: &PostingManifest) -> Result<Vec<u8>> {
    manifest.limits.validate()?;
    validate_manifest(manifest)?;
    let state_segments = manifest.state_segments.as_deref().unwrap_or(&[]);
    let state_count = u32::try_from(state_segments.len())
        .map_err(|_| corrupt("state segment count exceeds u32"))?;
    let change_count = u32::try_from(manifest.changes.len())
        .map_err(|_| corrupt("posting change count exceeds u32"))?;
    let mut bytes = Vec::with_capacity(MANIFEST_HEADER_BYTES + SEAL_BYTES + 256);
    bytes.extend_from_slice(&SPANN_MANIFEST_MAGIC);
    bytes.extend_from_slice(&SPANN_POSTING_FORMAT_VERSION.to_le_bytes());
    bytes.push(manifest.kind as u8);
    bytes.push(manifest.identity.metric.tag());
    bytes.extend_from_slice(&manifest.identity.index_id);
    bytes.extend_from_slice(&manifest.identity.centroid_hash);
    bytes.extend_from_slice(&manifest.generation.to_le_bytes());
    bytes.extend_from_slice(&manifest.parent_generation.to_le_bytes());
    bytes.extend_from_slice(&manifest.parent_hash);
    bytes.extend_from_slice(&manifest.identity.slot.get().to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&manifest.identity.dim.to_le_bytes());
    bytes.extend_from_slice(&manifest.identity.centroid_count.to_le_bytes());
    bytes.extend_from_slice(&manifest.built_at_seq.to_le_bytes());
    bytes.extend_from_slice(&manifest.base_seq.to_le_bytes());
    bytes.extend_from_slice(&manifest.chain_depth.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    manifest.limits.encode(&mut bytes);
    bytes.push(u8::from(manifest.state_segments.is_some()));
    bytes.extend_from_slice(&[0_u8; 3]);
    bytes.extend_from_slice(&state_count.to_le_bytes());
    bytes.extend_from_slice(&change_count.to_le_bytes());
    if bytes.len() != MANIFEST_HEADER_BYTES {
        return Err(corrupt(format!(
            "internal manifest header size {} != {MANIFEST_HEADER_BYTES}",
            bytes.len()
        )));
    }
    for descriptor in state_segments {
        encode_descriptor(descriptor, &mut bytes)?;
    }
    for change in &manifest.changes {
        bytes.extend_from_slice(&change.centroid_id.to_le_bytes());
        let count = u16::try_from(change.segments.len())
            .map_err(|_| corrupt("posting segment count exceeds u16"))?;
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        for descriptor in &change.segments {
            encode_descriptor(descriptor, &mut bytes)?;
        }
    }
    if bytes.len() as u64 + SEAL_BYTES as u64 > manifest.limits.max_manifest_bytes {
        return Err(corrupt(format!(
            "manifest bytes {} exceed registry limit {}",
            bytes.len() + SEAL_BYTES,
            manifest.limits.max_manifest_bytes
        )));
    }
    let seal = blake3::hash(&bytes);
    bytes.extend_from_slice(seal.as_bytes());
    Ok(bytes)
}

fn decode_manifest(
    bytes: &[u8],
    expected_identity: &SpannIndexIdentity,
    expected_limits: &SpannPostingLimits,
) -> Result<PostingManifest> {
    if bytes.len() < MANIFEST_HEADER_BYTES + SEAL_BYTES {
        return Err(corrupt(format!("manifest is only {} B", bytes.len())));
    }
    if bytes.len() as u64 > expected_limits.max_manifest_bytes {
        return Err(corrupt(format!(
            "manifest length {} exceeds registry limit {}",
            bytes.len(),
            expected_limits.max_manifest_bytes
        )));
    }
    let seal_offset = bytes.len() - SEAL_BYTES;
    if blake3::hash(&bytes[..seal_offset]).as_bytes() != &bytes[seal_offset..] {
        return Err(corrupt("manifest seal mismatch"));
    }
    let mut cursor = 0_usize;
    if take_array::<8>(bytes, &mut cursor, "manifest magic")? != SPANN_MANIFEST_MAGIC {
        return Err(corrupt("bad manifest magic"));
    }
    let version = read_u16(bytes, &mut cursor, "manifest version")?;
    if version != SPANN_POSTING_FORMAT_VERSION {
        return Err(corrupt(format!("unsupported manifest version {version}")));
    }
    let kind = ManifestKind::from_tag(read_u8(bytes, &mut cursor, "manifest kind")?)?;
    let metric = SpannDistanceMetric::from_tag(read_u8(bytes, &mut cursor, "manifest metric")?)?;
    let index_id = take_array::<32>(bytes, &mut cursor, "manifest index id")?;
    let centroid_hash = take_array::<32>(bytes, &mut cursor, "manifest centroid hash")?;
    let generation = read_u64(bytes, &mut cursor, "manifest generation")?;
    let parent_generation = read_u64(bytes, &mut cursor, "manifest parent generation")?;
    let parent_hash = take_array::<32>(bytes, &mut cursor, "manifest parent hash")?;
    let slot = SlotId::new(read_u16(bytes, &mut cursor, "manifest slot")?);
    let reserved = read_u16(bytes, &mut cursor, "manifest reserved")?;
    let dim = read_u32(bytes, &mut cursor, "manifest dim")?;
    let centroid_count = read_u32(bytes, &mut cursor, "manifest centroid count")?;
    let built_at_seq = read_u64(bytes, &mut cursor, "manifest built sequence")?;
    let base_seq = read_u64(bytes, &mut cursor, "manifest base sequence")?;
    let chain_depth = read_u16(bytes, &mut cursor, "manifest chain depth")?;
    let reserved2 = read_u16(bytes, &mut cursor, "manifest reserved")?;
    if reserved != 0 || reserved2 != 0 {
        return Err(corrupt("manifest reserved field is nonzero"));
    }
    let limits = decode_limits(bytes, &mut cursor)?;
    let state_mode = read_u8(bytes, &mut cursor, "manifest state mode")?;
    let reserved3 = take_array::<3>(bytes, &mut cursor, "manifest reserved")?;
    if reserved3 != [0; 3] || state_mode > 1 {
        return Err(corrupt("manifest state mode/reserved field invalid"));
    }
    let state_count = read_u32(bytes, &mut cursor, "manifest state count")?;
    let change_count = read_u32(bytes, &mut cursor, "manifest change count")?;
    if cursor != MANIFEST_HEADER_BYTES {
        return Err(corrupt("manifest header cursor mismatch"));
    }
    let identity = SpannIndexIdentity {
        index_id,
        centroid_hash,
        slot,
        dim,
        centroid_count,
        metric,
    };
    if &identity != expected_identity || &limits != expected_limits {
        return Err(corrupt(
            "manifest index identity or registry limits disagree with opener",
        ));
    }
    if limits_hash(&limits) != limits_hash(expected_limits) {
        return Err(corrupt("manifest registry hash mismatch"));
    }
    let state_segments = if state_mode == 1 {
        let count = checked_count_before_allocation(
            state_count,
            seal_offset.saturating_sub(cursor),
            84,
            "state descriptors",
        )?;
        let mut segments = Vec::with_capacity(count);
        for _ in 0..state_count {
            segments.push(decode_descriptor(bytes, &mut cursor, seal_offset)?);
        }
        Some(segments)
    } else {
        if state_count != 0 {
            return Err(corrupt("manifest state count without replacement mode"));
        }
        None
    };
    let change_capacity = checked_count_before_allocation(
        change_count,
        seal_offset.saturating_sub(cursor),
        8,
        "posting changes",
    )?;
    let mut changes = Vec::with_capacity(change_capacity);
    let mut seen = BTreeSet::new();
    let mut previous_centroid = None;
    for _ in 0..change_count {
        let centroid_id = read_u32(bytes, &mut cursor, "change centroid")?;
        let segment_count = read_u16(bytes, &mut cursor, "change segment count")?;
        let reserved = read_u16(bytes, &mut cursor, "change reserved")?;
        if centroid_id >= identity.centroid_count
            || !seen.insert(centroid_id)
            || previous_centroid.is_some_and(|previous| centroid_id <= previous)
            || reserved != 0
        {
            return Err(corrupt(format!(
                "invalid or duplicate posting change for centroid {centroid_id}"
            )));
        }
        if segment_count > limits.max_segments_per_posting {
            return Err(corrupt(format!(
                "centroid {centroid_id} segment count {segment_count} exceeds registry limit {}",
                limits.max_segments_per_posting
            )));
        }
        let count = checked_count_before_allocation(
            u32::from(segment_count),
            seal_offset.saturating_sub(cursor),
            84,
            "posting descriptors",
        )?;
        let mut segments = Vec::with_capacity(count);
        for _ in 0..segment_count {
            let descriptor = decode_descriptor(bytes, &mut cursor, seal_offset)?;
            if descriptor.kind != SegmentKind::Posting || descriptor.centroid_id != centroid_id {
                return Err(corrupt(format!(
                    "centroid {centroid_id} references mismatched segment {}",
                    descriptor.file_name
                )));
            }
            segments.push(descriptor);
        }
        changes.push(PostingChange {
            centroid_id,
            segments,
        });
        previous_centroid = Some(centroid_id);
    }
    if cursor != seal_offset {
        return Err(corrupt(format!(
            "{} trailing manifest payload bytes",
            seal_offset - cursor
        )));
    }
    let manifest = PostingManifest {
        kind,
        generation,
        parent_generation,
        parent_hash,
        chain_depth,
        built_at_seq,
        base_seq,
        identity,
        limits,
        state_segments,
        changes,
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &PostingManifest) -> Result<()> {
    if manifest.generation == 0 || manifest.chain_depth == 0 {
        return Err(corrupt(
            "manifest generation and chain depth must be positive",
        ));
    }
    match manifest.kind {
        ManifestKind::Snapshot => {
            if manifest.parent_generation != 0
                || manifest.parent_hash != [0; 32]
                || manifest.chain_depth != 1
                || manifest.state_segments.is_none()
            {
                return Err(corrupt("snapshot parent/depth/state contract invalid"));
            }
        }
        ManifestKind::Delta => {
            if manifest.parent_generation + 1 != manifest.generation
                || manifest.parent_hash == [0; 32]
                || manifest.chain_depth <= 1
            {
                return Err(corrupt("delta parent/depth contract invalid"));
            }
        }
    }
    if manifest.base_seq > manifest.built_at_seq {
        return Err(corrupt("manifest base sequence exceeds built sequence"));
    }
    if manifest
        .state_segments
        .as_ref()
        .is_some_and(|segments| segments.len() > manifest.limits.max_state_segments as usize)
    {
        return Err(corrupt("state segment count exceeds registry limit"));
    }
    let mut previous_state_key = None;
    for descriptor in manifest.state_segments.iter().flatten() {
        if descriptor.kind != SegmentKind::State || descriptor.centroid_id != u32::MAX {
            return Err(corrupt(format!(
                "state declaration references non-state segment {}",
                descriptor.file_name
            )));
        }
        let key = (descriptor.generation, descriptor.min_local_id);
        if previous_state_key.is_some_and(|previous| key < previous) {
            return Err(corrupt("state segment declarations are not canonical"));
        }
        previous_state_key = Some(key);
    }
    let mut previous_change = None;
    for change in &manifest.changes {
        if previous_change.is_some_and(|previous| change.centroid_id <= previous) {
            return Err(corrupt("posting changes are not strictly ordered"));
        }
        previous_change = Some(change.centroid_id);
        let mut previous_generation = 0_u64;
        for descriptor in &change.segments {
            if descriptor.kind != SegmentKind::Posting
                || descriptor.centroid_id != change.centroid_id
                || descriptor.generation < previous_generation
            {
                return Err(corrupt(format!(
                    "posting segment declaration is noncanonical for centroid {}",
                    change.centroid_id
                )));
            }
            previous_generation = descriptor.generation;
        }
    }
    Ok(())
}

fn encode_descriptor(descriptor: &SegmentDescriptor, out: &mut Vec<u8>) -> Result<()> {
    let name = descriptor.file_name.as_bytes();
    let name_len = u16::try_from(name.len()).map_err(|_| corrupt("segment name exceeds u16"))?;
    if name.is_empty() || name.len() > 255 {
        return Err(corrupt("segment name length outside 1..=255"));
    }
    out.push(descriptor.kind as u8);
    out.push(0);
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&descriptor.centroid_id.to_le_bytes());
    out.extend_from_slice(&descriptor.generation.to_le_bytes());
    out.extend_from_slice(&descriptor.record_count.to_le_bytes());
    out.extend_from_slice(&descriptor.min_local_id.to_le_bytes());
    out.extend_from_slice(&descriptor.max_local_id.to_le_bytes());
    out.extend_from_slice(&descriptor.file_len.to_le_bytes());
    out.extend_from_slice(&descriptor.decoded_len.to_le_bytes());
    out.extend_from_slice(&descriptor.compressed_len.to_le_bytes());
    out.extend_from_slice(&descriptor.file_hash);
    out.extend_from_slice(name);
    Ok(())
}

fn decode_descriptor(
    bytes: &[u8],
    cursor: &mut usize,
    payload_end: usize,
) -> Result<SegmentDescriptor> {
    if payload_end.saturating_sub(*cursor) < 84 {
        return Err(corrupt("truncated segment descriptor"));
    }
    let kind = SegmentKind::from_tag(read_u8(bytes, cursor, "descriptor kind")?)?;
    if read_u8(bytes, cursor, "descriptor reserved")? != 0 {
        return Err(corrupt("segment descriptor reserved byte is nonzero"));
    }
    let name_len = read_u16(bytes, cursor, "descriptor name length")? as usize;
    let centroid_id = read_u32(bytes, cursor, "descriptor centroid")?;
    let generation = read_u64(bytes, cursor, "descriptor generation")?;
    let record_count = read_u32(bytes, cursor, "descriptor record count")?;
    let min_local_id = read_u32(bytes, cursor, "descriptor min id")?;
    let max_local_id = read_u32(bytes, cursor, "descriptor max id")?;
    let file_len = read_u64(bytes, cursor, "descriptor file length")?;
    let decoded_len = read_u64(bytes, cursor, "descriptor decoded length")?;
    let compressed_len = read_u64(bytes, cursor, "descriptor compressed length")?;
    let file_hash = take_array::<32>(bytes, cursor, "descriptor file hash")?;
    if name_len == 0 || name_len > 255 || name_len > payload_end.saturating_sub(*cursor) {
        return Err(corrupt(format!(
            "segment descriptor name length {name_len} is invalid"
        )));
    }
    let name_bytes = &bytes[*cursor..*cursor + name_len];
    *cursor += name_len;
    let file_name = std::str::from_utf8(name_bytes)
        .map_err(|_| corrupt("segment descriptor name is not UTF-8"))?
        .to_string();
    validate_component_name(&file_name)?;
    if file_len != 232_u64.saturating_add(compressed_len) {
        return Err(corrupt(format!(
            "segment {file_name} file/compressed length mismatch"
        )));
    }
    if record_count == 0 && (min_local_id != 0 || max_local_id != 0)
        || record_count > 0 && min_local_id > max_local_id
    {
        return Err(corrupt(format!(
            "segment {file_name} id range/count mismatch"
        )));
    }
    Ok(SegmentDescriptor {
        kind,
        centroid_id,
        generation,
        record_count,
        min_local_id,
        max_local_id,
        file_len,
        decoded_len,
        compressed_len,
        file_hash,
        file_name,
    })
}

fn encode_active_pointer(pointer: &ActivePointer) -> [u8; ACTIVE_POINTER_BYTES] {
    let mut bytes = [0_u8; ACTIVE_POINTER_BYTES];
    bytes[0..8].copy_from_slice(&SPANN_ACTIVE_MAGIC);
    bytes[8..10].copy_from_slice(&SPANN_POSTING_FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(ACTIVE_POINTER_BYTES as u16).to_le_bytes());
    bytes[12..20].copy_from_slice(&pointer.generation.to_le_bytes());
    bytes[20..28].copy_from_slice(&pointer.manifest_len.to_le_bytes());
    bytes[28..60].copy_from_slice(&pointer.manifest_hash);
    bytes[60..92].copy_from_slice(&pointer.index_id);
    let seal = blake3::hash(&bytes[..ACTIVE_SEAL_OFFSET]);
    bytes[ACTIVE_SEAL_OFFSET..].copy_from_slice(seal.as_bytes());
    bytes
}

fn parse_active_pointer(bytes: &[u8], identity: &SpannIndexIdentity) -> Result<ActivePointer> {
    if bytes.len() != ACTIVE_POINTER_BYTES
        || bytes[0..8] != SPANN_ACTIVE_MAGIC
        || le_u16(bytes, 8) != SPANN_POSTING_FORMAT_VERSION
        || le_u16(bytes, 10) != ACTIVE_POINTER_BYTES as u16
        || bytes[60..92] != identity.index_id
        || bytes[92..96] != [0; 4]
        || blake3::hash(&bytes[..ACTIVE_SEAL_OFFSET]).as_bytes() != &bytes[ACTIVE_SEAL_OFFSET..]
    {
        return Err(corrupt(
            "active posting pointer identity/header/seal invalid",
        ));
    }
    let generation = le_u64(bytes, 12);
    let manifest_len = le_u64(bytes, 20);
    let manifest_hash = bytes[28..60].try_into().expect("32B");
    if generation == 0 || manifest_hash == [0; 32] {
        return Err(corrupt("active posting pointer generation/hash is empty"));
    }
    Ok(ActivePointer {
        generation,
        manifest_len,
        manifest_hash,
        index_id: identity.index_id,
    })
}

fn decode_active_pointer(bytes: &[u8], identity: &SpannIndexIdentity) -> Result<[u8; 32]> {
    Ok(parse_active_pointer(bytes, identity)?.manifest_hash)
}

fn decode_limits(bytes: &[u8], cursor: &mut usize) -> Result<SpannPostingLimits> {
    let max_members_per_segment = read_u32(bytes, cursor, "limit max members")?;
    let max_nnz_per_member = read_u32(bytes, cursor, "limit max nnz")?;
    let max_decoded_segment_bytes = read_u64(bytes, cursor, "limit decoded bytes")?;
    let max_compressed_segment_bytes = read_u64(bytes, cursor, "limit compressed bytes")?;
    let max_segments_per_posting = read_u16(bytes, cursor, "limit posting segments")?;
    let max_state_segments = read_u16(bytes, cursor, "limit state segments")?;
    let max_manifest_chain = read_u16(bytes, cursor, "limit manifest chain")?;
    let max_reader_leases = read_u16(bytes, cursor, "limit reader leases")?;
    let max_manifest_bytes = read_u64(bytes, cursor, "limit manifest bytes")?;
    let max_centroid_file_bytes = read_u64(bytes, cursor, "limit centroid bytes")?;
    let max_query_decoded_bytes = read_u64(bytes, cursor, "limit query bytes")?;
    let cache_capacity_bytes = read_u64(bytes, cursor, "limit cache bytes")?;
    let zstd_level = read_i32(bytes, cursor, "limit zstd level")?;
    let zstd_window_log_max = read_u32(bytes, cursor, "limit zstd window")?;
    let boundary_epsilon_bits = read_u32(bytes, cursor, "limit boundary epsilon")?;
    let max_replication = read_u16(bytes, cursor, "limit max replication")?;
    let max_reclaim_files = read_u16(bytes, cursor, "limit reclaim files")?;
    let limits = SpannPostingLimits {
        max_members_per_segment,
        max_nnz_per_member,
        max_decoded_segment_bytes,
        max_compressed_segment_bytes,
        max_segments_per_posting,
        max_state_segments,
        max_manifest_chain,
        max_reader_leases,
        max_manifest_bytes,
        max_centroid_file_bytes,
        max_query_decoded_bytes,
        cache_capacity_bytes,
        zstd_level,
        zstd_window_log_max,
        boundary_epsilon_bits,
        max_replication,
        max_reclaim_files,
    };
    limits.validate()?;
    Ok(limits)
}

fn manifest_file_name(generation: u64, hash: &[u8; 32]) -> String {
    let prefix = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("manifest-g{generation:016x}-{prefix}.spm")
}

fn validate_component_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    let mut parts = path.components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(_)), None) if !name.is_empty() && name.len() <= 255 => Ok(()),
        _ => Err(corrupt(format!("unsafe manifest component name {name:?}"))),
    }
}

fn unique_temp_path(path: &Path) -> Result<std::path::PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| corrupt(format!("manifest path {} has no file name", path.display())))?;
    let mut temp = OsString::from(".");
    temp.push(name);
    temp.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(path.with_file_name(temp))
}

fn write_synced_new(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io(&format!("create {label} temp"), error))?;
    file.write_all(bytes)
        .map_err(|error| io(&format!("write {label} temp"), error))?;
    file.sync_all()
        .map_err(|error| io(&format!("fsync {label} temp"), error))
}

fn read_bounded_file_from_stat(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let len = fs::metadata(path)
        .map_err(|error| io(&format!("stat {label}"), error))?
        .len();
    read_bounded_file(path, len, maximum, label)
}

fn read_bounded_file(path: &Path, expected: u64, maximum: u64, label: &str) -> Result<Vec<u8>> {
    if expected == 0 || expected > maximum {
        return Err(corrupt(format!(
            "{label} {} declared length {expected} outside 1..={maximum}",
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|error| io(&format!("open {label}"), error))?;
    let actual = file
        .metadata()
        .map_err(|error| io(&format!("stat {label}"), error))?
        .len();
    if actual != expected {
        return Err(corrupt(format!(
            "{label} {} length {actual} != declared {expected}",
            path.display()
        )));
    }
    let len = usize::try_from(actual).map_err(|_| corrupt(format!("{label} exceeds usize")))?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes)
        .map_err(|error| io(&format!("read {label}"), error))?;
    Ok(bytes)
}

fn checked_count_before_allocation(
    count: u32,
    remaining: usize,
    minimum_each: usize,
    label: &str,
) -> Result<usize> {
    let count = usize::try_from(count).map_err(|_| corrupt(format!("{label} exceeds usize")))?;
    let minimum = count
        .checked_mul(minimum_each)
        .ok_or_else(|| corrupt(format!("{label} minimum byte count overflow")))?;
    if minimum > remaining {
        return Err(corrupt(format!(
            "{label} count {count} needs at least {minimum} bytes but {remaining} remain"
        )));
    }
    Ok(count)
}

fn read_u8(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u8> {
    let value = *bytes
        .get(*cursor)
        .ok_or_else(|| corrupt(format!("truncated {label}")))?;
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(take_array::<2>(bytes, cursor, label)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(take_array::<4>(bytes, cursor, label)?))
}

fn read_i32(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<i32> {
    Ok(i32::from_le_bytes(take_array::<4>(bytes, cursor, label)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(take_array::<8>(bytes, cursor, label)?))
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| corrupt(format!("{label} offset overflow")))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| corrupt(format!("truncated {label}")))?;
    *cursor = end;
    Ok(value.try_into().expect("exact length"))
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2B"))
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8B"))
}
