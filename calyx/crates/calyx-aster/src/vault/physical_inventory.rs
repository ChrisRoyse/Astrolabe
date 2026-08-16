//! Authoritative physical readback for one retained durable commit generation.
//!
//! This module deliberately lives below `AsterVault`: callers name a commit
//! and its exact column-family set, but they never supply filesystem paths,
//! byte counts, hashes, or decoded rows. Aster derives all of those facts from
//! its retained durable root after the commit and checkpoint have completed.
//! Historical generations are attributable only while their exact WAL record,
//! immutable manifest, and per-CF durable-batch SSTs all remain present.

use super::{AsterVault, encode};
use crate::cf::ColumnFamily;
use crate::compaction::StorageTier;
use crate::manifest::VaultManifest;
use crate::sst::SstReader;
use crate::storage_names::{SstName, classify_sst, wal_segment_index};
use calyx_core::{CalyxError, Clock, Result, Seq};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Stable error code for a physical commit whose durable bytes do not form one
/// exact, self-consistent generation.
pub const CALYX_ASTER_PHYSICAL_COMMIT_INVENTORY_INVALID: &str =
    "CALYX_ASTER_PHYSICAL_COMMIT_INVENTORY_INVALID";

const ROUTER_HANDOFF_SCHEMA: &str = "calyx-router-handoff-v1";
const IMMUTABLE_MANIFEST_PREFIX: &str = "manifest-";
const IMMUTABLE_MANIFEST_SUFFIX: &str = ".json";
const IMMUTABLE_MANIFEST_DIGITS: usize = 20;

/// Logical container that owns a physical component.
///
/// `relative_path` on [`PhysicalCommitComponent`] is relative to this exact
/// Aster-owned container. Tier identities remain explicit even when an
/// operator configures both tiers to the same physical root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PhysicalCommitContainer {
    Vault,
    HotTier,
    ArchiveTier,
}

impl PhysicalCommitContainer {
    /// Stable, filesystem-independent name used in report identities.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::HotTier => "hot-tier",
            Self::ArchiveTier => "archive-tier",
        }
    }
}

/// Physical role of one independently retained byte range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalCommitComponentRole {
    WalRecord,
    DurableSst {
        cf: ColumnFamily,
        sst_index: usize,
        entries: usize,
    },
    CurrentPointer,
    ImmutableManifest {
        manifest_seq: u64,
    },
    ManifestMirror {
        manifest_seq: u64,
    },
    RouterHandoff {
        manifest_seq: u64,
    },
}

/// One exact, hash-bound physical byte range attributable to a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalCommitComponent {
    pub role: PhysicalCommitComponentRole,
    pub container: PhysicalCommitContainer,
    /// Canonical forward-slash path relative to `container`.
    pub relative_path: String,
    /// Inclusive byte offset within `relative_path`.
    pub offset: u64,
    /// Number of bytes in this component.
    pub length: u64,
    /// SHA-256 of exactly `offset..offset + length`, including WAL framing.
    pub sha256: [u8; 32],
}

impl PhysicalCommitComponent {
    /// Canonical report identity. The identity is stable across vault moves;
    /// the byte hash binds it to the observed physical generation.
    pub fn canonical_identity(&self) -> String {
        format!(
            "{}/{}@{}+{}",
            self.container.name(),
            self.relative_path,
            self.offset,
            self.length
        )
    }

    pub fn sha256_hex(&self) -> String {
        encode_hex(&self.sha256)
    }
}

/// Digest-only decoded WAL row for binding an upper-layer expected write set.
///
/// The key is returned because it is the natural row identity; potentially
/// large values remain single-copy inside WAL decode and are represented by
/// their exact length and SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalCommitRowDigest {
    pub ordinal: usize,
    pub cf: ColumnFamily,
    pub key: Vec<u8>,
    pub key_sha256: [u8; 32],
    pub value_length: u64,
    pub value_sha256: [u8; 32],
    pub tombstoned: bool,
}

impl PhysicalCommitRowDigest {
    pub fn key_sha256_hex(&self) -> String {
        encode_hex(&self.key_sha256)
    }

    pub fn value_sha256_hex(&self) -> String {
        encode_hex(&self.value_sha256)
    }
}

/// Independently reconstructed durable state for one retained commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalCommitInventory {
    pub seq: Seq,
    pub manifest_seq: u64,
    pub column_families: Vec<ColumnFamily>,
    pub rows: Vec<PhysicalCommitRowDigest>,
    pub components: Vec<PhysicalCommitComponent>,
    pub total_physical_bytes: u64,
}

#[derive(Debug)]
struct BuiltComponent {
    component: PhysicalCommitComponent,
    absolute_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouterHandoffStateV1 {
    schema: String,
    manifest_seq: u64,
    durable_seq: u64,
    pointer: String,
    manifest_blake3: String,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Reads the exact physical generation for one retained durable commit.
    ///
    /// This is a post-commit read, not a receipt conversion: Aster reopens the
    /// framed WAL record, decodes its rows, validates the caller's complete CF
    /// set, reopens each commit-owned durable SST, matches every persisted row
    /// to the WAL's latest value for that key, and then reads the manifest
    /// control generation bound to `seq`. No caller-provided size or digest is
    /// trusted.
    ///
    /// `seq` must be nonzero and no newer than both the live and durable WAL
    /// tips. At the exact common tip, CURRENT, MANIFEST, and ROUTER_HANDOFF are
    /// validated but never charged to the commit: they are mutable vault-head
    /// controls, not generation-owned bytes. At every age, Aster inventories
    /// the one immutable manifest that first advanced `durable_seq` to `seq`.
    /// Later control-only manifests may legitimately retain the same
    /// `durable_seq`; they are validated as part of the monotone manifest roster
    /// but are not substituted for or charged to the generation.
    ///
    /// Structural cost (issue #557; PC-02/03/04/13/29/41) is
    /// `O(W + H_seq + F + exact WAL/SST/control bytes)`: canonical WAL segment
    /// names `W` and framing headers through `seq` (`H_seq`) are walked once;
    /// `F` is the total retained immutable-manifest roster bytes read and
    /// decoded to locate `durable_seq == seq`. Only the requested WAL payload,
    /// exact per-CF SSTs, and selected immutable manifest are SHA-256
    /// inventoried. Tip controls are read once, and the immutable bytes are
    /// BLAKE3-bound to ROUTER_HANDOFF, solely to validate the active vault head.
    /// Real production `W`, `H_seq`, and `F` are unknown until #557's
    /// production-size measurement; a fixture must not be cited as their bound.
    pub fn physical_commit_inventory(
        &self,
        seq: Seq,
        expected_cfs: &[ColumnFamily],
    ) -> Result<PhysicalCommitInventory> {
        self.with_durable_commit_lock(|| self.physical_commit_inventory_locked(seq, expected_cfs))
    }

    fn physical_commit_inventory_locked(
        &self,
        seq: Seq,
        expected_cfs: &[ColumnFamily],
    ) -> Result<PhysicalCommitInventory> {
        let durable = self.durable.as_ref().ok_or_else(|| {
            inventory_error(
                "physical commit inventory requires a durable Aster vault; volatile vaults have no physical source of truth",
            )
        })?;
        if seq == 0 {
            return Err(inventory_error(
                "physical commit inventory sequence must be nonzero",
            ));
        }
        let latest_seq = self.latest_seq();
        let durable_tip = durable.durable_tip_seq()?;
        if seq > latest_seq || seq > durable_tip {
            return Err(inventory_error(format!(
                "physical commit inventory requested future seq {seq}: live seq {latest_seq}, durable WAL tip {durable_tip}"
            )));
        }
        let at_common_tip = seq == latest_seq && seq == durable_tip;

        let expected_cfs = canonical_cf_set(expected_cfs)?;
        let root = durable.root();
        let wal_dir = root.join("wal");
        let record = if at_common_tip {
            crate::wal::read_tip_record(&wal_dir, seq)?
        } else {
            crate::wal::read_record_by_seq(&wal_dir, seq)?
        };
        validate_wal_location(root, &record.segment_path)?;
        let wal_length = record
            .end_offset
            .checked_sub(record.start_offset)
            .ok_or_else(|| inventory_error("WAL record byte range is inverted"))?;
        if wal_length == 0 {
            return Err(inventory_error("WAL record byte range is empty"));
        }
        let wal_sha256 = hash_file_range(
            &record.segment_path,
            record.start_offset,
            wal_length,
            "WAL commit",
        )?;
        let write_rows = encode::decode_write_batch(&record.payload)?;
        let actual_cfs = write_rows
            .iter()
            .map(|row| row.cf)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if actual_cfs != expected_cfs {
            return Err(inventory_error(format!(
                "commit {seq} CF set differs from the exact request: expected [{}], decoded WAL [{}]",
                cf_names(&expected_cfs),
                cf_names(&actual_cfs)
            )));
        }

        let wal_name = utf8_file_name(&record.segment_path, "WAL segment")?;
        let mut built = vec![BuiltComponent {
            component: PhysicalCommitComponent {
                role: PhysicalCommitComponentRole::WalRecord,
                container: PhysicalCommitContainer::Vault,
                relative_path: format!("wal/{wal_name}"),
                offset: record.start_offset,
                length: wal_length,
                sha256: wal_sha256,
            },
            absolute_path: record.segment_path.clone(),
        }];

        for cf in &expected_cfs {
            built.push(self.read_commit_sst(seq, *cf, &write_rows)?);
        }

        if at_common_tip {
            validate_current_control_generation(root, seq)?;
        }
        let (manifest_seq, mut controls) = read_generation_manifest(root, seq)?;
        built.append(&mut controls);
        validate_component_set(&built)?;
        built.sort_by(|left, right| {
            left.component
                .canonical_identity()
                .cmp(&right.component.canonical_identity())
        });

        let mut total_physical_bytes = 0u64;
        for item in &built {
            total_physical_bytes = total_physical_bytes
                .checked_add(item.component.length)
                .ok_or_else(|| inventory_error("physical component byte total overflow"))?;
        }
        let rows = write_rows
            .into_iter()
            .enumerate()
            .map(|(ordinal, row)| PhysicalCommitRowDigest {
                ordinal,
                cf: row.cf,
                key_sha256: sha256_bytes(&row.key),
                value_length: row.value.len() as u64,
                value_sha256: sha256_bytes(&row.value),
                tombstoned: crate::mvcc::is_tombstone_value(&row.value),
                key: row.key,
            })
            .collect();

        Ok(PhysicalCommitInventory {
            seq,
            manifest_seq,
            column_families: expected_cfs,
            rows,
            components: built.into_iter().map(|item| item.component).collect(),
            total_physical_bytes,
        })
    }

    fn read_commit_sst(
        &self,
        seq: Seq,
        cf: ColumnFamily,
        write_rows: &[encode::WriteRow],
    ) -> Result<BuiltComponent> {
        let locations = match &self.durable_tiering_policy {
            Some(policy) => {
                let placement = policy.place_current_cf(cf);
                let container = match placement.tier {
                    StorageTier::Hot => PhysicalCommitContainer::HotTier,
                    StorageTier::Cold => PhysicalCommitContainer::ArchiveTier,
                };
                let current_dir = placement.absolute_dir();
                let alternate = match placement.tier {
                    StorageTier::Hot => (
                        PhysicalCommitContainer::ArchiveTier,
                        policy.archive_root().join("cf").join(cf.name()),
                    ),
                    StorageTier::Cold => (
                        PhysicalCommitContainer::HotTier,
                        policy.hot_root().join("cf").join(cf.name()),
                    ),
                };
                let mut locations = vec![(container, current_dir.clone(), true)];
                if alternate.1 != current_dir {
                    locations.push((alternate.0, alternate.1, false));
                }
                locations
            }
            None => {
                let root = self
                    .durable
                    .as_ref()
                    .expect("durability established before SST read")
                    .root();
                vec![(
                    PhysicalCommitContainer::Vault,
                    root.join("cf").join(cf.name()),
                    true,
                )]
            }
        };
        let (expected_index, expected_rows) = expected_sst_rows(write_rows, cf)?;
        let mut candidates = Vec::new();
        for (container, cf_dir, is_current_placement) in locations {
            let entries = match fs::read_dir(&cf_dir) {
                Ok(entries) => entries,
                Err(error)
                    if !is_current_placement && error.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(inventory_io_error(
                        "list exact commit CF directory",
                        &cf_dir,
                        error,
                    ));
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    inventory_io_error("read exact commit CF directory entry", &cf_dir, error)
                })?;
                let path = entry.path();
                match classify_sst(&path)? {
                    Some(SstName::DurableBatch {
                        seq: observed_seq,
                        index,
                    }) if observed_seq == seq => {
                        candidates.push((is_current_placement, container, index, path));
                    }
                    Some(_) | None => {}
                }
            }
        }
        candidates.sort_by_key(|(_, container, index, path)| (*container, *index, path.clone()));
        if candidates.len() != 1 {
            return Err(inventory_error(format!(
                "commit {seq} CF {} requires exactly one durable-batch SST, found {}",
                cf.name(),
                candidates.len()
            )));
        }
        let (is_current_placement, container, sst_index, path) =
            candidates.pop().expect("one candidate checked above");
        if !is_current_placement {
            return Err(inventory_error(format!(
                "commit {seq} CF {} durable SST exists only outside the tier policy's current placement",
                cf.name()
            )));
        }
        if sst_index != expected_index {
            return Err(inventory_error(format!(
                "commit {seq} CF {} durable SST index {sst_index} differs from WAL-derived index {expected_index}",
                cf.name()
            )));
        }
        let reader = SstReader::open(&path)?;
        let mut expected = expected_rows.iter();
        let observed_count = reader.visit_entries(|observed_key, observed_value| {
            let Some((expected_key, (_, expected_value))) = expected.next() else {
                return Err(inventory_error(format!(
                    "commit {seq} CF {} durable SST has more rows than its decoded WAL generation",
                    cf.name()
                )));
            };
            if observed_key != *expected_key || observed_value != *expected_value {
                return Err(inventory_error(format!(
                    "commit {seq} CF {} durable SST row differs from its decoded WAL generation",
                    cf.name()
                )));
            }
            Ok(())
        })?;
        if expected.next().is_some() {
            return Err(inventory_error(format!(
                "commit {seq} CF {} durable SST rows differ from the decoded WAL generation (observed {}, expected {})",
                cf.name(),
                observed_count,
                expected_rows.len()
            )));
        }
        let length = fs::metadata(&path)
            .map_err(|error| inventory_io_error("stat durable SST", &path, error))?
            .len();
        if length == 0 {
            return Err(inventory_error(format!(
                "commit {seq} CF {} durable SST is empty",
                cf.name()
            )));
        }
        let sha256 = hash_file_range(&path, 0, length, "durable SST")?;
        let file_name = utf8_file_name(&path, "durable SST")?;
        Ok(BuiltComponent {
            component: PhysicalCommitComponent {
                role: PhysicalCommitComponentRole::DurableSst {
                    cf,
                    sst_index,
                    entries: observed_count,
                },
                container,
                relative_path: format!("cf/{}/{file_name}", cf.name()),
                offset: 0,
                length,
                sha256,
            },
            absolute_path: path,
        })
    }
}

fn canonical_cf_set(expected_cfs: &[ColumnFamily]) -> Result<Vec<ColumnFamily>> {
    if expected_cfs.is_empty() {
        return Err(inventory_error(
            "physical commit inventory requires a non-empty exact CF set",
        ));
    }
    let mut canonical = expected_cfs.to_vec();
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(inventory_error(format!(
            "physical commit inventory CF request contains duplicates: [{}]",
            cf_names(&canonical)
        )));
    }
    Ok(canonical)
}

fn expected_sst_rows<'a>(
    write_rows: &'a [encode::WriteRow],
    cf: ColumnFamily,
) -> Result<(usize, BTreeMap<&'a [u8], (usize, &'a [u8])>)> {
    let mut latest = BTreeMap::<&[u8], (usize, &[u8])>::new();
    for (ordinal, row) in write_rows.iter().enumerate() {
        if row.cf == cf {
            latest.insert(row.key.as_slice(), (ordinal, row.value.as_slice()));
        }
    }
    let expected_index = latest
        .first_key_value()
        .map(|(_, (ordinal, _))| *ordinal)
        .ok_or_else(|| {
            inventory_error(format!(
                "decoded WAL CF set named {} but no rows were present",
                cf.name()
            ))
        })?;
    Ok((expected_index, latest))
}

fn validate_current_control_generation(root: &Path, seq: Seq) -> Result<()> {
    let current_path = root.join("CURRENT");
    let current_bytes = read_whole_file(&current_path, "CURRENT")?;
    let pointer = std::str::from_utf8(&current_bytes)
        .map_err(|error| inventory_error(format!("CURRENT is not canonical UTF-8: {error}")))?;
    if pointer.is_empty() || pointer.trim() != pointer {
        return Err(inventory_error(
            "CURRENT must contain one canonical immutable manifest filename without surrounding whitespace",
        ));
    }
    let manifest_path = root.join(pointer);
    let manifest_bytes = read_whole_file(&manifest_path, "immutable manifest")?;
    let manifest: VaultManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        inventory_error(format!(
            "decode immutable manifest {}: {error}",
            manifest_path.display()
        ))
    })?;
    manifest.validate()?;
    let expected_pointer = format!("manifest-{:020}.json", manifest.manifest_seq);
    if pointer != expected_pointer {
        return Err(inventory_error(format!(
            "CURRENT pointer {pointer:?} differs from manifest identity {expected_pointer:?}"
        )));
    }
    if manifest.durable_seq != seq {
        return Err(inventory_error(format!(
            "CURRENT manifest durable_seq {} does not attribute its control generation to requested commit {seq}",
            manifest.durable_seq
        )));
    }
    let mirror_path = root.join("MANIFEST");
    let mirror_bytes = read_whole_file(&mirror_path, "MANIFEST mirror")?;
    if mirror_bytes != manifest_bytes {
        return Err(inventory_error(format!(
            "MANIFEST mirror differs from immutable generation {pointer}"
        )));
    }

    let manifest_blake3 = blake3::hash(&manifest_bytes).to_hex().to_string();
    let handoff_path = root.join("ROUTER_HANDOFF");
    let handoff_bytes = read_whole_file(&handoff_path, "ROUTER_HANDOFF")?;
    let handoff: RouterHandoffStateV1 =
        serde_json::from_slice(&handoff_bytes).map_err(|error| {
            inventory_error(format!(
                "decode ROUTER_HANDOFF {}: {error}",
                handoff_path.display()
            ))
        })?;
    if handoff.schema != ROUTER_HANDOFF_SCHEMA
        || handoff.manifest_seq != manifest.manifest_seq
        || handoff.durable_seq != seq
        || handoff.pointer != pointer
        || handoff.manifest_blake3 != manifest_blake3
    {
        return Err(inventory_error(format!(
            "ROUTER_HANDOFF is not bound to CURRENT manifest generation ({}, {seq}, {pointer}, {manifest_blake3})",
            manifest.manifest_seq
        )));
    }

    Ok(())
}

fn read_generation_manifest(root: &Path, seq: Seq) -> Result<(u64, Vec<BuiltComponent>)> {
    let entries = fs::read_dir(root)
        .map_err(|error| inventory_io_error("list retained manifest roster", root, error))?;
    let mut roster = Vec::<(u64, String, PathBuf)>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            inventory_io_error("read retained manifest roster entry", root, error)
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(name_seq) = immutable_manifest_name_seq(file_name)? else {
            continue;
        };
        let file_type = entry.file_type().map_err(|error| {
            inventory_io_error("inspect retained immutable manifest", &entry.path(), error)
        })?;
        if !file_type.is_file() {
            return Err(inventory_error(format!(
                "retained immutable manifest {} is not a regular file",
                entry.path().display()
            )));
        }
        roster.push((name_seq, file_name.to_string(), entry.path()));
    }
    roster.sort_by_key(|(manifest_seq, _, _)| *manifest_seq);
    if roster.is_empty() {
        return Err(inventory_error(format!(
            "commit {seq} has no retained immutable manifest roster"
        )));
    }
    for pair in roster.windows(2) {
        let expected = pair[0]
            .0
            .checked_add(1)
            .ok_or_else(|| inventory_error("retained immutable manifest sequence exhausted"))?;
        if pair[1].0 != expected {
            return Err(inventory_error(format!(
                "retained immutable manifest sequence is not contiguous: {} is followed by {}",
                pair[0].1, pair[1].1
            )));
        }
    }

    let mut previous_durable_seq = None;
    let mut owner = None::<(u64, BuiltComponent)>;
    for (name_seq, file_name, path) in roster {
        let bytes = read_whole_file(&path, "retained immutable manifest")?;
        let manifest: VaultManifest = serde_json::from_slice(&bytes).map_err(|error| {
            inventory_error(format!(
                "decode retained immutable manifest {}: {error}",
                path.display()
            ))
        })?;
        manifest.validate()?;
        if manifest.manifest_seq != name_seq {
            return Err(inventory_error(format!(
                "retained immutable manifest filename {file_name:?} names sequence {name_seq} but its payload names {}",
                manifest.manifest_seq
            )));
        }
        if let Some(previous) = previous_durable_seq
            && manifest.durable_seq < previous
        {
            return Err(inventory_error(format!(
                "retained immutable manifest {file_name} regresses durable_seq from {previous} to {}",
                manifest.durable_seq
            )));
        }
        // Equal durable watermarks are expected after content-neutral control
        // writes (and after a retry crosses manifest publication before the
        // pending checkpoint is cleared). Ownership belongs to the first
        // retained manifest that proves the monotone transition, never an
        // arbitrary or latest equal-watermark manifest.
        let first_bootstrap_owner = previous_durable_seq.is_none()
            && manifest.manifest_seq == manifest.durable_seq
            && manifest.durable_seq == seq;
        let transition_owner = previous_durable_seq
            .is_some_and(|previous| previous < seq && manifest.durable_seq == seq);
        if first_bootstrap_owner || transition_owner {
            if owner.is_some() {
                return Err(inventory_error(format!(
                    "commit {seq} has more than one retained manifest that first advances durable_seq to {seq}"
                )));
            }
            owner = Some((
                manifest.manifest_seq,
                whole_file_component(
                    PhysicalCommitComponentRole::ImmutableManifest {
                        manifest_seq: manifest.manifest_seq,
                    },
                    &file_name,
                    path,
                    &bytes,
                )?,
            ));
        }
        previous_durable_seq = Some(manifest.durable_seq);
    }
    let (manifest_seq, component) = owner.ok_or_else(|| {
        inventory_error(format!(
            "commit {seq} has no retained immutable manifest that first advances durable_seq to {seq}; the generation manifest is absent, compacted, or replaced by a later control-only manifest"
        ))
    })?;
    Ok((manifest_seq, vec![component]))
}

fn immutable_manifest_name_seq(file_name: &str) -> Result<Option<u64>> {
    let expected_len = IMMUTABLE_MANIFEST_PREFIX.len()
        + IMMUTABLE_MANIFEST_DIGITS
        + IMMUTABLE_MANIFEST_SUFFIX.len();
    if file_name.len() != expected_len
        || !file_name.starts_with(IMMUTABLE_MANIFEST_PREFIX)
        || !file_name.ends_with(IMMUTABLE_MANIFEST_SUFFIX)
    {
        return Ok(None);
    }
    let digits = &file_name[IMMUTABLE_MANIFEST_PREFIX.len()
        ..IMMUTABLE_MANIFEST_PREFIX.len() + IMMUTABLE_MANIFEST_DIGITS];
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let seq = digits.parse::<u64>().map_err(|error| {
        inventory_error(format!(
            "retained immutable manifest filename {file_name:?} has an out-of-range sequence: {error}"
        ))
    })?;
    if format!("{IMMUTABLE_MANIFEST_PREFIX}{seq:020}{IMMUTABLE_MANIFEST_SUFFIX}") != file_name {
        return Err(inventory_error(format!(
            "retained immutable manifest filename {file_name:?} is not canonical"
        )));
    }
    Ok(Some(seq))
}

fn whole_file_component(
    role: PhysicalCommitComponentRole,
    relative_path: &str,
    absolute_path: PathBuf,
    bytes: &[u8],
) -> Result<BuiltComponent> {
    if bytes.is_empty() {
        return Err(inventory_error(format!(
            "physical control component {relative_path} is empty"
        )));
    }
    Ok(BuiltComponent {
        component: PhysicalCommitComponent {
            role,
            container: PhysicalCommitContainer::Vault,
            relative_path: relative_path.to_string(),
            offset: 0,
            length: bytes.len() as u64,
            sha256: sha256_bytes(bytes),
        },
        absolute_path,
    })
}

fn validate_wal_location(root: &Path, path: &Path) -> Result<()> {
    let expected_parent = root.join("wal");
    if path.parent() != Some(expected_parent.as_path()) {
        return Err(inventory_error(format!(
            "WAL replay returned non-canonical segment path {} outside {}",
            path.display(),
            expected_parent.display()
        )));
    }
    if wal_segment_index(path)?.is_none() {
        return Err(inventory_error(format!(
            "WAL replay returned non-segment path {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_component_set(components: &[BuiltComponent]) -> Result<()> {
    let mut identities = BTreeSet::new();
    let mut physical_ranges = Vec::with_capacity(components.len());
    for item in components {
        let component = &item.component;
        if component.length == 0 {
            return Err(inventory_error(format!(
                "physical component {} has zero length",
                component.canonical_identity()
            )));
        }
        let end = component
            .offset
            .checked_add(component.length)
            .ok_or_else(|| {
                inventory_error(format!(
                    "physical component {} range overflows u64",
                    component.canonical_identity()
                ))
            })?;
        if !identities.insert(component.canonical_identity()) {
            return Err(inventory_error(format!(
                "duplicate physical component identity {}",
                component.canonical_identity()
            )));
        }
        let canonical_path = fs::canonicalize(&item.absolute_path).map_err(|error| {
            inventory_io_error(
                "canonicalize physical component",
                &item.absolute_path,
                error,
            )
        })?;
        physical_ranges.push((canonical_path, component.offset, end));
    }
    physical_ranges.sort();
    for pair in physical_ranges.windows(2) {
        if pair[0].0 == pair[1].0 && pair[1].1 < pair[0].2 {
            return Err(inventory_error(format!(
                "physical component ranges overlap in {}: {}..{} and {}..{}",
                pair[0].0.display(),
                pair[0].1,
                pair[0].2,
                pair[1].1,
                pair[1].2
            )));
        }
    }
    Ok(())
}

fn read_whole_file(path: &Path, role: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| inventory_io_error(&format!("read {role}"), path, error))
}

fn hash_file_range(path: &Path, offset: u64, length: u64, role: &str) -> Result<[u8; 32]> {
    let file_length = fs::metadata(path)
        .map_err(|error| inventory_io_error(&format!("stat {role}"), path, error))?
        .len();
    let end = offset.checked_add(length).ok_or_else(|| {
        inventory_error(format!(
            "{role} range {offset}+{length} overflows for {}",
            path.display()
        ))
    })?;
    if end > file_length {
        return Err(inventory_error(format!(
            "{role} range {offset}..{end} exceeds {} byte container {}",
            file_length,
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| inventory_io_error(&format!("open {role}"), path, error))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| inventory_io_error(&format!("seek {role}"), path, error))?;
    let mut reader = file.take(length);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read_bytes = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| inventory_io_error(&format!("hash {role}"), path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        read_bytes = read_bytes
            .checked_add(read as u64)
            .ok_or_else(|| inventory_error(format!("{role} hash byte count overflow")))?;
    }
    if read_bytes != length {
        return Err(inventory_error(format!(
            "{role} short read for {}: hashed {read_bytes} of {length} bytes",
            path.display()
        )));
    }
    Ok(hasher.finalize().into())
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write to String cannot fail");
    }
    encoded
}

fn utf8_file_name(path: &Path, role: &str) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            inventory_error(format!(
                "{role} path {} has no canonical UTF-8 file name",
                path.display()
            ))
        })
}

fn cf_names(cfs: &[ColumnFamily]) -> String {
    cfs.iter()
        .map(ColumnFamily::name)
        .collect::<Vec<_>>()
        .join(",")
}

fn inventory_io_error(context: &str, path: &Path, error: std::io::Error) -> CalyxError {
    inventory_error(format!("{context} {}: {error}", path.display()))
}

fn inventory_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_PHYSICAL_COMMIT_INVENTORY_INVALID,
        message: message.into(),
        remediation: "preserve the vault and inspect the named WAL record, exact CF durable SSTs, retained immutable manifest, and CURRENT/MANIFEST/ROUTER_HANDOFF controls when the commit is current; repair or re-ingest the mismatched durable generation before measuring or admitting it",
    }
}
