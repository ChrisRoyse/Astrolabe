//! Atomic manifest and recovery ordering for Aster vaults.

mod quarantine;

use crate::cf::ColumnFamily;
use crate::dedup::DedupPolicy;
use crate::sst::SstReader;
use crate::storage_names::parse_cf_dir_name;
use crate::timetravel::RetentionHorizon;
use crate::vault::input_store::InputRetention;
use crate::wal::{ReplayRecord, TornTail, replay_dir_after};
use calyx_core::{CalyxError, Result, TemporalPolicy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const CURRENT_FILE: &str = "CURRENT";
const MANIFEST_FILE: &str = "MANIFEST";
const MANIFEST_PREFIX: &str = "manifest-";
const MANIFEST_SUFFIX: &str = ".json";
const SUPPORTED_MANIFEST_MAJOR: u16 = 1;
const SUPPORTED_MANIFEST_MINOR: u16 = 1;

pub use quarantine::QuarantineRecord;

/// Version guard for MANIFEST bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestVersion {
    pub major: u16,
    pub minor: u16,
}

impl ManifestVersion {
    pub const fn current() -> Self {
        Self {
            major: SUPPORTED_MANIFEST_MAJOR,
            minor: SUPPORTED_MANIFEST_MINOR,
        }
    }

    fn validate(self) -> Result<()> {
        if self.major != SUPPORTED_MANIFEST_MAJOR {
            return Err(format_version_unsupported(format!(
                "unsupported MANIFEST major version {}; supported major is {}",
                self.major, SUPPORTED_MANIFEST_MAJOR
            )));
        }
        if self.minor > SUPPORTED_MANIFEST_MINOR {
            return Err(format_version_unsupported(format!(
                "unsupported MANIFEST minor version {}; newest supported minor is {}",
                self.minor, SUPPORTED_MANIFEST_MINOR
            )));
        }
        Ok(())
    }
}

/// Content-addressed immutable reference captured by a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImmutableRef {
    pub logical_path: String,
    pub blake3_hex: String,
}

impl ImmutableRef {
    pub fn from_bytes(logical_path: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let hash = blake3::hash(bytes).to_hex().to_string();
        Self::new(logical_path, hash)
    }

    pub fn new(logical_path: impl Into<String>, blake3_hex: impl Into<String>) -> Result<Self> {
        let reference = Self {
            logical_path: logical_path.into(),
            blake3_hex: blake3_hex.into().to_ascii_lowercase(),
        };
        reference.validate()?;
        Ok(reference)
    }

    fn validate(&self) -> Result<()> {
        if self.logical_path.is_empty() || self.logical_path.starts_with('/') {
            return Err(CalyxError::aster_corrupt_shard(
                "manifest immutable ref path must be vault-relative",
            ));
        }
        if Path::new(&self.logical_path)
            .components()
            .any(invalid_component)
        {
            return Err(CalyxError::aster_corrupt_shard(
                "manifest immutable ref path escapes vault",
            ));
        }
        if self.logical_path == CURRENT_FILE
            || self.logical_path == MANIFEST_FILE
            || self.logical_path.ends_with(".tmp")
        {
            return Err(CalyxError::aster_corrupt_shard(
                "manifest immutable ref points at mutable control file",
            ));
        }
        if self.blake3_hex.len() != 64 || !self.blake3_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CalyxError::aster_corrupt_shard(
                "manifest immutable ref hash must be 32-byte hex blake3",
            ));
        }
        Ok(())
    }
}

/// Durable Aster vault manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultManifest {
    pub version: ManifestVersion,
    pub manifest_seq: u64,
    pub durable_seq: u64,
    /// Max checkpointed seq (<= `durable_seq`) whose commit wrote at least one
    /// row in a CF that feeds derived search content (issue #1100). `None` on
    /// manifests written before this field existed; readers fail closed to
    /// `durable_seq` via [`Self::effective_derived_content_seq`].
    #[serde(default)]
    pub derived_content_seq: Option<u64>,
    /// Conservative floor for per-column-family content generations. `None`
    /// identifies a legacy manifest that did not persist exact CF provenance;
    /// readers then fail closed to `durable_seq`. New manifests always persist
    /// `Some(floor)` and keep exact generations above that floor in
    /// `cf_content_generations`.
    #[serde(default)]
    pub cf_content_generation_floor_seq: Option<u64>,
    /// Exact last checkpointed mutation sequence by canonical CF directory
    /// name. Entries equal to the floor are omitted, so this remains bounded by
    /// the number of distinct CFs rather than row count.
    #[serde(default, deserialize_with = "deserialize_cf_content_generations")]
    pub cf_content_generations: BTreeMap<String, u64>,
    pub panel_ref: ImmutableRef,
    #[serde(default)]
    pub registry_ref: Option<ImmutableRef>,
    pub codebook_refs: Vec<ImmutableRef>,
    #[serde(default)]
    pub temporal_policy: Option<TemporalPolicy>,
    #[serde(default)]
    pub dedup_policy: Option<DedupPolicy>,
    #[serde(default)]
    pub retention_horizon: RetentionHorizon,
    /// Raw-input retention policy for this vault (issue #446). `#[serde(default)]`
    /// decodes older manifests as [`InputRetention::Persist`].
    #[serde(default)]
    pub input_retention: InputRetention,
    pub degraded_rebuildable: bool,
    #[serde(default)]
    pub quarantines: Vec<QuarantineRecord>,
}

fn deserialize_cf_content_generations<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct GenerationMapVisitor;

    impl<'de> serde::de::Visitor<'de> for GenerationMapVisitor {
        type Value = BTreeMap<String, u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique canonical CF generation keys")
        }

        fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((name, seq)) = access.next_entry::<String, u64>()? {
                if values.insert(name.clone(), seq).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate CF content-generation key {name:?}"
                    )));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(GenerationMapVisitor)
}

impl VaultManifest {
    pub fn new(
        manifest_seq: u64,
        durable_seq: u64,
        panel_ref: ImmutableRef,
        codebook_refs: Vec<ImmutableRef>,
    ) -> Result<Self> {
        Self::new_with_temporal_policy(
            manifest_seq,
            durable_seq,
            panel_ref,
            codebook_refs,
            Some(TemporalPolicy::default()),
        )
    }

    pub fn new_with_temporal_policy(
        manifest_seq: u64,
        durable_seq: u64,
        panel_ref: ImmutableRef,
        codebook_refs: Vec<ImmutableRef>,
        temporal_policy: Option<TemporalPolicy>,
    ) -> Result<Self> {
        Self::new_with_policies(
            manifest_seq,
            durable_seq,
            panel_ref,
            codebook_refs,
            temporal_policy,
            Some(DedupPolicy::default()),
        )
    }

    pub fn new_with_policies(
        manifest_seq: u64,
        durable_seq: u64,
        panel_ref: ImmutableRef,
        codebook_refs: Vec<ImmutableRef>,
        temporal_policy: Option<TemporalPolicy>,
        dedup_policy: Option<DedupPolicy>,
    ) -> Result<Self> {
        let manifest = Self {
            version: ManifestVersion::current(),
            manifest_seq,
            durable_seq,
            derived_content_seq: None,
            cf_content_generation_floor_seq: Some(durable_seq),
            cf_content_generations: BTreeMap::new(),
            panel_ref,
            registry_ref: None,
            codebook_refs,
            temporal_policy,
            dedup_policy,
            retention_horizon: RetentionHorizon::default(),
            input_retention: InputRetention::default(),
            degraded_rebuildable: false,
            quarantines: Vec::new(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Derived-content watermark this manifest vouches for. Legacy manifests
    /// (field absent) fail closed to `durable_seq`: every checkpointed seq is
    /// assumed to have changed derived-search inputs, which reproduces the
    /// pre-#1100 exact-equality freshness behavior — never laxer.
    pub fn effective_derived_content_seq(&self) -> u64 {
        self.derived_content_seq.unwrap_or(self.durable_seq)
    }

    /// Per-CF generation floor vouched for by this manifest. Legacy manifests
    /// conservatively bind every CF to their durable tip because they contain no
    /// narrower provenance.
    pub fn effective_cf_content_generation_floor_seq(&self) -> u64 {
        self.cf_content_generation_floor_seq
            .unwrap_or(self.durable_seq)
    }

    /// Decodes the exact per-CF generation overrides after validating every
    /// canonical CF name and sequence bound.
    pub fn decoded_cf_content_generations(&self) -> Result<BTreeMap<ColumnFamily, u64>> {
        let floor = self.effective_cf_content_generation_floor_seq();
        let mut decoded = BTreeMap::new();
        for (name, seq) in &self.cf_content_generations {
            let cf = parse_cf_dir_name(name)?;
            if cf.name() != *name {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "manifest CF content-generation name {name:?} is not canonical; expected {:?}",
                    cf.name()
                )));
            }
            if *seq <= floor || *seq > self.durable_seq {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "manifest CF content generation {name:?}={seq} is outside canonical range (floor={floor}, durable_seq={})",
                    self.durable_seq
                )));
            }
            if decoded.insert(cf, *seq).is_some() {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "manifest contains duplicate decoded CF content generation for {name:?}"
                )));
            }
        }
        Ok(decoded)
    }

    pub fn validate(&self) -> Result<()> {
        self.version.validate()?;
        if self.manifest_seq == 0 {
            return Err(CalyxError::aster_corrupt_shard(
                "manifest sequence must start at one",
            ));
        }
        if let Some(derived_content_seq) = self.derived_content_seq
            && derived_content_seq > self.durable_seq
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "manifest derived_content_seq {derived_content_seq} exceeds durable_seq {}; the watermark can only vouch for checkpointed seqs",
                self.durable_seq
            )));
        }
        if self.version.minor == 0
            && (self.cf_content_generation_floor_seq.is_some()
                || !self.cf_content_generations.is_empty())
        {
            return Err(CalyxError::aster_corrupt_shard(
                "legacy MANIFEST v1.0 cannot carry v1.1 CF content-generation provenance",
            ));
        }
        if self.version.minor >= 1 && self.cf_content_generation_floor_seq.is_none() {
            return Err(CalyxError::aster_corrupt_shard(
                "MANIFEST v1.1+ requires an explicit CF content-generation floor",
            ));
        }
        if let Some(floor) = self.cf_content_generation_floor_seq {
            if floor > self.durable_seq {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "manifest CF content-generation floor {floor} exceeds durable_seq {}",
                    self.durable_seq
                )));
            }
        } else if !self.cf_content_generations.is_empty() {
            return Err(CalyxError::aster_corrupt_shard(
                "legacy manifest without a CF content-generation floor cannot contain exact CF generation overrides",
            ));
        }
        let _ = self.decoded_cf_content_generations()?;
        self.panel_ref.validate()?;
        require_prefix(&self.panel_ref, "panel/")?;
        if let Some(reference) = &self.registry_ref {
            reference.validate()?;
            require_prefix(reference, "registry/")?;
        }
        let mut seen = BTreeSet::new();
        for reference in &self.codebook_refs {
            reference.validate()?;
            require_prefix(reference, "codebooks/")?;
            if !seen.insert(reference.logical_path.as_str()) {
                return Err(CalyxError::aster_corrupt_shard(
                    "manifest contains duplicate codebook ref",
                ));
            }
        }
        for quarantine in &self.quarantines {
            quarantine.validate()?;
        }
        if let Some(policy) = &self.temporal_policy {
            policy.validate()?;
        }
        if let Some(policy) = &self.dedup_policy {
            policy.validate_manifest()?;
        }
        self.retention_horizon.validate()?;
        Ok(())
    }
}

/// Atomic manifest writer/reader rooted at one vault directory.
#[derive(Debug, Clone)]
pub struct ManifestStore {
    vault_dir: PathBuf,
}

/// Exact identity of one `CURRENT` generation observed before a manifest
/// control transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestCurrentIdentity {
    pointer: String,
    current_blake3_hex: String,
    manifest_seq: u64,
    manifest_blake3_hex: String,
}

impl ManifestCurrentIdentity {
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    pub const fn manifest_seq(&self) -> u64 {
        self.manifest_seq
    }

    pub fn current_blake3_hex(&self) -> &str {
        &self.current_blake3_hex
    }

    pub fn manifest_blake3_hex(&self) -> &str {
        &self.manifest_blake3_hex
    }
}

/// Manifest bytes and the exact `CURRENT` identity that selected them.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestCurrentSnapshot {
    pub manifest: VaultManifest,
    pub identity: ManifestCurrentIdentity,
}

/// Read-back result of one lock-bound manifest control transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestUpdate {
    pub before: ManifestCurrentIdentity,
    pub after: ManifestCurrentSnapshot,
    pub write: ManifestWrite,
}

impl ManifestStore {
    pub fn open(vault_dir: impl AsRef<Path>) -> Self {
        Self {
            vault_dir: vault_dir.as_ref().to_path_buf(),
        }
    }

    /// Internal data-plane publication primitive. The caller must already hold
    /// this vault's exact `locks/durable.commit.lock`; production control-plane
    /// callers cannot access it and use the identity transaction below.
    pub(crate) fn write_current_under_commit_lock(
        &self,
        manifest: &VaultManifest,
    ) -> Result<ManifestWrite> {
        manifest.validate()?;
        fs::create_dir_all(&self.vault_dir)
            .map_err(|error| storage_error("create vault manifest directory", error))?;
        let pointer = manifest_filename(manifest.manifest_seq);
        let manifest_path = self.vault_dir.join(&pointer);
        let mirror_path = self.vault_dir.join(MANIFEST_FILE);
        let current_path = self.vault_dir.join(CURRENT_FILE);
        let bytes = encode_manifest(manifest)?;

        write_atomic(&manifest_path, &bytes)?;
        write_atomic(&mirror_path, &bytes)?;
        write_atomic(&current_path, pointer.as_bytes())?;

        Ok(ManifestWrite {
            manifest_path,
            mirror_path,
            current_path,
            manifest_blake3_hex: blake3::hash(&bytes).to_hex().to_string(),
            current_blake3_hex: blake3::hash(pointer.as_bytes()).to_hex().to_string(),
            pointer,
        })
    }

    /// Writes an intentionally synthetic crash-recovery fixture without the
    /// production commit lock/CURRENT compare-and-swap transaction.
    ///
    /// Production manifest writers must use [`Self::transact_current_if_identity`].
    #[doc(hidden)]
    pub fn write_current_unlocked_crash_fixture(
        &self,
        manifest: &VaultManifest,
    ) -> Result<ManifestWrite> {
        self.write_current_under_commit_lock(manifest)
    }

    pub fn load_current(&self) -> Result<VaultManifest> {
        Ok(self.load_current_snapshot()?.manifest)
    }

    pub fn load_current_snapshot(&self) -> Result<ManifestCurrentSnapshot> {
        self.load_current_snapshot_inner(true)
    }

    fn load_current_snapshot_inner(
        &self,
        verify_references: bool,
    ) -> Result<ManifestCurrentSnapshot> {
        let pointer_bytes = fs::read(self.vault_dir.join(CURRENT_FILE))
            .map_err(|error| storage_error("read CURRENT", error))?;
        let pointer = std::str::from_utf8(&pointer_bytes)
            .map_err(|error| CalyxError::aster_corrupt_shard(format!("CURRENT utf8: {error}")))?
            .trim();
        if !valid_manifest_filename(pointer) {
            return Err(CalyxError::aster_corrupt_shard(
                "CURRENT does not point at immutable manifest file",
            ));
        }
        let bytes = fs::read(self.vault_dir.join(pointer))
            .map_err(|error| storage_error("read pointed MANIFEST", error))?;
        let manifest = decode_manifest(&bytes)?;
        let expected_pointer = manifest_filename(manifest.manifest_seq);
        if pointer != expected_pointer {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "CURRENT points at {pointer}, but the decoded manifest sequence requires {expected_pointer}"
            )));
        }
        if verify_references {
            verify_immutable_refs(&self.vault_dir, &manifest)?;
        }
        Ok(ManifestCurrentSnapshot {
            identity: ManifestCurrentIdentity {
                pointer: pointer.to_string(),
                current_blake3_hex: blake3::hash(&pointer_bytes).to_hex().to_string(),
                manifest_seq: manifest.manifest_seq,
                manifest_blake3_hex: blake3::hash(&bytes).to_hex().to_string(),
            },
            manifest,
        })
    }

    pub fn current_pointer(&self) -> Result<String> {
        let pointer = fs::read_to_string(self.vault_dir.join(CURRENT_FILE))
            .map_err(|error| storage_error("read CURRENT", error))?;
        Ok(pointer.trim().to_string())
    }

    pub fn append_quarantine(&self, record: QuarantineRecord) -> Result<VaultManifest> {
        let observed = self.load_current_snapshot()?;
        let update = self.transact_current_if_identity(&observed.identity, |mut manifest| {
            if !manifest.quarantines.contains(&record) {
                manifest.quarantines.push(record);
            }
            Ok(manifest)
        })?;
        Ok(update.after.manifest)
    }

    /// Applies one control-plane manifest mutation only when `CURRENT` still
    /// selects the exact bytes observed by the caller.
    ///
    /// The compare, mutation, publication, and independent readback all occur
    /// while `locks/durable.commit.lock` is retained. The transaction advances
    /// `manifest_seq` exactly once and refuses any attempted change to durable
    /// row provenance; callers cannot overwrite a concurrent checkpoint or
    /// discard exact per-CF content generations. A conflict is returned without
    /// retrying or invoking `update` against a newer generation.
    pub fn transact_current_if_identity<F>(
        &self,
        expected: &ManifestCurrentIdentity,
        update: F,
    ) -> Result<ManifestUpdate>
    where
        F: FnOnce(VaultManifest) -> Result<VaultManifest>,
    {
        let _commit_guard = crate::file_lock::FileLockGuard::acquire(
            &self.vault_dir.join("locks").join("durable.commit.lock"),
        )?;
        let before = self.load_current_snapshot_inner(false)?;
        if &before.identity != expected {
            return Err(CalyxError {
                code: "CALYX_MANIFEST_CURRENT_CONFLICT",
                message: format!(
                    "manifest control transaction expected CURRENT pointer {} bytes {} seq {} manifest {}, but observed pointer {} bytes {} seq {} manifest {}; no manifest bytes were written",
                    expected.pointer,
                    expected.current_blake3_hex,
                    expected.manifest_seq,
                    expected.manifest_blake3_hex,
                    before.identity.pointer,
                    before.identity.current_blake3_hex,
                    before.identity.manifest_seq,
                    before.identity.manifest_blake3_hex,
                ),
                remediation: "inspect the intervening manifest generation and explicitly derive a new control mutation from that exact CURRENT identity",
            });
        }
        let mut after = update(before.manifest.clone())?;
        let next_manifest_seq = before
            .manifest
            .manifest_seq
            .checked_add(1)
            .ok_or_else(|| CalyxError::ledger_chain_broken("manifest sequence exhausted"))?;
        after.manifest_seq = next_manifest_seq;
        ensure_control_update_preserves_durable_provenance(&before.manifest, &after)?;
        after.validate()?;
        verify_changed_immutable_refs(&self.vault_dir, &before.manifest, &after)?;
        let write = self.write_current_under_commit_lock(&after)?;
        let readback = self.load_current_snapshot_inner(false)?;
        let mirror_bytes = fs::read(&write.mirror_path).map_err(|error| {
            storage_error("read MANIFEST mirror after control transaction", error)
        })?;
        let mirror_blake3_hex = blake3::hash(&mirror_bytes).to_hex().to_string();
        if readback.manifest != after
            || readback.identity.pointer != write.pointer
            || readback.identity.manifest_blake3_hex != write.manifest_blake3_hex
            || readback.identity.current_blake3_hex != write.current_blake3_hex
            || mirror_blake3_hex != write.manifest_blake3_hex
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "manifest control transaction readback differs from published generation {}: expected pointer={} current_hash={} manifest_hash={}; actual pointer={} current_hash={} pointed_manifest_hash={} mirror_manifest_hash={}",
                after.manifest_seq,
                write.pointer,
                write.current_blake3_hex,
                write.manifest_blake3_hex,
                readback.identity.pointer,
                readback.identity.current_blake3_hex,
                readback.identity.manifest_blake3_hex,
                mirror_blake3_hex,
            )));
        }
        Ok(ManifestUpdate {
            before: before.identity,
            after: readback,
            write,
        })
    }
}

fn ensure_control_update_preserves_durable_provenance(
    before: &VaultManifest,
    after: &VaultManifest,
) -> Result<()> {
    if after.version != before.version
        || after.durable_seq != before.durable_seq
        || after.derived_content_seq != before.derived_content_seq
        || after.cf_content_generation_floor_seq != before.cf_content_generation_floor_seq
        || after.cf_content_generations != before.cf_content_generations
    {
        return Err(CalyxError {
            code: "CALYX_MANIFEST_CONTROL_PROVENANCE_CHANGED",
            message: format!(
                "manifest control transaction changed durable provenance: before durable_seq={} derived={:?} floor={:?} generations={:?}; after durable_seq={} derived={:?} floor={:?} generations={:?}; no manifest bytes were written",
                before.durable_seq,
                before.derived_content_seq,
                before.cf_content_generation_floor_seq,
                before.cf_content_generations,
                after.durable_seq,
                after.derived_content_seq,
                after.cf_content_generation_floor_seq,
                after.cf_content_generations,
            ),
            remediation: "publish checkpoint and row-provenance changes through the Aster durable commit path; manifest control transactions may only preserve those fields",
        });
    }
    Ok(())
}

/// Files produced by an atomic manifest swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestWrite {
    pub manifest_path: PathBuf,
    pub mirror_path: PathBuf,
    pub current_path: PathBuf,
    pub pointer: String,
    pub current_blake3_hex: String,
    pub manifest_blake3_hex: String,
}

/// Recovery result after loading MANIFEST first, then replaying WAL past it.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryOutcome {
    pub manifest: VaultManifest,
    pub wal_records: Vec<ReplayRecord>,
    pub torn_tail: Option<TornTail>,
    pub last_recovered_seq: u64,
    pub degraded_rebuildable: bool,
}

pub fn recover_vault(vault_dir: impl AsRef<Path>) -> Result<RecoveryOutcome> {
    let vault_dir = vault_dir.as_ref();
    let manifest = ManifestStore::open(vault_dir).load_current()?;
    let replay = replay_dir_after(vault_dir.join("wal"), manifest.durable_seq)?;
    let wal_records: Vec<_> = replay
        .records
        .into_iter()
        .filter(|record| record.seq > manifest.durable_seq)
        .collect();
    let last_recovered_seq = wal_records
        .last()
        .map_or(manifest.durable_seq, |record| record.seq);
    let degraded_rebuildable = manifest.degraded_rebuildable;

    Ok(RecoveryOutcome {
        manifest,
        wal_records,
        torn_tail: replay.torn_tail,
        last_recovered_seq,
        degraded_rebuildable,
    })
}

/// Loads one immutable manifest generation and validates its WAL tail without
/// truncation or write-capable lock admission.
pub(crate) fn recover_vault_read_only(vault_dir: impl AsRef<Path>) -> Result<RecoveryOutcome> {
    let vault_dir = vault_dir.as_ref();
    let manifest = ManifestStore::open(vault_dir).load_current()?;
    let replay =
        crate::wal::replay_dir_read_only_after(vault_dir.join("wal"), manifest.durable_seq)?;
    let wal_records: Vec<_> = replay
        .records
        .into_iter()
        .filter(|record| record.seq > manifest.durable_seq)
        .collect();
    let last_recovered_seq = wal_records
        .last()
        .map_or(manifest.durable_seq, |record| record.seq);
    let degraded_rebuildable = manifest.degraded_rebuildable;

    Ok(RecoveryOutcome {
        manifest,
        wal_records,
        torn_tail: replay.torn_tail,
        last_recovered_seq,
        degraded_rebuildable,
    })
}

/// Reads a base CF shard through the fail-closed SST path.
pub fn read_base_shard(path: impl AsRef<Path>, key: &[u8]) -> Result<Option<Vec<u8>>> {
    SstReader::open(path)?.get(key)
}

pub fn is_quarantined(manifest: &VaultManifest, seq: u64) -> bool {
    manifest
        .quarantines
        .iter()
        .any(|record| record.contains(seq))
}

pub fn is_vault_seq_quarantined(vault_dir: impl AsRef<Path>, seq: u64) -> Result<bool> {
    let vault_dir = vault_dir.as_ref();
    let current = vault_dir.join(CURRENT_FILE);
    if !current
        .try_exists()
        .map_err(|error| storage_error("inspect quarantine CURRENT", error))?
    {
        return Ok(false);
    }
    let manifest = ManifestStore::open(vault_dir).load_current()?;
    Ok(is_quarantined(&manifest, seq))
}

fn manifest_filename(seq: u64) -> String {
    format!("{MANIFEST_PREFIX}{seq:020}{MANIFEST_SUFFIX}")
}

fn valid_manifest_filename(name: &str) -> bool {
    if !name.starts_with(MANIFEST_PREFIX) || !name.ends_with(MANIFEST_SUFFIX) {
        return false;
    }
    let digits = &name[MANIFEST_PREFIX.len()..name.len() - MANIFEST_SUFFIX.len()];
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn encode_manifest(manifest: &VaultManifest) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(manifest)
        .map_err(|error| CalyxError::aster_corrupt_shard(format!("encode MANIFEST: {error}")))
}

fn decode_manifest(bytes: &[u8]) -> Result<VaultManifest> {
    let manifest: VaultManifest = serde_json::from_slice(bytes)
        .map_err(|error| CalyxError::aster_corrupt_shard(format!("decode MANIFEST: {error}")))?;
    manifest.validate()?;
    Ok(manifest)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file =
            File::create(&tmp).map_err(|error| storage_error("create atomic temp", error))?;
        file.write_all(bytes)
            .map_err(|error| storage_error("write atomic temp", error))?;
        file.sync_all()
            .map_err(|error| storage_error("fsync atomic temp", error))?;
    }
    fs::rename(&tmp, path).map_err(|error| storage_error("rename atomic file", error))?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<()> {
    crate::fsync::sync_parent(path, "manifest")
}

fn invalid_component(component: Component<'_>) -> bool {
    matches!(
        component,
        Component::ParentDir | Component::RootDir | Component::Prefix(_)
    )
}

fn require_prefix(reference: &ImmutableRef, prefix: &str) -> Result<()> {
    if !reference.logical_path.starts_with(prefix) {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "manifest ref {} must be under {prefix}",
            reference.logical_path
        )));
    }
    Ok(())
}

fn verify_immutable_refs(vault_dir: &Path, manifest: &VaultManifest) -> Result<()> {
    verify_immutable_ref(vault_dir, &manifest.panel_ref)?;
    if let Some(reference) = &manifest.registry_ref {
        verify_immutable_ref(vault_dir, reference)?;
    }
    for reference in &manifest.codebook_refs {
        verify_immutable_ref(vault_dir, reference)?;
    }
    Ok(())
}

fn verify_changed_immutable_refs(
    vault_dir: &Path,
    before: &VaultManifest,
    after: &VaultManifest,
) -> Result<()> {
    if after.panel_ref != before.panel_ref {
        verify_immutable_ref(vault_dir, &after.panel_ref)?;
    }
    if after.registry_ref != before.registry_ref
        && let Some(reference) = &after.registry_ref
    {
        verify_immutable_ref(vault_dir, reference)?;
    }
    for reference in &after.codebook_refs {
        if !before.codebook_refs.contains(reference) {
            verify_immutable_ref(vault_dir, reference)?;
        }
    }
    Ok(())
}

fn verify_immutable_ref(vault_dir: &Path, reference: &ImmutableRef) -> Result<()> {
    reference.validate()?;
    let path = vault_dir.join(&reference.logical_path);
    let bytes = fs::read(&path).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!(
            "manifest immutable ref {} unreadable: {error}",
            reference.logical_path
        ))
    })?;
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual != reference.blake3_hex {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "manifest immutable ref {} hash mismatch: expected {}, got {}",
            reference.logical_path, reference.blake3_hex, actual
        )));
    }
    Ok(())
}

fn storage_error(context: &str, error: io::Error) -> CalyxError {
    CalyxError::disk_pressure(format!("{context}: {error}"))
}

fn format_version_unsupported(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_FORMAT_VERSION_UNSUPPORTED",
        message: message.into(),
        remediation: "refuse unknown format major; migrate through a compatible reader",
    }
}
