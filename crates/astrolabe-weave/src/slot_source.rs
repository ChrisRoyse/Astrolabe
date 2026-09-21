//! One explicit interpretation boundary for persisted Weave slot sources.
//!
//! Aster owns ordinary `SlotVector` bytes but cannot interpret a Registry
//! compression envelope without the exact frozen panel/lens state.  Production
//! Weave operations retain one instance of [`WeaveSlotSource`] for their
//! interpretation generation. Supplying a vault-panel root permits that state to be loaded at
//! most once when a manifest requires it;
//! omitting it selects Aster's strict raw resolver, which refuses a compressed
//! tag instead of consulting a raw sidecar.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver};
use calyx_core::{CalyxError, Clock, CxId, Result, Seq, Slot, SlotId, SlotVector};
use calyx_registry::{CompressedGenerationIdentity, VaultPanelState, load_vault_panel_state};
use serde::{Deserialize, Serialize};

/// A compressed generation was encountered without its exact persisted panel
/// and registered lens interpretation.
pub const ASTRO_WEAVE_SLOT_CONTEXT_REQUIRED: &str = "ASTRO_WEAVE_SLOT_CONTEXT_REQUIRED";
/// A source Slot or Compression generation no longer matches the exact
/// representation captured before derived writes began.
pub const ASTRO_WEAVE_SLOT_BINDING_CHANGED: &str = "ASTRO_WEAVE_SLOT_BINDING_CHANGED";

/// Exact operation-wide identity of one source slot in a latest-only vault.
///
/// The global MVCC sequence is deliberately absent: derived commits may advance
/// it. Every read must instead use a fresh current-latest epoch and prove these
/// source identities unchanged before and after resolving rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeaveSlotBinding {
    pub slot: SlotId,
    pub slot_cf_generation: u64,
    pub compression_cf_generation: u64,
    pub compressed_generation_identity: Option<CompressedGenerationIdentity>,
}

/// One operation-local slot interpretation owner.
///
/// The persisted [`VaultPanelState`] and requested slot identity are invariant
/// across each operation and are therefore retained here rather than reloaded
/// in a row loop (PC-03, PC-12, PC-40). The configured snapshot is the default
/// for genuinely point-in-time operations. A latest-only mutating operation may
/// instead use the explicit `*_at` methods with one short current-latest epoch
/// per read while it separately proves the source column-family generations
/// unchanged. Production `R`, `D`, and requested `Q` remain an explicit
/// measurement gap; fixture-scale verification does not establish their cost.
pub struct WeaveSlotSource {
    snapshot: Seq,
    vault_panel_root: Option<PathBuf>,
    expected_panel_version: Option<u32>,
    panel_state: RefCell<Option<VaultPanelState>>,
}

impl WeaveSlotSource {
    /// Creates the interpretation owner for one exact snapshot. Persisted
    /// panel/registry assets are loaded and hash-validated at most once, on the
    /// first manifested slot; an all-raw operation performs no registry IO.
    pub fn open(
        snapshot: Seq,
        vault_panel_root: Option<&Path>,
        expected_panel_version: Option<u32>,
    ) -> Result<Self> {
        Ok(Self {
            snapshot,
            vault_panel_root: vault_panel_root.map(Path::to_path_buf),
            expected_panel_version,
            panel_state: RefCell::new(None),
        })
    }

    /// Exact sequence retained by this operation.
    pub fn snapshot(&self) -> Seq {
        self.snapshot
    }

    /// Verifies that an operation-discovered Base/graph panel version equals
    /// the retained persisted interpretation whenever one was supplied.
    pub fn ensure_panel_version(&self, expected: u32) -> Result<()> {
        if self.panel_state.borrow().is_some() {
            self.with_panel_state(|state| {
                if state.panel.version != expected {
                    return Err(slot_context_error(format!(
                        "persisted panel version {} does not equal source panel version {expected}",
                        state.panel.version
                    )));
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Captures one exact source representation at a caller-retained
    /// current-latest epoch. Any sequence or source-generation movement during
    /// capture refuses instead of returning a partially mixed binding.
    pub fn bind_latest_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot: SlotId,
    ) -> Result<WeaveSlotBinding>
    where
        C: Clock,
    {
        if vault.latest_seq() != snapshot {
            return Err(slot_binding_error(format!(
                "cannot bind S{} at non-latest seq {snapshot}; observed latest seq {}",
                slot.get(),
                vault.latest_seq(),
            )));
        }
        let slot_cf_generation = vault.cf_content_generation(ColumnFamily::slot(slot))?;
        let compression_cf_generation = vault.cf_content_generation(ColumnFamily::Compression)?;
        let compressed_generation_identity =
            self.compressed_generation_identity_at(vault, snapshot, slot)?;
        let binding = WeaveSlotBinding {
            slot,
            slot_cf_generation,
            compression_cf_generation,
            compressed_generation_identity,
        };
        self.verify_latest_binding_at(vault, snapshot, &binding)?;
        Ok(binding)
    }

    /// Verifies a previously captured source representation at one exact
    /// current-latest read epoch.
    pub fn verify_latest_binding_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        binding: &WeaveSlotBinding,
    ) -> Result<()>
    where
        C: Clock,
    {
        let latest_before = vault.latest_seq();
        let slot_generation_before =
            vault.cf_content_generation(ColumnFamily::slot(binding.slot))?;
        let compression_generation_before =
            vault.cf_content_generation(ColumnFamily::Compression)?;
        if latest_before != snapshot
            || slot_generation_before != binding.slot_cf_generation
            || compression_generation_before != binding.compression_cf_generation
        {
            return Err(slot_binding_error(format!(
                "S{} binding changed before read: expected_seq={snapshot}, observed_seq={latest_before}, expected_slot_generation={}, observed_slot_generation={slot_generation_before}, expected_compression_generation={}, observed_compression_generation={compression_generation_before}",
                binding.slot.get(),
                binding.slot_cf_generation,
                binding.compression_cf_generation,
            )));
        }
        let observed_identity =
            self.compressed_generation_identity_at(vault, snapshot, binding.slot)?;
        let latest_after = vault.latest_seq();
        let slot_generation_after =
            vault.cf_content_generation(ColumnFamily::slot(binding.slot))?;
        let compression_generation_after =
            vault.cf_content_generation(ColumnFamily::Compression)?;
        if observed_identity != binding.compressed_generation_identity
            || latest_after != snapshot
            || slot_generation_after != binding.slot_cf_generation
            || compression_generation_after != binding.compression_cf_generation
        {
            return Err(slot_binding_error(format!(
                "S{} binding changed during verification: expected_identity={:?}, observed_identity={observed_identity:?}, expected_seq={snapshot}, observed_seq={latest_after}, expected_slot_generation={}, observed_slot_generation={slot_generation_after}, expected_compression_generation={}, observed_compression_generation={compression_generation_after}",
                binding.slot.get(),
                binding.compressed_generation_identity,
                binding.slot_cf_generation,
                binding.compression_cf_generation,
            )));
        }
        Ok(())
    }

    /// Resolves one roster through a source binding captured before derived
    /// writes. Verification brackets the physical resolution.
    pub fn resolve_many_bound_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        binding: &WeaveSlotBinding,
        cx_ids: &[CxId],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>>
    where
        C: Clock,
    {
        self.verify_latest_binding_at(vault, snapshot, binding)?;
        let resolved = self.resolve_many_at(vault, snapshot, binding.slot, cx_ids)?;
        self.verify_latest_binding_at(vault, snapshot, binding)?;
        Ok(resolved)
    }

    /// Resolves one whole column through a source binding captured before
    /// derived writes. Verification brackets the physical resolution.
    pub fn resolve_column_bound_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        binding: &WeaveSlotBinding,
    ) -> Result<Vec<(CxId, SlotVector)>>
    where
        C: Clock,
    {
        self.verify_latest_binding_at(vault, snapshot, binding)?;
        let resolved = self.resolve_column_at(vault, snapshot, binding.slot)?;
        self.verify_latest_binding_at(vault, snapshot, binding)?;
        Ok(resolved)
    }

    /// Resolves a duplicate-free requested roster in caller order.  The
    /// Registry implementation uses one batch path for a compressed generation;
    /// the strict raw implementation refuses compressed envelopes.
    pub fn resolve_many<C>(
        &self,
        vault: &AsterVault<C>,
        slot: SlotId,
        cx_ids: &[CxId],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>>
    where
        C: Clock,
    {
        self.resolve_many_at(vault, self.snapshot, slot, cx_ids)
    }

    /// Resolves a duplicate-free requested roster at one caller-retained read
    /// epoch. This does not authorize a source-generation change: latest-only
    /// callers must bind and verify the Slot and Compression CF generations
    /// around the complete read.
    pub fn resolve_many_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot: SlotId,
        cx_ids: &[CxId],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>>
    where
        C: Clock,
    {
        if !self.has_compressed_manifest_at(vault, snapshot, slot)? {
            return StrictRawSlotResolver.resolve_slot_vectors_at(vault, snapshot, slot, cx_ids);
        }
        self.with_panel_state(|state| state.resolve_slot_vectors_at(vault, snapshot, slot, cx_ids))
    }

    /// Resolves the complete visible column in ascending CxId order. This is an
    /// explicit whole-column operation, never a hidden point-read loop.
    pub fn resolve_column<C>(
        &self,
        vault: &AsterVault<C>,
        slot: SlotId,
    ) -> Result<Vec<(CxId, SlotVector)>>
    where
        C: Clock,
    {
        self.resolve_column_at(vault, self.snapshot, slot)
    }

    /// Resolves the complete visible column at one caller-retained read epoch.
    /// See [`Self::resolve_many_at`] for the required generation contract.
    pub fn resolve_column_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot: SlotId,
    ) -> Result<Vec<(CxId, SlotVector)>>
    where
        C: Clock,
    {
        if !self.has_compressed_manifest_at(vault, snapshot, slot)? {
            return StrictRawSlotResolver.resolve_slot_column_at(vault, snapshot, slot);
        }
        self.with_panel_state(|state| state.resolve_slot_column_at(vault, snapshot, slot))
    }

    /// Returns the immutable Registry generation identity when `slot` is
    /// manifested at this source's exact snapshot.  Manifest absence is the only
    /// authorization for a caller to enter its raw-byte path.
    pub fn compressed_generation_identity<C>(
        &self,
        vault: &AsterVault<C>,
        slot: SlotId,
    ) -> Result<Option<CompressedGenerationIdentity>>
    where
        C: Clock,
    {
        self.compressed_generation_identity_at(vault, self.snapshot, slot)
    }

    /// Returns the immutable Registry generation identity at one
    /// caller-retained read epoch. Manifest absence is an explicit raw
    /// representation identity and must be protected by the caller's captured
    /// Compression CF generation.
    pub fn compressed_generation_identity_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot: SlotId,
    ) -> Result<Option<CompressedGenerationIdentity>>
    where
        C: Clock,
    {
        if !self.has_compressed_manifest_at(vault, snapshot, slot)? {
            return Ok(None);
        }
        self.with_registered_slot(slot, |state, registered| {
            state
                .registry
                .compressed_generation_identity_at(vault, registered, snapshot)
                .map(Some)
        })
    }

    fn has_compressed_manifest_at<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot: SlotId,
    ) -> Result<bool>
    where
        C: Clock,
    {
        vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Compression,
                &compression_manifest_key(slot),
            )
            .map(|manifest| manifest.is_some())
    }

    fn with_panel_state<T>(
        &self,
        operation: impl FnOnce(&VaultPanelState) -> Result<T>,
    ) -> Result<T> {
        self.load_panel_state_if_needed()?;
        let state = self.panel_state.borrow();
        operation(state.as_ref().ok_or_else(|| {
            slot_context_error("persisted panel state disappeared after successful load")
        })?)
    }

    fn with_registered_slot<T>(
        &self,
        slot: SlotId,
        operation: impl FnOnce(&VaultPanelState, &Slot) -> Result<T>,
    ) -> Result<T> {
        self.load_panel_state_if_needed()?;
        let state = self.panel_state.borrow();
        let state = state.as_ref().ok_or_else(|| {
            slot_context_error("persisted panel state disappeared after successful load")
        })?;
        let registered = state.registered_slot(slot).map_err(|error| {
            slot_context_error(format!(
                "resolve manifested slot {} through persisted panel index: {}: {}; remediation: {}",
                slot.get(),
                error.code,
                error.message,
                error.remediation
            ))
        })?;
        operation(state, registered)
    }

    fn load_panel_state_if_needed(&self) -> Result<()> {
        if self.panel_state.borrow().is_none() {
            let root = self.vault_panel_root.as_ref().ok_or_else(|| {
                slot_context_error(format!(
                    "a manifested slot at seq={} requires the exact vault-panel root",
                    self.snapshot
                ))
            })?;
            let state = load_vault_panel_state(root).map_err(|error| {
                slot_context_error(format!(
                    "load persisted panel/Registry state from {}: {}: {}; remediation: {}",
                    root.display(),
                    error.code,
                    error.message,
                    error.remediation
                ))
            })?;
            if let Some(expected) = self.expected_panel_version
                && state.panel.version != expected
            {
                return Err(slot_context_error(format!(
                    "persisted panel version {} does not equal source panel version {expected}",
                    state.panel.version
                )));
            }
            *self.panel_state.borrow_mut() = Some(state);
        }
        Ok(())
    }
}

fn slot_context_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_WEAVE_SLOT_CONTEXT_REQUIRED,
        message: message.into(),
        remediation: "open the exact vault root that owns the persisted panel and frozen Registry lens state; never infer a compressed slot or substitute its raw sidecar",
    }
}

fn slot_binding_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_WEAVE_SLOT_BINDING_CHANGED,
        message: message.into(),
        remediation: "preserve the staged generation and identify the exact Slot or Compression writer; recapture the complete source generation before any derived write instead of retrying a historical sequence or changing representation",
    }
}
