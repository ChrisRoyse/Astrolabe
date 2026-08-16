//! One explicit interpretation boundary for persisted Weave slot sources.
//!
//! Aster owns ordinary `SlotVector` bytes but cannot interpret a Registry
//! compression envelope without the exact frozen panel/lens state.  Production
//! Weave operations retain one instance of [`WeaveSlotSource`] for their pinned
//! snapshot.  Supplying a vault-panel root permits that state to be loaded at
//! most once when a manifest requires it;
//! omitting it selects Aster's strict raw resolver, which refuses a compressed
//! tag instead of consulting a raw sidecar.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver};
use calyx_core::{CalyxError, Clock, CxId, Result, Seq, Slot, SlotId, SlotVector};
use calyx_registry::{CompressedGenerationIdentity, VaultPanelState, load_vault_panel_state};

/// A compressed generation was encountered without its exact persisted panel
/// and registered lens interpretation.
pub const ASTRO_WEAVE_SLOT_CONTEXT_REQUIRED: &str = "ASTRO_WEAVE_SLOT_CONTEXT_REQUIRED";

/// One operation-local, snapshot-pinned slot interpretation owner.
///
/// The persisted [`VaultPanelState`] and requested slot identity are invariant
/// across each operation and are therefore retained here rather than reloaded
/// in a row loop (PC-03, PC-12, PC-40). Production `R`, `D`, and requested `Q`
/// remain an explicit measurement gap; fixture-scale verification does not
/// establish their cost.
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
        if !self.has_compressed_manifest(vault, slot)? {
            return StrictRawSlotResolver.resolve_slot_vectors_at(
                vault,
                self.snapshot,
                slot,
                cx_ids,
            );
        }
        self.with_panel_state(|state| {
            state.resolve_slot_vectors_at(vault, self.snapshot, slot, cx_ids)
        })
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
        if !self.has_compressed_manifest(vault, slot)? {
            return StrictRawSlotResolver.resolve_slot_column_at(vault, self.snapshot, slot);
        }
        self.with_panel_state(|state| state.resolve_slot_column_at(vault, self.snapshot, slot))
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
        if !self.has_compressed_manifest(vault, slot)? {
            return Ok(None);
        }
        self.with_panel_state(|state| {
            let registered = unique_registered_slot(state, slot)?;
            state
                .registry
                .compressed_slot_index(vault, registered)?
                .generation_identity_at(self.snapshot)
                .map(Some)
        })
    }

    fn has_compressed_manifest<C>(&self, vault: &AsterVault<C>, slot: SlotId) -> Result<bool>
    where
        C: Clock,
    {
        vault
            .read_cf_at(
                self.snapshot,
                ColumnFamily::Compression,
                &compression_manifest_key(slot),
            )
            .map(|manifest| manifest.is_some())
    }

    fn with_panel_state<T>(
        &self,
        operation: impl FnOnce(&VaultPanelState) -> Result<T>,
    ) -> Result<T> {
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
        let state = self.panel_state.borrow();
        operation(state.as_ref().ok_or_else(|| {
            slot_context_error("persisted panel state disappeared after successful load")
        })?)
    }
}

fn unique_registered_slot(state: &VaultPanelState, slot: SlotId) -> Result<&Slot> {
    let mut matches = state
        .panel
        .slots
        .iter()
        .filter(|registered| registered.slot_id == slot);
    let registered = matches.next().ok_or_else(|| {
        slot_context_error(format!(
            "persisted panel version {} does not register manifested slot {}",
            state.panel.version,
            slot.get()
        ))
    })?;
    if matches.next().is_some() {
        return Err(slot_context_error(format!(
            "persisted panel version {} registers manifested slot {} more than once",
            state.panel.version,
            slot.get()
        )));
    }
    Ok(registered)
}

fn slot_context_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_WEAVE_SLOT_CONTEXT_REQUIRED,
        message: message.into(),
        remediation: "open the exact vault root that owns the persisted panel and frozen Registry lens state; never infer a compressed slot or substitute its raw sidecar",
    }
}
