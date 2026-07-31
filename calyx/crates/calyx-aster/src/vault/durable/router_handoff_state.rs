//! Durable completion marker for manifest-bound router handoff.
//!
//! Manifest publication necessarily precedes router-copy retirement. The
//! marker records the exact immutable manifest generation whose covered router
//! flushes were verified and removed. If a process dies in that window, the
//! manifest remains authoritative and the older/absent marker forces the next
//! writer to perform a full physical inventory before advancing the marker.

use super::{DurableVault, storage_error};
use crate::manifest::{ManifestStore, VaultManifest};
use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

const ROUTER_HANDOFF_FILE: &str = "ROUTER_HANDOFF";
const ROUTER_HANDOFF_TEMP: &str = "ROUTER_HANDOFF.tmp";
const ROUTER_HANDOFF_SCHEMA: &str = "calyx-router-handoff-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::vault) struct DurableManifestIdentity {
    pub manifest_seq: u64,
    pub durable_seq: u64,
    pub pointer: String,
    pub manifest_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouterHandoffStateV1 {
    schema: String,
    manifest_seq: u64,
    durable_seq: u64,
    pointer: String,
    manifest_blake3: String,
}

impl DurableVault {
    pub(in crate::vault) fn current_manifest_identity(
        &self,
    ) -> Result<Option<DurableManifestIdentity>> {
        let current_path = self.root.join("CURRENT");
        if !current_path.exists() {
            return Ok(None);
        }
        let store = ManifestStore::open(&self.root);
        let manifest = store.load_current()?;
        let pointer = store.current_pointer()?;
        let manifest_path = self.root.join(&pointer);
        let bytes = fs::read(&manifest_path)
            .map_err(|error| storage_error("read current handoff manifest", error))?;
        Ok(Some(DurableManifestIdentity {
            manifest_seq: manifest.manifest_seq,
            durable_seq: manifest.durable_seq,
            pointer,
            manifest_blake3: blake3::hash(&bytes).to_hex().to_string(),
        }))
    }

    /// Returns true unless the durable completion marker is byte-bound to the
    /// exact current manifest generation before this flush begins.
    pub(in crate::vault) fn router_handoff_needs_full_inventory(
        &self,
        before: Option<&DurableManifestIdentity>,
    ) -> Result<bool> {
        let Some(state) = read_state(&self.root)? else {
            return Ok(true);
        };
        validate_state_manifest(&self.root, &state)?;
        let Some(before) = before else {
            return Err(handoff_state_error(
                "ROUTER_HANDOFF exists while CURRENT is absent",
            ));
        };
        if state.manifest_seq > before.manifest_seq || state.durable_seq > before.durable_seq {
            return Err(handoff_state_error(format!(
                "ROUTER_HANDOFF generation ({},{}) is ahead of current manifest ({},{})",
                state.manifest_seq, state.durable_seq, before.manifest_seq, before.durable_seq
            )));
        }
        Ok(state.manifest_seq != before.manifest_seq
            || state.durable_seq != before.durable_seq
            || state.pointer != before.pointer
            || state.manifest_blake3 != before.manifest_blake3)
    }

    pub(in crate::vault) fn publish_router_handoff(
        &self,
        identity: &DurableManifestIdentity,
    ) -> Result<PathBuf> {
        let current = self.current_manifest_identity()?.ok_or_else(|| {
            handoff_state_error("cannot publish ROUTER_HANDOFF while CURRENT is absent")
        })?;
        if &current != identity {
            return Err(handoff_state_error(format!(
                "CURRENT changed before ROUTER_HANDOFF publication: expected {:?}, read {:?}",
                identity, current
            )));
        }
        let state = RouterHandoffStateV1 {
            schema: ROUTER_HANDOFF_SCHEMA.to_string(),
            manifest_seq: identity.manifest_seq,
            durable_seq: identity.durable_seq,
            pointer: identity.pointer.clone(),
            manifest_blake3: identity.manifest_blake3.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&state).map_err(|error| {
            handoff_state_error(format!("encode ROUTER_HANDOFF state: {error}"))
        })?;
        let path = self.root.join(ROUTER_HANDOFF_FILE);
        let temp = self.root.join(ROUTER_HANDOFF_TEMP);
        {
            let mut file = File::create(&temp)
                .map_err(|error| storage_error("create ROUTER_HANDOFF temp", error))?;
            file.write_all(&bytes)
                .map_err(|error| storage_error("write ROUTER_HANDOFF temp", error))?;
            file.sync_all()
                .map_err(|error| storage_error("fsync ROUTER_HANDOFF temp", error))?;
        }
        fs::rename(&temp, &path).map_err(|error| storage_error("publish ROUTER_HANDOFF", error))?;
        crate::fsync::sync_parent(&path, "router handoff state")?;
        let persisted = read_state(&self.root)?.ok_or_else(|| {
            handoff_state_error("ROUTER_HANDOFF disappeared immediately after publication")
        })?;
        if persisted.manifest_seq != state.manifest_seq
            || persisted.durable_seq != state.durable_seq
            || persisted.pointer != state.pointer
            || persisted.manifest_blake3 != state.manifest_blake3
        {
            return Err(handoff_state_error(
                "ROUTER_HANDOFF readback differs from the published manifest identity",
            ));
        }
        validate_state_manifest(&self.root, &persisted)?;
        Ok(path)
    }
}

fn read_state(root: &Path) -> Result<Option<RouterHandoffStateV1>> {
    let path = root.join(ROUTER_HANDOFF_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|error| storage_error("read ROUTER_HANDOFF", error))?;
    let state: RouterHandoffStateV1 = serde_json::from_slice(&bytes).map_err(|error| {
        handoff_state_error(format!("decode ROUTER_HANDOFF {}: {error}", path.display()))
    })?;
    if state.schema != ROUTER_HANDOFF_SCHEMA {
        return Err(handoff_state_error(format!(
            "ROUTER_HANDOFF schema {:?} is not {:?}",
            state.schema, ROUTER_HANDOFF_SCHEMA
        )));
    }
    Ok(Some(state))
}

fn validate_state_manifest(root: &Path, state: &RouterHandoffStateV1) -> Result<()> {
    let expected_pointer = format!("manifest-{:020}.json", state.manifest_seq);
    if state.pointer != expected_pointer {
        return Err(handoff_state_error(format!(
            "ROUTER_HANDOFF pointer {:?} is not canonical {:?}",
            state.pointer, expected_pointer
        )));
    }
    let path = root.join(&state.pointer);
    let bytes = fs::read(&path)
        .map_err(|error| storage_error("read ROUTER_HANDOFF immutable manifest", error))?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    if hash != state.manifest_blake3 {
        return Err(handoff_state_error(format!(
            "ROUTER_HANDOFF manifest hash mismatch for {}: recorded {}, read {}",
            path.display(),
            state.manifest_blake3,
            hash
        )));
    }
    let manifest: VaultManifest = serde_json::from_slice(&bytes).map_err(|error| {
        handoff_state_error(format!(
            "decode ROUTER_HANDOFF immutable manifest {}: {error}",
            path.display()
        ))
    })?;
    manifest.validate()?;
    if manifest.manifest_seq != state.manifest_seq || manifest.durable_seq != state.durable_seq {
        return Err(handoff_state_error(format!(
            "ROUTER_HANDOFF identity ({},{}) differs from immutable manifest ({},{})",
            state.manifest_seq, state.durable_seq, manifest.manifest_seq, manifest.durable_seq
        )));
    }
    Ok(())
}

fn handoff_state_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ASTER_ROUTER_HANDOFF_STATE_INVALID",
        message: message.into(),
        remediation: "preserve the vault and repair the exact manifest/handoff identity mismatch before allowing another durable publication",
    }
}
