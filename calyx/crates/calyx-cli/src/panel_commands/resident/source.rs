use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Modality, Placement, SlotState};
use calyx_registry::{lens_spec_from_manifest_path, load_vault_panel_state};

use super::flags::ServeFlags;
use super::*;
use crate::panel_commands::template_store::{self, TemplateStore};
use crate::panel_commands::warm::resident_support::is_managed_resident_neural_runtime;

const NO_APPLICABLE_GPU_LENS: &str = "CALYX_PANEL_RESIDENT_NO_APPLICABLE_GPU_LENS";

#[derive(Clone, Debug)]
pub(super) struct FrozenResidentSource {
    pub(super) fingerprint: String,
    pub(super) selector: String,
    pub(super) source_of_truth: String,
    pub(super) canonical_vault: Option<PathBuf>,
    pub(super) template: Option<String>,
    applicable_neural_modalities: Vec<Modality>,
}

impl FrozenResidentSource {
    /// Reject work that cannot execute an active, managed GPU neural lens.
    /// This check is source-only and does not construct or wake a runtime.
    pub(super) fn require_applicable_neural_modality(&self, modality: Modality) -> CliResult {
        if self.applicable_neural_modalities.contains(&modality) {
            return Ok(());
        }
        Err(CliError::from(CalyxError {
            code: NO_APPLICABLE_GPU_LENS,
            message: format!(
                "resident source {} has no active managed GPU neural lens for modality {modality:?}",
                self.selector
            ),
            remediation: "send a modality represented by an active managed GPU neural lens in the frozen panel, or commission that lens before retrying",
        }))
    }
}

/// Freeze the panel/registry identity without constructing any neural runtime.
/// Every worker generation recomputes this fingerprint before loading models.
pub(super) fn freeze_source(home: &Path, flags: &ServeFlags) -> CliResult<FrozenResidentSource> {
    if flags.template.is_some() == flags.vault.is_some() {
        return Err(CliError::usage(
            "resident source requires exactly one of template or vault",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hash_part(&mut hasher, b"calyx-panel-resident-frozen-source-v1");
    hash_part(&mut hasher, home.to_string_lossy().as_bytes());
    for slot in &flags.slots {
        hash_part(&mut hasher, &slot.get().to_le_bytes());
    }
    hash_part(
        &mut hasher,
        &serde_json::to_vec(&flags.modality)
            .map_err(|error| CliError::runtime(format!("serialize resident modality: {error}")))?,
    );

    if let Some(selector) = flags.template.as_deref() {
        let template = TemplateStore::open(home).load(selector)?;
        template.validate()?;
        let mut applicable_neural_modalities = Vec::new();
        let template_bytes = serde_json::to_vec(&template).map_err(|error| {
            CliError::runtime(format!(
                "serialize resident template {selector} for frozen fingerprint: {error}"
            ))
        })?;
        hash_part(&mut hasher, b"template");
        hash_part(&mut hasher, selector.as_bytes());
        hash_part(&mut hasher, &template_bytes);
        for lens in &template.lenses {
            let manifest_path = Path::new(&lens.manifest);
            let manifest = std::fs::read(manifest_path).map_err(|error| {
                CliError::io(format!(
                    "read resident frozen manifest {}: {error}",
                    manifest_path.display()
                ))
            })?;
            hash_part(&mut hasher, lens.manifest.as_bytes());
            hash_part(&mut hasher, &manifest);
            let spec = lens_spec_from_manifest_path(manifest_path)?;
            template_store::validate_lens_ref_against_spec(lens, &spec)?;
            if lens.placement == Placement::Gpu && is_managed_resident_neural_runtime(&spec.runtime)
            {
                push_unique_modality(&mut applicable_neural_modalities, lens.modality);
            }
        }
        let fingerprint = hasher.finalize().to_hex().to_string();
        return Ok(FrozenResidentSource {
            source_of_truth: format!(
                "{} plus immutable template object and frozen lens manifests",
                home.join("panels")
                    .join("templates")
                    .join("index.json")
                    .display()
            ),
            selector: selector.to_string(),
            fingerprint,
            canonical_vault: None,
            template: Some(selector.to_string()),
            applicable_neural_modalities,
        });
    }

    let vault = flags.vault.as_ref().expect("validated vault source");
    let canonical_vault = vault.canonicalize().map_err(|error| {
        CliError::io(format!(
            "canonicalize resident --vault {}: {error}",
            vault.display()
        ))
    })?;
    // Vault registry restoration is lazy. Serializing its frozen snapshots
    // proves panel_ref/registry_ref identity without loading a model or CUDA.
    let state = load_vault_panel_state(&canonical_vault)?;
    let applicable_neural_modalities = state
        .panel
        .slots
        .iter()
        .filter(|slot| {
            slot.state == SlotState::Active
                && slot.resource.placement == Placement::Gpu
                && (flags.slots.is_empty() || flags.slots.contains(&slot.slot_id))
                && flags
                    .modality
                    .is_none_or(|modality| slot.modality == modality)
        })
        .filter_map(|slot| {
            state
                .registry
                .lens_spec(slot.lens_id)
                .filter(|spec| is_managed_resident_neural_runtime(&spec.runtime))
                .map(|_| slot.modality)
        })
        .fold(Vec::new(), |mut modalities, modality| {
            push_unique_modality(&mut modalities, modality);
            modalities
        });
    let panel_bytes = serde_json::to_vec(&state.panel).map_err(|error| {
        CliError::runtime(format!(
            "serialize resident vault panel {}: {error}",
            canonical_vault.display()
        ))
    })?;
    let registry_bytes = serde_json::to_vec(&state.registry.lens_snapshots()).map_err(|error| {
        CliError::runtime(format!(
            "serialize resident vault registry {}: {error}",
            canonical_vault.display()
        ))
    })?;
    hash_part(&mut hasher, b"vault");
    hash_part(&mut hasher, canonical_vault.to_string_lossy().as_bytes());
    hash_part(&mut hasher, &panel_bytes);
    hash_part(&mut hasher, &registry_bytes);
    let fingerprint = hasher.finalize().to_hex().to_string();
    let selector = format!("vault:{}", canonical_vault.display());
    Ok(FrozenResidentSource {
        source_of_truth: format!(
            "vault MANIFEST panel_ref registry_ref:{}",
            canonical_vault.display()
        ),
        selector,
        fingerprint,
        canonical_vault: Some(canonical_vault),
        template: None,
        applicable_neural_modalities,
    })
}

fn push_unique_modality(modalities: &mut Vec<Modality>, modality: Modality) {
    if !modalities.contains(&modality) {
        modalities.push(modality);
    }
}

fn hash_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
