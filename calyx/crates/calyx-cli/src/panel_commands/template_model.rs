use std::collections::BTreeSet;
use std::path::Path;

use calyx_core::{
    Asymmetry, CalyxError, LensCost, LensId, Modality, Panel, Placement, QuantPolicy, Slot, SlotId,
    SlotKey, SlotResource, SlotShape, SlotState, content_address,
};
use calyx_registry::{LensHealth, LensRuntime, LensSpec};
use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult};
use crate::lens_commands::catalog::{
    LocalExecutionAttestationReport, bound_spec_from_catalog_entry, catalog_cost_matches,
    reparse_manifest_binding, resolved_runtime_placement,
};
use crate::lens_commands::support::runtime_name;

pub(super) const MIN_CONTENT_LENSES: usize = 10;
pub(super) const CATALOG_VERSION: u16 = 1;
pub(super) const OBJECT_VERSION: u16 = 2;
pub(super) const CARD_VERSION: u16 = 1;
pub(super) const A37_ADMISSION_VERSION: u16 = 1;
pub(super) const TEMPLATE_INVALID: &str = "CALYX_PANEL_TEMPLATE_INVALID";
pub(super) const TEMPLATE_NOT_FOUND: &str = "CALYX_PANEL_TEMPLATE_NOT_FOUND";
pub(super) const TEMPLATE_A37_GATE_REFUSED: &str = "CALYX_PANEL_TEMPLATE_A37_GATE_REFUSED";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PanelTemplateCatalog {
    pub schema_version: u16,
    pub templates: Vec<PanelTemplateIndexEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PanelTemplateIndexEntry {
    pub name: String,
    pub active_template_id: String,
    pub versions: Vec<PanelTemplateVersionRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PanelTemplateVersionRef {
    pub version: u32,
    pub template_id: String,
    pub object_path: String,
    pub blake3_hex: String,
    pub size_bytes: u64,
    pub saved_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedPanelTemplate {
    pub schema_version: u16,
    pub name: String,
    pub version: u32,
    pub notes: String,
    pub min_content_lenses: usize,
    pub lenses: Vec<TemplateLensRef>,
    pub time_controls: Vec<TemplateTimeControl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ensemble_card: Option<TemplateEnsembleCard>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TemplateLensRef {
    pub slot_key: String,
    pub lens_name: String,
    pub lens_id: LensId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_lens_id: Option<LensId>,
    pub weights_sha256: String,
    pub runtime: String,
    pub modality: Modality,
    pub shape: SlotShape,
    pub placement: Placement,
    pub cost: LensCost,
    pub manifest: String,
    pub manifest_sha256: String,
    pub execution_attestation: Option<LocalExecutionAttestationReport>,
    pub counts_toward_a35: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TemplateTimeControl {
    pub slot_key: String,
    pub kind: String,
    pub shape: SlotShape,
    pub purpose: String,
    pub counts_toward_a35: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TemplateEnsembleCard {
    pub schema_version: u16,
    pub source: String,
    pub content_lens_count: usize,
    pub measured_lens_count: usize,
    pub all_loaded: bool,
    pub min_coverage_rate: f32,
    pub total_vram_bytes: u64,
    pub total_ram_bytes: u64,
    pub mean_ms_per_input: f32,
    pub card_refs: Vec<CapabilityCardRef>,
    #[serde(default)]
    pub a37_admission: TemplateA37Admission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a37_ensemble_card_ref: Option<TemplateA37CardRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a37_admission_card_ref: Option<TemplateA37CardRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CapabilityCardRef {
    pub path: String,
    pub blake3_hex: String,
    pub lens_id: LensId,
    pub probe_count: usize,
    pub coverage_rate: f32,
    pub failed: usize,
    pub health: LensHealth,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TemplateA37Admission {
    pub schema_version: u16,
    pub source: String,
    pub gate_eligible: bool,
    pub status: String,
    pub verdict: String,
    pub content_lens_count: usize,
    pub temporal_sidecar_count: usize,
    pub temporal_counts_toward_content_floor: bool,
    pub association_family_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_eff: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_pairwise_corr: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_pairwise_nmi: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sum_unique_pid_bits: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TemplateA37CardRef {
    pub path: String,
    pub blake3_hex: String,
    pub card_schema_version: u32,
    pub card_source: String,
    pub panel_lens_count: usize,
    pub status: String,
}

#[derive(Clone, Debug)]
pub(super) struct TemplateDraft {
    pub name: String,
    pub notes: String,
    pub lenses: Vec<TemplateLensRef>,
    pub ensemble_card: Option<TemplateEnsembleCard>,
}

impl SavedPanelTemplate {
    pub(super) fn content_lens_count(&self) -> usize {
        self.lenses
            .iter()
            .filter(|lens| lens.counts_toward_a35)
            .count()
    }

    pub(super) fn validate(&self) -> CliResult {
        if self.schema_version != OBJECT_VERSION {
            return Err(template_error(
                TEMPLATE_INVALID,
                format!("unsupported panel template object {}", self.schema_version),
                "migrate the panel template object through a compatible reader",
            ));
        }
        if self.name.trim().is_empty() || self.name.contains(['/', '\\']) {
            return Err(template_error(
                TEMPLATE_INVALID,
                "panel template name must be non-empty and path-safe",
                "choose a stable template name such as text-deep",
            ));
        }
        if self.content_lens_count() < MIN_CONTENT_LENSES {
            return Err(template_error(
                TEMPLATE_INVALID,
                format!(
                    "panel template {} has {} content lenses; minimum is {MIN_CONTENT_LENSES}",
                    self.name,
                    self.content_lens_count()
                ),
                "add real frozen content lenses until the template has at least ten",
            ));
        }
        validate_lenses(self)?;
        validate_time_controls(self)?;
        for lens in &self.lenses {
            bound_lens_spec(lens)?;
        }
        Ok(())
    }

    pub(super) fn a37_admission(&self) -> TemplateA37Admission {
        self.ensemble_card
            .as_ref()
            .map(|card| card.a37_admission.clone())
            .unwrap_or_default()
    }

    pub(super) fn a37_gate_eligible(&self) -> bool {
        self.a37_admission().gate_eligible
    }

    pub(super) fn require_a37_gate(&self) -> CliResult {
        let admission = self.a37_admission();
        if admission.gate_eligible {
            return Ok(());
        }
        Err(template_error(
            TEMPLATE_A37_GATE_REFUSED,
            format!(
                "template {} is not A37 gate eligible: {}",
                self.name, admission.verdict
            ),
            "profile the template with an Assay EnsembleCard whose A37 status is gate_passed",
        ))
    }

    pub(super) fn to_target_panel(&self, created_at: u64) -> Panel {
        let mut slots = Vec::with_capacity(self.lenses.len() + self.time_controls.len());
        for lens in &self.lenses {
            let slot_id = SlotId::new(slots.len() as u16);
            slots.push(Slot {
                slot_id,
                slot_key: SlotKey::new(slot_id, lens.slot_key.clone()),
                lens_id: lens.lens_id,
                shape: lens.shape,
                modality: lens.modality,
                asymmetry: Asymmetry::None,
                quant: calyx_registry::spec::default_quant_for_shape(lens.shape),
                resource: SlotResource {
                    cost: lens.cost,
                    placement: lens.placement,
                },
                axis: Some(lens.slot_key.clone()),
                retrieval_only: false,
                excluded_from_dedup: false,
                bits_about: Default::default(),
                state: SlotState::Active,
                added_at_panel_version: (slots.len() + 1) as u32,
            });
        }
        for control in &self.time_controls {
            let slot_id = SlotId::new(slots.len() as u16);
            slots.push(Slot {
                slot_id,
                slot_key: SlotKey::new(slot_id, control.slot_key.clone()),
                lens_id: time_control_id(&self.name, control),
                shape: control.shape,
                modality: Modality::Structured,
                asymmetry: Asymmetry::None,
                quant: QuantPolicy::None,
                resource: SlotResource::default(),
                axis: Some(control.slot_key.clone()),
                retrieval_only: true,
                excluded_from_dedup: true,
                bits_about: Default::default(),
                state: SlotState::Active,
                added_at_panel_version: (slots.len() + 1) as u32,
            });
        }
        Panel {
            version: slots.len() as u32,
            slots,
            created_at,
            kernel_ref: None,
            guard_ref: None,
        }
    }
}

impl Default for TemplateA37Admission {
    fn default() -> Self {
        Self {
            schema_version: A37_ADMISSION_VERSION,
            source: "missing_assay_ensemble_card".to_string(),
            gate_eligible: false,
            status: "missing_a37_ensemble_card".to_string(),
            verdict: "A37 gate not evaluated; template has no Assay EnsembleCard".to_string(),
            content_lens_count: 0,
            temporal_sidecar_count: 0,
            temporal_counts_toward_content_floor: false,
            association_family_count: 0,
            n_eff: None,
            mean_pairwise_corr: None,
            mean_pairwise_nmi: None,
            sum_unique_pid_bits: None,
        }
    }
}

pub(super) fn default_time_controls() -> Vec<TemplateTimeControl> {
    vec![
        time_control("E2_recency", "temporal_recent", SlotShape::Dense(1)),
        time_control("E3_periodic", "temporal_periodic", SlotShape::Dense(2)),
        time_control("E4_positional", "temporal_positional", SlotShape::Dense(4)),
    ]
}

pub(super) fn lens_ref_from_catalog(entry: &super::LensCatalogEntry) -> CliResult<TemplateLensRef> {
    let spec = bound_spec_from_catalog_entry(entry)?;
    let catalog_lens_id: LensId = entry
        .lens_id
        .parse()
        .map_err(|err| CliError::usage(format!("parse lens_id {}: {err}", entry.lens_id)))?;
    let manifest_lens_id = spec.lens_id();
    if catalog_lens_id != manifest_lens_id {
        return Err(template_error(
            TEMPLATE_INVALID,
            format!(
                "lens catalog entry {} has lens_id {}, but manifest {} resolves to {}",
                entry.name,
                catalog_lens_id,
                entry.manifest.display(),
                manifest_lens_id
            ),
            "repair the lens catalog with `calyx lens add --manifest <manifest> --home <dir>` before saving templates",
        ));
    }
    Ok(TemplateLensRef {
        slot_key: slug(&entry.name),
        lens_name: entry.name.clone(),
        lens_id: catalog_lens_id,
        runtime_lens_id: None,
        weights_sha256: entry.weights_sha256.clone(),
        runtime: runtime_name(&spec.runtime).to_string(),
        modality: spec.modality,
        shape: spec.output,
        placement: entry.placement,
        cost: entry.cost,
        manifest: entry.manifest.display().to_string(),
        manifest_sha256: entry.manifest_sha256.clone(),
        execution_attestation: entry.execution_attestation.clone(),
        counts_toward_a35: true,
    })
}

pub(super) fn bound_lens_spec(lens: &TemplateLensRef) -> CliResult<LensSpec> {
    let manifest_path = Path::new(&lens.manifest);
    let (spec, manifest_sha256) = reparse_manifest_binding(manifest_path)?;
    if manifest_sha256 != lens.manifest_sha256 {
        return Err(template_error(
            "CALYX_PANEL_TEMPLATE_MANIFEST_DIGEST_MISMATCH",
            format!(
                "template lens {} binds manifest SHA-256 {}, but {} currently hashes to {}",
                lens.lens_name,
                lens.manifest_sha256,
                manifest_path.display(),
                manifest_sha256
            ),
            "preserve the template and manifest bytes, restore the admitted manifest, and save a new schema-v2 template only after re-attestation",
        ));
    }
    validate_lens_ref_against_spec(lens, &spec)?;
    Ok(spec)
}

pub(super) fn template_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    CliError::from(CalyxError {
        code,
        message: message.into(),
        remediation,
    })
}

pub(super) fn validate_lens_ref_against_spec(lens: &TemplateLensRef, spec: &LensSpec) -> CliResult {
    let expected_weights = crate::lens_commands::support::hex_from_bytes(&spec.weights_sha256);
    let expected_runtime = runtime_name(&spec.runtime);
    let expected_placement = resolved_runtime_placement(spec)?;
    let resource_matches =
        lens.placement == expected_placement && catalog_cost_matches(spec, lens.cost)?;
    let fields_match = lens.lens_name == spec.name
        && lens.lens_id == spec.lens_id()
        && lens.weights_sha256.eq_ignore_ascii_case(&expected_weights)
        && lens.runtime == expected_runtime
        && lens.modality == spec.modality
        && lens.shape == spec.output
        && resource_matches;
    if !fields_match {
        return Err(template_error(
            TEMPLATE_INVALID,
            format!(
                "template lens {} does not match canonical manifest {}: template_id={} manifest_id={} template_runtime={} manifest_runtime={} template_shape={:?} manifest_shape={:?} template_placement={:?} manifest_placement={:?} resource_matches={resource_matches}",
                lens.lens_name,
                lens.manifest,
                lens.lens_id,
                spec.lens_id(),
                lens.runtime,
                expected_runtime,
                lens.shape,
                spec.output,
                lens.placement,
                expected_placement
            ),
            "preserve the template bytes and rebuild a new template version from the canonical catalog",
        ));
    }
    validate_execution_attestation_against_spec(
        lens.execution_attestation.as_ref(),
        spec,
        lens.placement,
    )?;
    Ok(())
}

pub(super) fn validate_execution_attestation_against_spec(
    report: Option<&LocalExecutionAttestationReport>,
    spec: &LensSpec,
    placement: Placement,
) -> CliResult {
    let expected_runtime = mandatory_execution_runtime(&spec.runtime);
    let Some(expected_runtime) = expected_runtime else {
        if report.is_none() {
            return Ok(());
        }
        return Err(template_error(
            TEMPLATE_INVALID,
            format!(
                "template lens {} carries execution evidence for runtime {:?}, which has no persisted execution-attestation contract",
                spec.name, spec.runtime
            ),
            "rebuild the template from the authoritative catalog row",
        ));
    };
    let report = report.ok_or_else(|| {
        template_error(
            "CALYX_PANEL_TEMPLATE_EXECUTION_ATTESTATION_MISSING",
            format!(
                "template lens {} runtime {:?} has no persisted first-real-inference execution attestation",
                spec.name, spec.runtime
            ),
            "re-attest the exact manifest through calyx lens add and save a new schema-v2 template",
        )
    })?;
    let expected_corpus_hash =
        crate::lens_commands::support::hex_from_bytes(&spec.declared_contract().corpus_hash());
    if report.executable_lens_id != spec.lens_id().to_string()
        || report.executable_corpus_hash != expected_corpus_hash
        || report.runtime != expected_runtime
        || report.evidence_kind.trim().is_empty()
        || report.provider.trim().is_empty()
        || report.observed_execution_device.trim().is_empty()
    {
        return Err(template_error(
            TEMPLATE_INVALID,
            format!(
                "template lens {} contains incomplete or conflicting execution evidence",
                spec.name
            ),
            "rebuild the template from the authoritative attested catalog row",
        ));
    }
    let provider = report.provider.to_ascii_uppercase();
    match placement {
        Placement::Gpu => {
            if provider.contains("CPU")
                || !provider.contains("CUDA")
                || report
                    .observed_execution_device
                    .parse::<calyx_forge::PinnedCudaDeviceIdentity>()
                    .is_err()
            {
                return Err(template_error(
                    TEMPLATE_INVALID,
                    format!(
                        "GPU template lens {} persists non-CUDA execution provider={} device={}",
                        spec.name, report.provider, report.observed_execution_device
                    ),
                    "re-attest the manifest on its exact physical CUDA device and save a new template",
                ));
            }
        }
        Placement::Cpu => {
            if provider.contains("CUDA")
                || !provider.contains("CPU")
                || report.observed_execution_device != "cpu"
            {
                return Err(template_error(
                    TEMPLATE_INVALID,
                    format!(
                        "CPU template lens {} persists conflicting provider={} device={}",
                        spec.name, report.provider, report.observed_execution_device
                    ),
                    "re-attest only under the shared genuine-no-CUDA CPU authorization and save a new template",
                ));
            }
        }
    }
    if matches!(
        &spec.runtime,
        LensRuntime::Onnx { .. }
            | LensRuntime::OnnxColbert { .. }
            | LensRuntime::FastembedDensePlaced { .. }
            | LensRuntime::FastembedSparsePlaced { .. }
            | LensRuntime::FastembedBgem3Placed { .. }
            | LensRuntime::FastembedRerankerPlaced { .. }
    ) {
        let total = report.total_compute_nodes.unwrap_or_default();
        let cpu = report.cpu_compute_nodes.unwrap_or(u64::MAX);
        let expected_cpu = if placement == Placement::Cpu {
            total
        } else {
            0
        };
        if total == 0 || cpu != expected_cpu {
            return Err(template_error(
                TEMPLATE_INVALID,
                format!(
                    "template lens {} placement={placement:?} persists cpu_nodes={cpu}/{total}",
                    spec.name
                ),
                "re-attest committed node placement and save a new template",
            ));
        }
    }
    Ok(())
}

fn mandatory_execution_runtime(runtime: &LensRuntime) -> Option<&'static str> {
    match runtime {
        LensRuntime::CandleLocal { .. } => Some("candle-local"),
        LensRuntime::FastembedQwen3 { .. } => Some("fastembed-qwen3"),
        LensRuntime::Onnx { .. } => Some("onnx-custom"),
        LensRuntime::OnnxColbert { .. } => Some("onnx-colbert"),
        LensRuntime::FastembedDensePlaced { .. }
        | LensRuntime::FastembedSparsePlaced { .. }
        | LensRuntime::FastembedBgem3Placed { .. }
        | LensRuntime::FastembedRerankerPlaced { .. } => Some("onnx-fastembed-5.16.0-owned"),
        _ => None,
    }
}

fn validate_lenses(template: &SavedPanelTemplate) -> CliResult {
    let mut ids = BTreeSet::new();
    for lens in &template.lenses {
        if !ids.insert(lens.lens_id) {
            return Err(template_error(
                TEMPLATE_INVALID,
                format!("template {} repeats lens {}", template.name, lens.lens_id),
                "remove duplicate lens ids from the template",
            ));
        }
        if let Some(runtime_lens_id) = lens.runtime_lens_id
            && runtime_lens_id != lens.lens_id
        {
            return Err(template_error(
                "CALYX_LENS_IDENTITY_MIGRATION_REQUIRED",
                format!(
                    "template {} stores catalog lens {} and conflicting runtime lens {}",
                    template.name, lens.lens_id, runtime_lens_id
                ),
                "preserve the template bytes and perform an explicit lineage migration before loading it",
            ));
        }
        validate_weight_hash(&lens.weights_sha256)?;
        validate_manifest_hash(&lens.manifest_sha256)?;
        if !lens.counts_toward_a35 {
            return Err(template_error(
                TEMPLATE_INVALID,
                format!("template {} has a non-counting content lens", template.name),
                "store non-content time controls in time_controls, not lenses",
            ));
        }
    }
    Ok(())
}

fn validate_manifest_hash(value: &str) -> CliResult {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(template_error(
        "CALYX_PANEL_TEMPLATE_SCHEMA_MIGRATION_REQUIRED",
        format!("manifest_sha256 must be 64 lowercase hex chars, got {value}"),
        "preserve the old object and save a new schema-v2 template from the authoritative attested catalog",
    ))
}

fn validate_time_controls(template: &SavedPanelTemplate) -> CliResult {
    for control in &template.time_controls {
        if control.counts_toward_a35 {
            return Err(template_error(
                TEMPLATE_INVALID,
                format!("time control {} counts toward A35", control.slot_key),
                "temporal/time capture is a control sidecar and must not count as an embedder",
            ));
        }
    }
    Ok(())
}

fn validate_weight_hash(value: &str) -> CliResult {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(template_error(
        TEMPLATE_INVALID,
        format!("weights_sha256 must be 64 hex chars, got {value}"),
        "rebuild the template from frozen lens manifests",
    ))
}

fn time_control(slot_key: &str, kind: &str, shape: SlotShape) -> TemplateTimeControl {
    TemplateTimeControl {
        slot_key: slot_key.to_string(),
        kind: kind.to_string(),
        shape,
        purpose: "walk_forward_backward_as_of_time_control".to_string(),
        counts_toward_a35: false,
    }
}

fn time_control_id(template: &str, control: &TemplateTimeControl) -> LensId {
    LensId::from_bytes(content_address([
        b"panel-template-time-control-v1".as_slice(),
        template.as_bytes(),
        control.slot_key.as_bytes(),
        control.kind.as_bytes(),
    ]))
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

pub(super) fn id_for_loaded(template: &SavedPanelTemplate) -> CliResult<String> {
    Ok(blake3::hash(&object_bytes(template)?).to_hex().to_string())
}

pub(super) fn object_bytes(template: &SavedPanelTemplate) -> CliResult<Vec<u8>> {
    serde_json::to_vec_pretty(template)
        .map_err(|error| CliError::runtime(format!("serialize template object: {error}")))
}
