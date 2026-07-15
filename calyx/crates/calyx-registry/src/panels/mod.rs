mod defaults;
mod materialize;

use std::collections::BTreeMap;

use calyx_core::{
    Asymmetry, LensId, Modality, Panel, QuantPolicy, Slot, SlotId, SlotKey, SlotShape, SlotState,
    content_address,
};
use serde::{Deserialize, Serialize};

pub use defaults::{
    bio_default, civic_default, code_default, legal_default, media_default, medical_default,
    text_default,
};
pub use materialize::{MaterializedPanelTemplate, materialize_panel_template};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelSlotSpec {
    pub name: String,
    pub runtime: PanelLensRuntime,
    pub output: SlotShape,
    pub modality: Modality,
    pub retrieval_only: bool,
    pub excluded_from_dedup: bool,
    pub required: bool,
    pub asymmetry: Asymmetry,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelLensRuntime {
    Registry { name: String },
    TeiHttp { endpoint: String },
    Algorithmic { lens: AlgorithmicPanelLens },
    ExternalCmd { name: String },
    Placeholder { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmicPanelLens {
    ByteFeatures,
    AstStyle,
    SparseKeywords,
    TemporalRecent,
    TemporalPeriodic,
    TemporalPositional,
    Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelTemplate {
    pub name: String,
    pub slots: Vec<PanelSlotSpec>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstantiatedPanel {
    pub template_name: String,
    pub panel: Panel,
    pub slot_specs: Vec<PanelSlotSpec>,
}

pub fn instantiate_panel(template: &PanelTemplate, created_at: u64) -> InstantiatedPanel {
    let slots = template
        .slots
        .iter()
        .enumerate()
        .map(|(idx, spec)| {
            let slot_id = SlotId::new(idx as u16);
            Slot {
                slot_id,
                slot_key: SlotKey::new(slot_id, spec.name.clone()),
                lens_id: slot_lens_id(&template.name, spec),
                shape: spec.output,
                modality: spec.modality,
                asymmetry: spec.asymmetry,
                quant: QuantPolicy::None,
                resource: Default::default(),
                axis: Some(spec.name.clone()),
                retrieval_only: spec.retrieval_only,
                excluded_from_dedup: spec.excluded_from_dedup,
                bits_about: BTreeMap::new(),
                state: SlotState::Active,
                added_at_panel_version: (idx + 1) as u32,
            }
        })
        .collect::<Vec<_>>();
    InstantiatedPanel {
        template_name: template.name.clone(),
        panel: Panel {
            version: slots.len() as u32,
            slots,
            created_at,
            kernel_ref: None,
            guard_ref: None,
        },
        slot_specs: template.slots.clone(),
    }
}

impl PanelTemplate {
    pub fn temporal_specs(&self) -> impl Iterator<Item = &PanelSlotSpec> {
        self.slots
            .iter()
            .filter(|slot| slot.retrieval_only || slot.excluded_from_dedup)
    }
}

impl PanelSlotSpec {
    pub fn content(
        name: impl Into<String>,
        runtime: PanelLensRuntime,
        output: SlotShape,
        modality: Modality,
    ) -> Self {
        Self {
            name: name.into(),
            runtime,
            output,
            modality,
            retrieval_only: false,
            excluded_from_dedup: false,
            required: true,
            asymmetry: Asymmetry::None,
        }
    }

    pub fn registry(
        name: impl Into<String>,
        registry_name: impl Into<String>,
        output: SlotShape,
        modality: Modality,
    ) -> Self {
        Self::content(
            name,
            PanelLensRuntime::Registry {
                name: registry_name.into(),
            },
            output,
            modality,
        )
    }

    pub fn temporal(
        name: impl Into<String>,
        lens: AlgorithmicPanelLens,
        output: SlotShape,
    ) -> Self {
        Self {
            name: name.into(),
            runtime: PanelLensRuntime::Algorithmic { lens },
            output,
            modality: Modality::Structured,
            retrieval_only: true,
            excluded_from_dedup: true,
            required: false,
            asymmetry: Asymmetry::None,
        }
    }

    pub fn with_asymmetry(mut self, asymmetry: Asymmetry) -> Self {
        self.asymmetry = asymmetry;
        self
    }
}

pub(super) fn slot_lens_id(template: &str, spec: &PanelSlotSpec) -> LensId {
    let spec_text = format!(
        "{template}:{}:{:?}:{:?}:{:?}:{}:{}",
        spec.name,
        spec.runtime,
        spec.output,
        spec.modality,
        spec.retrieval_only,
        spec.excluded_from_dedup
    );
    LensId::from_bytes(content_address([spec_text.as_bytes()]))
}
