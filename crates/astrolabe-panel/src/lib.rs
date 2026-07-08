#![forbid(unsafe_code)]

mod embeddings;
mod lenses;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use astrolabe_domain::{ASTRO_SYMBOL_NON_FINITE, SymbolLabel};
use calyx_core::{
    AbsentReason, Input, Lens, LensId, Modality, SlotId, SlotShape, SlotVector, SparseEntry,
    content_address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use embeddings::{
    NOMIC_EMBED_DIM, NOMIC_TOKEN_COUNT, NOMIC_VECTOR_BLOB_SHA256, StaticEmbeddingInput,
    StaticEmbeddingLens, StaticEmbeddingTable, fixture_static_embedding_input, s18_s20_lenses,
};
pub use lenses::{
    ApiCall, AstProfile, ChannelObservation, ChurnProfileInput, ComplexityMetrics,
    ConfigEnvSurfaceInput, DeterministicEncoderLens, EncoderLensInput, ErrorSurfaceInput,
    GraphPositionInput, IdentifierLexicalInput, LangLabelInput, PathHierarchyInput,
    RECORD_VECTOR_SCALAR_KEYS, RecordVectorInput, RoleFlagsInput, RouteObservation,
    RouteSurfaceInput, StructuralTrigram, TestTopologyInput, TypeSurfaceInput, canonical_route_qn,
    cbm_camel_split_text, cbm_camel_split_tokens, cbm_route_canon_path, encode_slot,
    fixture_encoder_input, fixture_scalar_sidecar, s0_s9_lenses, s10_s17_s21_lenses,
};

/// Crate name reported by Cargo metadata.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// Frozen Astrolabe panel schema identifier.
pub const PANEL_SCHEMA_ID: &str = "astro.panel.v1";
/// First Astrolabe panel version.
pub const DEFAULT_PANEL_VERSION: u32 = 1;
/// Frozen seed registry schema identifier.
pub const ASTRO_SEED_REGISTRY_SCHEMA: &str = "astro.seed_registry.v1";
/// Frozen seed registry artifact kind.
pub const ASTRO_SEED_REGISTRY_ARTIFACT: &str = "astro_frozen_encoder_seed_registry";
/// Frozen seed registry version for the default panel.
pub const ASTRO_SEED_REGISTRY_VERSION: &str = "astro.panel.v1.seeds.v1";
/// Error code returned when a probe observes nondeterministic lens output.
pub const ASTRO_PANEL_NONDETERMINISTIC: &str = "ASTRO_PANEL_NONDETERMINISTIC";
/// Error code returned when a frozen contract is internally inconsistent.
pub const ASTRO_PANEL_CONTRACT_INVALID: &str = "ASTRO_PANEL_CONTRACT_INVALID";
/// Error code returned when a vector violates its frozen slot shape or norm.
pub const ASTRO_PANEL_VECTOR_INVALID: &str = "ASTRO_PANEL_VECTOR_INVALID";
/// Error code returned when the seed registry bytes drift from the frozen table.
pub const ASTRO_PANEL_SEED_REGISTRY_INVALID: &str = "ASTRO_PANEL_SEED_REGISTRY_INVALID";

/// Result type for panel operations.
pub type PanelResult<T> = std::result::Result<T, PanelError>;

/// Error returned by the Astrolabe panel core.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PanelError {
    code: &'static str,
    message: String,
    remediation: String,
}

impl PanelError {
    fn new(code: &'static str, message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            remediation: remediation.into(),
        }
    }

    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable failure message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Suggested operator remediation.
    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

impl fmt::Display for PanelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} Remediation: {}",
            self.code, self.message, self.remediation
        )
    }
}

impl Error for PanelError {}

/// Runtime dtype declared by a frozen lens contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensDType {
    /// Dense/sparse/multi f32 vectors.
    F32,
    /// Quantized int8 vectors or lookup tables.
    I8,
}

impl LensDType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::I8 => "i8",
        }
    }
}

/// Numerical invariant declared by a frozen lens contract.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormPolicy {
    /// Values must be finite; unit length is not required.
    Finite,
    /// Values must be finite and each vector must be unit length.
    Unit {
        /// Absolute tolerance for unit-length validation.
        tolerance: f32,
    },
}

impl NormPolicy {
    /// Unit norm with the Astrolabe v1 default tolerance.
    pub const fn unit() -> Self {
        Self::Unit { tolerance: 1.0e-3 }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Finite => "finite",
            Self::Unit { .. } => "unit",
        }
    }
}

/// Frozen instrument metadata used to content-address and validate a lens.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrozenLensContract {
    /// Stable lens name.
    pub name: String,
    /// SHA-256 of the frozen encoder weights/spec bytes.
    pub weights_sha: [u8; 32],
    /// SHA-256 of the corpus snapshot for commissioned lenses; all-zero-independent hash for v1 defaults.
    pub corpus_hash: [u8; 32],
    /// Declared output shape.
    pub shape: SlotShape,
    /// Accepted input modality.
    pub modality: Modality,
    /// Runtime dtype.
    pub dtype: LensDType,
    /// Numerical norm policy.
    pub norm: NormPolicy,
}

impl FrozenLensContract {
    /// Creates a frozen lens contract.
    pub fn new(
        name: impl Into<String>,
        weights_sha: [u8; 32],
        corpus_hash: [u8; 32],
        shape: SlotShape,
        modality: Modality,
        dtype: LensDType,
        norm: NormPolicy,
    ) -> Self {
        Self {
            name: name.into(),
            weights_sha,
            corpus_hash,
            shape,
            modality,
            dtype,
            norm,
        }
    }

    /// Creates the default frozen contract for a v1 panel slot.
    pub fn for_slot(slot: &PanelSlotSpec) -> Self {
        let shape = shape_fingerprint(slot.shape);
        let weights_sha = if matches!(slot.slot, 18 | 19 | 20 | 22) {
            NOMIC_VECTOR_BLOB_SHA256
        } else {
            sha256_digest(&[
                PANEL_SCHEMA_ID.as_bytes(),
                slot.key.as_bytes(),
                shape.as_bytes(),
                b"default-encoder-v1",
            ])
        };
        let corpus_hash = sha256_digest(&[b"corpus-independent"]);
        Self::new(
            slot.key,
            weights_sha,
            corpus_hash,
            slot.shape,
            slot.modality,
            LensDType::F32,
            slot.norm,
        )
    }

    /// Stable content-addressed id for this contract.
    pub fn lens_id(&self) -> LensId {
        let shape = shape_fingerprint(self.shape);
        let modality = modality_fingerprint(self.modality);
        let dtype = self.dtype.as_str();
        let norm = self.norm.as_str();
        LensId::from_bytes(content_address([
            PANEL_SCHEMA_ID.as_bytes(),
            self.name.as_bytes(),
            self.weights_sha.as_slice(),
            self.corpus_hash.as_slice(),
            shape.as_bytes(),
            modality.as_bytes(),
            dtype.as_bytes(),
            norm.as_bytes(),
        ]))
    }

    /// Verifies id, shape, modality, probe determinism, and vector invariants.
    pub fn verify_determinism_probe(
        &self,
        lens: &dyn Lens,
        probe: &Input,
    ) -> PanelResult<DeterminismProof> {
        let expected = self.lens_id();
        if lens.id() != expected {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "lens id {} does not match frozen contract {expected}",
                    lens.id()
                ),
                "Register the runtime built from the exact frozen lens contract.",
            ));
        }
        if lens.shape() != self.shape {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "lens {} shape {:?} != {:?}",
                    lens.id(),
                    lens.shape(),
                    self.shape
                ),
                "Rebuild the lens runtime with the frozen output shape.",
            ));
        }
        if lens.modality() != self.modality || probe.modality != self.modality {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "lens/probe modality mismatch: lens={:?} probe={:?} contract={:?}",
                    lens.modality(),
                    probe.modality,
                    self.modality
                ),
                "Use a probe input with the same modality declared by the frozen contract.",
            ));
        }

        let first = lens.measure(probe).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("first determinism probe failed: {err}"),
                "Fix the lens runtime before registering it.",
            )
        })?;
        let second = lens.measure(probe).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("second determinism probe failed: {err}"),
                "Fix the lens runtime before registering it.",
            )
        })?;
        validate_vector(self, lens.id(), &first)?;
        validate_vector(self, lens.id(), &second)?;

        let first_bytes = serde_json::to_vec(&first).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("serialize first probe vector failed: {err}"),
                "Use a serializable Calyx SlotVector payload.",
            )
        })?;
        let second_bytes = serde_json::to_vec(&second).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("serialize second probe vector failed: {err}"),
                "Use a serializable Calyx SlotVector payload.",
            )
        })?;
        if first_bytes != second_bytes {
            return Err(PanelError::new(
                ASTRO_PANEL_NONDETERMINISTIC,
                format!("lens {} changed output for deterministic probe", lens.id()),
                "Freeze all seeds, clocks, model versions, and input ordering before registration.",
            ));
        }

        Ok(DeterminismProof {
            lens_id: lens.id(),
            probe_sha256: sha256_digest(&[probe.bytes.as_slice()]),
            output_sha256: sha256_digest(&[first_bytes.as_slice()]),
        })
    }
}

/// Byte evidence retained when a frozen lens passes registration probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeterminismProof {
    /// Registered lens id.
    pub lens_id: LensId,
    /// SHA-256 of the probe bytes.
    pub probe_sha256: [u8; 32],
    /// SHA-256 of the byte-exact serialized probe output.
    pub output_sha256: [u8; 32],
}

/// Minimal frozen registration table for Astrolabe panel lenses.
#[derive(Debug, Default)]
pub struct PanelLensRegistry {
    contracts: BTreeMap<LensId, FrozenLensContract>,
    proofs: BTreeMap<LensId, DeterminismProof>,
}

impl PanelLensRegistry {
    /// Registers a runtime lens only after contract and determinism probes pass.
    pub fn register(
        &mut self,
        lens: &dyn Lens,
        contract: FrozenLensContract,
        probe: &Input,
    ) -> PanelResult<LensId> {
        let proof = contract.verify_determinism_probe(lens, probe)?;
        let id = contract.lens_id();
        self.contracts.insert(id, contract);
        self.proofs.insert(id, proof);
        Ok(id)
    }

    /// Returns a registered contract by lens id.
    pub fn contract(&self, lens_id: LensId) -> Option<&FrozenLensContract> {
        self.contracts.get(&lens_id)
    }

    /// Returns determinism proof by lens id.
    pub fn determinism_proof(&self, lens_id: LensId) -> Option<DeterminismProof> {
        self.proofs.get(&lens_id).copied()
    }
}

/// One slot in the Astrolabe v1 panel roster.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PanelSlotSpec {
    /// Stable slot number.
    pub slot: u16,
    /// Stable slot key.
    pub key: &'static str,
    /// Calyx vector shape.
    pub shape: SlotShape,
    /// Input modality accepted by this slot.
    pub modality: Modality,
    /// Declared norm policy.
    pub norm: NormPolicy,
    /// Retrieval-only slots are not included in dedup identity.
    pub retrieval_only: bool,
    /// Slots excluded from dedup do not affect content identity.
    pub excluded_from_dedup: bool,
}

impl PanelSlotSpec {
    /// Returns the Calyx slot id.
    pub const fn slot_id(self) -> SlotId {
        SlotId::new(self.slot)
    }
}

const fn slot(
    slot: u16,
    key: &'static str,
    shape: SlotShape,
    modality: Modality,
    norm: NormPolicy,
) -> PanelSlotSpec {
    PanelSlotSpec {
        slot,
        key,
        shape,
        modality,
        norm,
        retrieval_only: false,
        excluded_from_dedup: false,
    }
}

const fn retrieval_slot(
    slot: u16,
    key: &'static str,
    shape: SlotShape,
    modality: Modality,
    norm: NormPolicy,
) -> PanelSlotSpec {
    PanelSlotSpec {
        slot,
        key,
        shape,
        modality,
        norm,
        retrieval_only: true,
        excluded_from_dedup: true,
    }
}

/// Frozen v1 slot roster from blueprint `05_LENS_PANEL.md` section 2.
pub const PANEL_V1_SLOTS: &[PanelSlotSpec] = &[
    slot(
        0,
        "ast_profile",
        SlotShape::Dense(25),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        1,
        "struct_trigrams",
        SlotShape::Sparse(65_536),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        2,
        "complexity_log",
        SlotShape::Dense(8),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        3,
        "complexity_ple",
        SlotShape::Dense(56),
        Modality::Code,
        NormPolicy::unit(),
    ),
    slot(
        4,
        "api_callees",
        SlotShape::Sparse(262_144),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        5,
        "type_surface",
        SlotShape::Sparse(65_536),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        6,
        "decorators",
        SlotShape::Sparse(4_096),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        7,
        "identifier_lexical",
        SlotShape::Sparse(131_072),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        8,
        "graph_position",
        SlotShape::Dense(16),
        Modality::Structured,
        NormPolicy::Finite,
    ),
    slot(
        9,
        "path_hierarchy",
        SlotShape::Sparse(16_384),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        10,
        "churn_profile",
        SlotShape::Dense(8),
        Modality::Structured,
        NormPolicy::Finite,
    ),
    retrieval_slot(
        11,
        "recency",
        SlotShape::Dense(1),
        Modality::Structured,
        NormPolicy::Finite,
    ),
    slot(
        12,
        "role_flags",
        SlotShape::Dense(12),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        13,
        "lang_label",
        SlotShape::Sparse(256),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        14,
        "test_topology",
        SlotShape::Dense(4),
        Modality::Structured,
        NormPolicy::Finite,
    ),
    slot(
        15,
        "error_surface",
        SlotShape::Sparse(4_096),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        16,
        "config_env_surface",
        SlotShape::Sparse(4_096),
        Modality::Code,
        NormPolicy::Finite,
    ),
    slot(
        17,
        "route_surface",
        SlotShape::Sparse(4_096),
        Modality::Structured,
        NormPolicy::Finite,
    ),
    slot(
        18,
        "code_semantic",
        SlotShape::Dense(768),
        Modality::Code,
        NormPolicy::unit(),
    ),
    slot(
        19,
        "doc_semantic",
        SlotShape::Dense(768),
        Modality::Text,
        NormPolicy::unit(),
    ),
    slot(
        20,
        "name_semantic",
        SlotShape::Dense(768),
        Modality::Code,
        NormPolicy::unit(),
    ),
    slot(
        21,
        "record_vec",
        SlotShape::Dense(24),
        Modality::Structured,
        NormPolicy::unit(),
    ),
    slot(
        22,
        "token_multi",
        SlotShape::Multi { token_dim: 128 },
        Modality::Code,
        NormPolicy::Finite,
    ),
];

/// Returns the frozen v1 slot roster.
pub fn default_panel_slots() -> &'static [PanelSlotSpec] {
    PANEL_V1_SLOTS
}

/// Returns a slot specification by id.
pub fn slot_spec(slot_id: SlotId) -> Option<&'static PanelSlotSpec> {
    PANEL_V1_SLOTS.iter().find(|slot| slot.slot_id() == slot_id)
}

/// Returns the default frozen contracts for every v1 slot.
pub fn default_contracts() -> Vec<FrozenLensContract> {
    PANEL_V1_SLOTS
        .iter()
        .map(FrozenLensContract::for_slot)
        .collect()
}

/// Returns slots that participate in constellation identity/dedup.
pub fn identity_slot_ids() -> BTreeSet<SlotId> {
    PANEL_V1_SLOTS
        .iter()
        .filter(|slot| !slot.excluded_from_dedup)
        .map(|slot| slot.slot_id())
        .collect()
}

/// Label class used by blueprint `05_LENS_PANEL.md` section 3.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelClass {
    /// Function, method, and macro atoms.
    Callable,
    /// Type/class-like declaration atoms.
    TypeDeclaration,
    /// Field, variable, constant, property, and enum-member atoms.
    Value,
    /// Module/file atoms.
    ModuleFile,
    /// Route/channel atoms.
    RouteChannel,
    /// Structured resource atoms.
    StructuredResource,
    /// Documentation section atoms.
    Section,
    /// Project/branch/folder metadata that does not receive panel measurements.
    Structural,
}

/// Maps a domain label to the panel applicability class.
pub const fn label_class(label: SymbolLabel) -> LabelClass {
    match label {
        SymbolLabel::Function | SymbolLabel::Method | SymbolLabel::Macro => LabelClass::Callable,
        SymbolLabel::Class
        | SymbolLabel::Struct
        | SymbolLabel::Interface
        | SymbolLabel::Enum
        | SymbolLabel::Trait
        | SymbolLabel::Type
        | SymbolLabel::TypeAlias
        | SymbolLabel::Namespace
        | SymbolLabel::Union
        | SymbolLabel::Protocol
        | SymbolLabel::Mixin
        | SymbolLabel::Object
        | SymbolLabel::Impl
        | SymbolLabel::Annotation => LabelClass::TypeDeclaration,
        SymbolLabel::Field
        | SymbolLabel::Variable
        | SymbolLabel::Constant
        | SymbolLabel::Property
        | SymbolLabel::EnumMember => LabelClass::Value,
        SymbolLabel::Module | SymbolLabel::File => LabelClass::ModuleFile,
        SymbolLabel::Route | SymbolLabel::Channel => LabelClass::RouteChannel,
        SymbolLabel::Resource | SymbolLabel::Chart | SymbolLabel::Package | SymbolLabel::EnvVar => {
            LabelClass::StructuredResource
        }
        SymbolLabel::Section => LabelClass::Section,
        SymbolLabel::Project | SymbolLabel::Branch | SymbolLabel::Folder => LabelClass::Structural,
    }
}

/// Returns true when a slot applies to a label.
pub fn slot_applies(label: SymbolLabel, slot_id: SlotId) -> bool {
    applicable_slot_ids_for_class(label_class(label)).contains(&slot_id)
}

/// Returns the applicable slot ids for a domain label.
pub fn applicable_slot_ids(label: SymbolLabel) -> BTreeSet<SlotId> {
    applicable_slot_ids_for_class(label_class(label))
}

/// Returns the applicable slot ids for a label class.
pub fn applicable_slot_ids_for_class(class: LabelClass) -> BTreeSet<SlotId> {
    match class {
        LabelClass::Callable => slot_set(0..=22),
        LabelClass::TypeDeclaration => slot_set(0..=21),
        LabelClass::Value => slot_set([5, 6, 7, 9, 10, 11, 12, 13, 18, 20, 21]),
        LabelClass::ModuleFile => slot_set([1, 7, 8, 9, 10, 11, 12, 13, 16, 18, 21]),
        LabelClass::RouteChannel => slot_set([9, 11, 12, 13, 17]),
        LabelClass::StructuredResource => slot_set([7, 9, 12, 13, 16, 17, 21]),
        LabelClass::Section => slot_set([7, 9, 11, 13, 19]),
        LabelClass::Structural => BTreeSet::new(),
    }
}

fn slot_set<I>(ids: I) -> BTreeSet<SlotId>
where
    I: IntoIterator<Item = u16>,
{
    ids.into_iter().map(SlotId::new).collect()
}

/// Input passed through the panel driver.
#[derive(Clone, Debug, PartialEq)]
pub struct PanelInput {
    /// Domain label for the symbol being measured.
    pub label: SymbolLabel,
    /// Slots with source input available to the runtime.
    pub available_slots: BTreeSet<SlotId>,
    /// Stable source bytes for deterministic fixture/runtime probes.
    pub source_bytes: Vec<u8>,
    /// Exact scalar measurements preserved beside the vector panel.
    pub scalars: BTreeMap<String, f64>,
}

impl PanelInput {
    /// Builds an input where all v1 slot sources are available.
    pub fn fixture(label: SymbolLabel) -> Self {
        Self {
            label,
            available_slots: PANEL_V1_SLOTS.iter().map(|slot| slot.slot_id()).collect(),
            source_bytes: label.as_str().as_bytes().to_vec(),
            scalars: BTreeMap::new(),
        }
    }

    /// Builds an input with a caller-supplied available-slot set.
    pub fn with_available_slots<I>(label: SymbolLabel, available_slots: I) -> Self
    where
        I: IntoIterator<Item = SlotId>,
    {
        Self {
            label,
            available_slots: available_slots.into_iter().collect(),
            source_bytes: label.as_str().as_bytes().to_vec(),
            scalars: BTreeMap::new(),
        }
    }

    /// Attaches exact scalar measurements to be preserved beside emitted vectors.
    pub fn with_scalars(mut self, scalars: BTreeMap<String, f64>) -> Self {
        self.scalars = scalars;
        self
    }
}

/// Runtime implementation for producing one slot vector.
pub trait SlotRuntime {
    /// Measures an applicable, source-available slot.
    fn measure_slot(&self, slot: &PanelSlotSpec, input: &PanelInput) -> PanelResult<SlotVector>;
}

/// Deterministic runtime used by FSV tests and examples before real lenses land.
#[derive(Debug, Default)]
pub struct FixtureSlotRuntime;

impl SlotRuntime for FixtureSlotRuntime {
    fn measure_slot(&self, slot: &PanelSlotSpec, input: &PanelInput) -> PanelResult<SlotVector> {
        Ok(fixture_vector(
            slot.shape,
            slot.slot,
            input.source_bytes.len(),
        ))
    }
}

/// A full panel measurement result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PanelReadout {
    /// Frozen panel schema id.
    pub schema_id: String,
    /// Panel version that produced this readout.
    pub panel_version: u32,
    /// Symbol label measured by the panel.
    pub label: SymbolLabel,
    /// One vector or explicit absence for every v1 slot.
    pub slots: BTreeMap<SlotId, SlotVector>,
    /// Exact scalar measurements from the source symbol.
    pub scalars: BTreeMap<String, f64>,
}

/// Default Astrolabe panel driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PanelDriver {
    version: u32,
}

impl Default for PanelDriver {
    fn default() -> Self {
        Self {
            version: DEFAULT_PANEL_VERSION,
        }
    }
}

impl PanelDriver {
    /// Creates a driver for a non-zero panel version.
    pub fn new(version: u32) -> PanelResult<Self> {
        if version == 0 {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "panel version 0 cannot measure Astrolabe slots",
                "Commission a non-zero panel version before measurement.",
            ));
        }
        Ok(Self { version })
    }

    /// Returns the driver panel version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Measures all v1 slots, enforcing applicability before runtime dispatch.
    pub fn measure<R>(&self, input: &PanelInput, runtime: &R) -> PanelResult<PanelReadout>
    where
        R: SlotRuntime,
    {
        validate_scalar_sidecar(&input.scalars)?;
        let applicable = applicable_slot_ids(input.label);
        let mut slots = BTreeMap::new();
        for slot in PANEL_V1_SLOTS {
            let slot_id = slot.slot_id();
            let vector = if !applicable.contains(&slot_id) {
                SlotVector::Absent {
                    reason: AbsentReason::NotApplicable,
                }
            } else if !input.available_slots.contains(&slot_id) {
                SlotVector::Absent {
                    reason: AbsentReason::LensUnavailable,
                }
            } else {
                let vector = runtime.measure_slot(slot, input)?;
                validate_slot_shape(*slot, &vector)?;
                vector
            };
            slots.insert(slot_id, vector);
        }
        Ok(PanelReadout {
            schema_id: PANEL_SCHEMA_ID.to_string(),
            panel_version: self.version,
            label: input.label,
            slots,
            scalars: input.scalars.clone(),
        })
    }
}

/// One seed-bearing frozen encoder entry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrozenSeedSpec {
    /// Panel slot id.
    pub slot: u16,
    /// Lens key.
    pub lens_key: &'static str,
    /// Hex seed value.
    pub seed_hex: &'static str,
    /// Encoder dimension.
    pub dim: u32,
    /// Frozen scale parameter.
    pub sigma: f64,
    /// Source field covered by this seed.
    pub source_field: &'static str,
    /// Frozen transform.
    pub transform: &'static str,
    /// Reason this seed exists.
    pub purpose: &'static str,
}

impl FrozenSeedSpec {
    fn entry(self) -> SeedRegistryEntry {
        SeedRegistryEntry {
            slot: self.slot,
            lens_key: self.lens_key.to_string(),
            seed_hex: self.seed_hex.to_string(),
            dim: self.dim,
            sigma: self.sigma,
            source_field: self.source_field.to_string(),
            transform: self.transform.to_string(),
            purpose: self.purpose.to_string(),
        }
    }
}

/// Serializable seed registry entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SeedRegistryEntry {
    /// Panel slot id.
    pub slot: u16,
    /// Lens key.
    pub lens_key: String,
    /// Hex seed value.
    pub seed_hex: String,
    /// Encoder dimension.
    pub dim: u32,
    /// Frozen scale parameter.
    pub sigma: f64,
    /// Source field covered by this seed.
    pub source_field: String,
    /// Frozen transform.
    pub transform: String,
    /// Reason this seed exists.
    pub purpose: String,
}

/// Serializable seed registry artifact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SeedRegistryArtifact {
    /// Registry schema id.
    pub schema_id: String,
    /// Artifact kind.
    pub artifact_kind: String,
    /// Registry version.
    pub registry_version: String,
    /// Frozen entries.
    pub entries: Vec<SeedRegistryEntry>,
}

/// Seed registry validation summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SeedRegistryValidation {
    /// Registry version.
    pub registry_version: String,
    /// Number of frozen entries.
    pub entry_count: usize,
    /// Number of distinct seed values.
    pub seed_count: usize,
}

/// Frozen v1 seed-bearing encoder table.
pub const ASTRO_SEED_SPECS: &[FrozenSeedSpec] = &[
    seed(
        1,
        "struct_trigrams",
        "0xA570000000000001",
        65_536,
        1.0,
        "ast_trigrams",
        "signed_feature_hash",
        "structural AST trigram hashing",
    ),
    seed(
        3,
        "complexity_ple",
        "0xA570000000000003",
        56,
        1.0,
        "complexity_metrics",
        "piecewise_linear_thermometer",
        "frozen complexity thermometer edges",
    ),
    seed(
        4,
        "api_callees",
        "0xA570000000000004",
        262_144,
        1.0,
        "resolved_callees",
        "hashed_multihot_log_count",
        "callee set hashing",
    ),
    seed(
        5,
        "type_surface",
        "0xA570000000000005",
        65_536,
        1.0,
        "type_refs",
        "hashed_set",
        "type surface hashing",
    ),
    seed(
        6,
        "decorators",
        "0xA570000000000006",
        4_096,
        1.0,
        "decorators",
        "hashed_set",
        "decorator and annotation hashing",
    ),
    seed(
        7,
        "identifier_lexical",
        "0xA570000000000007",
        131_072,
        1.0,
        "identifier_tokens",
        "tf_hash",
        "identifier lexical hashing",
    ),
    seed(
        9,
        "path_hierarchy",
        "0xA570000000000009",
        16_384,
        1.0,
        "file_path",
        "ancestor_prefix_hash",
        "path hierarchy hashing",
    ),
    seed(
        13,
        "lang_label",
        "0xA57000000000000D",
        256,
        1.0,
        "language_label",
        "hashed_one_hot",
        "language and label hashing",
    ),
    seed(
        15,
        "error_surface",
        "0xA57000000000000F",
        4_096,
        1.0,
        "throws",
        "hashed_set",
        "exception surface hashing",
    ),
    seed(
        16,
        "config_env_surface",
        "0xA570000000000010",
        4_096,
        1.0,
        "env_and_config_keys",
        "hashed_set",
        "environment/config surface hashing",
    ),
    seed(
        17,
        "route_surface",
        "0xA570000000000011",
        4_096,
        1.0,
        "routes_and_channels",
        "canonical_path_hash",
        "route and channel surface hashing",
    ),
    seed(
        18,
        "code_semantic",
        "0xA570000000000012",
        768,
        0.125,
        "body_tokens",
        "nomic_static_sum",
        "code semantic random-index fallback",
    ),
    seed(
        19,
        "doc_semantic",
        "0xA570000000000013",
        768,
        0.125,
        "docstring_comments",
        "nomic_static_sum",
        "documentation semantic random-index fallback",
    ),
    seed(
        20,
        "name_semantic",
        "0xA570000000000014",
        768,
        0.125,
        "identifier_name",
        "nomic_static_sum",
        "name semantic random-index fallback",
    ),
    seed(
        22,
        "token_multi",
        "0xA570000000000016",
        128,
        0.125,
        "body_tokens",
        "random_projection_768_to_128",
        "late-interaction token projection",
    ),
];

#[allow(clippy::too_many_arguments)]
const fn seed(
    slot: u16,
    lens_key: &'static str,
    seed_hex: &'static str,
    dim: u32,
    sigma: f64,
    source_field: &'static str,
    transform: &'static str,
    purpose: &'static str,
) -> FrozenSeedSpec {
    FrozenSeedSpec {
        slot,
        lens_key,
        seed_hex,
        dim,
        sigma,
        source_field,
        transform,
        purpose,
    }
}

/// Returns the default seed registry artifact.
pub fn default_seed_registry_artifact() -> SeedRegistryArtifact {
    SeedRegistryArtifact {
        schema_id: ASTRO_SEED_REGISTRY_SCHEMA.to_string(),
        artifact_kind: ASTRO_SEED_REGISTRY_ARTIFACT.to_string(),
        registry_version: ASTRO_SEED_REGISTRY_VERSION.to_string(),
        entries: ASTRO_SEED_SPECS.iter().map(|spec| spec.entry()).collect(),
    }
}

/// Returns one frozen seed spec by lens key.
pub fn seed_spec_for_lens(lens_key: &str) -> Option<&'static FrozenSeedSpec> {
    ASTRO_SEED_SPECS
        .iter()
        .find(|spec| spec.lens_key == lens_key)
}

/// Validates the seed registry artifact against the frozen v1 slot table.
pub fn validate_seed_registry_artifact(
    registry: &SeedRegistryArtifact,
) -> PanelResult<SeedRegistryValidation> {
    if registry.schema_id != ASTRO_SEED_REGISTRY_SCHEMA
        || registry.artifact_kind != ASTRO_SEED_REGISTRY_ARTIFACT
        || registry.registry_version != ASTRO_SEED_REGISTRY_VERSION
    {
        return Err(seed_error(
            "unexpected seed registry schema, artifact kind, or version",
        ));
    }
    let mut keys = BTreeSet::new();
    let mut seeds = BTreeSet::new();
    for entry in &registry.entries {
        validate_seed_entry(entry)?;
        if !keys.insert(entry.lens_key.as_str()) {
            return Err(seed_error(format!(
                "duplicate seed registry lens_key {}",
                entry.lens_key
            )));
        }
        if !seeds.insert(entry.seed_hex.as_str()) {
            return Err(seed_error(format!(
                "duplicate seed registry seed {}",
                entry.seed_hex
            )));
        }
        let Some(spec) = seed_spec_for_lens(&entry.lens_key) else {
            return Err(seed_error(format!(
                "seed entry {} is not in the frozen v1 registry",
                entry.lens_key
            )));
        };
        if entry != &spec.entry() {
            return Err(seed_error(format!(
                "seed entry {} drifted from the frozen v1 table",
                entry.lens_key
            )));
        }
        let Some(slot) = slot_spec(SlotId::new(entry.slot)) else {
            return Err(seed_error(format!(
                "seed entry {} points at unknown slot {}",
                entry.lens_key, entry.slot
            )));
        };
        if shape_dim(slot.shape) != entry.dim {
            return Err(seed_error(format!(
                "seed entry {} dim {} does not match slot shape {:?}",
                entry.lens_key, entry.dim, slot.shape
            )));
        }
    }
    for spec in ASTRO_SEED_SPECS {
        if !keys.contains(spec.lens_key) {
            return Err(seed_error(format!(
                "required seed entry {} missing",
                spec.lens_key
            )));
        }
    }
    Ok(SeedRegistryValidation {
        registry_version: registry.registry_version.clone(),
        entry_count: registry.entries.len(),
        seed_count: seeds.len(),
    })
}

fn validate_seed_entry(entry: &SeedRegistryEntry) -> PanelResult<()> {
    if entry.lens_key.trim().is_empty()
        || entry.seed_hex.trim().is_empty()
        || entry.source_field.trim().is_empty()
        || entry.transform.trim().is_empty()
        || entry.purpose.trim().is_empty()
    {
        return Err(seed_error(
            "seed entries require lens_key, seed_hex, source_field, transform, and purpose",
        ));
    }
    if !entry.seed_hex.starts_with("0x") || entry.seed_hex.len() != 18 {
        return Err(seed_error(format!(
            "seed entry {} has invalid seed_hex {}",
            entry.lens_key, entry.seed_hex
        )));
    }
    if entry.dim == 0 || !entry.sigma.is_finite() || entry.sigma <= 0.0 {
        return Err(seed_error(format!(
            "seed entry {} has invalid dim={} sigma={}",
            entry.lens_key, entry.dim, entry.sigma
        )));
    }
    Ok(())
}

fn seed_error(message: impl Into<String>) -> PanelError {
    PanelError::new(
        ASTRO_PANEL_SEED_REGISTRY_INVALID,
        message,
        "Regenerate the seed registry from the frozen ASTRO_SEED_SPECS table.",
    )
}

/// Backfill hook emitted for a panel version bump.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackfillHook {
    /// Slot affected by the encoder change.
    pub slot_id: SlotId,
    /// Previous frozen lens id.
    pub previous_lens_id: LensId,
    /// New frozen lens id.
    pub new_lens_id: LensId,
    /// Previous panel version.
    pub from_panel_version: u32,
    /// New panel version.
    pub to_panel_version: u32,
    /// Hook kind for Calyx backfill integration.
    pub kind: String,
}

/// Planned panel version bump for an encoder change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncoderChangePlan {
    /// New panel version.
    pub panel_version: u32,
    /// New lens id.
    pub new_lens_id: LensId,
    /// Lazy backfill hooks.
    pub backfill_hooks: Vec<BackfillHook>,
}

/// Plans encoder replacement without mutating the existing contract in place.
pub fn plan_encoder_change(
    slot_id: SlotId,
    current_panel_version: u32,
    previous: &FrozenLensContract,
    next: &FrozenLensContract,
) -> PanelResult<EncoderChangePlan> {
    if current_panel_version == 0 {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            "current panel version must be non-zero before an encoder change",
            "Commission panel v1 before applying encoder change discipline.",
        ));
    }
    let previous_lens_id = previous.lens_id();
    let new_lens_id = next.lens_id();
    if previous_lens_id == new_lens_id {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            "encoder change did not produce a new frozen lens id",
            "Change the frozen contract and bump the panel version; never mutate in place.",
        ));
    }
    let panel_version = current_panel_version.checked_add(1).ok_or_else(|| {
        PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            "panel version overflow during encoder change",
            "Retire the exhausted panel lineage before adding lenses.",
        )
    })?;
    Ok(EncoderChangePlan {
        panel_version,
        new_lens_id,
        backfill_hooks: vec![BackfillHook {
            slot_id,
            previous_lens_id,
            new_lens_id,
            from_panel_version: current_panel_version,
            to_panel_version: panel_version,
            kind: "lazy_backfill".to_string(),
        }],
    })
}

/// Returns the parent system this crate currently binds against.
pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

/// Computes a length-delimited SHA-256 digest for frozen contract fields.
pub fn sha256_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn validate_vector(
    contract: &FrozenLensContract,
    lens_id: LensId,
    vector: &SlotVector,
) -> PanelResult<()> {
    if vector.is_absent() {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("lens {lens_id} emitted an absent vector for a registration probe"),
            "Use explicit Absent only for unavailable runtime paths, not registration probes.",
        ));
    }
    validate_slot_shape(
        PanelSlotSpec {
            slot: 0,
            key: "registration",
            shape: contract.shape,
            modality: contract.modality,
            norm: contract.norm,
            retrieval_only: false,
            excluded_from_dedup: false,
        },
        vector,
    )?;
    if let NormPolicy::Unit { tolerance } = contract.norm {
        let norm = vector_norm(vector).ok_or_else(|| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("lens {lens_id} emitted absent vector for a unit-norm contract"),
                "Use explicit Absent only for unavailable runtime paths, not registration probes.",
            )
        })?;
        if (norm - 1.0).abs() > tolerance {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("lens {lens_id} norm {norm:.6} outside unit tolerance {tolerance}"),
                "Normalize the emitted vector or change the frozen contract norm policy.",
            ));
        }
    }
    Ok(())
}

fn validate_slot_shape(slot: PanelSlotSpec, vector: &SlotVector) -> PanelResult<()> {
    vector.validate_schema().map_err(|err| {
        PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("slot {} vector schema failed: {err}", slot.key),
            "Emit a valid Calyx SlotVector for the frozen slot shape.",
        )
    })?;
    match (slot.shape, vector) {
        (SlotShape::Dense(expected), SlotVector::Dense { dim, .. }) if expected == *dim => Ok(()),
        (SlotShape::Sparse(expected), SlotVector::Sparse { dim, .. }) if expected == *dim => Ok(()),
        (
            SlotShape::Multi { token_dim },
            SlotVector::Multi {
                token_dim: actual, ..
            },
        ) if token_dim == *actual => Ok(()),
        (_, SlotVector::Absent { .. }) => Ok(()),
        _ => Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!(
                "slot {} expected {:?}, got {:?}",
                slot.key, slot.shape, vector
            ),
            "Emit the vector shape declared by the frozen slot spec.",
        )),
    }
}

fn validate_scalar_sidecar(scalars: &BTreeMap<String, f64>) -> PanelResult<()> {
    for (key, value) in scalars {
        if key.is_empty() {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                "scalar sidecar key must not be empty",
                "Preserve scalar fields under stable non-empty keys.",
            ));
        }
        if !value.is_finite() {
            return Err(PanelError::new(
                ASTRO_SYMBOL_NON_FINITE,
                format!("scalar sidecar {key} is non-finite"),
                "Drop or repair non-finite scalar values before panel measurement.",
            ));
        }
    }
    Ok(())
}

fn vector_norm(vector: &SlotVector) -> Option<f32> {
    let sum = match vector {
        SlotVector::Dense { data, .. } => data.iter().map(|value| value * value).sum::<f32>(),
        SlotVector::Sparse { entries, .. } => entries
            .iter()
            .map(|entry| entry.val * entry.val)
            .sum::<f32>(),
        SlotVector::Multi { tokens, .. } => tokens
            .iter()
            .flatten()
            .map(|value| value * value)
            .sum::<f32>(),
        SlotVector::Absent { .. } => return None,
    };
    Some(sum.sqrt())
}

fn fixture_vector(shape: SlotShape, slot: u16, salt: usize) -> SlotVector {
    let value = 1.0 + f32::from(slot) / 100.0 + salt as f32 / 10_000.0;
    match shape {
        SlotShape::Dense(dim) => SlotVector::Dense {
            dim,
            data: vec![value; dim as usize],
        },
        SlotShape::Sparse(dim) => SlotVector::Sparse {
            dim,
            entries: vec![SparseEntry {
                idx: u32::from(slot) % dim,
                val: value,
            }],
        },
        SlotShape::Multi { token_dim } => SlotVector::Multi {
            token_dim,
            tokens: vec![vec![value; token_dim as usize]],
        },
    }
}

fn shape_dim(shape: SlotShape) -> u32 {
    match shape {
        SlotShape::Dense(dim) | SlotShape::Sparse(dim) => dim,
        SlotShape::Multi { token_dim } => token_dim,
    }
}

fn shape_fingerprint(shape: SlotShape) -> String {
    match shape {
        SlotShape::Dense(dim) => format!("dense:{dim}"),
        SlotShape::Sparse(dim) => format!("sparse:{dim}"),
        SlotShape::Multi { token_dim } => format!("multi:{token_dim}"),
    }
}

fn modality_fingerprint(modality: Modality) -> &'static str {
    match modality {
        Modality::Text => "text",
        Modality::Code => "code",
        Modality::Image => "image",
        Modality::Audio => "audio",
        Modality::Video => "video",
        Modality::Protein => "protein",
        Modality::Dna => "dna",
        Modality::Molecule => "molecule",
        Modality::Structured => "structured",
        Modality::Mixed => "mixed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use proptest::prelude::*;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn contract_lens_id_is_stable_and_all_fields_participate() {
        let base = FrozenLensContract::for_slot(&PANEL_V1_SLOTS[0]);
        let same = FrozenLensContract::for_slot(&PANEL_V1_SLOTS[0]);
        assert_eq!(base.lens_id(), same.lens_id());

        let mut changed = Vec::new();
        let mut name = base.clone();
        name.name.push_str("-v2");
        changed.push(name);
        let mut weights = base.clone();
        weights.weights_sha[0] ^= 0xff;
        changed.push(weights);
        let mut corpus = base.clone();
        corpus.corpus_hash[0] ^= 0xff;
        changed.push(corpus);
        let mut shape = base.clone();
        shape.shape = SlotShape::Dense(26);
        changed.push(shape);
        let mut modality = base.clone();
        modality.modality = Modality::Text;
        changed.push(modality);
        let mut dtype = base.clone();
        dtype.dtype = LensDType::I8;
        changed.push(dtype);
        let mut norm = base.clone();
        norm.norm = NormPolicy::unit();
        changed.push(norm);

        for contract in changed {
            assert_ne!(base.lens_id(), contract.lens_id());
        }
    }

    #[test]
    fn deterministic_registration_is_idempotent_and_nondeterminism_is_refused() {
        let contract = FrozenLensContract::new(
            "test_dense",
            sha256_digest(&[b"test-dense"]),
            sha256_digest(&[b"corpus-independent"]),
            SlotShape::Dense(2),
            Modality::Code,
            LensDType::F32,
            NormPolicy::Finite,
        );
        let probe = Input::new(Modality::Code, b"probe");
        let deterministic = DeterministicLens::new(contract.clone());
        let mut registry = PanelLensRegistry::default();

        let first = registry
            .register(&deterministic, contract.clone(), &probe)
            .expect("first registration");
        let second = registry
            .register(&deterministic, contract.clone(), &probe)
            .expect("second registration");
        assert_eq!(first, second);
        assert!(registry.determinism_proof(first).is_some());

        let nondeterministic = NondeterministicLens::new(contract.clone());
        let err = contract
            .verify_determinism_probe(&nondeterministic, &probe)
            .expect_err("nondeterministic lens must be refused");
        assert_eq!(err.code(), ASTRO_PANEL_NONDETERMINISTIC);
        assert!(err.remediation().contains("Freeze all seeds"));

        let absent = AbsentLens::new(contract.clone());
        let err = contract
            .verify_determinism_probe(&absent, &probe)
            .expect_err("absent registration probe must be refused");
        assert_eq!(err.code(), ASTRO_PANEL_VECTOR_INVALID);
    }

    #[test]
    fn applicability_matrix_is_table_driven_for_every_label_class() {
        let driver = PanelDriver::default();
        let runtime = FixtureSlotRuntime;
        let cases = [
            (LabelClass::Callable, SymbolLabel::Function),
            (LabelClass::TypeDeclaration, SymbolLabel::Class),
            (LabelClass::Value, SymbolLabel::Field),
            (LabelClass::ModuleFile, SymbolLabel::File),
            (LabelClass::RouteChannel, SymbolLabel::Route),
            (LabelClass::StructuredResource, SymbolLabel::Resource),
            (LabelClass::Section, SymbolLabel::Section),
            (LabelClass::Structural, SymbolLabel::Project),
        ];

        for (class, label) in cases {
            assert_eq!(label_class(label), class);
            let expected = applicable_slot_ids_for_class(class);
            let readout = driver
                .measure(&PanelInput::fixture(label), &runtime)
                .expect("measure fixture");
            let mut actual = BTreeSet::new();
            for slot in PANEL_V1_SLOTS {
                let slot_id = slot.slot_id();
                let vector = readout.slots.get(&slot_id).expect("slot emitted");
                if expected.contains(&slot_id) {
                    assert!(
                        !matches!(
                            vector,
                            SlotVector::Absent {
                                reason: AbsentReason::NotApplicable
                            }
                        ),
                        "{class:?} slot {} was incorrectly marked not applicable",
                        slot.slot
                    );
                    assert!(!vector.is_absent());
                    actual.insert(slot_id);
                } else {
                    assert_eq!(
                        vector,
                        &SlotVector::Absent {
                            reason: AbsentReason::NotApplicable,
                        },
                        "{class:?} slot {} should be NotApplicable",
                        slot.slot
                    );
                }
            }
            assert_eq!(actual, expected);
        }
    }

    proptest! {
        #[test]
        fn missing_applicable_inputs_are_absent_never_zero(
            label in label_strategy(),
            availability_mask in any::<u32>(),
        ) {
            let available = PANEL_V1_SLOTS
                .iter()
                .filter(|slot| (availability_mask & (1_u32 << slot.slot)) != 0)
                .map(|slot| slot.slot_id())
                .collect::<Vec<_>>();
            let input = PanelInput::with_available_slots(label, available);
            let readout = PanelDriver::default()
                .measure(&input, &FixtureSlotRuntime)
                .expect("measure partial input");
            let applicable = applicable_slot_ids(label);

            for slot in PANEL_V1_SLOTS {
                let slot_id = slot.slot_id();
                let vector = readout.slots.get(&slot_id).expect("slot emitted");
                if !applicable.contains(&slot_id) {
                    prop_assert_eq!(
                        vector,
                        &SlotVector::Absent {
                            reason: AbsentReason::NotApplicable,
                        }
                    );
                } else if !input.available_slots.contains(&slot_id) {
                    prop_assert_eq!(
                        vector,
                        &SlotVector::Absent {
                            reason: AbsentReason::LensUnavailable,
                        }
                    );
                    prop_assert!(vector.as_dense().is_none());
                }
            }
        }
    }

    #[test]
    fn seed_registry_golden_bytes_are_frozen() {
        let artifact = default_seed_registry_artifact();
        let validation = validate_seed_registry_artifact(&artifact).expect("valid registry");
        assert_eq!(validation.entry_count, ASTRO_SEED_SPECS.len());
        let bytes = serde_json::to_vec(&artifact).expect("serialize registry");
        assert_eq!(bytes.as_slice(), SEED_REGISTRY_GOLDEN_JSON.as_bytes());
    }

    #[test]
    fn encoder_change_plan_bumps_version_and_emits_lazy_backfill_hook() {
        let previous = FrozenLensContract::for_slot(&PANEL_V1_SLOTS[18]);
        let mut next = previous.clone();
        next.weights_sha[31] ^= 0x44;

        let plan =
            plan_encoder_change(SlotId::new(18), 7, &previous, &next).expect("plan encoder change");

        assert_eq!(plan.panel_version, 8);
        assert_eq!(plan.new_lens_id, next.lens_id());
        assert_eq!(
            plan.backfill_hooks,
            vec![BackfillHook {
                slot_id: SlotId::new(18),
                previous_lens_id: previous.lens_id(),
                new_lens_id: next.lens_id(),
                from_panel_version: 7,
                to_panel_version: 8,
                kind: "lazy_backfill".to_string(),
            }]
        );
    }

    const SEED_REGISTRY_GOLDEN_JSON: &str = r#"{"schema_id":"astro.seed_registry.v1","artifact_kind":"astro_frozen_encoder_seed_registry","registry_version":"astro.panel.v1.seeds.v1","entries":[{"slot":1,"lens_key":"struct_trigrams","seed_hex":"0xA570000000000001","dim":65536,"sigma":1.0,"source_field":"ast_trigrams","transform":"signed_feature_hash","purpose":"structural AST trigram hashing"},{"slot":3,"lens_key":"complexity_ple","seed_hex":"0xA570000000000003","dim":56,"sigma":1.0,"source_field":"complexity_metrics","transform":"piecewise_linear_thermometer","purpose":"frozen complexity thermometer edges"},{"slot":4,"lens_key":"api_callees","seed_hex":"0xA570000000000004","dim":262144,"sigma":1.0,"source_field":"resolved_callees","transform":"hashed_multihot_log_count","purpose":"callee set hashing"},{"slot":5,"lens_key":"type_surface","seed_hex":"0xA570000000000005","dim":65536,"sigma":1.0,"source_field":"type_refs","transform":"hashed_set","purpose":"type surface hashing"},{"slot":6,"lens_key":"decorators","seed_hex":"0xA570000000000006","dim":4096,"sigma":1.0,"source_field":"decorators","transform":"hashed_set","purpose":"decorator and annotation hashing"},{"slot":7,"lens_key":"identifier_lexical","seed_hex":"0xA570000000000007","dim":131072,"sigma":1.0,"source_field":"identifier_tokens","transform":"tf_hash","purpose":"identifier lexical hashing"},{"slot":9,"lens_key":"path_hierarchy","seed_hex":"0xA570000000000009","dim":16384,"sigma":1.0,"source_field":"file_path","transform":"ancestor_prefix_hash","purpose":"path hierarchy hashing"},{"slot":13,"lens_key":"lang_label","seed_hex":"0xA57000000000000D","dim":256,"sigma":1.0,"source_field":"language_label","transform":"hashed_one_hot","purpose":"language and label hashing"},{"slot":15,"lens_key":"error_surface","seed_hex":"0xA57000000000000F","dim":4096,"sigma":1.0,"source_field":"throws","transform":"hashed_set","purpose":"exception surface hashing"},{"slot":16,"lens_key":"config_env_surface","seed_hex":"0xA570000000000010","dim":4096,"sigma":1.0,"source_field":"env_and_config_keys","transform":"hashed_set","purpose":"environment/config surface hashing"},{"slot":17,"lens_key":"route_surface","seed_hex":"0xA570000000000011","dim":4096,"sigma":1.0,"source_field":"routes_and_channels","transform":"canonical_path_hash","purpose":"route and channel surface hashing"},{"slot":18,"lens_key":"code_semantic","seed_hex":"0xA570000000000012","dim":768,"sigma":0.125,"source_field":"body_tokens","transform":"nomic_static_sum","purpose":"code semantic random-index fallback"},{"slot":19,"lens_key":"doc_semantic","seed_hex":"0xA570000000000013","dim":768,"sigma":0.125,"source_field":"docstring_comments","transform":"nomic_static_sum","purpose":"documentation semantic random-index fallback"},{"slot":20,"lens_key":"name_semantic","seed_hex":"0xA570000000000014","dim":768,"sigma":0.125,"source_field":"identifier_name","transform":"nomic_static_sum","purpose":"name semantic random-index fallback"},{"slot":22,"lens_key":"token_multi","seed_hex":"0xA570000000000016","dim":128,"sigma":0.125,"source_field":"body_tokens","transform":"random_projection_768_to_128","purpose":"late-interaction token projection"}]}"#;

    #[derive(Debug)]
    struct DeterministicLens {
        contract: FrozenLensContract,
    }

    impl DeterministicLens {
        fn new(contract: FrozenLensContract) -> Self {
            Self { contract }
        }
    }

    impl Lens for DeterministicLens {
        fn id(&self) -> LensId {
            self.contract.lens_id()
        }

        fn shape(&self) -> SlotShape {
            self.contract.shape
        }

        fn modality(&self) -> Modality {
            self.contract.modality
        }

        fn measure(&self, _input: &Input) -> calyx_core::Result<SlotVector> {
            Ok(SlotVector::Dense {
                dim: 2,
                data: vec![1.0, 2.0],
            })
        }
    }

    #[derive(Debug)]
    struct NondeterministicLens {
        contract: FrozenLensContract,
        counter: AtomicU32,
    }

    impl NondeterministicLens {
        fn new(contract: FrozenLensContract) -> Self {
            Self {
                contract,
                counter: AtomicU32::new(0),
            }
        }
    }

    impl Lens for NondeterministicLens {
        fn id(&self) -> LensId {
            self.contract.lens_id()
        }

        fn shape(&self) -> SlotShape {
            self.contract.shape
        }

        fn modality(&self) -> Modality {
            self.contract.modality
        }

        fn measure(&self, _input: &Input) -> calyx_core::Result<SlotVector> {
            let next = self.counter.fetch_add(1, Ordering::SeqCst) as f32;
            Ok(SlotVector::Dense {
                dim: 2,
                data: vec![1.0 + next, 2.0],
            })
        }
    }

    #[derive(Debug)]
    struct AbsentLens {
        contract: FrozenLensContract,
    }

    impl AbsentLens {
        fn new(contract: FrozenLensContract) -> Self {
            Self { contract }
        }
    }

    impl Lens for AbsentLens {
        fn id(&self) -> LensId {
            self.contract.lens_id()
        }

        fn shape(&self) -> SlotShape {
            self.contract.shape
        }

        fn modality(&self) -> Modality {
            self.contract.modality
        }

        fn measure(&self, _input: &Input) -> calyx_core::Result<SlotVector> {
            Ok(SlotVector::Absent {
                reason: AbsentReason::LensUnavailable,
            })
        }
    }

    fn label_strategy() -> impl Strategy<Value = SymbolLabel> {
        prop::sample::select(vec![
            SymbolLabel::Function,
            SymbolLabel::Method,
            SymbolLabel::Class,
            SymbolLabel::Struct,
            SymbolLabel::Interface,
            SymbolLabel::Enum,
            SymbolLabel::EnumMember,
            SymbolLabel::Trait,
            SymbolLabel::Type,
            SymbolLabel::TypeAlias,
            SymbolLabel::Field,
            SymbolLabel::Variable,
            SymbolLabel::Constant,
            SymbolLabel::Module,
            SymbolLabel::File,
            SymbolLabel::Route,
            SymbolLabel::Channel,
            SymbolLabel::Resource,
            SymbolLabel::Chart,
            SymbolLabel::Package,
            SymbolLabel::Macro,
            SymbolLabel::Section,
            SymbolLabel::Namespace,
            SymbolLabel::Property,
            SymbolLabel::Union,
            SymbolLabel::Protocol,
            SymbolLabel::Mixin,
            SymbolLabel::Object,
            SymbolLabel::Impl,
            SymbolLabel::Annotation,
            SymbolLabel::EnvVar,
            SymbolLabel::Project,
            SymbolLabel::Branch,
            SymbolLabel::Folder,
        ])
    }
}
