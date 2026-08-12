#![forbid(unsafe_code)]

mod detmath;
mod embeddings;
pub mod layout_registry;
mod lenses;
pub mod semantic;
pub mod similarity;
mod unicode61;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::LazyLock;

use astrolabe_domain::{ASTRO_SYMBOL_NON_FINITE, SymbolLabel};
use calyx_core::{
    AbsentReason, Input, Lens, LensId, Modality, SlotId, SlotShape, SlotVector, SparseEntry,
    content_address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use embeddings::{
    NOMIC_EMBED_DIM, NOMIC_TOKEN_COUNT, NOMIC_TOKEN_TABLE_SHA256, NOMIC_VECTOR_BLOB_SHA256,
    StaticEmbeddingInput, StaticEmbeddingLens, StaticEmbeddingTable, encode_static_embedding_slot,
    fixture_static_embedding_input, nomic_weights_identity, s18_s20_lenses,
    shared_default_static_embedding_table, shared_default_static_embedding_table_load_count,
};
pub use lenses::{
    ApiCall, ApiFamily, AstProfile, ChannelObservation, ChurnProfileInput, ComplexityMetrics,
    ConfigEnvSurfaceInput, DEFAULT_PERSISTENCE_FAMILY_SEEDS, DEFAULT_TRANSPORT_FAMILY_SEEDS,
    DeterministicEncoderLens, EncoderLensInput, ErrorSurfaceInput, GraphPositionInput,
    IdentifierLexicalInput, LangLabelInput, PathHierarchyInput, RECORD_VECTOR_SCALAR_KEYS,
    RecordVectorInput, RoleFlagsInput, RouteObservation, RouteSurfaceInput, StructuralTrigram,
    TestTopologyInput, TypeSurfaceInput, canonical_route_qn, cbm_camel_split_text,
    cbm_camel_split_tokens, cbm_route_canon_path, default_api_family,
    encode_identifier_lexical_streaming, encode_slot, fixture_encoder_input,
    fixture_scalar_sidecar, layer_role_lens, s0_s9_lenses, s10_s17_s21_lenses,
};
pub use similarity::{
    ASTRO_PANEL_COSINE_SHAPE_MISMATCH, ASTRO_PANEL_COSINE_UNSUPPORTED_SHAPE, slot_centroid,
    slot_vector_cosine,
};

/// Crate name reported by Cargo metadata.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// Frozen Astrolabe panel schema identifier.
///
/// This string is the panel-*family* content-address salt baked into every slot's
/// [`FrozenLensContract::lens_id`] and deterministic `weights_sha`. It is stable
/// across panel *roster* versions: a lens's identity is per-lens (its name, weights,
/// shape, modality, norm), so a new roster version that only *adds* a slot never
/// disturbs the frozen identities of the existing S0-S22 lenses. The roster version
/// itself is carried separately as [`PanelReadout::panel_version`] /
/// [`PANEL_SCHEMA_ID_V2`].
pub const PANEL_SCHEMA_ID: &str = "astro.panel.v1";
/// Panel schema id emitted by readouts from the v2 roster (S0-S23, adds S23 `layer_role`).
pub const PANEL_SCHEMA_ID_V2: &str = "astro.panel.v2";
/// Panel schema id emitted by the v3 exhaustive code-memory semantic roster.
pub const PANEL_SCHEMA_ID_V3: &str = "astro.panel.v3";
/// Panel schema id emitted by the v4 semantic-input-bound roster.
pub const PANEL_SCHEMA_ID_V4: &str = "astro.panel.v4";
/// First Astrolabe panel version.
pub const DEFAULT_PANEL_VERSION: u32 = 1;
/// Second Astrolabe panel version — adds the S23 `layer_role` frozen slot (#180a).
pub const PANEL_V2_VERSION: u32 = 2;
/// Third Astrolabe panel version — exhaustive typed CBM semantic atom coverage.
pub const PANEL_V3_VERSION: u32 = 3;
/// Fourth Astrolabe panel version — binds every measured node semantic input into CxId.
pub const PANEL_V4_VERSION: u32 = 4;
/// Current exhaustive code-memory panel version.
pub const CURRENT_SEMANTIC_PANEL_VERSION: u32 = PANEL_V4_VERSION;
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
/// Stable reason label recorded on the S21 slot when the frozen record scalars carry
/// no measurable signal (all zero). Such a vector has zero L2 norm and cannot be
/// unit-normalized, so the slot degrades to an explicit labeled absence instead of
/// aborting the whole panel readout for the symbol.
pub const ASTRO_PANEL_S21_ZERO_SIGNAL: &str = "ASTRO_PANEL_S21_ZERO_SIGNAL";
/// Error code returned when a panel-version bump is inconsistent (e.g. non-monotonic).
pub const ASTRO_PANEL_VERSION_BUMP_INVALID: &str = "ASTRO_PANEL_VERSION_BUMP_INVALID";
/// Frozen schema id of the canonical layer-role taxonomy shared with the layout registry.
pub const ASTRO_LAYOUT_CANONICAL_ROLES_SCHEMA: &str = "astro.layout.canonical_roles.v1";

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

    /// Builds a fail-closed vector-invariant error for a production runtime.
    pub fn invalid_vector(message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self::new(ASTRO_PANEL_VECTOR_INVALID, message, remediation)
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
    /// Values must be finite and each vector must be unit (L2) length.
    Unit {
        /// Absolute tolerance for unit-length validation.
        tolerance: f32,
    },
    /// Values must be finite and each vector's L1 mass (sum of absolute values)
    /// must be one — i.e. the vector is a probability distribution. Used by the
    /// S23 `layer_role` posterior.
    L1 {
        /// Absolute tolerance for L1-mass validation.
        tolerance: f32,
    },
}

impl NormPolicy {
    /// Unit (L2) norm with the Astrolabe v1 default tolerance.
    pub const fn unit() -> Self {
        Self::Unit { tolerance: 1.0e-3 }
    }

    /// L1-mass (probability-distribution) norm with the Astrolabe v1 default tolerance.
    pub const fn l1() -> Self {
        Self::L1 { tolerance: 1.0e-3 }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Finite => "finite",
            Self::Unit { .. } => "unit",
            Self::L1 { .. } => "l1",
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
    ///
    /// For the deterministic S0-S17/S21 encoder slots, `weights_sha` binds the
    /// encoder's actual frozen-fixture output (see [`encoder_weights_identity`]),
    /// so any change to the encoder math or its goldens moves the frozen lens
    /// identity. Fails closed if the deterministic encoder cannot produce a
    /// concrete vector for its frozen probe fixture, rather than minting a bogus
    /// identity that omits the math.
    pub fn for_slot(slot: &PanelSlotSpec) -> PanelResult<Self> {
        let shape = shape_fingerprint(slot.shape);
        let weights_sha = if slot.slot >= semantic::SEMANTIC_SLOT_START {
            semantic::semantic_weights_identity(slot.slot_id())?
        } else if matches!(slot.slot, 18 | 19 | 20 | 22) {
            nomic_weights_identity()
        } else {
            encoder_weights_identity(slot, &shape)?
        };
        let corpus_hash = sha256_digest(&[b"corpus-independent"]);
        Ok(Self::new(
            slot.key,
            weights_sha,
            corpus_hash,
            slot.shape,
            slot.modality,
            LensDType::F32,
            slot.norm,
        ))
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
    /// Guard-designated slots are persisted **raw** (no quantization) so a guard
    /// conformal readback is byte-exact against the encoder's real posterior.
    pub guard_raw: bool,
}

impl PanelSlotSpec {
    /// Returns the Calyx slot id.
    pub const fn slot_id(self) -> SlotId {
        SlotId::new(self.slot)
    }

    /// Returns true when this slot is guard-designated (persisted raw).
    pub const fn is_guard_raw(self) -> bool {
        self.guard_raw
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
        guard_raw: false,
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
        guard_raw: false,
    }
}

/// Frozen slot spec for a guard-designated slot persisted raw (no quantization).
const fn guard_raw_slot(
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
        guard_raw: true,
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

/// Frozen canonical layer-role taxonomy for the S23 `layer_role` lens
/// (`astro.layout.canonical_roles.v1`).
///
/// This is a fixed *coordinate system* — a taxonomy/enum, not a measurable
/// threshold — so it is a permitted literal under standing invariant 4. Repos
/// declare their own directory *names*; the per-repo directory→role assignment
/// lives in the `astro.layout.declared_map.v1` registry knob, and any behavioral
/// surface that does not map to one of these roles overflows to
/// [`LayerRole::Other`] (the S13 hashed-overflow pattern). The **order** here is
/// frozen: it is the Dense(8) dimension order of every persisted S23 posterior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerRole {
    /// Transport / API layer: routes, handlers, request/response surface.
    TransportApi,
    /// Service / business-domain layer: orchestration between transport and data.
    ServiceDomain,
    /// Persistence layer: database, store, ORM, connection/query surface.
    Persistence,
    /// Model / schema layer: data-holding declarations with no behavioral surface.
    ModelSchema,
    /// Infrastructure / configuration layer.
    InfraConfig,
    /// Test layer.
    Test,
    /// Presentation / UI layer.
    Presentation,
    /// Overflow role for behavioral surface that maps to no declared layer.
    Other,
}

/// Number of canonical layer roles — the frozen S23 `layer_role` Dense dimension.
pub const LAYER_ROLE_COUNT: usize = 8;

/// Frozen canonical role order (the S23 Dense(8) dimension order).
pub const CANONICAL_ROLES: [LayerRole; LAYER_ROLE_COUNT] = [
    LayerRole::TransportApi,
    LayerRole::ServiceDomain,
    LayerRole::Persistence,
    LayerRole::ModelSchema,
    LayerRole::InfraConfig,
    LayerRole::Test,
    LayerRole::Presentation,
    LayerRole::Other,
];

impl LayerRole {
    /// Stable snake_case identifier for this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransportApi => "transport_api",
            Self::ServiceDomain => "service_domain",
            Self::Persistence => "persistence",
            Self::ModelSchema => "model_schema",
            Self::InfraConfig => "infra_config",
            Self::Test => "test",
            Self::Presentation => "presentation",
            Self::Other => "other",
        }
    }

    /// Fixed Dense(8) dimension index of this role.
    pub const fn index(self) -> usize {
        match self {
            Self::TransportApi => 0,
            Self::ServiceDomain => 1,
            Self::Persistence => 2,
            Self::ModelSchema => 3,
            Self::InfraConfig => 4,
            Self::Test => 5,
            Self::Presentation => 6,
            Self::Other => 7,
        }
    }

    /// Parses a canonical role name, or `None` if it is not in the frozen taxonomy.
    pub fn from_str_canonical(name: &str) -> Option<Self> {
        CANONICAL_ROLES
            .into_iter()
            .find(|role| role.as_str() == name)
    }
}

/// Frozen slot spec for the S23 `layer_role` lens (panel v2 addition, #180a).
///
/// Guard-designated (persisted raw), Dense(8) over [`CANONICAL_ROLES`], L1-normalized
/// (a probability distribution). The calyx input [`Modality::Structured`] carries the
/// derived behavioral graph/flag evidence the encoder combines; the blueprint "Content"
/// modality is the guard lens *category* (distinct axis from the calyx input modality).
pub const S23_LAYER_ROLE_SLOT: PanelSlotSpec = guard_raw_slot(
    23,
    "layer_role",
    SlotShape::Dense(LAYER_ROLE_COUNT as u32),
    Modality::Structured,
    NormPolicy::l1(),
);

/// Frozen v2 slot roster: the v1 slots (S0-S22) plus the S23 `layer_role` slot.
///
/// The v1 lenses keep their exact frozen identities (per-lens content addressing);
/// only S23 is minted. Built lazily to append S23 to [`PANEL_V1_SLOTS`] without
/// duplicating the 23-entry v1 table.
pub static PANEL_V2_SLOTS: LazyLock<Vec<PanelSlotSpec>> = LazyLock::new(|| {
    let mut slots = PANEL_V1_SLOTS.to_vec();
    slots.push(S23_LAYER_ROLE_SLOT);
    slots
});

/// Frozen v3 slot roster: panel v2 plus the exhaustive typed CBM semantic
/// registry. Existing S0-S23 specs and lens identities remain byte-identical.
pub static PANEL_V3_SLOTS: LazyLock<Vec<PanelSlotSpec>> = LazyLock::new(|| {
    let mut slots = PANEL_V2_SLOTS.iter().copied().collect::<Vec<_>>();
    slots.extend(semantic::SEMANTIC_SLOT_SPECS.iter().copied());
    slots
});

/// Frozen v4 slot roster. The lens roster and every lens identity remain
/// byte-identical to v3; v4 versions the node constellation identity contract so
/// the complete measured semantic input, including source-generation handles,
/// is bound into CxId.
pub static PANEL_V4_SLOTS: LazyLock<Vec<PanelSlotSpec>> =
    LazyLock::new(|| PANEL_V3_SLOTS.iter().copied().collect());

/// Returns the frozen v1 slot roster.
pub fn default_panel_slots() -> &'static [PanelSlotSpec] {
    PANEL_V1_SLOTS
}

/// Returns the frozen v2 slot roster (S0-S23).
pub fn default_panel_v2_slots() -> &'static [PanelSlotSpec] {
    &PANEL_V2_SLOTS
}

/// Returns the frozen v3 roster including exhaustive CBM semantic slots.
pub fn default_panel_v3_slots() -> &'static [PanelSlotSpec] {
    &PANEL_V3_SLOTS
}

/// Returns the frozen v4 roster including exhaustive CBM semantic slots.
pub fn default_panel_v4_slots() -> &'static [PanelSlotSpec] {
    &PANEL_V4_SLOTS
}

/// Returns the frozen slot roster for a panel roster version.
///
/// Fails closed for a version that has no frozen roster rather than silently
/// measuring an empty or wrong panel.
pub fn slots_for_version(version: u32) -> PanelResult<&'static [PanelSlotSpec]> {
    match version {
        DEFAULT_PANEL_VERSION => Ok(PANEL_V1_SLOTS),
        PANEL_V2_VERSION => Ok(&PANEL_V2_SLOTS),
        PANEL_V3_VERSION => Ok(&PANEL_V3_SLOTS),
        PANEL_V4_VERSION => Ok(&PANEL_V4_SLOTS),
        other => Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("panel version {other} has no frozen slot roster"),
            "Measure with panel version 1 (S0-S22), 2 (S0-S23), 3 (S0-S185), or 4 (S0-S185 with semantic-input-bound identity).",
        )),
    }
}

/// Returns the frozen panel schema id emitted by a roster version's readouts.
pub fn schema_id_for_version(version: u32) -> PanelResult<&'static str> {
    match version {
        DEFAULT_PANEL_VERSION => Ok(PANEL_SCHEMA_ID),
        PANEL_V2_VERSION => Ok(PANEL_SCHEMA_ID_V2),
        PANEL_V3_VERSION => Ok(PANEL_SCHEMA_ID_V3),
        PANEL_V4_VERSION => Ok(PANEL_SCHEMA_ID_V4),
        other => Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("panel version {other} has no frozen schema id"),
            "Measure with panel version 1, 2, 3, or 4.",
        )),
    }
}

/// Returns the canonical SHA-256 witness for every frozen slot contract in a
/// panel version.
///
/// The manifest is explicitly length-delimited and includes the slot id/key,
/// physical shape, modality, full norm policy, lifecycle flags, and frozen lens
/// id. It is intentionally independent of Serde so a diagnostic JSON change
/// cannot silently move the persisted coverage contract.
pub fn panel_slot_manifest_sha256(version: u32) -> PanelResult<[u8; 32]> {
    const MANIFEST_SCHEMA: &[u8] = b"astro.panel.slot-manifest.v1";

    fn append_part(bytes: &mut Vec<u8>, part: &[u8]) {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }

    let slots = slots_for_version(version)?;
    let schema_id = schema_id_for_version(version)?;
    let mut bytes = Vec::with_capacity(slots.len() * 128);
    append_part(&mut bytes, MANIFEST_SCHEMA);
    append_part(&mut bytes, schema_id.as_bytes());
    append_part(&mut bytes, &version.to_be_bytes());
    append_part(&mut bytes, &(slots.len() as u64).to_be_bytes());
    for spec in slots {
        append_part(&mut bytes, &spec.slot.to_be_bytes());
        append_part(&mut bytes, spec.key.as_bytes());
        append_part(&mut bytes, shape_fingerprint(spec.shape).as_bytes());
        append_part(&mut bytes, modality_fingerprint(spec.modality).as_bytes());
        match spec.norm {
            NormPolicy::Finite => append_part(&mut bytes, b"finite"),
            NormPolicy::Unit { tolerance } => {
                append_part(&mut bytes, b"unit");
                append_part(&mut bytes, &tolerance.to_bits().to_be_bytes());
            }
            NormPolicy::L1 { tolerance } => {
                append_part(&mut bytes, b"l1");
                append_part(&mut bytes, &tolerance.to_bits().to_be_bytes());
            }
        }
        append_part(
            &mut bytes,
            &[
                u8::from(spec.retrieval_only),
                u8::from(spec.excluded_from_dedup),
                u8::from(spec.guard_raw),
            ],
        );
        let lens_id = FrozenLensContract::for_slot(spec)?.lens_id();
        append_part(&mut bytes, lens_id.as_bytes());
    }
    Ok(sha256_digest(&[&bytes]))
}

/// Returns a slot specification by id, searching the current superset roster.
///
/// Older rosters are byte-identical prefixes, so their consumers see the same
/// answer while v3 semantic slots additionally resolve.
pub fn slot_spec(slot_id: SlotId) -> Option<&'static PanelSlotSpec> {
    PANEL_V4_SLOTS.iter().find(|slot| slot.slot_id() == slot_id)
}

/// Returns the default frozen contracts for every v1 slot.
///
/// Fails closed if any deterministic encoder slot cannot bind its real output into
/// `weights_sha` (see [`FrozenLensContract::for_slot`]).
pub fn default_contracts() -> PanelResult<Vec<FrozenLensContract>> {
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
        | SymbolLabel::Annotation
        | SymbolLabel::Decorator => LabelClass::TypeDeclaration,
        SymbolLabel::Field
        | SymbolLabel::Variable
        | SymbolLabel::Constant
        | SymbolLabel::Property
        | SymbolLabel::EnumMember => LabelClass::Value,
        SymbolLabel::Module | SymbolLabel::File => LabelClass::ModuleFile,
        SymbolLabel::Route | SymbolLabel::Channel => LabelClass::RouteChannel,
        SymbolLabel::Resource
        | SymbolLabel::Chart
        | SymbolLabel::Package
        | SymbolLabel::EnvVar
        | SymbolLabel::ParseDiagnostic
        | SymbolLabel::RuntimeModuleRequest
        | SymbolLabel::ContentDefect => LabelClass::StructuredResource,
        SymbolLabel::Section => LabelClass::Section,
        SymbolLabel::Project | SymbolLabel::Branch | SymbolLabel::Folder => LabelClass::Structural,
    }
}

/// Returns true when a slot applies to a label (v1 roster).
pub fn slot_applies(label: SymbolLabel, slot_id: SlotId) -> bool {
    applicable_slot_ids_for_class(label_class(label)).contains(&slot_id)
}

/// Returns the applicable slot ids for a domain label (v1 roster).
pub fn applicable_slot_ids(label: SymbolLabel) -> BTreeSet<SlotId> {
    applicable_slot_ids_for_class(label_class(label))
}

/// Returns the applicable slot ids for a domain label under a panel roster version.
///
/// For the v2 roster this adds S23 `layer_role` to the classes with a behavioral
/// surface (Callable, TypeDeclaration, ModuleFile, RouteChannel). Value-class atoms
/// (Field/Constant/Property) and structural atoms have no behavioral surface, so S23
/// stays *not applicable* and their readout carries an explicit `Absent{NotApplicable}`.
pub fn applicable_slot_ids_versioned(label: SymbolLabel, version: u32) -> BTreeSet<SlotId> {
    applicable_slot_ids_for_class_versioned(label_class(label), version)
}

/// Returns the applicable slot ids for a label class under a panel roster version.
pub fn applicable_slot_ids_for_class_versioned(
    class: LabelClass,
    version: u32,
) -> BTreeSet<SlotId> {
    let mut set = applicable_slot_ids_for_class(class);
    if version >= PANEL_V2_VERSION && layer_role_applies_to_class(class) {
        set.insert(S23_LAYER_ROLE_SLOT.slot_id());
    }
    set
}

/// S23 `layer_role` applicability by class (blueprint applicability-matrix rows):
/// Function/Method/Macro (full); Class/Struct/Interface/Enum/Trait (aggregate over
/// members); Module/File (directory-role feeder); Route/Channel (`transport_api` by
/// construction). Field/Constant/Property and structural atoms ⇒ not applicable.
const fn layer_role_applies_to_class(class: LabelClass) -> bool {
    matches!(
        class,
        LabelClass::Callable
            | LabelClass::TypeDeclaration
            | LabelClass::ModuleFile
            | LabelClass::RouteChannel
    )
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
    /// Local symbol name supplied by the production CBM importer.
    pub symbol_name: String,
    /// Fully-qualified symbol name supplied by the production CBM importer.
    pub qualified_name: String,
    /// Repository-relative source path supplied by the production CBM importer.
    pub rel_file_path: String,
    /// Source-language label supplied by the production CBM importer.
    pub language: String,
    /// Signature supplied by the production CBM importer.
    pub signature: String,
    /// Parsed CBM node properties. Keeping this parsed avoids reparsing the same
    /// JSON once for every slot in a panel measurement.
    pub properties: serde_json::Value,
    /// Exact scalar measurements preserved beside the vector panel.
    pub scalars: BTreeMap<String, f64>,
    /// CBM row family for panel-v3+ semantic slots. `None` is valid only for
    /// pre-v3 measurement.
    pub semantic_family: Option<semantic::SemanticFamily>,
    /// Typed semantic source values for present atoms, keyed by their frozen
    /// value slot. The driver derives the family presence vector and dispatches
    /// each value through the slot runtime; there is no JSON catch-all path.
    pub semantic_values: BTreeMap<SlotId, semantic::SemanticValue>,
    /// Whether the legacy S0-S23 symbol panel is requested for this input.
    /// Non-symbol CBM row families set this false and measure only their typed
    /// semantic registry slots.
    pub legacy_slots_enabled: bool,
}

impl PanelInput {
    /// Builds an input where all v1 slot sources are available.
    pub fn fixture(label: SymbolLabel) -> Self {
        Self {
            label,
            available_slots: PANEL_V1_SLOTS.iter().map(|slot| slot.slot_id()).collect(),
            source_bytes: label.as_str().as_bytes().to_vec(),
            symbol_name: String::new(),
            qualified_name: String::new(),
            rel_file_path: String::new(),
            language: String::new(),
            signature: String::new(),
            properties: serde_json::Value::Object(serde_json::Map::new()),
            scalars: BTreeMap::new(),
            semantic_family: None,
            semantic_values: BTreeMap::new(),
            legacy_slots_enabled: true,
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
            symbol_name: String::new(),
            qualified_name: String::new(),
            rel_file_path: String::new(),
            language: String::new(),
            signature: String::new(),
            properties: serde_json::Value::Object(serde_json::Map::new()),
            scalars: BTreeMap::new(),
            semantic_family: None,
            semantic_values: BTreeMap::new(),
            legacy_slots_enabled: true,
        }
    }

    /// Attaches exact scalar measurements to be preserved beside emitted vectors.
    pub fn with_scalars(mut self, scalars: BTreeMap<String, f64>) -> Self {
        self.scalars = scalars;
        self
    }

    /// Attaches the exact panel-v3+ semantic family and present-slot map.
    pub fn with_semantic_values(
        mut self,
        family: semantic::SemanticFamily,
        values: BTreeMap<SlotId, semantic::SemanticValue>,
    ) -> Self {
        self.semantic_family = Some(family);
        self.semantic_values = values;
        self
    }

    /// Enables or disables legacy S0-S23 dispatch for this input.
    pub fn with_legacy_slots_enabled(mut self, enabled: bool) -> Self {
        self.legacy_slots_enabled = enabled;
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
    /// Roll-up accounting for how every slot resolved, so no degradation is silent.
    #[serde(default)]
    pub summary: PanelReadoutSummary,
}

/// Accounting roll-up for a [`PanelReadout`].
///
/// Every one of the [`PANEL_V1_SLOTS`] lands in exactly one bucket: a real measured
/// vector, a structural non-applicability, or an explicitly labeled degradation (with
/// the reason recorded both on its slot and here). The buckets always sum to the full
/// slot count, so a degraded or skipped slot can never be silently lost.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelReadoutSummary {
    /// Count of slots carrying a real measured vector (`Dense`/`Sparse`/`Multi`).
    pub measured: usize,
    /// Count of slots absent because the lens does not apply to this symbol/modality.
    pub not_applicable: usize,
    /// Slots that degraded to a labeled absence, mapped to the recorded reason label.
    pub degraded: BTreeMap<SlotId, String>,
    /// Registered optional semantic value slots omitted because their source
    /// atom is not present. Missingness is carried by the family presence slot.
    #[serde(default)]
    pub semantic_not_present: usize,
}

impl PanelReadoutSummary {
    /// Number of slots that degraded to a labeled absence.
    pub fn degradation_count(&self) -> usize {
        self.degraded.len()
    }

    /// Total number of slots accounted for across every bucket.
    pub fn accounted_slots(&self) -> usize {
        self.measured + self.not_applicable + self.degraded.len() + self.semantic_not_present
    }
}

/// Returns the stable reason label recorded for a degraded (non-applicable-excluded)
/// slot absence, so degradations carry a durable machine-readable tag.
fn absent_reason_label(reason: &AbsentReason) -> String {
    match reason {
        AbsentReason::NotApplicable => "not_applicable".to_string(),
        AbsentReason::Redacted => "redacted".to_string(),
        AbsentReason::LensUnavailable => "lens_unavailable".to_string(),
        AbsentReason::Deferred => "deferred".to_string(),
        AbsentReason::LensInactive => "lens_inactive".to_string(),
        AbsentReason::Error(code) => code.clone(),
    }
}

/// Returns a slot specification by its stable key, searching the v2 superset roster.
///
/// The lens capability gate (`astrolabe-assay`, #35) reaches verdicts in lens-name
/// space; this bridges a gated lens key to its frozen [`SlotId`] so a per-repo
/// admission set can be applied to a readout without touching the frozen roster.
pub fn slot_spec_by_key(key: &str) -> Option<&'static PanelSlotSpec> {
    PANEL_V4_SLOTS.iter().find(|slot| slot.key == key)
}

impl PanelReadout {
    /// Returns a per-repo serving view with parked/retired lenses masked.
    ///
    /// `active_slots` is the repo's admitted lens set expressed as [`SlotId`]s
    /// (the capability gate's Admit set, #35). Any slot that currently carries a
    /// real measured vector whose id is **not** in `active_slots` is replaced with
    /// `Absent{LensInactive}` in the returned readout, and its accounting moves
    /// from `measured` to a labeled `degraded` entry so the serving exclusion is
    /// never silent (standing invariant 3).
    ///
    /// This is a **non-destructive overlay**: `self` is left untouched — its real
    /// vectors stay readable for historical/as-of reads — and the frozen roster
    /// ([`slots_for_version`]) is never consulted for mutation. Parking a lens is a
    /// per-repo serving decision, not a roster-contract edit, so the panel-version
    /// roster is unchanged by admission.
    pub fn serving_view(&self, active_slots: &BTreeSet<SlotId>) -> PanelReadout {
        let mut slots = BTreeMap::new();
        let mut summary = PanelReadoutSummary {
            semantic_not_present: self.summary.semantic_not_present,
            ..PanelReadoutSummary::default()
        };
        for (slot_id, vector) in &self.slots {
            let is_measured = matches!(
                vector,
                SlotVector::Dense { .. } | SlotVector::Sparse { .. } | SlotVector::Multi { .. }
            );
            let out = if is_measured && !active_slots.contains(slot_id) {
                SlotVector::Absent {
                    reason: AbsentReason::LensInactive,
                }
            } else {
                vector.clone()
            };
            match &out {
                SlotVector::Absent {
                    reason: AbsentReason::NotApplicable,
                } => summary.not_applicable += 1,
                SlotVector::Absent { reason } => {
                    summary
                        .degraded
                        .insert(*slot_id, absent_reason_label(reason));
                }
                SlotVector::Dense { .. } | SlotVector::Sparse { .. } | SlotVector::Multi { .. } => {
                    summary.measured += 1
                }
            }
            slots.insert(*slot_id, out);
        }
        PanelReadout {
            schema_id: self.schema_id.clone(),
            panel_version: self.panel_version,
            label: self.label,
            slots,
            scalars: self.scalars.clone(),
            summary,
        }
    }
}

fn validate_semantic_panel_input(version: u32, input: &PanelInput) -> PanelResult<()> {
    if version < PANEL_V3_VERSION {
        if input.semantic_family.is_some() || !input.semantic_values.is_empty() {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("panel version {version} cannot accept exhaustive semantic slots"),
                "Use the current semantic panel version for exhaustive code-memory measurement.",
            ));
        }
        return Ok(());
    }

    let Some(family) = input.semantic_family else {
        if input.semantic_values.is_empty() {
            // Ad-hoc panel measurements (for example guard candidates) are not
            // persisted CBM rows and may request only S0-S23.
            return Ok(());
        }
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            "semantic values have no exact row family",
            "Classify the CBM source row before attaching semantic values.",
        ));
    };
    for (slot_id, value) in &input.semantic_values {
        let rule = semantic::semantic_rule_by_slot(*slot_id).ok_or_else(|| {
            PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("semantic input contains unregistered slot {slot_id}"),
                "Add a versioned semantic registry rule before emitting the source atom.",
            )
        })?;
        if rule.family != family {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "{} input contains {} rule {}",
                    family.as_str(),
                    rule.family.as_str(),
                    rule.path
                ),
                "Keep each constellation's semantic slots within one exact row family.",
            ));
        }
        if value.source_type() != rule.source_type {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "{} rule {} expects {}, received {}",
                    family.as_str(),
                    rule.path,
                    rule.source_type.as_str(),
                    value.source_type().as_str()
                ),
                "Update the versioned registry for a real CBM schema change; never coerce the observed value.",
            ));
        }
    }
    Ok(())
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
    /// Creates a driver for a known, frozen panel version.
    ///
    /// The version is validated eagerly against the frozen slot roster and schema
    /// set at construction, so an unknown version (e.g. 99) fails closed here with
    /// [`ASTRO_PANEL_CONTRACT_INVALID`] naming the known versions — rather than
    /// surviving construction and surfacing later as a generic measure-time panel
    /// failure. Callers that map construction errors to a version-specific code
    /// (guard_check panel mode, guard_calibrate auto path) therefore see the
    /// version error at the point they expect it.
    pub fn new(version: u32) -> PanelResult<Self> {
        if version == 0 {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "panel version 0 cannot measure Astrolabe slots",
                "Commission a non-zero panel version before measurement.",
            ));
        }
        // Force the frozen roster and schema lookups eagerly so an unknown version
        // is rejected at construction, not lazily at measure time.
        slots_for_version(version)?;
        schema_id_for_version(version)?;
        Ok(Self { version })
    }

    /// Returns the driver panel version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Measures the selected frozen roster, enforcing applicability before runtime dispatch.
    pub fn measure<R>(&self, input: &PanelInput, runtime: &R) -> PanelResult<PanelReadout>
    where
        R: SlotRuntime,
    {
        validate_scalar_sidecar(&input.scalars)?;
        let roster = slots_for_version(self.version)?;
        let schema_id = schema_id_for_version(self.version)?;
        validate_semantic_panel_input(self.version, input)?;
        let applicable = applicable_slot_ids_versioned(input.label, self.version);
        let mut slots = BTreeMap::new();
        let mut summary = PanelReadoutSummary::default();
        for slot in roster
            .iter()
            .filter(|slot| slot.slot < semantic::SEMANTIC_SLOT_START)
        {
            let slot_id = slot.slot_id();
            if !input.legacy_slots_enabled {
                summary.not_applicable += 1;
                continue;
            }
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
                validate_slot_vector_contract(slot_id, &vector)?;
                vector
            };
            match &vector {
                SlotVector::Absent {
                    reason: AbsentReason::NotApplicable,
                } => summary.not_applicable += 1,
                SlotVector::Absent { reason } => {
                    summary
                        .degraded
                        .insert(slot_id, absent_reason_label(reason));
                }
                SlotVector::Dense { .. } | SlotVector::Sparse { .. } | SlotVector::Multi { .. } => {
                    summary.measured += 1
                }
            }
            slots.insert(slot_id, vector);
        }
        if let Some(family) = input.semantic_family {
            let rules = input
                .semantic_values
                .keys()
                .map(|slot_id| {
                    semantic::semantic_rule_by_slot(*slot_id)
                        .expect("validated semantic value slot")
                })
                .collect::<Vec<_>>();
            let presence_slot_id = family.presence_slot();
            let _presence_slot = slot_spec(presence_slot_id).ok_or_else(|| {
                PanelError::new(
                    ASTRO_PANEL_CONTRACT_INVALID,
                    format!(
                        "{} presence slot {} is absent from panel version {}",
                        family.as_str(),
                        presence_slot_id,
                        self.version
                    ),
                    "Restore the exact frozen semantic roster before measurement.",
                )
            })?;
            let presence = semantic::encode_presence(family, rules)?;
            validate_slot_vector_contract(presence_slot_id, &presence)?;
            slots.insert(presence_slot_id, presence);
            summary.measured += 1;

            for slot_id in input.semantic_values.keys() {
                let slot = slot_spec(*slot_id).ok_or_else(|| {
                    PanelError::new(
                        ASTRO_PANEL_CONTRACT_INVALID,
                        format!("semantic slot {slot_id} is absent from the frozen roster"),
                        "Restore the exact semantic registry and slot roster before measurement.",
                    )
                })?;
                let vector = runtime.measure_slot(slot, input)?;
                validate_slot_vector_contract(*slot_id, &vector)?;
                if vector.is_absent() {
                    return Err(PanelError::new(
                        ASTRO_PANEL_VECTOR_INVALID,
                        format!("present semantic slot {slot_id} emitted Absent"),
                        "Repair the frozen encoder/embedder input or registry; every present CBM atom must produce a concrete vector.",
                    ));
                }
                slots.insert(*slot_id, vector);
                summary.measured += 1;
            }
            let family_rules = semantic::semantic_rule_count_for_family(family);
            summary.semantic_not_present = family_rules
                .checked_sub(input.semantic_values.len())
                .ok_or_else(|| {
                    PanelError::new(
                        ASTRO_PANEL_CONTRACT_INVALID,
                        format!(
                            "{} semantic input contains {} values for only {family_rules} rules",
                            family.as_str(),
                            input.semantic_values.len()
                        ),
                        "Repair the frozen semantic registry or typed input map before measurement.",
                    )
                })?;
        }
        Ok(PanelReadout {
            schema_id: schema_id.to_string(),
            panel_version: self.version,
            label: input.label,
            slots,
            scalars: input.scalars.clone(),
            summary,
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
        "frozen Nomic static code-token embedding",
    ),
    seed(
        19,
        "doc_semantic",
        "0xA570000000000013",
        768,
        0.125,
        "docstring_comments",
        "nomic_static_sum",
        "frozen Nomic static documentation embedding",
    ),
    seed(
        20,
        "name_semantic",
        "0xA570000000000014",
        768,
        0.125,
        "identifier_name",
        "nomic_static_sum",
        "frozen Nomic static identifier embedding",
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

/// Re-derivation cost incurred by adding a frozen slot to the panel roster.
///
/// Adding S23 to the roster and to dedup identity means every symbol whose label
/// class receives S23 must be re-deduped and re-assayed. The concrete touched-scope
/// *count* is repo-specific and is measured by the ingest ledger entry against the
/// real corpus; this record states the policy (which classes, that re-derivation is
/// required) so the cost is never silently absorbed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReDerivationCost {
    /// True when the added slot participates in constellation identity/dedup.
    pub added_to_identity: bool,
    /// Whether dedup constellations must be re-indexed for touched scopes.
    pub dedup_reindex_required: bool,
    /// Whether assay/quality re-derivation is required for touched scopes.
    pub assay_recompute_required: bool,
    /// Stable snake_case names of the label classes that receive the new slot.
    pub affected_label_classes: Vec<String>,
}

/// A ledgerable record of a panel roster-version bump (e.g. v1 → v2 adding S23).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PanelVersionBump {
    /// Previous panel schema id.
    pub from_schema_id: String,
    /// New panel schema id.
    pub to_schema_id: String,
    /// Previous panel roster version.
    pub from_version: u32,
    /// New panel roster version.
    pub to_version: u32,
    /// Slot id added by this bump.
    pub added_slot: SlotId,
    /// Stable key of the added slot.
    pub added_slot_key: String,
    /// Content-addressed frozen lens id of the added slot.
    pub added_lens_id: LensId,
    /// Re-derivation cost this bump imposes on touched scopes.
    pub rederivation: ReDerivationCost,
}

/// Plans the panel v1 → v2 bump that adds the S23 `layer_role` slot (#180a).
///
/// Fails closed if the S23 frozen contract cannot bind its real encoder output.
pub fn plan_panel_version_bump_v1_to_v2() -> PanelResult<PanelVersionBump> {
    let contract = FrozenLensContract::for_slot(&S23_LAYER_ROLE_SLOT)?;
    let added_to_identity =
        !S23_LAYER_ROLE_SLOT.retrieval_only && !S23_LAYER_ROLE_SLOT.excluded_from_dedup;
    let affected = [
        LabelClass::Callable,
        LabelClass::TypeDeclaration,
        LabelClass::ModuleFile,
        LabelClass::RouteChannel,
    ]
    .into_iter()
    .filter(|class| layer_role_applies_to_class(*class))
    .map(|class| label_class_key(class).to_string())
    .collect::<Vec<_>>();
    Ok(PanelVersionBump {
        from_schema_id: PANEL_SCHEMA_ID.to_string(),
        to_schema_id: PANEL_SCHEMA_ID_V2.to_string(),
        from_version: DEFAULT_PANEL_VERSION,
        to_version: PANEL_V2_VERSION,
        added_slot: S23_LAYER_ROLE_SLOT.slot_id(),
        added_slot_key: S23_LAYER_ROLE_SLOT.key.to_string(),
        added_lens_id: contract.lens_id(),
        rederivation: ReDerivationCost {
            added_to_identity,
            dedup_reindex_required: added_to_identity,
            assay_recompute_required: added_to_identity,
            affected_label_classes: affected,
        },
    })
}

/// Stable snake_case key for a panel applicability label class.
pub const fn label_class_key(class: LabelClass) -> &'static str {
    match class {
        LabelClass::Callable => "callable",
        LabelClass::TypeDeclaration => "type_declaration",
        LabelClass::Value => "value",
        LabelClass::ModuleFile => "module_file",
        LabelClass::RouteChannel => "route_channel",
        LabelClass::StructuredResource => "structured_resource",
        LabelClass::Section => "section",
        LabelClass::Structural => "structural",
    }
}

/// Serializes a concrete slot vector to its guard-raw byte form (no quantization):
/// `b"D" | dim:u32be | dim×f32be` for dense, `b"S" | dim:u32be | len:u32be |
/// (idx:u32be,val:f32be)×len` for sparse. This is the exact byte-level form a
/// guard-designated slot (e.g. S23 `layer_role`) is persisted and read back in.
///
/// Fails closed on `Multi`/`Absent`: a guard-designated raw sidecar records a
/// concrete measured vector, never a placeholder.
pub fn slot_raw_bytes(vector: &SlotVector) -> PanelResult<Vec<u8>> {
    slot_vector_identity_bytes(vector)
}

/// Decodes guard-raw bytes produced by [`slot_raw_bytes`] back into a slot vector.
///
/// Fails closed with [`ASTRO_PANEL_VECTOR_INVALID`] on a truncated or unrecognized
/// envelope so a corrupt persisted sidecar can never be read as a valid posterior.
pub fn decode_slot_raw(bytes: &[u8]) -> PanelResult<SlotVector> {
    let invalid = |message: String| {
        PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            message,
            "Re-persist the guard-raw slot sidecar from the encoder's real output.",
        )
    };
    let (tag, rest) = bytes
        .split_first()
        .ok_or_else(|| invalid("empty guard-raw slot envelope".to_string()))?;
    match tag {
        b'D' => {
            let dim_bytes: [u8; 4] = rest
                .get(0..4)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| invalid("dense guard-raw envelope missing dim".to_string()))?;
            let dim = u32::from_be_bytes(dim_bytes);
            let payload = &rest[4..];
            if payload.len() != dim as usize * 4 {
                return Err(invalid(format!(
                    "dense guard-raw envelope has {} value bytes, expected {}",
                    payload.len(),
                    dim as usize * 4
                )));
            }
            let data = payload
                .chunks_exact(4)
                .map(|chunk| {
                    let mut word = [0_u8; 4];
                    word.copy_from_slice(chunk);
                    f32::from_bits(u32::from_be_bytes(word))
                })
                .collect::<Vec<_>>();
            Ok(SlotVector::Dense { dim, data })
        }
        b'S' => {
            let dim_bytes: [u8; 4] = rest
                .get(0..4)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| invalid("sparse guard-raw envelope missing dim".to_string()))?;
            let dim = u32::from_be_bytes(dim_bytes);
            let len_bytes: [u8; 4] = rest
                .get(4..8)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| invalid("sparse guard-raw envelope missing len".to_string()))?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            let payload = &rest[8..];
            if payload.len() != len * 8 {
                return Err(invalid(format!(
                    "sparse guard-raw envelope has {} entry bytes, expected {}",
                    payload.len(),
                    len * 8
                )));
            }
            let entries = payload
                .chunks_exact(8)
                .map(|chunk| {
                    let mut idx = [0_u8; 4];
                    idx.copy_from_slice(&chunk[0..4]);
                    let mut val = [0_u8; 4];
                    val.copy_from_slice(&chunk[4..8]);
                    SparseEntry {
                        idx: u32::from_be_bytes(idx),
                        val: f32::from_bits(u32::from_be_bytes(val)),
                    }
                })
                .collect::<Vec<_>>();
            Ok(SlotVector::Sparse { dim, entries })
        }
        other => Err(invalid(format!(
            "unrecognized guard-raw envelope tag {other:#x}"
        ))),
    }
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

/// Frozen tag distinguishing the deterministic-encoder weights identity domain.
const DETERMINISTIC_ENCODER_WEIGHTS_TAG: &[u8] = b"astro.panel.v1.deterministic-encoder.weights.v1";

/// Canonical bit-exact serialization of a lens output vector for content-addressing.
///
/// Uses the raw IEEE-754 bit patterns (never a lossy text form) so the folded
/// identity moves on any real change to the encoder's numeric output. Fails
/// closed on `Absent`/`Multi`: the deterministic S0-S17/S21 encoders must yield a
/// concrete dense or sparse vector on their complete frozen probe fixture, and an
/// empty/degenerate result must never be folded into a "same version" hash.
fn slot_vector_identity_bytes(vector: &SlotVector) -> PanelResult<Vec<u8>> {
    let mut out = Vec::new();
    match vector {
        SlotVector::Dense { dim, data } => {
            out.extend_from_slice(b"D");
            out.extend_from_slice(&dim.to_be_bytes());
            for value in data {
                out.extend_from_slice(&value.to_bits().to_be_bytes());
            }
        }
        SlotVector::Sparse { dim, entries } => {
            out.extend_from_slice(b"S");
            out.extend_from_slice(&dim.to_be_bytes());
            out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for entry in entries {
                out.extend_from_slice(&entry.idx.to_be_bytes());
                out.extend_from_slice(&entry.val.to_bits().to_be_bytes());
            }
        }
        SlotVector::Multi { .. } | SlotVector::Absent { .. } => {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                "deterministic encoder produced no concrete vector for its frozen weights probe",
                "Provide a complete encoder fixture so weights_sha binds the encoder's real output.",
            ));
        }
    }
    Ok(out)
}

/// Folds an already-serialized encoder output into the deterministic weights identity.
///
/// Split out so tests can drive the exact identity math with known output bytes and
/// assert that different encoder output yields a different `weights_sha`.
fn encoder_weights_identity_from(
    slot: &PanelSlotSpec,
    shape: &str,
    output_bytes: &[u8],
) -> [u8; 32] {
    sha256_digest(&[
        PANEL_SCHEMA_ID.as_bytes(),
        slot.key.as_bytes(),
        shape.as_bytes(),
        DETERMINISTIC_ENCODER_WEIGHTS_TAG,
        output_bytes,
    ])
}

/// Derives the deterministic S0-S17/S21 `weights_sha` from the encoder's actual
/// output on the frozen probe fixture.
///
/// This makes `weights_sha` a *measurement* of the encoder rather than a fixed
/// constant: any change to the encoder algorithm, its weights, or its frozen
/// goldens changes the fixture output and therefore the identity. Fails closed if
/// the encoder cannot produce a concrete vector for the fixture.
fn encoder_weights_identity(slot: &PanelSlotSpec, shape: &str) -> PanelResult<[u8; 32]> {
    let fixture = lenses::fixture_encoder_input();
    let output = lenses::encode_slot(slot.slot_id(), &fixture)?;
    let output_bytes = slot_vector_identity_bytes(&output)?;
    Ok(encoder_weights_identity_from(slot, shape, &output_bytes))
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
            guard_raw: false,
        },
        vector,
    )?;
    validate_vector_norm(contract.norm, &format!("lens {lens_id}"), vector)
}

fn validate_vector_norm(
    norm_policy: NormPolicy,
    subject: &str,
    vector: &SlotVector,
) -> PanelResult<()> {
    match norm_policy {
        NormPolicy::Unit { tolerance } => {
            let norm = vector_norm(vector).ok_or_else(|| {
                PanelError::new(
                    ASTRO_PANEL_VECTOR_INVALID,
                    format!("{subject} emitted absent vector for a unit-norm contract"),
                    "Use explicit Absent only for unavailable runtime paths, not registration probes.",
                )
            })?;
            if (norm - 1.0).abs() > tolerance {
                return Err(PanelError::new(
                    ASTRO_PANEL_VECTOR_INVALID,
                    format!("{subject} norm {norm:.6} outside unit tolerance {tolerance}"),
                    "Normalize the emitted vector or change the frozen contract norm policy.",
                ));
            }
        }
        NormPolicy::L1 { tolerance } => {
            let mass = vector_l1_mass(vector).ok_or_else(|| {
                PanelError::new(
                    ASTRO_PANEL_VECTOR_INVALID,
                    format!("{subject} emitted absent vector for an L1-norm contract"),
                    "Use explicit Absent only for unavailable runtime paths, not registration probes.",
                )
            })?;
            if (mass - 1.0).abs() > tolerance {
                return Err(PanelError::new(
                    ASTRO_PANEL_VECTOR_INVALID,
                    format!("{subject} L1 mass {mass:.6} outside tolerance {tolerance}"),
                    "L1-normalize the emitted distribution or change the frozen contract norm policy.",
                ));
            }
        }
        NormPolicy::Finite => {}
    }
    Ok(())
}

/// Validates one persisted/runtime vector against its frozen slot shape and norm.
///
/// Explicit [`SlotVector::Absent`] remains a valid representation for a genuinely
/// unavailable or inapplicable slot. Callers that are verifying a declared-present
/// semantic atom must additionally require a concrete vector.
pub fn validate_slot_vector_contract(slot_id: SlotId, vector: &SlotVector) -> PanelResult<()> {
    let slot = slot_spec(slot_id).ok_or_else(|| {
        PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("slot {slot_id} has no frozen panel contract"),
            "Restore the versioned frozen slot roster before reading or writing this vector.",
        )
    })?;
    validate_slot_shape(*slot, vector)?;
    if vector.is_absent() {
        return Ok(());
    }
    validate_vector_norm(slot.norm, &format!("slot {} ({slot_id})", slot.key), vector)
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

/// Returns the L1 mass (sum of absolute values) of a concrete vector, or `None` for
/// an absent slot. Used to validate an [`NormPolicy::L1`] probability-distribution slot.
fn vector_l1_mass(vector: &SlotVector) -> Option<f32> {
    let mass = match vector {
        SlotVector::Dense { data, .. } => data.iter().map(|value| value.abs()).sum::<f32>(),
        SlotVector::Sparse { entries, .. } => {
            entries.iter().map(|entry| entry.val.abs()).sum::<f32>()
        }
        SlotVector::Multi { tokens, .. } => tokens
            .iter()
            .flatten()
            .map(|value| value.abs())
            .sum::<f32>(),
        SlotVector::Absent { .. } => return None,
    };
    Some(mass)
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
