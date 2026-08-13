//! Frozen code-memory semantic atom registry for panel v3.
//!
//! The v1/v2 panel measures a curated set of code surfaces.  Panel v3 adds the
//! schema contract that makes *every* value emitted by the owned CBM SQLite
//! substrate independently addressable.  Each present atom has its own value
//! slot.  Missingness is represented without write amplification by one sparse
//! presence slot per row family; its dimensions are the stable rule ordinals.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use calyx_core::{Modality, SlotId, SlotShape, SlotVector, SparseEntry, content_address};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ASTRO_PANEL_CONTRACT_INVALID, ASTRO_PANEL_VECTOR_INVALID, NormPolicy, PanelError, PanelResult,
    PanelSlotSpec, embeddings::nomic_weights_identity,
};

/// First semantic slot id. S0-S23 remain byte-identical to panel v2.
pub const SEMANTIC_SLOT_START: u16 = 24;
/// First per-atom semantic value slot after the seven family-presence slots.
pub const SEMANTIC_VALUE_SLOT_START: u16 = 31;
/// Dimension of each family presence vector.
pub const SEMANTIC_PRESENCE_DIM: u32 = 256;
/// Dimension of deterministic categorical/path/set encodings.
pub const SEMANTIC_HASH_DIM: u32 = 65_536;
/// Versioned semantic registry schema used by the frozen panel-v3/v4 prefix.
pub const SEMANTIC_REGISTRY_SCHEMA: &str = "astro.cbm.semantic-registry.v1";
/// Registry schema for panel v5 and later. It gives each value lens an identity
/// independent of unrelated future additions while each frozen panel keeps its
/// exact ordered registry prefix.
pub const SEMANTIC_REGISTRY_SCHEMA_V2: &str = "astro.cbm.semantic-registry.v2";
/// Stable algorithm identity for exact structured encoders.
pub const SEMANTIC_ENCODER_ID: &str = "astro.cbm.semantic-encoders.v1";
/// Frozen framing contract for learned panel-v3 code/prose inputs.  The
/// modality prefix is part of the lens input, not an OOV fallback: the exact
/// source value follows it byte-for-byte.  It gives a legitimately present
/// empty/tokenless atom a concrete learned measurement while the legacy
/// embedding API retains its explicit empty/OOV `Absent` policy.
pub const SEMANTIC_LATENT_INPUT_SCHEMA: &str = "astro.cbm.semantic-latent-input.v1";

/// CBM row family whose atomic fields a rule covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticFamily {
    Project,
    FileHash,
    Node,
    Edge,
    ProjectSummary,
    NodeVector,
    TokenVector,
}

impl SemanticFamily {
    /// Complete frozen family order used by coverage manifests and verification.
    pub const ALL: [Self; 7] = [
        Self::Project,
        Self::FileHash,
        Self::Node,
        Self::Edge,
        Self::ProjectSummary,
        Self::NodeVector,
        Self::TokenVector,
    ];

    /// Stable family name used in persisted manifests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::FileHash => "file_hash",
            Self::Node => "node",
            Self::Edge => "edge",
            Self::ProjectSummary => "project_summary",
            Self::NodeVector => "node_vector",
            Self::TokenVector => "token_vector",
        }
    }

    /// Sparse presence slot for this family.
    pub const fn presence_slot(self) -> SlotId {
        SlotId::new(match self {
            Self::Project => 24,
            Self::FileHash => 25,
            Self::Node => 26,
            Self::Edge => 27,
            Self::ProjectSummary => 28,
            Self::NodeVector => 29,
            Self::TokenVector => 30,
        })
    }

    /// Resolves the exact persisted family name. Unknown names are schema drift.
    pub fn from_manifest_str(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value)
    }
}

/// Exact source type accepted by a semantic rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSourceType {
    Boolean,
    Integer,
    IntegerArray,
    Real,
    Text,
    TextArray,
    BlobI8x768,
}

/// One typed source atom handed to a panel-v3 lens. The enum deliberately has
/// no JSON catch-all variant: schema drift must be classified before measure.
#[derive(Clone, Debug, PartialEq)]
pub enum SemanticValue {
    Boolean(bool),
    Integer(i64),
    IntegerArray(Vec<i64>),
    Real(f64),
    Text(String),
    TextArray(Vec<String>),
    BlobI8x768(Vec<u8>),
}

impl SemanticValue {
    /// Exact registry source type represented by this value.
    pub const fn source_type(&self) -> SemanticSourceType {
        match self {
            Self::Boolean(_) => SemanticSourceType::Boolean,
            Self::Integer(_) => SemanticSourceType::Integer,
            Self::IntegerArray(_) => SemanticSourceType::IntegerArray,
            Self::Real(_) => SemanticSourceType::Real,
            Self::Text(_) => SemanticSourceType::Text,
            Self::TextArray(_) => SemanticSourceType::TextArray,
            Self::BlobI8x768(_) => SemanticSourceType::BlobI8x768,
        }
    }
}

impl SemanticSourceType {
    /// Stable source-type name used in manifests and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::IntegerArray => "integer_array",
            Self::Real => "real",
            Self::Text => "text",
            Self::TextArray => "text_array",
            Self::BlobI8x768 => "blob_i8x768",
        }
    }
}

/// Encoding semantics for one independently measurable atom.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticKind {
    Boolean,
    Numeric,
    NumericSet,
    Category,
    Reference,
    Path,
    Set,
    Temporal,
    LatentCode,
    LatentProse,
    ImportedVector,
}

impl SemanticKind {
    /// Stable kind name used in manifests and lens identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Numeric => "numeric",
            Self::NumericSet => "numeric_set",
            Self::Category => "category",
            Self::Reference => "reference",
            Self::Path => "path",
            Self::Set => "set",
            Self::Temporal => "temporal",
            Self::LatentCode => "latent_code",
            Self::LatentProse => "latent_prose",
            Self::ImportedVector => "imported_vector",
        }
    }

    /// Frozen output shape for this encoder/embedder class.
    pub const fn shape(self) -> SlotShape {
        match self {
            Self::Boolean => SlotShape::Dense(1),
            Self::Numeric | Self::Temporal => SlotShape::Dense(2),
            Self::NumericSet => SlotShape::Dense(6),
            Self::Category | Self::Reference | Self::Path | Self::Set => {
                SlotShape::Sparse(SEMANTIC_HASH_DIM)
            }
            Self::LatentCode | Self::LatentProse | Self::ImportedVector => SlotShape::Dense(768),
        }
    }

    /// Frozen norm policy for this encoder/embedder class.
    pub const fn norm(self) -> NormPolicy {
        match self {
            Self::LatentCode | Self::LatentProse | Self::ImportedVector => NormPolicy::unit(),
            _ => NormPolicy::Finite,
        }
    }

    /// Whether the value is a learned/imported semantic vector rather than an
    /// exact deterministic structured encoding.
    pub const fn is_embedding(self) -> bool {
        matches!(
            self,
            Self::LatentCode | Self::LatentProse | Self::ImportedVector
        )
    }
}

/// One frozen `(family,path,type) -> value lens` binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticRule {
    pub ordinal: u16,
    pub family: SemanticFamily,
    pub path: &'static str,
    pub source_type: SemanticSourceType,
    pub kind: SemanticKind,
    pub value_slot: u16,
    pub slot_key: &'static str,
}

macro_rules! rule {
    ($ord:literal, $slot:literal, $family:ident, $path:literal, $source:ident, $kind:ident, $key:literal) => {
        SemanticRule {
            ordinal: $ord,
            family: SemanticFamily::$family,
            path: $path,
            source_type: SemanticSourceType::$source,
            kind: SemanticKind::$kind,
            value_slot: $slot,
            slot_key: $key,
        }
    };
}

/// Frozen exhaustive schema for CBM semantic outputs.
///
/// Property arrays are decomposed to their typed child path. `edge.args` is not
/// treated as one JSON blob: its `i/e/k/v` children are independent rules.
pub const SEMANTIC_RULES: &[SemanticRule] = &[
    rule!(0, 31, Project, "name", Text, Category, "sem.project.name"),
    rule!(
        1,
        32,
        Project,
        "indexed_at",
        Text,
        Temporal,
        "sem.project.indexed_at"
    ),
    rule!(
        2,
        33,
        Project,
        "root_path",
        Text,
        Path,
        "sem.project.root_path"
    ),
    rule!(
        3,
        34,
        FileHash,
        "project",
        Text,
        Reference,
        "sem.file_hash.project"
    ),
    rule!(
        4,
        35,
        FileHash,
        "rel_path",
        Text,
        Path,
        "sem.file_hash.rel_path"
    ),
    rule!(
        5,
        36,
        FileHash,
        "sha256",
        Text,
        Category,
        "sem.file_hash.sha256"
    ),
    rule!(
        6,
        37,
        FileHash,
        "mtime_ns",
        Integer,
        Temporal,
        "sem.file_hash.mtime_ns"
    ),
    rule!(
        7,
        38,
        FileHash,
        "size",
        Integer,
        Numeric,
        "sem.file_hash.size"
    ),
    rule!(8, 39, Node, "id", Integer, Reference, "sem.node.id"),
    rule!(9, 40, Node, "project", Text, Reference, "sem.node.project"),
    rule!(10, 41, Node, "label", Text, Category, "sem.node.label"),
    rule!(11, 42, Node, "name", Text, Category, "sem.node.name"),
    rule!(12, 43, Node, "atom_id", Text, Reference, "sem.node.atom_id"),
    rule!(
        13,
        44,
        Node,
        "qualified_name",
        Text,
        Category,
        "sem.node.qualified_name"
    ),
    rule!(14, 45, Node, "file_path", Text, Path, "sem.node.file_path"),
    rule!(
        15,
        46,
        Node,
        "start_line",
        Integer,
        Numeric,
        "sem.node.start_line"
    ),
    rule!(
        16,
        47,
        Node,
        "end_line",
        Integer,
        Numeric,
        "sem.node.end_line"
    ),
    rule!(
        17,
        48,
        Node,
        "source_present",
        Boolean,
        Boolean,
        "sem.node.source_present"
    ),
    rule!(
        18,
        49,
        Node,
        "source_bytes",
        Text,
        LatentCode,
        "sem.node.source_bytes"
    ),
    rule!(
        19,
        50,
        Node,
        "source_sha256",
        Text,
        Category,
        "sem.node.source_sha256"
    ),
    rule!(
        20,
        51,
        Node,
        "start_byte",
        Integer,
        Numeric,
        "sem.node.start_byte"
    ),
    rule!(
        21,
        52,
        Node,
        "end_byte",
        Integer,
        Numeric,
        "sem.node.end_byte"
    ),
    rule!(
        22,
        53,
        Node,
        "properties.alloc_in_loop",
        Integer,
        Numeric,
        "sem.node.alloc_in_loop"
    ),
    rule!(
        23,
        54,
        Node,
        "properties.base_classes[]",
        TextArray,
        Set,
        "sem.node.base_classes"
    ),
    rule!(
        24,
        55,
        Node,
        "properties.base_sha",
        Text,
        Category,
        "sem.node.base_sha"
    ),
    rule!(
        25,
        56,
        Node,
        "properties.branch",
        Text,
        Category,
        "sem.node.branch"
    ),
    rule!(
        26,
        57,
        Node,
        "properties.bt",
        Text,
        LatentCode,
        "sem.node.bt"
    ),
    rule!(
        27,
        58,
        Node,
        "properties.callees",
        Text,
        Category,
        "sem.node.callees"
    ),
    rule!(
        28,
        59,
        Node,
        "properties.canonical_root",
        Text,
        Path,
        "sem.node.canonical_root"
    ),
    rule!(
        29,
        60,
        Node,
        "properties.change_count",
        Integer,
        Numeric,
        "sem.node.change_count"
    ),
    rule!(
        30,
        61,
        Node,
        "properties.code",
        Text,
        LatentCode,
        "sem.node.code"
    ),
    rule!(
        31,
        62,
        Node,
        "properties.cognitive",
        Integer,
        Numeric,
        "sem.node.cognitive"
    ),
    rule!(
        32,
        63,
        Node,
        "properties.complexity",
        Integer,
        Numeric,
        "sem.node.complexity"
    ),
    rule!(
        33,
        64,
        Node,
        "properties.decorator_tags[]",
        TextArray,
        Set,
        "sem.node.decorator_tags"
    ),
    rule!(
        34,
        65,
        Node,
        "properties.decorators[]",
        TextArray,
        Set,
        "sem.node.decorators"
    ),
    rule!(
        35,
        66,
        Node,
        "properties.docstring",
        Text,
        LatentProse,
        "sem.node.docstring"
    ),
    rule!(
        36,
        67,
        Node,
        "properties.end_byte",
        Integer,
        Numeric,
        "sem.node.property_end_byte"
    ),
    rule!(
        37,
        68,
        Node,
        "properties.extension",
        Text,
        Category,
        "sem.node.extension"
    ),
    rule!(38, 69, Node, "properties.fp", Text, Category, "sem.node.fp"),
    rule!(
        39,
        70,
        Node,
        "properties.git_common_dir",
        Text,
        Path,
        "sem.node.git_common_dir"
    ),
    rule!(
        40,
        71,
        Node,
        "properties.head_sha",
        Text,
        Category,
        "sem.node.head_sha"
    ),
    rule!(
        41,
        72,
        Node,
        "properties.is_detached",
        Boolean,
        Boolean,
        "sem.node.is_detached"
    ),
    rule!(
        42,
        73,
        Node,
        "properties.is_entry_point",
        Boolean,
        Boolean,
        "sem.node.is_entry_point"
    ),
    rule!(
        43,
        74,
        Node,
        "properties.is_exported",
        Boolean,
        Boolean,
        "sem.node.is_exported"
    ),
    rule!(
        44,
        75,
        Node,
        "properties.is_git",
        Boolean,
        Boolean,
        "sem.node.is_git"
    ),
    rule!(
        45,
        76,
        Node,
        "properties.is_test",
        Boolean,
        Boolean,
        "sem.node.is_test"
    ),
    rule!(
        46,
        77,
        Node,
        "properties.is_worktree",
        Boolean,
        Boolean,
        "sem.node.is_worktree"
    ),
    rule!(
        47,
        78,
        Node,
        "properties.key_path",
        Text,
        Path,
        "sem.node.key_path"
    ),
    rule!(
        48,
        79,
        Node,
        "properties.last_modified",
        Integer,
        Temporal,
        "sem.node.last_modified"
    ),
    rule!(
        49,
        80,
        Node,
        "properties.linear_scan_in_loop",
        Integer,
        Numeric,
        "sem.node.linear_scan_in_loop"
    ),
    rule!(
        50,
        81,
        Node,
        "properties.lines",
        Integer,
        Numeric,
        "sem.node.lines"
    ),
    rule!(
        51,
        82,
        Node,
        "properties.loop_count",
        Integer,
        Numeric,
        "sem.node.loop_count"
    ),
    rule!(
        52,
        83,
        Node,
        "properties.loop_depth",
        Integer,
        Numeric,
        "sem.node.loop_depth"
    ),
    rule!(
        53,
        84,
        Node,
        "properties.max_access_depth",
        Integer,
        Numeric,
        "sem.node.max_access_depth"
    ),
    rule!(
        54,
        85,
        Node,
        "properties.message",
        Text,
        LatentProse,
        "sem.node.message"
    ),
    rule!(
        55,
        86,
        Node,
        "properties.method",
        Text,
        Category,
        "sem.node.method"
    ),
    rule!(
        56,
        87,
        Node,
        "properties.missing",
        Boolean,
        Boolean,
        "sem.node.missing"
    ),
    rule!(
        57,
        88,
        Node,
        "properties.node_type",
        Text,
        Category,
        "sem.node.node_type"
    ),
    rule!(
        58,
        89,
        Node,
        "properties.operation",
        Text,
        Category,
        "sem.node.operation"
    ),
    rule!(
        59,
        90,
        Node,
        "properties.param_count",
        Integer,
        Numeric,
        "sem.node.param_count"
    ),
    rule!(
        60,
        91,
        Node,
        "properties.param_names[]",
        TextArray,
        Set,
        "sem.node.param_names"
    ),
    rule!(
        61,
        92,
        Node,
        "properties.param_types[]",
        TextArray,
        Set,
        "sem.node.param_types"
    ),
    rule!(
        62,
        93,
        Node,
        "properties.parent_class",
        Text,
        Reference,
        "sem.node.parent_class"
    ),
    rule!(
        63,
        94,
        Node,
        "properties.recursion_in_loop",
        Boolean,
        Boolean,
        "sem.node.recursion_in_loop"
    ),
    rule!(
        64,
        95,
        Node,
        "properties.recursive",
        Boolean,
        Boolean,
        "sem.node.recursive"
    ),
    rule!(
        65,
        96,
        Node,
        "properties.remediation",
        Text,
        LatentProse,
        "sem.node.remediation"
    ),
    rule!(
        66,
        97,
        Node,
        "properties.return_type",
        Text,
        Category,
        "sem.node.return_type"
    ),
    rule!(
        67,
        98,
        Node,
        "properties.root_exists",
        Boolean,
        Boolean,
        "sem.node.root_exists"
    ),
    rule!(
        68,
        99,
        Node,
        "properties.self_recursive",
        Boolean,
        Boolean,
        "sem.node.self_recursive"
    ),
    rule!(
        69,
        100,
        Node,
        "properties.signature",
        Text,
        LatentCode,
        "sem.node.signature"
    ),
    rule!(
        70,
        101,
        Node,
        "properties.source",
        Text,
        LatentProse,
        "sem.node.property_source"
    ),
    rule!(
        71,
        102,
        Node,
        "properties.sp",
        Text,
        Category,
        "sem.node.sp"
    ),
    rule!(
        72,
        103,
        Node,
        "properties.st",
        Text,
        Category,
        "sem.node.st"
    ),
    rule!(
        73,
        104,
        Node,
        "properties.start_byte",
        Integer,
        Numeric,
        "sem.node.property_start_byte"
    ),
    rule!(
        74,
        105,
        Node,
        "properties.structured_classification",
        Text,
        Category,
        "sem.node.structured_classification"
    ),
    rule!(
        75,
        106,
        Node,
        "properties.structured_classification_provenance",
        Text,
        Category,
        "sem.node.structured_classification_provenance"
    ),
    rule!(
        76,
        107,
        Node,
        "properties.structured_first_end_byte",
        Integer,
        Numeric,
        "sem.node.structured_first_end_byte"
    ),
    rule!(
        77,
        108,
        Node,
        "properties.structured_first_start_byte",
        Integer,
        Numeric,
        "sem.node.structured_first_start_byte"
    ),
    rule!(
        78,
        109,
        Node,
        "properties.structured_last_end_byte",
        Integer,
        Numeric,
        "sem.node.structured_last_end_byte"
    ),
    rule!(
        79,
        110,
        Node,
        "properties.structured_last_start_byte",
        Integer,
        Numeric,
        "sem.node.structured_last_start_byte"
    ),
    rule!(
        80,
        111,
        Node,
        "properties.structured_occurrence_count",
        Integer,
        Numeric,
        "sem.node.structured_occurrence_count"
    ),
    rule!(
        81,
        112,
        Node,
        "properties.structured_occurrence_sha256",
        Text,
        Category,
        "sem.node.structured_occurrence_sha256"
    ),
    rule!(
        82,
        113,
        Node,
        "properties.structured_path",
        Text,
        Path,
        "sem.node.structured_path"
    ),
    rule!(
        83,
        114,
        Node,
        "properties.structured_schema_path_count",
        Integer,
        Numeric,
        "sem.node.structured_schema_path_count"
    ),
    rule!(
        84,
        115,
        Node,
        "properties.transitive_loop_depth",
        Integer,
        Numeric,
        "sem.node.transitive_loop_depth"
    ),
    rule!(
        85,
        116,
        Node,
        "properties.unguarded_recursion",
        Boolean,
        Boolean,
        "sem.node.unguarded_recursion"
    ),
    rule!(
        86,
        117,
        Node,
        "properties.worktree_root",
        Text,
        Path,
        "sem.node.worktree_root"
    ),
    rule!(
        87,
        118,
        NodeVector,
        "node_id",
        Integer,
        Reference,
        "sem.node_vector.node_id"
    ),
    rule!(
        88,
        119,
        NodeVector,
        "project",
        Text,
        Reference,
        "sem.node_vector.project"
    ),
    rule!(
        89,
        120,
        NodeVector,
        "vector",
        BlobI8x768,
        ImportedVector,
        "sem.node_vector.vector"
    ),
    rule!(90, 121, Edge, "id", Integer, Reference, "sem.edge.id"),
    rule!(
        91,
        122,
        Edge,
        "project",
        Text,
        Reference,
        "sem.edge.project"
    ),
    rule!(
        92,
        123,
        Edge,
        "source_id",
        Integer,
        Reference,
        "sem.edge.source_id"
    ),
    rule!(
        93,
        124,
        Edge,
        "target_id",
        Integer,
        Reference,
        "sem.edge.target_id"
    ),
    rule!(94, 125, Edge, "type", Text, Category, "sem.edge.type"),
    rule!(
        95,
        126,
        Edge,
        "local_name_gen",
        Text,
        Category,
        "sem.edge.local_name_gen"
    ),
    rule!(
        96,
        127,
        Edge,
        "preprocess_context_id_gen",
        Text,
        Reference,
        "sem.edge.preprocess_context_id_gen"
    ),
    rule!(
        97,
        128,
        Edge,
        "properties.args[].i",
        IntegerArray,
        NumericSet,
        "sem.edge.args_i"
    ),
    rule!(
        98,
        129,
        Edge,
        "properties.args[].e",
        TextArray,
        LatentCode,
        "sem.edge.args_e"
    ),
    rule!(
        99,
        130,
        Edge,
        "properties.args[].k",
        TextArray,
        Set,
        "sem.edge.args_k"
    ),
    rule!(
        100,
        131,
        Edge,
        "properties.args[].v",
        TextArray,
        LatentCode,
        "sem.edge.args_v"
    ),
    rule!(
        101,
        132,
        Edge,
        "properties.base_sha",
        Text,
        Category,
        "sem.edge.base_sha"
    ),
    rule!(
        102,
        133,
        Edge,
        "properties.binding_kind",
        Text,
        Category,
        "sem.edge.binding_kind"
    ),
    rule!(
        103,
        134,
        Edge,
        "properties.branch",
        Text,
        Category,
        "sem.edge.branch"
    ),
    rule!(
        104,
        135,
        Edge,
        "properties.callee",
        Text,
        Reference,
        "sem.edge.callee"
    ),
    rule!(
        105,
        136,
        Edge,
        "properties.candidates",
        Integer,
        Numeric,
        "sem.edge.candidates"
    ),
    rule!(
        106,
        137,
        Edge,
        "properties.canonical_root",
        Text,
        Path,
        "sem.edge.canonical_root"
    ),
    rule!(
        107,
        138,
        Edge,
        "properties.confidence",
        Real,
        Numeric,
        "sem.edge.confidence"
    ),
    rule!(
        108,
        139,
        Edge,
        "properties.config_key",
        Text,
        Reference,
        "sem.edge.config_key"
    ),
    rule!(
        109,
        140,
        Edge,
        "properties.coupling_score",
        Real,
        Numeric,
        "sem.edge.coupling_score"
    ),
    rule!(
        110,
        141,
        Edge,
        "properties.decorator",
        Text,
        Category,
        "sem.edge.decorator"
    ),
    rule!(
        111,
        142,
        Edge,
        "properties.dependency_kind",
        Text,
        Category,
        "sem.edge.dependency_kind"
    ),
    rule!(
        112,
        143,
        Edge,
        "properties.git_common_dir",
        Text,
        Path,
        "sem.edge.git_common_dir"
    ),
    rule!(
        113,
        144,
        Edge,
        "properties.head_sha",
        Text,
        Category,
        "sem.edge.head_sha"
    ),
    rule!(
        114,
        145,
        Edge,
        "properties.is_detached",
        Boolean,
        Boolean,
        "sem.edge.is_detached"
    ),
    rule!(
        115,
        146,
        Edge,
        "properties.is_git",
        Boolean,
        Boolean,
        "sem.edge.is_git"
    ),
    rule!(
        116,
        147,
        Edge,
        "properties.is_worktree",
        Boolean,
        Boolean,
        "sem.edge.is_worktree"
    ),
    rule!(
        117,
        148,
        Edge,
        "properties.jaccard",
        Real,
        Numeric,
        "sem.edge.jaccard"
    ),
    rule!(
        118,
        149,
        Edge,
        "properties.key",
        Text,
        Reference,
        "sem.edge.key"
    ),
    rule!(
        119,
        150,
        Edge,
        "properties.last_co_change",
        Integer,
        Temporal,
        "sem.edge.last_co_change"
    ),
    rule!(
        120,
        151,
        Edge,
        "properties.line",
        Integer,
        Numeric,
        "sem.edge.line"
    ),
    rule!(
        121,
        152,
        Edge,
        "properties.local_name",
        Text,
        Category,
        "sem.edge.local_name"
    ),
    rule!(
        122,
        153,
        Edge,
        "properties.preprocess_context_id",
        Text,
        Reference,
        "sem.edge.preprocess_context_id"
    ),
    rule!(
        123,
        154,
        Edge,
        "properties.resource_kind",
        Text,
        Category,
        "sem.edge.resource_kind"
    ),
    rule!(
        124,
        155,
        Edge,
        "properties.root_exists",
        Boolean,
        Boolean,
        "sem.edge.root_exists"
    ),
    rule!(
        125,
        156,
        Edge,
        "properties.same_file",
        Boolean,
        Boolean,
        "sem.edge.same_file"
    ),
    rule!(
        126,
        157,
        Edge,
        "properties.score",
        Real,
        Numeric,
        "sem.edge.score"
    ),
    rule!(
        127,
        158,
        Edge,
        "properties.strategy",
        Text,
        Category,
        "sem.edge.strategy"
    ),
    rule!(
        128,
        159,
        Edge,
        "properties.url_path",
        Text,
        Path,
        "sem.edge.url_path"
    ),
    rule!(
        129,
        160,
        Edge,
        "properties.via",
        Text,
        Category,
        "sem.edge.via"
    ),
    rule!(
        130,
        161,
        Edge,
        "properties.worktree_root",
        Text,
        Path,
        "sem.edge.worktree_root"
    ),
    rule!(
        131,
        162,
        ProjectSummary,
        "project",
        Text,
        Reference,
        "sem.project_summary.project"
    ),
    rule!(
        132,
        163,
        ProjectSummary,
        "summary",
        Text,
        LatentProse,
        "sem.project_summary.summary"
    ),
    rule!(
        133,
        164,
        ProjectSummary,
        "source_hash",
        Text,
        Category,
        "sem.project_summary.source_hash"
    ),
    rule!(
        134,
        165,
        ProjectSummary,
        "created_at",
        Text,
        Temporal,
        "sem.project_summary.created_at"
    ),
    rule!(
        135,
        166,
        ProjectSummary,
        "updated_at",
        Text,
        Temporal,
        "sem.project_summary.updated_at"
    ),
    rule!(
        136,
        167,
        TokenVector,
        "id",
        Integer,
        Reference,
        "sem.token_vector.id"
    ),
    rule!(
        137,
        168,
        TokenVector,
        "project",
        Text,
        Reference,
        "sem.token_vector.project"
    ),
    rule!(
        138,
        169,
        TokenVector,
        "token",
        Text,
        Category,
        "sem.token_vector.token"
    ),
    rule!(
        139,
        170,
        TokenVector,
        "vector",
        BlobI8x768,
        ImportedVector,
        "sem.token_vector.vector"
    ),
    rule!(
        140,
        171,
        TokenVector,
        "idf",
        Integer,
        Numeric,
        "sem.token_vector.idf"
    ),
    rule!(
        141,
        172,
        Node,
        "node_vector",
        BlobI8x768,
        ImportedVector,
        "sem.node.node_vector"
    ),
    rule!(
        142,
        173,
        Edge,
        "properties.args.count",
        Integer,
        Numeric,
        "sem.edge.args_count"
    ),
    rule!(
        143,
        174,
        Edge,
        "url_path_gen",
        Text,
        Path,
        "sem.edge.url_path_gen"
    ),
    rule!(
        144,
        175,
        Node,
        "properties.compile_context_count",
        Integer,
        Numeric,
        "sem.node.compile_context_count"
    ),
    rule!(
        145,
        176,
        Node,
        "properties.compile_context_code",
        Text,
        Category,
        "sem.node.compile_context_code"
    ),
    rule!(
        146,
        177,
        Node,
        "properties.compile_context_ids[]",
        TextArray,
        Set,
        "sem.node.compile_context_ids"
    ),
    rule!(
        147,
        178,
        Node,
        "properties.compile_context_reason",
        Text,
        Category,
        "sem.node.compile_context_reason"
    ),
    rule!(
        148,
        179,
        Node,
        "properties.compile_context_state",
        Text,
        Category,
        "sem.node.compile_context_state"
    ),
    rule!(
        149,
        180,
        Node,
        "properties.compiler_language_applied",
        Boolean,
        Boolean,
        "sem.node.compiler_language_applied"
    ),
    rule!(
        150,
        181,
        Node,
        "properties.declared_language",
        Text,
        Category,
        "sem.node.declared_language"
    ),
    rule!(
        151,
        182,
        Node,
        "properties.effective_language",
        Text,
        Category,
        "sem.node.effective_language"
    ),
    rule!(
        152,
        183,
        Node,
        "properties.effective_language_family",
        Text,
        Category,
        "sem.node.effective_language_family"
    ),
    rule!(
        153,
        184,
        Node,
        "properties.language_provenance",
        Text,
        Category,
        "sem.node.language_provenance"
    ),
    rule!(
        154,
        185,
        Edge,
        "properties.co_changes",
        Integer,
        Numeric,
        "sem.edge.co_changes"
    ),
    rule!(
        155,
        186,
        Node,
        "properties.outcome_class",
        Text,
        Category,
        "sem.node.outcome_class"
    ),
    rule!(
        156,
        187,
        Node,
        "properties.defect_code",
        Text,
        Category,
        "sem.node.defect_code"
    ),
    rule!(
        157,
        188,
        Node,
        "properties.phase",
        Text,
        Category,
        "sem.node.phase"
    ),
    rule!(
        158,
        189,
        Node,
        "properties.file_sha256",
        Text,
        Category,
        "sem.node.file_sha256"
    ),
    rule!(
        159,
        190,
        Node,
        "properties.site_identity",
        Text,
        Reference,
        "sem.node.site_identity"
    ),
    rule!(
        160,
        191,
        Node,
        "properties.requested",
        Integer,
        Numeric,
        "sem.node.requested"
    ),
    rule!(
        161,
        192,
        Node,
        "properties.discarded_atom_facts",
        Integer,
        Numeric,
        "sem.node.discarded_atom_facts"
    ),
    rule!(
        162,
        193,
        Node,
        "properties.discarded_relationship_facts",
        Integer,
        Numeric,
        "sem.node.discarded_relationship_facts"
    ),
    rule!(
        163,
        194,
        Node,
        "properties.unmeasured_file",
        Boolean,
        Boolean,
        "sem.node.unmeasured_file"
    ),
    rule!(
        164,
        195,
        Edge,
        "properties.outcome_class",
        Text,
        Category,
        "sem.edge.outcome_class"
    ),
    rule!(
        165,
        196,
        Node,
        "properties.broker",
        Text,
        Category,
        "sem.node.broker"
    ),
    rule!(
        166,
        197,
        Node,
        "properties.transport",
        Text,
        Category,
        "sem.node.transport"
    ),
    rule!(
        167,
        198,
        Edge,
        "properties.broker",
        Text,
        Category,
        "sem.edge.broker"
    ),
    rule!(
        168,
        199,
        Edge,
        "properties.transport",
        Text,
        Category,
        "sem.edge.transport"
    ),
];

/// Number of rules frozen into the panel-v3/v4 prefix.
pub const SEMANTIC_V4_RULE_COUNT: usize = 155;
/// Last semantic slot id in the panel-v3/v4 frozen roster.
pub const SEMANTIC_V4_SLOT_END: u16 = 185;
/// Number of rules frozen into the panel-v5 prefix.
pub const SEMANTIC_V5_RULE_COUNT: usize = 165;
/// Last semantic slot id in the panel-v5 frozen roster.
pub const SEMANTIC_V5_SLOT_END: u16 = 195;
/// Last semantic slot id in the current frozen roster.
pub const SEMANTIC_SLOT_END: u16 = 199;

const PRESENCE_SLOTS: &[PanelSlotSpec] = &[
    presence_slot(24, "sem.presence.project"),
    presence_slot(25, "sem.presence.file_hash"),
    presence_slot(26, "sem.presence.node"),
    presence_slot(27, "sem.presence.edge"),
    presence_slot(28, "sem.presence.project_summary"),
    presence_slot(29, "sem.presence.node_vector"),
    presence_slot(30, "sem.presence.token_vector"),
];

const fn presence_slot(slot: u16, key: &'static str) -> PanelSlotSpec {
    PanelSlotSpec {
        slot,
        key,
        shape: SlotShape::Sparse(SEMANTIC_PRESENCE_DIM),
        modality: Modality::Structured,
        norm: NormPolicy::Finite,
        retrieval_only: false,
        excluded_from_dedup: false,
        guard_raw: false,
    }
}

fn slot_spec_for_rule(rule: &SemanticRule) -> PanelSlotSpec {
    PanelSlotSpec {
        slot: rule.value_slot,
        key: rule.slot_key,
        shape: rule.kind.shape(),
        modality: match rule.kind {
            SemanticKind::LatentCode => Modality::Code,
            SemanticKind::LatentProse => Modality::Text,
            _ => Modality::Structured,
        },
        norm: rule.kind.norm(),
        retrieval_only: false,
        excluded_from_dedup: false,
        guard_raw: false,
    }
}

/// Frozen semantic slot specifications used by panel v3 and v4. This prefix
/// must never be rebuilt from the current registry or old rosters would drift.
pub static SEMANTIC_SLOT_SPECS_V4: LazyLock<Vec<PanelSlotSpec>> = LazyLock::new(|| {
    let mut out = PRESENCE_SLOTS.to_vec();
    out.extend(
        SEMANTIC_RULES[..SEMANTIC_V4_RULE_COUNT]
            .iter()
            .map(slot_spec_for_rule),
    );
    out
});

/// Frozen semantic slot specifications used by panel v5. This prefix must
/// remain byte-identical when later producer atoms append new rules.
pub static SEMANTIC_SLOT_SPECS_V5: LazyLock<Vec<PanelSlotSpec>> = LazyLock::new(|| {
    let mut out = PRESENCE_SLOTS.to_vec();
    out.extend(
        SEMANTIC_RULES[..SEMANTIC_V5_RULE_COUNT]
            .iter()
            .map(slot_spec_for_rule),
    );
    out
});

/// Frozen current semantic slot specifications.
pub static SEMANTIC_SLOT_SPECS: LazyLock<Vec<PanelSlotSpec>> = LazyLock::new(|| {
    let mut out = PRESENCE_SLOTS.to_vec();
    out.extend(SEMANTIC_RULES.iter().map(slot_spec_for_rule));
    out
});

static SEMANTIC_RULE_INDEX: LazyLock<
    BTreeMap<(SemanticFamily, SemanticSourceType), BTreeMap<&'static str, &'static SemanticRule>>,
> = LazyLock::new(|| {
    let mut index = BTreeMap::<
        (SemanticFamily, SemanticSourceType),
        BTreeMap<&'static str, &'static SemanticRule>,
    >::new();
    for rule in SEMANTIC_RULES {
        let prior = index
            .entry((rule.family, rule.source_type))
            .or_default()
            .insert(rule.path, rule);
        assert!(prior.is_none(), "duplicate frozen semantic rule key");
    }
    index
});

static SEMANTIC_FAMILY_RULE_COUNTS: LazyLock<BTreeMap<SemanticFamily, usize>> =
    LazyLock::new(|| {
        let mut counts = BTreeMap::new();
        for rule in SEMANTIC_RULES {
            *counts.entry(rule.family).or_default() += 1;
        }
        counts
    });

/// Looks up an exact schema rule. Unknown paths or type drift return `None` and
/// therefore cannot be silently routed through a generic JSON encoder.
pub fn semantic_rule(
    family: SemanticFamily,
    path: &str,
    source_type: SemanticSourceType,
) -> Option<&'static SemanticRule> {
    SEMANTIC_RULE_INDEX
        .get(&(family, source_type))?
        .get(path)
        .copied()
}

/// Looks up a semantic rule by its value slot.
pub fn semantic_rule_by_slot(slot: SlotId) -> Option<&'static SemanticRule> {
    let index = usize::from(slot.get().checked_sub(SEMANTIC_VALUE_SLOT_START)?);
    let rule = SEMANTIC_RULES.get(index)?;
    (rule.value_slot == slot.get()).then_some(rule)
}

/// Number of independently typed value rules registered for one row family.
pub fn semantic_rule_count_for_family(family: SemanticFamily) -> usize {
    SEMANTIC_FAMILY_RULE_COUNTS
        .get(&family)
        .copied()
        .unwrap_or(0)
}

/// Number of independently typed rules in a family for one frozen panel
/// version. Older panels see only their immutable registry prefix.
pub fn semantic_rule_count_for_family_version(family: SemanticFamily, version: u32) -> usize {
    let rules = match version {
        0..=crate::PANEL_V4_VERSION => &SEMANTIC_RULES[..SEMANTIC_V4_RULE_COUNT],
        crate::PANEL_V5_VERSION => &SEMANTIC_RULES[..SEMANTIC_V5_RULE_COUNT],
        _ => SEMANTIC_RULES,
    };
    rules.iter().filter(|rule| rule.family == family).count()
}

/// True for a family-level semantic presence slot.
pub fn is_semantic_presence_slot(slot: SlotId) -> bool {
    PRESENCE_SLOTS.iter().any(|spec| spec.slot_id() == slot)
}

/// Content address of the exact ordered registry manifest.
pub fn semantic_registry_sha256() -> [u8; 32] {
    semantic_registry_sha256_for_panel(crate::CURRENT_SEMANTIC_PANEL_VERSION)
}

/// Content address of the exact ordered registry manifest for a frozen panel
/// version. Earlier panels retain their original prefix and schema bytes.
pub fn semantic_registry_sha256_for_panel(version: u32) -> [u8; 32] {
    let (schema, rules) = match version {
        0..=crate::PANEL_V4_VERSION => (
            SEMANTIC_REGISTRY_SCHEMA,
            &SEMANTIC_RULES[..SEMANTIC_V4_RULE_COUNT],
        ),
        crate::PANEL_V5_VERSION => (
            SEMANTIC_REGISTRY_SCHEMA_V2,
            &SEMANTIC_RULES[..SEMANTIC_V5_RULE_COUNT],
        ),
        _ => (SEMANTIC_REGISTRY_SCHEMA_V2, SEMANTIC_RULES),
    };
    let mut hasher = Sha256::new();
    hasher.update(schema.as_bytes());
    for rule in rules {
        for part in [
            rule.ordinal.to_string(),
            rule.family.as_str().to_string(),
            rule.path.to_string(),
            rule.source_type.as_str().to_string(),
            rule.kind.as_str().to_string(),
            rule.value_slot.to_string(),
            rule.slot_key.to_string(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Frozen weights/spec identity for a semantic slot.
pub fn semantic_weights_identity(slot: SlotId) -> PanelResult<[u8; 32]> {
    semantic_weights_identity_for_panel(slot, crate::CURRENT_SEMANTIC_PANEL_VERSION)
}

/// Frozen weights/spec identity for a semantic slot in one panel version.
///
/// Panel v3/v4 preserve the historical whole-registry identity. Panel v5 and
/// later value lenses bind only their own typed rule, so appending an unrelated
/// future lens cannot mutate an existing lens id. Presence lenses still bind the
/// complete version-specific registry because each new ordinal changes their
/// interpreted dimensions.
pub fn semantic_weights_identity_for_panel(slot: SlotId, version: u32) -> PanelResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_ENCODER_ID.as_bytes());
    if is_semantic_presence_slot(slot) {
        hasher.update(semantic_registry_sha256_for_panel(version));
        hasher.update(b"presence");
        hasher.update(slot.get().to_be_bytes());
        return Ok(hasher.finalize().into());
    }
    let rule = semantic_rule_by_slot(slot).ok_or_else(|| {
        PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("semantic slot {slot} has no frozen registry rule"),
            "Restore the exact panel-v3 semantic registry before measuring code-memory atoms.",
        )
    })?;
    if version <= crate::PANEL_V4_VERSION {
        hasher.update(semantic_registry_sha256_for_panel(version));
    } else {
        hasher.update(SEMANTIC_REGISTRY_SCHEMA_V2.as_bytes());
        hasher.update(rule.ordinal.to_be_bytes());
        hasher.update(rule.value_slot.to_be_bytes());
    }
    hasher.update(rule.family.as_str().as_bytes());
    hasher.update(rule.path.as_bytes());
    hasher.update(rule.source_type.as_str().as_bytes());
    hasher.update(rule.kind.as_str().as_bytes());
    hasher.update(rule.slot_key.as_bytes());
    if matches!(
        rule.kind,
        SemanticKind::LatentCode | SemanticKind::LatentProse
    ) {
        hasher.update(SEMANTIC_LATENT_INPUT_SCHEMA.as_bytes());
        hasher.update(nomic_weights_identity());
    }
    Ok(hasher.finalize().into())
}

/// Builds the frozen learned-embedding input for one present latent semantic
/// atom.  The complete original text is retained after a stable modality word,
/// so empty, whitespace-only, punctuation-only, and all-OOV values still pass
/// through the real learned Nomic table without inventing a pseudo-vector.
pub fn latent_embedding_input(rule: &SemanticRule, value: &SemanticValue) -> PanelResult<String> {
    if !matches!(
        rule.kind,
        SemanticKind::LatentCode | SemanticKind::LatentProse
    ) {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "semantic rule {} is {}, not a learned latent lens",
                rule.path,
                rule.kind.as_str()
            ),
            "Route only latent code/prose rules through the frozen latent input frame.",
        ));
    }
    if value.source_type() != rule.source_type {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "semantic rule {} expects {}, received {}",
                rule.path,
                rule.source_type.as_str(),
                value.source_type().as_str()
            ),
            "Update the versioned registry for a real schema change; never coerce a drifted source type.",
        ));
    }
    let text = match value {
        SemanticValue::Text(text) => text.clone(),
        SemanticValue::TextArray(values) => values.join("\n"),
        _ => {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "latent semantic rule {} did not receive text or a text array",
                    rule.path
                ),
                "Correct the frozen semantic source-type binding before measurement.",
            ));
        }
    };
    let modality = match rule.kind {
        SemanticKind::LatentCode => "code",
        SemanticKind::LatentProse => "text",
        _ => unreachable!("validated latent kind"),
    };
    let mut framed = String::with_capacity(modality.len() + 1 + text.len());
    framed.push_str(modality);
    framed.push('\n');
    framed.push_str(&text);
    Ok(framed)
}

/// Builds the family presence vector and rejects duplicate/out-of-range rules.
pub fn encode_presence<'a>(
    family: SemanticFamily,
    rules: impl IntoIterator<Item = &'a SemanticRule>,
) -> PanelResult<SlotVector> {
    let mut ordinals = BTreeSet::new();
    for rule in rules {
        if rule.family != family {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!(
                    "presence vector for {} received {} rule {}",
                    family.as_str(),
                    rule.family.as_str(),
                    rule.path
                ),
                "Build each presence vector only from rules in its own row family.",
            ));
        }
        if u32::from(rule.ordinal) >= SEMANTIC_PRESENCE_DIM || !ordinals.insert(rule.ordinal) {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!(
                    "invalid or duplicate semantic rule ordinal {}",
                    rule.ordinal
                ),
                "Keep semantic rule ordinals unique and within the frozen presence dimension.",
            ));
        }
    }
    Ok(SlotVector::Sparse {
        dim: SEMANTIC_PRESENCE_DIM,
        entries: ordinals
            .into_iter()
            .map(|ordinal| SparseEntry {
                idx: u32::from(ordinal),
                val: 1.0,
            })
            .collect(),
    })
}

/// Deterministically encodes one boolean atom.
pub fn encode_boolean(value: bool) -> SlotVector {
    SlotVector::Dense {
        dim: 1,
        data: vec![if value { 1.0 } else { 0.0 }],
    }
}

/// Deterministically encodes one finite exact numeric atom as raw + signed
/// log1p views. The exact f64 remains in the constellation scalar sidecar.
pub fn encode_numeric(value: f64, path: &str) -> PanelResult<SlotVector> {
    if !value.is_finite() || value < f64::from(f32::MIN) || value > f64::from(f32::MAX) {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("semantic numeric atom {path}={value} cannot be represented as finite f32"),
            "Repair the source numeric value or commission a wider frozen numeric lens.",
        ));
    }
    let log = value.signum() * value.abs().ln_1p();
    Ok(SlotVector::Dense {
        dim: 2,
        data: vec![value as f32, log as f32],
    })
}

/// Deterministically encodes a non-empty ordered collection of exact integers
/// as count/min/max/mean/population-standard-deviation/mean-signed-log1p.
/// Canonical input bytes retain every source integer and its order; this lens is
/// a numeric-distribution view, not a replacement for those exact bytes.
pub fn encode_numeric_set(values: &[i64], path: &str) -> PanelResult<SlotVector> {
    if values.is_empty() {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("semantic numeric-set atom {path} is present but empty"),
            "Omit an absent child path; only pass a numeric set when the source contains at least one integer.",
        ));
    }
    let count = values.len() as f64;
    let min = *values.iter().min().expect("non-empty numeric set") as f64;
    let max = *values.iter().max().expect("non-empty numeric set") as f64;
    let mean = values.iter().map(|value| *value as f64).sum::<f64>() / count;
    let variance = values
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / count;
    let signed_log_mean = values
        .iter()
        .map(|value| {
            let value = *value as f64;
            value.signum() * value.abs().ln_1p()
        })
        .sum::<f64>()
        / count;
    let encoded = [count, min, max, mean, variance.sqrt(), signed_log_mean];
    if encoded.iter().any(|value| {
        !value.is_finite() || *value < f64::from(f32::MIN) || *value > f64::from(f32::MAX)
    }) {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!(
                "semantic numeric-set atom {path} cannot be represented as six finite f32 statistics"
            ),
            "Repair the source integer collection or commission a wider frozen numeric-set lens.",
        ));
    }
    Ok(SlotVector::Dense {
        dim: 6,
        data: encoded.into_iter().map(|value| value as f32).collect(),
    })
}

/// Deterministic signed feature-hash encoding for category/reference/set atoms.
pub fn encode_hashed<'a>(
    rule: &SemanticRule,
    values: impl IntoIterator<Item = &'a str>,
) -> PanelResult<SlotVector> {
    let mut bins = BTreeMap::<u32, f32>::new();
    let mut count = 0_usize;
    for value in values {
        count += 1;
        let value = if value.is_empty() { "<empty>" } else { value };
        let digest = content_address([
            SEMANTIC_ENCODER_ID.as_bytes(),
            rule.slot_key.as_bytes(),
            value.as_bytes(),
        ]);
        let idx = u32::from_be_bytes(digest[0..4].try_into().expect("four hash bytes"))
            % SEMANTIC_HASH_DIM;
        let sign = if digest[4] & 1 == 0 { 1.0 } else { -1.0 };
        *bins.entry(idx).or_default() += sign;
    }
    if count == 0 {
        let digest = content_address([
            SEMANTIC_ENCODER_ID.as_bytes(),
            rule.slot_key.as_bytes(),
            b"<empty-set>".as_slice(),
        ]);
        let idx = u32::from_be_bytes(digest[0..4].try_into().expect("four hash bytes"))
            % SEMANTIC_HASH_DIM;
        let sign = if digest[4] & 1 == 0 { 1.0 } else { -1.0 };
        bins.insert(idx, sign);
    }
    Ok(SlotVector::Sparse {
        dim: SEMANTIC_HASH_DIM,
        entries: bins
            .into_iter()
            .filter(|(_, value)| *value != 0.0)
            .map(|(idx, val)| SparseEntry { idx, val })
            .collect(),
    })
}

/// Hierarchy-aware path encoding: the full normalized path and every ancestor
/// contribute independent signed features to the rule's sparse slot.
pub fn encode_path(rule: &SemanticRule, value: &str) -> PanelResult<SlotVector> {
    let normalized = value.replace('\\', "/");
    let mut parts = Vec::new();
    let mut prefix = String::new();
    for component in normalized.split('/').filter(|part| !part.is_empty()) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        parts.push(prefix.clone());
    }
    if parts.is_empty() {
        parts.push("<empty>".to_string());
    }
    encode_hashed(rule, parts.iter().map(String::as_str))
}

/// Encodes a structured semantic value. Learned latent-text slots are rejected
/// here so the caller must route them through the frozen embedding runtime.
pub fn encode_structured_value(
    rule: &SemanticRule,
    value: &SemanticValue,
) -> PanelResult<SlotVector> {
    if value.source_type() != rule.source_type {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "semantic rule {} expects {}, received {}",
                rule.path,
                rule.source_type.as_str(),
                value.source_type().as_str()
            ),
            "Update the versioned registry for a real schema change; never coerce a drifted source type.",
        ));
    }
    match (rule.kind, value) {
        (SemanticKind::Boolean, SemanticValue::Boolean(value)) => Ok(encode_boolean(*value)),
        (SemanticKind::Numeric, SemanticValue::Integer(value)) => {
            encode_numeric(*value as f64, rule.path)
        }
        (SemanticKind::Numeric, SemanticValue::Real(value)) => encode_numeric(*value, rule.path),
        (SemanticKind::NumericSet, SemanticValue::IntegerArray(values)) => {
            encode_numeric_set(values, rule.path)
        }
        (SemanticKind::Temporal, SemanticValue::Integer(value)) => {
            encode_numeric(*value as f64, rule.path)
        }
        (SemanticKind::Temporal, SemanticValue::Text(value)) => {
            encode_numeric(parse_rfc3339_seconds(value, rule.path)?, rule.path)
        }
        (SemanticKind::Category | SemanticKind::Reference, SemanticValue::Text(value)) => {
            encode_hashed(rule, std::iter::once(value.as_str()))
        }
        (SemanticKind::Reference, SemanticValue::Integer(value)) => {
            let rendered = value.to_string();
            encode_hashed(rule, std::iter::once(rendered.as_str()))
        }
        (SemanticKind::Path, SemanticValue::Text(value)) => encode_path(rule, value),
        (SemanticKind::Set, SemanticValue::TextArray(values)) => {
            encode_hashed(rule, values.iter().map(String::as_str))
        }
        (SemanticKind::ImportedVector, SemanticValue::BlobI8x768(bytes)) => {
            decode_imported_i8x768(bytes, rule.path)
        }
        (
            SemanticKind::LatentCode | SemanticKind::LatentProse,
            SemanticValue::Text(_) | SemanticValue::TextArray(_),
        ) => Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "latent semantic atom {} was routed to a structured encoder",
                rule.path
            ),
            "Measure latent code/prose through the frozen embedding table, never through a deterministic structured encoder.",
        )),
        _ => Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "semantic rule {} kind {} cannot encode source type {}",
                rule.path,
                rule.kind.as_str(),
                value.source_type().as_str()
            ),
            "Correct the frozen registry's source-type/semantic-kind binding before ingestion.",
        )),
    }
}

fn parse_rfc3339_seconds(value: &str, path: &str) -> PanelResult<f64> {
    // CBM emits UTC RFC3339 (`YYYY-MM-DDTHH:MM:SSZ`). Accepting a broader or
    // locale-dependent parser would make the frozen lens runtime-dependent.
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("semantic temporal atom {path} is not canonical UTC RFC3339: {value:?}"),
            "Rebuild CBM metadata with YYYY-MM-DDTHH:MM:SSZ timestamps or version the temporal lens contract.",
        ));
    }
    let parse = |range: std::ops::Range<usize>, label: &str| -> PanelResult<i64> {
        value[range].parse::<i64>().map_err(|error| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("semantic temporal atom {path} has invalid {label}: {error}"),
                "Rebuild CBM metadata with canonical UTC RFC3339 timestamps.",
            )
        })
    };
    let year = parse(0..4, "year")?;
    let month = parse(5..7, "month")?;
    let day = parse(8..10, "day")?;
    let hour = parse(11..13, "hour")?;
    let minute = parse(14..16, "minute")?;
    let second = parse(17..19, "second")?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("semantic temporal atom {path} has out-of-range fields: {value:?}"),
            "Repair the persisted UTC timestamp before ingestion.",
        ));
    }
    // Howard Hinnant's civil-date transform; deterministic proleptic Gregorian
    // days relative to 1970-01-01.
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let yoe = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * shifted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok((days * 86_400 + hour * 3_600 + minute * 60 + second) as f64)
}

/// Converts CBM's exact signed-int8 vector bytes into a finite L2-unit dense
/// vector. The caller retains and witnesses the original byte hash separately.
pub fn decode_imported_i8x768(bytes: &[u8], path: &str) -> PanelResult<SlotVector> {
    if bytes.len() != 768 {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!(
                "semantic vector {path} has {} bytes, expected 768",
                bytes.len()
            ),
            "Rebuild the CBM SQLite generation with the frozen 768-byte semantic vector contract.",
        ));
    }
    let mut data = bytes
        .iter()
        .map(|byte| f32::from(*byte as i8) / 127.0)
        .collect::<Vec<_>>();
    let norm = data
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    if !norm.is_finite() || norm == 0.0 {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("semantic vector {path} has invalid L2 norm {norm}"),
            "Rebuild the source vector; zero or non-finite imported vectors cannot carry semantic evidence.",
        ));
    }
    for value in &mut data {
        *value = (f64::from(*value) / norm) as f32;
    }
    Ok(SlotVector::Dense { dim: 768, data })
}
