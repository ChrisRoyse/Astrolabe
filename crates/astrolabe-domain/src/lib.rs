//! Domain types for turning Codebase Memory MCP symbols into Calyx identities.
//!
//! The crate owns Astrolabe's code-domain identity spine:
//! series identity is stable across edits, while version identity is a Calyx
//! `CxId` derived from byte-exact canonical symbol input.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod fsv;
pub mod knobs;
pub mod lowering_trigger;

/// Re-export of the Calyx core crate used for vault identities and content addressing.
pub use calyx_core as calyx;

/// Cross-crate hook a weave mutation path calls to schedule a debounced
/// lowered-SQLite regeneration (#225).
pub use lowering_trigger::LoweringTrigger;

/// The Cargo package name for this crate.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// Absolute path to the owned Calyx tree used by this workspace.
pub const CALYX_VENDOR_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../calyx");
/// Version tag prepended to every symbol canonical byte sequence.
pub const SYMBOL_CANONICAL_TAG: &str = "astro-symbol-v1";
/// Domain tag framed into every stable series identifier preimage.
pub const SERIES_ID_TAG: &str = "astro-series-v2";
/// Prefix used to build the per-project Calyx vault salt.
pub const VAULT_SALT_PREFIX: &str = "astrolabe-v1:";
/// Error code used when a symbol carries a non-finite scalar.
pub const ASTRO_SYMBOL_NON_FINITE: &str = "ASTRO_SYMBOL_NON_FINITE";
/// Error code used when project, qualified name, or label is empty.
pub const ASTRO_SYMBOL_IDENTITY_EMPTY: &str = "ASTRO_SYMBOL_IDENTITY_EMPTY";
/// Error code used when supplied source snippet hash does not match snippet bytes.
pub const ASTRO_SOURCE_DRIFT: &str = "ASTRO_SOURCE_DRIFT";
/// Error code used when attempting to derive a `CxId` with panel version zero.
pub const ASTRO_PANEL_VERSION_ZERO: &str = "ASTRO_PANEL_VERSION_ZERO";
/// Error code used when an anchor confidence is not in the open-closed range `(0, 1]`.
pub const ASTRO_ANCHOR_CONFIDENCE_RANGE: &str = "ASTRO_ANCHOR_CONFIDENCE_RANGE";
/// Error code used when grounded evidence has no catalog source prefix.
pub const ASTRO_ANCHOR_SOURCE_PREFIX_INVALID: &str = "ASTRO_ANCHOR_SOURCE_PREFIX_INVALID";
/// Error code used when confidence contradicts the source's grounding kind.
pub const ASTRO_ANCHOR_CONFIDENCE_INVALID: &str = "ASTRO_ANCHOR_CONFIDENCE_INVALID";

/// Confidence carried by resolved evidence.
pub const RESOLVED_SOURCE_CONFIDENCE: f32 = 1.0;
/// Default confidence for provisional proxy evidence.
pub const DEFAULT_PROVISIONAL_CONFIDENCE: f32 = 0.8;

const GROUNDING_SOURCE_REMEDIATION: &str = "use a catalog source: ci:/trace:/review:/git:revert: for resolved evidence, or git:fix:/agent:/survival:/propagation: for proxy evidence";

const ID_BYTES: usize = 16;

/// The upstream system that owns a piece of Astrolabe behavior.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ParentSystem {
    /// Behavior inherited from vendored Calyx.
    Calyx,
    /// Behavior inherited from vendored Codebase Memory MCP.
    CodebaseMemoryMcp,
}

/// Returns the absolute path to the vendored Calyx checkout.
pub fn calyx_vendor_root() -> &'static str {
    CALYX_VENDOR_ROOT
}

/// A stable fail-closed domain error with a machine-readable code and remediation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DomainError {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

/// Grounding kind classified from the exhaustive source-prefix catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingKind {
    /// Direct external evidence, certain at confidence 1.0.
    Resolved,
    /// Indirect proxy evidence, always below confidence 1.0.
    Proxy,
}

/// Trust carried by grounded evidence and aggregates derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTag {
    /// Every contributor is resolved evidence.
    Trusted,
    /// At least one contributor is proxy evidence, or no evidence exists.
    Provisional,
}

impl TrustTag {
    /// Stable response-envelope label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Provisional => "provisional",
        }
    }
}

/// Complete classification of one catalog source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceClassification {
    /// Whether the source is direct resolved evidence or a proxy.
    pub grounding_kind: GroundingKind,
    /// Trust implied by that grounding kind.
    pub trust: TrustTag,
}

impl DomainError {
    /// Builds a new domain error.
    pub fn new(code: &'static str, message: impl Into<String>, remediation: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            remediation,
        }
    }

    /// Returns the stable `ASTRO_*` refusal code.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the refusal message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the operator-facing remediation text.
    pub const fn remediation(&self) -> &'static str {
        self.remediation
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DomainError {}

/// Classifies a grounding source using the exhaustive prefix catalog.
pub fn classify_grounding_source(source: &str) -> Result<SourceClassification> {
    const CATALOG: &[(&str, GroundingKind, TrustTag)] = &[
        ("git:revert:", GroundingKind::Resolved, TrustTag::Trusted),
        ("git:fix:", GroundingKind::Proxy, TrustTag::Provisional),
        ("ci:", GroundingKind::Resolved, TrustTag::Trusted),
        ("trace:", GroundingKind::Resolved, TrustTag::Trusted),
        ("review:", GroundingKind::Resolved, TrustTag::Trusted),
        ("agent:", GroundingKind::Proxy, TrustTag::Provisional),
        ("survival:", GroundingKind::Proxy, TrustTag::Provisional),
        ("propagation:", GroundingKind::Proxy, TrustTag::Provisional),
    ];
    for &(prefix, grounding_kind, trust) in CATALOG {
        if let Some(rest) = source.strip_prefix(prefix) {
            if rest.trim().is_empty() {
                return Err(DomainError::new(
                    ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
                    format!("source {source:?} must name evidence after {prefix:?}"),
                    GROUNDING_SOURCE_REMEDIATION,
                ));
            }
            if matches!(prefix, "ci:" | "agent:") {
                let Some((owner, observation)) = rest.split_once(':') else {
                    return Err(DomainError::new(
                        ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
                        format!("source {source:?} must be {prefix}<owner>:<observation>"),
                        GROUNDING_SOURCE_REMEDIATION,
                    ));
                };
                if owner.trim().is_empty() || observation.trim().is_empty() {
                    return Err(DomainError::new(
                        ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
                        format!("source {source:?} has an empty owner or observation"),
                        GROUNDING_SOURCE_REMEDIATION,
                    ));
                }
            }
            return Ok(SourceClassification {
                grounding_kind,
                trust,
            });
        }
    }
    Err(DomainError::new(
        ASTRO_ANCHOR_SOURCE_PREFIX_INVALID,
        format!("grounding source {source:?} has no recognized catalog prefix"),
        GROUNDING_SOURCE_REMEDIATION,
    ))
}

/// Validates or defaults confidence against a source's grounding kind.
pub fn validate_grounding_confidence(
    grounding_kind: GroundingKind,
    confidence: Option<f32>,
) -> Result<f32> {
    match grounding_kind {
        GroundingKind::Resolved => match confidence {
            None => Ok(RESOLVED_SOURCE_CONFIDENCE),
            Some(value) if value == RESOLVED_SOURCE_CONFIDENCE => Ok(value),
            Some(value) => Err(DomainError::new(
                ASTRO_ANCHOR_CONFIDENCE_INVALID,
                format!("resolved evidence confidence {value} must be exactly 1.0"),
                "resolved evidence is certain; omit confidence or pass exactly 1.0",
            )),
        },
        GroundingKind::Proxy => match confidence {
            None => Ok(DEFAULT_PROVISIONAL_CONFIDENCE),
            Some(value) if value.is_finite() && value > 0.0 && value < 1.0 => Ok(value),
            Some(value) => Err(DomainError::new(
                ASTRO_ANCHOR_CONFIDENCE_INVALID,
                format!("proxy evidence confidence {value} must be finite and within (0, 1)"),
                "proxy evidence is provisional; pass confidence strictly between 0 and 1",
            )),
        },
    }
}

/// Rolls contributor trust up fail-closed: empty or any Provisional input is
/// Provisional; only a non-empty all-Trusted input is Trusted.
pub fn rollup_trust(tags: impl IntoIterator<Item = TrustTag>) -> TrustTag {
    let mut saw_contributor = false;
    for tag in tags {
        saw_contributor = true;
        if tag == TrustTag::Provisional {
            return TrustTag::Provisional;
        }
    }
    if saw_contributor {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    }
}

/// Result type used by Astrolabe domain operations.
pub type Result<T> = std::result::Result<T, DomainError>;

/// Stable identity for a symbol series across edits and reindexes.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SeriesId([u8; ID_BYTES]);

impl SeriesId {
    /// Builds a series id from raw bytes.
    pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw id bytes by value.
    pub const fn to_bytes(self) -> [u8; ID_BYTES] {
        self.0
    }

    /// Returns the raw id bytes by reference.
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SeriesId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SeriesId")
            .field(&hex_lower(&self.0))
            .finish()
    }
}

impl fmt::Display for SeriesId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_lower(&self.0))
    }
}

impl FromStr for SeriesId {
    type Err = ParseSeriesIdError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        parse_hex_16(value).map(Self)
    }
}

impl Serialize for SeriesId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SeriesId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SeriesIdVisitor)
    }
}

/// Error returned when parsing a [`SeriesId`] from hex.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParseSeriesIdError {
    /// The supplied hex string did not contain exactly 32 characters.
    InvalidLength {
        /// Required character count.
        expected: usize,
        /// Actual character count.
        actual: usize,
    },
    /// The supplied hex string contained a non-hex byte at the given index.
    InvalidHex {
        /// Byte index of the first invalid character.
        index: usize,
    },
}

impl fmt::Display for ParseSeriesIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid series id length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidHex { index } => write!(f, "invalid series id hex byte at index {index}"),
        }
    }
}

impl std::error::Error for ParseSeriesIdError {}

struct SeriesIdVisitor;

impl<'de> Visitor<'de> for SeriesIdVisitor {
    type Value = SeriesId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-character lowercase or uppercase hex series id")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        value.parse::<SeriesId>().map_err(E::custom)
    }
}

/// Typed vocabulary for Codebase Memory MCP node labels.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum SymbolLabel {
    /// Callable function symbol.
    Function,
    /// Method symbol associated with a receiver or class.
    Method,
    /// Class declaration symbol.
    Class,
    /// Struct declaration symbol.
    Struct,
    /// Interface declaration symbol.
    Interface,
    /// Enum declaration symbol.
    Enum,
    /// Enum member symbol.
    EnumMember,
    /// Trait declaration symbol.
    Trait,
    /// Type declaration symbol.
    Type,
    /// Type alias declaration symbol.
    TypeAlias,
    /// Field symbol.
    Field,
    /// Variable symbol.
    Variable,
    /// Constant symbol.
    Constant,
    /// Module symbol.
    Module,
    /// File symbol.
    File,
    /// Route symbol.
    Route,
    /// Channel symbol.
    Channel,
    /// Resource symbol.
    Resource,
    /// Chart symbol.
    Chart,
    /// Package symbol.
    Package,
    /// Macro symbol.
    Macro,
    /// Documentation section symbol.
    Section,
    /// Namespace symbol.
    Namespace,
    /// Property symbol.
    Property,
    /// Union declaration symbol.
    Union,
    /// Protocol declaration symbol.
    Protocol,
    /// Mixin declaration symbol.
    Mixin,
    /// Object declaration symbol.
    Object,
    /// Implementation block symbol.
    Impl,
    /// Annotation symbol.
    Annotation,
    /// Decorator symbol (synthetic decorator target node emitted by CBM for
    /// DECORATES relations whose decorator has no definition in the corpus).
    Decorator,
    /// Environment variable symbol.
    EnvVar,
    /// Structural project label that does not receive panel measurements.
    Project,
    /// Structural branch label that does not receive panel measurements.
    Branch,
    /// Structural folder label that does not receive panel measurements.
    Folder,
}

impl SymbolLabel {
    /// Returns the canonical string label used in symbol canonical bytes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Method => "Method",
            Self::Class => "Class",
            Self::Struct => "Struct",
            Self::Interface => "Interface",
            Self::Enum => "Enum",
            Self::EnumMember => "EnumMember",
            Self::Trait => "Trait",
            Self::Type => "Type",
            Self::TypeAlias => "TypeAlias",
            Self::Field => "Field",
            Self::Variable => "Variable",
            Self::Constant => "Constant",
            Self::Module => "Module",
            Self::File => "File",
            Self::Route => "Route",
            Self::Channel => "Channel",
            Self::Resource => "Resource",
            Self::Chart => "Chart",
            Self::Package => "Package",
            Self::Macro => "Macro",
            Self::Section => "Section",
            Self::Namespace => "Namespace",
            Self::Property => "Property",
            Self::Union => "Union",
            Self::Protocol => "Protocol",
            Self::Mixin => "Mixin",
            Self::Object => "Object",
            Self::Impl => "Impl",
            Self::Annotation => "Annotation",
            Self::Decorator => "Decorator",
            Self::EnvVar => "EnvVar",
            Self::Project => "Project",
            Self::Branch => "Branch",
            Self::Folder => "Folder",
        }
    }

    /// Returns true for structural labels that are graph metadata only.
    pub const fn is_structural(self) -> bool {
        matches!(self, Self::Project | Self::Branch | Self::Folder)
    }
}

impl fmt::Display for SymbolLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed vocabulary for Codebase Memory MCP graph edges admitted by Astrolabe.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum EdgeKind {
    /// Direct call edge.
    Calls = 1,
    /// LSP-resolved call edge.
    ResolvedCalls = 2,
    /// Import edge.
    Imports = 3,
    /// Definition edge.
    Defines = 4,
    /// Method definition edge.
    DefinesMethod = 5,
    /// Containment edge.
    Contains = 6,
    /// Branch membership edge.
    HasBranch = 7,
    /// Inheritance edge.
    Inherits = 8,
    /// Interface or trait implementation edge.
    Implements = 9,
    /// Override edge.
    Override = 10,
    /// Decoration edge.
    Decorates = 11,
    /// Instantiation edge.
    Instantiates = 12,
    /// Type-use edge.
    UsesType = 13,
    /// General usage edge.
    Usage = 14,
    /// Read dataflow edge.
    Reads = 15,
    /// Write dataflow edge.
    Writes = 16,
    /// Throw or raise edge.
    Throws = 17,
    /// Test-to-symbol edge.
    Tests = 18,
    /// Test-to-file edge.
    TestsFile = 19,
    /// HTTP service call edge.
    HttpCalls = 20,
    /// Asynchronous service call edge.
    AsyncCalls = 21,
    /// gRPC service call edge.
    GrpcCalls = 22,
    /// GraphQL service call edge.
    GraphqlCalls = 23,
    /// tRPC service call edge.
    TrpcCalls = 24,
    /// Handler edge.
    Handles = 25,
    /// Explicit dataflow edge.
    DataFlows = 26,
    /// Infrastructure mapping edge.
    InfraMaps = 27,
    /// Configuration edge.
    Configures = 28,
    /// Dependency edge.
    DependsOn = 29,
    /// Channel emit edge.
    Emits = 30,
    /// Channel listen edge.
    ListensOn = 31,
    /// Temporal co-change edge.
    FileChangesWith = 32,
    /// Structural similarity edge.
    SimilarTo = 33,
    /// Semantic similarity edge.
    SemanticallyRelated = 34,
    /// Cross-project HTTP service call edge.
    CrossHttpCalls = 35,
    /// Cross-project asynchronous service call edge.
    CrossAsyncCalls = 36,
    /// Cross-project channel edge.
    CrossChannel = 37,
    /// Cross-project gRPC service call edge.
    CrossGrpcCalls = 38,
    /// Cross-project GraphQL service call edge.
    CrossGraphqlCalls = 39,
    /// Cross-project tRPC service call edge.
    CrossTrpcCalls = 40,
    /// Unchecked-exception raise edge (CBM `RAISES`; the checked form is `THROWS`).
    Raises = 41,
}

impl EdgeKind {
    /// All stable edge kinds in `etype` order.
    pub const ALL: [Self; 41] = [
        Self::Calls,
        Self::ResolvedCalls,
        Self::Imports,
        Self::Defines,
        Self::DefinesMethod,
        Self::Contains,
        Self::HasBranch,
        Self::Inherits,
        Self::Implements,
        Self::Override,
        Self::Decorates,
        Self::Instantiates,
        Self::UsesType,
        Self::Usage,
        Self::Reads,
        Self::Writes,
        Self::Throws,
        Self::Tests,
        Self::TestsFile,
        Self::HttpCalls,
        Self::AsyncCalls,
        Self::GrpcCalls,
        Self::GraphqlCalls,
        Self::TrpcCalls,
        Self::Handles,
        Self::DataFlows,
        Self::InfraMaps,
        Self::Configures,
        Self::DependsOn,
        Self::Emits,
        Self::ListensOn,
        Self::FileChangesWith,
        Self::SimilarTo,
        Self::SemanticallyRelated,
        Self::CrossHttpCalls,
        Self::CrossAsyncCalls,
        Self::CrossChannel,
        Self::CrossGrpcCalls,
        Self::CrossGraphqlCalls,
        Self::CrossTrpcCalls,
        Self::Raises,
    ];

    /// Returns the stable `u16` edge vocabulary code.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Returns the canonical Codebase Memory MCP edge type string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Calls => "CALLS",
            Self::ResolvedCalls => "RESOLVED_CALLS",
            Self::Imports => "IMPORTS",
            Self::Defines => "DEFINES",
            Self::DefinesMethod => "DEFINES_METHOD",
            Self::Contains => "CONTAINS",
            Self::HasBranch => "HAS_BRANCH",
            Self::Inherits => "INHERITS",
            Self::Implements => "IMPLEMENTS",
            Self::Override => "OVERRIDE",
            Self::Decorates => "DECORATES",
            Self::Instantiates => "INSTANTIATES",
            Self::UsesType => "USES_TYPE",
            Self::Usage => "USAGE",
            Self::Reads => "READS",
            Self::Writes => "WRITES",
            Self::Throws => "THROWS",
            Self::Raises => "RAISES",
            Self::Tests => "TESTS",
            Self::TestsFile => "TESTS_FILE",
            Self::HttpCalls => "HTTP_CALLS",
            Self::AsyncCalls => "ASYNC_CALLS",
            Self::GrpcCalls => "GRPC_CALLS",
            Self::GraphqlCalls => "GRAPHQL_CALLS",
            Self::TrpcCalls => "TRPC_CALLS",
            Self::Handles => "HANDLES",
            Self::DataFlows => "DATA_FLOWS",
            Self::InfraMaps => "INFRA_MAPS",
            Self::Configures => "CONFIGURES",
            Self::DependsOn => "DEPENDS_ON",
            Self::Emits => "EMITS",
            Self::ListensOn => "LISTENS_ON",
            Self::FileChangesWith => "FILE_CHANGES_WITH",
            Self::SimilarTo => "SIMILAR_TO",
            Self::SemanticallyRelated => "SEMANTICALLY_RELATED",
            Self::CrossHttpCalls => "CROSS_HTTP_CALLS",
            Self::CrossAsyncCalls => "CROSS_ASYNC_CALLS",
            Self::CrossChannel => "CROSS_CHANNEL",
            Self::CrossGrpcCalls => "CROSS_GRPC_CALLS",
            Self::CrossGraphqlCalls => "CROSS_GRAPHQL_CALLS",
            Self::CrossTrpcCalls => "CROSS_TRPC_CALLS",
        }
    }

    /// Parses a Codebase Memory MCP edge type string into Astrolabe's stable
    /// vocabulary. CBM's `CONTAINS_*` family is stored as the `CONTAINS` class.
    pub fn from_cbm_type(value: &str) -> Option<Self> {
        match value {
            "CALLS" => Some(Self::Calls),
            "RESOLVED_CALLS" => Some(Self::ResolvedCalls),
            "IMPORTS" => Some(Self::Imports),
            "DEFINES" => Some(Self::Defines),
            "DEFINES_METHOD" => Some(Self::DefinesMethod),
            "CONTAINS" | "CONTAINS_FILE" | "CONTAINS_FOLDER" => Some(Self::Contains),
            "HAS_BRANCH" => Some(Self::HasBranch),
            "INHERITS" => Some(Self::Inherits),
            "IMPLEMENTS" => Some(Self::Implements),
            "OVERRIDE" => Some(Self::Override),
            "DECORATES" => Some(Self::Decorates),
            "INSTANTIATES" => Some(Self::Instantiates),
            "USES_TYPE" => Some(Self::UsesType),
            "USAGE" => Some(Self::Usage),
            "READS" => Some(Self::Reads),
            "WRITES" => Some(Self::Writes),
            "THROWS" => Some(Self::Throws),
            "RAISES" => Some(Self::Raises),
            "TESTS" => Some(Self::Tests),
            "TESTS_FILE" => Some(Self::TestsFile),
            "HTTP_CALLS" => Some(Self::HttpCalls),
            "ASYNC_CALLS" => Some(Self::AsyncCalls),
            "GRPC_CALLS" => Some(Self::GrpcCalls),
            "GRAPHQL_CALLS" => Some(Self::GraphqlCalls),
            "TRPC_CALLS" => Some(Self::TrpcCalls),
            "HANDLES" => Some(Self::Handles),
            "DATA_FLOWS" => Some(Self::DataFlows),
            "INFRA_MAPS" => Some(Self::InfraMaps),
            "CONFIGURES" => Some(Self::Configures),
            "DEPENDS_ON" => Some(Self::DependsOn),
            "EMITS" => Some(Self::Emits),
            "LISTENS_ON" => Some(Self::ListensOn),
            "FILE_CHANGES_WITH" => Some(Self::FileChangesWith),
            "SIMILAR_TO" => Some(Self::SimilarTo),
            "SEMANTICALLY_RELATED" => Some(Self::SemanticallyRelated),
            "CROSS_HTTP_CALLS" => Some(Self::CrossHttpCalls),
            "CROSS_ASYNC_CALLS" => Some(Self::CrossAsyncCalls),
            "CROSS_CHANNEL" => Some(Self::CrossChannel),
            "CROSS_GRPC_CALLS" => Some(Self::CrossGrpcCalls),
            "CROSS_GRAPHQL_CALLS" => Some(Self::CrossGraphqlCalls),
            "CROSS_TRPC_CALLS" => Some(Self::CrossTrpcCalls),
            _ => None,
        }
    }

    /// Data-driven v1 prior used only when the source edge does not carry the
    /// measured property named in `dynamic_weight_property`.
    pub const fn weight_prior(self) -> EdgeWeightPrior {
        match self {
            Self::Calls | Self::ResolvedCalls => EdgeWeightPrior::new(0.4, Some("confidence")),
            Self::Imports
            | Self::Defines
            | Self::DefinesMethod
            | Self::Contains
            | Self::HasBranch => EdgeWeightPrior::new(1.0, None),
            Self::Inherits
            | Self::Implements
            | Self::Override
            | Self::Decorates
            | Self::Instantiates
            | Self::UsesType => EdgeWeightPrior::new(0.9, None),
            Self::Usage | Self::Reads | Self::Writes | Self::Throws | Self::Raises => {
                EdgeWeightPrior::new(0.7, None)
            }
            Self::Tests | Self::TestsFile => EdgeWeightPrior::new(0.9, None),
            Self::HttpCalls
            | Self::AsyncCalls
            | Self::GrpcCalls
            | Self::GraphqlCalls
            | Self::TrpcCalls
            | Self::CrossHttpCalls
            | Self::CrossAsyncCalls
            | Self::CrossGrpcCalls
            | Self::CrossGraphqlCalls
            | Self::CrossTrpcCalls => EdgeWeightPrior::new(0.5, Some("confidence")),
            Self::Handles | Self::DependsOn => EdgeWeightPrior::new(0.9, Some("confidence")),
            Self::DataFlows => EdgeWeightPrior::new(0.7, Some("confidence")),
            Self::InfraMaps | Self::Configures => EdgeWeightPrior::new(0.8, Some("confidence")),
            Self::Emits | Self::ListensOn | Self::CrossChannel => EdgeWeightPrior::new(0.7, None),
            Self::FileChangesWith => EdgeWeightPrior::new(0.5, Some("coupling_score")),
            Self::SimilarTo => EdgeWeightPrior::new(0.95, Some("jaccard")),
            Self::SemanticallyRelated => EdgeWeightPrior::new(0.8, Some("score")),
        }
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// V1 edge-weight prior registry entry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EdgeWeightPrior {
    /// Fallback weight in the closed interval `[0, 1]`.
    pub fallback: f32,
    /// Source property that supersedes `fallback` when present and valid.
    pub dynamic_weight_property: Option<&'static str>,
}

impl EdgeWeightPrior {
    /// Builds a static prior-table entry.
    pub const fn new(fallback: f32, dynamic_weight_property: Option<&'static str>) -> Self {
        Self {
            fallback,
            dynamic_weight_property,
        }
    }
}

/// Anchor evidence attached to a symbol before it is lowered into Calyx.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorEvidence {
    /// Source or kind of the evidence, such as `ci:github` or `trace:runtime`.
    pub source: String,
    /// Confidence score that must be finite and in the open-closed range `(0, 1]`.
    pub confidence: f32,
}

impl AnchorEvidence {
    /// Creates an anchor evidence record.
    pub fn new(source: impl Into<String>, confidence: f32) -> Self {
        Self {
            source: source.into(),
            confidence,
        }
    }
}

/// Code symbol observation used to derive Astrolabe series and version identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymbolRecord {
    /// Stable project key used in both series id and vault salt derivation.
    pub project: String,
    /// Fully qualified symbol name, stable across edits for the same logical symbol.
    pub qualified_name: String,
    /// Codebase Memory MCP label string for the symbol.
    pub label: String,
    /// Repository-relative file path for the observed symbol.
    pub rel_file_path: String,
    /// Source language identifier for the observed symbol.
    pub language: String,
    /// Exact source snippet bytes observed for the symbol.
    pub source_snippet_bytes: Vec<u8>,
    /// Signature string observed for the symbol.
    pub signature: String,
    /// One-based inclusive start line for the observed symbol.
    pub start_line: u32,
    /// One-based inclusive end line for the observed symbol.
    pub end_line: u32,
    /// Optional BLAKE3 hash of the source snippet bytes read from the source file.
    pub expected_source_snippet_blake3: Option<[u8; 32]>,
    /// Numeric observations that must be finite before the symbol is admitted.
    pub scalars: BTreeMap<String, f64>,
    /// Anchor evidence whose confidence values must be finite and within `(0, 1]`.
    pub anchors: Vec<AnchorEvidence>,
}

impl SymbolRecord {
    /// Creates a symbol record with no expected source hash, scalar fields, or anchors.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: impl Into<String>,
        qualified_name: impl Into<String>,
        label: impl Into<String>,
        rel_file_path: impl Into<String>,
        language: impl Into<String>,
        source_snippet_bytes: impl Into<Vec<u8>>,
        signature: impl Into<String>,
        start_line: u32,
        end_line: u32,
    ) -> Self {
        Self {
            project: project.into(),
            qualified_name: qualified_name.into(),
            label: label.into(),
            rel_file_path: rel_file_path.into(),
            language: language.into(),
            source_snippet_bytes: source_snippet_bytes.into(),
            signature: signature.into(),
            start_line,
            end_line,
            expected_source_snippet_blake3: None,
            scalars: BTreeMap::new(),
            anchors: Vec::new(),
        }
    }

    /// Returns this symbol's exact canonical bytes for content addressing.
    pub fn canonical_input_bytes(&self) -> Result<Vec<u8>> {
        canonical_input_bytes(self)
    }

    /// Returns the stable series id for this symbol.
    pub fn series_id(&self) -> Result<SeriesId> {
        series_id(self)
    }

    /// Returns this symbol's project-derived Calyx vault salt.
    pub fn vault_salt(&self) -> Result<String> {
        vault_salt(&self.project)
    }

    /// Returns this symbol's immutable Calyx version id for a non-zero panel version.
    pub fn cx_id(&self, panel_version: u32) -> Result<calyx::CxId> {
        cx_id(self, panel_version)
    }

    /// Returns both levels of identity and the exact bytes used to derive the version id.
    pub fn identity(&self, panel_version: u32) -> Result<SymbolIdentity> {
        let series_id = self.series_id()?;
        let canonical_input_bytes = self.canonical_input_bytes()?;
        let vault_salt = self.vault_salt()?;
        let cx_id =
            cx_id_from_canonical(&canonical_input_bytes, panel_version, vault_salt.as_bytes())?;

        Ok(SymbolIdentity {
            series_id,
            cx_id,
            canonical_input_bytes,
            vault_salt,
        })
    }

    fn validate_symbol_fields(&self) -> Result<()> {
        validate_identity_parts(&self.project, &self.qualified_name, &self.label)?;

        for (key, value) in &self.scalars {
            if !value.is_finite() {
                return Err(DomainError::new(
                    ASTRO_SYMBOL_NON_FINITE,
                    format!("symbol {} scalar {key} is non-finite", self.qualified_name),
                    "Drop or repair non-finite scalar values before admitting the symbol.",
                ));
            }
        }

        for anchor in &self.anchors {
            let classification = classify_grounding_source(&anchor.source)?;
            validate_grounding_confidence(classification.grounding_kind, Some(anchor.confidence))
                .map_err(|error| {
                DomainError::new(
                    ASTRO_ANCHOR_CONFIDENCE_RANGE,
                    error.message().to_string(),
                    "Clamp or reject anchor confidence so only values in (0, 1] are admitted.",
                )
            })?;
        }

        if let Some(expected) = self.expected_source_snippet_blake3 {
            let actual = blake3::hash(&self.source_snippet_bytes);
            if actual.as_bytes() != &expected {
                return Err(DomainError::new(
                    ASTRO_SOURCE_DRIFT,
                    format!(
                        "symbol {} source snippet hash does not match the supplied source hash",
                        self.qualified_name
                    ),
                    "Re-read the source snippet from persisted bytes and recompute the supplied hash before ingest.",
                ));
            }
        }

        Ok(())
    }
}

/// Combined two-level identity for a validated symbol.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolIdentity {
    /// Stable series id derived from project, qualified name, and label.
    pub series_id: SeriesId,
    /// Immutable version id derived from canonical input bytes, panel version, and vault salt.
    pub cx_id: calyx::CxId,
    /// Exact canonical bytes used to derive `cx_id`.
    pub canonical_input_bytes: Vec<u8>,
    /// Per-project vault salt used to derive `cx_id`.
    pub vault_salt: String,
}

/// Returns `frame(x) = be_u64(len(x)) || x`.
pub fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    append_frame(&mut out, bytes);
    out
}

/// Returns the exact Astrolabe canonical byte sequence for a symbol.
pub fn canonical_input_bytes(symbol: &SymbolRecord) -> Result<Vec<u8>> {
    symbol.validate_symbol_fields()?;

    let mut out = Vec::new();
    append_frame(&mut out, SYMBOL_CANONICAL_TAG.as_bytes());
    append_frame(&mut out, symbol.project.as_bytes());
    append_frame(&mut out, symbol.qualified_name.as_bytes());
    append_frame(&mut out, symbol.label.as_bytes());
    append_frame(&mut out, symbol.rel_file_path.as_bytes());
    append_frame(&mut out, symbol.language.as_bytes());
    append_frame(&mut out, &symbol.source_snippet_bytes);
    append_frame(&mut out, symbol.signature.as_bytes());
    append_frame(&mut out, &symbol.start_line.to_be_bytes());
    append_frame(&mut out, &symbol.end_line.to_be_bytes());
    Ok(out)
}

/// Returns the stable series id for a symbol.
pub fn series_id(symbol: &SymbolRecord) -> Result<SeriesId> {
    series_id_parts(&symbol.project, &symbol.qualified_name, &symbol.label)
}

/// Returns the stable series id for raw identity fields.
pub fn series_id_parts(project: &str, qualified_name: &str, label: &str) -> Result<SeriesId> {
    validate_identity_parts(project, qualified_name, label)?;

    let mut preimage = Vec::new();
    append_frame(&mut preimage, SERIES_ID_TAG.as_bytes());
    append_frame(&mut preimage, project.as_bytes());
    append_frame(&mut preimage, qualified_name.as_bytes());
    append_frame(&mut preimage, label.as_bytes());

    let mut out = [0_u8; ID_BYTES];
    out.copy_from_slice(&blake3::hash(&preimage).as_bytes()[..ID_BYTES]);
    Ok(SeriesId::from_bytes(out))
}

/// Returns the Calyx vault salt string for a project.
pub fn vault_salt(project: &str) -> Result<String> {
    if project.trim().is_empty() {
        return Err(identity_empty_error(project, "", ""));
    }
    Ok(format!("{VAULT_SALT_PREFIX}{project}"))
}

/// Returns the immutable Calyx version id for a symbol and non-zero panel version.
pub fn cx_id(symbol: &SymbolRecord, panel_version: u32) -> Result<calyx::CxId> {
    let canonical_input_bytes = symbol.canonical_input_bytes()?;
    let vault_salt = symbol.vault_salt()?;
    cx_id_from_canonical(&canonical_input_bytes, panel_version, vault_salt.as_bytes())
}

/// Returns the immutable Calyx version id from already canonicalized bytes.
pub fn cx_id_from_canonical(
    canonical_input_bytes: &[u8],
    panel_version: u32,
    vault_salt: &[u8],
) -> Result<calyx::CxId> {
    if panel_version == 0 {
        return Err(DomainError::new(
            ASTRO_PANEL_VERSION_ZERO,
            "panel version 0 cannot be used for Astrolabe symbol identity",
            "Commission a non-zero panel version before deriving a CxId.",
        ));
    }

    Ok(calyx::CxId::from_input(
        canonical_input_bytes,
        panel_version,
        vault_salt,
    ))
}

fn validate_identity_parts(project: &str, qualified_name: &str, label: &str) -> Result<()> {
    if project.trim().is_empty() || qualified_name.trim().is_empty() || label.trim().is_empty() {
        return Err(identity_empty_error(project, qualified_name, label));
    }
    Ok(())
}

fn identity_empty_error(project: &str, qualified_name: &str, label: &str) -> DomainError {
    DomainError::new(
        ASTRO_SYMBOL_IDENTITY_EMPTY,
        format!(
            "symbol identity fields must be non-empty: project={project:?}, qualified_name={qualified_name:?}, label={label:?}"
        ),
        "Populate project, qualified_name, and label before deriving Astrolabe identity.",
    )
}

fn append_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hex_lower(bytes: &[u8; ID_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(ID_BYTES * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_hex_16(value: &str) -> std::result::Result<[u8; ID_BYTES], ParseSeriesIdError> {
    if value.len() != ID_BYTES * 2 {
        return Err(ParseSeriesIdError::InvalidLength {
            expected: ID_BYTES * 2,
            actual: value.len(),
        });
    }

    let mut out = [0_u8; ID_BYTES];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(chunk[0]).ok_or(ParseSeriesIdError::InvalidHex { index: index * 2 })?;
        let lo = hex_value(chunk[1]).ok_or(ParseSeriesIdError::InvalidHex {
            index: index * 2 + 1,
        })?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol() -> SymbolRecord {
        SymbolRecord::new(
            "demo",
            "demo.math.add",
            SymbolLabel::Function.as_str(),
            "src/math.c",
            "c",
            b"int add(int a, int b) { return a + b; }\n".to_vec(),
            "int add(int a, int b)",
            10,
            12,
        )
    }

    #[test]
    fn exposes_calyx_vendor_root() {
        assert!(calyx_vendor_root().ends_with("/calyx"));
    }

    #[test]
    fn frame_is_big_endian_length_prefixed() {
        assert_eq!(frame(b"abc"), [0, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn series_id_v2_frames_every_field_and_separates_boundary_shifts() {
        let left = series_id_parts("ab", "c", "d").expect("left series id");
        let right = series_id_parts("a", "bc", "d").expect("right series id");
        assert_ne!(left, right);

        let mut expected_preimage = frame(SERIES_ID_TAG.as_bytes());
        expected_preimage.extend_from_slice(&frame(b"ab"));
        expected_preimage.extend_from_slice(&frame(b"c"));
        expected_preimage.extend_from_slice(&frame(b"d"));
        let expected = blake3::hash(&expected_preimage);
        assert_eq!(left.as_bytes(), &expected.as_bytes()[..ID_BYTES]);
    }

    #[test]
    fn validation_refuses_empty_identity() {
        let mut symbol = symbol();
        symbol.qualified_name.clear();

        let err = symbol
            .canonical_input_bytes()
            .expect_err("empty qn refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_IDENTITY_EMPTY);
        assert_eq!(
            err.remediation(),
            "Populate project, qualified_name, and label before deriving Astrolabe identity."
        );
    }

    #[test]
    fn validation_refuses_non_finite_scalar() {
        let mut symbol = symbol();
        symbol.scalars.insert("complexity".to_string(), f64::NAN);

        let err = symbol.canonical_input_bytes().expect_err("nan refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);
        assert_eq!(
            err.remediation(),
            "Drop or repair non-finite scalar values before admitting the symbol."
        );
    }

    #[test]
    fn validation_refuses_source_drift() {
        let mut symbol = symbol();
        symbol.expected_source_snippet_blake3 = Some([7; 32]);

        let err = symbol.canonical_input_bytes().expect_err("drift refused");
        assert_eq!(err.code(), ASTRO_SOURCE_DRIFT);
        assert_eq!(
            err.remediation(),
            "Re-read the source snippet from persisted bytes and recompute the supplied hash before ingest."
        );
    }

    #[test]
    fn validation_refuses_panel_version_zero() {
        let err = symbol().cx_id(0).expect_err("zero panel version refused");
        assert_eq!(err.code(), ASTRO_PANEL_VERSION_ZERO);
        assert_eq!(
            err.remediation(),
            "Commission a non-zero panel version before deriving a CxId."
        );
    }

    #[test]
    fn validation_refuses_anchor_confidence_outside_range() {
        let mut symbol = symbol();
        symbol
            .anchors
            .push(AnchorEvidence::new("ci:github:run-1", 0.0));

        let err = symbol
            .canonical_input_bytes()
            .expect_err("zero confidence refused");
        assert_eq!(err.code(), ASTRO_ANCHOR_CONFIDENCE_RANGE);
        assert_eq!(
            err.remediation(),
            "Clamp or reject anchor confidence so only values in (0, 1] are admitted."
        );
    }

    #[test]
    fn matching_source_hash_is_accepted() {
        let mut symbol = symbol();
        symbol.expected_source_snippet_blake3 =
            Some(*blake3::hash(&symbol.source_snippet_bytes).as_bytes());

        symbol
            .canonical_input_bytes()
            .expect("matching source hash accepted");
    }

    #[test]
    fn vocabularies_expose_stable_strings_and_codes() {
        assert_eq!(SymbolLabel::Function.as_str(), "Function");
        assert!(!SymbolLabel::Function.is_structural());
        assert!(SymbolLabel::Project.is_structural());
        assert_eq!(EdgeKind::Calls.as_str(), "CALLS");
        assert_eq!(EdgeKind::Calls.code(), 1);
        assert_eq!(EdgeKind::CrossTrpcCalls.code(), 40);
    }

    #[test]
    fn edge_vocabulary_parses_cbm_aliases_and_has_complete_priors() {
        assert_eq!(
            EdgeKind::from_cbm_type("CONTAINS_FILE"),
            Some(EdgeKind::Contains)
        );
        assert_eq!(
            EdgeKind::from_cbm_type("CONTAINS_FOLDER"),
            Some(EdgeKind::Contains)
        );
        assert_eq!(
            EdgeKind::from_cbm_type("SEMANTICALLY_RELATED"),
            Some(EdgeKind::SemanticallyRelated)
        );

        for (index, kind) in EdgeKind::ALL.iter().copied().enumerate() {
            assert_eq!(kind.code(), (index + 1) as u16);
            assert_eq!(EdgeKind::from_cbm_type(kind.as_str()), Some(kind));
            let prior = kind.weight_prior();
            assert!(
                prior.fallback.is_finite() && (0.0..=1.0).contains(&prior.fallback),
                "bad prior for {kind}"
            );
        }
    }

    #[test]
    fn series_id_display_parse_roundtrips() {
        let id = symbol().series_id().expect("series id");
        assert_eq!(id.to_string().parse::<SeriesId>().expect("parse"), id);
    }
}
