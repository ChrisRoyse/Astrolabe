//! Directory-role reference frame, `placement_truth` cross-term, and the
//! `layout_map` aspect (#180b — sub-issue of #180).
//!
//! This module realizes the reference-frame half of the structure-convention
//! design on top of the S23 `layer_role` lens minted in #180a:
//!
//! * **Directory-role frame** — a `Dense(8)` L1 vector per directory over the
//!   frozen [`astrolabe_panel::CANONICAL_ROLES`] coordinate system, keyed by the
//!   directory's CxId on the `astrolabe.scope_summary.v1` substrate. It is the
//!   declared-map assignment (a one-hot identity-locked prior) when the repo
//!   declares one, else the L1 aggregate of its members' persisted S23
//!   posteriors — measured, never a global constant (invariant 4).
//! * **`placement_truth` cross-term** — the designed agreement between a
//!   symbol's S23 posterior and its directory-role frame, both `Dense(8)` L1 in
//!   the same frozen coordinate system so direct overlap agreement is
//!   shape-safe. Keyed `(symbol CxId, directory CxId)` for the `xterm` CF.
//! * **`layout_map` aspect** — per-directory role + coherence + top
//!   disagreements, the substrate the server folds into `get_architecture` and
//!   the `onboarding` context-pack preamble through the existing
//!   declared-vs-measured boundary diff (no new top-level tool).
//! * **Declared⇔learned boundary diff** — a first-class finding when a repo
//!   declares a directory's role but its members behave as another role.
//! * **First-touch fail-closed** — when neither a declared map nor an index
//!   exists, orientation refuses with `{code, message, remediation}` rather than
//!   fabricating a map.
//!
//! Every artifact here is a pure, deterministic, worker-count-invariant
//! computation whose persisted byte form is produced exactly as it lands in its
//! column family; the live `AsterVault` CF write and the MCP surface wiring
//! (`get_architecture` / `get_context_pack`) are the server-side follow-up
//! (server-pending), consuming these bytes and structs.

use astrolabe_domain::{DomainError, Result};
use astrolabe_panel::layout_registry::role_for_directory;
use astrolabe_panel::{CANONICAL_ROLES, LAYER_ROLE_COUNT, LayerRole, decode_slot_raw};

/// Directory-role frame substrate schema (shared with the kernel scope-summary
/// substrate — the frame is a scope-summary row keyed by the directory CxId).
pub const DIRECTORY_ROLE_FRAME_SCHEMA: &str = "astrolabe.scope_summary.v1";
/// Row-kind discriminator distinguishing a directory-role frame from a plain
/// kernel scope summary on the shared `astrolabe.scope_summary.v1` substrate.
pub const DIRECTORY_ROLE_FRAME_KIND: &str = "astrolabe.directory_role_frame.v1";
/// Row schema for a persisted `placement_truth` cross-term (xterm CF value).
pub const PLACEMENT_TRUTH_SCHEMA: &str = "astrolabe.placement_truth.v1";
/// Stable schema for the `get_architecture` / context-pack `layout_map` aspect.
pub const LAYOUT_MAP_ASPECT_SCHEMA: &str = "astrolabe.layout_map_aspect.v1";
/// Provenance label: the physical source of a directory-role frame row.
pub const DIRECTORY_ROLE_FRAME_PROVENANCE: &str = "AsterVault:ColumnFamily::Kernel:scope_summary";
/// Provenance label: the physical source of a `placement_truth` cross-term row.
pub const PLACEMENT_TRUTH_PROVENANCE: &str = "AsterVault:ColumnFamily::XTerm:placement_truth";

/// A directory has no declared role and no members — no frame can be formed.
pub const ASTRO_LAYOUT_FRAME_EMPTY: &str = "ASTRO_LAYOUT_FRAME_EMPTY";
/// A member's persisted S23 sidecar bytes are undecodable or the wrong shape.
pub const ASTRO_LAYOUT_S23_DECODE: &str = "ASTRO_LAYOUT_S23_DECODE";
/// A persisted directory-role frame artifact is corrupt or truncated.
pub const ASTRO_LAYOUT_FRAME_CORRUPT: &str = "ASTRO_LAYOUT_FRAME_CORRUPT";
/// Declared directory role disagrees with the learned aggregate (a finding).
pub const ASTRO_LAYOUT_DECLARED_LEARNED_DISAGREEMENT: &str =
    "ASTRO_LAYOUT_DECLARED_LEARNED_DISAGREEMENT";
/// A symbol behaves as a role its directory is not (a per-symbol finding).
pub const ASTRO_LAYOUT_PLACEMENT_DRIFT: &str = "ASTRO_LAYOUT_PLACEMENT_DRIFT";
/// First touch with neither a declared layout map nor an index available.
pub const ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE: &str = "ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE";

const FRAME_ARTIFACT_TAG: &[u8] = b"astrolabe-directory-role-frame-v1";

/// How a directory-role frame vector was assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameProvenance {
    /// One-hot from the identity-locked `astro.layout.declared_map.v1` prior.
    Declared,
    /// L1 aggregate of the directory members' persisted S23 posteriors.
    LearnedAggregate,
}

impl FrameProvenance {
    /// Stable wire identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::LearnedAggregate => "learned_aggregate",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "declared" => Some(Self::Declared),
            "learned_aggregate" => Some(Self::LearnedAggregate),
            _ => None,
        }
    }
}

/// One directory member carrying its persisted S23 `layer_role` sidecar bytes.
///
/// `s23_raw_bytes` is the exact guard-raw `slot_23.raw` CF envelope
/// ([`astrolabe_panel::slot_raw_bytes`] output) — the frame is recomputed by
/// decoding these persisted bytes, never a planner echo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryMember {
    /// Member symbol CxId (or stable id).
    pub symbol_id: String,
    /// Member qualified name (for findings and exemplars).
    pub qualified_name: String,
    /// Persisted S23 `layer_role` guard-raw sidecar bytes.
    pub s23_raw_bytes: Vec<u8>,
}

impl DirectoryMember {
    /// Builds a directory member from its id, name, and persisted S23 bytes.
    pub fn new(
        symbol_id: impl Into<String>,
        qualified_name: impl Into<String>,
        s23_raw_bytes: Vec<u8>,
    ) -> Self {
        Self {
            symbol_id: symbol_id.into(),
            qualified_name: qualified_name.into(),
            s23_raw_bytes,
        }
    }
}

/// A directory-role `Dense(8)` L1 reference frame.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryRoleFrame {
    /// Substrate schema (`astrolabe.scope_summary.v1`).
    pub schema: &'static str,
    /// Row-kind discriminator (`astrolabe.directory_role_frame.v1`).
    pub kind: &'static str,
    /// Directory CxId (or stable directory id) this frame is keyed by.
    pub directory_id: String,
    /// Directory path (for orientation and findings).
    pub directory_path: String,
    /// `Dense(8)` L1 distribution over [`astrolabe_panel::CANONICAL_ROLES`].
    pub role_vector: [f32; LAYER_ROLE_COUNT],
    /// Argmax role of `role_vector` (canonical-order tie-break).
    pub dominant_role: LayerRole,
    /// Whether the frame is a declared one-hot or a learned aggregate.
    pub source: FrameProvenance,
    /// Number of members that contributed to a learned aggregate (0 for a pure
    /// declared frame with no indexed members).
    pub member_count: usize,
    /// Content address of the canonical frame bytes.
    pub frame_hash: String,
    /// Trust label: `verified` for a declared identity-locked prior, else
    /// `provisional` for a learned aggregate not yet coherence-calibrated.
    pub trust: &'static str,
    /// Freshness label: recomputed from persisted state at build time.
    pub freshness: &'static str,
}

/// L1-normalizes a directory's members' persisted S23 posteriors into one
/// `Dense(8)` aggregate distribution.
///
/// Each member's `s23_raw_bytes` is independently decoded via
/// [`astrolabe_panel::decode_slot_raw`]; a non-dense, wrong-dimension,
/// non-finite, or negative vector fails closed with [`ASTRO_LAYOUT_S23_DECODE`]
/// (a corrupt sidecar can never be read as a valid posterior). An empty member
/// set or an all-zero mass fails closed with [`ASTRO_LAYOUT_FRAME_EMPTY`] — an
/// absent aggregate is never returned as a zero vector. Deterministic and
/// worker-count-invariant: the sum is order-independent and the divisor is the
/// exact accumulated mass.
pub fn learned_role_aggregate(members: &[DirectoryMember]) -> Result<[f32; LAYER_ROLE_COUNT]> {
    if members.is_empty() {
        return Err(DomainError::new(
            ASTRO_LAYOUT_FRAME_EMPTY,
            "directory has no members to aggregate a learned role frame from",
            "index the directory's symbols so their S23 posteriors exist, or declare its role in astro.layout.declared_map.v1",
        ));
    }
    let mut sum = [0.0_f64; LAYER_ROLE_COUNT];
    for member in members {
        let vector = decode_slot_raw(&member.s23_raw_bytes).map_err(|error| {
            DomainError::new(
                ASTRO_LAYOUT_S23_DECODE,
                format!(
                    "member {:?} S23 sidecar undecodable: {}",
                    member.symbol_id,
                    error.message()
                ),
                "re-persist the member's guard-raw slot_23.raw sidecar from the S23 encoder's real output",
            )
        })?;
        let data = vector.as_dense().ok_or_else(|| {
            DomainError::new(
                ASTRO_LAYOUT_S23_DECODE,
                format!(
                    "member {:?} S23 sidecar is not a dense posterior",
                    member.symbol_id
                ),
                "re-persist the member's guard-raw slot_23.raw sidecar as a Dense(8) posterior",
            )
        })?;
        if data.len() != LAYER_ROLE_COUNT {
            return Err(DomainError::new(
                ASTRO_LAYOUT_S23_DECODE,
                format!(
                    "member {:?} S23 sidecar has dimension {}, expected {LAYER_ROLE_COUNT}",
                    member.symbol_id,
                    data.len()
                ),
                "re-persist the member's guard-raw slot_23.raw sidecar as a Dense(8) posterior",
            ));
        }
        for (accumulator, &value) in sum.iter_mut().zip(data.iter()) {
            if !value.is_finite() || value < 0.0 {
                return Err(DomainError::new(
                    ASTRO_LAYOUT_S23_DECODE,
                    format!(
                        "member {:?} S23 posterior carries a non-finite or negative mass",
                        member.symbol_id
                    ),
                    "re-persist the member's guard-raw slot_23.raw sidecar from the S23 encoder's real output",
                ));
            }
            *accumulator += f64::from(value);
        }
    }
    let total: f64 = sum.iter().sum();
    if total <= 0.0 {
        return Err(DomainError::new(
            ASTRO_LAYOUT_FRAME_EMPTY,
            "directory members carry no S23 role mass to aggregate",
            "index members whose S23 posteriors carry behavioral role mass, or declare the directory role",
        ));
    }
    let mut frame = [0.0_f32; LAYER_ROLE_COUNT];
    for (out, &accumulator) in frame.iter_mut().zip(sum.iter()) {
        *out = (accumulator / total) as f32;
    }
    Ok(frame)
}

/// Computes a directory-role frame: the declared one-hot prior when
/// `declared_role` is `Some`, else the L1 aggregate of `members`' persisted S23
/// posteriors.
///
/// A declared frame is identity-locked (`trust: verified`) and independent of
/// the members; a learned frame is a measurement (`trust: provisional` until
/// coherence is scored in #180d). Fails closed with [`ASTRO_LAYOUT_FRAME_EMPTY`]
/// when neither a declared role nor any member exists.
pub fn compute_directory_role_frame(
    directory_id: impl Into<String>,
    directory_path: impl Into<String>,
    declared_role: Option<LayerRole>,
    members: &[DirectoryMember],
) -> Result<DirectoryRoleFrame> {
    let directory_id = directory_id.into();
    let directory_path = directory_path.into();
    let (role_vector, source, trust) = match declared_role {
        Some(role) => {
            let mut vector = [0.0_f32; LAYER_ROLE_COUNT];
            vector[role.index()] = 1.0;
            (vector, FrameProvenance::Declared, "verified")
        }
        None => (
            learned_role_aggregate(members)?,
            FrameProvenance::LearnedAggregate,
            "provisional",
        ),
    };
    let dominant_role = dominant_role(&role_vector);
    let frame_hash = frame_content_hash(&directory_id, &directory_path, source, &role_vector);
    Ok(DirectoryRoleFrame {
        schema: DIRECTORY_ROLE_FRAME_SCHEMA,
        kind: DIRECTORY_ROLE_FRAME_KIND,
        directory_id,
        directory_path,
        role_vector,
        dominant_role,
        source,
        member_count: members.len(),
        frame_hash,
        trust,
        freshness: "fresh",
    })
}

/// Resolves a directory's declared canonical role from its path components via
/// the `astro.layout.declared_map.v1` knob, if any component maps.
///
/// The deepest (last) mapping component wins — a nested `api/models` directory
/// is a model directory. Returns `None` (a labeled absence, never a default)
/// when no component maps.
pub fn declared_role_for_path(directory_path: &str) -> Option<LayerRole> {
    directory_path
        .split(['/', '\\'])
        .rev()
        .find_map(role_for_directory)
}

/// Canonical byte form of a directory-role frame — the exact bytes persisted as
/// the scope-summary CF row for this directory.
///
/// The role vector is emitted as exact IEEE-754 bit patterns (never a lossy
/// text form) so a persisted frame round-trips bit-identically.
pub fn directory_role_frame_artifact_bytes(frame: &DirectoryRoleFrame) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(frame.schema);
    out.push('\n');
    out.push_str("kind=");
    out.push_str(frame.kind);
    out.push('\n');
    out.push_str("directory_id=");
    out.push_str(&frame.directory_id);
    out.push('\n');
    out.push_str("directory_path=");
    out.push_str(&frame.directory_path);
    out.push('\n');
    out.push_str("source=");
    out.push_str(frame.source.as_str());
    out.push('\n');
    out.push_str("member_count=");
    out.push_str(&frame.member_count.to_string());
    out.push('\n');
    out.push_str("dominant_role=");
    out.push_str(frame.dominant_role.as_str());
    out.push('\n');
    out.push_str("trust=");
    out.push_str(frame.trust);
    out.push('\n');
    out.push_str("freshness=");
    out.push_str(frame.freshness);
    out.push('\n');
    out.push_str("frame_hash=");
    out.push_str(&frame.frame_hash);
    out.push('\n');
    for (index, role) in CANONICAL_ROLES.iter().enumerate() {
        out.push_str("role\t");
        out.push_str(role.as_str());
        out.push('\t');
        out.push_str(&format!("{:08x}", frame.role_vector[index].to_bits()));
        out.push('\n');
    }
    out.into_bytes()
}

/// Reads a persisted directory-role frame artifact back into its role vector and
/// header fields (the independent-readback side of FSV 2).
///
/// Fails closed with [`ASTRO_LAYOUT_FRAME_CORRUPT`] on a truncated, reordered,
/// or malformed artifact so a corrupt persisted frame is never read as valid.
pub fn parse_directory_role_frame_artifact(bytes: &[u8]) -> Result<DirectoryRoleFrame> {
    let corrupt = |message: String| {
        DomainError::new(
            ASTRO_LAYOUT_FRAME_CORRUPT,
            message,
            "re-persist the directory-role frame from compute_directory_role_frame",
        )
    };
    let text = std::str::from_utf8(bytes)
        .map_err(|error| corrupt(format!("frame artifact is not UTF-8: {error}")))?;
    let mut schema = None;
    let mut kind = None;
    let mut directory_id = None;
    let mut directory_path = None;
    let mut source = None;
    let mut member_count = None;
    let mut trust = None;
    let mut freshness = None;
    let mut frame_hash = None;
    let mut dominant_role_field = None;
    let mut role_bits: [Option<u32>; LAYER_ROLE_COUNT] = [None; LAYER_ROLE_COUNT];
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("role\t") {
            let mut parts = rest.split('\t');
            let role_name = parts
                .next()
                .ok_or_else(|| corrupt("role line missing role name".to_string()))?;
            let bits_hex = parts
                .next()
                .ok_or_else(|| corrupt("role line missing value bits".to_string()))?;
            let role = LayerRole::from_str_canonical(role_name)
                .ok_or_else(|| corrupt(format!("unknown canonical role {role_name:?}")))?;
            let bits = u32::from_str_radix(bits_hex, 16)
                .map_err(|error| corrupt(format!("role value bits invalid: {error}")))?;
            if role_bits[role.index()].replace(bits).is_some() {
                return Err(corrupt(format!("duplicate role line for {role_name:?}")));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(corrupt(format!(
                "frame artifact line without '=': {line:?}"
            )));
        };
        match key {
            "schema" => schema = Some(value.to_string()),
            "kind" => kind = Some(value.to_string()),
            "directory_id" => directory_id = Some(value.to_string()),
            "directory_path" => directory_path = Some(value.to_string()),
            "source" => source = Some(value.to_string()),
            "member_count" => member_count = Some(value.to_string()),
            "dominant_role" => dominant_role_field = Some(value.to_string()),
            "trust" => trust = Some(value.to_string()),
            "freshness" => freshness = Some(value.to_string()),
            "frame_hash" => frame_hash = Some(value.to_string()),
            other => return Err(corrupt(format!("unknown frame artifact field {other:?}"))),
        }
    }
    let mut role_vector = [0.0_f32; LAYER_ROLE_COUNT];
    for (index, bits) in role_bits.iter().copied().enumerate() {
        let bits = bits.ok_or_else(|| {
            corrupt(format!(
                "frame artifact missing role dimension {}",
                CANONICAL_ROLES[index].as_str()
            ))
        })?;
        role_vector[index] = f32::from_bits(bits);
    }
    let field = |name: &str, value: Option<String>| {
        value.ok_or_else(|| corrupt(format!("frame artifact missing {name}")))
    };
    let schema_value = field("schema", schema)?;
    if schema_value != DIRECTORY_ROLE_FRAME_SCHEMA {
        return Err(corrupt(format!("unexpected frame schema {schema_value:?}")));
    }
    let kind_value = field("kind", kind)?;
    if kind_value != DIRECTORY_ROLE_FRAME_KIND {
        return Err(corrupt(format!("unexpected frame kind {kind_value:?}")));
    }
    let source_value = field("source", source)?;
    let source = FrameProvenance::from_str(&source_value)
        .ok_or_else(|| corrupt(format!("unknown frame source {source_value:?}")))?;
    let member_count = field("member_count", member_count)?
        .parse::<usize>()
        .map_err(|error| corrupt(format!("member_count invalid: {error}")))?;
    let directory_id = field("directory_id", directory_id)?;
    let directory_path = field("directory_path", directory_path)?;
    let frame_hash = field("frame_hash", frame_hash)?;
    // Trust and freshness are frozen labels; keep the leaked references stable.
    let trust = match field("trust", trust)?.as_str() {
        "verified" => "verified",
        "provisional" => "provisional",
        other => return Err(corrupt(format!("unknown trust label {other:?}"))),
    };
    let freshness = match field("freshness", freshness)?.as_str() {
        "fresh" => "fresh",
        other => return Err(corrupt(format!("unknown freshness label {other:?}"))),
    };
    let dominant_role = dominant_role(&role_vector);
    if let Some(field) = dominant_role_field {
        if field != dominant_role.as_str() {
            return Err(corrupt(format!(
                "persisted dominant_role {field:?} disagrees with the role vector argmax {:?}",
                dominant_role.as_str()
            )));
        }
    } else {
        return Err(corrupt("frame artifact missing dominant_role".to_string()));
    }
    let expected_hash = frame_content_hash(&directory_id, &directory_path, source, &role_vector);
    if expected_hash != frame_hash {
        return Err(corrupt(
            "frame_hash does not match the persisted role vector".to_string(),
        ));
    }
    Ok(DirectoryRoleFrame {
        schema: DIRECTORY_ROLE_FRAME_SCHEMA,
        kind: DIRECTORY_ROLE_FRAME_KIND,
        directory_id,
        directory_path,
        role_vector,
        dominant_role,
        source,
        member_count,
        frame_hash,
        trust,
        freshness,
    })
}

/// One decoded `placement_truth` cross-term: a symbol's S23 agreement with its
/// directory-role frame, in the same frozen coordinate system.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementTruthRow {
    /// Row schema (`astrolabe.placement_truth.v1`).
    pub schema: &'static str,
    /// Symbol CxId (or stable id).
    pub symbol_id: String,
    /// Qualified name (for findings and exemplars).
    pub qualified_name: String,
    /// Directory CxId (or stable id) whose frame this symbol was scored against.
    pub directory_id: String,
    /// Overlap agreement in `[0, 1]` between the symbol's S23 posterior and the
    /// directory-role frame (`sum_i min(s23_i, frame_i)`).
    pub agreement: f32,
    /// Argmax role of the symbol's S23 posterior.
    pub symbol_role: LayerRole,
    /// Argmax role of the directory-role frame.
    pub directory_role: LayerRole,
    /// Whether the symbol's behavioral role matches its directory's role.
    pub agrees: bool,
    /// Provenance label for the aspect/finding consumer.
    pub provenance: &'static str,
}

/// Overlap agreement between two `Dense(8)` L1 distributions in the frozen
/// canonical-role coordinate system: `sum_i min(a_i, b_i)` ∈ `[0, 1]`.
///
/// For two probability vectors this equals `1 - ½·‖a-b‖₁` (the complement of
/// total variation), so identical distributions score 1.0 and disjoint ones
/// 0.0. A fixed mathematical definition, not a tunable weight (invariant 4).
pub fn placement_truth_agreement(
    symbol_s23: &[f32; LAYER_ROLE_COUNT],
    frame: &[f32; LAYER_ROLE_COUNT],
) -> f32 {
    let mut overlap = 0.0_f64;
    for (a, b) in symbol_s23.iter().zip(frame.iter()) {
        overlap += f64::from(a.min(*b));
    }
    overlap as f32
}

/// Computes the `placement_truth` cross-term for one member against a frame.
///
/// The member's persisted S23 sidecar is independently decoded; a corrupt or
/// wrong-shape sidecar fails closed with [`ASTRO_LAYOUT_S23_DECODE`].
pub fn compute_placement_truth(
    member: &DirectoryMember,
    frame: &DirectoryRoleFrame,
) -> Result<PlacementTruthRow> {
    let s23 = decode_member_posterior(member)?;
    let agreement = placement_truth_agreement(&s23, &frame.role_vector);
    let symbol_role = dominant_role(&s23);
    Ok(PlacementTruthRow {
        schema: PLACEMENT_TRUTH_SCHEMA,
        symbol_id: member.symbol_id.clone(),
        qualified_name: member.qualified_name.clone(),
        directory_id: frame.directory_id.clone(),
        agreement,
        symbol_role,
        directory_role: frame.dominant_role,
        agrees: symbol_role == frame.dominant_role,
        provenance: PLACEMENT_TRUTH_PROVENANCE,
    })
}

/// Builds the `xterm` CF key for a `placement_truth` cross-term:
/// `symbol_cx || directory_cx` — the `(symbol CxId, directory CxId)` shape the
/// blueprint assigns this designed cross-term.
pub fn placement_truth_xterm_key(symbol_cx: &[u8], directory_cx: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(symbol_cx.len() + directory_cx.len());
    key.extend_from_slice(symbol_cx);
    key.extend_from_slice(directory_cx);
    key
}

/// Canonical byte form of a `placement_truth` row — the exact value bytes
/// persisted under [`placement_truth_xterm_key`] in the `xterm` CF. The
/// agreement is emitted as its exact IEEE-754 bit pattern.
pub fn placement_truth_row_bytes(row: &PlacementTruthRow) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(row.schema);
    out.push('\n');
    out.push_str("symbol_id=");
    out.push_str(&row.symbol_id);
    out.push('\n');
    out.push_str("qualified_name=");
    out.push_str(&row.qualified_name);
    out.push('\n');
    out.push_str("directory_id=");
    out.push_str(&row.directory_id);
    out.push('\n');
    out.push_str("agreement=");
    out.push_str(&format!("{:08x}", row.agreement.to_bits()));
    out.push('\n');
    out.push_str("symbol_role=");
    out.push_str(row.symbol_role.as_str());
    out.push('\n');
    out.push_str("directory_role=");
    out.push_str(row.directory_role.as_str());
    out.push('\n');
    out.push_str("agrees=");
    out.push_str(if row.agrees { "true" } else { "false" });
    out.push('\n');
    out.into_bytes()
}

/// A per-symbol placement-drift finding for the `layout_map` aspect.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementDisagreement {
    /// Drifting symbol CxId (or id).
    pub symbol_id: String,
    /// Drifting symbol qualified name.
    pub qualified_name: String,
    /// The role the symbol behaves as.
    pub symbol_role: LayerRole,
    /// The role its directory is assigned.
    pub directory_role: LayerRole,
    /// Placement agreement in `[0, 1]`.
    pub agreement: f32,
    /// Stable finding code (`ASTRO_LAYOUT_PLACEMENT_DRIFT`).
    pub code: &'static str,
    /// Human-readable finding message.
    pub message: String,
    /// Remediation guidance.
    pub remediation: &'static str,
}

/// One directory entry in the `layout_map` aspect.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryLayoutEntry {
    /// Directory CxId (or id).
    pub directory_id: String,
    /// Directory path.
    pub directory_path: String,
    /// The directory's assigned role (frame argmax).
    pub role: LayerRole,
    /// The full `Dense(8)` L1 frame vector.
    pub role_vector: [f32; LAYER_ROLE_COUNT],
    /// Whether the role is declared or a learned aggregate.
    pub source: FrameProvenance,
    /// Layout coherence: mean `placement_truth` agreement over members
    /// (`None` when the directory has no scored members — never zero-filled).
    pub coherence: Option<f32>,
    /// Number of members scored against the frame.
    pub member_count: usize,
    /// Members whose behavioral role disagrees with the directory role, sorted
    /// by ascending agreement then symbol id (deterministic).
    pub top_disagreements: Vec<PlacementDisagreement>,
    /// Trust label inherited from the frame.
    pub trust: &'static str,
}

/// The `get_architecture` / context-pack `layout_map` aspect.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutMapAspect {
    /// Stable payload schema.
    pub schema: &'static str,
    /// `empty` when no directory frame exists, else `built`.
    pub status: &'static str,
    /// Number of directory entries.
    pub directory_count: usize,
    /// Per-directory layout entries, sorted by directory id (deterministic).
    pub directories: Vec<DirectoryLayoutEntry>,
    /// Mean coherence over directories with a scored coherence (`None` when
    /// none is scored — never zero-filled).
    pub mean_coherence: Option<f32>,
    /// Total placement-drift disagreements across all directories.
    pub disagreement_count: usize,
    /// Provenance label: the physical source of the underlying frame rows.
    pub provenance: &'static str,
    /// Freshness label.
    pub freshness: &'static str,
    /// Trust label: `verified` only when every directory frame is verified.
    pub trust: &'static str,
}

/// A frame plus its members, the input to one `layout_map` directory entry.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryLayoutInput {
    /// The directory's computed role frame.
    pub frame: DirectoryRoleFrame,
    /// The directory's members (their persisted S23 sidecars).
    pub members: Vec<DirectoryMember>,
}

/// Builds the `layout_map` aspect from computed directory frames and their
/// members.
///
/// Per directory: scores each member's `placement_truth` against the frame,
/// reports coherence as the mean member agreement, and lists every drifting
/// member (behavioral role ≠ directory role) as a placement-drift finding.
/// Member S23 decode fails closed with [`ASTRO_LAYOUT_S23_DECODE`]. Emits an
/// `empty` aspect (never an error) when there are no directories, so a
/// first-touch consumer sees a labeled empty rather than a fabricated map.
pub fn build_layout_map_aspect(inputs: &[DirectoryLayoutInput]) -> Result<LayoutMapAspect> {
    let mut directories = Vec::with_capacity(inputs.len());
    let mut disagreement_count = 0usize;
    let mut coherence_sum = 0.0_f64;
    let mut coherence_count = 0usize;
    let mut all_verified = true;

    for input in inputs {
        let frame = &input.frame;
        if frame.trust != "verified" {
            all_verified = false;
        }
        let mut agreement_sum = 0.0_f64;
        let mut disagreements = Vec::new();
        for member in &input.members {
            let row = compute_placement_truth(member, frame)?;
            agreement_sum += f64::from(row.agreement);
            if !row.agrees {
                disagreement_count += 1;
                disagreements.push(PlacementDisagreement {
                    symbol_id: row.symbol_id.clone(),
                    qualified_name: row.qualified_name.clone(),
                    symbol_role: row.symbol_role,
                    directory_role: row.directory_role,
                    agreement: row.agreement,
                    code: ASTRO_LAYOUT_PLACEMENT_DRIFT,
                    message: format!(
                        "{} behaves as {} but lives in {} assigned {}",
                        row.qualified_name,
                        row.symbol_role.as_str(),
                        frame.directory_path,
                        row.directory_role.as_str()
                    ),
                    remediation: "move the symbol to a directory of its behavioral role, or reclassify the directory in astro.layout.declared_map.v1",
                });
            }
        }
        disagreements.sort_by(|left, right| {
            left.agreement
                .total_cmp(&right.agreement)
                .then_with(|| left.symbol_id.cmp(&right.symbol_id))
        });
        let coherence = if input.members.is_empty() {
            None
        } else {
            let value = (agreement_sum / input.members.len() as f64) as f32;
            coherence_sum += f64::from(value);
            coherence_count += 1;
            Some(value)
        };
        directories.push(DirectoryLayoutEntry {
            directory_id: frame.directory_id.clone(),
            directory_path: frame.directory_path.clone(),
            role: frame.dominant_role,
            role_vector: frame.role_vector,
            source: frame.source,
            coherence,
            member_count: input.members.len(),
            top_disagreements: disagreements,
            trust: frame.trust,
        });
    }
    directories.sort_by(|left, right| left.directory_id.cmp(&right.directory_id));

    let mean_coherence =
        (coherence_count > 0).then(|| (coherence_sum / coherence_count as f64) as f32);
    Ok(LayoutMapAspect {
        schema: LAYOUT_MAP_ASPECT_SCHEMA,
        status: if directories.is_empty() {
            "empty"
        } else {
            "built"
        },
        directory_count: directories.len(),
        directories,
        mean_coherence,
        disagreement_count,
        provenance: DIRECTORY_ROLE_FRAME_PROVENANCE,
        freshness: "fresh",
        trust: if all_verified && !inputs.is_empty() {
            "verified"
        } else {
            "provisional"
        },
    })
}

/// A declared⇔learned directory-role disagreement — the first-class boundary-diff
/// finding surfaced through `get_architecture`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeclaredLearnedDisagreement {
    /// Directory path.
    pub directory_path: String,
    /// Directory CxId (or id).
    pub directory_id: String,
    /// The role the repo declared.
    pub declared_role: LayerRole,
    /// The role the members actually behave as (learned argmax).
    pub learned_role: LayerRole,
    /// Fraction of the learned aggregate mass NOT on the declared role, in
    /// `[0, 1]` — the measured strength of the disagreement.
    pub off_declared_fraction: f32,
    /// Number of members contributing to the learned aggregate.
    pub member_count: usize,
    /// Stable finding code (`ASTRO_LAYOUT_DECLARED_LEARNED_DISAGREEMENT`).
    pub code: &'static str,
    /// Human-readable finding message.
    pub message: String,
    /// Remediation guidance.
    pub remediation: &'static str,
}

/// Compares a directory's declared role against the learned aggregate of its
/// members' S23 posteriors, returning a boundary-diff finding when the learned
/// dominant role differs from the declared role.
///
/// The finding fires on an argmax disagreement (a boolean structural test — no
/// tunable threshold, invariant 4) and reports the measured off-declared mass
/// fraction as its strength. Returns `Ok(None)` when the members behave as
/// declared. Fails closed with [`ASTRO_LAYOUT_S23_DECODE`]/[`ASTRO_LAYOUT_FRAME_EMPTY`]
/// on undecodable or empty members.
pub fn layout_boundary_diff(
    directory_id: impl Into<String>,
    directory_path: impl Into<String>,
    declared_role: LayerRole,
    members: &[DirectoryMember],
) -> Result<Option<DeclaredLearnedDisagreement>> {
    let learned = learned_role_aggregate(members)?;
    let learned_role = dominant_role(&learned);
    if learned_role == declared_role {
        return Ok(None);
    }
    let on_declared = f64::from(learned[declared_role.index()]);
    let off_declared_fraction = (1.0 - on_declared).clamp(0.0, 1.0) as f32;
    let directory_path = directory_path.into();
    let off_percent = (f64::from(off_declared_fraction) * 100.0).round() as u32;
    Ok(Some(DeclaredLearnedDisagreement {
        directory_path: directory_path.clone(),
        directory_id: directory_id.into(),
        declared_role,
        learned_role,
        off_declared_fraction,
        member_count: members.len(),
        code: ASTRO_LAYOUT_DECLARED_LEARNED_DISAGREEMENT,
        message: format!(
            "{} is declared {} but {}% of its members behave otherwise (dominant learned role {})",
            directory_path,
            declared_role.as_str(),
            off_percent,
            learned_role.as_str()
        ),
        remediation: "move the off-role members out, or update the directory's declared role in astro.layout.declared_map.v1",
    }))
}

/// The first-touch layout orientation served to a fresh agent.
#[derive(Debug, Clone, PartialEq)]
pub enum FirstTouchLayout {
    /// A declared map exists: serve the declared directory roles directly, before
    /// any retrieval.
    Declared(Vec<DirectoryLayoutEntry>),
    /// No declared map, but the repo is indexed: serve the learned `layout_map`.
    Learned(LayoutMapAspect),
}

/// Resolves first-touch layout orientation, failing closed when neither a
/// declared map nor an index exists.
///
/// When `declared` is `Some`, the declared entries are served directly (cheap
/// orientation before any retrieval). Otherwise, when `learned` is `Some`, the
/// learned aggregate map is served. When both are absent the surface refuses
/// with [`ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE`] — never a fabricated map.
pub fn first_touch_layout(
    declared: Option<Vec<DirectoryLayoutEntry>>,
    learned: Option<LayoutMapAspect>,
) -> Result<FirstTouchLayout> {
    if let Some(entries) = declared {
        return Ok(FirstTouchLayout::Declared(entries));
    }
    if let Some(aspect) = learned {
        return Ok(FirstTouchLayout::Learned(aspect));
    }
    Err(DomainError::new(
        ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE,
        "layout orientation unavailable: no declared map and no index",
        "declare astro.layout.declared_map.v1 or index the repository before requesting first-touch layout orientation",
    ))
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

fn decode_member_posterior(member: &DirectoryMember) -> Result<[f32; LAYER_ROLE_COUNT]> {
    let vector = decode_slot_raw(&member.s23_raw_bytes).map_err(|error| {
        DomainError::new(
            ASTRO_LAYOUT_S23_DECODE,
            format!(
                "member {:?} S23 sidecar undecodable: {}",
                member.symbol_id,
                error.message()
            ),
            "re-persist the member's guard-raw slot_23.raw sidecar from the S23 encoder's real output",
        )
    })?;
    let data = vector.as_dense().ok_or_else(|| {
        DomainError::new(
            ASTRO_LAYOUT_S23_DECODE,
            format!(
                "member {:?} S23 sidecar is not a dense posterior",
                member.symbol_id
            ),
            "re-persist the member's guard-raw slot_23.raw sidecar as a Dense(8) posterior",
        )
    })?;
    if data.len() != LAYER_ROLE_COUNT {
        return Err(DomainError::new(
            ASTRO_LAYOUT_S23_DECODE,
            format!(
                "member {:?} S23 sidecar has dimension {}, expected {LAYER_ROLE_COUNT}",
                member.symbol_id,
                data.len()
            ),
            "re-persist the member's guard-raw slot_23.raw sidecar as a Dense(8) posterior",
        ));
    }
    let mut out = [0.0_f32; LAYER_ROLE_COUNT];
    for (slot, &value) in out.iter_mut().zip(data.iter()) {
        if !value.is_finite() || value < 0.0 {
            return Err(DomainError::new(
                ASTRO_LAYOUT_S23_DECODE,
                format!(
                    "member {:?} S23 posterior carries a non-finite or negative mass",
                    member.symbol_id
                ),
                "re-persist the member's guard-raw slot_23.raw sidecar from the S23 encoder's real output",
            ));
        }
        *slot = value;
    }
    Ok(out)
}

/// Argmax over the frozen canonical-role order; the lowest canonical index wins
/// ties, so the dominant role is deterministic.
fn dominant_role(vector: &[f32; LAYER_ROLE_COUNT]) -> LayerRole {
    let mut best_index = 0usize;
    let mut best_value = vector[0];
    for (index, &value) in vector.iter().enumerate().skip(1) {
        if value > best_value {
            best_value = value;
            best_index = index;
        }
    }
    CANONICAL_ROLES[best_index]
}

fn frame_content_hash(
    directory_id: &str,
    directory_path: &str,
    source: FrameProvenance,
    role_vector: &[f32; LAYER_ROLE_COUNT],
) -> String {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(directory_id.as_bytes());
    canonical.push(b'\t');
    canonical.extend_from_slice(directory_path.as_bytes());
    canonical.push(b'\t');
    canonical.extend_from_slice(source.as_str().as_bytes());
    canonical.push(b'\n');
    for value in role_vector {
        canonical.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    let digest =
        astrolabe_domain::calyx::content_address([FRAME_ARTIFACT_TAG, canonical.as_slice()]);
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod fsv {
    //! Full State Verification for the directory-role frame, `placement_truth`
    //! cross-term, and `layout_map` aspect (#180b).
    //!
    //! Members' S23 posteriors are persisted to **real files** in the exact
    //! guard-raw `slot_23.raw` CF byte form via
    //! [`astrolabe_panel::slot_raw_bytes`]; the frame and cross-term rows are
    //! persisted in their exact CF byte form; every assertion reads the bytes
    //! back off disk and recomputes independently. No mocks.

    use super::*;
    use astrolabe_domain::calyx::SlotVector;
    use astrolabe_panel::slot_raw_bytes;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-kernel-layout-{name}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create layout fsv dir");
        dir
    }

    /// Encodes a hand-computed Dense(8) S23 posterior into the exact guard-raw
    /// CF byte form.
    fn s23_bytes(mass: [f32; LAYER_ROLE_COUNT]) -> Vec<u8> {
        let vector = SlotVector::Dense {
            dim: LAYER_ROLE_COUNT as u32,
            data: mass.to_vec(),
        };
        slot_raw_bytes(&vector).expect("serialize guard-raw S23 posterior")
    }

    fn one_hot(role: LayerRole) -> [f32; LAYER_ROLE_COUNT] {
        let mut mass = [0.0_f32; LAYER_ROLE_COUNT];
        mass[role.index()] = 1.0;
        mass
    }

    /// Persists a member's S23 sidecar to a real file and returns the member.
    fn persist_member(
        dir: &Path,
        symbol_id: &str,
        qn: &str,
        mass: [f32; LAYER_ROLE_COUNT],
    ) -> DirectoryMember {
        let bytes = s23_bytes(mass);
        fs::write(dir.join(format!("{symbol_id}.slot_23.raw")), &bytes).expect("persist sidecar");
        DirectoryMember::new(symbol_id, qn, bytes)
    }

    /// Independently reads a member's persisted sidecar off disk and decodes its
    /// Dense(8) posterior — the readback side of FSV 2.
    fn readback_posterior(dir: &Path, symbol_id: &str) -> [f32; LAYER_ROLE_COUNT] {
        let bytes = fs::read(dir.join(format!("{symbol_id}.slot_23.raw"))).expect("read sidecar");
        let vector = decode_slot_raw(&bytes).expect("decode sidecar");
        let data = vector.as_dense().expect("dense sidecar").to_vec();
        assert_eq!(data.len(), LAYER_ROLE_COUNT, "S23 sidecar must be Dense(8)");
        let mut out = [0.0_f32; LAYER_ROLE_COUNT];
        out.copy_from_slice(&data);
        out
    }

    // FSV 2 — independent recompute of the L1 aggregate from members' persisted
    // S23 CF bytes must equal the persisted directory-role frame row.
    #[test]
    fn fsv2_learned_aggregate_from_persisted_bytes_equals_persisted_frame() {
        let dir = fresh_dir("fsv2");
        // A directory with no declared role: the frame is the learned aggregate.
        // Two members, one transport one-hot and one persistence one-hot, so the
        // hand-computed aggregate is exactly [0.5, 0, 0.5, 0, 0, 0, 0, 0].
        let members = vec![
            persist_member(
                &dir,
                "sym_t",
                "mixed::serve",
                one_hot(LayerRole::TransportApi),
            ),
            persist_member(
                &dir,
                "sym_p",
                "mixed::store",
                one_hot(LayerRole::Persistence),
            ),
        ];

        let frame = compute_directory_role_frame("dir_mixed", "mixed", None, &members)
            .expect("compute learned frame");
        assert_eq!(frame.source, FrameProvenance::LearnedAggregate);
        assert_eq!(frame.trust, "provisional");

        // Persist the frame row and read it back off disk (persisted-state side).
        let frame_path = dir.join("frame_mixed.row");
        fs::write(&frame_path, directory_role_frame_artifact_bytes(&frame)).expect("persist frame");
        let persisted =
            parse_directory_role_frame_artifact(&fs::read(&frame_path).expect("read frame row"))
                .expect("parse persisted frame");

        // Independently recompute the L1 aggregate from the members' persisted
        // S23 sidecar bytes (decode off disk, sum, normalize) — not the frame API.
        let mut sum = [0.0_f64; LAYER_ROLE_COUNT];
        for symbol_id in ["sym_t", "sym_p"] {
            let posterior = readback_posterior(&dir, symbol_id);
            for (acc, value) in sum.iter_mut().zip(posterior.iter()) {
                *acc += f64::from(*value);
            }
        }
        let total: f64 = sum.iter().sum();
        let mut recomputed = [0.0_f32; LAYER_ROLE_COUNT];
        for (out, acc) in recomputed.iter_mut().zip(sum.iter()) {
            *out = (acc / total) as f32;
        }

        assert_eq!(
            recomputed,
            [0.5, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0],
            "hand-computed aggregate must match"
        );
        assert_eq!(
            persisted.role_vector, recomputed,
            "persisted frame row must equal the independent recompute from persisted S23 bytes"
        );
        assert_eq!(persisted.role_vector, frame.role_vector);
        // Argmax tie-break is deterministic (lowest canonical index wins).
        assert_eq!(persisted.dominant_role, LayerRole::TransportApi);

        let _ = fs::remove_dir_all(&dir);
    }

    // Determinism / worker-count-invariance: the aggregate is order- and
    // thread-count-independent because it is a commutative sum over persisted
    // bytes.
    #[test]
    fn fsv2_aggregate_is_worker_count_invariant() {
        let dir = fresh_dir("winv");
        let members = vec![
            persist_member(&dir, "a", "m::a", one_hot(LayerRole::TransportApi)),
            persist_member(&dir, "b", "m::b", one_hot(LayerRole::Persistence)),
            persist_member(&dir, "c", "m::c", one_hot(LayerRole::ServiceDomain)),
            persist_member(&dir, "d", "m::d", one_hot(LayerRole::Persistence)),
        ];

        let sequential = learned_role_aggregate(&members).expect("sequential aggregate");

        // Parallel decode+recompute across threads, then the same normalize.
        let sums: Vec<[f64; LAYER_ROLE_COUNT]> = std::thread::scope(|scope| {
            let handles: Vec<_> = members
                .iter()
                .map(|member| {
                    scope.spawn(|| {
                        let posterior = decode_member_posterior(member).expect("decode");
                        let mut partial = [0.0_f64; LAYER_ROLE_COUNT];
                        for (acc, value) in partial.iter_mut().zip(posterior.iter()) {
                            *acc += f64::from(*value);
                        }
                        partial
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("join"))
                .collect()
        });
        let mut total = [0.0_f64; LAYER_ROLE_COUNT];
        for partial in &sums {
            for (acc, value) in total.iter_mut().zip(partial.iter()) {
                *acc += value;
            }
        }
        let mass: f64 = total.iter().sum();
        let mut parallel = [0.0_f32; LAYER_ROLE_COUNT];
        for (out, acc) in parallel.iter_mut().zip(total.iter()) {
            *out = (acc / mass) as f32;
        }
        assert_eq!(
            sequential, parallel,
            "aggregate must be worker-count-invariant"
        );

        // Byte-identical persisted frame across a reordered member set.
        let frame_a = compute_directory_role_frame("d", "m", None, &members).unwrap();
        let mut reordered = members.clone();
        reordered.reverse();
        let frame_b = compute_directory_role_frame("d", "m", None, &reordered).unwrap();
        assert_eq!(
            directory_role_frame_artifact_bytes(&frame_a),
            directory_role_frame_artifact_bytes(&frame_b),
            "frame bytes must be member-order-independent"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // Declared frame: one-hot, identity-locked, verified trust.
    #[test]
    fn declared_frame_is_one_hot_and_verified() {
        let declared = declared_role_for_path("services");
        assert_eq!(declared, Some(LayerRole::ServiceDomain));
        let frame = compute_directory_role_frame("d_services", "services", declared, &[])
            .expect("declared frame needs no members");
        assert_eq!(frame.source, FrameProvenance::Declared);
        assert_eq!(frame.trust, "verified");
        assert_eq!(frame.dominant_role, LayerRole::ServiceDomain);
        assert_eq!(frame.role_vector, one_hot(LayerRole::ServiceDomain));
        // Deepest component wins on a nested path.
        assert_eq!(
            declared_role_for_path("api/models"),
            Some(LayerRole::ModelSchema)
        );
    }

    // Edge (empty dir): no declared role and no members must fail closed.
    #[test]
    fn edge_empty_directory_fails_closed() {
        let err = compute_directory_role_frame("d_empty", "empty", None, &[])
            .expect_err("empty directory must fail closed");
        assert_eq!(err.code(), ASTRO_LAYOUT_FRAME_EMPTY);
        assert!(!err.message().is_empty());
        assert!(!err.remediation().is_empty());
    }

    // Edge (mixed-role dir) + declared⇔learned disagreement surfacing: api/ is
    // declared TransportApi but its members mostly do persistence, so the
    // boundary diff must surface the disagreement finding.
    #[test]
    fn edge_mixed_dir_surfaces_declared_learned_disagreement() {
        let dir = fresh_dir("boundary");
        // 1 transport member + 3 persistence members: learned dominant role is
        // Persistence, off-declared mass fraction = 0.75.
        let members = vec![
            persist_member(&dir, "h", "api::route", one_hot(LayerRole::TransportApi)),
            persist_member(&dir, "s1", "api::insert", one_hot(LayerRole::Persistence)),
            persist_member(&dir, "s2", "api::update", one_hot(LayerRole::Persistence)),
            persist_member(&dir, "s3", "api::delete", one_hot(LayerRole::Persistence)),
        ];
        let finding = layout_boundary_diff("d_api", "api", LayerRole::TransportApi, &members)
            .expect("boundary diff")
            .expect("disagreement must surface");
        assert_eq!(finding.code, ASTRO_LAYOUT_DECLARED_LEARNED_DISAGREEMENT);
        assert_eq!(finding.declared_role, LayerRole::TransportApi);
        assert_eq!(finding.learned_role, LayerRole::Persistence);
        assert_eq!(finding.off_declared_fraction, 0.75);
        assert!(
            finding.message.contains("75%"),
            "message reports measured strength"
        );

        // When members behave as declared, no disagreement fires.
        let aligned = vec![
            persist_member(&dir, "a1", "data::q1", one_hot(LayerRole::Persistence)),
            persist_member(&dir, "a2", "data::q2", one_hot(LayerRole::Persistence)),
        ];
        let none = layout_boundary_diff("d_data", "data", LayerRole::Persistence, &aligned)
            .expect("boundary diff");
        assert_eq!(
            none, None,
            "aligned members must not surface a disagreement"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // Edge (invalid placement) + placement_truth persisted-byte readback: a
    // persistence fn living in an api/ directory drifts against the frame; the
    // cross-term row persists and reads back with the drift finding.
    #[test]
    fn edge_invalid_placement_drifts_and_persists_cross_term() {
        let dir = fresh_dir("placement");
        // Declared api/ = TransportApi frame.
        let frame =
            compute_directory_role_frame("d_api", "api", Some(LayerRole::TransportApi), &[])
                .expect("declared api frame");

        // A misplaced persistence-behaving symbol living in api/.
        let misplaced = persist_member(
            &dir,
            "mp",
            "api::save_user",
            one_hot(LayerRole::Persistence),
        );
        let row = compute_placement_truth(&misplaced, &frame).expect("placement truth");
        assert_eq!(row.symbol_role, LayerRole::Persistence);
        assert_eq!(row.directory_role, LayerRole::TransportApi);
        assert!(!row.agrees);
        // Overlap of two disjoint one-hots is 0.0.
        assert_eq!(row.agreement, 0.0);

        // A correctly placed handler agrees fully.
        let handler = persist_member(
            &dir,
            "ok",
            "api::get_user",
            one_hot(LayerRole::TransportApi),
        );
        let ok_row = compute_placement_truth(&handler, &frame).expect("placement truth");
        assert!(ok_row.agrees);
        assert_eq!(ok_row.agreement, 1.0);

        // Persist the placement_truth cross-term row (exact xterm CF bytes) and
        // read it back independently.
        let key = placement_truth_xterm_key(b"symbol-cx-mp", b"dir-cx-api");
        assert_eq!(key.len(), b"symbol-cx-mp".len() + b"dir-cx-api".len());
        let row_bytes = placement_truth_row_bytes(&row);
        let row_path = dir.join("xterm_placement_mp.row");
        fs::write(&row_path, &row_bytes).expect("persist placement row");
        let read = fs::read(&row_path).expect("read placement row");
        let text = String::from_utf8(read).expect("utf8");
        assert!(text.contains(&format!("agreement={:08x}", 0.0_f32.to_bits())));
        assert!(text.contains("symbol_role=persistence"));
        assert!(text.contains("directory_role=transport_api"));
        assert!(text.contains("agrees=false"));

        // The layout_map aspect over this directory lists the drift finding.
        let aspect = build_layout_map_aspect(&[DirectoryLayoutInput {
            frame: frame.clone(),
            members: vec![misplaced, handler],
        }])
        .expect("layout map aspect");
        assert_eq!(aspect.status, "built");
        assert_eq!(aspect.directory_count, 1);
        assert_eq!(aspect.disagreement_count, 1);
        let entry = &aspect.directories[0];
        assert_eq!(entry.role, LayerRole::TransportApi);
        // Coherence = mean(0.0 for misplaced, 1.0 for handler) = 0.5.
        assert_eq!(entry.coherence, Some(0.5));
        assert_eq!(entry.top_disagreements.len(), 1);
        assert_eq!(
            entry.top_disagreements[0].code,
            ASTRO_LAYOUT_PLACEMENT_DRIFT
        );
        assert_eq!(
            entry.top_disagreements[0].symbol_role,
            LayerRole::Persistence
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // Corrupt persisted frame fails closed on readback (not read as valid).
    #[test]
    fn corrupt_persisted_frame_fails_closed() {
        let dir = fresh_dir("corrupt");
        let members = vec![persist_member(
            &dir,
            "x",
            "m::x",
            one_hot(LayerRole::Persistence),
        )];
        let frame = compute_directory_role_frame("d", "m", None, &members).unwrap();
        let mut bytes = directory_role_frame_artifact_bytes(&frame);
        // Flip a role value byte so the frame_hash no longer matches.
        let needle = b"role\ttransport_api\t";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("role line present")
            + needle.len();
        bytes[pos] ^= 0xff;
        let err = parse_directory_role_frame_artifact(&bytes)
            .expect_err("tampered frame must fail closed");
        assert_eq!(err.code(), ASTRO_LAYOUT_FRAME_CORRUPT);

        // A member with a corrupt S23 sidecar also fails closed.
        let bad = DirectoryMember::new("bad", "m::bad", b"not-a-slot-envelope".to_vec());
        let err = learned_role_aggregate(&[bad]).expect_err("bad sidecar must fail closed");
        assert_eq!(err.code(), ASTRO_LAYOUT_S23_DECODE);

        let _ = fs::remove_dir_all(&dir);
    }

    // First-touch fail-closed: neither declared map nor index refuses; a declared
    // map or an index each serve orientation.
    #[test]
    fn first_touch_fails_closed_without_map_or_index() {
        let err = first_touch_layout(None, None).expect_err("first touch must fail closed");
        assert_eq!(err.code(), ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE);
        assert!(err.message().contains("unavailable"));
        assert!(!err.remediation().is_empty());

        // Declared map present: served directly.
        let entries = vec![DirectoryLayoutEntry {
            directory_id: "d".into(),
            directory_path: "api".into(),
            role: LayerRole::TransportApi,
            role_vector: one_hot(LayerRole::TransportApi),
            source: FrameProvenance::Declared,
            coherence: None,
            member_count: 0,
            top_disagreements: Vec::new(),
            trust: "verified",
        }];
        match first_touch_layout(Some(entries.clone()), None).expect("declared served") {
            FirstTouchLayout::Declared(served) => assert_eq!(served, entries),
            FirstTouchLayout::Learned(_) => panic!("declared map must be served directly"),
        }

        // No map but an index: the learned aspect is served.
        let empty_aspect = build_layout_map_aspect(&[]).expect("empty aspect");
        assert_eq!(empty_aspect.status, "empty");
        match first_touch_layout(None, Some(empty_aspect.clone())).expect("learned served") {
            FirstTouchLayout::Learned(served) => assert_eq!(served, empty_aspect),
            FirstTouchLayout::Declared(_) => panic!("index must serve the learned map"),
        }
    }
}
