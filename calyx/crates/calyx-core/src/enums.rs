//! Closed shared enum vocabulary for Calyx engines.

use serde::{Deserialize, Serialize};

use crate::SlotId;

/// Input modality for a constellation or lens slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Natural language text.
    Text,
    /// Source code or structured code artifacts.
    Code,
    /// Still images.
    Image,
    /// Audio streams or clips.
    Audio,
    /// Video streams or clips.
    Video,
    /// Protein or peptide sequences.
    Protein,
    /// DNA or nucleotide sequences.
    Dna,
    /// Molecules encoded as SMILES or related chemistry strings.
    Molecule,
    /// Structured records, tables, or typed objects.
    Structured,
    /// Mixed or multi-modal inputs.
    Mixed,
}

/// Physical vector shape produced by a lens slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotShape {
    /// Dense vector with a fixed dimension.
    Dense(u32),
    /// Sparse vector with a fixed ambient dimension.
    Sparse(u32),
    /// Multi-vector token representation with a fixed per-token dimension.
    Multi { token_dim: u32 },
}

/// Directional relationship for asymmetric slot pairings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Asymmetry {
    /// Symmetric or direction-free interpretation.
    None,
    /// Directed dual-slot relation.
    Dual { a: SlotId, b: SlotId },
}

/// Quantization policy attached to a slot or vector block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantPolicy {
    /// Store unquantized values.
    None,
    /// TurboQuant storage with `bits_per_channel_x2` where 7 means 3.5 bpc.
    TurboQuant { bits_per_channel_x2: u8 },
    /// Blackwell microscaling FP4 storage; requires current assay evidence.
    MxFp4,
    /// Product quantization with `m` subquantizers and `nbits` codebook bits.
    Pq { m: u8, nbits: u8 },
    /// Float8 storage.
    Float8,
    /// Binary storage.
    Binary,
}

impl QuantPolicy {
    /// Quality-neutral TurboQuant default from PRD 23 section 4.1.
    pub const fn turboquant_default() -> Self {
        Self::TurboQuant {
            bits_per_channel_x2: 7,
        }
    }
}

/// Grounded outcome axis for anchors and Assay bits.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// Deterministic test or oracle passed.
    TestPass,
    /// A tie or relationship was formed.
    TieFormed,
    /// User thumb signal.
    Thumbs,
    /// Named label axis.
    Label(String),
    /// Reward or outcome score.
    Reward,
    /// Speaker identity match.
    SpeakerMatch,
    /// Style/persona hold under pressure.
    StyleHold,
    /// Recurring event or outcome series.
    Recurrence,
}

/// Lifecycle state for a panel slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotState {
    /// Slot participates in new ingests and reads.
    Active,
    /// Slot is parked but remains interpretable for old constellations.
    Parked,
    /// Slot is tombstoned for future use but historical data remains readable.
    Retired,
}

/// Explicit reason a slot vector is absent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsentReason {
    /// Slot does not apply to this input or modality.
    NotApplicable,
    /// Source input or output was redacted by policy.
    Redacted,
    /// Lens was unavailable at ingest time.
    LensUnavailable,
    /// Slot is intentionally deferred for lazy backfill.
    Deferred,
    /// Slot is absent because the producing lens is parked or retired.
    LensInactive,
    /// Slot production failed with a stable code or short reason.
    Error(String),
}
