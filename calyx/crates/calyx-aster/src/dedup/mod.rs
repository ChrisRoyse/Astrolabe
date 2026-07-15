//! Vault-level deduplication policy contracts.

mod audit;
mod compression_ratio;
mod engine;
mod ingest_at;
mod ingest_event;
mod ingest_input;
mod ingest_ledger;
mod policy;
mod signature;

use calyx_core::{CalyxError, CxId, Panel, Result, Slot, SlotId};
use serde::{Deserialize, Serialize};

pub use audit::{
    CALYX_DEDUP_UNDO_EMPTY_TOKEN, CALYX_DEDUP_UNDO_MISSING_RESTORE, CALYX_DEDUP_WRONG_VAULT,
    DedupAuditReport, DedupRestoreSnapshot, DedupUndoRecord, MergeRecord, ReversalToken,
    dedup_audit, dedup_undo,
};
pub use compression_ratio::{
    CALYX_DEDUP_INVALID_FREQUENCY, CALYX_DEDUP_MISSING_FREQUENCY, CompressionRatio, Domain,
    DomainCompressionStats, compression_ratio, domain_compression_stats,
};
pub use engine::{
    DEFAULT_DEDUP_DPI_CANDIDATE_LIMIT, DedupDecision, check_dedup, check_dedup_with_limit,
    cosine_passes_all_required, resolve_tau,
};
pub use ingest_at::{ingest, ingest_at, ingest_at_with_retention};
pub use ingest_event::{
    DedupOnlineEvent, DedupOnlineKind, decode_dedup_online_event, dedup_online_key,
};
pub use ingest_input::{CALYX_DEDUP_INVALID_EVENT_TIME, EpochSecs, IngestInput};
pub(crate) use policy::is_recurrence_series_policy;
pub use policy::{
    ANCHOR_VECTOR_TAU, AnchorConflictResult, ConflictReason, ContestedWith, check_anchor_conflict,
    contested_with_key, decode_contested_with, encode_contested_with,
};
pub use signature::{
    CALYX_RECURRENCE_SLOT_MISSING, SignatureResult, detect_recurrence_signature,
    temporal_slot_ids_for_panel,
};

pub const CALYX_DEDUP_NO_REQUIRED_SLOTS: &str = "CALYX_DEDUP_NO_REQUIRED_SLOTS";
pub const CALYX_DEDUP_TEMPORAL_SLOT_IN_REQUIRED: &str = "CALYX_DEDUP_TEMPORAL_SLOT_IN_REQUIRED";
pub const CALYX_DEDUP_INVALID_TAU: &str = "CALYX_DEDUP_INVALID_TAU";
pub const CALYX_DEDUP_SLOT_NOT_IN_TAU: &str = "CALYX_DEDUP_SLOT_NOT_IN_TAU";
pub const CALYX_DEDUP_SLOT_NOT_IN_PANEL: &str = "CALYX_DEDUP_SLOT_NOT_IN_PANEL";
pub const CALYX_DEDUP_MISSING_GUARD_PROFILE: &str = "CALYX_DEDUP_MISSING_GUARD_PROFILE";
pub const CALYX_DEDUP_SLOT_NOT_IN_CONSTELLATION: &str = "CALYX_DEDUP_SLOT_NOT_IN_CONSTELLATION";
pub const CALYX_DEDUP_DPI_EXCEEDED: &str = "CALYX_DEDUP_DPI_EXCEEDED";
pub const CALYX_DEDUP_ANCHOR_CONFLICT: &str = "CALYX_DEDUP_ANCHOR_CONFLICT";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TauStrategy {
    PerSlot(Vec<(SlotId, f32)>),
    Calibrated,
}

impl TauStrategy {
    fn validate(&self, required_slots: &[SlotId]) -> Result<()> {
        if let Self::PerSlot(entries) = self {
            if entries.is_empty() {
                return Err(dedup_error(
                    CALYX_DEDUP_INVALID_TAU,
                    "per-slot tau strategy must include at least one threshold",
                ));
            }
            for (slot, tau) in entries {
                if !tau.is_finite() || !(-1.0..=1.0).contains(tau) {
                    return Err(dedup_error(
                        CALYX_DEDUP_INVALID_TAU,
                        format!("tau for slot {slot} must be finite and in -1.0..=1.0"),
                    ));
                }
            }
            for required in required_slots {
                if !entries.iter().any(|(slot, _)| slot == required) {
                    return Err(dedup_error(
                        CALYX_DEDUP_INVALID_TAU,
                        format!("required slot {required} is missing a per-slot tau"),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupAction {
    Collapse,
    Link,
    RecurrenceSeries,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TctCosineConfig {
    pub required_slots: Vec<SlotId>,
    pub tau: TauStrategy,
    pub action: DedupAction,
}

impl TctCosineConfig {
    pub fn new(required_slots: Vec<SlotId>, tau: TauStrategy, action: DedupAction) -> Result<Self> {
        let config = Self {
            required_slots,
            tau,
            action,
        };
        config.validate_static()?;
        Ok(config)
    }

    pub fn validate(&self, panel: &Panel) -> Result<()> {
        self.validate_static()?;
        for required in &self.required_slots {
            let Some(slot) = panel.slots.iter().find(|slot| slot.slot_id == *required) else {
                return Err(dedup_error(
                    CALYX_DEDUP_SLOT_NOT_IN_PANEL,
                    format!("required slot {required} is missing from the active panel"),
                ));
            };
            if slot_excluded_from_dedup(slot) {
                return Err(dedup_error(
                    CALYX_DEDUP_TEMPORAL_SLOT_IN_REQUIRED,
                    format!("required slot {required} maps to a temporal or dedup-excluded lens"),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_static(&self) -> Result<()> {
        if self.required_slots.is_empty() {
            return Err(dedup_error(
                CALYX_DEDUP_NO_REQUIRED_SLOTS,
                "TctCosine dedup requires at least one content slot",
            ));
        }
        self.tau.validate(&self.required_slots)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum DedupPolicy {
    #[default]
    Off,
    Exact,
    TctCosine(TctCosineConfig),
}

impl DedupPolicy {
    pub fn validate(&self, panel: &Panel) -> Result<()> {
        match self {
            Self::Off | Self::Exact => Ok(()),
            Self::TctCosine(config) => config.validate(panel),
        }
    }

    pub(crate) fn validate_manifest(&self) -> Result<()> {
        match self {
            Self::Off | Self::Exact => Ok(()),
            Self::TctCosine(config) => config.validate_static(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OccurrenceId(pub u64);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DedupResult {
    New(CxId),
    DedupMerge {
        into: CxId,
        occurrence: OccurrenceId,
    },
    ExactDuplicate(CxId),
}

fn slot_excluded_from_dedup(slot: &Slot) -> bool {
    slot.excluded_from_dedup || slot.retrieval_only || signature::is_temporal_slot(slot)
}

pub(crate) fn dedup_error(code: &'static str, message: impl Into<String>) -> CalyxError {
    let remediation = match code {
        CALYX_DEDUP_NO_REQUIRED_SLOTS => "choose at least one required content slot",
        CALYX_DEDUP_TEMPORAL_SLOT_IN_REQUIRED => {
            "remove E2/E3/E4 temporal lenses from required dedup slots"
        }
        CALYX_DEDUP_INVALID_TAU => "set finite cosine thresholds in -1.0..=1.0",
        CALYX_DEDUP_SLOT_NOT_IN_TAU => "add a threshold for every required dedup slot",
        CALYX_DEDUP_SLOT_NOT_IN_PANEL => {
            "add the required slot to the active panel or remove it from required_slots"
        }
        CALYX_DEDUP_MISSING_GUARD_PROFILE => {
            "provide a calibrated guard profile with tau for each required slot"
        }
        CALYX_DEDUP_SLOT_NOT_IN_CONSTELLATION => {
            "ensure every required content slot has a dense vector on both constellations"
        }
        CALYX_DEDUP_DPI_EXCEEDED => "reduce the candidate set or use Exact dedup policy",
        CALYX_DEDUP_ANCHOR_CONFLICT => "keep conflicting anchors as separate contested regions",
        CALYX_DEDUP_INVALID_EVENT_TIME => "use a non-negative Unix epoch timestamp in seconds",
        CALYX_DEDUP_MISSING_FREQUENCY => {
            "write recurrence.frequency to the Base CF before reading recurrence consumers"
        }
        CALYX_DEDUP_INVALID_FREQUENCY => {
            "store recurrence.frequency as a finite non-negative integer scalar"
        }
        CALYX_DEDUP_WRONG_VAULT => "apply the reversal token to the vault that produced it",
        CALYX_DEDUP_UNDO_MISSING_RESTORE => {
            "use a merge ledger entry that contains a dedup restore snapshot"
        }
        CALYX_DEDUP_UNDO_EMPTY_TOKEN => "use a reversal token with at least one snapshot CxId",
        _ => "inspect dedup policy",
    };
    CalyxError {
        code,
        message: message.into(),
        remediation,
    }
}
