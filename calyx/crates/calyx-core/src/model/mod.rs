//! Constellation data-model structs.

pub mod anchor;
pub mod constellation;
pub mod signal;
pub mod slot;
mod validation;
pub mod vector;

pub use crate::time::Ts;
pub use anchor::{Anchor, AnchorValue};
pub use constellation::{
    Constellation, METADATA_CHUNK_ID, METADATA_DATABASE_NAME, METADATA_SOURCE_EVENT_TIME_RAW,
    METADATA_SOURCE_EVENT_TIME_SECS, METADATA_SOURCE_SEQUENCE, METADATA_TEMPORAL_INACTIVE_REASON,
    METADATA_TEMPORAL_LANE_STATE, TEMPORAL_LANE_ACTIVE, TEMPORAL_LANE_INACTIVE,
    TEMPORAL_MISSING_CREATED_AT,
};
pub use signal::{ConfidenceInterval, CxFlags, InputRef, LedgerRef, Signal};
pub use slot::{LensCost, Panel, Placement, Slot, SlotResource};
pub use validation::CALYX_RECORD_SCHEMA_VIOLATION;
pub use vector::{SlotVector, SparseEntry};
