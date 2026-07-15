pub mod e2_recency;
pub mod e3_periodic;
pub mod e4_positional;

use calyx_core::{CalyxError, LensId, Result, content_address};
use serde::{Deserialize, Serialize};

pub use e2_recency::{DecayFunction, E2RecencyConfig, E2RecencyLens};
pub use e3_periodic::{E3PeriodicConfig, E3PeriodicLens, PeriodicOptions};
pub use e4_positional::{
    E4PositionalConfig, E4PositionalLens, MultiAnchorMode, SequenceDirection, SequenceOptions,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalLensFlags {
    pub retrieval_only: bool,
    pub excluded_from_dedup: bool,
}

pub const TEMPORAL_FLAGS: TemporalLensFlags = TemporalLensFlags {
    retrieval_only: true,
    excluded_from_dedup: true,
};

pub(crate) fn temporal_lens_id(parts: &[&str]) -> LensId {
    LensId::from_bytes(content_address(parts.iter().map(|part| part.as_bytes())))
}

pub(crate) fn parse_i64_timestamp(bytes: &[u8], lens: &str) -> Result<i64> {
    let raw = bytes.get(..8).ok_or_else(|| {
        CalyxError::lens_dim_mismatch(format!("{lens} expects 8-byte little-endian i64 timestamp"))
    })?;
    Ok(i64::from_le_bytes(
        raw.try_into().expect("slice length checked"),
    ))
}

pub(crate) fn parse_position_total(bytes: &[u8], lens: &str) -> Result<(u64, u64)> {
    let raw = bytes.get(..16).ok_or_else(|| {
        CalyxError::lens_dim_mismatch(format!(
            "{lens} expects 16 bytes: u64 position then u64 total"
        ))
    })?;
    let position = u64::from_le_bytes(raw[..8].try_into().expect("slice length checked"));
    let total = u64::from_le_bytes(raw[8..16].try_into().expect("slice length checked"));
    Ok((position, total))
}

pub(crate) fn utc_hour(timestamp: i64) -> u8 {
    (timestamp.rem_euclid(86_400) / 3_600) as u8
}

pub(crate) fn utc_day_of_week_monday0(timestamp: i64) -> u8 {
    let days = timestamp.div_euclid(86_400);
    (days + 3).rem_euclid(7) as u8
}

pub(crate) fn clamp01(value: f32) -> f32 {
    value.clamp(0.0, 1.0)
}
