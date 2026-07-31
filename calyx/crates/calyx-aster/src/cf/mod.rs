//! Association-native Aster column families and key codecs.

mod family;
mod key;
mod router;
mod router_handoff;
mod router_load;
mod router_scan;

pub use family::{ColumnFamily, SlotFamilyKind};
pub use key::{
    COMPRESSION_LIFECYCLE_KEY_TAG, KeyRange, OnlineKeyKind, ScalarId, XTermKind, anchor_key,
    anchor_prefix_range, base_key, compression_lifecycle_key, compression_lifecycle_prefix_range,
    compression_manifest_key, cx_id_from_full_hash, cx_prefix_range, full_content_hash, ledger_key,
    ledger_range, online_key, parse_compression_lifecycle_key, prefix_range, recurrence_key,
    recurrence_prefix_range, scalar_key, scalar_prefix_range, slot_key, temporal_xterm_key,
    temporal_xterm_prefix_range, verify_cx_hash_prefix, xterm_key, xterm_prefix_range,
};
pub use router::{CfRouter, NO_COMMIT_DOMAIN};
pub(crate) use router_handoff::RouterManifestHandoffReport;

/// Reserved leading byte for registry-owned compressed slot envelopes.
pub const COMPRESSED_SLOT_VALUE_TAG: u8 = 16;
