//! Vault-wide MVCC sequence and snapshot scaffolding.

mod lease;
mod read_barrier;
mod store;

pub use lease::{Freshness, ReaderLease, SeqAllocator, Snapshot};
pub use read_barrier::{CALYX_ASTER_BASE_CORRUPT, ReadBarrier};
pub use store::{
    CALYX_ASTER_LATEST_ONLY_COMPRESSION_REQUIRES_MVCC, CfRead, VersionedCfStore,
    is_tombstone_value, tombstone_value,
};
