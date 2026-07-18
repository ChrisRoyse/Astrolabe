//! SPANN sparse-slot index: centroid ANN in RAM, posting lists on disk.

pub mod centroids;
pub mod posting;

pub use centroids::{SPANN_CENTROID_MAGIC, SpannCentroidIndex, build_centroids};
pub use posting::{
    PostingListReader, PostingListWriter, PostingMember, SPANN_ACTIVE_MAGIC, SPANN_MANIFEST_MAGIC,
    SPANN_POSTING_FORMAT_VERSION, SPANN_POSTING_SEGMENT_MAGIC, SPANN_STATE_SEGMENT_MAGIC,
    SpannDistanceMetric, SpannIndexIdentity, SpannPostingLimits, SpannPostingPhysicalStats,
    SpannPostingWriteReceipt, SpannSearch, decode_posting_block, encode_posting_block,
};
