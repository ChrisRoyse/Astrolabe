use calyx_core::{Result, SlotId};

use super::super::centroids::SpannCentroidIndex;
use super::invalid;

pub const SPANN_POSTING_SEGMENT_MAGIC: [u8; 8] = *b"CLXSPB03";
pub const SPANN_STATE_SEGMENT_MAGIC: [u8; 8] = *b"CLXSPS03";
pub const SPANN_MANIFEST_MAGIC: [u8; 8] = *b"CLXSPM03";
pub const SPANN_ACTIVE_MAGIC: [u8; 8] = *b"CLXSPA03";
pub const SPANN_POSTING_FORMAT_VERSION: u16 = 3;

/// The single distance contract used by SPANN training, assignment, routing,
/// closure replication, and member ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SpannDistanceMetric {
    SquaredL2 = 1,
}

impl SpannDistanceMetric {
    pub(super) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::SquaredL2),
            _ => Err(invalid(format!("unsupported SPANN metric tag {tag}"))),
        }
    }

    pub(super) const fn tag(self) -> u8 {
        self as u8
    }
}

/// Registry-owned physical limits for one SPANN posting generation.
///
/// The complete value is sealed into every manifest. Opening with a different
/// registry value fails closed, so a caller cannot silently reinterpret an
/// existing index with wider allocations or different codec parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpannPostingLimits {
    pub max_members_per_segment: u32,
    pub max_nnz_per_member: u32,
    pub max_decoded_segment_bytes: u64,
    pub max_compressed_segment_bytes: u64,
    pub max_segments_per_posting: u16,
    pub max_state_segments: u16,
    pub max_manifest_chain: u16,
    pub max_reader_leases: u16,
    pub max_manifest_bytes: u64,
    pub max_centroid_file_bytes: u64,
    pub max_query_decoded_bytes: u64,
    pub cache_capacity_bytes: u64,
    pub zstd_level: i32,
    pub zstd_window_log_max: u32,
    pub boundary_epsilon_bits: u32,
    pub max_replication: u16,
    pub max_reclaim_files: u16,
}

impl SpannPostingLimits {
    /// Tunable Calyx defaults. Production registries persist the exact selected
    /// value in the manifest; callers may supply a narrower measured profile.
    pub const fn production() -> Self {
        Self {
            max_members_per_segment: 65_536,
            max_nnz_per_member: 65_536,
            max_decoded_segment_bytes: 64 * 1024 * 1024,
            max_compressed_segment_bytes: 64 * 1024 * 1024,
            max_segments_per_posting: 8,
            max_state_segments: 16,
            max_manifest_chain: 256,
            max_reader_leases: 64,
            max_manifest_bytes: 64 * 1024 * 1024,
            max_centroid_file_bytes: 1024 * 1024 * 1024,
            max_query_decoded_bytes: 256 * 1024 * 1024,
            cache_capacity_bytes: 256 * 1024 * 1024,
            zstd_level: 3,
            zstd_window_log_max: 26,
            boundary_epsilon_bits: 0.10_f32.to_bits(),
            max_replication: 2,
            max_reclaim_files: u16::MAX,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_members_per_segment == 0
            || self.max_nnz_per_member == 0
            || self.max_decoded_segment_bytes < 4
            || self.max_compressed_segment_bytes < 16
            || self.max_segments_per_posting == 0
            || self.max_state_segments == 0
            || self.max_manifest_chain == 0
            || self.max_reader_leases == 0
            || self.max_manifest_bytes < 512
            || self.max_centroid_file_bytes < 40
            || self.max_query_decoded_bytes < self.max_decoded_segment_bytes
            || self.cache_capacity_bytes == 0
            || !(10..=31).contains(&self.zstd_window_log_max)
            || !zstd::compression_level_range().contains(&self.zstd_level)
            || !f32::from_bits(self.boundary_epsilon_bits).is_finite()
            || f32::from_bits(self.boundary_epsilon_bits) < 0.0
            || self.max_replication == 0
            || self.max_reclaim_files == 0
        {
            return Err(invalid(format!(
                "invalid registry limits: members={} nnz={} decoded={} compressed={} posting_segments={} state_segments={} manifest_chain={} reader_leases={} manifest_bytes={} centroid_bytes={} query_bytes={} cache_bytes={} zstd_level={} window_log={} boundary_epsilon={} max_replication={} reclaim_files={}",
                self.max_members_per_segment,
                self.max_nnz_per_member,
                self.max_decoded_segment_bytes,
                self.max_compressed_segment_bytes,
                self.max_segments_per_posting,
                self.max_state_segments,
                self.max_manifest_chain,
                self.max_reader_leases,
                self.max_manifest_bytes,
                self.max_centroid_file_bytes,
                self.max_query_decoded_bytes,
                self.cache_capacity_bytes,
                self.zstd_level,
                self.zstd_window_log_max,
                f32::from_bits(self.boundary_epsilon_bits),
                self.max_replication,
                self.max_reclaim_files
            )));
        }
        Ok(())
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.max_members_per_segment.to_le_bytes());
        out.extend_from_slice(&self.max_nnz_per_member.to_le_bytes());
        out.extend_from_slice(&self.max_decoded_segment_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_compressed_segment_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_segments_per_posting.to_le_bytes());
        out.extend_from_slice(&self.max_state_segments.to_le_bytes());
        out.extend_from_slice(&self.max_manifest_chain.to_le_bytes());
        out.extend_from_slice(&self.max_reader_leases.to_le_bytes());
        out.extend_from_slice(&self.max_manifest_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_centroid_file_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_query_decoded_bytes.to_le_bytes());
        out.extend_from_slice(&self.cache_capacity_bytes.to_le_bytes());
        out.extend_from_slice(&self.zstd_level.to_le_bytes());
        out.extend_from_slice(&self.zstd_window_log_max.to_le_bytes());
        out.extend_from_slice(&self.boundary_epsilon_bits.to_le_bytes());
        out.extend_from_slice(&self.max_replication.to_le_bytes());
        out.extend_from_slice(&self.max_reclaim_files.to_le_bytes());
    }
}

impl Default for SpannPostingLimits {
    fn default() -> Self {
        Self::production()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpannIndexIdentity {
    pub index_id: [u8; 32],
    pub centroid_hash: [u8; 32],
    pub slot: SlotId,
    pub dim: u32,
    pub centroid_count: u32,
    pub metric: SpannDistanceMetric,
}

impl SpannIndexIdentity {
    pub fn from_centroids(slot: SlotId, centroids: &SpannCentroidIndex) -> Result<Self> {
        let centroid_count = u32::try_from(centroids.centroid_count())
            .map_err(|_| invalid("centroid count exceeds u32"))?;
        let centroid_hash = centroids.content_hash();
        let metric = SpannDistanceMetric::SquaredL2;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"calyx-spann-index-v3");
        hasher.update(&slot.get().to_le_bytes());
        hasher.update(&centroids.dim().to_le_bytes());
        hasher.update(&centroid_count.to_le_bytes());
        hasher.update(&[metric.tag()]);
        hasher.update(&centroid_hash);
        Ok(Self {
            index_id: *hasher.finalize().as_bytes(),
            centroid_hash,
            slot,
            dim: centroids.dim(),
            centroid_count,
            metric,
        })
    }
}
