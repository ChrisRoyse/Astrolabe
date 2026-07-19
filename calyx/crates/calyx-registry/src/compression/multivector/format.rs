use calyx_core::{LensId, Result, Seq};

use super::wire::{
    CENTROID_CODE_BYTES, CODEC_TAG_RESIDUAL_2BIT, CUTOFF_COUNT, DIGEST_BYTES, DTYPE_TAG_F32,
    METRIC_TAG_COSINE_MAXSIM, RESIDUAL_BITS, WEIGHT_COUNT, append_digest, array_16, array_32,
    invalid, read_f32, read_seq, read_u16, read_u32, read_u64, require_digest, require_tag,
    require_u16, sorted_finite,
};
use super::{MultiVectorCompressionConfig, MultiVectorStorageCodec};

/// Four-byte magic for a packed multi-vector generation manifest.
pub const MULTIVECTOR_MANIFEST_MAGIC: &[u8; 4] = b"CMVF";
/// Manifest wire version.
pub const MULTIVECTOR_MANIFEST_VERSION: u16 = 1;
const MANIFEST_PREFIX_BYTES: usize = 280;
const MANIFEST_HASH_DOMAIN: &[u8] = b"calyx-colbert-residual-manifest-v1";

/// Fully validated generation manifest and embedded codebook.
#[derive(Clone, Debug, PartialEq)]
pub struct PackedMultiVectorManifest {
    pub codec: MultiVectorStorageCodec,
    pub token_dim: u32,
    pub config: MultiVectorCompressionConfig,
    pub generation_rows: u32,
    pub total_tokens: u64,
    pub generation_seq: Seq,
    pub slot_id: u16,
    pub lens_id: LensId,
    pub codec_context_id: [u8; 32],
    pub generation_root: [u8; 32],
    pub raw_generation_root: [u8; 32],
    pub admission_queries: u32,
    pub admission_k: u32,
    pub max_abs_score_error: f32,
    pub mean_abs_score_error: f32,
    pub recall_at_k: f32,
    pub exact_ranking_root: [u8; 32],
    pub packed_ranking_root: [u8; 32],
    pub centroids: Vec<f32>,
    pub bucket_cutoffs: [f32; CUTOFF_COUNT],
    pub bucket_weights: [f32; WEIGHT_COUNT],
}

impl PackedMultiVectorManifest {
    /// Exact codebook bytes embedded between the manifest prefix and checksum.
    pub fn codebook_bytes(&self) -> usize {
        self.centroids.len() * 4 + CUTOFF_COUNT * 4 + WEIGHT_COUNT * 4
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        validate_manifest(self)?;
        let codebook_bytes = self.codebook_bytes();
        let centroid_values = u64::try_from(self.centroids.len())
            .map_err(|_| invalid("manifest centroid value count exceeds u64"))?;
        let mut bytes = Vec::with_capacity(MANIFEST_PREFIX_BYTES + codebook_bytes + DIGEST_BYTES);
        bytes.extend_from_slice(MULTIVECTOR_MANIFEST_MAGIC);
        bytes.extend_from_slice(&MULTIVECTOR_MANIFEST_VERSION.to_be_bytes());
        bytes.push(CODEC_TAG_RESIDUAL_2BIT);
        bytes.push(METRIC_TAG_COSINE_MAXSIM);
        bytes.push(DTYPE_TAG_F32);
        bytes.push(RESIDUAL_BITS);
        bytes.push(CENTROID_CODE_BYTES);
        bytes.push(0);
        bytes.extend_from_slice(&self.token_dim.to_be_bytes());
        bytes.extend_from_slice(&self.config.max_tokens.to_be_bytes());
        bytes.extend_from_slice(&self.config.centroid_count.to_be_bytes());
        bytes.extend_from_slice(&self.config.kmeans_iterations.to_be_bytes());
        bytes.extend_from_slice(&self.config.max_score_error.to_bits().to_be_bytes());
        bytes.extend_from_slice(&self.generation_rows.to_be_bytes());
        bytes.extend_from_slice(&self.total_tokens.to_be_bytes());
        bytes.extend_from_slice(&self.generation_seq.to_be_bytes());
        bytes.extend_from_slice(&self.slot_id.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(self.lens_id.as_bytes());
        bytes.extend_from_slice(&self.codec_context_id);
        bytes.extend_from_slice(&self.generation_root);
        bytes.extend_from_slice(&self.raw_generation_root);
        bytes.extend_from_slice(&self.admission_queries.to_be_bytes());
        bytes.extend_from_slice(&self.admission_k.to_be_bytes());
        bytes.extend_from_slice(&self.max_abs_score_error.to_bits().to_be_bytes());
        bytes.extend_from_slice(&self.mean_abs_score_error.to_bits().to_be_bytes());
        bytes.extend_from_slice(&self.recall_at_k.to_bits().to_be_bytes());
        bytes.extend_from_slice(&self.exact_ranking_root);
        bytes.extend_from_slice(&self.packed_ranking_root);
        bytes.extend_from_slice(&(codebook_bytes as u64).to_be_bytes());
        bytes.extend_from_slice(&centroid_values.to_be_bytes());
        bytes.extend_from_slice(&(CUTOFF_COUNT as u32).to_be_bytes());
        bytes.extend_from_slice(&(WEIGHT_COUNT as u32).to_be_bytes());
        bytes.extend_from_slice(&self.config.max_token_dim.to_be_bytes());
        debug_assert_eq!(bytes.len(), MANIFEST_PREFIX_BYTES);
        for value in &self.centroids {
            bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        for value in self.bucket_cutoffs {
            bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        for value in self.bucket_weights {
            bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        append_digest(&mut bytes, MANIFEST_HASH_DOMAIN);
        Ok(bytes)
    }
}

/// Parses and checksum-validates a manifest without assuming a slot context.
pub fn parse_packed_multivector_manifest(bytes: &[u8]) -> Result<PackedMultiVectorManifest> {
    if bytes.len() < MANIFEST_PREFIX_BYTES + DIGEST_BYTES {
        return Err(invalid(format!(
            "packed multi-vector manifest is {} bytes; minimum is {}",
            bytes.len(),
            MANIFEST_PREFIX_BYTES + DIGEST_BYTES
        )));
    }
    require_digest(bytes, MANIFEST_HASH_DOMAIN, "manifest")?;
    if &bytes[0..4] != MULTIVECTOR_MANIFEST_MAGIC {
        return Err(invalid(
            "compression manifest magic is not CMVF (dense, legacy, or foreign manifests are refused)",
        ));
    }
    require_u16(bytes, 4, MULTIVECTOR_MANIFEST_VERSION, "manifest version")?;
    require_tag(bytes[6], CODEC_TAG_RESIDUAL_2BIT, "manifest codec")?;
    require_tag(bytes[7], METRIC_TAG_COSINE_MAXSIM, "manifest metric")?;
    require_tag(bytes[8], DTYPE_TAG_F32, "manifest dtype")?;
    require_tag(bytes[9], RESIDUAL_BITS, "manifest residual bits")?;
    require_tag(
        bytes[10],
        CENTROID_CODE_BYTES,
        "manifest centroid-code width",
    )?;
    if bytes[11] != 0 || read_u16(bytes, 54)? != 0 {
        return Err(invalid("manifest reserved fields are non-zero"));
    }
    let token_dim = read_u32(bytes, 12)?;
    let config = MultiVectorCompressionConfig {
        max_tokens: read_u32(bytes, 16)?,
        max_token_dim: read_u32(bytes, 276)?,
        centroid_count: read_u32(bytes, 20)?,
        kmeans_iterations: read_u32(bytes, 24)?,
        max_score_error: read_f32(bytes, 28)?,
    };
    config.validate(token_dim)?;
    let generation_rows = read_u32(bytes, 32)?;
    let total_tokens = read_u64(bytes, 36)?;
    let generation_seq = read_seq(bytes, 44)?;
    let slot_id = read_u16(bytes, 52)?;
    let lens_id = LensId::from_bytes(array_16(bytes, 56)?);
    let codec_context_id = array_32(bytes, 72)?;
    let generation_root = array_32(bytes, 104)?;
    let raw_generation_root = array_32(bytes, 136)?;
    let admission_queries = read_u32(bytes, 168)?;
    let admission_k = read_u32(bytes, 172)?;
    let max_abs_score_error = read_f32(bytes, 176)?;
    let mean_abs_score_error = read_f32(bytes, 180)?;
    let recall_at_k = read_f32(bytes, 184)?;
    let exact_ranking_root = array_32(bytes, 188)?;
    let packed_ranking_root = array_32(bytes, 220)?;
    let codebook_bytes = usize::try_from(read_u64(bytes, 252)?)
        .map_err(|_| invalid("manifest codebook byte count exceeds usize"))?;
    let centroid_values = usize::try_from(read_u64(bytes, 260)?)
        .map_err(|_| invalid("manifest centroid value count exceeds usize"))?;
    if read_u32(bytes, 268)? as usize != CUTOFF_COUNT
        || read_u32(bytes, 272)? as usize != WEIGHT_COUNT
    {
        return Err(invalid(
            "manifest residual bucket counts are not 3 cutoffs/4 weights",
        ));
    }
    let expected_centroid_values = (config.centroid_count as usize)
        .checked_mul(token_dim as usize)
        .ok_or_else(|| invalid("manifest centroid geometry overflow"))?;
    if centroid_values != expected_centroid_values {
        return Err(invalid(format!(
            "manifest has {centroid_values} centroid values but geometry requires {expected_centroid_values}"
        )));
    }
    let expected_codebook = centroid_values
        .checked_mul(4)
        .and_then(|value| value.checked_add((CUTOFF_COUNT + WEIGHT_COUNT) * 4))
        .ok_or_else(|| invalid("manifest codebook length overflow"))?;
    let expected_len = MANIFEST_PREFIX_BYTES
        .checked_add(expected_codebook)
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .ok_or_else(|| invalid("manifest total length overflow"))?;
    if codebook_bytes != expected_codebook || bytes.len() != expected_len {
        return Err(invalid(format!(
            "manifest codebook/length mismatch: declared={codebook_bytes}, expected={expected_codebook}, bytes={}, expected_bytes={expected_len}",
            bytes.len()
        )));
    }
    let mut cursor = MANIFEST_PREFIX_BYTES;
    let mut centroids = Vec::with_capacity(centroid_values);
    for _ in 0..centroid_values {
        centroids.push(read_f32(bytes, cursor)?);
        cursor += 4;
    }
    let bucket_cutoffs = [
        read_f32(bytes, cursor)?,
        read_f32(bytes, cursor + 4)?,
        read_f32(bytes, cursor + 8)?,
    ];
    cursor += CUTOFF_COUNT * 4;
    let bucket_weights = [
        read_f32(bytes, cursor)?,
        read_f32(bytes, cursor + 4)?,
        read_f32(bytes, cursor + 8)?,
        read_f32(bytes, cursor + 12)?,
    ];
    let manifest = PackedMultiVectorManifest {
        codec: MultiVectorStorageCodec::ColbertResidual2BitV1,
        token_dim,
        config,
        generation_rows,
        total_tokens,
        generation_seq,
        slot_id,
        lens_id,
        codec_context_id,
        generation_root,
        raw_generation_root,
        admission_queries,
        admission_k,
        max_abs_score_error,
        mean_abs_score_error,
        recall_at_k,
        exact_ranking_root,
        packed_ranking_root,
        centroids,
        bucket_cutoffs,
        bucket_weights,
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &PackedMultiVectorManifest) -> Result<()> {
    manifest.config.validate(manifest.token_dim)?;
    if manifest.generation_rows == 0 || manifest.total_tokens == 0 {
        return Err(invalid(
            "manifest generation row/token counts must be non-zero",
        ));
    }
    if manifest.admission_queries == 0
        || manifest.admission_k == 0
        || manifest.admission_k > manifest.generation_rows
    {
        return Err(invalid("manifest admission query/k geometry is invalid"));
    }
    for (field, value) in [
        ("max_abs_score_error", manifest.max_abs_score_error),
        ("mean_abs_score_error", manifest.mean_abs_score_error),
        ("recall_at_k", manifest.recall_at_k),
    ] {
        if !value.is_finite() || value < 0.0 {
            return Err(invalid(format!("manifest {field} is invalid: {value}")));
        }
    }
    if manifest.max_abs_score_error > manifest.config.max_score_error {
        return Err(invalid(format!(
            "manifest observed score error {} exceeds declared maximum {}",
            manifest.max_abs_score_error, manifest.config.max_score_error
        )));
    }
    let expected = manifest.config.centroid_count as usize * manifest.token_dim as usize;
    if manifest.centroids.len() != expected
        || manifest.centroids.iter().any(|value| !value.is_finite())
    {
        return Err(invalid(
            "manifest centroid codebook geometry/finiteness is invalid",
        ));
    }
    if !sorted_finite(&manifest.bucket_cutoffs) || !sorted_finite(&manifest.bucket_weights) {
        return Err(invalid(
            "manifest residual cutoffs/weights must be finite and monotonically ordered",
        ));
    }
    Ok(())
}
