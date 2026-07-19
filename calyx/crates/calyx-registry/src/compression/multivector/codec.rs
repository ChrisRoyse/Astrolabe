use std::collections::BTreeSet;

use calyx_core::{CxId, Result, Seq, Slot};
use sha2::{Digest, Sha256};

use super::admission::measure_admission;
use super::row_format::{PendingPackedRow, encode_packed_row};
use super::simd;
use super::training::{
    codec_context_id, normalized_corpus, pack_rows, require_distinct_centroids, train_centroids,
    train_residual_buckets,
};
use super::{
    CALYX_MULTIVECTOR_ADMISSION_FAILED, CALYX_MULTIVECTOR_PACK_INVALID,
    MultiVectorCompressionConfig, MultiVectorCompressionQuery, MultiVectorCompressionReport,
    MultiVectorCompressionRow, MultiVectorStorageCodec, PackedMaxSimScratch,
    PackedMultiVectorBytes, PackedMultiVectorManifest, PackedMultiVectorRow, multivector_error,
    parse_packed_multivector_row,
};
use crate::spec::LensSpec;

const GENERATION_ROOT_DOMAIN: &[u8] = b"calyx-colbert-residual-generation-v1";
const RAW_ROOT_DOMAIN: &[u8] = b"calyx-colbert-residual-raw-generation-v1";

pub(super) struct PreparedGeneration {
    pub report: MultiVectorCompressionReport,
    pub manifest: PackedMultiVectorManifest,
}

pub(super) fn prepare_generation(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[MultiVectorCompressionRow],
    queries: &[MultiVectorCompressionQuery],
    config: MultiVectorCompressionConfig,
    k: usize,
    generation_seq: Seq,
) -> Result<PreparedGeneration> {
    let token_dim = super::validate_multivector_context(slot, lens)?;
    config.validate(token_dim)?;
    let sorted_rows = validate_and_sort_rows(rows, token_dim, config.max_tokens)?;
    validate_queries(queries, token_dim, config.max_tokens)?;
    if k == 0 || k > sorted_rows.len() {
        return Err(invalid(format!(
            "admission k {k} is outside 1..={} generation rows",
            sorted_rows.len()
        )));
    }
    let k_u32 = u32::try_from(k).map_err(|_| invalid("admission k exceeds u32"))?;
    let generation_rows =
        u32::try_from(sorted_rows.len()).map_err(|_| invalid("generation rows exceed u32"))?;
    let total_tokens = sorted_rows.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.tokens.len() as u64)
            .ok_or_else(|| invalid("generation token count overflow"))
    })?;
    if u64::from(config.centroid_count) > total_tokens {
        return Err(invalid(format!(
            "centroid_count {} exceeds the {total_tokens} source tokens",
            config.centroid_count
        )));
    }
    let normalized_corpus = normalized_corpus(&sorted_rows)?;
    require_distinct_centroids(&normalized_corpus, config.centroid_count)?;
    let centroids = train_centroids(
        &normalized_corpus,
        token_dim as usize,
        config.centroid_count as usize,
        config.kmeans_iterations,
    )?;
    let (bucket_cutoffs, bucket_weights) =
        train_residual_buckets(&normalized_corpus, &centroids, token_dim as usize)?;
    let codec_context_id = codec_context_id(
        slot,
        lens,
        config,
        &centroids,
        bucket_cutoffs,
        bucket_weights,
    );
    let pending = pack_rows(&sorted_rows, token_dim, config, &centroids, bucket_cutoffs)?;
    let generation_root = compute_generation_root(
        codec_context_id,
        generation_rows,
        pending
            .iter()
            .map(|row| (row.cx_id, row.token_count, row.payload.as_slice())),
    );
    let raw_generation_root = compute_raw_generation_root(
        codec_context_id,
        generation_rows,
        pending
            .iter()
            .map(|row| (row.cx_id, row.raw_bytes.as_slice())),
    );
    let admission_queries =
        u32::try_from(queries.len()).map_err(|_| invalid("admission query count exceeds u32"))?;
    let mut manifest = PackedMultiVectorManifest {
        codec: MultiVectorStorageCodec::ColbertResidual2BitV1,
        token_dim,
        config,
        generation_rows,
        total_tokens,
        generation_seq,
        slot_id: slot.slot_id.get(),
        lens_id: lens.lens_id(),
        codec_context_id,
        generation_root,
        raw_generation_root,
        admission_queries,
        admission_k: k_u32,
        max_abs_score_error: 0.0,
        mean_abs_score_error: 0.0,
        recall_at_k: 1.0,
        exact_ranking_root: [0; 32],
        packed_ranking_root: [0; 32],
        centroids,
        bucket_cutoffs,
        bucket_weights,
    };
    let mut packed_rows = encode_rows(&manifest, &pending)?;
    let admission = measure_admission(queries, &sorted_rows, &packed_rows, &manifest, k)?;
    if admission.max_abs_score_error > config.max_score_error {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_ADMISSION_FAILED,
            format!(
                "packed MaxSim maximum absolute score error {:.8} exceeds declared bound {:.8}; no generation was written",
                admission.max_abs_score_error, config.max_score_error
            ),
        ));
    }
    let recall_drop = 1.0 - admission.recall_at_k;
    if recall_drop > lens.recall_delta {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_ADMISSION_FAILED,
            format!(
                "packed MaxSim recall drop {:.8} exceeds lens recall_delta {:.8}; no generation was written",
                recall_drop, lens.recall_delta
            ),
        ));
    }
    manifest.max_abs_score_error = admission.max_abs_score_error;
    manifest.mean_abs_score_error = admission.mean_abs_score_error;
    manifest.recall_at_k = admission.recall_at_k;
    manifest.exact_ranking_root = admission.exact_ranking_root;
    manifest.packed_ranking_root = admission.packed_ranking_root;
    let manifest_bytes = manifest.encode()?;
    // Row bytes are independent of admission statistics; parse them once
    // against the final manifest to prove that invariant and retain only exact
    // validated bytes in the report.
    for row in &packed_rows {
        parse_packed_multivector_row(&row.packed_bytes, &manifest, row.cx_id)?;
    }
    let bytes = initial_byte_accounting(&manifest, &packed_rows, manifest_bytes.len())?;
    let report = MultiVectorCompressionReport {
        slot_id: slot.slot_id.get(),
        slot_key: slot.slot_key.key().to_string(),
        requested_quant: lens.quant_default,
        stored_codec: manifest.codec,
        config,
        generation_rows,
        total_tokens,
        admission_queries,
        admission_k: k_u32,
        recall_at_k_raw: 1.0,
        recall_at_k_packed: admission.recall_at_k,
        recall_drop,
        max_abs_score_error: admission.max_abs_score_error,
        mean_abs_score_error: admission.mean_abs_score_error,
        exact_ranking_root_sha256: admission.exact_ranking_root,
        packed_ranking_root_sha256: admission.packed_ranking_root,
        scoring_backend: simd::packed_maxsim_backend().to_string(),
        bytes,
        rows: std::mem::take(&mut packed_rows),
        generation_manifest_bytes: manifest_bytes,
        snapshot: None,
        ledger: None,
    };
    Ok(PreparedGeneration { report, manifest })
}

/// Directly scores one query against one residual-packed document.
///
/// The only decoded F32 state is one document token plus the normalized query
/// matrix and its running maxima, all bounded by persisted `max_tokens` and
/// `token_dim`.
pub fn packed_maxsim(
    query: &[Vec<f32>],
    row: &super::ParsedPackedMultiVectorRow,
    manifest: &PackedMultiVectorManifest,
    scratch: &mut PackedMaxSimScratch,
) -> Result<f32> {
    prepare_maxsim_query(query, manifest, scratch)?;
    score_prepared_maxsim(row, manifest, scratch)
}

pub(super) fn prepare_maxsim_query(
    query: &[Vec<f32>],
    manifest: &PackedMultiVectorManifest,
    scratch: &mut PackedMaxSimScratch,
) -> Result<()> {
    validate_token_matrix(
        query,
        manifest.token_dim,
        manifest.config.max_tokens,
        "query",
    )?;
    let dim = manifest.token_dim as usize;
    let components = query
        .len()
        .checked_mul(dim)
        .ok_or_else(|| invalid("packed MaxSim query component count overflow"))?;
    scratch.normalized_query.clear();
    scratch.normalized_query.reserve(components);
    for token in query {
        let start = scratch.normalized_query.len();
        scratch.normalized_query.extend_from_slice(token);
        simd::normalize(&mut scratch.normalized_query[start..start + dim])?;
    }
    scratch.query_tokens = query.len();
    Ok(())
}

pub(super) fn score_prepared_maxsim(
    row: &super::ParsedPackedMultiVectorRow,
    manifest: &PackedMultiVectorManifest,
    scratch: &mut PackedMaxSimScratch,
) -> Result<f32> {
    let dim = manifest.token_dim as usize;
    if scratch.query_tokens == 0
        || scratch.normalized_query.len() != scratch.query_tokens.saturating_mul(dim)
    {
        return Err(invalid(
            "packed MaxSim query scratch is empty or does not match the manifest",
        ));
    }
    scratch.maxima.clear();
    scratch
        .maxima
        .resize(scratch.query_tokens, f32::NEG_INFINITY);
    for token_index in 0..row.token_count() {
        row.decode_token_into(manifest, token_index, &mut scratch.decoded_token)?;
        for (query_index, query_token) in scratch.normalized_query.chunks_exact(dim).enumerate() {
            let score = simd::dot(query_token, &scratch.decoded_token)?;
            if score > scratch.maxima[query_index] {
                scratch.maxima[query_index] = score;
            }
        }
    }
    let score = scratch.maxima.iter().sum::<f32>();
    if !score.is_finite() {
        return Err(invalid("packed MaxSim produced a non-finite score"));
    }
    Ok(score)
}

fn validate_and_sort_rows(
    rows: &[MultiVectorCompressionRow],
    token_dim: u32,
    max_tokens: u32,
) -> Result<Vec<MultiVectorCompressionRow>> {
    if rows.is_empty() {
        return Err(invalid(
            "packed generation requires at least one source row",
        ));
    }
    let mut sorted = rows.to_vec();
    sorted.sort_by_key(|row| row.cx_id);
    for pair in sorted.windows(2) {
        if pair[0].cx_id == pair[1].cx_id {
            return Err(invalid(format!(
                "packed generation contains duplicate CxId {}",
                pair[0].cx_id
            )));
        }
    }
    for row in &sorted {
        validate_token_matrix(&row.tokens, token_dim, max_tokens, "document")?;
    }
    Ok(sorted)
}

fn validate_queries(
    queries: &[MultiVectorCompressionQuery],
    token_dim: u32,
    max_tokens: u32,
) -> Result<()> {
    if queries.is_empty() {
        return Err(invalid(
            "packed generation requires independently identified admission queries",
        ));
    }
    let mut ids = BTreeSet::new();
    for query in queries {
        if !ids.insert(query.cx_id) {
            return Err(invalid(format!(
                "admission queries contain duplicate CxId {}",
                query.cx_id
            )));
        }
        validate_token_matrix(&query.tokens, token_dim, max_tokens, "query")?;
    }
    Ok(())
}

pub(super) fn validate_token_matrix(
    tokens: &[Vec<f32>],
    token_dim: u32,
    max_tokens: u32,
    label: &str,
) -> Result<()> {
    if tokens.is_empty() {
        return Err(invalid(format!("{label} token matrix is empty")));
    }
    if tokens.len() > max_tokens as usize {
        return Err(invalid(format!(
            "{label} token count {} exceeds max_tokens {max_tokens}",
            tokens.len()
        )));
    }
    for (index, token) in tokens.iter().enumerate() {
        if token.len() != token_dim as usize {
            return Err(invalid(format!(
                "{label} token {index} length {} != token_dim {token_dim}",
                token.len()
            )));
        }
        if token.iter().any(|value| !value.is_finite()) {
            return Err(invalid(format!(
                "{label} token {index} contains a non-finite component"
            )));
        }
        let norm_sq = token.iter().map(|value| value * value).sum::<f32>();
        if !norm_sq.is_finite() || norm_sq <= 0.0 {
            return Err(invalid(format!(
                "{label} token {index} has invalid squared L2 norm {norm_sq}"
            )));
        }
    }
    Ok(())
}

pub(super) fn compute_generation_root<'a>(
    context: [u8; 32],
    generation_rows: u32,
    rows: impl IntoIterator<Item = (CxId, u32, &'a [u8])>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENERATION_ROOT_DOMAIN);
    hasher.update(context);
    hasher.update(generation_rows.to_be_bytes());
    for (cx_id, token_count, payload) in rows {
        hasher.update(cx_id.as_bytes());
        hasher.update(token_count.to_be_bytes());
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
    }
    hasher.finalize().into()
}

pub(super) fn compute_raw_generation_root<'a>(
    context: [u8; 32],
    generation_rows: u32,
    rows: impl IntoIterator<Item = (CxId, &'a [u8])>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RAW_ROOT_DOMAIN);
    hasher.update(context);
    hasher.update(generation_rows.to_be_bytes());
    for (cx_id, raw_bytes) in rows {
        hasher.update(cx_id.as_bytes());
        hasher.update((raw_bytes.len() as u64).to_be_bytes());
        hasher.update(raw_bytes);
    }
    hasher.finalize().into()
}

fn encode_rows(
    manifest: &PackedMultiVectorManifest,
    pending: &[PendingPackedRow],
) -> Result<Vec<PackedMultiVectorRow>> {
    pending
        .iter()
        .map(|row| {
            Ok(PackedMultiVectorRow {
                cx_id: row.cx_id,
                token_count: row.token_count,
                raw_bytes: row.raw_bytes.clone(),
                packed_bytes: encode_packed_row(manifest, row)?,
            })
        })
        .collect()
}

fn initial_byte_accounting(
    manifest: &PackedMultiVectorManifest,
    rows: &[PackedMultiVectorRow],
    manifest_bytes: usize,
) -> Result<PackedMultiVectorBytes> {
    let mut bytes = PackedMultiVectorBytes {
        codebook_bytes: manifest.codebook_bytes(),
        manifest_value_bytes: manifest_bytes,
        ..PackedMultiVectorBytes::default()
    };
    for row in rows {
        let parsed = parse_packed_multivector_row(&row.packed_bytes, manifest, row.cx_id)?;
        bytes.raw_sidecar_value_bytes = checked_add(
            bytes.raw_sidecar_value_bytes,
            row.raw_bytes.len(),
            "raw byte accounting",
        )?;
        bytes.packed_row_value_bytes = checked_add(
            bytes.packed_row_value_bytes,
            row.packed_bytes.len(),
            "packed byte accounting",
        )?;
        bytes.row_header_bytes = checked_add(
            bytes.row_header_bytes,
            super::MULTIVECTOR_ROW_HEADER_BYTES,
            "row-header accounting",
        )?;
        bytes.centroid_code_bytes = checked_add(
            bytes.centroid_code_bytes,
            parsed.code_bytes(),
            "centroid-code accounting",
        )?;
        bytes.residual_bytes = checked_add(
            bytes.residual_bytes,
            parsed.residual_bytes(),
            "residual accounting",
        )?;
        bytes.row_checksum_bytes =
            checked_add(bytes.row_checksum_bytes, 32, "row-checksum accounting")?;
    }
    bytes.accounted_bytes = bytes
        .raw_sidecar_value_bytes
        .checked_add(bytes.packed_row_value_bytes)
        .and_then(|value| value.checked_add(bytes.manifest_value_bytes))
        .ok_or_else(|| invalid("initial total byte accounting overflow"))?;
    Ok(bytes)
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| invalid(format!("{label} overflow")))
}

pub(super) fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    multivector_error(CALYX_MULTIVECTOR_PACK_INVALID, message)
}
