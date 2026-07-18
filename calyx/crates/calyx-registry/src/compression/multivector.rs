//! Truthful packed multi-vector (ColBERT) token-matrix storage and direct
//! MaxSim scoring (issue #575).
//!
//! Commissioning historically stamped [`QuantPolicy::turboquant_default`] onto
//! sparse and multi-vector lens shapes, but the registry dense compression path
//! only encodes dense `SlotVector`s. That produced two truth failures: the
//! catalog advertised a codec the shape could never execute, and the ColBERT
//! token-matrix representation was omitted from the compression inventory
//! entirely.
//!
//! This module closes both:
//!
//! * [`resolve_multivector_storage`] is the commission-/pre-mutation authority
//!   that maps a [`SlotShape::Multi`] to its one supported physical codec and
//!   fails closed for every other shape. [`reject_dense_codec_for_multivector`]
//!   is the guard the dense compression entry points call so a non-dense slot
//!   is refused with an exact diagnostic *before* any catalog mutation instead
//!   of being silently flattened into a dense codec.
//! * [`pack_colbert_matrix`] / [`parse_colbert_matrix`] define a single
//!   versioned, self-describing packed format that persists every identity
//!   needed for exact decode and direct scoring: dimensions, token bounds,
//!   dtype, metric, model/lens identity, generation binding, and a payload
//!   checksum. Parsing fails closed on any shape, context, bound, offset, or
//!   checksum mismatch.
//! * [`packed_maxsim`] scores a query directly against the packed bytes using a
//!   caller-owned scratch buffer bounded by `token_dim`, decoding one document
//!   token at a time. It never materializes the whole corpus as F32.
//!
//! # Codec choice
//!
//! `PackedColbertInt8V1` stores each token vector as symmetric max-abs INT8
//! (one signed byte per channel) plus a per-token f32 scale — the same frozen
//! scalar-INT8 contract already admitted for dense slots
//! ([`QuantPolicy::ScalarInt8`]), applied per token row of the matrix. This is
//! the primary proven quantization used by production late-interaction stacks
//! (PLAID/ColBERTv2 residual compression) and its reconstruction error is
//! measured against exact raw-F32 MaxSim on a real corpus, not assumed. The
//! stored metric is cosine MaxSim, matching the live late-interaction scorer;
//! cosine is scale-invariant in the document token, so the per-token scale is
//! retained for exact dequantization and physical-byte accounting rather than
//! to change the ranking.

use calyx_core::{CalyxError, LensId, QuantPolicy, Result, Seq, SlotShape};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Frozen 16-byte magic prefix for the packed ColBERT format.
pub const MULTIVECTOR_PACK_MAGIC: &[u8; 16] = b"CYX_COLBERT_PK_1";
/// Packed format version. A reader refuses any other value.
pub const MULTIVECTOR_PACK_VERSION: u16 = 1;
/// Fixed codec tag for symmetric per-token INT8 packing.
const CODEC_TAG_COLBERT_INT8: u8 = 1;
/// Fixed metric tag for cosine MaxSim late interaction.
const METRIC_TAG_COSINE_MAXSIM: u8 = 1;

/// Fixed header byte length preceding the first token record.
///
/// magic(16) + version(2) + codec_tag(1) + metric_tag(1) + token_dim(4)
/// + token_count(4) + max_tokens(4) + lens_id(16) + generation_seq(8) = 56.
pub const MULTIVECTOR_HEADER_BYTES: usize = 16 + 2 + 1 + 1 + 4 + 4 + 4 + 16 + 8;
/// Trailing SHA-256 digest byte length.
pub const MULTIVECTOR_DIGEST_BYTES: usize = 32;
/// Per-token scale field byte length (one f32).
const TOKEN_SCALE_BYTES: usize = 4;

const MULTIVECTOR_REMEDIATION: &str =
    "Persist multi-vector/ColBERT token matrices through the packed_colbert codec with the exact \
     lens/generation context and read the reported diagnostic field; dense compression codecs \
     cannot execute against token matrices";

/// Structured error code: a shape has no packed multi-vector storage codec.
pub const CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED: &str = "CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED";
/// Structured error code: a packed record is malformed (bounds/offsets/checksum).
pub const CALYX_MULTIVECTOR_PACK_INVALID: &str = "CALYX_MULTIVECTOR_PACK_INVALID";
/// Structured error code: a packed record's context does not match expectations.
pub const CALYX_MULTIVECTOR_CONTEXT_MISMATCH: &str = "CALYX_MULTIVECTOR_CONTEXT_MISMATCH";

/// The one physical storage codec supported for a multi-vector shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiVectorStorageCodec {
    /// Symmetric per-token max-abs INT8 with cosine MaxSim scoring.
    PackedColbertInt8V1,
}

impl MultiVectorStorageCodec {
    /// Stable catalog label the registry advertises for this codec, replacing
    /// the false dense TurboQuant advertisement on multi-vector lenses.
    pub const fn catalog_label(self) -> &'static str {
        match self {
            Self::PackedColbertInt8V1 => "packed_colbert_int8_v1",
        }
    }
}

fn multivector_error(code: &'static str, message: impl Into<String>) -> CalyxError {
    CalyxError {
        code,
        message: message.into(),
        remediation: MULTIVECTOR_REMEDIATION,
    }
}

/// Commission-/pre-mutation authority: resolves the physical storage codec for a
/// slot shape and fails closed for every unsupported shape.
///
/// A [`SlotShape::Multi`] with a positive `token_dim` resolves to
/// [`MultiVectorStorageCodec::PackedColbertInt8V1`]. `Dense` and `Sparse` shapes
/// are refused here — dense slots are the dense compression path's domain, and
/// sparse storage has no commissioned codec yet, so this returns a structured
/// refusal rather than silently selecting a dense format.
pub fn resolve_multivector_storage(shape: SlotShape) -> Result<MultiVectorStorageCodec> {
    match shape {
        SlotShape::Multi { token_dim } if token_dim > 0 => {
            Ok(MultiVectorStorageCodec::PackedColbertInt8V1)
        }
        SlotShape::Multi { token_dim } => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "multi-vector shape has token_dim {token_dim}; packed ColBERT storage requires a positive token dimension"
            ),
        )),
        SlotShape::Dense(dim) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "dense shape (dim {dim}) is not a multi-vector shape; use the dense compression codecs, not packed ColBERT storage"
            ),
        )),
        SlotShape::Sparse(dim) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "sparse shape (ambient dim {dim}) has no commissioned physical storage codec; packed ColBERT storage is defined only for multi-vector token matrices"
            ),
        )),
    }
}

/// Guard the dense compression entry points call before any catalog mutation.
///
/// A [`SlotShape::Multi`] or [`SlotShape::Sparse`] slot fed to the dense
/// compression path is refused here with a diagnostic naming the shape and the
/// codec the catalog cannot execute, closing the "catalog advertises a codec
/// the shape cannot execute" truth failure. `requested` is the policy the
/// catalog stamped on the slot and is surfaced in the diagnostic so the false
/// advertisement is visible.
pub fn reject_dense_codec_for_multivector(shape: SlotShape, requested: QuantPolicy) -> Result<()> {
    match shape {
        SlotShape::Dense(_) => Ok(()),
        SlotShape::Multi { token_dim } => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "multi-vector slot (token_dim {token_dim}) carries dense quant policy {requested:?}, which cannot execute against token matrices; route it through the packed ColBERT ({}) codec",
                MultiVectorStorageCodec::PackedColbertInt8V1.catalog_label()
            ),
        )),
        SlotShape::Sparse(dim) => Err(multivector_error(
            CALYX_MULTIVECTOR_SHAPE_UNSUPPORTED,
            format!(
                "sparse slot (ambient dim {dim}) carries dense quant policy {requested:?}, which cannot execute against sparse vectors; no sparse storage codec is commissioned"
            ),
        )),
    }
}

/// Physical byte accounting for a packed ColBERT matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedColbertBytes {
    /// Total physical bytes of the packed record (header + tokens + digest).
    pub total_bytes: usize,
    /// Fixed header bytes (magic, version, tags, dims, bounds, identity).
    pub header_bytes: usize,
    /// Per-token metadata bytes (the f32 scale fields across all tokens).
    pub token_scale_bytes: usize,
    /// Quantized INT8 component bytes across all tokens.
    pub component_bytes: usize,
    /// Trailing checksum bytes.
    pub digest_bytes: usize,
}

/// Packs a ColBERT token matrix into the versioned self-describing format.
///
/// `tokens` is the raw F32 token matrix (`token_count` rows of `token_dim`
/// components). Every identity needed for exact decode and direct scoring is
/// embedded. Fails closed on an empty matrix, a token whose length does not
/// match `token_dim`, a non-finite component, a zero `token_dim`, or a
/// `token_count` above `max_tokens`.
pub fn pack_colbert_matrix(
    lens_id: LensId,
    generation_seq: Seq,
    token_dim: u32,
    max_tokens: u32,
    tokens: &[Vec<f32>],
) -> Result<Vec<u8>> {
    if token_dim == 0 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT token_dim must be greater than zero",
        ));
    }
    if max_tokens == 0 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT max_tokens bound must be greater than zero",
        ));
    }
    if tokens.is_empty() {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT matrix must contain at least one token (empty document tokens are refused)",
        ));
    }
    let token_count = u32::try_from(tokens.len()).map_err(|_| {
        multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT token count exceeds u32",
        )
    })?;
    if token_count > max_tokens {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!(
                "packed ColBERT token count {token_count} exceeds declared max_tokens bound {max_tokens}"
            ),
        ));
    }
    let token_dim_usize = token_dim as usize;
    let mut body = Vec::with_capacity(
        MULTIVECTOR_HEADER_BYTES
            + tokens.len() * (TOKEN_SCALE_BYTES + token_dim_usize)
            + MULTIVECTOR_DIGEST_BYTES,
    );
    body.extend_from_slice(MULTIVECTOR_PACK_MAGIC);
    body.extend_from_slice(&MULTIVECTOR_PACK_VERSION.to_le_bytes());
    body.push(CODEC_TAG_COLBERT_INT8);
    body.push(METRIC_TAG_COSINE_MAXSIM);
    body.extend_from_slice(&token_dim.to_le_bytes());
    body.extend_from_slice(&token_count.to_le_bytes());
    body.extend_from_slice(&max_tokens.to_le_bytes());
    body.extend_from_slice(lens_id.as_bytes());
    body.extend_from_slice(&generation_seq.to_le_bytes());
    debug_assert_eq!(body.len(), MULTIVECTOR_HEADER_BYTES);

    for (idx, token) in tokens.iter().enumerate() {
        if token.len() != token_dim_usize {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!(
                    "packed ColBERT token {idx} has length {} but token_dim is {token_dim}",
                    token.len()
                ),
            ));
        }
        let mut max_abs = 0.0f32;
        for &component in token {
            if !component.is_finite() {
                return Err(multivector_error(
                    CALYX_MULTIVECTOR_PACK_INVALID,
                    format!("packed ColBERT token {idx} has a non-finite component"),
                ));
            }
            let abs = component.abs();
            if abs > max_abs {
                max_abs = abs;
            }
        }
        let scale = max_abs / 127.0;
        body.extend_from_slice(&scale.to_le_bytes());
        for &component in token {
            let quantized = if scale > 0.0 {
                let q = (component / scale).round();
                q.clamp(-127.0, 127.0) as i8
            } else {
                0i8
            };
            body.push(quantized as u8);
        }
    }

    let digest = Sha256::digest(&body);
    body.extend_from_slice(&digest);
    Ok(body)
}

/// A validated, self-describing packed ColBERT matrix bound to its owning bytes.
#[derive(Clone, Debug)]
pub struct ParsedColbertMatrix {
    bytes: Vec<u8>,
    token_dim: u32,
    token_count: u32,
    max_tokens: u32,
    lens_id: LensId,
    generation_seq: Seq,
}

impl ParsedColbertMatrix {
    /// Per-token component dimension.
    pub fn token_dim(&self) -> u32 {
        self.token_dim
    }
    /// Number of document tokens.
    pub fn token_count(&self) -> u32 {
        self.token_count
    }
    /// Declared maximum token bound stored in the header.
    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
    /// Frozen lens identity the matrix was packed under.
    pub fn lens_id(&self) -> LensId {
        self.lens_id
    }
    /// Generation binding the matrix was packed under.
    pub fn generation_seq(&self) -> Seq {
        self.generation_seq
    }

    /// Physical byte accounting for this record.
    pub fn physical_bytes(&self) -> PackedColbertBytes {
        let token_scale_bytes = self.token_count as usize * TOKEN_SCALE_BYTES;
        let component_bytes = self.token_count as usize * self.token_dim as usize;
        PackedColbertBytes {
            total_bytes: self.bytes.len(),
            header_bytes: MULTIVECTOR_HEADER_BYTES,
            token_scale_bytes,
            component_bytes,
            digest_bytes: MULTIVECTOR_DIGEST_BYTES,
        }
    }

    /// Byte offset of token `idx` within the packed body.
    fn token_offset(&self, idx: u32) -> usize {
        MULTIVECTOR_HEADER_BYTES + idx as usize * (TOKEN_SCALE_BYTES + self.token_dim as usize)
    }

    /// Decodes token `idx` into `scratch` in place (dequantized F32).
    ///
    /// `scratch` is rebuilt to hold exactly `token_dim` values; the caller
    /// reuses one buffer across the whole matrix so scoring never materializes
    /// the corpus as F32.
    pub fn decode_token_into(&self, idx: u32, scratch: &mut Vec<f32>) -> Result<()> {
        if idx >= self.token_count {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!(
                    "packed ColBERT token index {idx} out of bounds for token_count {}",
                    self.token_count
                ),
            ));
        }
        let base = self.token_offset(idx);
        let scale_bytes: [u8; 4] = self.bytes[base..base + TOKEN_SCALE_BYTES]
            .try_into()
            .expect("token scale slice is 4 bytes");
        let scale = f32::from_le_bytes(scale_bytes);
        if !scale.is_finite() || scale < 0.0 {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!("packed ColBERT token {idx} has a non-finite or negative scale {scale}"),
            ));
        }
        let component_base = base + TOKEN_SCALE_BYTES;
        let token_dim_usize = self.token_dim as usize;
        scratch.clear();
        scratch.reserve(token_dim_usize);
        for offset in 0..token_dim_usize {
            let quantized = self.bytes[component_base + offset] as i8;
            scratch.push(quantized as f32 * scale);
        }
        Ok(())
    }
}

/// Parses and fully validates a packed ColBERT record against the exact
/// expected context, failing closed on any mismatch.
///
/// Validates magic, version, codec/metric tags, `token_dim` (shape), lens
/// identity and generation binding (context), token bounds, byte-length
/// consistency (offsets/counts), and the trailing SHA-256 digest (checksum).
pub fn parse_colbert_matrix(
    bytes: &[u8],
    expected_lens_id: LensId,
    expected_generation_seq: Seq,
    expected_token_dim: u32,
) -> Result<ParsedColbertMatrix> {
    if bytes.len() < MULTIVECTOR_HEADER_BYTES + MULTIVECTOR_DIGEST_BYTES {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!(
                "packed ColBERT record is {} bytes; below the {} byte header+digest floor",
                bytes.len(),
                MULTIVECTOR_HEADER_BYTES + MULTIVECTOR_DIGEST_BYTES
            ),
        ));
    }
    if &bytes[0..16] != MULTIVECTOR_PACK_MAGIC {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT record has an unrecognized magic prefix (legacy or foreign row); it is refused, not decoded as a raw-F32 proxy",
        ));
    }
    let version = u16::from_le_bytes([bytes[16], bytes[17]]);
    if version != MULTIVECTOR_PACK_VERSION {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!(
                "packed ColBERT record version {version} is not the supported version {MULTIVECTOR_PACK_VERSION}"
            ),
        ));
    }
    let codec_tag = bytes[18];
    if codec_tag != CODEC_TAG_COLBERT_INT8 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!("packed ColBERT record codec tag {codec_tag} is not the supported INT8 codec"),
        ));
    }
    let metric_tag = bytes[19];
    if metric_tag != METRIC_TAG_COSINE_MAXSIM {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!("packed ColBERT record metric tag {metric_tag} is not cosine MaxSim"),
        ));
    }
    let token_dim = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let token_count = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    let max_tokens = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    let mut lens_bytes = [0u8; 16];
    lens_bytes.copy_from_slice(&bytes[32..48]);
    let lens_id = LensId::from_bytes(lens_bytes);
    let generation_seq = u64::from_le_bytes([
        bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
    ]);

    if token_dim == 0 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT record declares token_dim 0",
        ));
    }
    if token_dim != expected_token_dim {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "packed ColBERT record token_dim {token_dim} does not match expected slot token_dim {expected_token_dim}"
            ),
        ));
    }
    if lens_id != expected_lens_id {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "packed ColBERT record lens {lens_id} does not match expected lens {expected_lens_id}"
            ),
        ));
    }
    if generation_seq != expected_generation_seq {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "packed ColBERT record generation seq {generation_seq} does not match expected generation seq {expected_generation_seq}"
            ),
        ));
    }
    if max_tokens == 0 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT record declares a zero max_tokens bound",
        ));
    }
    if token_count == 0 {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT record declares zero tokens (empty document tokens are refused)",
        ));
    }
    if token_count > max_tokens {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!(
                "packed ColBERT record token_count {token_count} exceeds its max_tokens bound {max_tokens}"
            ),
        ));
    }

    let per_token = TOKEN_SCALE_BYTES + token_dim as usize;
    let expected_len = MULTIVECTOR_HEADER_BYTES
        .checked_add(token_count as usize * per_token)
        .and_then(|len| len.checked_add(MULTIVECTOR_DIGEST_BYTES))
        .ok_or_else(|| {
            multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                "packed ColBERT record length computation overflowed",
            )
        })?;
    if bytes.len() != expected_len {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            format!(
                "packed ColBERT record is {} bytes but token_dim/token_count imply {expected_len} bytes (malformed offsets/counts)",
                bytes.len()
            ),
        ));
    }

    let body_len = bytes.len() - MULTIVECTOR_DIGEST_BYTES;
    let computed = Sha256::digest(&bytes[..body_len]);
    if computed.as_slice() != &bytes[body_len..] {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT record checksum does not match its bytes (corruption or tampering)",
        ));
    }

    Ok(ParsedColbertMatrix {
        bytes: bytes.to_vec(),
        token_dim,
        token_count,
        max_tokens,
        lens_id,
        generation_seq,
    })
}

/// Cosine similarity between two equal-length vectors; matches the live
/// late-interaction scorer's zero-norm handling (returns 0.0).
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut an = 0.0f32;
    let mut bn = 0.0f32;
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
        an += x * x;
        bn += y * y;
    }
    if an == 0.0 || bn == 0.0 {
        0.0
    } else {
        dot / (an.sqrt() * bn.sqrt())
    }
}

/// Directly scores a query token matrix against a packed document matrix using
/// cosine MaxSim late interaction.
///
/// `scratch` is a caller-owned buffer reused to decode one document token at a
/// time, so the whole corpus is never materialized as F32. Per-query running
/// maxima are the only additional state, bounded by the query token count. Fails
/// closed on an empty query or a query token whose length or finiteness does not
/// match the document `token_dim`.
pub fn packed_maxsim(
    query: &[Vec<f32>],
    doc: &ParsedColbertMatrix,
    scratch: &mut Vec<f32>,
) -> Result<f32> {
    if query.is_empty() {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_PACK_INVALID,
            "packed ColBERT MaxSim query has no tokens (empty query tokens are refused)",
        ));
    }
    let token_dim_usize = doc.token_dim as usize;
    for (idx, token) in query.iter().enumerate() {
        if token.len() != token_dim_usize {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
                format!(
                    "packed ColBERT query token {idx} has length {} but document token_dim is {}",
                    token.len(),
                    doc.token_dim
                ),
            ));
        }
        if token.iter().any(|component| !component.is_finite()) {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_PACK_INVALID,
                format!("packed ColBERT query token {idx} has a non-finite component"),
            ));
        }
    }

    let mut maxima = vec![f32::NEG_INFINITY; query.len()];
    for token_idx in 0..doc.token_count {
        doc.decode_token_into(token_idx, scratch)?;
        for (query_idx, query_token) in query.iter().enumerate() {
            let similarity = cosine(query_token, scratch);
            if similarity > maxima[query_idx] {
                maxima[query_idx] = similarity;
            }
        }
    }
    Ok(maxima.iter().sum())
}
