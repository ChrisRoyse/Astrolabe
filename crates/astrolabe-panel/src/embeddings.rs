use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use calyx_core::{
    AbsentReason, CalyxError, Input, Lens, LensId, Modality, SlotId, SlotShape, SlotVector,
    content_address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::lenses::cbm_camel_split_tokens;
use crate::{
    ASTRO_PANEL_CONTRACT_INVALID, ASTRO_PANEL_VECTOR_INVALID, FrozenLensContract, PanelError,
    PanelResult, slot_spec,
};

/// Number of tokens in the vendored nomic static-vector table.
pub const NOMIC_TOKEN_COUNT: usize = 40_856;
/// Dense embedding dimension for S18-S20.
pub const NOMIC_EMBED_DIM: usize = 768;
/// Optional S22 token vector dimension.
#[cfg(feature = "multi-vector")]
pub const TOKEN_MULTI_DIM: usize = 128;
const NOMIC_VECTOR_BLOB_LEN: usize = 31_377_416;
const NOMIC_VECTOR_HEADER_LEN: usize = 8;
const NOMIC_OOV_NNZ: usize = 8;
const INT8_SCALE: f32 = 127.0;

/// SHA-256 of `cbm/vendored/nomic/code_vectors.bin`.
pub const NOMIC_VECTOR_BLOB_SHA256: [u8; 32] = [
    0xc7, 0x6b, 0xba, 0x4c, 0x50, 0x32, 0x32, 0x3d, 0xed, 0x62, 0x02, 0x05, 0x3a, 0xf5, 0xaf, 0xdb,
    0xba, 0xc1, 0x2f, 0x6d, 0x92, 0x0c, 0x69, 0x1b, 0x3b, 0x3b, 0x4c, 0xd7, 0x08, 0xf9, 0x9e, 0x83,
];

/// SHA-256 of the raw bytes of
/// `cbm/vendored/nomic/code_tokens.txt` (LF-normalized by
/// `.gitattributes`). The token file assigns each vector row its token identity,
/// so a reordered/edited table with the same row count would silently change
/// S18-S20/S22 outputs under the same lens id. Freezing this hash makes any such
/// drift fail closed in `load_from_paths`.
pub const NOMIC_TOKEN_TABLE_SHA256: [u8; 32] = [
    0xc9, 0x28, 0xf5, 0xe2, 0xf9, 0xdd, 0x85, 0xf2, 0x29, 0x4a, 0x50, 0xa0, 0x5d, 0xd9, 0xf2, 0xf8,
    0xbc, 0x95, 0x19, 0x27, 0x27, 0x57, 0x9a, 0xa1, 0x6b, 0x06, 0x2f, 0xf8, 0xef, 0x30, 0x1d, 0x25,
];

const CODE_VECTORS_REL: &str = "../../cbm/vendored/nomic/code_vectors.bin";
const CODE_TOKENS_REL: &str = "../../cbm/vendored/nomic/code_tokens.txt";

/// Input measured by S18-S20/S22 static embedding lenses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticEmbeddingInput {
    /// Body/code tokens for S18.
    pub body_tokens: Vec<String>,
    /// Docstring and adjacent-comment tokens for S19.
    pub doc_tokens: Vec<String>,
    /// Local identifier name for S20.
    pub name: String,
    /// Qualified identifier name for S20.
    pub qualified_name: String,
}

/// Loaded nomic static-vector table with verified blob hash.
#[derive(Clone, Debug)]
pub struct StaticEmbeddingTable {
    token_to_index: HashMap<String, usize>,
    vectors: Vec<i8>,
    weights_sha: [u8; 32],
}

impl StaticEmbeddingTable {
    /// Loads and verifies the vendored Codebase Memory MCP nomic vector blob.
    pub fn load_default() -> PanelResult<Self> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        Self::load_from_paths(
            manifest_dir.join(CODE_VECTORS_REL),
            manifest_dir.join(CODE_TOKENS_REL),
            NOMIC_VECTOR_BLOB_SHA256,
            NOMIC_TOKEN_TABLE_SHA256,
        )
    }

    /// Loads a token table and vector blob, failing closed when either SHA, the
    /// layout, or the token-uniqueness invariant drifts.
    ///
    /// The vector blob and the token table are both content-verified: the blob
    /// carries the row vectors, the token table binds each row to its token
    /// identity, and both are folded into `weights_sha` so the frozen lens
    /// version changes if either input changes.
    pub fn load_from_paths(
        blob_path: impl AsRef<Path>,
        tokens_path: impl AsRef<Path>,
        expected_sha: [u8; 32],
        expected_tokens_sha: [u8; 32],
    ) -> PanelResult<Self> {
        let blob = fs::read(blob_path.as_ref()).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "failed to read nomic vector blob {}: {err}",
                    blob_path.as_ref().display()
                ),
                "Restore the vendored code_vectors.bin blob before registering embedding lenses.",
            )
        })?;
        let actual_sha: [u8; 32] = Sha256::digest(&blob).into();
        if actual_sha != expected_sha {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "nomic vector blob SHA-256 does not match the frozen contract",
                "Use the exact vendored code_vectors.bin that matches NOMIC_VECTOR_BLOB_SHA256.",
            ));
        }
        validate_blob_layout(&blob)?;

        let token_text = fs::read_to_string(tokens_path.as_ref()).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!(
                    "failed to read nomic token table {}: {err}",
                    tokens_path.as_ref().display()
                ),
                "Restore the vendored code_tokens.txt table before registering embedding lenses.",
            )
        })?;
        let actual_tokens_sha: [u8; 32] = Sha256::digest(token_text.as_bytes()).into();
        if actual_tokens_sha != expected_tokens_sha {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "nomic token table SHA-256 does not match the frozen contract",
                "Use the exact vendored code_tokens.txt that matches NOMIC_TOKEN_TABLE_SHA256; \
                 a reordered or edited table changes S18-S20/S22 outputs and requires a new lens version.",
            ));
        }
        let mut token_to_index = HashMap::with_capacity(NOMIC_TOKEN_COUNT);
        let mut row_count = 0_usize;
        for (idx, token) in token_text.lines().enumerate() {
            row_count += 1;
            if idx >= NOMIC_TOKEN_COUNT {
                return Err(PanelError::new(
                    ASTRO_PANEL_CONTRACT_INVALID,
                    "nomic token table has more rows than the vector blob",
                    "Keep code_tokens.txt aligned with code_vectors.bin.",
                ));
            }
            if !token.is_empty() && token_to_index.insert(token.to_string(), idx).is_some() {
                return Err(PanelError::new(
                    ASTRO_PANEL_CONTRACT_INVALID,
                    format!("nomic token table contains a duplicate token at row {idx}: {token:?}"),
                    "Keep every non-empty token in code_tokens.txt unique so a single row maps to a single vector.",
                ));
            }
        }
        if row_count != NOMIC_TOKEN_COUNT {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("nomic token table has {row_count} rows, expected {NOMIC_TOKEN_COUNT}"),
                "Keep code_tokens.txt aligned with code_vectors.bin.",
            ));
        }

        let vectors = blob[NOMIC_VECTOR_HEADER_LEN..]
            .iter()
            .map(|byte| *byte as i8)
            .collect();
        Ok(Self {
            token_to_index,
            vectors,
            weights_sha: nomic_weights_identity_from(&actual_sha, &actual_tokens_sha),
        })
    }

    /// Frozen weights identity for the loaded table: SHA-256 over the vector
    /// blob SHA and the token table SHA (see [`nomic_weights_identity`]).
    pub const fn weights_sha(&self) -> [u8; 32] {
        self.weights_sha
    }

    fn token_vector(&self, token: &str) -> Vec<f32> {
        let mut out = vec![0.0; NOMIC_EMBED_DIM];
        if let Some(index) = self.token_to_index.get(token).copied() {
            let start = index * NOMIC_EMBED_DIM;
            for (dst, src) in out
                .iter_mut()
                .zip(self.vectors[start..start + NOMIC_EMBED_DIM].iter())
            {
                *dst = f32::from(*src) / INT8_SCALE;
            }
        } else {
            fill_oov_sparse(token, &mut out);
        }
        out
    }

    fn embed_tokens(&self, tokens: &[String]) -> PanelResult<SlotVector> {
        if tokens.is_empty() {
            return Ok(absent());
        }
        let mut data = vec![0.0; NOMIC_EMBED_DIM];
        for token in tokens {
            if token.trim().is_empty() {
                continue;
            }
            let token_vec = self.token_vector(token.trim());
            for (dst, src) in data.iter_mut().zip(token_vec) {
                *dst += src;
            }
        }
        l2_normalize(&mut data)?;
        Ok(SlotVector::Dense {
            dim: NOMIC_EMBED_DIM as u32,
            data,
        })
    }

    #[cfg(feature = "multi-vector")]
    fn embed_token_multi(&self, tokens: &[String]) -> PanelResult<SlotVector> {
        if tokens.is_empty() {
            return Ok(absent());
        }
        let seed = crate::seed_spec_for_lens("token_multi").ok_or_else(|| {
            PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "missing token_multi seed registry entry",
                "Keep the frozen seed registry aligned with S22 token_multi.",
            )
        })?;
        let mut projected = Vec::new();
        for token in tokens {
            if token.trim().is_empty() {
                continue;
            }
            let token_vec = self.token_vector(token.trim());
            let mut out = vec![0.0; TOKEN_MULTI_DIM];
            for (dim, value) in token_vec.iter().copied().enumerate() {
                let dim_bytes = (dim as u32).to_be_bytes();
                let hash = content_address([
                    b"token_multi_projection".as_slice(),
                    dim_bytes.as_slice(),
                    seed.seed_hex.as_bytes(),
                ]);
                let mut idx = [0_u8; 4];
                idx.copy_from_slice(&hash[..4]);
                let target = u32::from_be_bytes(idx) as usize % TOKEN_MULTI_DIM;
                let sign = if hash[4] & 1 == 0 { 1.0 } else { -1.0 };
                out[target] += sign * value;
            }
            l2_normalize(&mut out)?;
            projected.push(out);
        }
        if projected.is_empty() {
            return Ok(absent());
        }
        Ok(SlotVector::Multi {
            token_dim: TOKEN_MULTI_DIM as u32,
            tokens: projected,
        })
    }
}

/// Runtime lens for S18-S20 and optional S22.
#[derive(Clone, Debug)]
pub struct StaticEmbeddingLens {
    slot_id: SlotId,
    contract: FrozenLensContract,
    table: Arc<StaticEmbeddingTable>,
}

impl StaticEmbeddingLens {
    /// Builds a static embedding lens for S18-S20, or S22 with `multi-vector` enabled.
    pub fn new(slot_id: SlotId, table: Arc<StaticEmbeddingTable>) -> PanelResult<Self> {
        let slot = slot_spec(slot_id).ok_or_else(|| {
            PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("slot {slot_id} is not in the frozen panel roster"),
                "Use one of the frozen panel v1 slot ids.",
            )
        })?;
        if !matches!(slot.slot, 18 | 19 | 20 | 22) {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("slot {slot_id} is outside the static embedding lens range"),
                "Use S18-S20, or S22 when multi-vector is enabled.",
            ));
        }
        if slot.slot == 22 && !cfg!(feature = "multi-vector") {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "S22 token_multi is excluded from the default build",
                "Enable the astrolabe-panel `multi-vector` feature to register S22.",
            ));
        }
        let contract = FrozenLensContract::for_slot(slot)?;
        if contract.weights_sha != table.weights_sha() {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                "static embedding table hash does not match the frozen lens contract",
                "Load the exact nomic vector blob before registering embedding lenses.",
            ));
        }
        Ok(Self {
            slot_id,
            contract,
            table,
        })
    }

    /// Returns the slot this lens measures.
    pub const fn slot_id(&self) -> SlotId {
        self.slot_id
    }

    /// Builds the registration probe input for this lens.
    pub fn probe_input(&self) -> PanelResult<Input> {
        let slot = slot_spec(self.slot_id).expect("validated slot");
        let bytes = serde_json::to_vec(&fixture_static_embedding_input()).map_err(|err| {
            PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!("fixture StaticEmbeddingInput did not serialize: {err}"),
                "Keep deterministic embedding probe fixtures serializable.",
            )
        })?;
        Ok(Input::new(slot.modality, bytes))
    }

    /// Returns the frozen contract.
    pub fn contract(&self) -> &FrozenLensContract {
        &self.contract
    }
}

impl Lens for StaticEmbeddingLens {
    fn id(&self) -> LensId {
        self.contract.lens_id()
    }

    fn shape(&self) -> SlotShape {
        self.contract.shape
    }

    fn modality(&self) -> Modality {
        self.contract.modality
    }

    fn measure(&self, input: &Input) -> calyx_core::Result<SlotVector> {
        if input.modality != self.contract.modality {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "slot {} expected {:?} input, got {:?}",
                self.slot_id, self.contract.modality, input.modality
            )));
        }
        let decoded: StaticEmbeddingInput =
            serde_json::from_slice(&input.bytes).map_err(|err| {
                CalyxError::lens_frozen_violation(format!(
                    "slot {} probe/input JSON is not a StaticEmbeddingInput: {err}",
                    self.slot_id
                ))
            })?;
        encode_static_embedding_slot(self.slot_id, &decoded, &self.table).map_err(|err| {
            CalyxError::lens_numerical_invariant(format!("{}: {}", err.code(), err.message()))
        })
    }
}

/// Returns S18-S20 static embedding lenses.
pub fn s18_s20_lenses(table: Arc<StaticEmbeddingTable>) -> PanelResult<Vec<StaticEmbeddingLens>> {
    (18_u16..=20)
        .map(|slot| StaticEmbeddingLens::new(SlotId::new(slot), Arc::clone(&table)))
        .collect()
}

/// Fixture input for S18-S20/S22 tests and registration probes.
pub fn fixture_static_embedding_input() -> StaticEmbeddingInput {
    StaticEmbeddingInput {
        body_tokens: vec![
            "fn".to_string(),
            "load".to_string(),
            "user".to_string(),
            "return".to_string(),
        ],
        doc_tokens: vec![
            "load".to_string(),
            "user".to_string(),
            "response".to_string(),
        ],
        name: "loadUserHTTP2".to_string(),
        qualified_name: "crate::service::UserStore::loadUserHTTP2".to_string(),
    }
}

/// Encodes one production static-embedding slot from a content-verified table.
pub fn encode_static_embedding_slot(
    slot_id: SlotId,
    input: &StaticEmbeddingInput,
    table: &StaticEmbeddingTable,
) -> PanelResult<SlotVector> {
    match slot_id.get() {
        18 => table.embed_tokens(&input.body_tokens),
        19 => table.embed_tokens(&input.doc_tokens),
        20 => {
            let mut tokens = cbm_camel_split_tokens(&input.name);
            let qn_tail = input
                .qualified_name
                .rsplit([':', '.', '/', '#'])
                .find(|part| !part.is_empty())
                .unwrap_or(&input.qualified_name);
            tokens.extend(cbm_camel_split_tokens(qn_tail));
            table.embed_tokens(&tokens)
        }
        22 => {
            #[cfg(feature = "multi-vector")]
            {
                table.embed_token_multi(&input.body_tokens)
            }
            #[cfg(not(feature = "multi-vector"))]
            {
                Err(PanelError::new(
                    ASTRO_PANEL_CONTRACT_INVALID,
                    "S22 token_multi is excluded from the default build",
                    "Enable the astrolabe-panel `multi-vector` feature to encode S22.",
                ))
            }
        }
        _ => Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("slot {slot_id} is not a static embedding slot"),
            "Use S18-S20, or S22 with the multi-vector feature.",
        )),
    }
}

/// Frozen weights identity for the S18-S20/S22 static embedding lenses.
///
/// The identity folds both content addresses of the vendored nomic table — the
/// vector blob and the token-index table — under a domain-separated SHA-256, so
/// the lens version (and every content address derived from it) changes if the
/// vectors *or* the token ordering changes.
pub fn nomic_weights_identity() -> [u8; 32] {
    nomic_weights_identity_from(&NOMIC_VECTOR_BLOB_SHA256, &NOMIC_TOKEN_TABLE_SHA256)
}

fn nomic_weights_identity_from(blob_sha: &[u8; 32], tokens_sha: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe.panel.nomic.weights.v1");
    hasher.update(blob_sha);
    hasher.update(tokens_sha);
    hasher.finalize().into()
}

fn validate_blob_layout(blob: &[u8]) -> PanelResult<()> {
    if blob.len() != NOMIC_VECTOR_BLOB_LEN {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "nomic vector blob length {} != {NOMIC_VECTOR_BLOB_LEN}",
                blob.len()
            ),
            "Restore the exact vendored code_vectors.bin blob.",
        ));
    }
    let count = u32::from_le_bytes(blob[0..4].try_into().expect("count bytes"));
    let dim = u32::from_le_bytes(blob[4..8].try_into().expect("dim bytes"));
    if count as usize != NOMIC_TOKEN_COUNT || dim as usize != NOMIC_EMBED_DIM {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("nomic vector blob header count={count} dim={dim}"),
            "Use a blob with the frozen 40856 x 768 layout.",
        ));
    }
    Ok(())
}

fn fill_oov_sparse(token: &str, out: &mut [f32]) {
    for i in 0..NOMIC_OOV_NNZ {
        let idx_bytes = (i as u32).to_be_bytes();
        let hash = content_address([
            NOMIC_VECTOR_BLOB_SHA256.as_slice(),
            token.as_bytes(),
            idx_bytes.as_slice(),
        ]);
        let mut idx = [0_u8; 4];
        idx.copy_from_slice(&hash[..4]);
        let pos = u32::from_be_bytes(idx) as usize % NOMIC_EMBED_DIM;
        let sign = if hash[4] & 1 == 0 { 1.0 } else { -1.0 };
        out[pos] += sign;
    }
}

fn l2_normalize(data: &mut [f32]) -> PanelResult<()> {
    let norm = data
        .iter()
        .map(|value| {
            let value = f64::from(*value);
            value * value
        })
        .sum::<f64>()
        .sqrt();
    if !norm.is_finite() {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            "embedding vector norm is non-finite",
            "Use only finite static vectors and deterministic fallback values.",
        ));
    }
    if norm == 0.0 {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            "embedding vector has zero norm",
            "Provide at least one token with a static or OOV fallback vector.",
        ));
    }
    for value in data {
        *value = (f64::from(*value) / norm) as f32;
    }
    Ok(())
}

fn absent() -> SlotVector {
    SlotVector::Absent {
        reason: AbsentReason::LensUnavailable,
    }
}
