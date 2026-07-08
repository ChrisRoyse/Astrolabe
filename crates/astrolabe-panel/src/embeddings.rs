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

/// SHA-256 of `vendor/codebase-memory-mcp/vendored/nomic/code_vectors.bin`.
pub const NOMIC_VECTOR_BLOB_SHA256: [u8; 32] = [
    0xc7, 0x6b, 0xba, 0x4c, 0x50, 0x32, 0x32, 0x3d, 0xed, 0x62, 0x02, 0x05, 0x3a, 0xf5, 0xaf, 0xdb,
    0xba, 0xc1, 0x2f, 0x6d, 0x92, 0x0c, 0x69, 0x1b, 0x3b, 0x3b, 0x4c, 0xd7, 0x08, 0xf9, 0x9e, 0x83,
];

const CODE_VECTORS_REL: &str = "../../vendor/codebase-memory-mcp/vendored/nomic/code_vectors.bin";
const CODE_TOKENS_REL: &str = "../../vendor/codebase-memory-mcp/vendored/nomic/code_tokens.txt";

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
        )
    }

    /// Loads a token table and vector blob, failing closed when the SHA or layout drifts.
    pub fn load_from_paths(
        blob_path: impl AsRef<Path>,
        tokens_path: impl AsRef<Path>,
        expected_sha: [u8; 32],
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
            if !token.is_empty() {
                token_to_index.insert(token.to_string(), idx);
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
            weights_sha: actual_sha,
        })
    }

    /// SHA-256 verified for the loaded vector blob.
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
        let contract = FrozenLensContract::for_slot(slot);
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
        encode_embedding_slot(self.slot_id, &decoded, &self.table).map_err(|err| {
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

fn encode_embedding_slot(
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use proptest::prelude::*;

    const GOLDEN_SHA_BY_SLOT: &[(u16, &str)] = &[
        (
            18,
            "c48369735e2df470487ff80970ed09601a74664012aa86dc74d2ab6f0328bbc7",
        ),
        (
            19,
            "f10d5351783f7edd65d48be7571e992adf1a6d3b5cfce53e5f57e32a389ab63f",
        ),
        (
            20,
            "013897e8805ffc3dd658b17eb4c82f6f12f212df257c63a69c6b1ba8fbd9bac1",
        ),
    ];
    const OOV_GOLDEN_SHA: &str = "5a0ee90d4ae880dbad1ffbfab8b5ea928edd9190f024bedb8a0ed00df774827c";
    #[cfg(feature = "multi-vector")]
    const S22_GOLDEN_SHA: &str = "09c0806e71acf677ca8fca6e5671c36e483da2193da690f57bcb8bdc60bef0d2";

    #[test]
    fn blob_integrity_gate_verifies_sha_and_refuses_corruption() {
        let table = test_table();
        assert_eq!(table.weights_sha(), NOMIC_VECTOR_BLOB_SHA256);

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let blob_path = manifest_dir.join(CODE_VECTORS_REL);
        let token_path = manifest_dir.join(CODE_TOKENS_REL);
        let mut blob = fs::read(&blob_path).expect("read blob");
        blob[NOMIC_VECTOR_HEADER_LEN] ^= 0x7f;
        let corrupt_path = std::env::temp_dir().join(format!(
            "astrolabe-corrupt-code-vectors-{}.bin",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::write(&corrupt_path, blob).expect("write corrupt blob");
        let err = StaticEmbeddingTable::load_from_paths(
            &corrupt_path,
            &token_path,
            NOMIC_VECTOR_BLOB_SHA256,
        )
        .expect_err("corrupt blob refused");
        let _ = fs::remove_file(corrupt_path);
        assert_eq!(err.code(), ASTRO_PANEL_CONTRACT_INVALID);
    }

    #[test]
    fn static_embedding_contract_uses_blob_sha_and_probes_are_deterministic() {
        let table = Arc::clone(test_table());
        for lens in s18_s20_lenses(Arc::clone(&table)).expect("embedding lenses") {
            assert_eq!(lens.contract().weights_sha, NOMIC_VECTOR_BLOB_SHA256);
            let proof = lens
                .contract()
                .verify_determinism_probe(&lens, &lens.probe_input().expect("probe input"))
                .expect("determinism proof");
            assert_eq!(proof.lens_id, lens.id());
        }
    }

    #[test]
    fn golden_embeddings_s18_s20_are_exact_bitpatterns() {
        let table = test_table();
        let input = fixture_static_embedding_input();
        for (slot, expected) in GOLDEN_SHA_BY_SLOT {
            let vector = encode_embedding_slot(SlotId::new(*slot), &input, table.as_ref())
                .expect("embedding vector");
            let actual = hex_lower(&sha256_digest_bytes(&slot_vector_bytes(&vector)));
            if expected.is_empty() {
                eprintln!("slot {slot}: {actual}");
                continue;
            }
            assert_eq!(actual, *expected, "slot {slot} embedding drifted");
        }
    }

    #[test]
    fn oov_tokens_use_deterministic_random_index_fallback() {
        let table = test_table();
        let input = StaticEmbeddingInput {
            body_tokens: vec!["astrolabe_oov_fixture".to_string()],
            ..StaticEmbeddingInput::default()
        };
        let first = encode_embedding_slot(SlotId::new(18), &input, table.as_ref())
            .expect("first OOV vector");
        let second = encode_embedding_slot(SlotId::new(18), &input, table.as_ref())
            .expect("second OOV vector");
        assert_eq!(slot_vector_bytes(&first), slot_vector_bytes(&second));
        let actual = hex_lower(&sha256_digest_bytes(&slot_vector_bytes(&first)));
        if OOV_GOLDEN_SHA.is_empty() {
            eprintln!("oov: {actual}");
        } else {
            assert_eq!(actual, OOV_GOLDEN_SHA);
        }
    }

    #[test]
    fn s19_without_doc_tokens_is_absent_not_zero() {
        let table = test_table();
        let input = StaticEmbeddingInput {
            body_tokens: vec!["fn".to_string()],
            doc_tokens: Vec::new(),
            name: "loadUser".to_string(),
            qualified_name: "crate::loadUser".to_string(),
        };
        assert_eq!(
            encode_embedding_slot(SlotId::new(19), &input, table.as_ref()).expect("S19 absent"),
            absent()
        );
    }

    #[test]
    fn default_build_excludes_s22_token_multi() {
        let table = Arc::clone(test_table());
        if cfg!(feature = "multi-vector") {
            StaticEmbeddingLens::new(SlotId::new(22), table).expect("S22 enabled");
        } else {
            let err = StaticEmbeddingLens::new(SlotId::new(22), table)
                .expect_err("S22 disabled by default");
            assert_eq!(err.code(), ASTRO_PANEL_CONTRACT_INVALID);
        }
    }

    #[cfg(feature = "multi-vector")]
    #[test]
    fn multi_vector_feature_emits_s22_goldens() {
        let table = test_table();
        let vector = encode_embedding_slot(
            SlotId::new(22),
            &fixture_static_embedding_input(),
            table.as_ref(),
        )
        .expect("S22 vector");
        let actual = hex_lower(&sha256_digest_bytes(&slot_vector_bytes(&vector)));
        if S22_GOLDEN_SHA.is_empty() {
            eprintln!("s22: {actual}");
        } else {
            assert_eq!(actual, S22_GOLDEN_SHA, "S22 token_multi drifted");
        }
        let SlotVector::Multi { token_dim, tokens } = vector else {
            panic!("S22 must emit Multi");
        };
        assert_eq!(token_dim, TOKEN_MULTI_DIM as u32);
        assert!(!tokens.is_empty());
        for token in tokens {
            assert_eq!(token.len(), TOKEN_MULTI_DIM);
            assert!(token.iter().all(|value| value.is_finite()));
        }
    }

    proptest! {
        #[test]
        fn unit_norm_property_holds_for_static_and_oov_tokens(
            suffix in "[a-z]{1,12}",
        ) {
            let table = test_table();
            let tokens = vec![
                "fn".to_string(),
                "return".to_string(),
                format!("astrolabe_oov_{suffix}"),
            ];
            let vector = table.embed_tokens(&tokens).expect("embedding");
            let SlotVector::Dense { data, .. } = vector else {
                panic!("dense embedding");
            };
            prop_assert!(data.iter().all(|value| value.is_finite()));
            let norm = data
                .iter()
                .map(|value| {
                    let value = f64::from(*value);
                    value * value
                })
                .sum::<f64>()
                .sqrt();
            prop_assert!((norm - 1.0).abs() <= 1.0e-6);
        }
    }

    fn slot_vector_bytes(vector: &SlotVector) -> Vec<u8> {
        let mut out = Vec::new();
        match vector {
            SlotVector::Dense { dim, data } => {
                out.extend_from_slice(b"D");
                out.extend_from_slice(&dim.to_be_bytes());
                for value in data {
                    out.extend_from_slice(&value.to_bits().to_be_bytes());
                }
            }
            SlotVector::Multi { token_dim, tokens } => {
                out.extend_from_slice(b"M");
                out.extend_from_slice(&token_dim.to_be_bytes());
                out.extend_from_slice(&(tokens.len() as u32).to_be_bytes());
                for token in tokens {
                    for value in token {
                        out.extend_from_slice(&value.to_bits().to_be_bytes());
                    }
                }
            }
            SlotVector::Sparse { .. } | SlotVector::Absent { .. } => {
                panic!("embedding goldens must be dense or multi")
            }
        }
        out
    }

    fn sha256_digest_bytes(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn test_table() -> &'static Arc<StaticEmbeddingTable> {
        static TABLE: OnceLock<Arc<StaticEmbeddingTable>> = OnceLock::new();
        TABLE.get_or_init(|| {
            Arc::new(StaticEmbeddingTable::load_default().expect("load vendored nomic table"))
        })
    }
}
