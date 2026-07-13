//! Shared support for the S18-S20/S22 embedding golden and feature-gate tests.
//!
//! Everything here works on **real** artifacts: the vendored nomic blob and token
//! table, real source-code fixture snippets checked in under `tests/fixtures/`, and
//! golden files whose persisted bytes are the emitted f32 bitpatterns. No mocks, no
//! synthesized vectors.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use astrolabe_panel::{
    NOMIC_EMBED_DIM, NOMIC_TOKEN_COUNT, NOMIC_TOKEN_TABLE_SHA256, NOMIC_VECTOR_BLOB_SHA256,
    PanelResult, StaticEmbeddingInput, StaticEmbeddingLens, StaticEmbeddingTable,
    cbm_camel_split_tokens,
};
use calyx_core::{Input, Lens, SlotId, SlotVector};
use sha2::{Digest, Sha256};

/// Big-endian f32 byte length of one dense 768-d embedding golden.
pub const DENSE_GOLDEN_LEN: usize = NOMIC_EMBED_DIM * 4;

/// Language of a fixture snippet; selects the doc/comment extraction rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lang {
    Rust,
    Python,
}

/// A real source snippet plus the symbol identity it belongs to.
#[derive(Clone, Copy, Debug)]
pub struct Fixture {
    /// Stable golden-file key.
    pub key: &'static str,
    /// File name under `tests/fixtures/`.
    pub file: &'static str,
    /// Language rule used to split doc/comment lines from body lines.
    pub lang: Lang,
    /// Local identifier of the symbol in the snippet.
    pub name: &'static str,
    /// Qualified name of the symbol in the snippet.
    pub qualified_name: &'static str,
}

/// The frozen fixture roster. Both snippets are real code, checked in verbatim.
pub const FIXTURES: &[Fixture] = &[
    Fixture {
        key: "rust_user_store",
        file: "rust_user_store.rs.txt",
        lang: Lang::Rust,
        name: "loadUserHTTP2",
        qualified_name: "crate::service::UserStore::loadUserHTTP2",
    },
    Fixture {
        key: "python_metrics_client",
        file: "python_metrics_client.py.txt",
        lang: Lang::Python,
        name: "flush_metric_batch",
        qualified_name: "app.telemetry.MetricsClient.flush_metric_batch",
    },
];

/// Dense embedding slots covered by the goldens.
pub const DENSE_SLOTS: [u16; 3] = [18, 19, 20];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Absolute path of a fixture snippet.
pub fn fixture_path(fixture: &Fixture) -> PathBuf {
    crate_dir().join("tests/fixtures").join(fixture.file)
}

/// Absolute path of a golden file (`<key>_s<slot>.f32be`).
pub fn golden_path(key: &str, slot: u16) -> PathBuf {
    crate_dir()
        .join("tests/golden")
        .join(format!("{key}_s{slot}.f32be"))
}

/// Path of the vendored nomic vector blob.
pub fn blob_path() -> PathBuf {
    crate_dir().join("../../cbm/vendored/nomic/code_vectors.bin")
}

/// Path of the vendored nomic token table.
pub fn tokens_path() -> PathBuf {
    crate_dir().join("../../cbm/vendored/nomic/code_tokens.txt")
}

/// The one real, SHA-verified nomic table, shared by every test in the binary.
pub fn table() -> Arc<StaticEmbeddingTable> {
    static TABLE: OnceLock<Arc<StaticEmbeddingTable>> = OnceLock::new();
    Arc::clone(TABLE.get_or_init(|| {
        Arc::new(StaticEmbeddingTable::load_default().expect("load vendored nomic table"))
    }))
}

/// Reads a fixture snippet, normalizing CRLF so a Windows checkout and an LF
/// checkout tokenize the identical byte stream.
pub fn read_fixture(fixture: &Fixture) -> String {
    fs::read_to_string(fixture_path(fixture))
        .expect("fixture snippet is checked in")
        .replace("\r\n", "\n")
}

/// Splits a real snippet into the S18/S19/S20 input the panel measures.
///
/// Doc/comment lines (Rust `///`, `//!`, `//`; Python `#` and `"""` blocks) feed
/// S19; every other non-blank line feeds S18. S20 takes its tokens from the
/// symbol identity, exactly as the lens does. Tokenization is the crate's frozen
/// `cbm_camel_split_tokens` (Unicode-6.1 `unicode61`), i.e. the production path.
pub fn embedding_input(fixture: &Fixture) -> StaticEmbeddingInput {
    let text = read_fixture(fixture);
    let mut body_tokens = Vec::new();
    let mut doc_tokens = Vec::new();
    let mut in_py_docstring = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let is_doc = match fixture.lang {
            Lang::Rust => trimmed.starts_with("//"),
            Lang::Python => {
                let fences = trimmed.matches("\"\"\"").count();
                let doc_line = in_py_docstring || trimmed.starts_with('#') || fences > 0;
                if fences % 2 == 1 {
                    in_py_docstring = !in_py_docstring;
                }
                doc_line
            }
        };
        let sink = if is_doc {
            &mut doc_tokens
        } else {
            &mut body_tokens
        };
        sink.extend(cbm_camel_split_tokens(line));
    }

    StaticEmbeddingInput {
        body_tokens,
        doc_tokens,
        name: fixture.name.to_string(),
        qualified_name: fixture.qualified_name.to_string(),
    }
}

/// Measures a slot through the **production** lens path: JSON `Input` -> `Lens::measure`.
pub fn measure(
    slot: u16,
    input: &StaticEmbeddingInput,
    table: Arc<StaticEmbeddingTable>,
) -> SlotVector {
    try_measure(slot, input, table).unwrap_or_else(|err| panic!("measure slot {slot}: {err}"))
}

/// Measures a slot through the production lens path, surfacing the fail-closed error.
pub fn try_measure(
    slot: u16,
    input: &StaticEmbeddingInput,
    table: Arc<StaticEmbeddingTable>,
) -> calyx_core::Result<SlotVector> {
    let lens = StaticEmbeddingLens::new(SlotId::new(slot), table)
        .unwrap_or_else(|err| panic!("lens for slot {slot}: {err}"));
    let bytes = serde_json::to_vec(input).expect("serialize embedding input");
    lens.measure(&Input::new(lens.modality(), bytes))
}

/// The emitted f32 bitpatterns of a dense vector, big-endian — the exact bytes the
/// goldens persist.
pub fn dense_bitpatterns(vector: &SlotVector) -> Vec<u8> {
    let SlotVector::Dense { dim, data } = vector else {
        panic!("expected a dense embedding, got {vector:?}");
    };
    assert_eq!(*dim as usize, NOMIC_EMBED_DIM, "dense dim drifted");
    let mut out = Vec::with_capacity(data.len() * 4);
    for value in data {
        out.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    out
}

/// Attempts to build a lens for `slot`, surfacing the fail-closed panel error
/// (e.g. S22 refused under the default build).
pub fn new_lens(slot: u16, table: Arc<StaticEmbeddingTable>) -> PanelResult<StaticEmbeddingLens> {
    StaticEmbeddingLens::new(SlotId::new(slot), table)
}

/// True when `needle` occurs contiguously in `haystack` (naive scan). Used to prove
/// a feature-gated code path is or is not present in a built artifact.
pub fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Path of a multi-vector (S22) golden file.
pub fn multi_golden_path(key: &str) -> PathBuf {
    crate_dir()
        .join("tests/golden")
        .join(format!("{key}_s22.f32be"))
}

/// Reads a multi golden's persisted bytes, failing closed on a missing/empty file.
pub fn read_multi_golden(key: &str) -> Vec<u8> {
    let path = multi_golden_path(key);
    let bytes = fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "S22 golden {} is missing ({err}); regenerate with \
             `cargo test -p astrolabe-panel --features multi-vector --test feature_gate -- \
              --ignored regenerate`",
            path.display()
        )
    });
    assert!(
        !bytes.is_empty() && bytes.len().is_multiple_of(4),
        "S22 golden {} holds {} bytes; expected a non-empty multiple of 4",
        path.display(),
        bytes.len()
    );
    bytes
}

/// The emitted f32 bitpatterns of a multi vector, big-endian, token-major.
pub fn multi_bitpatterns(vector: &SlotVector) -> Vec<u8> {
    let SlotVector::Multi { token_dim, tokens } = vector else {
        panic!("expected a multi embedding, got {vector:?}");
    };
    let mut out = Vec::with_capacity(tokens.len() * *token_dim as usize * 4);
    for token in tokens {
        assert_eq!(token.len(), *token_dim as usize, "multi token dim drifted");
        for value in token {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
    }
    out
}

/// Lowercase hex SHA-256, used to print/compare worker-count hashes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Reads a golden file's persisted bytes, failing closed on a missing, empty, or
/// wrong-length golden. A blanked golden can never pass by comparing nothing.
pub fn read_dense_golden(key: &str, slot: u16) -> Vec<u8> {
    let path = golden_path(key, slot);
    let bytes = fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "golden {} is missing ({err}); regenerate with \
             `cargo test -p astrolabe-panel --test embedding_goldens -- --ignored regenerate`",
            path.display()
        )
    });
    assert_eq!(
        bytes.len(),
        DENSE_GOLDEN_LEN,
        "golden {} holds {} bytes, expected {DENSE_GOLDEN_LEN} (768 big-endian f32 bitpatterns); \
         an empty or truncated golden cannot enforce byte-exactness",
        path.display(),
        bytes.len()
    );
    bytes
}

// ---------------------------------------------------------------------------
// Independent oracle: recomputes the embedding straight from the vendored files.
// ---------------------------------------------------------------------------

fn raw_table() -> &'static (Vec<i8>, Vec<String>) {
    static RAW: OnceLock<(Vec<i8>, Vec<String>)> = OnceLock::new();
    RAW.get_or_init(|| {
        let blob = fs::read(blob_path()).expect("read code_vectors.bin");
        let blob_sha: [u8; 32] = Sha256::digest(&blob).into();
        assert_eq!(
            blob_sha, NOMIC_VECTOR_BLOB_SHA256,
            "oracle blob SHA drifted"
        );
        let text = fs::read_to_string(tokens_path()).expect("read code_tokens.txt");
        let tokens_sha: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        assert_eq!(
            tokens_sha, NOMIC_TOKEN_TABLE_SHA256,
            "oracle token table SHA drifted"
        );
        let vectors: Vec<i8> = blob[8..].iter().map(|byte| *byte as i8).collect();
        let rows: Vec<String> = text.lines().map(str::to_string).collect();
        assert_eq!(rows.len(), NOMIC_TOKEN_COUNT);
        (vectors, rows)
    })
}

/// Recomputes a dense embedding from the raw vendored bytes, independently of
/// `StaticEmbeddingTable`: row lookup by scanning the token file, `i8 / 127.0`,
/// sum in token order, L2-normalize in f64. This is the oracle the goldens are
/// checked against, so the goldens are not merely self-consistent.
pub fn oracle_dense(tokens: &[String]) -> Vec<f32> {
    let (vectors, rows) = raw_table();
    let mut acc = vec![0.0_f32; NOMIC_EMBED_DIM];
    for token in tokens {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match rows.iter().position(|row| !row.is_empty() && row == token) {
            Some(index) => {
                let start = index * NOMIC_EMBED_DIM;
                for (dim, slot) in acc.iter_mut().enumerate() {
                    *slot += f32::from(vectors[start + dim]) / 127.0_f32;
                }
            }
            None => {
                for i in 0..8_u32 {
                    let hash = calyx_core::content_address([
                        NOMIC_VECTOR_BLOB_SHA256.as_slice(),
                        token.as_bytes(),
                        i.to_be_bytes().as_slice(),
                    ]);
                    let mut idx = [0_u8; 4];
                    idx.copy_from_slice(&hash[..4]);
                    let pos = u32::from_be_bytes(idx) as usize % NOMIC_EMBED_DIM;
                    let sign = if hash[4] & 1 == 0 { 1.0 } else { -1.0 };
                    acc[pos] += sign;
                }
            }
        }
    }
    let norm = acc
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    assert!(norm.is_finite() && norm > 0.0, "oracle norm must be usable");
    acc.iter()
        .map(|value| (f64::from(*value) / norm) as f32)
        .collect()
}

/// The token stream the S20 lens measures, derived from the symbol identity by the
/// same frozen rule (`name` tokens, then the qualified-name tail tokens).
pub fn oracle_name_tokens(input: &StaticEmbeddingInput) -> Vec<String> {
    let mut tokens = cbm_camel_split_tokens(&input.name);
    let tail = input
        .qualified_name
        .rsplit([':', '.', '/', '#'])
        .find(|part| !part.is_empty())
        .unwrap_or(&input.qualified_name);
    tokens.extend(cbm_camel_split_tokens(tail));
    tokens
}

/// The token stream measured by `slot` for `input`.
pub fn tokens_for_slot(slot: u16, input: &StaticEmbeddingInput) -> Vec<String> {
    match slot {
        18 => input.body_tokens.clone(),
        19 => input.doc_tokens.clone(),
        20 => oracle_name_tokens(input),
        other => panic!("slot {other} is not a dense embedding slot"),
    }
}

/// Writes golden bytes, creating the directory. Only the `#[ignore]`d regeneration
/// test calls this.
pub fn write_golden(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create golden dir");
    }
    fs::write(path, bytes).expect("write golden");
}
