//! S18-S20 golden embedding tests over real fixture snippets (#12).
//!
//! Source of truth = the **persisted golden bytes** under `tests/golden/` (768
//! big-endian f32 bitpatterns per vector) and the **bitpatterns the lens actually
//! emits**. Every assertion here reads one and compares it to the other; nothing is
//! mocked and no vector is synthesized.
//!
//! Bit-stability: the embedding path performs **no parallel reduction**. Each vector
//! is a sequential f32 accumulation over its tokens in fixed token order, followed by
//! a sequential f64 L2 fold in fixed dimension order. f32 addition is non-associative,
//! so a parallel/work-stealing reduction (e.g. `rayon::reduce`) would let the worker
//! count reorder the sum and change the low bits. Because no such reduction exists on
//! this path, the worker count can only schedule *whole, independent* vectors — the
//! reduction order inside a vector is invariant. `worker_count_invariance_*` pins that
//! property so any future parallel fold inside the encoder fails this test.
//!
//! Cross-platform bitpattern identity (the other half of the original DoD wording) is
//! DEFERRED[ASTRO_PORT_PHASE] -> #238 / milestone "Port — cross-platform (deferred)".
//! These tests prove Windows-native byte-exactness and worker-count invariance only.

mod support;

use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_panel::{
    ASTRO_PANEL_CONTRACT_INVALID, NOMIC_TOKEN_TABLE_SHA256, NOMIC_VECTOR_BLOB_SHA256,
    StaticEmbeddingInput, StaticEmbeddingTable,
};
use calyx_core::{AbsentReason, SlotVector};

use support::{
    DENSE_GOLDEN_LEN, DENSE_SLOTS, FIXTURES, blob_path, dense_bitpatterns, embedding_input,
    golden_path, measure, oracle_dense, read_dense_golden, sha256_hex, table, tokens_for_slot,
    tokens_path, try_measure, write_golden,
};

/// Every fixture x slot pair, in a frozen order.
fn cases() -> Vec<(&'static str, u16, StaticEmbeddingInput)> {
    let mut out = Vec::new();
    for fixture in FIXTURES {
        let input = embedding_input(fixture);
        for slot in DENSE_SLOTS {
            out.push((fixture.key, slot, input.clone()));
        }
    }
    out
}

/// The emitted bitpatterns must equal the persisted golden bytes, byte for byte.
#[test]
fn golden_dense_embeddings_are_exact_f32_bitpatterns() {
    let table = table();
    assert!(!FIXTURES.is_empty(), "fixture roster is empty");
    let mut checked = 0_usize;
    for (key, slot, input) in cases() {
        let tokens = tokens_for_slot(slot, &input);
        assert!(
            !tokens.is_empty(),
            "fixture {key} slot {slot} produced no tokens; a golden over an absent \
             vector would prove nothing"
        );
        let vector = measure(slot, &input, Arc::clone(&table));
        let emitted = dense_bitpatterns(&vector);
        let golden = read_dense_golden(key, slot);
        assert_eq!(emitted.len(), DENSE_GOLDEN_LEN);
        assert_eq!(
            emitted,
            golden,
            "fixture {key} slot {slot} drifted: emitted sha256={} golden sha256={} \
             (golden file {})",
            sha256_hex(&emitted),
            sha256_hex(&golden),
            golden_path(key, slot).display()
        );
        println!(
            "FSV golden {key} S{slot}: tokens={} bytes={} sha256={} first_f32_bits={:02x?}",
            tokens.len(),
            golden.len(),
            sha256_hex(&golden),
            &golden[..4]
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        FIXTURES.len() * DENSE_SLOTS.len(),
        "every fixture x slot pair must be byte-checked"
    );
}

/// The goldens are not merely self-consistent: an independent recomputation straight
/// from the vendored `code_vectors.bin` / `code_tokens.txt` bytes reproduces them bit
/// for bit.
#[test]
fn goldens_match_independent_recomputation_from_vendored_bytes() {
    for (key, slot, input) in cases() {
        let tokens = tokens_for_slot(slot, &input);
        let oracle = oracle_dense(&tokens);
        let mut oracle_bytes = Vec::with_capacity(DENSE_GOLDEN_LEN);
        for value in &oracle {
            oracle_bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        let golden = read_dense_golden(key, slot);
        assert_eq!(
            oracle_bytes,
            golden,
            "fixture {key} slot {slot}: independent oracle sha256={} != golden sha256={}",
            sha256_hex(&oracle_bytes),
            sha256_hex(&golden)
        );
        println!(
            "FSV oracle {key} S{slot}: independent recomputation sha256={}",
            sha256_hex(&oracle_bytes)
        );
    }
}

/// Worker-count invariance (standing invariant 5): the same seeded fixture set,
/// measured by 1, 2, 4, 8 and 16 concurrent workers sharing one table, yields
/// byte-identical vectors — and they equal the persisted goldens.
#[test]
fn worker_count_invariance_dense_embeddings_are_byte_identical() {
    let table = table();
    let cases = cases();

    let expected: Vec<u8> = cases
        .iter()
        .flat_map(|(key, slot, _)| read_dense_golden(key, *slot))
        .collect();
    let expected_hash = sha256_hex(&expected);

    let mut hashes = Vec::new();
    for workers in [1_usize, 2, 4, 8, 16] {
        let mut per_worker = thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|worker| {
                    let table = Arc::clone(&table);
                    let cases = &cases;
                    scope.spawn(move || {
                        // Rotate the start offset per worker so each worker visits the
                        // cases in a different global order; only the *within-vector*
                        // reduction order may not vary.
                        let len = cases.len();
                        let mut bytes: Vec<Vec<u8>> = vec![Vec::new(); len];
                        for step in 0..len {
                            let idx = (step + worker) % len;
                            let (_, slot, input) = &cases[idx];
                            let vector = measure(*slot, input, Arc::clone(&table));
                            bytes[idx] = dense_bitpatterns(&vector);
                        }
                        bytes.concat()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("worker thread"))
                .collect::<Vec<_>>()
        });
        per_worker.dedup();
        assert_eq!(
            per_worker.len(),
            1,
            "workers={workers}: concurrent workers disagreed on the emitted bytes"
        );
        let hash = sha256_hex(&per_worker[0]);
        println!("worker-count invariance: workers={workers} sha256={hash}");
        assert_eq!(
            per_worker[0], expected,
            "workers={workers}: emitted sha256={hash} != golden sha256={expected_hash}"
        );
        hashes.push(hash);
    }
    println!("worker-count invariance: golden sha256={expected_hash}");
    assert!(
        hashes.windows(2).all(|pair| pair[0] == pair[1]),
        "worker counts produced different hashes: {hashes:?}"
    );
}

/// Edge triad (a): an empty token stream is a labeled absence, and a token stream that
/// contains only blanks fails closed instead of emitting a zero vector.
#[test]
fn edge_empty_input_is_absent_and_blank_tokens_fail_closed() {
    let table = table();

    let empty = StaticEmbeddingInput::default();
    println!("edge/empty before: body_tokens={:?}", empty.body_tokens);
    let vector = measure(18, &empty, Arc::clone(&table));
    println!("edge/empty after: {vector:?}");
    assert_eq!(
        vector,
        SlotVector::Absent {
            reason: AbsentReason::LensUnavailable
        }
    );

    let blank = StaticEmbeddingInput {
        body_tokens: vec!["   ".to_string(), "\t".to_string()],
        ..StaticEmbeddingInput::default()
    };
    println!("edge/blank before: body_tokens={:?}", blank.body_tokens);
    let err = try_measure(18, &blank, table).expect_err("blank tokens must fail closed");
    println!("edge/blank after: {err}");
    assert!(
        err.to_string().contains("ASTRO_PANEL_VECTOR_INVALID"),
        "blank-token failure must be the fail-closed vector error, got: {err}"
    );
}

/// Edge triad (b): a token outside the 40,856-row table routes to the deterministic
/// random-index fallback — same OOV token, same bits, on every call and in both the
/// lens and the independent oracle.
#[test]
fn edge_oov_token_beyond_table_is_deterministic_and_matches_oracle() {
    let table = table();
    let input = StaticEmbeddingInput {
        body_tokens: vec!["astrolabe_oov_fixture".to_string()],
        ..StaticEmbeddingInput::default()
    };
    println!("edge/oov before: token={:?}", input.body_tokens[0]);
    let first = dense_bitpatterns(&measure(18, &input, Arc::clone(&table)));
    let second = dense_bitpatterns(&measure(18, &input, Arc::clone(&table)));
    assert_eq!(first, second, "OOV fallback is not deterministic");
    let oracle: Vec<u8> = oracle_dense(&input.body_tokens)
        .iter()
        .flat_map(|value| value.to_bits().to_be_bytes())
        .collect();
    println!(
        "edge/oov after: lens sha256={} oracle sha256={}",
        sha256_hex(&first),
        sha256_hex(&oracle)
    );
    assert_eq!(first, oracle, "OOV fallback drifted from the frozen rule");
}

/// Edge triad (c): a corrupted `code_vectors.bin` is refused with a fail-closed
/// `{code, message, remediation}` error — no silent fallback to an unverified blob.
#[test]
fn edge_corrupted_blob_is_refused_fail_closed() {
    let mut blob = fs::read(blob_path()).expect("read vendored blob");
    let original = blob[9];
    blob[9] ^= 0x5f;
    println!(
        "edge/corrupt before: blob byte[9]={original:#04x} -> {:#04x}",
        blob[9]
    );
    let corrupt = std::env::temp_dir().join(format!(
        "astrolabe-panel-corrupt-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::write(&corrupt, &blob).expect("write corrupt blob");
    let err = StaticEmbeddingTable::load_from_paths(
        &corrupt,
        tokens_path(),
        NOMIC_VECTOR_BLOB_SHA256,
        NOMIC_TOKEN_TABLE_SHA256,
    )
    .expect_err("corrupted blob must be refused");
    let _ = fs::remove_file(&corrupt);
    println!(
        "edge/corrupt after: code={} message={} remediation={}",
        err.code(),
        err.message(),
        err.remediation()
    );
    assert_eq!(err.code(), ASTRO_PANEL_CONTRACT_INVALID);
    assert!(err.message().contains("SHA-256"));
    assert!(!err.remediation().is_empty());
}

/// Regenerates the persisted goldens from the current encoder. Never runs in a normal
/// test pass: a golden that regenerates itself proves nothing. Run explicitly, review
/// the byte diff, and only then commit.
///
/// `cargo test -p astrolabe-panel --test embedding_goldens -- --ignored regenerate`
#[test]
#[ignore = "golden regeneration is an explicit, reviewed action"]
fn regenerate_dense_goldens() {
    let table = table();
    for (key, slot, input) in cases() {
        let bytes = dense_bitpatterns(&measure(slot, &input, Arc::clone(&table)));
        let path = golden_path(key, slot);
        write_golden(&path, &bytes);
        println!(
            "regenerated {} ({} bytes, sha256={})",
            path.display(),
            bytes.len(),
            sha256_hex(&bytes)
        );
    }
}
