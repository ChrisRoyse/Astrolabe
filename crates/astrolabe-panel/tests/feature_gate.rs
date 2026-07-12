//! S22 `multi-vector` feature-gate proof (#12, DoD box 2).
//!
//! Proves two things that mere source-level `#[cfg]` inspection cannot:
//!  1. The default build genuinely **excludes** the S22 encode path — not "doesn't
//!     call it", but the code is not compiled into the artifact. We scan the built
//!     integration-test binary (`current_exe()`, which statically links
//!     astrolabe-panel) for the domain-separation marker `token_multi_projection`
//!     that lives **only** inside `embed_token_multi`, which is `#[cfg(feature =
//!     "multi-vector")]`. The needle is assembled at runtime from fragments so the
//!     contiguous bytes are never a literal in this test's own rodata.
//!  2. With `--features multi-vector`, the marker is present, S22 constructs and
//!     measures a `Multi` vector, and its bytes equal the persisted S22 golden.
//!
//! The "CI matrix job" wording of the DoD is the only deferred part: with CI banned
//! (owner directive) this runs natively via two `cargo test` invocations, one per
//! feature configuration.

mod support;

use std::sync::Arc;

use astrolabe_panel::ASTRO_PANEL_CONTRACT_INVALID;

use support::{contains_subsequence, new_lens, table};

/// The marker string that exists only in the feature-gated S22 encode path. Built at
/// runtime so the contiguous form never appears as a literal in this binary except via
/// the library code we are probing for.
fn s22_marker() -> Vec<u8> {
    ["token", "multi", "projection"].join("_").into_bytes()
}

#[test]
fn s22_code_is_compiled_in_iff_multi_vector_feature_is_enabled() {
    let enabled = cfg!(feature = "multi-vector");
    let exe = std::env::current_exe().expect("current test exe");
    let bytes = std::fs::read(&exe).expect("read own test binary");
    let marker = s22_marker();
    let present = contains_subsequence(&bytes, &marker);
    println!(
        "feature-gate: cfg!(multi-vector)={enabled}; S22 encode marker {:?} present in {} = {present} (binary {} bytes)",
        String::from_utf8_lossy(&marker),
        exe.display(),
        bytes.len()
    );
    assert_eq!(
        present, enabled,
        "the S22 encode path must be present in the artifact IFF the multi-vector \
         feature is enabled (cfg={enabled}, marker_present={present})"
    );
}

#[test]
fn s22_lens_construction_matches_feature_state() {
    let table = table();
    let result = new_lens(22, Arc::clone(&table));
    if cfg!(feature = "multi-vector") {
        let lens = result.expect("S22 lens must build when multi-vector is enabled");
        println!(
            "feature-gate: S22 lens built, slot={}",
            lens.slot_id().get()
        );
    } else {
        let err = result.expect_err("S22 lens must be refused under the default build");
        println!(
            "feature-gate: S22 refused code={} message={}",
            err.code(),
            err.message()
        );
        assert_eq!(err.code(), ASTRO_PANEL_CONTRACT_INVALID);
    }
}

#[cfg(not(feature = "multi-vector"))]
#[test]
fn default_build_absent_s22_never_emits_a_vector() {
    // With the feature off there is no S22 lens to measure at all; the roster refuses
    // it up front. Confirm the refusal carries a fail-closed error, not a silent skip.
    let table = table();
    let err = new_lens(22, table).expect_err("S22 excluded by default");
    assert_eq!(err.code(), ASTRO_PANEL_CONTRACT_INVALID);
    assert!(
        err.remediation().contains("multi-vector"),
        "remediation must point at the feature: {}",
        err.remediation()
    );
}

#[cfg(feature = "multi-vector")]
mod multi_vector_enabled {
    use super::*;
    use astrolabe_panel::StaticEmbeddingInput;
    use calyx_core::SlotVector;
    use support::{
        FIXTURES, embedding_input, measure, multi_bitpatterns, multi_golden_path,
        read_multi_golden, sha256_hex,
    };

    fn s22_cases() -> Vec<(&'static str, StaticEmbeddingInput)> {
        FIXTURES
            .iter()
            .map(|fixture| (fixture.key, embedding_input(fixture)))
            .collect()
    }

    #[test]
    fn s22_goldens_are_exact_multi_bitpatterns() {
        let table = table();
        let mut checked = 0_usize;
        for (key, input) in s22_cases() {
            assert!(
                !input.body_tokens.is_empty(),
                "fixture {key} has no body tokens; an S22 golden would prove nothing"
            );
            let vector = measure(22, &input, Arc::clone(&table));
            let SlotVector::Multi { token_dim, tokens } = &vector else {
                panic!("S22 must emit Multi, got {vector:?}");
            };
            assert!(!tokens.is_empty());
            let emitted = multi_bitpatterns(&vector);
            let golden = read_multi_golden(key);
            assert_eq!(
                emitted,
                golden,
                "S22 fixture {key} drifted: emitted sha256={} golden sha256={} (file {})",
                sha256_hex(&emitted),
                sha256_hex(&golden),
                multi_golden_path(key).display()
            );
            println!(
                "FSV S22 golden {key}: token_dim={token_dim} tokens={} bytes={} sha256={}",
                tokens.len(),
                golden.len(),
                sha256_hex(&golden)
            );
            checked += 1;
        }
        assert_eq!(
            checked,
            FIXTURES.len(),
            "every fixture must have an S22 golden"
        );
    }

    #[test]
    fn s22_is_worker_count_invariant() {
        use std::thread;
        let table = table();
        let cases = s22_cases();
        let mut hashes = Vec::new();
        for workers in [1_usize, 4, 8] {
            let outputs = thread::scope(|scope| {
                let handles: Vec<_> = (0..workers)
                    .map(|_| {
                        let table = Arc::clone(&table);
                        let cases = &cases;
                        scope.spawn(move || {
                            let mut bytes = Vec::new();
                            for (_, input) in cases {
                                bytes.extend(multi_bitpatterns(&measure(
                                    22,
                                    input,
                                    Arc::clone(&table),
                                )));
                            }
                            bytes
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("worker"))
                    .collect::<Vec<_>>()
            });
            for out in &outputs {
                assert_eq!(out, &outputs[0], "workers={workers} disagreed on S22 bytes");
            }
            let hash = sha256_hex(&outputs[0]);
            println!("S22 worker-count invariance: workers={workers} sha256={hash}");
            hashes.push(hash);
        }
        assert!(
            hashes.windows(2).all(|pair| pair[0] == pair[1]),
            "S22 worker counts diverged: {hashes:?}"
        );
    }

    #[test]
    #[ignore = "S22 golden regeneration is an explicit, reviewed action"]
    fn regenerate_s22_goldens() {
        let table = table();
        for (key, input) in s22_cases() {
            let bytes = multi_bitpatterns(&measure(22, &input, Arc::clone(&table)));
            let path = multi_golden_path(key);
            support::write_golden(&path, &bytes);
            println!(
                "regenerated {} ({} bytes, sha256={})",
                path.display(),
                bytes.len(),
                sha256_hex(&bytes)
            );
        }
    }
}
