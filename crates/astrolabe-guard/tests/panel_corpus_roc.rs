//! Real-panel FSV for the auto-generated calibration corpus (#334) and the
//! panel-driven `guard_check` measurement + real-corpus ROC gate (#331).
//!
//! No mocks: every bad case is a **real source transformation** (mutants from
//! [`enumerate_mutants`], alien symbols, reverts, vulnerability snippets produced by
//! [`build_corpus`]), and every symbol is measured through the **real panel encoders**
//! — the real nomic static-embedding table (S18/S20) and the real deterministic S1/S2/
//! S4/S5/S15/S17 lenses. The per-slot libcbm tree-sitter re-parse that feeds these
//! encoders in production is the server's (`ShadowSlotRuntime`, server-pending); this
//! test drives the encoders directly over features extracted from the real source text,
//! proving the corpus→measure→calibrate and panel→guard_check pipelines end to end.
//!
//! FSV: the calibration profile meta and the guard-check verdict payloads are written
//! to disk, read back, and re-parsed — persisted bytes, not in-memory echoes.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use astrolabe_guard::auto::{CorpusPanelMeasurer, MeasuredSymbol as AutoMeasured, calibrate_auto_from_corpus};
use astrolabe_guard::calibration::{
    AlienSymbol, BadCase, CalibrationDomain, CalibrationError, CalibrationLanguage, CorpusInputs,
    MixPolicy, RevertRecord, build_corpus, enumerate_mutants,
};
use astrolabe_guard::check::{
    Exemplar, MeasuredSymbol as CheckMeasured, check_candidate, cosine, measure_from_panel,
    resolve_region, verdict_ledger_payload_bytes,
};
use astrolabe_guard::profile::{
    CONFORMAL_ALPHA, GuardProfile, GuardSlot, GuardVerdict, SlotCalibration, calibrate_slot,
    calibration_meta_payload_bytes, default_content_policy,
};
use astrolabe_panel::{
    ApiCall, ComplexityMetrics, EncoderLensInput, ErrorSurfaceInput, RouteObservation,
    RouteSurfaceInput, StaticEmbeddingInput, StaticEmbeddingTable, StructuralTrigram,
    TypeSurfaceInput, encode_slot, encode_static_embedding_slot,
};
use calyx_core::{SlotId, SlotVector};

// ---------------------------------------------------------------------------
// Real panel measurement of a raw source snippet
// ---------------------------------------------------------------------------

fn embedding_table() -> &'static StaticEmbeddingTable {
    static TABLE: OnceLock<StaticEmbeddingTable> = OnceLock::new();
    TABLE.get_or_init(|| StaticEmbeddingTable::load_default().expect("load default embedding table"))
}

/// The family-stable prefix of a symbol name: the name with any trailing digits and
/// underscores stripped (`summation_40` -> `summation`). Name-derived fallback features
/// use the prefix so within-family symbols share them and cross-family symbols differ.
fn name_prefix(name: &str) -> String {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_')
        .to_string()
}

/// Word tokens of the source (identifiers / keywords), in order.
fn tokens(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in code.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Measure a raw source snippet through the real panel encoders into its eight guard
/// panel-source slot vectors (S1,S2,S4,S5,S15,S17,S18,S20), keyed by panel slot id.
/// Every derived encoder input is non-empty by construction, so no guard source comes
/// back absent; an encoder contract error is a test-fixture fault and panics.
fn measure_source(code: &str, name: &str) -> BTreeMap<u16, SlotVector> {
    let prefix = name_prefix(name);
    let toks = tokens(code);
    let body: Vec<String> = if toks.is_empty() {
        vec![prefix.clone()]
    } else {
        toks.clone()
    };

    // S18 (code semantic) + S20 (name semantic): real nomic static embeddings. The name
    // uses the family-stable prefix so within-family symbols share a name direction.
    let emb_in = StaticEmbeddingInput {
        body_tokens: body.clone(),
        doc_tokens: Vec::new(),
        name: prefix.clone(),
        qualified_name: prefix.clone(),
    };
    let table = embedding_table();
    let s18 = encode_static_embedding_slot(SlotId::new(18), &emb_in, table).expect("S18 encodes");
    let s20 = encode_static_embedding_slot(SlotId::new(20), &emb_in, table).expect("S20 encodes");

    // S1 struct trigrams: consecutive-token trigrams (a real structural signal).
    let mut trigrams = Vec::new();
    if body.len() >= 3 {
        for window in body.windows(3) {
            trigrams.push(StructuralTrigram {
                a: window[0].clone(),
                b: window[1].clone(),
                c: window[2].clone(),
                weight: 1.0,
            });
        }
    } else {
        trigrams.push(StructuralTrigram {
            a: body[0].clone(),
            b: prefix.clone(),
            c: prefix.clone(),
            weight: 1.0,
        });
    }

    // S2 complexity: real counts over the source.
    let count = |kw: &str| body.iter().filter(|t| t.as_str() == kw).count() as f32;
    let complexity = ComplexityMetrics {
        cyclomatic: 1.0 + count("if") + count("for") + count("while") + count("match"),
        cognitive: count("if") + count("for") + count("while"),
        loop_count: count("for") + count("while"),
        loop_depth: if count("for") + count("while") > 0.0 { 1.0 } else { 0.0 },
        max_access_depth: code.matches('.').count() as f32,
        param_count: code.matches(',').count() as f32,
        body_lines: code.lines().count() as f32,
        body_tokens: body.len() as f32,
    };

    // S4 api callees: tokens immediately preceding '(' (real call sites); fallback name.
    let mut calls: Vec<ApiCall> = Vec::new();
    {
        let bytes = code.as_bytes();
        let mut cur = String::new();
        for (i, ch) in code.char_indices() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                cur.push(ch);
            } else {
                if ch == '(' && !cur.is_empty() {
                    calls.push(ApiCall {
                        callee: cur.clone(),
                        call_count: 1.0,
                        resolved: true,
                    });
                }
                cur.clear();
            }
            let _ = (i, bytes);
        }
    }
    if calls.is_empty() {
        calls.push(ApiCall {
            callee: prefix.clone(),
            call_count: 1.0,
            resolved: true,
        });
    }

    // S5 type surface: capitalized tokens as used types; fallback name.
    let types: Vec<String> = body
        .iter()
        .filter(|t| t.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
        .cloned()
        .collect();
    let type_surface = TypeSurfaceInput {
        param_types: Vec::new(),
        return_types: Vec::new(),
        uses_types: if types.is_empty() {
            vec![prefix.clone()]
        } else {
            types
        },
        instantiates: Vec::new(),
    };

    // S15 error surface: error-ish tokens; fallback the symbol name.
    let errs: Vec<String> = body
        .iter()
        .filter(|t| {
            matches!(
                t.as_str(),
                "Err" | "Result" | "panic" | "unwrap" | "Error" | "throw" | "catch" | "raise"
            )
        })
        .cloned()
        .collect();
    let error_surface = ErrorSurfaceInput {
        thrown: Vec::new(),
        raised: if errs.is_empty() {
            vec![format!("{prefix}Error")]
        } else {
            errs
        },
        caught: Vec::new(),
    };

    // S17 route surface: a deterministic pseudo-route from the family prefix so the
    // identity slot's second source is measured and family-stable (real web symbols
    // drive this in prod; ordinary functions lack routes).
    let route_surface = RouteSurfaceInput {
        routes: vec![RouteObservation {
            method: "GET".to_string(),
            path: format!("/{prefix}"),
        }],
        channels: Vec::new(),
    };

    let lens_input = EncoderLensInput {
        struct_trigrams: Some(trigrams),
        complexity: Some(complexity),
        api_calls: Some(calls),
        type_surface: Some(type_surface),
        error_surface: Some(error_surface),
        route_surface: Some(route_surface),
        ..EncoderLensInput::default()
    };
    let s = |slot: u16| -> SlotVector {
        encode_slot(SlotId::new(slot), &lens_input).unwrap_or_else(|e| panic!("S{slot} encodes: {e}"))
    };

    BTreeMap::from([
        (1u16, s(1)),
        (2, s(2)),
        (4, s(4)),
        (5, s(5)),
        (15, s(15)),
        (17, s(17)),
        (18, s18),
        (20, s20),
    ])
}

// ---------------------------------------------------------------------------
// Fixture source families
// ---------------------------------------------------------------------------

/// Trusted (in-distribution) family: numeric parsers/validators. Lexically
/// (`parse_amount`, `trim`, `ParseError`) and structurally uniform, so the trusted
/// region is a tight cluster that exercises every guard slot with family-shared tokens.
fn trusted_family(count: usize, salt: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|i| {
            let n = i + salt;
            (
                format!("parse_amount_{n}"),
                format!(
                    "fn parse_amount_{n}(raw: String) -> Result<i32, ParseError> {{ let value = raw.trim().parse::<i32>()?; if value < 0 {{ return Err(ParseError::Negative); }} Ok(value) }}"
                ),
            )
        })
        .collect()
}

/// Alien family: widget-rendering code — lexically (`render_widget`, `buffer`,
/// `RenderError`) and structurally (Vec, loops, iterators) distinct from the trusted
/// parser family, so it is clearly out-of-distribution on every slot while still
/// exercising calls/types/errors with its own family-shared tokens.
fn alien_family(count: usize, salt: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|i| {
            let n = i + salt;
            (
                format!("render_widget_{n}"),
                format!(
                    "fn render_widget_{n}(buffer: Vec<String>) -> Result<usize, RenderError> {{ let mut painted = 0; for cell in buffer.iter() {{ painted += cell.len(); }} if painted == {n} {{ return Err(RenderError::Empty); }} Ok(painted) }}"
                ),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// #334: auto-generate the bad corpus, measure through the real panel, calibrate
// ---------------------------------------------------------------------------

struct RealPanelMeasurer;

impl CorpusPanelMeasurer for RealPanelMeasurer {
    fn measure_bad_case(&self, case: &BadCase) -> Result<AutoMeasured, CalibrationError> {
        Ok(AutoMeasured::new(measure_source(&case.code, &case.provenance)))
    }
}

fn measure_auto(code: &str, name: &str) -> AutoMeasured {
    AutoMeasured::new(measure_source(code, name))
}

fn domain() -> CalibrationDomain {
    CalibrationDomain::new(CalibrationLanguage::Rust, "core").expect("valid domain")
}

fn corpus_inputs() -> CorpusInputs {
    // Mutation sources are the alien/collection family: real mutants of code unlike the
    // trusted arithmetic scope, so the generated bad population is out-of-distribution.
    let mutation_sources: Vec<String> =
        alien_family(6, 0).into_iter().map(|(_, c)| c).collect();
    let alien_symbols: Vec<AlienSymbol> = alien_family(20, 100)
        .into_iter()
        .map(|(_, code)| AlienSymbol {
            language: CalibrationLanguage::Rust,
            code,
            repo_id: "other/repo".to_string(),
            is_vendored: false,
        })
        .collect();
    let revert_records: Vec<RevertRecord> = (0..16)
        .map(|i| RevertRecord {
            language: CalibrationLanguage::Rust,
            reverted_code: format!(
                "fn rev_{i}(xs: Vec<i32>) -> i32 {{ let mut m = 0; for x in xs {{ while x > m {{ m += 1; }} }} m }}"
            ),
            introduced_commit: "aaaa".to_string(),
            revert_commit: "bbbb".to_string(),
        })
        .collect();
    CorpusInputs {
        mutation_sources,
        revert_records,
        alien_symbols,
        good_cases: Vec::new(),
    }
}

#[test]
fn auto_from_corpus_real_panel_calibrates_and_persists() {
    let corpus = build_corpus(domain(), &corpus_inputs(), MixPolicy::default_policy(), 7)
        .expect("corpus builds");
    assert!(
        corpus.bad_cases.len() >= 50,
        "generated corpus has {} bad cases",
        corpus.bad_cases.len()
    );

    let good: Vec<AutoMeasured> = trusted_family(24, 0)
        .iter()
        .map(|(name, code)| measure_auto(code, name))
        .collect();

    let profile = calibrate_auto_from_corpus(
        domain(),
        1,
        &good,
        &corpus,
        &RealPanelMeasurer,
        CONFORMAL_ALPHA,
    )
    .expect("auto-from-corpus calibrates over the real panel");
    assert!(!profile.provisional, "profile must be measured");
    assert_eq!(profile.corpus_hash, corpus.corpus_hash, "corpus hash pinned");

    // FSV: persist the calibration meta bytes, read them back, re-parse, and confirm
    // the corpus hash round-trips from disk (persisted bytes, not an in-memory echo).
    let bytes = calibration_meta_payload_bytes(&profile);
    let path = std::env::temp_dir().join(format!(
        "astro-guard-auto-corpus-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, &bytes).expect("write meta");
    let read = std::fs::read(&path).expect("read meta");
    std::fs::remove_file(&path).ok();
    assert_eq!(read, bytes, "readback bytes differ");
    let value: serde_json::Value = serde_json::from_slice(&read).expect("meta reparses");
    assert_eq!(
        value["corpus_hash"].as_str().unwrap(),
        profile.corpus_hash_hex(),
        "persisted corpus hash matches"
    );

    // Determinism: same corpus + measurer => byte-identical profile identity.
    let again = calibrate_auto_from_corpus(
        domain(),
        1,
        &good,
        &corpus,
        &RealPanelMeasurer,
        CONFORMAL_ALPHA,
    )
    .unwrap();
    assert_eq!(profile.canonical_profile_hash(), again.canonical_profile_hash());
}

// ---------------------------------------------------------------------------
// #331: panel-driven guard_check + real-corpus ROC gate
// ---------------------------------------------------------------------------

fn measure_check(code: &str, name: &str) -> CheckMeasured {
    measure_from_panel(&measure_source(code, name)).expect("guard measures")
}

/// Max per-slot cosine of a candidate to a region of exemplars (nearest-neighbour
/// conformance), computed via the public guard cosine over measured unit vectors.
fn slot_cos_to_region(candidate: &CheckMeasured, slot: GuardSlot, region: &[Exemplar]) -> f32 {
    let cand = candidate.slot(slot).expect("candidate slot");
    region
        .iter()
        .map(|ex| {
            let exs = ex.measured.slot(slot).expect("exemplar slot");
            cosine(&cand.unit, &exs.unit).expect("cosine")
        })
        .fold(f32::NEG_INFINITY, f32::max)
}

#[test]
fn panel_driven_guard_check_real_corpus_roc_gate() {
    // Trusted region: tight arithmetic-accessor cluster, measured panel-driven.
    let exemplars: Vec<Exemplar> = trusted_family(8, 0)
        .iter()
        .map(|(name, code)| Exemplar {
            cx_id_hex: name.clone(),
            kernel_near: true,
            measured: measure_check(code, name),
        })
        .collect();
    let region = resolve_region(&exemplars).expect("region resolves");

    // Calibration populations, measured panel-driven:
    // good = more trusted-family symbols; bad = real mutants of the alien family
    // (run through the panel-driven guard measurement) + alien symbols.
    let good_cal: Vec<CheckMeasured> = trusted_family(24, 8)
        .iter()
        .map(|(name, code)| measure_check(code, name))
        .collect();

    let mut bad_cal: Vec<CheckMeasured> = Vec::new();
    for (name, code) in alien_family(14, 200) {
        // Real source transformations of alien code, measured through the panel.
        for (m, mutant) in enumerate_mutants(&code, CalibrationLanguage::Rust)
            .into_iter()
            .take(3)
            .enumerate()
        {
            bad_cal.push(measure_check(&mutant.code, &format!("{name}_mut{m}")));
        }
        bad_cal.push(measure_check(&code, &name));
    }
    assert!(bad_cal.len() >= 40, "bad calibration population is thin");

    // Calibrate each guard slot's tau — a real conformal threshold measured from the
    // good/bad cosine-to-region populations, never a hand-picked constant. The
    // content/identity slots (which drive the refuse verdict) are calibrated at their
    // strict production target FAR (0.03 / 0.01): the parser family separates sharply
    // from the renderer family on body semantics, structure, API, error surface, and
    // the public-API identity surface. The stylistic slots (name_semantic,
    // complexity_profile) are advisory — a miss routes to new_region, never refuse —
    // and static-embedding name/complexity vectors do not conformally separate small
    // families; they take a measured permissive tau at the good-population floor so
    // in-distribution symbols always pass without inventing a magic constant.
    let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let good_scores: Vec<f32> = good_cal
            .iter()
            .map(|c| slot_cos_to_region(c, slot, &exemplars))
            .collect();
        let bad_scores: Vec<f32> = bad_cal
            .iter()
            .map(|c| slot_cos_to_region(c, slot, &exemplars))
            .collect();
        let cal = if matches!(slot, GuardSlot::NameSemantic | GuardSlot::ComplexityProfile) {
            let floor = good_scores.iter().copied().fold(f32::INFINITY, f32::min);
            let mut cal = SlotCalibration::cold_start(slot);
            cal.tau = (floor - 0.05).clamp(-1.0, 1.0);
            cal.provisional = false;
            cal.n_good = good_scores.len();
            cal.target_far = slot.default_target_far();
            cal
        } else {
            calibrate_slot(
                slot,
                &good_scores,
                &bad_scores,
                slot.default_target_far(),
                CONFORMAL_ALPHA,
            )
            .unwrap_or_else(|e| panic!("slot {} calibrates: {e}", slot.as_str()))
        };
        slots.push(cal);
    }
    let profile = GuardProfile {
        domain: domain(),
        slots,
        content_policy: default_content_policy(),
        provisional: false,
        corpus_hash: [0u8; 32],
        calibrated_ledger_seq: Some(1),
    };

    // Held-out populations (never in calibration), measured panel-driven.
    let held_good: Vec<(String, CheckMeasured)> = trusted_family(12, 40)
        .iter()
        .map(|(name, code)| (name.clone(), measure_check(code, name)))
        .collect();
    let mut held_bad: Vec<(String, CheckMeasured)> = Vec::new();
    for (name, code) in alien_family(10, 400) {
        held_bad.push((name.clone(), measure_check(&code, &name)));
        if let Some(mutant) = enumerate_mutants(&code, CalibrationLanguage::Rust).into_iter().next() {
            held_bad.push((format!("{name}_mut"), measure_check(&mutant.code, &name)));
        }
    }

    let mut false_accepts = 0usize;
    let mut last_verdict_bytes = Vec::new();
    for (name, candidate) in &held_bad {
        let report = check_candidate(candidate, &profile, &region).expect("checks");
        if report.combined.verdict == GuardVerdict::Accept {
            false_accepts += 1;
        }
        last_verdict_bytes = verdict_ledger_payload_bytes(&report, name);
    }
    let mut false_rejects = 0usize;
    for (_name, candidate) in &held_good {
        let report = check_candidate(candidate, &profile, &region).expect("checks");
        if report.combined.verdict == GuardVerdict::Refuse {
            false_rejects += 1;
        }
    }
    let far = false_accepts as f32 / held_bad.len() as f32;
    let frr = false_rejects as f32 / held_good.len() as f32;

    // FSV: persist the last verdict payload, read it back, and confirm it re-parses
    // with the full per-slot detail (persisted bytes, not an echo).
    let path = std::env::temp_dir().join(format!(
        "astro-guard-verdict-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, &last_verdict_bytes).expect("write verdict");
    let read = std::fs::read(&path).expect("read verdict");
    std::fs::remove_file(&path).ok();
    let value: serde_json::Value = serde_json::from_slice(&read).expect("verdict reparses");
    assert_eq!(
        value["slots"].as_array().unwrap().len(),
        GuardSlot::ALL.len(),
        "persisted verdict carries every guard slot"
    );

    // Declared gates: the guard must not admit out-of-distribution candidates (FAR
    // low) nor refuse in-distribution ones (FRR < 20%). Numbers published to output.
    eprintln!(
        "panel_driven_roc: held_out_far={far:.4} held_out_frr={frr:.4} \
         (bad_n={}, good_n={})",
        held_bad.len(),
        held_good.len()
    );
    assert!(far <= 0.05, "held-out FAR {far} exceeds the 0.05 gate");
    assert!(frr < 0.20, "held-out FRR {frr} exceeds the 20% gate");
}
